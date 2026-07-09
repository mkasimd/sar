//! SAR-over-TCP binding (M10d).
//!
//! Wraps an existing [`InMemoryTransport`] in TCP-policy mode and drives it
//! over any `Read + Write` byte stream.  The standard entry point is
//! [`TcpSarConnection`], which can be constructed from a
//! [`std::net::TcpStream`] or from any in-memory `Read + Write` pair (useful
//! for unit-testing without a network socket).
//!
//! # Protocol constraints (Section 18 TCP policy)
//!
//! - SAR streams MUST NOT be byte-interleaved on one TCP connection.
//! - A new SAR stream may begin only after the previous stream terminates via
//!   `SESSION_CLOSE` or reaches end-of-archive.
//! - If invalid stream bytes cannot be safely skipped, the connection is
//!   closed (a [`TransportAction::CloseConnection`] action is returned and the
//!   connection is marked closed).
//! - `SESSION_CLOSE` unbinds the SAR Stream ID and permits a later SAR stream
//!   on the same TCP connection.
//!
//! # Status/ACK emission
//!
//! When bidirectional control is enabled and the underlying M10c policy
//! produces [`TransportAction::EmitSessionStatus`] or
//! [`TransportAction::EmitSessionAck`], this binding serializes those frames
//! as SAR LFH control entries and writes them back over the same TCP
//! connection.  A single NO_INDEX global header is written before the first
//! outbound control frame; subsequent frames reuse the same open reverse
//! session.  Sequence numbers for outbound control frames are managed
//! internally.
//!
//! # Heartbeat / watchdog
//!
//! No background threads or timers are used.  Pass an explicit `now_ms` value
//! to [`TcpSarConnection::process_available`] to drive heartbeat and
//! inactivity watchdog checks.
//!
//! # TLS / transport security
//!
//! TLS is **not** implemented in this stage.  For untrusted networks, SAR
//! AEAD and/or an external transport-security layer (e.g. WireGuard, IPsec)
//! is required.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, ResourceLimits, SarError,
    write_global_header, write_lfh,
};
use sar_stream::SessionOpCode;

use crate::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

// ──────────────────────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for a [`TcpSarConnection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpTransportConfig {
    /// Underlying transport / session policy settings.
    pub transport: TransportConfig,
    /// Maximum bytes consumed per [`TcpSarConnection::process_available`] call.
    ///
    /// Reads are capped at this size to prevent unbounded allocation from
    /// network input.
    pub read_buffer_size: usize,
    /// Maximum bytes accepted per [`TcpSarConnection::write_all_sar_bytes`]
    /// call.
    ///
    /// Callers that need to send more data must split it into smaller chunks.
    pub write_buffer_size: usize,
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            read_buffer_size: 64 * 1024,
            write_buffer_size: 64 * 1024,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection state
// ──────────────────────────────────────────────────────────────────────────────

/// Tracks the state of the outbound (reverse-control) SAR session.
struct OutboundControlState {
    global_header_written: bool,
    sequence_no: u16,
}

impl OutboundControlState {
    const fn new() -> Self {
        Self {
            global_header_written: false,
            sequence_no: 0,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection type
// ──────────────────────────────────────────────────────────────────────────────

/// SAR-over-TCP connection binding.
///
/// Generic over any `Read + Write` stream.  Construct with
/// [`TcpSarConnection::connect`] / [`TcpSarConnection::accept`] for real TCP,
/// or directly with [`TcpSarConnection::from_stream`] for testing.
///
/// A single fixed [`TransportStreamId`] (`0`) is used for the one logical SAR
/// stream permitted over a TCP connection at any point in time.
pub struct TcpSarConnection<S> {
    stream: S,
    inner: InMemoryTransport,
    config: TcpTransportConfig,
    closed: bool,
    outbound: OutboundControlState,
}

// ──────────────────────────────────────────────────────────────────────────────
// TcpStream constructors
// ──────────────────────────────────────────────────────────────────────────────

impl TcpSarConnection<TcpStream> {
    /// Connect to a remote SAR-over-TCP server.
    ///
    /// Returns a ready-to-use connection.  The TCP stream is left in its
    /// default blocking mode; callers may adjust it before or after this call.
    pub fn connect(
        addr: std::net::SocketAddr,
        config: TcpTransportConfig,
    ) -> Result<Self, SarError> {
        let stream = TcpStream::connect(addr).map_err(SarError::Io)?;
        Self::from_stream(stream, config)
    }

    /// Accept an already-connected [`TcpStream`] from a listener.
    ///
    /// The stream is typically obtained from `TcpListener::accept()`.
    pub fn accept(stream: TcpStream, config: TcpTransportConfig) -> Result<Self, SarError> {
        Self::from_stream(stream, config)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Generic constructor
// ──────────────────────────────────────────────────────────────────────────────

impl<S: Read + Write> TcpSarConnection<S> {
    /// Construct a connection from any `Read + Write` stream.
    ///
    /// Useful for testing with in-memory streams.  Opens transport stream 0 on
    /// the underlying in-memory TCP-policy harness.
    pub fn from_stream(stream: S, config: TcpTransportConfig) -> Result<Self, SarError> {
        let mut inner = InMemoryTransport::new_tcp(config.transport.clone());
        inner.open_transport_stream(STREAM_ID)?;
        Ok(Self {
            stream,
            inner,
            config,
            closed: false,
            outbound: OutboundControlState::new(),
        })
    }

    // ── Main processing ───────────────────────────────────────────────────────

    /// Read and process one batch of bytes from the TCP stream.
    ///
    /// Reads up to `read_buffer_size` bytes from the stream.
    /// - Returns an empty `Vec` when no bytes are available (non-blocking mode)
    ///   or after a successful but idle read.
    /// - Returns [`SarError::StreamClosed`] on EOF.
    /// - Feeds received bytes through the M10c TCP policy / session layer.
    /// - Serializes and writes outbound `SESSION_STATUS` / `SESSION_ACK`
    ///   control frames back to the stream when bidirectional control is active.
    /// - Marks the connection closed if a [`TransportAction::CloseConnection`]
    ///   action is produced.
    /// - Checks inactivity watchdog when `now_ms` is `Some`.
    ///
    /// The `now_ms` parameter accepts an explicit monotonic millisecond
    /// timestamp used for heartbeat and watchdog decisions without a background
    /// timer.  Pass `None` to skip time-based checks.
    pub fn process_available(
        &mut self,
        now_ms: Option<u64>,
    ) -> Result<Vec<TransportAction>, SarError> {
        if self.closed {
            return Err(SarError::StreamClosed("TCP connection is closed"));
        }

        // Read one bounded chunk from the stream.
        let mut buf = vec![0u8; self.config.read_buffer_size];
        let n = match self.stream.read(&mut buf) {
            Ok(0) => {
                // Peer closed the write side (EOF).
                self.handle_eof()
            }
            Ok(n) => Ok(n),
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(0)
            }
            Err(e) => return Err(SarError::Io(e)),
        }?;

        let actions = if n == 0 {
            Vec::new()
        } else {
            buf.truncate(n);
            self.inner
                .feed_bytes(STREAM_ID, &buf, now_ms)
                .unwrap_or_else(|err| vec![map_error_to_close_action(err)])
        };

        let actions = self.handle_actions(actions)?;

        // Watchdog check after feeding data.
        if let Some(now) = now_ms
            && let Err(e) = self.inner.check_inactivity(now)
        {
            self.closed = true;
            return Err(e);
        }

        Ok(actions)
    }

    /// Write raw SAR archive bytes to the TCP connection.
    ///
    /// The caller is responsible for constructing valid SAR bytes (global
    /// header + entries).  Bytes are written atomically via `write_all`.
    ///
    /// Returns [`SarError::LimitExceeded`] if `bytes.len() >
    /// write_buffer_size`.
    pub fn write_all_sar_bytes(&mut self, bytes: &[u8]) -> Result<(), SarError> {
        if self.closed {
            return Err(SarError::StreamClosed("TCP connection is closed"));
        }
        if bytes.len() > self.config.write_buffer_size {
            return Err(SarError::LimitExceeded(
                "write chunk exceeds configured write buffer size",
            ));
        }
        self.stream.write_all(bytes).map_err(SarError::Io)
    }

    /// Flush pending write bytes to the underlying stream.
    pub fn flush(&mut self) -> Result<(), SarError> {
        if self.closed {
            return Err(SarError::StreamClosed("TCP connection is closed"));
        }
        self.stream.flush().map_err(SarError::Io)
    }

    /// Close the connection gracefully.
    ///
    /// Marks the connection as closed, finalises the underlying transport
    /// stream, and flushes the write buffer.  Subsequent calls are no-ops.
    ///
    /// For `TcpStream`, callers may additionally call
    /// `stream.shutdown(Shutdown::Write)` after obtaining the inner stream.
    pub fn close(&mut self) -> Result<(), SarError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.inner.close_transport_stream(STREAM_ID);
        let _ = self.stream.flush();
        Ok(())
    }

    /// Returns `true` when the connection has been closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns `true` when SAR Stream ID `sar_stream_id` is currently bound.
    #[must_use]
    pub fn is_sar_stream_bound(&self, sar_stream_id: u16) -> bool {
        self.inner.is_sar_stream_bound(sar_stream_id)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn handle_eof(&mut self) -> Result<usize, SarError> {
        self.closed = true;
        Err(SarError::StreamClosed("TCP peer closed the connection"))
    }

    /// Drive action side-effects: serialize/emit control frames and update
    /// connection state.
    fn handle_actions(
        &mut self,
        actions: Vec<TransportAction>,
    ) -> Result<Vec<TransportAction>, SarError> {
        let mut result = Vec::with_capacity(actions.len());
        for action in actions {
            match &action {
                TransportAction::EmitSessionStatus {
                    sar_stream_id,
                    frame,
                } => {
                    if self.config.transport.bidirectional_control {
                        let limits = ResourceLimits::default();
                        match frame.to_bytes(&limits) {
                            Ok(payload) => {
                                let _ = self.write_outbound_control_frame(
                                    *sar_stream_id,
                                    SessionOpCode::Status as u8,
                                    &payload,
                                );
                            }
                            Err(_) => {
                                // Serialization failed; action is still returned.
                            }
                        }
                    }
                }
                TransportAction::EmitSessionAck {
                    sar_stream_id,
                    frame,
                } => {
                    if self.config.transport.bidirectional_control {
                        match frame.to_bytes() {
                            Ok(payload) => {
                                let _ = self.write_outbound_control_frame(
                                    *sar_stream_id,
                                    SessionOpCode::Ack as u8,
                                    &payload,
                                );
                            }
                            Err(_) => {
                                // Serialization failed; action is still returned.
                            }
                        }
                    }
                }
                TransportAction::CloseConnection { .. } => {
                    self.closed = true;
                }
                _ => {}
            }
            result.push(action);
        }
        Ok(result)
    }

    /// Serialize one outbound SESSION_STATUS or SESSION_ACK entry and write it
    /// to the stream.
    ///
    /// Writes a NO_INDEX global header before the very first control frame.
    fn write_outbound_control_frame(
        &mut self,
        sar_stream_id: u16,
        opcode: u8,
        payload: &[u8],
    ) -> Result<(), SarError> {
        // Enforce write buffer limit.
        let lfh_overhead: usize = 64; // conservative LFH upper bound
        let total = lfh_overhead
            .checked_add(payload.len())
            .ok_or(SarError::Overflow("control frame total size"))?;
        if total > self.config.write_buffer_size {
            return Err(SarError::LimitExceeded(
                "outbound control frame exceeds write buffer size",
            ));
        }

        // Write global header once.
        if !self.outbound.global_header_written {
            let flags = GlobalFlags::NO_INDEX;
            let header = GlobalHeader {
                version: 1,
                flags_bytes: flags.bits().to_le_bytes().to_vec(),
                flags,
                partition_descriptor: None,
                kms: None,
            };
            let hdr_bytes = write_global_header(&header)
                .map_err(|_| SarError::Internal("global header write"))?;
            self.stream.write_all(&hdr_bytes).map_err(SarError::Io)?;
            self.outbound.global_header_written = true;
        }

        // Build and write the LFH + payload.
        let mut lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), payload.len() as u64);
        lfh.stream_id = sar_stream_id;
        lfh.sequence_no = self.outbound.sequence_no;
        lfh.entry_mode =
            EntryMode::from_bits((u16::from(opcode) << 8) | EntryMode::SESSION_CONTROL);
        lfh.payload_size = payload.len() as u64;
        lfh.uncompressed_size = payload.len() as u64;

        let lfh_bytes =
            write_lfh(&GlobalFlags::NO_INDEX, &lfh).map_err(|_| SarError::Internal("lfh write"))?;
        self.stream.write_all(&lfh_bytes).map_err(SarError::Io)?;
        self.stream.write_all(payload).map_err(SarError::Io)?;

        // Increment sequence; wrapping on u16 is intentional (same as SAR spec).
        self.outbound.sequence_no = self.outbound.sequence_no.wrapping_add(1);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// The single fixed transport-stream ID used by TCP connections.
///
/// TCP is a single byte stream; only one SAR session is active at a time.
pub const STREAM_ID: TransportStreamId = TransportStreamId(0);

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Convert a hard policy error into a synthetic `CloseConnection` action.
///
/// Used when `InMemoryTransport::feed_bytes` returns an `Err` that should be
/// surfaced as an action rather than propagated as a fatal `process_available`
/// error.
fn map_error_to_close_action(err: SarError) -> TransportAction {
    TransportAction::CloseConnection { error: err }
}
