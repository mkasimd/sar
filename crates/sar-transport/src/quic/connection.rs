//! SAR-over-QUIC listener, connection, and stream types.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig as RustlsQuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig as RustlsServerConfig;
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, ResourceLimits, SarError,
    write_global_header, write_lfh,
};
use sar_stream::{CapabilityFlags, SessionOpCode};

use crate::quic::config::{QuicClientConfig, QuicServerConfig, QuicTransportConfig};
use crate::quic::identity::QuicClientTrust;
use crate::{InMemoryTransport, SarTransportBinding, TransportAction, TransportStreamId};

// ──────────────────────────────────────────────────────────────────────────────
// QuicSarListener
// ──────────────────────────────────────────────────────────────────────────────

/// SAR-over-QUIC listener.
///
/// Binds to a local UDP address and accepts QUIC connections.  Each accepted
/// connection becomes a [`QuicSarConnection`] that can carry multiple
/// concurrent SAR sessions.
///
/// # Security
///
/// Server TLS identity (certificate + key) must be supplied via
/// [`QuicServerConfig`].  There is no insecure / cleartext fallback.
pub struct QuicSarListener {
    endpoint: Endpoint,
    config: QuicServerConfig,
}

impl QuicSarListener {
    /// Bind a new QUIC listener on `addr`.
    ///
    /// Builds the server TLS configuration from `config.identity` and binds
    /// the underlying UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`SarError`] if TLS configuration fails (e.g. unsupported key
    /// type) or if the UDP socket cannot be bound.
    pub fn bind(addr: SocketAddr, config: QuicServerConfig) -> Result<Self, SarError> {
        let rustls_cfg = build_rustls_server_config(&config)?;
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(rustls_cfg));
        let endpoint = Endpoint::server(server_cfg, addr)
            .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC bind: {e}"))))?;
        Ok(Self { endpoint, config })
    }

    /// Returns the local address the listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::Io`] if the local address cannot be determined.
    pub fn local_addr(&self) -> Result<SocketAddr, SarError> {
        self.endpoint.local_addr().map_err(SarError::Io)
    }

    /// Accept the next incoming QUIC connection.
    ///
    /// Returns a [`QuicSarConnection`] once the QUIC handshake completes.
    /// The connection is in server (TLS-server) role.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::StreamClosed`] when the listener endpoint is
    /// closed.  Returns [`SarError::Io`] for QUIC handshake failures.
    pub async fn accept(&self) -> Result<QuicSarConnection, SarError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(SarError::StreamClosed("QUIC listener closed"))?;
        let connection = incoming
            .await
            .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC handshake: {e}"))))?;
        Ok(QuicSarConnection::new(
            connection,
            self.config.transport.clone(),
            false, // server is not the TLS client
        ))
    }

    /// Close the listener and stop accepting new connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"listener closed");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client connect
// ──────────────────────────────────────────────────────────────────────────────

/// Connect to a SAR-over-QUIC server.
///
/// Builds the client TLS configuration from `config.trust`, creates a QUIC
/// endpoint, and completes the QUIC handshake with the server at `server_addr`.
///
/// `server_name` is the DNS name or IP used for TLS SNI and certificate
/// verification.
///
/// # Errors
///
/// Returns [`SarError`] if TLS configuration fails, the UDP socket cannot be
/// bound, or the QUIC handshake fails.
pub async fn connect_quic(
    server_addr: SocketAddr,
    server_name: &str,
    config: QuicClientConfig,
) -> Result<QuicSarConnection, SarError> {
    let client_tls = build_rustls_client_config(&config.trust)?;
    let quic_client_cfg = RustlsQuicClientConfig::try_from(client_tls)
        .map_err(|_| SarError::Internal("QUIC client TLS config conversion"))?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_client_cfg));

    let bind_addr: SocketAddr = if server_addr.is_ipv6() {
        "[::]:0"
            .parse()
            .map_err(|_| SarError::Internal("bind addr parse"))?
    } else {
        "0.0.0.0:0"
            .parse()
            .map_err(|_| SarError::Internal("bind addr parse"))?
    };

    let mut endpoint = Endpoint::client(bind_addr)
        .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC client bind: {e}"))))?;
    endpoint.set_default_client_config(client_cfg);

    // Validate the server name before calling connect.
    rustls_pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|_| SarError::Malformed("QuicClientConfig: invalid server name"))?;

    let connection = endpoint
        .connect(server_addr, server_name)
        .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC connect: {e}"))))?
        .await
        .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC handshake: {e}"))))?;

    Ok(QuicSarConnection::new(
        connection,
        config.transport,
        true, // client is the TLS client
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// QuicSarConnection
// ──────────────────────────────────────────────────────────────────────────────

/// A SAR-over-QUIC connection that may carry multiple concurrent SAR sessions.
///
/// Each SAR session is established via a primary QUIC stream carrying a SAR
/// Global Header and `SESSION_INIT`.  Additional control streams for
/// `SESSION_ACK` / `SESSION_STATUS` may be associated with an existing SAR
/// session using the same SAR Stream ID and Session UUID.
///
/// # Key usage direction
///
/// [`is_tls_client`](Self::is_tls_client) identifies the TLS-transport role:
/// * `true` = this endpoint initiated the QUIC connection (TLS client).
/// * `false` = this endpoint accepted the QUIC connection (TLS server).
///
/// For `TLS_EXPORTER` SAR-AEAD, SAR entries sent by the TLS client use
/// `CLIENT_TO_SERVER_ENTRY`, and entries sent by the TLS server use
/// `SERVER_TO_CLIENT_ENTRY`.
pub struct QuicSarConnection {
    conn: quinn::Connection,
    inner: InMemoryTransport,
    config: QuicTransportConfig,
    closed: bool,
    is_tls_client: bool,
    next_stream_id: u64,
    /// Outbound control state per SAR stream ID.
    outbound_control: BTreeMap<u16, OutboundControlState>,
    /// Bytes accumulated by synchronous control-frame serialisation.
    ///
    /// Callers must flush these via [`Self::flush_pending_control_frames`]
    /// after each call to [`Self::feed_stream_bytes`].
    pending_control_bytes: Vec<u8>,
}

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

impl QuicSarConnection {
    pub(crate) fn new(
        conn: quinn::Connection,
        config: QuicTransportConfig,
        is_tls_client: bool,
    ) -> Self {
        let inner = InMemoryTransport::new_quic(config.transport.clone());
        Self {
            conn,
            inner,
            config,
            closed: false,
            is_tls_client,
            next_stream_id: 0,
            outbound_control: BTreeMap::new(),
            pending_control_bytes: Vec::new(),
        }
    }

    /// Returns `true` if this endpoint initiated the QUIC connection (TLS client).
    #[must_use]
    pub const fn is_tls_client(&self) -> bool {
        self.is_tls_client
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

    /// Returns the session UUID for the given active SAR stream, if known.
    #[must_use]
    pub fn session_uuid_for(&self, sar_stream_id: u16) -> Option<[u8; 16]> {
        self.inner.session_uuid_for(sar_stream_id)
    }

    /// Returns the local key-usage ID for SAR-AEAD based on TLS role.
    ///
    /// * TLS client → [`sar_crypto::TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER`]
    /// * TLS server → [`sar_crypto::TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT`]
    #[must_use]
    pub fn local_key_usage_id(&self) -> u8 {
        if self.is_tls_client {
            sar_crypto::TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER
        } else {
            sar_crypto::TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT
        }
    }

    /// Derive SAR AEAD keying material from the TLS exporter for this connection.
    ///
    /// `label` must be an ASCII TLS exporter label (e.g.
    /// [`sar_crypto::EXPORTER_LABEL_QUIC_AEAD`]).  `context` is the encoded
    /// TLS exporter context (e.g. from
    /// [`sar_crypto::encode_tls_exporter_context_v1`]).  `output` is filled
    /// with exactly `output.len()` bytes of derived keying material.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::Unsupported`] if the TLS stack does not expose
    /// exporter material (connection is closed or not yet established).
    /// Returns [`SarError::Internal`] for unexpected exporter errors.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> Result<(), SarError> {
        self.conn
            .export_keying_material(output, label, context)
            .map_err(|_| SarError::Unsupported("TLS exporter: keying material unavailable"))
    }

    /// Open a new outbound bidirectional QUIC stream for a SAR session.
    ///
    /// Returns a [`QuicSarStream`] that the caller can use to send SAR bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] if the QUIC stream limit is
    /// reached.  Returns [`SarError::Io`] for transport-level errors.
    pub async fn open_sar_stream(&mut self) -> Result<QuicSarStream, SarError> {
        if self.closed {
            return Err(SarError::StreamClosed("QUIC connection is closed"));
        }
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| SarError::Io(std::io::Error::other(format!("open_bi: {e}"))))?;
        let tsid = self.alloc_transport_stream_id();
        self.inner.open_transport_stream(tsid)?;
        Ok(QuicSarStream {
            send,
            recv,
            transport_stream_id: tsid,
            config: self.config.clone(),
        })
    }

    /// Accept the next inbound bidirectional QUIC stream.
    ///
    /// Returns a [`QuicSarStream`] that the caller can use to receive SAR
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::StreamClosed`] when the connection is closed.
    /// Returns [`SarError::Io`] for transport-level errors.
    pub async fn accept_sar_stream(&mut self) -> Result<QuicSarStream, SarError> {
        if self.closed {
            return Err(SarError::StreamClosed("QUIC connection is closed"));
        }
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| SarError::Io(std::io::Error::other(format!("accept_bi: {e}"))))?;
        let tsid = self.alloc_transport_stream_id();
        self.inner.open_transport_stream(tsid)?;
        Ok(QuicSarStream {
            send,
            recv,
            transport_stream_id: tsid,
            config: self.config.clone(),
        })
    }

    /// Feed SAR bytes received from a QUIC stream into the session layer.
    ///
    /// Processes received bytes through the QUIC-policy transport harness.
    /// Returns a list of [`TransportAction`] items that describe session events
    /// (e.g. `BindSarStream`, `AttachControlStream`, `EmitSessionAck`, etc.).
    ///
    /// Outbound `SESSION_STATUS` / `SESSION_ACK` frames are serialised and
    /// written back to `stream` when bidirectional control is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::StreamClosed`] if the connection is closed.
    /// Returns [`SarError::LimitExceeded`] if the byte chunk exceeds the
    /// configured read limit.
    pub fn feed_stream_bytes(
        &mut self,
        stream: &mut QuicSarStream,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<Vec<TransportAction>, SarError> {
        if self.closed {
            return Err(SarError::StreamClosed("QUIC connection is closed"));
        }
        if bytes.len() > self.config.read_chunk_bytes {
            return Err(SarError::LimitExceeded(
                "QUIC stream read chunk exceeds configured limit",
            ));
        }
        let tsid = stream.transport_stream_id;
        let actions = self
            .inner
            .feed_bytes(tsid, bytes, now_ms)
            .unwrap_or_else(|err| vec![TransportAction::CloseConnection { error: err }]);

        let actions = self.handle_actions(actions)?;
        Ok(actions)
    }

    /// Write raw SAR bytes to a QUIC stream's send side.
    ///
    /// Returns [`SarError::LimitExceeded`] if `bytes.len()` exceeds
    /// [`QuicTransportConfig::outbound_write_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`SarError::Io`] on send failure.
    pub async fn write_sar_bytes(
        &self,
        stream: &mut QuicSarStream,
        bytes: &[u8],
    ) -> Result<(), SarError> {
        if bytes.len() > self.config.outbound_write_bytes {
            return Err(SarError::LimitExceeded(
                "QUIC outbound write exceeds configured limit",
            ));
        }
        stream
            .send
            .write_all(bytes)
            .await
            .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC write: {e}"))))
    }

    /// Read up to `read_chunk_bytes` from the receive side of a QUIC stream.
    ///
    /// Returns `None` on end-of-stream (remote closed their send side).
    ///
    /// # Errors
    ///
    /// Returns [`SarError::Io`] on receive errors.
    pub async fn read_stream_bytes(
        &self,
        stream: &mut QuicSarStream,
    ) -> Result<Option<Vec<u8>>, SarError> {
        let max = self.config.read_chunk_bytes;
        let mut buf = vec![0u8; max];
        match stream.recv.read(&mut buf).await {
            Ok(None) => Ok(None),
            Ok(Some(n)) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) => Err(SarError::Io(std::io::Error::other(format!(
                "QUIC recv: {e}"
            )))),
        }
    }

    /// Close the connection gracefully.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.conn.close(0u32.into(), b"SAR connection closed");
    }

    // ── Capability advertisement ──────────────────────────────────────────────

    /// Returns the local [`CapabilityFlags`] that this QUIC endpoint will
    /// advertise in `SESSION_CAPABILITIES`.
    ///
    /// Includes `CAP_TLS_EXPORTER_AEAD` when configured via
    /// [`QuicTransportConfig::advertise_tls_exporter_aead`].
    #[must_use]
    pub fn local_capabilities(&self) -> CapabilityFlags {
        let mut bits = 0u16;
        if self.config.transport.bidirectional_control {
            bits |= CapabilityFlags::SESSION_ACK | CapabilityFlags::SESSION_STATUS;
        }
        if self.config.advertise_tls_exporter_aead {
            bits |= CapabilityFlags::CAP_TLS_EXPORTER_AEAD;
        }
        CapabilityFlags::from_bits(bits)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn alloc_transport_stream_id(&mut self) -> TransportStreamId {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        TransportStreamId(id)
    }

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
                        if let Ok(payload) = frame.to_bytes(&limits) {
                            let _ = self.write_outbound_control_frame_sync(
                                *sar_stream_id,
                                SessionOpCode::Status as u8,
                                &payload,
                            );
                        }
                    }
                }
                TransportAction::EmitSessionAck {
                    sar_stream_id,
                    frame,
                } => {
                    if self.config.transport.bidirectional_control
                        && let Ok(payload) = frame.to_bytes()
                    {
                        let _ = self.write_outbound_control_frame_sync(
                            *sar_stream_id,
                            SessionOpCode::Ack as u8,
                            &payload,
                        );
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

    /// Flush any control frames accumulated by [`Self::feed_stream_bytes`].
    ///
    /// Must be called after `feed_stream_bytes` when bidirectional control is
    /// enabled to deliver buffered `SESSION_ACK` / `SESSION_STATUS` bytes to
    /// the remote peer.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::Io`] on send failure.
    pub async fn flush_pending_control_frames(
        &mut self,
        stream: &mut QuicSarStream,
    ) -> Result<(), SarError> {
        if self.pending_control_bytes.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.pending_control_bytes);
        stream
            .send
            .write_all(&bytes)
            .await
            .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC control flush: {e}"))))
    }

    /// Serialise a SAR control frame and append it to the outbound buffer.
    ///
    /// The buffered bytes are flushed to the wire by
    /// [`Self::flush_pending_control_frames`].
    fn write_outbound_control_frame_sync(
        &mut self,
        sar_stream_id: u16,
        opcode: u8,
        payload: &[u8],
    ) -> Result<(), SarError> {
        // Enforce write buffer limit.
        let lfh_overhead: usize = 64;
        let total = lfh_overhead
            .checked_add(payload.len())
            .ok_or(SarError::Overflow("control frame size"))?;
        if total > self.config.outbound_write_bytes {
            return Err(SarError::LimitExceeded(
                "outbound control frame exceeds configured write size",
            ));
        }

        let state = self
            .outbound_control
            .entry(sar_stream_id)
            .or_insert_with(OutboundControlState::new);

        let mut frame_bytes = Vec::new();

        // Write global header once.
        if !state.global_header_written {
            let flags = GlobalFlags::NO_INDEX;
            let header = GlobalHeader {
                version: 1,
                flags_bytes: flags.bits().to_le_bytes().to_vec(),
                flags,
                partition_descriptor: None,
                kms: None,
            };
            let hdr = write_global_header(&header)
                .map_err(|_| SarError::Internal("control stream global header"))?;
            frame_bytes.extend_from_slice(&hdr);
            state.global_header_written = true;
        }

        let mut lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), payload.len() as u64);
        lfh.stream_id = sar_stream_id;
        lfh.sequence_no = state.sequence_no;
        lfh.entry_mode =
            EntryMode::from_bits((u16::from(opcode) << 8) | EntryMode::SESSION_CONTROL);
        lfh.payload_size = payload.len() as u64;
        lfh.uncompressed_size = payload.len() as u64;

        let lfh_bytes =
            write_lfh(&GlobalFlags::NO_INDEX, &lfh).map_err(|_| SarError::Internal("lfh write"))?;
        frame_bytes.extend_from_slice(&lfh_bytes);
        frame_bytes.extend_from_slice(payload);

        state.sequence_no = state.sequence_no.wrapping_add(1);

        // Append to pending buffer; flushed asynchronously by
        // `flush_pending_control_frames`.
        self.pending_control_bytes.extend_from_slice(&frame_bytes);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// QuicSarStream
// ──────────────────────────────────────────────────────────────────────────────

/// One bidirectional QUIC stream used for SAR streaming.
///
/// A `QuicSarStream` wraps a quinn bidirectional stream pair and provides
/// an associated [`TransportStreamId`] used to route bytes through the
/// [`InMemoryTransport`] session harness.
pub struct QuicSarStream {
    /// Outbound send half.
    pub send: SendStream,
    /// Inbound receive half.
    pub recv: RecvStream,
    /// Transport stream identifier within the parent connection's harness.
    pub transport_stream_id: TransportStreamId,
    config: QuicTransportConfig,
}

impl std::fmt::Debug for QuicSarStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicSarStream")
            .field("transport_stream_id", &self.transport_stream_id)
            .finish()
    }
}

impl QuicSarStream {
    /// Returns the transport stream identifier.
    #[must_use]
    pub const fn transport_stream_id(&self) -> TransportStreamId {
        self.transport_stream_id
    }

    /// Finish the outbound (send) side of this stream.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::Io`] if the send side is already closed.
    pub fn finish_send(&mut self) -> Result<(), SarError> {
        self.send
            .finish()
            .map_err(|e| SarError::Io(std::io::Error::other(format!("QUIC finish: {e}"))))
    }

    /// Returns the configured maximum read chunk size.
    #[must_use]
    pub fn read_chunk_bytes(&self) -> usize {
        self.config.read_chunk_bytes
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS configuration builders
// ──────────────────────────────────────────────────────────────────────────────

fn build_rustls_server_config(config: &QuicServerConfig) -> Result<RustlsServerConfig, SarError> {
    let key = config.identity.private_key.clone_key();
    let cert_chain = config.identity.cert_chain.clone();

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();

    let tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| {
            SarError::Internal(
                // Use a static message since the error type is not easily inspected.
                if format!("{e}").is_empty() {
                    "TLS server config: version selection"
                } else {
                    "TLS server config: unsupported"
                },
            )
        })?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| {
            SarError::Malformed(if format!("{e}").contains("key") {
                "TLS server config: invalid private key"
            } else {
                "TLS server config: cert/key mismatch"
            })
        })?;

    RustlsServerConfig::try_from(Arc::new(tls_cfg))
        .map_err(|_| SarError::Internal("QUIC server TLS config conversion failed"))
}

fn build_rustls_client_config(trust: &QuicClientTrust) -> Result<rustls::ClientConfig, SarError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();

    let base = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| SarError::Internal("TLS client config: version selection"))?;

    match trust {
        QuicClientTrust::CustomCaDer(ca_der) => {
            let mut root_store = RootCertStore::empty();
            root_store
                .add(CertificateDer::from(ca_der.clone()))
                .map_err(|_| SarError::Malformed("QuicClientTrust: invalid CA certificate DER"))?;
            Ok(base
                .with_root_certificates(root_store)
                .with_no_client_auth())
        }
        QuicClientTrust::InsecureSkipVerifyForTestsOnly => Ok(base
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureSkipVerifier))
            .with_no_client_auth()),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Test-only certificate verifier (InsecureSkipVerifyForTestsOnly)
// ──────────────────────────────────────────────────────────────────────────────

/// **Test-only** verifier that accepts any server certificate.
///
/// This type implements [`rustls::client::danger::ServerCertVerifier`] and is
/// used only when [`QuicClientTrust::InsecureSkipVerifyForTestsOnly`] is
/// selected.  It **must never be used in production**.
#[derive(Debug)]
struct InsecureSkipVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureSkipVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls_pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
