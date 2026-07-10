//! Configuration types for SAR-over-QUIC.

use sar_core::SarError;

use crate::TransportConfig;
use crate::quic::identity::{QuicClientTrust, QuicServerIdentity};

// ──────────────────────────────────────────────────────────────────────────────
// Limits
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum concurrent QUIC connections accepted by one [`QuicSarListener`].
///
/// [`QuicSarListener`]: crate::quic::QuicSarListener
pub const MAX_CONNECTIONS: usize = 1024;
/// Maximum concurrent bidirectional QUIC streams per connection.
pub const MAX_QUIC_STREAMS_PER_CONNECTION: u64 = 256;
/// Maximum bytes buffered per QUIC stream read chunk.
pub const MAX_READ_CHUNK_BYTES: usize = 64 * 1024;
/// Maximum bytes in a single outbound write.
pub const MAX_OUTBOUND_WRITE_BYTES: usize = 64 * 1024;
/// Maximum bytes buffered for a STATUS / ACK outbound payload.
pub const MAX_STATUS_ACK_BYTES: usize = 4096;

// ──────────────────────────────────────────────────────────────────────────────
// Transport config
// ──────────────────────────────────────────────────────────────────────────────

/// Runtime limits and policy settings for a SAR-over-QUIC connection.
#[derive(Debug, Clone)]
pub struct QuicTransportConfig {
    /// Underlying SAR transport / session policy settings.
    pub transport: TransportConfig,
    /// Maximum bytes read per stream-processing call.
    pub read_chunk_bytes: usize,
    /// Maximum bytes sent per `write_sar_bytes` call.
    pub outbound_write_bytes: usize,
    /// Maximum concurrent bidirectional QUIC streams per connection.
    pub max_quic_streams_per_connection: u64,
    /// Maximum concurrent accepted QUIC connections.
    pub max_connections: usize,
    /// Whether the local endpoint will advertise `CAP_TLS_EXPORTER_AEAD`.
    ///
    /// Set to `true` only when TLS exporter material is expected to be
    /// available (i.e. in a QUIC + TLS session using quinn ≥ 0.11).
    pub advertise_tls_exporter_aead: bool,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            read_chunk_bytes: MAX_READ_CHUNK_BYTES,
            outbound_write_bytes: MAX_OUTBOUND_WRITE_BYTES,
            max_quic_streams_per_connection: MAX_QUIC_STREAMS_PER_CONNECTION,
            max_connections: MAX_CONNECTIONS,
            advertise_tls_exporter_aead: true,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Server config
// ──────────────────────────────────────────────────────────────────────────────

/// TLS + QUIC server configuration for [`QuicSarListener`].
///
/// The server identity (certificate chain + private key) must be provided
/// explicitly.  There is no default / auto-generate mode in production code.
///
/// [`QuicSarListener`]: crate::quic::QuicSarListener
pub struct QuicServerConfig {
    /// Server TLS identity.
    pub identity: QuicServerIdentity,
    /// Transport and session-layer limits.
    pub transport: QuicTransportConfig,
}

impl std::fmt::Debug for QuicServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServerConfig")
            .field("identity", &self.identity)
            .field("transport", &self.transport)
            .finish()
    }
}

impl QuicServerConfig {
    /// Construct with an explicit server identity and transport configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] if `max_connections` is `0`.
    pub fn new(
        identity: QuicServerIdentity,
        transport: QuicTransportConfig,
    ) -> Result<Self, SarError> {
        if transport.max_connections == 0 {
            return Err(SarError::LimitExceeded(
                "QuicServerConfig: max_connections must be > 0",
            ));
        }
        Ok(Self {
            identity,
            transport,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client config
// ──────────────────────────────────────────────────────────────────────────────

/// TLS + QUIC client configuration for connecting to a [`QuicSarListener`].
///
/// [`QuicSarListener`]: crate::quic::QuicSarListener
#[derive(Debug)]
pub struct QuicClientConfig {
    /// Client trust policy.
    pub trust: QuicClientTrust,
    /// Transport and session-layer limits.
    pub transport: QuicTransportConfig,
}

impl QuicClientConfig {
    /// Construct with an explicit trust policy and transport configuration.
    #[must_use]
    pub fn new(trust: QuicClientTrust, transport: QuicTransportConfig) -> Self {
        Self { trust, transport }
    }
}
