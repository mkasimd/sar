// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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
// TLS PQ/hybrid key agreement policy (Section 18.6.7)
// ──────────────────────────────────────────────────────────────────────────────

/// TLS key agreement policy for SAR-over-QUIC connections.
///
/// Aligns with Section 18.6.7 of the SAR specification.  Controls which TLS
/// key agreement algorithms are offered and accepted, and how the implementation
/// behaves when the desired algorithm class cannot be negotiated or verified.
///
/// # Spec names
///
/// Each variant maps to one of the four spec-defined policy names:
///
/// | Variant | Spec name |
/// |---|---|
/// | `ClassicalAllowed` | `CLASSICAL_ALLOWED` |
/// | `PreferPq` | `PREFER_PQ` |
/// | `RequirePqOrHybrid` | `REQUIRE_PQ_OR_HYBRID` |
/// | `RequirePqOnly` | `REQUIRE_PQ_ONLY` |
///
/// # Default
///
/// The default is [`ClassicalAllowed`] when the TLS stack does not expose any
/// PQ-safe or hybrid key agreement algorithms accepted by local policy (as is
/// the case with the `ring` provider used in this crate).  If a TLS provider
/// that supports PQ or hybrid groups is configured, the default SHOULD be
/// changed to [`PreferPq`] in accordance with the spec.
///
/// [`ClassicalAllowed`]: TlsPqPolicy::ClassicalAllowed
/// [`PreferPq`]: TlsPqPolicy::PreferPq
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsPqPolicy {
    /// **`CLASSICAL_ALLOWED`** — Classical, hybrid post-quantum, and
    /// post-quantum-safe TLS key agreement algorithms are all permitted when
    /// supported by the TLS stack and accepted by local policy.
    ///
    /// If PQ-safe or hybrid algorithms are available, they SHOULD be preferred
    /// over classical algorithms where the TLS stack allows preference ordering.
    ///
    /// This is the default when no PQ-safe or hybrid key agreement algorithm is
    /// supported by the active TLS provider.
    #[default]
    ClassicalAllowed,

    /// **`PREFER_PQ`** — Post-quantum-safe or hybrid post-quantum TLS key
    /// agreement is preferred.
    ///
    /// Classical TLS key agreement remains permitted only if no acceptable
    /// PQ-safe or hybrid algorithm can be negotiated.  With the `ring` provider
    /// used in this crate, no PQ/hybrid groups are available and this policy
    /// falls back to classical without error.
    ///
    /// Implementations MUST NOT claim PQ or HNDL protection for a connection
    /// where only classical key agreement was negotiated.
    PreferPq,

    /// **`REQUIRE_PQ_OR_HYBRID`** — The TLS session MUST negotiate a
    /// post-quantum-safe or hybrid post-quantum TLS key agreement accepted by
    /// policy.
    ///
    /// Classical-only key agreement MUST fail closed.  If the TLS stack cannot
    /// configure, negotiate, or confirm an acceptable PQ-safe or hybrid group,
    /// the connection attempt MUST fail with [`SarError::Unsupported`].
    ///
    /// This mode is currently **not supported** with the `ring` TLS provider
    /// because `ring` does not expose PQ or hybrid key agreement groups.
    /// Attempting to build a [`QuicServerConfig`] or [`QuicClientConfig`] with
    /// this policy and the `ring` provider returns `SAR_ERR_UNSUPPORTED`.
    ///
    /// [`SarError::Unsupported`]: sar_core::SarError::Unsupported
    /// [`QuicServerConfig`]: crate::quic::QuicServerConfig
    /// [`QuicClientConfig`]: crate::quic::QuicClientConfig
    RequirePqOrHybrid,

    /// **`REQUIRE_PQ_ONLY`** — The TLS session MUST negotiate a post-quantum-
    /// safe TLS key agreement accepted by policy.  Hybrid and classical key
    /// agreement MUST fail closed.
    ///
    /// This mode is currently **not supported** with the `ring` TLS provider.
    /// Attempting to build a [`QuicServerConfig`] or [`QuicClientConfig`] with
    /// this policy and the `ring` provider returns `SAR_ERR_UNSUPPORTED`.
    ///
    /// [`QuicServerConfig`]: crate::quic::QuicServerConfig
    /// [`QuicClientConfig`]: crate::quic::QuicClientConfig
    RequirePqOnly,
}

impl TlsPqPolicy {
    /// Returns `true` if this policy permits classical-only TLS key agreement.
    #[must_use]
    pub const fn allows_classical_fallback(self) -> bool {
        matches!(self, Self::ClassicalAllowed | Self::PreferPq)
    }

    /// Returns `true` if this policy requires PQ-safe or hybrid key agreement
    /// and MUST fail closed when it cannot be satisfied.
    #[must_use]
    pub const fn requires_pq(self) -> bool {
        matches!(self, Self::RequirePqOrHybrid | Self::RequirePqOnly)
    }

    /// Returns `true` if this policy requires PQ-only (non-hybrid) key
    /// agreement and MUST fail closed when it cannot be satisfied.
    #[must_use]
    pub const fn requires_pq_only(self) -> bool {
        matches!(self, Self::RequirePqOnly)
    }
}

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
    /// TLS key agreement policy per Section 18.6.7.
    ///
    /// Controls which TLS key agreement algorithm classes are offered and
    /// required.  The default is [`TlsPqPolicy::ClassicalAllowed`] because the
    /// bundled `ring` TLS provider does not expose PQ-safe or hybrid key
    /// agreement groups.  Set to [`TlsPqPolicy::PreferPq`] when a TLS provider
    /// that supports PQ or hybrid groups is in use.
    ///
    /// Setting this to [`TlsPqPolicy::RequirePqOrHybrid`] or
    /// [`TlsPqPolicy::RequirePqOnly`] with the `ring` provider will cause
    /// connection setup to fail with `SAR_ERR_UNSUPPORTED`.
    pub pq_policy: TlsPqPolicy,
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
            pq_policy: TlsPqPolicy::ClassicalAllowed,
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
