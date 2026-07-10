//! Server identity types for SAR-over-QUIC.
//!
//! These types carry TLS credentials in DER format and are independent of
//! any runtime or TLS library version details.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sar_core::SarError;

// ──────────────────────────────────────────────────────────────────────────────
// Server identity
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum certificate chain size in bytes.
pub const MAX_CERT_CHAIN_BYTES: usize = 64 * 1024;
/// Maximum private key size in bytes.
pub const MAX_PRIVATE_KEY_BYTES: usize = 8 * 1024;

/// TLS server identity: certificate chain and private key in DER format.
///
/// The certificate chain must contain at least the end-entity certificate.
/// Intermediate CA certificates should be appended in order (leaf first).
///
/// The private key DER must correspond to the end-entity certificate.
///
/// # Security
///
/// Private key material is stored in memory only for the duration needed to
/// build the TLS server configuration.  It is **never** logged, serialised to
/// SAR frames, or placed in KMS data.
pub struct QuicServerIdentity {
    /// Certificate chain in DER format, leaf first.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Private key DER.
    pub private_key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for QuicServerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServerIdentity")
            .field("cert_count", &self.cert_chain.len())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl QuicServerIdentity {
    /// Construct from raw DER byte buffers with basic size checks.
    ///
    /// `cert_chain_ders` must be a non-empty list of certificate DER byte
    /// slices, ordered leaf-first.
    ///
    /// `private_key_der` must be a PKCS#8 or SEC1/PKCS#1 DER blob whose
    /// total length must not exceed [`MAX_PRIVATE_KEY_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`SarError::LimitExceeded`] if a certificate exceeds
    /// [`MAX_CERT_CHAIN_BYTES`] or the key exceeds [`MAX_PRIVATE_KEY_BYTES`].
    /// Returns [`SarError::Malformed`] if `cert_chain_ders` is empty.
    pub fn from_der(
        cert_chain_ders: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
    ) -> Result<Self, SarError> {
        if cert_chain_ders.is_empty() {
            return Err(SarError::Malformed(
                "QuicServerIdentity: certificate chain must not be empty",
            ));
        }
        let total_cert_bytes: usize = cert_chain_ders.iter().map(|c| c.len()).sum();
        if total_cert_bytes > MAX_CERT_CHAIN_BYTES {
            return Err(SarError::LimitExceeded(
                "QuicServerIdentity: certificate chain exceeds size limit",
            ));
        }
        if private_key_der.len() > MAX_PRIVATE_KEY_BYTES {
            return Err(SarError::LimitExceeded(
                "QuicServerIdentity: private key exceeds size limit",
            ));
        }
        let cert_chain = cert_chain_ders
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private_key = PrivateKeyDer::try_from(private_key_der).map_err(|_| {
            SarError::Malformed("QuicServerIdentity: unrecognised private key DER format")
        })?;
        Ok(Self {
            cert_chain,
            private_key,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client trust
// ──────────────────────────────────────────────────────────────────────────────

/// Client-side TLS trust configuration for SAR-over-QUIC.
///
/// Determines which server certificates the QUIC client will accept.
///
/// # Security
///
/// Certificate verification is enforced by default.  The
/// `InsecureSkipVerifyForTestsOnly` variant **must never be used in
/// production**.  Its name is intentionally descriptive to prevent accidental
/// misuse.
#[derive(Debug)]
pub enum QuicClientTrust {
    /// Trust a single custom CA certificate in DER format.
    ///
    /// The client will accept server certificates signed by this CA.
    CustomCaDer(Vec<u8>),

    /// **Test-only**: skip all TLS certificate verification.
    ///
    /// # Warning
    ///
    /// This variant disables all server authentication.  Any server certificate
    /// will be accepted, including self-signed certificates with arbitrary
    /// subject names.  **Never use this in production.**
    InsecureSkipVerifyForTestsOnly,
}
