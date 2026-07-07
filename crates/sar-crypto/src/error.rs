use thiserror::Error;

/// Errors produced by SAR crypto primitives and KMS helpers.
#[derive(Debug, Error)]
pub enum SarCryptoError {
    /// Authentication failed for the named algorithm or stage.
    #[error("authentication failed: {0}")]
    AuthFailed(&'static str),
    /// Required key material was unavailable.
    #[error("key missing: {0}")]
    KeyMissing(&'static str),
    /// Input data was malformed.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// Feature or algorithm is recognized but unsupported.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// Reserved or unknown registry value was encountered.
    #[error("reserved value: {0}")]
    ReservedValue(&'static str),
    /// Input length was invalid.
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    /// Internal invariant or backend failure.
    #[error("internal error: {0}")]
    Internal(&'static str),
    /// Nonce reuse was detected locally.
    #[error("nonce reuse detected")]
    NonceReuse,
    /// Flags or configuration values conflict.
    #[error("flag conflict: {0}")]
    FlagConflict(&'static str),
}
