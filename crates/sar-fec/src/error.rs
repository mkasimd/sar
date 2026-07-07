//! Error type for the `sar-fec` crate.

use std::fmt;

/// Errors returned by FEC encode/decode operations.
///
/// These map 1-to-1 with the subset of `sar_core::SarError` variants used
/// by FEC operations.  `sar-core` implements `From<FecError> for SarError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    /// Truncated structure.
    Truncated(&'static str),
    /// Malformed structure.
    Malformed(&'static str),
    /// Invalid declared length.
    InvalidLength(&'static str),
    /// Arithmetic overflow.
    Overflow(&'static str),
    /// Implementation-defined limit exceeded.
    LimitExceeded(&'static str),
    /// Error correction failure.
    EcFailed(&'static str),
    /// Encountered reserved value.
    ReservedValue(&'static str),
    /// Unsupported feature/algorithm.
    Unsupported(&'static str),
    /// Recovery data unavailable.
    RecoveryUnavailable(&'static str),
}

impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(m) => write!(f, "truncated: {m}"),
            Self::Malformed(m) => write!(f, "malformed: {m}"),
            Self::InvalidLength(m) => write!(f, "invalid length: {m}"),
            Self::Overflow(m) => write!(f, "overflow: {m}"),
            Self::LimitExceeded(m) => write!(f, "limit exceeded: {m}"),
            Self::EcFailed(m) => write!(f, "error correction failed: {m}"),
            Self::ReservedValue(m) => write!(f, "reserved value: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
            Self::RecoveryUnavailable(m) => write!(f, "recovery unavailable: {m}"),
        }
    }
}

impl std::error::Error for FecError {}
