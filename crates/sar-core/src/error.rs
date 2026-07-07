#![allow(clippy::module_name_repetitions)]

use std::io;

use thiserror::Error;

/// SAR status and error registry values from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SarStatus {
    /// Success.
    Ok = 0,
    /// Unspecified failure.
    ErrGeneric = -1,
    /// Header magic mismatch.
    ErrInvalidMagic = 2,
    /// IO error.
    ErrIo = 3,
    /// Valid SAR feature is unsupported.
    ErrUnsupported = 7,
    /// Invalid flag combination.
    ErrFlagConflict = 8,
    /// Invalid map/range relation.
    ErrInvalidMap = 11,
    /// Truncated archive or structure.
    ErrTruncated = 22,
    /// Malformed structure.
    ErrMalformed = 23,
    /// Bounds violation.
    ErrBounds = 24,
    /// Reserved or prohibited value.
    ErrReservedValue = 25,
    /// Arithmetic overflow.
    ErrOverflow = 26,
    /// Alignment violation.
    ErrInvalidAlignment = 28,
    /// Invalid length declaration.
    ErrInvalidLength = 29,
    /// Invalid or unsupported version.
    ErrInvalidVersion = 35,
    /// Required metadata missing.
    ErrMetadataMissing = 40,
}

/// SAR protocol error type.
#[derive(Debug, Error)]
pub enum SarError {
    /// Generic SAR error.
    #[error("generic SAR error")]
    Generic,
    /// Invalid magic bytes.
    #[error("invalid SAR magic")]
    InvalidMagic,
    /// IO error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Unsupported feature/algorithm.
    #[error("unsupported feature: {0}")]
    Unsupported(&'static str),
    /// Global or entry flag conflict.
    #[error("flag conflict: {0}")]
    FlagConflict(&'static str),
    /// Invalid map/offset relation.
    #[error("invalid map: {0}")]
    InvalidMap(&'static str),
    /// Truncated structure.
    #[error("truncated structure: {0}")]
    Truncated(&'static str),
    /// Malformed structure.
    #[error("malformed structure: {0}")]
    Malformed(&'static str),
    /// Bounds violation.
    #[error("bounds violation: {0}")]
    Bounds(&'static str),
    /// Encountered reserved value.
    #[error("reserved value: {0}")]
    ReservedValue(&'static str),
    /// Arithmetic overflow.
    #[error("arithmetic overflow: {0}")]
    Overflow(&'static str),
    /// Invalid alignment/padding.
    #[error("invalid alignment: {0}")]
    InvalidAlignment(&'static str),
    /// Invalid declared length.
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    /// Invalid version.
    #[error("invalid version: {0}")]
    InvalidVersion(&'static str),
    /// Missing required metadata.
    #[error("metadata missing: {0}")]
    MetadataMissing(&'static str),
}

impl SarError {
    /// Returns the SAR status code mapped from this error.
    #[must_use]
    pub const fn status(&self) -> SarStatus {
        match self {
            Self::Generic => SarStatus::ErrGeneric,
            Self::InvalidMagic => SarStatus::ErrInvalidMagic,
            Self::Io(_) => SarStatus::ErrIo,
            Self::Unsupported(_) => SarStatus::ErrUnsupported,
            Self::FlagConflict(_) => SarStatus::ErrFlagConflict,
            Self::InvalidMap(_) => SarStatus::ErrInvalidMap,
            Self::Truncated(_) => SarStatus::ErrTruncated,
            Self::Malformed(_) => SarStatus::ErrMalformed,
            Self::Bounds(_) => SarStatus::ErrBounds,
            Self::ReservedValue(_) => SarStatus::ErrReservedValue,
            Self::Overflow(_) => SarStatus::ErrOverflow,
            Self::InvalidAlignment(_) => SarStatus::ErrInvalidAlignment,
            Self::InvalidLength(_) => SarStatus::ErrInvalidLength,
            Self::InvalidVersion(_) => SarStatus::ErrInvalidVersion,
            Self::MetadataMissing(_) => SarStatus::ErrMetadataMissing,
        }
    }
}
