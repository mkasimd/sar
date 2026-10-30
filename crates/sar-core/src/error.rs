// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_name_repetitions)]

use std::{fmt, io};

use thiserror::Error;

macro_rules! status_registry {
    ($($(#[$doc:meta])* $variant:ident = $value:literal => $name:literal,)+) => {
        /// SAR status registry values from specification section 10.2.
        ///
        /// The enumeration is closed: it contains exactly the standardized
        /// assignments. Retired, reserved, unassigned, and implementation-private
        /// numeric values are not members and are rejected by [`TryFrom<u16>`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u16)]
        pub enum SarStatus {
            $($(#[$doc])* $variant = $value,)+
        }

        impl SarStatus {
            /// Registry constant name.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        }

        impl TryFrom<u16> for SarStatus {
            type Error = SarStatusParseError;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(SarStatusParseError(value)),
                }
            }
        }
    };
}

status_registry! {
    /// Success.
    Ok = 0 => "SAR_OK",
    /// Permitted degraded or incomplete result; never implies full verification.
    WarnIncomplete = 1 => "SAR_WARN_INCOMPLETE",
    /// Repeated Full Logical Entry Path diagnostic.
    WarnDuplicate = 2 => "SAR_WARN_DUPLICATE",
    /// Aggregate result of explicitly enabled skipping of unsupported Entries.
    WarnSkipped = 3 => "SAR_WARN_SKIPPED",
    /// Structurally invalid archive, metadata, or protocol structure.
    ErrMalformed = 100 => "SAR_ERR_MALFORMED",
    /// Global Header magic mismatch.
    ErrInvalidMagic = 101 => "SAR_ERR_INVALID_MAGIC",
    /// Structurally or normatively invalid version value.
    ErrInvalidVersion = 102 => "SAR_ERR_INVALID_VERSION",
    /// Physical input ended before the declared bytes were available.
    ErrTruncated = 103 => "SAR_ERR_TRUNCATED",
    /// Exact length relationship violated.
    ErrInvalidLength = 104 => "SAR_ERR_INVALID_LENGTH",
    /// Offset, range, count, or position outside its allowed domain.
    ErrBounds = 105 => "SAR_ERR_BOUNDS",
    /// Invalid Sparse Map structure or extent relationships.
    ErrInvalidMap = 106 => "SAR_ERR_INVALID_MAP",
    /// Invalid flag combination or missing flag dependency.
    ErrFlagConflict = 108 => "SAR_ERR_FLAG_CONFLICT",
    /// Assigned but unimplemented feature, flag, profile, algorithm, or version.
    ErrUnsupported = 200 => "SAR_ERR_UNSUPPORTED",
    /// Reserved, prohibited, or unassigned registry value.
    ErrReservedValue = 201 => "SAR_ERR_RESERVED_VALUE",
    /// AEAD authentication failed.
    ErrAuthFailed = 300 => "SAR_ERR_AUTH_FAILED",
    /// CRC32 verification failed.
    ErrCrcMismatch = 301 => "SAR_ERR_CRC_MISMATCH",
    /// Cryptographic hash verification failed.
    ErrHashMismatch = 302 => "SAR_ERR_HASH_MISMATCH",
    /// Digital signature verification failed.
    ErrSignatureFailed = 303 => "SAR_ERR_SIGNATURE_FAILED",
    /// Required key or keying material unavailable.
    ErrKeyMissing = 304 => "SAR_ERR_KEY_MISSING",
    /// Provided key material rejected.
    ErrKeyRejected = 305 => "SAR_ERR_KEY_REJECTED",
    /// Encoder detected AEAD nonce reuse.
    ErrNonceReuse = 306 => "SAR_ERR_NONCE_REUSE",
    /// Required Fragment Index missing.
    ErrFragmentGap = 400 => "SAR_ERR_FRAGMENT_GAP",
    /// Fragment-group timeout expired.
    ErrFragmentTimeout = 401 => "SAR_ERR_FRAGMENT_TIMEOUT",
    /// CDC recipe hash could not be resolved.
    ErrRecipeUnresolvable = 402 => "SAR_ERR_RECIPE_UNRESOLVABLE",
    /// Error-correction decoding failed.
    ErrEcFailed = 403 => "SAR_ERR_EC_FAILED",
    /// Required recovery data unavailable.
    ErrRecoveryUnavailable = 404 => "SAR_ERR_RECOVERY_UNAVAILABLE",
    /// Recovery metadata or parity data corrupted or unusable.
    ErrRecoveryCorrupted = 405 => "SAR_ERR_RECOVERY_CORRUPTED",
    /// Patch payload malformed or patch application failed.
    ErrPatchFailed = 406 => "SAR_ERR_PATCH_FAILED",
    /// Required delta base cannot be resolved.
    ErrBaseMissing = 407 => "SAR_ERR_BASE_MISSING",
    /// Checked arithmetic cannot represent the required result.
    ErrOverflow = 500 => "SAR_ERR_OVERFLOW",
    /// Configured or implementation-defined resource cap exceeded.
    ErrLimitExceeded = 501 => "SAR_ERR_LIMIT_EXCEEDED",
    /// Fragment-reassembly buffer or group-tracking cap exceeded.
    ErrReassemblyBufferFull = 502 => "SAR_ERR_REASSEMBLY_BUFFER_FULL",
    /// Insufficient storage space.
    ErrNoSpace = 503 => "SAR_ERR_NO_SPACE",
    /// Invalid stream state, lifecycle, sequencing, or Stream ID conflict.
    ErrStreamState = 600 => "SAR_ERR_STREAM_STATE",
    /// Concurrent or active stream limit exceeded.
    ErrTooManyStreams = 601 => "SAR_ERR_TOO_MANY_STREAMS",
    /// Ordered stream terminated while the session remained active.
    ErrStreamClosed = 602 => "SAR_ERR_STREAM_CLOSED",
    /// Required Partition or physical volume missing.
    ErrPartitionMissing = 603 => "SAR_ERR_PARTITION_MISSING",
    /// Partition identity does not match the expected Partition Set.
    ErrPartitionMismatch = 604 => "SAR_ERR_PARTITION_MISMATCH",
    /// Session inactivity watchdog expired.
    ErrSessionTimeout = 605 => "SAR_ERR_SESSION_TIMEOUT",
    /// Conflicting logical-path identity at materialization.
    ErrPathCollision = 700 => "SAR_ERR_PATH_COLLISION",
    /// Materialization destination or symlink target escapes its scope.
    ErrPathEscape = 701 => "SAR_ERR_PATH_ESCAPE",
    /// Required SAR interpretation or application metadata absent.
    ErrMetadataMissing = 702 => "SAR_ERR_METADATA_MISSING",
    /// Conflicting or mutually exclusive metadata.
    ErrMetadataConflict = 703 => "SAR_ERR_METADATA_CONFLICT",
    /// Destination object already exists and overwriting is not permitted.
    ErrAlreadyExists = 704 => "SAR_ERR_ALREADY_EXISTS",
    /// Generic referenced object lookup failure.
    ErrNotFound = 705 => "SAR_ERR_NOT_FOUND",
    /// Hardware, network, storage, filesystem, or transport I/O error.
    ErrIo = 800 => "SAR_ERR_IO",
    /// Write-protected archive, partition, stream, or destination.
    ErrWriteProtected = 801 => "SAR_ERR_WRITE_PROTECTED",
    /// Internal implementation error or invariant violation.
    ErrInternal = 802 => "SAR_ERR_INTERNAL",
    /// Nonconforming caller-supplied input.
    ErrInvalidInput = 803 => "SAR_ERR_INVALID_INPUT",
    /// Unspecified failure.
    ErrGeneric = 0xFFFF => "SAR_ERR_GENERIC",
}

impl SarStatus {
    /// Canonical unsigned 16-bit registry value.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

impl From<SarStatus> for u16 {
    fn from(status: SarStatus) -> Self {
        status.code()
    }
}

impl fmt::Display for SarStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

/// Error returned when a `u16` is not a standardized status value.
///
/// Retired, reserved, unassigned, and implementation-private values are all
/// rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unrecognized SAR status code: {0}")]
pub struct SarStatusParseError(pub u16);

/// SAR protocol error type.
#[derive(Debug, Error)]
pub enum SarError {
    /// Generic SAR error.
    #[error("generic SAR error")]
    Generic,
    /// Entry/resource not found.
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// Invalid magic bytes.
    #[error("invalid SAR magic")]
    InvalidMagic,
    /// IO error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// CRC mismatch.
    #[error("CRC mismatch: {0}")]
    CrcMismatch(&'static str),
    /// Authentication failure.
    #[error("authentication failed: {0}")]
    AuthFailed(&'static str),
    /// Unsupported feature/algorithm.
    #[error("unsupported feature: {0}")]
    Unsupported(&'static str),
    /// Global or entry flag conflict.
    #[error("flag conflict: {0}")]
    FlagConflict(&'static str),
    /// Patch failure.
    #[error("patch failed: {0}")]
    PatchFailed(&'static str),
    /// Missing base object.
    #[error("base object missing: {0}")]
    BaseMissing(&'static str),
    /// Invalid map/offset relation.
    #[error("invalid map: {0}")]
    InvalidMap(&'static str),
    /// Out of space.
    #[error("no space: {0}")]
    NoSpace(&'static str),
    /// Missing partition.
    #[error("partition missing: {0}")]
    PartitionMissing(&'static str),
    /// Missing fragment.
    #[error("fragment gap: {0}")]
    FragmentGap(&'static str),
    /// Reassembly buffer full.
    #[error("reassembly buffer full: {0}")]
    ReassemblyBufferFull(&'static str),
    /// Partition mismatch.
    #[error("partition mismatch: {0}")]
    PartitionMismatch(&'static str),
    /// Fragment timeout.
    #[error("fragment timeout: {0}")]
    FragmentTimeout(&'static str),
    /// CDC recipe unresolved.
    #[error("CDC recipe unresolvable: {0}")]
    RecipeUnresolvable(&'static str),
    /// Error correction failure.
    #[error("error correction failed: {0}")]
    EcFailed(&'static str),
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
    /// Implementation-defined limit exceeded.
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Invalid declared length.
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    /// Cryptographic hash mismatch.
    #[error("hash mismatch: {0}")]
    HashMismatch(&'static str),
    /// Signature validation failure.
    #[error("signature validation failed: {0}")]
    SignatureFailed(&'static str),
    /// Invalid version.
    #[error("invalid version: {0}")]
    InvalidVersion(&'static str),
    /// Required key missing.
    #[error("key missing: {0}")]
    KeyMissing(&'static str),
    /// Key rejected.
    #[error("key rejected: {0}")]
    KeyRejected(&'static str),
    /// Stream closed unexpectedly.
    #[error("stream closed: {0}")]
    StreamClosed(&'static str),
    /// Invalid stream lifecycle/state.
    #[error("stream state error: {0}")]
    StreamState(&'static str),
    /// Session inactivity watchdog expired.
    #[error("session timeout: {0}")]
    SessionTimeout(&'static str),
    /// Conflicting logical-path identity at materialization.
    #[error("path collision: {0}")]
    PathCollision(&'static str),
    /// Materialization destination or symlink target escapes its scope.
    #[error("path escape: {0}")]
    PathEscape(&'static str),
    /// Missing required metadata.
    #[error("metadata missing: {0}")]
    MetadataMissing(&'static str),
    /// Conflicting metadata.
    #[error("metadata conflict: {0}")]
    MetadataConflict(&'static str),
    /// Recovery data unavailable.
    #[error("recovery unavailable: {0}")]
    RecoveryUnavailable(&'static str),
    /// Recovery data unusable.
    #[error("recovery corrupted: {0}")]
    RecoveryCorrupted(&'static str),
    /// Write-protected destination.
    #[error("write protected: {0}")]
    WriteProtected(&'static str),
    /// Object already exists.
    #[error("already exists: {0}")]
    AlreadyExists(&'static str),
    /// Internal invariant violation.
    #[error("internal error: {0}")]
    Internal(&'static str),
    /// Nonconforming caller-supplied input.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// Nonce reuse.
    #[error("nonce reuse detected: {0}")]
    NonceReuse(&'static str),
    /// Concurrent stream limit exceeded.
    #[error("too many streams: {0}")]
    TooManyStreams(&'static str),
}

impl SarError {
    /// Returns the SAR status code mapped from this error.
    #[must_use]
    pub const fn status(&self) -> SarStatus {
        match self {
            Self::Generic => SarStatus::ErrGeneric,
            Self::NotFound(_) => SarStatus::ErrNotFound,
            Self::InvalidMagic => SarStatus::ErrInvalidMagic,
            Self::Io(_) => SarStatus::ErrIo,
            Self::CrcMismatch(_) => SarStatus::ErrCrcMismatch,
            Self::AuthFailed(_) => SarStatus::ErrAuthFailed,
            Self::Unsupported(_) => SarStatus::ErrUnsupported,
            Self::FlagConflict(_) => SarStatus::ErrFlagConflict,
            Self::PatchFailed(_) => SarStatus::ErrPatchFailed,
            Self::BaseMissing(_) => SarStatus::ErrBaseMissing,
            Self::InvalidMap(_) => SarStatus::ErrInvalidMap,
            Self::NoSpace(_) => SarStatus::ErrNoSpace,
            Self::PartitionMissing(_) => SarStatus::ErrPartitionMissing,
            Self::FragmentGap(_) => SarStatus::ErrFragmentGap,
            Self::ReassemblyBufferFull(_) => SarStatus::ErrReassemblyBufferFull,
            Self::PartitionMismatch(_) => SarStatus::ErrPartitionMismatch,
            Self::FragmentTimeout(_) => SarStatus::ErrFragmentTimeout,
            Self::RecipeUnresolvable(_) => SarStatus::ErrRecipeUnresolvable,
            Self::EcFailed(_) => SarStatus::ErrEcFailed,
            Self::Truncated(_) => SarStatus::ErrTruncated,
            Self::Malformed(_) => SarStatus::ErrMalformed,
            Self::Bounds(_) => SarStatus::ErrBounds,
            Self::ReservedValue(_) => SarStatus::ErrReservedValue,
            Self::Overflow(_) => SarStatus::ErrOverflow,
            Self::LimitExceeded(_) => SarStatus::ErrLimitExceeded,
            Self::InvalidLength(_) => SarStatus::ErrInvalidLength,
            Self::HashMismatch(_) => SarStatus::ErrHashMismatch,
            Self::SignatureFailed(_) => SarStatus::ErrSignatureFailed,
            Self::InvalidVersion(_) => SarStatus::ErrInvalidVersion,
            Self::KeyMissing(_) => SarStatus::ErrKeyMissing,
            Self::KeyRejected(_) => SarStatus::ErrKeyRejected,
            Self::StreamClosed(_) => SarStatus::ErrStreamClosed,
            Self::StreamState(_) => SarStatus::ErrStreamState,
            Self::SessionTimeout(_) => SarStatus::ErrSessionTimeout,
            Self::PathCollision(_) => SarStatus::ErrPathCollision,
            Self::PathEscape(_) => SarStatus::ErrPathEscape,
            Self::MetadataMissing(_) => SarStatus::ErrMetadataMissing,
            Self::MetadataConflict(_) => SarStatus::ErrMetadataConflict,
            Self::RecoveryUnavailable(_) => SarStatus::ErrRecoveryUnavailable,
            Self::RecoveryCorrupted(_) => SarStatus::ErrRecoveryCorrupted,
            Self::WriteProtected(_) => SarStatus::ErrWriteProtected,
            Self::AlreadyExists(_) => SarStatus::ErrAlreadyExists,
            Self::Internal(_) => SarStatus::ErrInternal,
            Self::InvalidInput(_) => SarStatus::ErrInvalidInput,
            Self::NonceReuse(_) => SarStatus::ErrNonceReuse,
            Self::TooManyStreams(_) => SarStatus::ErrTooManyStreams,
        }
    }
}

impl From<sar_crypto::SarCryptoError> for SarError {
    fn from(err: sar_crypto::SarCryptoError) -> Self {
        match err {
            sar_crypto::SarCryptoError::AuthFailed(msg) => Self::AuthFailed(msg),
            sar_crypto::SarCryptoError::KeyMissing(msg) => Self::KeyMissing(msg),
            sar_crypto::SarCryptoError::Malformed(msg) => Self::Malformed(msg),
            sar_crypto::SarCryptoError::Unsupported(msg) => Self::Unsupported(msg),
            sar_crypto::SarCryptoError::ReservedValue(msg) => Self::ReservedValue(msg),
            sar_crypto::SarCryptoError::InvalidLength(msg) => Self::InvalidLength(msg),
            sar_crypto::SarCryptoError::Internal(msg) => Self::Internal(msg),
            sar_crypto::SarCryptoError::NonceReuse => Self::NonceReuse("nonce reuse detected"),
            sar_crypto::SarCryptoError::FlagConflict(msg) => Self::FlagConflict(msg),
            sar_crypto::SarCryptoError::KeyRejected(msg) => Self::KeyRejected(msg),
            sar_crypto::SarCryptoError::LimitExceeded(msg) => Self::LimitExceeded(msg),
        }
    }
}

impl From<sar_fragmentation::FragmentError> for SarError {
    fn from(err: sar_fragmentation::FragmentError) -> Self {
        match err {
            sar_fragmentation::FragmentError::Bounds(msg) => Self::Bounds(msg),
            sar_fragmentation::FragmentError::InvalidMap(msg) => Self::InvalidMap(msg),
            sar_fragmentation::FragmentError::FragmentGap(msg) => Self::FragmentGap(msg),
            sar_fragmentation::FragmentError::Overflow(msg) => Self::Overflow(msg),
            sar_fragmentation::FragmentError::LimitExceeded(msg) => Self::LimitExceeded(msg),
            sar_fragmentation::FragmentError::PayloadSizeMismatch(msg) => Self::InvalidLength(msg),
            sar_fragmentation::FragmentError::DuplicateIndex(msg) => Self::MetadataConflict(msg),
            sar_fragmentation::FragmentError::MetadataConflict(msg) => Self::MetadataConflict(msg),
        }
    }
}

impl From<sar_sparse::SparseError> for SarError {
    fn from(err: sar_sparse::SparseError) -> Self {
        match err {
            sar_sparse::SparseError::InvalidMap(msg) => Self::InvalidMap(msg),
            sar_sparse::SparseError::Overflow(msg) => Self::Overflow(msg),
            sar_sparse::SparseError::Truncated(msg) => Self::Truncated(msg),
            sar_sparse::SparseError::InvalidLength(msg) => Self::InvalidLength(msg),
            sar_sparse::SparseError::LimitExceeded(msg) => Self::LimitExceeded(msg),
        }
    }
}
