#![allow(clippy::module_name_repetitions)]

use std::{fmt, io};

use thiserror::Error;

/// SAR status and error registry values from specification section 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SarStatus {
    /// Success.
    Ok = 0,
    /// Unspecified failure.
    ErrGeneric = -1,
    /// Resource not found.
    ErrNotFound = 1,
    /// Header magic mismatch.
    ErrInvalidMagic = 2,
    /// I/O failure.
    ErrIo = 3,
    /// CRC mismatch.
    ErrCrcMismatch = 4,
    /// Authentication failed.
    ErrAuthFailed = 5,
    /// Allocation failure.
    ErrMalloc = 6,
    /// Valid but unsupported feature.
    ErrUnsupported = 7,
    /// Invalid flag combination.
    ErrFlagConflict = 8,
    /// Patch application failed.
    ErrPatchFailed = 9,
    /// Required base object missing.
    ErrBaseMissing = 10,
    /// Invalid mapping.
    ErrInvalidMap = 11,
    /// No storage space.
    ErrNoSpace = 12,
    /// Partition missing.
    ErrPartitionMissing = 13,
    /// Fragment gap.
    ErrFragmentGap = 14,
    /// Reassembly buffer full.
    ErrReassemblyBufferFull = 15,
    /// Partition mismatch.
    ErrPartitionMismatch = 16,
    /// Fragment timeout.
    ErrFragmentTimeout = 17,
    /// Non-fatal incomplete warning.
    WarnIncomplete = 18,
    /// CDC recipe unresolved.
    ErrRecipeUnresolvable = 19,
    /// CDC mismatch.
    ErrCdcMismatch = 20,
    /// Error correction decode failure.
    ErrEcFailed = 21,
    /// Truncated structure.
    ErrTruncated = 22,
    /// Malformed structure.
    ErrMalformed = 23,
    /// Bounds violation.
    ErrBounds = 24,
    /// Reserved/prohibited value.
    ErrReservedValue = 25,
    /// Arithmetic overflow.
    ErrOverflow = 26,
    /// Limit exceeded.
    ErrLimitExceeded = 27,
    /// Invalid alignment.
    ErrInvalidAlignment = 28,
    /// Invalid length.
    ErrInvalidLength = 29,
    /// Non-crypto checksum mismatch.
    ErrChecksumMismatch = 30,
    /// Crypto hash mismatch.
    ErrHashMismatch = 31,
    /// Decryption failed.
    ErrDecryptFailed = 32,
    /// Signature validation failed.
    ErrSignatureFailed = 33,
    /// Anchor hash failed.
    ErrAnchorHashFailed = 34,
    /// Invalid/unsupported version.
    ErrInvalidVersion = 35,
    /// Required key missing.
    ErrKeyMissing = 36,
    /// Key rejected.
    ErrKeyRejected = 37,
    /// Stream closed unexpectedly.
    ErrStreamClosed = 38,
    /// Stream lifecycle/state error.
    ErrStreamState = 39,
    /// Required metadata missing.
    ErrMetadataMissing = 40,
    /// Metadata conflict.
    ErrMetadataConflict = 41,
    /// Recovery data unavailable.
    ErrRecoveryUnavailable = 42,
    /// Recovery data corrupted.
    ErrRecoveryCorrupted = 43,
    /// Compression operation failed.
    ErrCompressionFailed = 44,
    /// Decompression operation failed.
    ErrDecompressionFailed = 45,
    /// Write protected destination.
    ErrWriteProtected = 46,
    /// Object already exists.
    ErrAlreadyExists = 47,
    /// Cancelled operation.
    ErrCancelled = 48,
    /// Timeout.
    ErrTimeout = 49,
    /// Internal invariant violation.
    ErrInternal = 50,
    /// Nonce reuse detected.
    ErrNonceReuse = 51,
    /// Too many concurrent streams.
    ErrTooManyStreams = 52,
}

impl SarStatus {
    /// Numeric registry code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Registry constant name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "SAR_OK",
            Self::ErrGeneric => "SAR_ERR_GENERIC",
            Self::ErrNotFound => "SAR_ERR_NOT_FOUND",
            Self::ErrInvalidMagic => "SAR_ERR_INVALID_MAGIC",
            Self::ErrIo => "SAR_ERR_IO",
            Self::ErrCrcMismatch => "SAR_ERR_CRC_MISMATCH",
            Self::ErrAuthFailed => "SAR_ERR_AUTH_FAILED",
            Self::ErrMalloc => "SAR_ERR_MALLOC",
            Self::ErrUnsupported => "SAR_ERR_UNSUPPORTED",
            Self::ErrFlagConflict => "SAR_ERR_FLAG_CONFLICT",
            Self::ErrPatchFailed => "SAR_ERR_PATCH_FAILED",
            Self::ErrBaseMissing => "SAR_ERR_BASE_MISSING",
            Self::ErrInvalidMap => "SAR_ERR_INVALID_MAP",
            Self::ErrNoSpace => "SAR_ERR_NO_SPACE",
            Self::ErrPartitionMissing => "SAR_ERR_PARTITION_MISSING",
            Self::ErrFragmentGap => "SAR_ERR_FRAGMENT_GAP",
            Self::ErrReassemblyBufferFull => "SAR_ERR_REASSEMBLY_BUFFER_FULL",
            Self::ErrPartitionMismatch => "SAR_ERR_PARTITION_MISMATCH",
            Self::ErrFragmentTimeout => "SAR_ERR_FRAGMENT_TIMEOUT",
            Self::WarnIncomplete => "SAR_WARN_INCOMPLETE",
            Self::ErrRecipeUnresolvable => "SAR_ERR_RECIPE_UNRESOLVABLE",
            Self::ErrCdcMismatch => "SAR_ERR_CDC_MISMATCH",
            Self::ErrEcFailed => "SAR_ERR_EC_FAILED",
            Self::ErrTruncated => "SAR_ERR_TRUNCATED",
            Self::ErrMalformed => "SAR_ERR_MALFORMED",
            Self::ErrBounds => "SAR_ERR_BOUNDS",
            Self::ErrReservedValue => "SAR_ERR_RESERVED_VALUE",
            Self::ErrOverflow => "SAR_ERR_OVERFLOW",
            Self::ErrLimitExceeded => "SAR_ERR_LIMIT_EXCEEDED",
            Self::ErrInvalidAlignment => "SAR_ERR_INVALID_ALIGNMENT",
            Self::ErrInvalidLength => "SAR_ERR_INVALID_LENGTH",
            Self::ErrChecksumMismatch => "SAR_ERR_CHECKSUM_MISMATCH",
            Self::ErrHashMismatch => "SAR_ERR_HASH_MISMATCH",
            Self::ErrDecryptFailed => "SAR_ERR_DECRYPT_FAILED",
            Self::ErrSignatureFailed => "SAR_ERR_SIGNATURE_FAILED",
            Self::ErrAnchorHashFailed => "SAR_ERR_ANCHOR_HASH_FAILED",
            Self::ErrInvalidVersion => "SAR_ERR_INVALID_VERSION",
            Self::ErrKeyMissing => "SAR_ERR_KEY_MISSING",
            Self::ErrKeyRejected => "SAR_ERR_KEY_REJECTED",
            Self::ErrStreamClosed => "SAR_ERR_STREAM_CLOSED",
            Self::ErrStreamState => "SAR_ERR_STREAM_STATE",
            Self::ErrMetadataMissing => "SAR_ERR_METADATA_MISSING",
            Self::ErrMetadataConflict => "SAR_ERR_METADATA_CONFLICT",
            Self::ErrRecoveryUnavailable => "SAR_ERR_RECOVERY_UNAVAILABLE",
            Self::ErrRecoveryCorrupted => "SAR_ERR_RECOVERY_CORRUPTED",
            Self::ErrCompressionFailed => "SAR_ERR_COMPRESSION_FAILED",
            Self::ErrDecompressionFailed => "SAR_ERR_DECOMPRESSION_FAILED",
            Self::ErrWriteProtected => "SAR_ERR_WRITE_PROTECTED",
            Self::ErrAlreadyExists => "SAR_ERR_ALREADY_EXISTS",
            Self::ErrCancelled => "SAR_ERR_CANCELLED",
            Self::ErrTimeout => "SAR_ERR_TIMEOUT",
            Self::ErrInternal => "SAR_ERR_INTERNAL",
            Self::ErrNonceReuse => "SAR_ERR_NONCE_REUSE",
            Self::ErrTooManyStreams => "SAR_ERR_TOO_MANY_STREAMS",
        }
    }
}

impl fmt::Display for SarStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

/// Unknown status-code conversion error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown SAR status code: {0}")]
pub struct SarStatusParseError(pub i32);

impl TryFrom<i32> for SarStatus {
    type Error = SarStatusParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let status = match value {
            -1 => Self::ErrGeneric,
            0 => Self::Ok,
            1 => Self::ErrNotFound,
            2 => Self::ErrInvalidMagic,
            3 => Self::ErrIo,
            4 => Self::ErrCrcMismatch,
            5 => Self::ErrAuthFailed,
            6 => Self::ErrMalloc,
            7 => Self::ErrUnsupported,
            8 => Self::ErrFlagConflict,
            9 => Self::ErrPatchFailed,
            10 => Self::ErrBaseMissing,
            11 => Self::ErrInvalidMap,
            12 => Self::ErrNoSpace,
            13 => Self::ErrPartitionMissing,
            14 => Self::ErrFragmentGap,
            15 => Self::ErrReassemblyBufferFull,
            16 => Self::ErrPartitionMismatch,
            17 => Self::ErrFragmentTimeout,
            18 => Self::WarnIncomplete,
            19 => Self::ErrRecipeUnresolvable,
            20 => Self::ErrCdcMismatch,
            21 => Self::ErrEcFailed,
            22 => Self::ErrTruncated,
            23 => Self::ErrMalformed,
            24 => Self::ErrBounds,
            25 => Self::ErrReservedValue,
            26 => Self::ErrOverflow,
            27 => Self::ErrLimitExceeded,
            28 => Self::ErrInvalidAlignment,
            29 => Self::ErrInvalidLength,
            30 => Self::ErrChecksumMismatch,
            31 => Self::ErrHashMismatch,
            32 => Self::ErrDecryptFailed,
            33 => Self::ErrSignatureFailed,
            34 => Self::ErrAnchorHashFailed,
            35 => Self::ErrInvalidVersion,
            36 => Self::ErrKeyMissing,
            37 => Self::ErrKeyRejected,
            38 => Self::ErrStreamClosed,
            39 => Self::ErrStreamState,
            40 => Self::ErrMetadataMissing,
            41 => Self::ErrMetadataConflict,
            42 => Self::ErrRecoveryUnavailable,
            43 => Self::ErrRecoveryCorrupted,
            44 => Self::ErrCompressionFailed,
            45 => Self::ErrDecompressionFailed,
            46 => Self::ErrWriteProtected,
            47 => Self::ErrAlreadyExists,
            48 => Self::ErrCancelled,
            49 => Self::ErrTimeout,
            50 => Self::ErrInternal,
            51 => Self::ErrNonceReuse,
            52 => Self::ErrTooManyStreams,
            _ => return Err(SarStatusParseError(value)),
        };
        Ok(status)
    }
}

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
    /// Allocation failure.
    #[error("memory allocation failure: {0}")]
    Malloc(&'static str),
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
    /// CDC mismatch.
    #[error("CDC mismatch: {0}")]
    CdcMismatch(&'static str),
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
    /// Invalid alignment/padding.
    #[error("invalid alignment: {0}")]
    InvalidAlignment(&'static str),
    /// Invalid declared length.
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    /// Non-cryptographic checksum mismatch.
    #[error("checksum mismatch: {0}")]
    ChecksumMismatch(&'static str),
    /// Cryptographic hash mismatch.
    #[error("hash mismatch: {0}")]
    HashMismatch(&'static str),
    /// Decryption failure.
    #[error("decryption failed: {0}")]
    DecryptFailed(&'static str),
    /// Signature validation failure.
    #[error("signature validation failed: {0}")]
    SignatureFailed(&'static str),
    /// Anchor hash validation failure.
    #[error("anchor hash validation failed: {0}")]
    AnchorHashFailed(&'static str),
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
    /// Compression failure.
    #[error("compression failed: {0}")]
    CompressionFailed(&'static str),
    /// Decompression failure.
    #[error("decompression failed: {0}")]
    DecompressionFailed(&'static str),
    /// Write-protected destination.
    #[error("write protected: {0}")]
    WriteProtected(&'static str),
    /// Object already exists.
    #[error("already exists: {0}")]
    AlreadyExists(&'static str),
    /// Operation cancelled.
    #[error("operation cancelled: {0}")]
    Cancelled(&'static str),
    /// Timeout.
    #[error("timeout: {0}")]
    Timeout(&'static str),
    /// Internal invariant violation.
    #[error("internal error: {0}")]
    Internal(&'static str),
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
            Self::Malloc(_) => SarStatus::ErrMalloc,
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
            Self::CdcMismatch(_) => SarStatus::ErrCdcMismatch,
            Self::EcFailed(_) => SarStatus::ErrEcFailed,
            Self::Truncated(_) => SarStatus::ErrTruncated,
            Self::Malformed(_) => SarStatus::ErrMalformed,
            Self::Bounds(_) => SarStatus::ErrBounds,
            Self::ReservedValue(_) => SarStatus::ErrReservedValue,
            Self::Overflow(_) => SarStatus::ErrOverflow,
            Self::LimitExceeded(_) => SarStatus::ErrLimitExceeded,
            Self::InvalidAlignment(_) => SarStatus::ErrInvalidAlignment,
            Self::InvalidLength(_) => SarStatus::ErrInvalidLength,
            Self::ChecksumMismatch(_) => SarStatus::ErrChecksumMismatch,
            Self::HashMismatch(_) => SarStatus::ErrHashMismatch,
            Self::DecryptFailed(_) => SarStatus::ErrDecryptFailed,
            Self::SignatureFailed(_) => SarStatus::ErrSignatureFailed,
            Self::AnchorHashFailed(_) => SarStatus::ErrAnchorHashFailed,
            Self::InvalidVersion(_) => SarStatus::ErrInvalidVersion,
            Self::KeyMissing(_) => SarStatus::ErrKeyMissing,
            Self::KeyRejected(_) => SarStatus::ErrKeyRejected,
            Self::StreamClosed(_) => SarStatus::ErrStreamClosed,
            Self::StreamState(_) => SarStatus::ErrStreamState,
            Self::MetadataMissing(_) => SarStatus::ErrMetadataMissing,
            Self::MetadataConflict(_) => SarStatus::ErrMetadataConflict,
            Self::RecoveryUnavailable(_) => SarStatus::ErrRecoveryUnavailable,
            Self::RecoveryCorrupted(_) => SarStatus::ErrRecoveryCorrupted,
            Self::CompressionFailed(_) => SarStatus::ErrCompressionFailed,
            Self::DecompressionFailed(_) => SarStatus::ErrDecompressionFailed,
            Self::WriteProtected(_) => SarStatus::ErrWriteProtected,
            Self::AlreadyExists(_) => SarStatus::ErrAlreadyExists,
            Self::Cancelled(_) => SarStatus::ErrCancelled,
            Self::Timeout(_) => SarStatus::ErrTimeout,
            Self::Internal(_) => SarStatus::ErrInternal,
            Self::NonceReuse(_) => SarStatus::ErrNonceReuse,
            Self::TooManyStreams(_) => SarStatus::ErrTooManyStreams,
        }
    }
}
