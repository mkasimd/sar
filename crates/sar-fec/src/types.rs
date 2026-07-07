//! Shared FEC types and the [`FecCodec`] trait.

use sar_core::SarError;

/// Algorithm identifier for Reed-Solomon FEC.
pub const FEC_ALGO_RS: u8 = 0x11;
/// Algorithm identifier for XOR FEC.
pub const FEC_ALGO_XOR: u8 = 0x14;

// ---------------------------------------------------------------------------
// FEC value type
// ---------------------------------------------------------------------------

/// Encoded FEC value as it appears in the FEC Value field (LFH) or TLV Value
/// field (Data Recovery TLV).
///
/// The `data` field contains the full algorithm-specific bytes:
/// `Config[2] || metadata || parity_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecValue {
    /// FEC algorithm identifier (e.g. `0x11` or `0x14`).
    pub algo_id: u8,
    /// Raw encoded bytes: config + metadata + parity.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Erasure type
// ---------------------------------------------------------------------------

/// An explicit erasure position.
///
/// For XOR FEC the index is the zero-based **data block index** (i.e.
/// `byte_offset / block_size`) within the protected byte sequence.
///
/// For Reed-Solomon FEC the index is the zero-based **data symbol index**
/// within the protected byte sequence (i.e. `byte_offset / symbol_size`).
/// The codec derives the group index and in-group symbol index from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Erasure {
    /// Zero-based block or symbol index.
    pub index: u64,
}

// ---------------------------------------------------------------------------
// Recovery input
// ---------------------------------------------------------------------------

/// Input for an FEC erasure-recovery operation.
#[derive(Debug)]
pub struct FecRecoverInput<'a> {
    /// Original protected byte length **before** any padding.
    pub original_protected_len: u64,
    /// The available stored payload bytes.  Bytes at erased positions may be
    /// zero or garbage; the codec ignores them.  The slice MUST be at least
    /// `original_protected_len` bytes long, or trailing erasures must account
    /// for any missing suffix.
    pub available_data: &'a [u8],
    /// Raw FEC value bytes (config + metadata + parity), as stored in the
    /// `FEC Value` / TLV `Value` field.
    pub fec_value_data: &'a [u8],
    /// Explicit erasure positions.  Positions must not repeat and must be
    /// within the range derivable from `original_protected_len` and the
    /// algorithm block/symbol size.
    pub erasures: &'a [Erasure],
}

// ---------------------------------------------------------------------------
// FEC options (encoding)
// ---------------------------------------------------------------------------

/// Encoding options passed to [`FecCodec::encode_recovery`].  The field
/// values are algorithm-specific.
#[derive(Debug, Clone, Copy, Default)]
pub struct FecOptions;

// ---------------------------------------------------------------------------
// Codec trait
// ---------------------------------------------------------------------------

/// Trait implemented by each FEC algorithm.
pub trait FecCodec {
    /// Algorithm identifier (e.g. `0x11`, `0x14`).
    fn algorithm_id(&self) -> u8;

    /// Encodes parity for `protected` bytes and returns the complete FEC
    /// `Value` (config + metadata + parity) ready to embed in a LFH or TLV.
    ///
    /// # Errors
    ///
    /// Returns [`SarError`] on overflow, length mismatch, or unsupported
    /// configuration.
    fn encode_recovery(&self, protected: &[u8], options: FecOptions)
        -> Result<FecValue, SarError>;

    /// Performs erasure recovery and returns the fully-recovered protected
    /// byte sequence truncated to `input.original_protected_len`.
    ///
    /// # Errors
    ///
    /// * [`SarError::EcFailed`] when too many erasures in one stripe/group.
    /// * [`SarError::RecoveryUnavailable`] when erasure positions are unknown.
    /// * [`SarError::Malformed`] / [`SarError::InvalidLength`] on corrupt FEC
    ///   metadata.
    fn recover(&self, input: FecRecoverInput<'_>) -> Result<Vec<u8>, SarError>;

    /// Validates the FEC value bytes without performing recovery.  Checks that
    /// config, counts, and parity data length are self-consistent.
    ///
    /// # Errors
    ///
    /// Returns [`SarError::InvalidLength`] or [`SarError::Malformed`] on
    /// inconsistencies.
    fn validate(&self, fec_value_data: &[u8]) -> Result<(), SarError>;
}

// ---------------------------------------------------------------------------
// Parsed FEC metadata (for inspect / verify)
// ---------------------------------------------------------------------------

/// Parsed metadata for an XOR FEC value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorMeta {
    /// Number of data blocks per stripe.
    pub stripe_size: u8,
    /// Block size in bytes.
    pub block_size: u32,
    /// Original protected byte length.
    pub original_protected_len: u64,
    /// Number of stripes.
    pub stripe_count: u32,
    /// Parity data length in bytes.
    pub parity_data_len: usize,
}

/// Parsed metadata for a Reed-Solomon FEC value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsMeta {
    /// Number of data symbols per group (`k`).
    pub k: u8,
    /// Number of parity symbols per group (`n-k`).
    pub parity_count: u8,
    /// Symbol size in bytes.
    pub symbol_size: u32,
    /// Original protected byte length.
    pub original_protected_len: u64,
    /// Number of groups.
    pub group_count: u32,
    /// Parity data length in bytes.
    pub parity_data_len: usize,
}

/// Parsed FEC metadata variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecMeta {
    /// XOR FEC metadata.
    Xor(XorMeta),
    /// Reed-Solomon FEC metadata.
    Rs(RsMeta),
}
