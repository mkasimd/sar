//! CDC validation helpers.
//!
//! These functions are used by both the reader and writer pipelines to enforce
//! spec constraints on CDC algorithm IDs, CDC_MAP records, and chunk-table
//! coverage.

use crate::{
    algo::{CDC_ALGO_CUSTOM_MAX, CDC_ALGO_CUSTOM_MIN, CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL},
    types::{CdcMap, CdcMetadata},
};

/// Error type used across the CDC crate.
///
/// We re-use the same error variant names as `sar_core::SarError` so that
/// `sar-core` can map them directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcError {
    /// Valid CDC feature or algorithm not implemented by this release.
    Unsupported(&'static str),
    /// Reserved/prohibited value encountered.
    ReservedValue(&'static str),
    /// Arithmetic overflow or underflow.
    Overflow(&'static str),
    /// Structural bounds violation.
    Bounds(&'static str),
    /// Malformed structure.
    Malformed(&'static str),
    /// Implementation-defined limit exceeded.
    LimitExceeded(&'static str),
    /// Zero-length chunk or zero-count condition.
    InvalidLength(&'static str),
}

impl core::fmt::Display for CdcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(m) => write!(f, "CDC unsupported: {m}"),
            Self::ReservedValue(m) => write!(f, "CDC reserved value: {m}"),
            Self::Overflow(m) => write!(f, "CDC overflow: {m}"),
            Self::Bounds(m) => write!(f, "CDC bounds: {m}"),
            Self::Malformed(m) => write!(f, "CDC malformed: {m}"),
            Self::LimitExceeded(m) => write!(f, "CDC limit exceeded: {m}"),
            Self::InvalidLength(m) => write!(f, "CDC invalid length: {m}"),
        }
    }
}

/// Maximum number of CDC_MAP records accepted during parsing.
///
/// Used when a full [`crate::ResourceLimits`]-style struct is not available.
/// The caller can supply a tighter bound by passing a lower value.
pub const CDC_MAP_MAX_RECORDS_DEFAULT: usize = 1_000_000;

/// Maximum number of CDC chunks accepted per entry during validation.
pub const CDC_CHUNK_MAX_DEFAULT: usize = 1_000_000;

/// Validates a `CDC Algo ID` value against the spec-defined algorithm
/// registry (section 8.5).
///
/// * `0x00` (LITERAL_MODE) — accepted; payload is literal data.
/// * `0x02` (FASTCDC) — accepted; implemented.
/// * `0x01` / `0x03` (RABIN / BUZHASH) — returns `Unsupported`.
/// * `0xF0–0xFF` (CUSTOM) — returns `Unsupported`.
/// * `0x04–0xEF` — returns `ReservedValue`.
///
/// # Errors
///
/// Returns [`CdcError::Unsupported`] or [`CdcError::ReservedValue`] for
/// invalid IDs.
pub fn validate_cdc_algo_id(id: u8) -> Result<(), CdcError> {
    match id {
        CDC_ALGO_LITERAL => Ok(()),
        CDC_ALGO_FASTCDC => Ok(()),
        0x01 | 0x03 => Err(CdcError::Unsupported(
            "CDC algorithm not implemented (RABIN/BUZHASH)",
        )),
        CDC_ALGO_CUSTOM_MIN..=CDC_ALGO_CUSTOM_MAX => {
            Err(CdcError::Unsupported("CUSTOM CDC algorithm not supported"))
        }
        _ => Err(CdcError::ReservedValue("reserved CDC algorithm ID")),
    }
}

/// Validates the raw bytes of a CDC_MAP TLV value.
///
/// Checks that `bytes.len()` is a multiple of the wire record length
/// (`CDC_MAP_RECORD_LEN = 50`), and that the total record count does not
/// exceed `max_records`.
///
/// # Errors
///
/// Returns [`CdcError::Malformed`] when length is not a multiple of 50.
/// Returns [`CdcError::LimitExceeded`] when the record count exceeds
/// `max_records`.
pub fn validate_cdc_map_bytes(bytes: &[u8], max_records: usize) -> Result<(), CdcError> {
    use crate::types::CDC_MAP_RECORD_LEN;
    if !bytes.len().is_multiple_of(CDC_MAP_RECORD_LEN) {
        return Err(CdcError::Malformed(
            "CDC_MAP byte length is not a multiple of the record size (50)",
        ));
    }
    let count = bytes.len() / CDC_MAP_RECORD_LEN;
    if count > max_records {
        return Err(CdcError::LimitExceeded(
            "CDC_MAP record count exceeds configured limit",
        ));
    }
    Ok(())
}

/// Validates a parsed [`CdcMap`].
///
/// Checks:
/// * record count ≤ `max_records`;
/// * no record has `compressed_size == 0`.
///
/// # Errors
///
/// Returns [`CdcError::LimitExceeded`] or [`CdcError::InvalidLength`].
pub fn validate_cdc_map(map: &CdcMap, max_records: usize) -> Result<(), CdcError> {
    if map.records.len() > max_records {
        return Err(CdcError::LimitExceeded(
            "CDC_MAP record count exceeds configured limit",
        ));
    }
    for record in &map.records {
        if record.compressed_size == 0 {
            return Err(CdcError::InvalidLength(
                "CDC_MAP record has zero compressed_size",
            ));
        }
    }
    Ok(())
}

/// Validates a [`CdcMetadata`] chunk table against a logical file size.
///
/// Checks:
/// * chunk count ≤ `max_chunks`;
/// * no zero-length chunks;
/// * `offset + length` does not overflow u64;
/// * no chunk extends beyond `logical_size` (when non-zero);
/// * chunks are contiguous (no gaps, no overlaps) and ordered.
///
/// # Errors
///
/// Returns the appropriate [`CdcError`] variant on any violation.
pub fn validate_cdc_metadata(
    meta: &CdcMetadata,
    logical_size: u64,
    max_chunks: usize,
) -> Result<(), CdcError> {
    if meta.chunks.len() > max_chunks {
        return Err(CdcError::LimitExceeded(
            "CDC chunk count exceeds configured limit",
        ));
    }
    let mut cursor: u64 = 0;
    for chunk in &meta.chunks {
        if chunk.length == 0 {
            return Err(CdcError::InvalidLength("CDC chunk has zero length"));
        }
        if chunk.offset != cursor {
            return Err(CdcError::Bounds(
                "CDC chunk table has gap or overlap (non-contiguous)",
            ));
        }
        let end = chunk
            .offset
            .checked_add(chunk.length)
            .ok_or(CdcError::Overflow("CDC chunk offset+length overflow"))?;
        if logical_size > 0 && end > logical_size {
            return Err(CdcError::Bounds(
                "CDC chunk extends beyond logical file size",
            ));
        }
        cursor = end;
    }
    // If logical_size is known and chunks are present, the last chunk must
    // reach exactly logical_size.
    if logical_size > 0 && !meta.chunks.is_empty() && cursor != logical_size {
        return Err(CdcError::Bounds(
            "CDC chunk table does not fully cover the logical file",
        ));
    }
    Ok(())
}
