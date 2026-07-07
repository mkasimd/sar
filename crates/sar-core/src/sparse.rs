//! Sparse-file map parsing, writing, validation, and scatter-gather reconstruction.

use serde::Serialize;

use crate::{error::SarError, limits::ResourceLimits};

/// A single contiguous data extent within a sparse logical file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SparseExtent {
    /// Byte offset of this extent within the logical file.
    pub offset: u64,
    /// Byte length of this extent.
    pub length: u64,
}

/// Parses a sparse map byte blob into a [`Vec<SparseExtent>`].
///
/// When `is_64bit` is `true`, each entry is 16 bytes (`u64 offset, u64
/// length`); otherwise 8 bytes (`u32 offset, u32 length`).
///
/// # Errors
///
/// Returns [`SarError::InvalidLength`] when `bytes` is not a multiple of the
/// entry size.
pub fn parse_sparse_map(
    bytes: &[u8],
    is_64bit: bool,
    limits: &ResourceLimits,
) -> Result<Vec<SparseExtent>, SarError> {
    limits.check_sparse_map_bytes(bytes.len())?;
    let entry_size: usize = if is_64bit { 16 } else { 8 };
    if !bytes.len().is_multiple_of(entry_size) {
        return Err(SarError::InvalidLength(
            "sparse map byte length is not a multiple of entry size",
        ));
    }
    let count = bytes.len() / entry_size;
    limits.check_sparse_descriptor_count(count)?;
    let mut extents = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if is_64bit {
            let offset = u64::from_le_bytes(
                bytes[pos..pos + 8]
                    .try_into()
                    .map_err(|_| SarError::Truncated("sparse entry offset"))?,
            );
            let length = u64::from_le_bytes(
                bytes[pos + 8..pos + 16]
                    .try_into()
                    .map_err(|_| SarError::Truncated("sparse entry length"))?,
            );
            extents.push(SparseExtent { offset, length });
            pos += 16;
        } else {
            let offset = u64::from(u32::from_le_bytes(
                bytes[pos..pos + 4]
                    .try_into()
                    .map_err(|_| SarError::Truncated("sparse entry offset"))?,
            ));
            let length = u64::from(u32::from_le_bytes(
                bytes[pos + 4..pos + 8]
                    .try_into()
                    .map_err(|_| SarError::Truncated("sparse entry length"))?,
            ));
            extents.push(SparseExtent { offset, length });
            pos += 8;
        }
    }
    Ok(extents)
}

/// Encodes sparse extents to the on-wire byte format.
///
/// When `is_64bit` is `true` each entry is written as two little-endian `u64`
/// values; otherwise as two little-endian `u32` values.
pub fn write_sparse_map(extents: &[SparseExtent], is_64bit: bool) -> Vec<u8> {
    let entry_size: usize = if is_64bit { 16 } else { 8 };
    let mut bytes = Vec::with_capacity(extents.len() * entry_size);
    for extent in extents {
        if is_64bit {
            bytes.extend_from_slice(&extent.offset.to_le_bytes());
            bytes.extend_from_slice(&extent.length.to_le_bytes());
        } else {
            #[allow(clippy::cast_possible_truncation)]
            bytes.extend_from_slice(&(extent.offset as u32).to_le_bytes());
            #[allow(clippy::cast_possible_truncation)]
            bytes.extend_from_slice(&(extent.length as u32).to_le_bytes());
        }
    }
    bytes
}

/// Validates a sparse extent list against the logical file size.
///
/// Checks that:
/// - No extent's `offset + length` exceeds `logical_size`.
/// - No two extents overlap (extents must be sorted by offset in ascending
///   order with no overlap).
///
/// # Errors
///
/// Returns [`SarError::InvalidMap`] on overlap or bounds violation.
/// Returns [`SarError::Overflow`] on arithmetic overflow.
pub fn validate_sparse_extents(
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<(), SarError> {
    limits.check_sparse_descriptor_count(extents.len())?;
    let mut last_end: u64 = 0;
    let mut total_length: u64 = 0;
    for extent in extents {
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SarError::Overflow("sparse extent offset+length overflow"))?;
        if end > logical_size {
            return Err(SarError::InvalidMap(
                "sparse extent exceeds logical file size",
            ));
        }
        if extent.offset < last_end {
            return Err(SarError::InvalidMap("sparse extents overlap"));
        }
        total_length = total_length
            .checked_add(extent.length)
            .ok_or(SarError::Overflow("sparse extent length sum overflow"))?;
        last_end = end;
    }
    let _ = total_length;
    Ok(())
}

/// Scatter-gathers a flat payload into a logical-size output buffer using the
/// sparse extent map.
///
/// Creates a `logical_size`-byte zero-filled buffer, then writes consecutive
/// chunks from `payload` at the positions specified by `extents`.  Gaps
/// between extents remain as `0x00` bytes.
///
/// # Errors
///
/// Returns [`SarError::InvalidMap`] (`SAR_ERR_INVALID_MAP`) when any extent's
/// `offset + length` exceeds `logical_size`.
/// Returns [`SarError::Truncated`] when `payload` is shorter than the total
/// data described by `extents`.
/// Returns [`SarError::Overflow`] on arithmetic overflow.
pub fn apply_sparse_reconstruction(
    payload: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<Vec<u8>, SarError> {
    limits.check_decoded_entry_size(logical_size)?;
    limits.check_allocation_bytes(logical_size)?;
    let logical_size_usize =
        usize::try_from(logical_size).map_err(|_| SarError::Overflow("logical size usize"))?;
    validate_sparse_extents(extents, logical_size, limits)?;
    let mut output = vec![0u8; logical_size_usize];
    let mut payload_pos: usize = 0;

    for extent in extents {
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SarError::Overflow("sparse extent offset+length overflow"))?;
        if end > logical_size {
            return Err(SarError::InvalidMap(
                "sparse extent exceeds logical file size",
            ));
        }
        let dst_start =
            usize::try_from(extent.offset).map_err(|_| SarError::Overflow("extent offset"))?;
        let len =
            usize::try_from(extent.length).map_err(|_| SarError::Overflow("extent length"))?;
        let dst_end = dst_start
            .checked_add(len)
            .ok_or(SarError::Overflow("extent end"))?;
        let src_end = payload_pos
            .checked_add(len)
            .ok_or(SarError::Overflow("payload position"))?;
        if src_end > payload.len() {
            return Err(SarError::Truncated(
                "payload too short for declared sparse extents",
            ));
        }
        output[dst_start..dst_end].copy_from_slice(&payload[payload_pos..src_end]);
        payload_pos = src_end;
    }
    if payload_pos != payload.len() {
        return Err(SarError::InvalidMap(
            "sparse payload has excess bytes beyond declared extents",
        ));
    }
    Ok(output)
}
