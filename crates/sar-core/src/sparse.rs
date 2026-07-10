//! Sparse-file map parsing, writing, and scatter-gather reconstruction.
//!
//! This module provides:
//!
//! * Physical LFH sparse map parse/write (`parse_sparse_map`, `write_sparse_map`):
//!   these are wire-format functions and remain in `sar-core`.
//! * Re-exports of semantic validation and reconstruction from [`sar_sparse`]:
//!   `SparseExtent`, `validate_sparse_extents`, `apply_sparse_reconstruction`.

pub use sar_sparse::{
    SparseError, SparseExtent, SparseLimits, apply_sparse_reconstruction, validate_sparse_extents,
};

use crate::{error::SarError, limits::ResourceLimits};

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
    if count > isize::MAX as usize / std::mem::size_of::<SparseExtent>() {
        return Err(SarError::Overflow("sparse descriptor allocation"));
    }
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
