// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Sparse-file map parsing, writing, and scatter-gather reconstruction.
//!
//! This module provides physical LFH sparse map parse/write functions:
//!
//! * [`parse_sparse_map`] — decodes the on-wire byte blob into a
//!   `Vec<SparseExtent>`.
//! * [`write_sparse_map`] — encodes `SparseExtent` values to the on-wire byte
//!   format.  Returns an error rather than silently truncating `u64` values
//!   that exceed `u32::MAX` in 32-bit sparse-map mode.
//!
//! Semantic validation ([`sar_sparse::validate_sparse_extents`]) and
//! scatter-gather reconstruction ([`sar_sparse::apply_sparse_reconstruction`])
//! are owned by the `sar-sparse` crate.  Import them directly from there.
//!
//! # Architectural note on `SparseExtent` re-export
//!
//! [`SparseExtent`] is re-exported here because it is the shared data type
//! between the wire-format functions in this module and the semantic functions
//! in `sar-sparse`.  Callers of [`parse_sparse_map`] and [`write_sparse_map`]
//! need to name the type without an additional direct dependency on `sar-sparse`.

pub use sar_sparse::SparseExtent;

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
///
/// # Errors
///
/// In 32-bit mode (`is_64bit = false`), returns [`SarError::Overflow`] if any
/// extent's `offset` or `length` exceeds [`u32::MAX`].  Silent truncation is
/// never permitted.
pub fn write_sparse_map(extents: &[SparseExtent], is_64bit: bool) -> Result<Vec<u8>, SarError> {
    let entry_size: usize = if is_64bit { 16 } else { 8 };
    let mut bytes = Vec::with_capacity(extents.len() * entry_size);
    for extent in extents {
        if is_64bit {
            bytes.extend_from_slice(&extent.offset.to_le_bytes());
            bytes.extend_from_slice(&extent.length.to_le_bytes());
        } else {
            let offset32 = u32::try_from(extent.offset).map_err(|_| {
                SarError::Overflow("sparse extent offset exceeds u32::MAX in 32-bit sparse map")
            })?;
            let length32 = u32::try_from(extent.length).map_err(|_| {
                SarError::Overflow("sparse extent length exceeds u32::MAX in 32-bit sparse map")
            })?;
            bytes.extend_from_slice(&offset32.to_le_bytes());
            bytes.extend_from_slice(&length32.to_le_bytes());
        }
    }
    Ok(bytes)
}
