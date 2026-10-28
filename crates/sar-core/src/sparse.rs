// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Sparse-file map parsing, writing, and scatter-gather reconstruction.
//!
//! This module provides physical LFH sparse map parse/write functions:
//!
//! * [`parse_sparse_map`] — decodes the on-wire byte blob (Sparse Logical Size
//!   followed by Sparse Extent descriptors) into a [`SparseMap`].
//! * [`write_sparse_map`] — encodes a [`SparseMap`] to the on-wire byte
//!   format.  Returns an error rather than silently truncating `u64` values
//!   that exceed `u32::MAX` in 32-bit sparse-map mode.
//!
//! Semantic validation ([`sar_sparse::validate_sparse_extents`]) and
//! scatter-gather reconstruction ([`sar_sparse::apply_sparse_reconstruction`])
//! are owned by the `sar-sparse` crate.  Import them directly from there.
//!
//! # Architectural note on `SparseExtent` re-export
//!
//! [`SparseExtent`] and [`SparseMap`] are re-exported here because it is the shared data type
//! between the wire-format functions in this module and the semantic functions
//! in `sar-sparse`.  Callers of [`parse_sparse_map`] and [`write_sparse_map`]
//! need to name the types without an additional direct dependency on `sar-sparse`.

pub use sar_sparse::{SparseExtent, SparseMap};

use crate::{error::SarError, limits::ResourceLimits};

/// Parses a Sparse Map byte blob (`Sparse Logical Size || extents`).
///
/// When `is_64bit` is `true`, the logical size is a `u64` and each extent is
/// 16 bytes (`u64 offset, u64 length`); otherwise the size is a `u32` and each
/// extent is 8 bytes.  The blob must be non-empty: an absent map is signalled
/// by a Sparse Map Size of zero and is handled by the caller.
///
/// Semantic extent validation is performed separately by
/// `sar_sparse::validate_sparse_extents`.
///
/// # Errors
///
/// Returns [`SarError::InvalidMap`] when `bytes` is shorter than the Sparse
/// Logical Size field or the remainder is not a multiple of the extent size.
/// Returns [`SarError::LimitExceeded`] when the byte length or descriptor count
/// exceeds the configured limits.
pub fn parse_sparse_map(
    bytes: &[u8],
    is_64bit: bool,
    limits: &ResourceLimits,
) -> Result<SparseMap, SarError> {
    limits.check_sparse_map_bytes(bytes.len())?;
    let width: usize = if is_64bit { 8 } else { 4 };
    let entry_size = width * 2;
    if bytes.len() < width {
        return Err(SarError::InvalidMap(
            "sparse map is shorter than the sparse logical size field",
        ));
    }
    let (size_bytes, descriptors) = bytes.split_at(width);
    if !descriptors.len().is_multiple_of(entry_size) {
        return Err(SarError::InvalidMap(
            "sparse map descriptor bytes are not a multiple of the extent size",
        ));
    }
    let count = descriptors.len() / entry_size;
    limits.check_sparse_descriptor_count(count)?;
    if count > isize::MAX as usize / std::mem::size_of::<SparseExtent>() {
        return Err(SarError::Overflow("sparse descriptor allocation"));
    }
    let read = |chunk: &[u8]| -> u64 {
        if is_64bit {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            u64::from_le_bytes(b)
        } else {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            u64::from(u32::from_le_bytes(b))
        }
    };
    let logical_size = read(size_bytes);
    let mut extents = Vec::with_capacity(count);
    for chunk in descriptors.chunks_exact(entry_size) {
        extents.push(SparseExtent {
            offset: read(&chunk[..width]),
            length: read(&chunk[width..]),
        });
    }
    Ok(SparseMap {
        logical_size,
        extents,
    })
}

/// Encodes a [`SparseMap`] to the on-wire byte format.
///
/// When `is_64bit` is `true` the logical size and each extent field are written
/// as little-endian `u64` values; otherwise as little-endian `u32` values.
///
/// # Errors
///
/// In 32-bit mode (`is_64bit = false`), returns [`SarError::Overflow`] if the
/// logical size or any extent `offset` or `length` exceeds [`u32::MAX`].
/// Silent truncation is never permitted.
pub fn write_sparse_map(map: &SparseMap, is_64bit: bool) -> Result<Vec<u8>, SarError> {
    let width: usize = if is_64bit { 8 } else { 4 };
    let total = map
        .extents
        .len()
        .checked_mul(width * 2)
        .and_then(|n| n.checked_add(width))
        .ok_or(SarError::Overflow("sparse map byte length"))?;
    let mut bytes = Vec::with_capacity(total);
    let mut put = |value: u64, what: &'static str| -> Result<(), SarError> {
        if is_64bit {
            bytes.extend_from_slice(&value.to_le_bytes());
        } else {
            let v = u32::try_from(value).map_err(|_| SarError::Overflow(what))?;
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    };
    put(
        map.logical_size,
        "sparse logical size exceeds u32::MAX in 32-bit sparse map",
    )?;
    for extent in &map.extents {
        put(
            extent.offset,
            "sparse extent offset exceeds u32::MAX in 32-bit sparse map",
        )?;
        put(
            extent.length,
            "sparse extent length exceeds u32::MAX in 32-bit sparse map",
        )?;
    }
    Ok(bytes)
}
