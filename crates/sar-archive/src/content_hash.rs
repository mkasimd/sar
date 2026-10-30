// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! LFH Content Hash generation and verification over the final logical Entry.
//!
//! The digest domain is the complete reconstructed logical Entry, including
//! sparse holes (logical zero-valued ranges), never the stored payload or the
//! gathered sparse bytes.

use sar_core::SarError;
use sar_crypto::hash::{Hasher, ct_eq, new_hasher};
use sar_sparse::SparseExtent;

const ZERO_CHUNK: [u8; 8192] = [0u8; 8192];

fn make_hasher(algo_id: u8) -> Result<Box<dyn Hasher>, SarError> {
    new_hasher(algo_id).map_err(SarError::from)
}

fn finish(hasher: Box<dyn Hasher>) -> Result<[u8; 32], SarError> {
    let digest = hasher.finalize();
    <[u8; 32]>::try_from(digest.as_slice())
        .map_err(|_| SarError::Internal("content hash digest is not 32 bytes"))
}

fn update_zeros(hasher: &mut dyn Hasher, mut count: u64) {
    while count > 0 {
        let step = usize::try_from(count).map_or(ZERO_CHUNK.len(), |n| n.min(ZERO_CHUNK.len()));
        hasher.update(&ZERO_CHUNK[..step]);
        count -= step as u64;
    }
}

/// Digest of a complete logical Entry held in memory.
pub(crate) fn digest_logical(algo_id: u8, data: &[u8]) -> Result<[u8; 32], SarError> {
    let mut hasher = make_hasher(algo_id)?;
    hasher.update(data);
    finish(hasher)
}

/// Digest of a sparse logical Entry computed from gathered bytes and extents,
/// hashing holes as zero runs without materializing the logical file.
///
/// `extents` must already be validated (ordered, non-overlapping, within
/// `logical_size`, summing to `gathered.len()`).
pub(crate) fn digest_sparse_logical(
    algo_id: u8,
    gathered: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
) -> Result<[u8; 32], SarError> {
    let mut hasher = make_hasher(algo_id)?;
    let mut position = 0u64;
    let mut cursor = 0usize;
    for extent in extents {
        let gap = extent
            .offset
            .checked_sub(position)
            .ok_or(SarError::Malformed("sparse extents are not ordered"))?;
        update_zeros(hasher.as_mut(), gap);
        let len = usize::try_from(extent.length)
            .map_err(|_| SarError::Overflow("sparse extent length"))?;
        let end = cursor
            .checked_add(len)
            .ok_or(SarError::Overflow("sparse gathered cursor"))?;
        let chunk = gathered.get(cursor..end).ok_or(SarError::InvalidLength(
            "gathered data shorter than extents",
        ))?;
        hasher.update(chunk);
        cursor = end;
        position = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SarError::Overflow("sparse extent end"))?;
    }
    let tail = logical_size
        .checked_sub(position)
        .ok_or(SarError::Malformed("sparse extent exceeds logical size"))?;
    update_zeros(hasher.as_mut(), tail);
    finish(hasher)
}

/// Verifies the final logical Entry against an authoritative Content Hash.
///
/// An all-zero `expected` value is an ordinary digest value, not an absent hash.
pub(crate) fn verify_logical(
    algo_id: Option<u8>,
    expected: Option<[u8; 32]>,
    data: &[u8],
) -> Result<(), SarError> {
    let (Some(algo_id), Some(expected)) = (algo_id, expected) else {
        return Ok(());
    };
    let actual = digest_logical(algo_id, data)?;
    if ct_eq(&actual, &expected) {
        Ok(())
    } else {
        Err(SarError::HashMismatch(
            "content hash mismatch on reconstructed logical entry",
        ))
    }
}

/// Verifies an authoritative LFH Content Hash over the final logical Entry
/// without materializing sparse holes.
///
/// `gathered` is the Entry's stored/gathered bytes.  When `sparse` is
/// `Some((extents, logical_size))`, the digest covers the logical file with
/// holes hashed as zero runs; otherwise it covers `gathered` directly.  Nothing
/// is verified when either `algo_id` or `expected` is `None`.  An all-zero
/// `expected` value is an ordinary digest.
///
/// # Errors
///
/// * [`SarError::HashMismatch`] when the digest differs.
/// * The mapped registry status for an unassigned, reserved or unsupported
///   `algo_id`.
/// * [`SarError::Malformed`] / [`SarError::InvalidLength`] /
///   [`SarError::Overflow`] when `extents` are inconsistent with `gathered`.
pub fn verify_content_hash(
    algo_id: Option<u8>,
    expected: Option<[u8; 32]>,
    gathered: &[u8],
    sparse: Option<(&[SparseExtent], u64)>,
) -> Result<(), SarError> {
    let (Some(algo), Some(expected)) = (algo_id, expected) else {
        return Ok(());
    };
    let actual = match sparse {
        Some((extents, logical_size)) => {
            digest_sparse_logical(algo, gathered, extents, logical_size)?
        }
        None => digest_logical(algo, gathered)?,
    };
    if ct_eq(&actual, &expected) {
        Ok(())
    } else {
        Err(SarError::HashMismatch(
            "content hash mismatch on reconstructed logical entry",
        ))
    }
}
