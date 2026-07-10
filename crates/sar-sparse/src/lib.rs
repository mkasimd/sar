#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Sparse-file extent model, semantic validation, and scatter-gather
//! reconstruction for SAR sparse-file support.
//!
//! This crate owns the sparse extent model, semantic validation (ordered
//! non-overlapping extents, bounds checks, payload-length agreement), and
//! in-memory scatter-gather reconstruction.  Physical sparse map
//! parse/write (LFH binary format) remains in `sar-core`.

use serde::Serialize;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by sparse extent validation and reconstruction.
///
/// `sar-core` converts these to [`sar_core::SarError`] via the `From`
/// implementation defined in that crate.
#[derive(Debug, thiserror::Error)]
pub enum SparseError {
    /// A sparse extent exceeds the declared logical file size, or two extents
    /// overlap.
    #[error("sparse invalid map: {0}")]
    InvalidMap(&'static str),

    /// An arithmetic overflow occurred during extent offset/size computation.
    #[error("sparse overflow: {0}")]
    Overflow(&'static str),

    /// The payload is shorter than the total data described by the extents, or
    /// the extent list has trailing payload bytes.
    #[error("sparse truncated: {0}")]
    Truncated(&'static str),

    /// A resource limit was exceeded.
    #[error("sparse limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

// ── Resource limits ───────────────────────────────────────────────────────────

/// Resource limits for sparse extent validation and reconstruction.
///
/// Populated by `sar-core` from its unified `ResourceLimits` before calling
/// into this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseLimits {
    /// Maximum byte length of the raw sparse map blob.
    pub max_sparse_map_bytes: usize,
    /// Maximum number of sparse descriptors in a single map.
    pub max_sparse_descriptors: usize,
    /// Maximum decoded entry size in bytes.
    pub max_decoded_entry_size: u64,
    /// Maximum in-memory allocation in bytes for a single operation.
    pub max_allocation_bytes: u64,
}

impl SparseLimits {
    /// Returns limits with all bounds set to their maximum values (effectively
    /// unlimited).  Suitable for unit tests; not recommended for production
    /// untrusted input.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_sparse_map_bytes: usize::MAX,
            max_sparse_descriptors: usize::MAX,
            max_decoded_entry_size: u64::MAX,
            max_allocation_bytes: u64::MAX,
        }
    }

    fn check_sparse_descriptor_count(&self, count: usize) -> Result<(), SparseError> {
        if count > self.max_sparse_descriptors {
            return Err(SparseError::LimitExceeded(
                "sparse descriptor count exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn check_decoded_entry_size(&self, bytes: u64) -> Result<(), SparseError> {
        if bytes > self.max_decoded_entry_size {
            return Err(SparseError::LimitExceeded(
                "decoded entry size exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn allocation_len(&self, bytes: u64, context: &'static str) -> Result<usize, SparseError> {
        if bytes > self.max_allocation_bytes {
            return Err(SparseError::LimitExceeded(
                "allocation exceeds configured limit",
            ));
        }
        let len = usize::try_from(bytes).map_err(|_| SparseError::Overflow(context))?;
        if len > isize::MAX as usize {
            return Err(SparseError::Overflow(context));
        }
        Ok(len)
    }
}

// ── Public data types ─────────────────────────────────────────────────────────

/// A single contiguous data extent within a sparse logical file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SparseExtent {
    /// Byte offset of this extent within the logical file.
    pub offset: u64,
    /// Byte length of this extent.
    pub length: u64,
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validates a sparse extent list against the logical file size.
///
/// Checks that:
/// - No extent's `offset + length` exceeds `logical_size`.
/// - No two extents overlap (extents must be sorted by offset in ascending
///   order with no overlap).
///
/// # Errors
///
/// Returns [`SparseError::InvalidMap`] on overlap or bounds violation.
/// Returns [`SparseError::Overflow`] on arithmetic overflow.
pub fn validate_sparse_extents(
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &SparseLimits,
) -> Result<(), SparseError> {
    limits.check_sparse_descriptor_count(extents.len())?;
    let mut last_end: u64 = 0;
    let mut total_length: u64 = 0;
    for extent in extents {
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SparseError::Overflow(
                "sparse extent offset+length overflow",
            ))?;
        if end > logical_size {
            return Err(SparseError::InvalidMap(
                "sparse extent exceeds logical file size",
            ));
        }
        if extent.offset < last_end {
            return Err(SparseError::InvalidMap("sparse extents overlap"));
        }
        total_length = total_length
            .checked_add(extent.length)
            .ok_or(SparseError::Overflow("sparse extent length sum overflow"))?;
        last_end = end;
    }
    // Keep the checked running sum even when reconstruction is not performed
    // here so malformed maps with overflowing total sparse lengths fail during
    // validation.
    let _checked_total_length = total_length;
    Ok(())
}

// ── Reconstruction ────────────────────────────────────────────────────────────

/// Scatter-gathers a flat payload into a logical-size output buffer using the
/// sparse extent map.
///
/// Creates a `logical_size`-byte zero-filled buffer, then writes consecutive
/// chunks from `payload` at the positions specified by `extents`.  Gaps
/// between extents remain as `0x00` bytes.
///
/// # Errors
///
/// Returns [`SparseError::InvalidMap`] when any extent's `offset + length`
/// exceeds `logical_size` or when the payload has excess bytes beyond declared
/// extents.
/// Returns [`SparseError::Truncated`] when `payload` is shorter than the total
/// data described by `extents`.
/// Returns [`SparseError::Overflow`] on arithmetic overflow.
pub fn apply_sparse_reconstruction(
    payload: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
    limits: &SparseLimits,
) -> Result<Vec<u8>, SparseError> {
    limits.check_decoded_entry_size(logical_size)?;
    let logical_size_usize = limits.allocation_len(logical_size, "logical size usize")?;
    validate_sparse_extents(extents, logical_size, limits)?;
    let mut output = vec![0u8; logical_size_usize];
    let mut payload_pos: usize = 0;

    for extent in extents {
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SparseError::Overflow(
                "sparse extent offset+length overflow",
            ))?;
        if end > logical_size {
            return Err(SparseError::InvalidMap(
                "sparse extent exceeds logical file size",
            ));
        }
        let dst_start =
            usize::try_from(extent.offset).map_err(|_| SparseError::Overflow("extent offset"))?;
        let len =
            usize::try_from(extent.length).map_err(|_| SparseError::Overflow("extent length"))?;
        let dst_end = dst_start
            .checked_add(len)
            .ok_or(SparseError::Overflow("extent end"))?;
        let src_end = payload_pos
            .checked_add(len)
            .ok_or(SparseError::Overflow("payload position"))?;
        if src_end > payload.len() {
            return Err(SparseError::Truncated(
                "payload too short for declared sparse extents",
            ));
        }
        output[dst_start..dst_end].copy_from_slice(&payload[payload_pos..src_end]);
        payload_pos = src_end;
    }
    if payload_pos != payload.len() {
        return Err(SparseError::InvalidMap(
            "sparse payload has excess bytes beyond declared extents",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SparseLimits {
        SparseLimits::unlimited()
    }

    fn ext(offset: u64, length: u64) -> SparseExtent {
        SparseExtent { offset, length }
    }

    // ── validate_sparse_extents ───────────────────────────────────────────────

    #[test]
    fn valid_single_extent() {
        let extents = vec![ext(0, 4)];
        assert!(validate_sparse_extents(&extents, 4, &limits()).is_ok());
    }

    #[test]
    fn valid_non_overlapping_extents() {
        let extents = vec![ext(0, 4), ext(8, 4)];
        assert!(validate_sparse_extents(&extents, 16, &limits()).is_ok());
    }

    #[test]
    fn valid_empty_extents() {
        assert!(validate_sparse_extents(&[], 0, &limits()).is_ok());
    }

    #[test]
    fn overlapping_extents_rejected() {
        let extents = vec![ext(0, 8), ext(4, 4)];
        let result = validate_sparse_extents(&extents, 16, &limits());
        assert!(matches!(result, Err(SparseError::InvalidMap(_))));
    }

    #[test]
    fn extent_beyond_logical_size_rejected() {
        let extents = vec![ext(8, 8)];
        let result = validate_sparse_extents(&extents, 12, &limits());
        assert!(matches!(result, Err(SparseError::InvalidMap(_))));
    }

    #[test]
    fn descriptor_count_limit_exceeded() {
        let limits = SparseLimits {
            max_sparse_descriptors: 1,
            ..SparseLimits::unlimited()
        };
        let extents = vec![ext(0, 4), ext(8, 4)];
        let result = validate_sparse_extents(&extents, 16, &limits);
        assert!(matches!(result, Err(SparseError::LimitExceeded(_))));
    }

    // ── apply_sparse_reconstruction ──────────────────────────────────────────

    #[test]
    fn reconstruction_with_leading_hole() {
        let extents = vec![ext(4, 4)];
        let payload = b"DATA";
        let output = apply_sparse_reconstruction(payload, &extents, 8, &limits())
            .expect("reconstruction ok");
        assert_eq!(output, b"\x00\x00\x00\x00DATA");
    }

    #[test]
    fn reconstruction_with_trailing_hole() {
        let extents = vec![ext(0, 4)];
        let payload = b"DATA";
        let output = apply_sparse_reconstruction(payload, &extents, 8, &limits())
            .expect("reconstruction ok");
        assert_eq!(output, b"DATA\x00\x00\x00\x00");
    }

    #[test]
    fn reconstruction_with_middle_hole() {
        let extents = vec![ext(0, 2), ext(6, 2)];
        let payload = b"ABCD";
        let output = apply_sparse_reconstruction(payload, &extents, 8, &limits())
            .expect("reconstruction ok");
        assert_eq!(output, b"AB\x00\x00\x00\x00CD");
    }

    #[test]
    fn reconstruction_empty_extents_zero_filled() {
        let output =
            apply_sparse_reconstruction(b"", &[], 4, &limits()).expect("reconstruction ok");
        assert_eq!(output, b"\x00\x00\x00\x00");
    }

    #[test]
    fn payload_too_short_returns_truncated() {
        let extents = vec![ext(0, 8)];
        let payload = b"ABCD"; // only 4 bytes, but 8 declared
        let result = apply_sparse_reconstruction(payload, &extents, 8, &limits());
        assert!(matches!(result, Err(SparseError::Truncated(_))));
    }

    #[test]
    fn excess_payload_bytes_rejected() {
        let extents = vec![ext(0, 4)];
        let payload = b"ABCDEFGH"; // 8 bytes, only 4 declared
        let result = apply_sparse_reconstruction(payload, &extents, 8, &limits());
        assert!(matches!(result, Err(SparseError::InvalidMap(_))));
    }

    #[test]
    fn expansion_bomb_limit_exceeded() {
        let limits = SparseLimits {
            max_decoded_entry_size: 8,
            max_allocation_bytes: 8,
            ..SparseLimits::unlimited()
        };
        // Claim a 16-byte logical file
        let extents = vec![ext(0, 4)];
        let result = apply_sparse_reconstruction(b"DATA", &extents, 16, &limits);
        assert!(matches!(result, Err(SparseError::LimitExceeded(_))));
    }

    #[test]
    fn sparse_map_on_non_zero_fragment_index_check() {
        // sar-core enforces this rule; sar-sparse just validates extents.
        // This test verifies extent validation is correct for a map that
        // would be on fragment index 0.
        let extents = vec![ext(0, 4), ext(8, 4)];
        assert!(validate_sparse_extents(&extents, 16, &limits()).is_ok());
    }
}
