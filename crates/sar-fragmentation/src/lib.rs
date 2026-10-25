// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Fragment-group semantic validation and canonical reassembly for SAR
//! file-fragmentation (Section 19).
//!
//! The canonical SAR v1.0 fragment representation carries only a Fragment ID
//! and a Fragment Index in each LFH.  A fragment's contribution length is its
//! LFH `Uncompressed Size`; there is no absolute offset on the wire.  This
//! crate reassembles decoded fragment contributions by concatenating them in
//! ascending Fragment Index order.
//!
//! Raw LFH fragment fields, `IS_FRAGMENT`/`LAST_FRAGMENT` bits, and archive
//! reader/writer integration remain in `sar-core`.
//!
//! # Validation coverage
//!
//! | Check                                          | Function                    |
//! |------------------------------------------------|-----------------------------|
//! | Fragment count limit                           | [`validate_fragment_group`] |
//! | Duplicate `fragment_index` (fatal)             | [`validate_fragment_group`] |
//! | Contribution length == `uncompressed_size`     | [`reconstruct_fragments`]   |
//! | `LAST_FRAGMENT` / `LOSS_TOLERANT` consistency  | [`validate_fragment_group`] |
//! | Checked total length, span and output limits   | [`validate_fragment_group`] |
//! | Dense index sequence and terminal marker       | [`reconstruct_fragments`]   |
//! | Longest-contiguous-prefix degraded output      | [`reconstruct_fragments`] via [`sar_loss_tolerant`] |

use sar_loss_tolerant::gap_degraded_output_permitted;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by fragment validation and reassembly operations.
///
/// `sar-core` converts these to [`sar_core::SarError`] via the `From`
/// implementation defined in that crate.
#[derive(Debug, thiserror::Error)]
pub enum FragmentError {
    /// A fragment bounds violation.
    #[error("fragment bounds error: {0}")]
    Bounds(&'static str),

    /// A structurally invalid map.
    #[error("fragment invalid map: {0}")]
    InvalidMap(&'static str),

    /// A gap in the fragment sequence was detected and `LOSS_TOLERANT` did not
    /// permit degraded output.
    #[error("fragment gap: {0}")]
    FragmentGap(&'static str),

    /// An arithmetic overflow occurred during fragment size computation.
    #[error("fragment overflow: {0}")]
    Overflow(&'static str),

    /// A resource limit was exceeded (fragment count, group span, output size).
    #[error("fragment limit exceeded: {0}")]
    LimitExceeded(&'static str),

    /// A fragment's decoded contribution length does not equal its declared
    /// LFH `Uncompressed Size`.  Always fatal, regardless of `LOSS_TOLERANT`.
    #[error("fragment payload size mismatch: {0}")]
    PayloadSizeMismatch(&'static str),

    /// Two or more fragments share the same `fragment_index`.  Always fatal,
    /// regardless of `LOSS_TOLERANT`.
    #[error("fragment duplicate index: {0}")]
    DuplicateIndex(&'static str),

    /// Fragment-group metadata is inconsistent (duplicate or misplaced
    /// `LAST_FRAGMENT`, or differing `LOSS_TOLERANT` values).  Always fatal.
    #[error("fragment metadata conflict: {0}")]
    MetadataConflict(&'static str),
}

// ── Resource limits ───────────────────────────────────────────────────────────

/// Resource limits for fragment group validation and reassembly.
///
/// Populated by `sar-core` from its unified `ResourceLimits` before calling
/// into this crate.  All fields are checked **before** allocating the
/// corresponding number of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentLimits {
    /// Maximum number of fragments in a single fragment group.
    pub max_fragment_count: usize,
    /// Maximum total decoded length (in bytes) of a fragment group.
    pub max_fragment_group_span: u64,
    /// Maximum decoded entry size in bytes.
    pub max_decoded_entry_size: u64,
    /// Maximum permitted loss-tolerant gap size in bytes.
    ///
    /// Not consulted by canonical reassembly: the length of a missing fragment
    /// is not recoverable, so no gap length can be measured.  Retained for
    /// limit-set compatibility pending M13b.2 review.
    pub max_loss_tolerant_gap: u64,
    /// Maximum in-memory allocation in bytes for a single operation.
    pub max_allocation_bytes: u64,
}

impl FragmentLimits {
    /// Returns limits with all bounds set to their maximum values (effectively
    /// unlimited).  Suitable for unit tests; not recommended for production
    /// untrusted input.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_fragment_count: usize::MAX,
            max_fragment_group_span: u64::MAX,
            max_decoded_entry_size: u64::MAX,
            max_loss_tolerant_gap: u64::MAX,
            max_allocation_bytes: u64::MAX,
        }
    }

    fn check_fragment_count(&self, count: usize) -> Result<(), FragmentError> {
        if count > self.max_fragment_count {
            return Err(FragmentError::LimitExceeded(
                "fragment count exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn check_fragment_group_span(&self, bytes: u64) -> Result<(), FragmentError> {
        if bytes > self.max_fragment_group_span {
            return Err(FragmentError::LimitExceeded(
                "fragment group span exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn check_decoded_entry_size(&self, bytes: u64) -> Result<(), FragmentError> {
        if bytes > self.max_decoded_entry_size {
            return Err(FragmentError::LimitExceeded(
                "decoded entry size exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn allocation_len(&self, bytes: u64, context: &'static str) -> Result<usize, FragmentError> {
        if bytes > self.max_allocation_bytes {
            return Err(FragmentError::LimitExceeded(
                "allocation exceeds configured limit",
            ));
        }
        let len = usize::try_from(bytes).map_err(|_| FragmentError::Overflow(context))?;
        if len > isize::MAX as usize {
            return Err(FragmentError::Overflow(context));
        }
        Ok(len)
    }
}

// ── Public data types ─────────────────────────────────────────────────────────

/// One fragment's reassembly data.
#[derive(Debug, Clone)]
pub struct FragmentEntry {
    /// Zero-based monotonic fragment sequence number (LFH Fragment Index).
    pub fragment_index: u32,
    /// True when the `LAST_FRAGMENT` mode bit is set.
    pub is_last_fragment: bool,
    /// True when the `LOSS_TOLERANT` mode bit is set.
    pub is_loss_tolerant: bool,
    /// Declared decoded contribution length: the LFH `Uncompressed Size`.
    pub uncompressed_size: u64,
    /// Decoded fragment contribution bytes.
    ///
    /// Must equal `uncompressed_size` in length.  A mismatch is always fatal:
    /// [`FragmentError::PayloadSizeMismatch`] regardless of `LOSS_TOLERANT`.
    pub payload: Vec<u8>,
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validates fragment-group metadata and size consistency.
///
/// Checks, in order:
/// 1. Fragment count ≤ `limits.max_fragment_count`.
/// 2. No duplicate `fragment_index`.
/// 3. At most one `LAST_FRAGMENT`, and no fragment with an index above it.
/// 4. `LOSS_TOLERANT` is identical across the group.
/// 5. Checked total contribution length (sum of declared `uncompressed_size`) ≤ group-span and decoded-entry limits.
///
/// Does **not** check payload bytes against `uncompressed_size`, index density,
/// or terminal-marker presence; those are evaluated by
/// [`reconstruct_fragments`].  Metadata-only callers may pass empty payloads.
///
/// # Errors
///
/// [`FragmentError::LimitExceeded`], [`FragmentError::DuplicateIndex`],
/// [`FragmentError::MetadataConflict`], or [`FragmentError::Overflow`].
pub fn validate_fragment_group(
    fragments: &[FragmentEntry],
    limits: &FragmentLimits,
) -> Result<(), FragmentError> {
    limits.check_fragment_count(fragments.len())?;

    let mut indices: Vec<u32> = fragments.iter().map(|f| f.fragment_index).collect();
    indices.sort_unstable();
    if indices.windows(2).any(|w| w[0] == w[1]) {
        return Err(FragmentError::DuplicateIndex(
            "duplicate fragment_index detected",
        ));
    }

    let mut total: u64 = 0;
    for frag in fragments {
        total = total
            .checked_add(frag.uncompressed_size)
            .ok_or(FragmentError::Overflow("fragment length sum overflow"))?;
    }

    let mut last_index: Option<u32> = None;
    for frag in fragments.iter().filter(|f| f.is_last_fragment) {
        if last_index.is_some() {
            return Err(FragmentError::MetadataConflict(
                "multiple LAST_FRAGMENT markers in fragment group",
            ));
        }
        last_index = Some(frag.fragment_index);
    }
    if let Some(last) = last_index
        && fragments.iter().any(|f| f.fragment_index > last)
    {
        return Err(FragmentError::MetadataConflict(
            "fragment index exceeds LAST_FRAGMENT index",
        ));
    }

    if let Some(first) = fragments.first()
        && fragments
            .iter()
            .any(|f| f.is_loss_tolerant != first.is_loss_tolerant)
    {
        return Err(FragmentError::MetadataConflict(
            "LOSS_TOLERANT differs across fragment group",
        ));
    }

    limits.check_fragment_group_span(total)?;
    limits.check_decoded_entry_size(total)?;
    Ok(())
}

// ── Reassembly ────────────────────────────────────────────────────────────────

/// Reconstructs a logical file from a fragment group by concatenating decoded
/// contributions in ascending Fragment Index order.
///
/// A group is complete when its indices are exactly `0..n` and the fragment
/// with index `n - 1` carries `LAST_FRAGMENT`.
///
/// For an incomplete group:
/// * without `LOSS_TOLERANT` the result is [`FragmentError::FragmentGap`];
/// * with `LOSS_TOLERANT`, if Fragment Index 0 is present, only the longest
///   contiguous valid prefix starting at index 0 is emitted and
///   `is_degraded` is `true`; otherwise [`FragmentError::FragmentGap`].
///
/// Missing fragments are never zero-filled, their lengths are never inferred,
/// and later fragments are never shifted across a gap.  Degraded output is not
/// verified output.
///
/// Returns `(reconstructed_bytes, is_degraded)`.
///
/// # Errors
///
/// Everything from [`validate_fragment_group`], plus
/// [`FragmentError::PayloadSizeMismatch`], [`FragmentError::FragmentGap`] and
/// allocation-limit errors.
pub fn reconstruct_fragments(
    mut fragments: Vec<FragmentEntry>,
    limits: &FragmentLimits,
) -> Result<(Vec<u8>, bool), FragmentError> {
    validate_fragment_group(&fragments, limits)?;
    if fragments.is_empty() {
        return Err(FragmentError::FragmentGap("fragment group is empty"));
    }
    for frag in &fragments {
        let actual = u64::try_from(frag.payload.len())
            .map_err(|_| FragmentError::Overflow("fragment payload length"))?;
        if actual != frag.uncompressed_size {
            return Err(FragmentError::PayloadSizeMismatch(
                "fragment decoded length does not match LFH uncompressed size",
            ));
        }
    }
    fragments.sort_by_key(|f| f.fragment_index);

    if fragments[0].fragment_index != 0 {
        return Err(FragmentError::FragmentGap(
            "fragment index 0 is missing from fragment group",
        ));
    }

    let mut prefix_len: usize = 1;
    while prefix_len < fragments.len()
        && u64::from(fragments[prefix_len].fragment_index)
            == u64::try_from(prefix_len)
                .map_err(|_| FragmentError::Overflow("fragment prefix length"))?
    {
        prefix_len += 1;
    }
    let complete = prefix_len == fragments.len() && fragments[prefix_len - 1].is_last_fragment;

    if !complete {
        let loss_tolerant = gap_degraded_output_permitted(fragments[0].is_loss_tolerant);
        if !loss_tolerant {
            return Err(FragmentError::FragmentGap(
                "fragment group is incomplete and LOSS_TOLERANT is not set",
            ));
        }
        fragments.truncate(prefix_len);
    }

    let mut total: u64 = 0;
    for frag in &fragments {
        total = total
            .checked_add(frag.uncompressed_size)
            .ok_or(FragmentError::Overflow("fragment length sum overflow"))?;
    }
    let capacity = limits.allocation_len(total, "fragment output length")?;
    let mut out = Vec::with_capacity(capacity);
    for frag in &fragments {
        out.extend_from_slice(&frag.payload);
    }
    Ok((out, !complete))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(index: u32, last: bool, lt: bool, data: &[u8]) -> FragmentEntry {
        FragmentEntry {
            fragment_index: index,
            is_last_fragment: last,
            is_loss_tolerant: lt,
            uncompressed_size: data.len() as u64,
            payload: data.to_vec(),
        }
    }

    fn unl() -> FragmentLimits {
        FragmentLimits::unlimited()
    }

    #[test]
    fn complete_dense_sequence() {
        let (out, degraded) = reconstruct_fragments(
            vec![frag(0, false, false, b"ab"), frag(1, true, false, b"cd")],
            &unl(),
        )
        .expect("ok");
        assert_eq!(out, b"abcd");
        assert!(!degraded);
    }

    #[test]
    fn out_of_order_input_ordered_by_index() {
        let (out, _) = reconstruct_fragments(
            vec![
                frag(2, true, false, b"EF"),
                frag(0, false, false, b"ab"),
                frag(1, false, false, b"cd"),
            ],
            &unl(),
        )
        .expect("ok");
        assert_eq!(out, b"abcdEF");
    }

    #[test]
    fn duplicate_index_is_fatal_even_loss_tolerant() {
        let err = reconstruct_fragments(
            vec![frag(0, false, true, b"a"), frag(0, true, true, b"b")],
            &unl(),
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::DuplicateIndex(_)));
    }

    #[test]
    fn missing_first_fragment_fails_even_loss_tolerant() {
        for lt in [false, true] {
            let err = reconstruct_fragments(vec![frag(1, true, lt, b"b")], &unl())
                .expect_err("must fail");
            assert!(matches!(err, FragmentError::FragmentGap(_)));
        }
    }

    #[test]
    fn missing_interior_fails_without_loss_tolerance() {
        let err = reconstruct_fragments(
            vec![frag(0, false, false, b"a"), frag(2, true, false, b"c")],
            &unl(),
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::FragmentGap(_)));
    }

    #[test]
    fn missing_interior_loss_tolerant_emits_prefix_only() {
        let (out, degraded) = reconstruct_fragments(
            vec![
                frag(0, false, true, b"aa"),
                frag(1, false, true, b"bb"),
                frag(3, true, true, b"dd"),
            ],
            &unl(),
        )
        .expect("ok");
        assert!(degraded);
        // No zero fill, no concatenation across the gap.
        assert_eq!(out, b"aabb");
    }

    #[test]
    fn missing_terminal_fails_without_loss_tolerance() {
        let err = reconstruct_fragments(
            vec![frag(0, false, false, b"a"), frag(1, false, false, b"b")],
            &unl(),
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::FragmentGap(_)));
    }

    #[test]
    fn missing_terminal_loss_tolerant_is_degraded_prefix() {
        let (out, degraded) = reconstruct_fragments(
            vec![frag(0, false, true, b"a"), frag(1, false, true, b"b")],
            &unl(),
        )
        .expect("ok");
        assert!(degraded);
        assert_eq!(out, b"ab");
    }

    #[test]
    fn duplicate_last_fragment_is_conflict() {
        let err = reconstruct_fragments(
            vec![frag(0, true, false, b"a"), frag(1, true, false, b"b")],
            &unl(),
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::MetadataConflict(_)));
    }

    #[test]
    fn fragment_after_last_is_conflict() {
        let err = reconstruct_fragments(
            vec![frag(0, true, true, b"a"), frag(1, false, true, b"b")],
            &unl(),
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::MetadataConflict(_)));
    }

    #[test]
    fn inconsistent_loss_tolerant_is_conflict() {
        let err = reconstruct_fragments(
            vec![frag(0, false, true, b"a"), frag(1, true, false, b"b")],
            &unl(),
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::MetadataConflict(_)));
    }

    #[test]
    fn contribution_length_mismatch_is_fatal() {
        let mut f = frag(0, true, true, b"abc");
        f.uncompressed_size = 2;
        let err = reconstruct_fragments(vec![f], &unl()).expect_err("must fail");
        assert!(matches!(err, FragmentError::PayloadSizeMismatch(_)));
    }

    #[test]
    fn size_sum_overflow_is_checked() {
        let mut a = frag(0, false, false, b"");
        let mut b = frag(1, true, false, b"");
        a.uncompressed_size = u64::MAX;
        b.uncompressed_size = 1;
        let err = validate_fragment_group(&[a, b], &unl()).expect_err("must fail");
        assert!(matches!(err, FragmentError::Overflow(_)));
    }

    #[test]
    fn limits_enforced() {
        let mut l = unl();
        l.max_fragment_count = 1;
        let err = reconstruct_fragments(
            vec![frag(0, false, false, b"a"), frag(1, true, false, b"b")],
            &l,
        )
        .expect_err("must fail");
        assert!(matches!(err, FragmentError::LimitExceeded(_)));

        let mut l = unl();
        l.max_decoded_entry_size = 1;
        let err =
            reconstruct_fragments(vec![frag(0, true, false, b"ab")], &l).expect_err("must fail");
        assert!(matches!(err, FragmentError::LimitExceeded(_)));

        let mut l = unl();
        l.max_fragment_group_span = 1;
        let err =
            reconstruct_fragments(vec![frag(0, true, false, b"ab")], &l).expect_err("must fail");
        assert!(matches!(err, FragmentError::LimitExceeded(_)));

        let mut l = unl();
        l.max_allocation_bytes = 1;
        let err =
            reconstruct_fragments(vec![frag(0, true, false, b"ab")], &l).expect_err("must fail");
        assert!(matches!(err, FragmentError::LimitExceeded(_)));
    }

    #[test]
    fn empty_group_is_gap() {
        let err = reconstruct_fragments(vec![], &unl()).expect_err("must fail");
        assert!(matches!(err, FragmentError::FragmentGap(_)));
    }
}
