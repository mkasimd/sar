#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Fragment-group semantic validation and reassembly for SAR file-fragmentation
//! (Section 19).
//!
//! This crate owns fragment descriptor models, fragment group ordering and
//! continuity validation, and fragment reassembly execution.  Raw LFH
//! fragment fields, `IS_FRAGMENT`/`LAST_FRAGMENT` bits, and archive
//! reader/writer integration remain in `sar-core`.
//!
//! # Validation coverage
//!
//! | Check                                     | Function                   |
//! |-------------------------------------------|----------------------------|
//! | Fragment count / group span limits        | [`validate_fragment_group`] |
//! | Descriptor bounds (offset+size ≤ logical) | [`validate_fragment_group`] |
//! | Descriptor overlap (sorted order)         | [`validate_fragment_group`] |
//! | Duplicate `fragment_index` (fatal)        | [`reconstruct_fragments`]  |
//! | Payload length == `fragment_size`         | [`reconstruct_fragments`]  |
//! | Index gaps / missing `LAST_FRAGMENT`      | [`reconstruct_fragments`]  |
//! | Loss-tolerant gap policy                  | [`reconstruct_fragments`] via [`sar_loss_tolerant`] |

use sar_loss_tolerant::gap_degraded_output_permitted;
use serde::Serialize;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by fragment validation and reassembly operations.
///
/// `sar-core` converts these to [`sar_core::SarError`] via the `From`
/// implementation defined in that crate.
#[derive(Debug, thiserror::Error)]
pub enum FragmentError {
    /// A fragment descriptor extends beyond the declared logical file size, or
    /// a scatter-gather offset exceeds the output buffer.
    #[error("fragment bounds error: {0}")]
    Bounds(&'static str),

    /// Two fragment descriptors overlap in the logical address space.
    #[error("fragment invalid map: {0}")]
    InvalidMap(&'static str),

    /// A gap in fragment indices was detected and `LOSS_TOLERANT` was not set.
    #[error("fragment gap: {0}")]
    FragmentGap(&'static str),

    /// An arithmetic overflow occurred during fragment offset/size computation.
    #[error("fragment overflow: {0}")]
    Overflow(&'static str),

    /// A resource limit was exceeded (fragment count, group span, or gap size).
    #[error("fragment limit exceeded: {0}")]
    LimitExceeded(&'static str),

    /// A fragment's `payload.len()` does not equal its `fragment_size`
    /// descriptor field.  This is always fatal, regardless of `LOSS_TOLERANT`.
    #[error("fragment payload size mismatch: {0}")]
    PayloadSizeMismatch(&'static str),

    /// Two or more fragments share the same `fragment_index`.  This is always
    /// fatal, regardless of `LOSS_TOLERANT`.
    #[error("fragment duplicate index: {0}")]
    DuplicateIndex(&'static str),
}

// ── Resource limits ───────────────────────────────────────────────────────────

/// Resource limits for fragment group validation and reassembly.
///
/// Populated by `sar-core` from its unified `ResourceLimits` before calling
/// into this crate.  All fields are checked **before** allocating or reading
/// the corresponding number of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentLimits {
    /// Maximum number of fragments in a single fragment group.
    pub max_fragment_count: usize,
    /// Maximum logical span (in bytes) of a fragment group.
    pub max_fragment_group_span: u64,
    /// Maximum decoded entry size in bytes.
    pub max_decoded_entry_size: u64,
    /// Maximum permitted loss-tolerant gap size in bytes.
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

    fn check_loss_tolerant_gap(&self, bytes: u64) -> Result<(), FragmentError> {
        if bytes > self.max_loss_tolerant_gap {
            return Err(FragmentError::LimitExceeded(
                "loss-tolerant gap exceeds configured limit",
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

/// Typed fragment descriptor extracted from an LFH.
///
/// Mirrors the `(u64, u32)` pair stored in the `LocalFileHeader` as
/// human-readable named fields.  The raw wire-format pair is owned by
/// `sar-core`; this struct is the semantic view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FragmentDescriptor {
    /// Absolute byte offset of this fragment within the logical file.
    pub absolute_offset: u64,
    /// Byte length of this fragment's contribution to the logical file.
    pub fragment_size: u32,
}

/// One fragment's reassembly data.
#[derive(Debug, Clone)]
pub struct FragmentEntry {
    /// Zero-based monotonic fragment sequence number.
    pub fragment_index: u32,
    /// True when the `LAST_FRAGMENT` mode bit is set.
    pub is_last_fragment: bool,
    /// True when the `LOSS_TOLERANT` mode bit is set.
    pub is_loss_tolerant: bool,
    /// Descriptor: absolute offset and declared size in logical file.
    pub descriptor: FragmentDescriptor,
    /// Decoded fragment payload bytes.
    ///
    /// Must equal `descriptor.fragment_size` in length.  A mismatch is always
    /// fatal: [`reconstruct_fragments`] returns
    /// [`FragmentError::PayloadSizeMismatch`] regardless of `LOSS_TOLERANT`.
    pub payload: Vec<u8>,
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validates fragment-group metadata consistency.
///
/// Checks (in order):
/// 1. Fragment count ≤ `limits.max_fragment_count`.
/// 2. `logical_size` ≤ `limits.max_fragment_group_span`.
/// 3. No fragment descriptor extends beyond `logical_size` (bounds check).
/// 4. No two descriptors overlap (sorted by absolute offset).
///
/// **Does not check**:
/// - Payload-length agreement (that check lives in [`reconstruct_fragments`]).
/// - Duplicate `fragment_index` (that check lives in [`reconstruct_fragments`]).
/// - Index gaps or `LAST_FRAGMENT` presence (those checks live in
///   [`reconstruct_fragments`]).
///
/// # Errors
///
/// Returns [`FragmentError::LimitExceeded`] when a limit is exceeded.
/// Returns [`FragmentError::Bounds`] when a fragment extends beyond
/// `logical_size`.
/// Returns [`FragmentError::InvalidMap`] when two fragment descriptors overlap.
/// Returns [`FragmentError::Overflow`] on arithmetic overflow.
pub fn validate_fragment_group(
    fragments: &[FragmentEntry],
    logical_size: u64,
    limits: &FragmentLimits,
) -> Result<(), FragmentError> {
    limits.check_fragment_count(fragments.len())?;
    limits.check_fragment_group_span(logical_size)?;
    // Validate each fragment independently
    for frag in fragments {
        let end = u64::from(frag.descriptor.fragment_size)
            .checked_add(frag.descriptor.absolute_offset)
            .ok_or(FragmentError::Overflow("fragment descriptor end overflow"))?;
        if end > logical_size {
            return Err(FragmentError::Bounds(
                "fragment descriptor extends beyond logical file size",
            ));
        }
    }

    // Check for overlapping descriptors by sorting on absolute_offset
    let mut sorted: Vec<&FragmentEntry> = fragments.iter().collect();
    sorted.sort_by_key(|f| f.descriptor.absolute_offset);

    let mut last_end: u64 = 0;
    for frag in &sorted {
        if frag.descriptor.absolute_offset < last_end {
            return Err(FragmentError::InvalidMap("fragment descriptors overlap"));
        }
        last_end = frag
            .descriptor
            .absolute_offset
            .checked_add(u64::from(frag.descriptor.fragment_size))
            .ok_or(FragmentError::Overflow("fragment end overflow"))?;
    }

    Ok(())
}

// ── Reassembly ────────────────────────────────────────────────────────────────

/// Reconstructs a logical file from a fragment group.
///
/// Algorithm:
/// 1. Limit-check fragment count and group span.
/// 2. **Fail closed** on duplicate `fragment_index` — always, regardless of
///    `LOSS_TOLERANT`.
/// 3. Sort fragments by `fragment_index`.
/// 4. **Fail closed** on payload-size mismatch (`payload.len() !=
///    fragment_size`) for each fragment — always, regardless of
///    `LOSS_TOLERANT`.
/// 5. Check for index gaps and missing `LAST_FRAGMENT` marker.  If gaps exist
///    and `LOSS_TOLERANT` is **not** set (as determined by
///    [`sar_loss_tolerant::gap_degraded_output_permitted`]), return
///    [`FragmentError::FragmentGap`].  With `LOSS_TOLERANT`, continue and mark
///    `is_degraded = true`.
/// 6. Run [`validate_fragment_group`] for bounds/overlap checks.
/// 7. Allocate a `logical_size`-byte zero buffer.
/// 8. Scatter each fragment's `payload` at `descriptor.absolute_offset`.
///
/// Returns `(reconstructed_bytes, is_degraded)` where `is_degraded` is `true`
/// when the output is incomplete due to missing fragments permitted by
/// `LOSS_TOLERANT`.
///
/// # Errors
///
/// * [`FragmentError::DuplicateIndex`] — duplicate `fragment_index` (always
///   fatal).
/// * [`FragmentError::PayloadSizeMismatch`] — `payload.len() != fragment_size`
///   (always fatal).
/// * [`FragmentError::FragmentGap`] — gap without `LOSS_TOLERANT`.
/// * [`FragmentError::Bounds`] / [`FragmentError::InvalidMap`] — from
///   validation.
/// * [`FragmentError::Overflow`] — on size arithmetic overflow.
/// * [`FragmentError::LimitExceeded`] — when a resource limit is exceeded.
pub fn reconstruct_fragments(
    mut fragments: Vec<FragmentEntry>,
    logical_size: u64,
    limits: &FragmentLimits,
) -> Result<(Vec<u8>, bool), FragmentError> {
    limits.check_fragment_count(fragments.len())?;
    limits.check_fragment_group_span(logical_size)?;
    limits.check_decoded_entry_size(logical_size)?;
    if fragments.is_empty() {
        let buf_size = limits.allocation_len(logical_size, "logical size")?;
        return Ok((vec![0u8; buf_size], false));
    }

    // Sort by fragment_index ascending
    fragments.sort_by_key(|f| f.fragment_index);

    // Duplicate index check — always fatal, regardless of LOSS_TOLERANT.
    for pair in fragments.windows(2) {
        if pair[0].fragment_index == pair[1].fragment_index {
            return Err(FragmentError::DuplicateIndex(
                "duplicate fragment_index detected",
            ));
        }
    }

    // Payload-size mismatch check — always fatal, regardless of LOSS_TOLERANT.
    for frag in &fragments {
        let declared = frag.descriptor.fragment_size as usize;
        if frag.payload.len() != declared {
            return Err(FragmentError::PayloadSizeMismatch(
                "fragment payload length does not match descriptor fragment_size",
            ));
        }
    }

    let is_loss_tolerant = fragments.iter().any(|f| f.is_loss_tolerant);
    let has_last = fragments.iter().any(|f| f.is_last_fragment);

    // Check for index gaps
    let mut has_gap = !has_last;
    if !has_gap {
        for pair in fragments.windows(2) {
            if pair[1].fragment_index != pair[0].fragment_index.wrapping_add(1) {
                has_gap = true;
                break;
            }
        }
    }

    if has_gap && !gap_degraded_output_permitted(is_loss_tolerant) {
        return Err(FragmentError::FragmentGap(
            "fragment index gap or missing last-fragment marker",
        ));
    }

    // Validate descriptor bounds and overlaps
    validate_fragment_group(&fragments, logical_size, limits)?;

    let mut sorted: Vec<&FragmentEntry> = fragments.iter().collect();
    sorted.sort_by_key(|f| f.descriptor.absolute_offset);
    let mut last_end: u64 = 0;
    for frag in &sorted {
        if frag.descriptor.absolute_offset > last_end && is_loss_tolerant {
            limits.check_loss_tolerant_gap(
                frag.descriptor
                    .absolute_offset
                    .checked_sub(last_end)
                    .ok_or(FragmentError::Overflow("fragment gap"))?,
            )?;
        }
        last_end = frag
            .descriptor
            .absolute_offset
            .checked_add(u64::from(frag.descriptor.fragment_size))
            .ok_or(FragmentError::Overflow("fragment end overflow"))?;
    }

    // Allocate logical output buffer
    let buf_size = limits.allocation_len(logical_size, "logical size usize")?;
    let mut output = vec![0u8; buf_size];

    // Scatter-gather: each fragment's payload goes to its absolute offset
    for frag in &fragments {
        let dst_start = usize::try_from(frag.descriptor.absolute_offset)
            .map_err(|_| FragmentError::Overflow("fragment offset usize"))?;
        let len = frag.payload.len();
        let dst_end = dst_start
            .checked_add(len)
            .ok_or(FragmentError::Overflow("fragment end usize"))?;
        if dst_end > buf_size {
            return Err(FragmentError::Bounds(
                "fragment payload extends beyond logical file size",
            ));
        }
        output[dst_start..dst_end].copy_from_slice(&frag.payload);
    }

    Ok((output, has_gap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> FragmentLimits {
        FragmentLimits::unlimited()
    }

    fn make_entry(
        index: u32,
        is_last: bool,
        is_loss_tolerant: bool,
        offset: u64,
        size: u32,
        payload: Vec<u8>,
    ) -> FragmentEntry {
        FragmentEntry {
            fragment_index: index,
            is_last_fragment: is_last,
            is_loss_tolerant,
            descriptor: FragmentDescriptor {
                absolute_offset: offset,
                fragment_size: size,
            },
            payload,
        }
    }

    #[test]
    fn complete_reassembly_two_fragments() {
        let f0 = make_entry(0, false, false, 0, 5, b"Hello".to_vec());
        let f1 = make_entry(1, true, false, 5, 6, b" World".to_vec());
        let (data, degraded) =
            reconstruct_fragments(vec![f0, f1], 11, &limits()).expect("reconstruct ok");
        assert_eq!(data, b"Hello World");
        assert!(!degraded);
    }

    #[test]
    fn single_fragment_complete() {
        let f0 = make_entry(0, true, false, 0, 4, b"test".to_vec());
        let (data, degraded) =
            reconstruct_fragments(vec![f0], 4, &limits()).expect("reconstruct ok");
        assert_eq!(data, b"test");
        assert!(!degraded);
    }

    #[test]
    fn out_of_order_fragments_reassembled() {
        let f1 = make_entry(1, true, false, 3, 3, b"BAR".to_vec());
        let f0 = make_entry(0, false, false, 0, 3, b"FOO".to_vec());
        let (data, degraded) =
            reconstruct_fragments(vec![f1, f0], 6, &limits()).expect("reconstruct ok");
        assert_eq!(data, b"FOOBAR");
        assert!(!degraded);
    }

    #[test]
    fn missing_fragment_without_loss_tolerant_is_error() {
        // Fragment 0 and 2, gap at 1
        let f0 = make_entry(0, false, false, 0, 4, b"AAAA".to_vec());
        let f2 = make_entry(2, true, false, 8, 4, b"CCCC".to_vec());
        let result = reconstruct_fragments(vec![f0, f2], 12, &limits());
        assert!(matches!(result, Err(FragmentError::FragmentGap(_))));
    }

    #[test]
    fn missing_fragment_with_loss_tolerant_produces_degraded_output() {
        let f0 = make_entry(0, false, true, 0, 4, b"AAAA".to_vec());
        let f2 = make_entry(2, true, true, 8, 4, b"CCCC".to_vec());
        let (data, degraded) =
            reconstruct_fragments(vec![f0, f2], 12, &limits()).expect("reconstruct ok");
        // Bytes 4-7 are zero-filled (gap), rest are as-written
        assert_eq!(&data[0..4], b"AAAA");
        assert_eq!(&data[4..8], b"\x00\x00\x00\x00");
        assert_eq!(&data[8..12], b"CCCC");
        assert!(degraded);
    }

    #[test]
    fn overlapping_fragment_descriptors_rejected() {
        let f0 = make_entry(0, false, false, 0, 8, b"AAAAAAAA".to_vec());
        let f1 = make_entry(1, true, false, 4, 8, b"BBBBBBBB".to_vec());
        let result = reconstruct_fragments(vec![f0, f1], 16, &limits());
        assert!(matches!(result, Err(FragmentError::InvalidMap(_))));
    }

    #[test]
    fn fragment_descriptor_beyond_logical_size_rejected() {
        let f0 = make_entry(0, true, false, 10, 6, b"XXXXXX".to_vec());
        let result = reconstruct_fragments(vec![f0], 12, &limits());
        // offset 10 + size 6 = 16 > 12
        assert!(matches!(result, Err(FragmentError::Bounds(_))));
    }

    #[test]
    fn fragment_count_limit_exceeded() {
        let limits = FragmentLimits {
            max_fragment_count: 2,
            ..FragmentLimits::unlimited()
        };
        let frags: Vec<FragmentEntry> = (0..3u32)
            .map(|i| make_entry(i, i == 2, false, u64::from(i) * 4, 4, vec![0u8; 4]))
            .collect();
        let result = reconstruct_fragments(frags, 12, &limits);
        assert!(matches!(result, Err(FragmentError::LimitExceeded(_))));
    }

    #[test]
    fn max_fragment_group_span_exceeded() {
        let limits = FragmentLimits {
            max_fragment_group_span: 8,
            ..FragmentLimits::unlimited()
        };
        let f0 = make_entry(0, true, false, 0, 4, b"AAAA".to_vec());
        // logical_size 16 > max_fragment_group_span 8
        let result = reconstruct_fragments(vec![f0], 16, &limits);
        assert!(matches!(result, Err(FragmentError::LimitExceeded(_))));
    }

    #[test]
    fn missing_last_fragment_marker_without_loss_tolerant_rejected() {
        // No fragment has is_last_fragment = true
        let f0 = make_entry(0, false, false, 0, 4, b"AAAA".to_vec());
        let f1 = make_entry(1, false, false, 4, 4, b"BBBB".to_vec());
        let result = reconstruct_fragments(vec![f0, f1], 8, &limits());
        assert!(matches!(result, Err(FragmentError::FragmentGap(_))));
    }

    #[test]
    fn validate_fragment_group_non_overlapping_ok() {
        let frags = vec![
            make_entry(0, false, false, 0, 4, vec![0u8; 4]),
            make_entry(1, true, false, 4, 4, vec![0u8; 4]),
        ];
        assert!(validate_fragment_group(&frags, 8, &limits()).is_ok());
    }

    #[test]
    fn validate_fragment_group_overlap_rejected() {
        let frags = vec![
            make_entry(0, false, false, 0, 8, vec![0u8; 8]),
            make_entry(1, true, false, 4, 4, vec![0u8; 4]),
        ];
        let result = validate_fragment_group(&frags, 16, &limits());
        assert!(matches!(result, Err(FragmentError::InvalidMap(_))));
    }

    // ── New: payload-size mismatch tests ─────────────────────────────────────

    #[test]
    fn payload_shorter_than_fragment_size_rejected() {
        // declared size=8, payload=4 bytes
        let f0 = make_entry(0, true, false, 0, 8, vec![0u8; 4]);
        let result = reconstruct_fragments(vec![f0], 8, &limits());
        assert!(
            matches!(result, Err(FragmentError::PayloadSizeMismatch(_))),
            "expected PayloadSizeMismatch, got {result:?}"
        );
    }

    #[test]
    fn payload_longer_than_fragment_size_rejected() {
        // declared size=4, payload=8 bytes
        let f0 = make_entry(0, true, false, 0, 4, vec![0u8; 8]);
        let result = reconstruct_fragments(vec![f0], 8, &limits());
        assert!(
            matches!(result, Err(FragmentError::PayloadSizeMismatch(_))),
            "expected PayloadSizeMismatch, got {result:?}"
        );
    }

    #[test]
    fn payload_size_mismatch_not_suppressed_by_loss_tolerant() {
        // LOSS_TOLERANT is set but payload mismatch must still fail closed
        let f0 = make_entry(0, true, true, 0, 8, vec![0u8; 4]);
        let result = reconstruct_fragments(vec![f0], 8, &limits());
        assert!(
            matches!(result, Err(FragmentError::PayloadSizeMismatch(_))),
            "expected PayloadSizeMismatch even with LOSS_TOLERANT, got {result:?}"
        );
    }

    // ── New: duplicate index tests ────────────────────────────────────────────

    #[test]
    fn duplicate_fragment_index_rejected() {
        // Two fragments with index 0
        let f0a = make_entry(0, false, false, 0, 4, vec![0u8; 4]);
        let f0b = make_entry(0, true, false, 4, 4, vec![0u8; 4]);
        let result = reconstruct_fragments(vec![f0a, f0b], 8, &limits());
        assert!(
            matches!(result, Err(FragmentError::DuplicateIndex(_))),
            "expected DuplicateIndex, got {result:?}"
        );
    }

    #[test]
    fn duplicate_fragment_index_with_loss_tolerant_rejected() {
        // Duplicate index must fail closed even with LOSS_TOLERANT set
        let f0a = make_entry(0, false, true, 0, 4, vec![0u8; 4]);
        let f0b = make_entry(0, true, true, 4, 4, vec![0u8; 4]);
        let result = reconstruct_fragments(vec![f0a, f0b], 8, &limits());
        assert!(
            matches!(result, Err(FragmentError::DuplicateIndex(_))),
            "expected DuplicateIndex even with LOSS_TOLERANT, got {result:?}"
        );
    }

    // ── New: LAST_FRAGMENT behavior test ──────────────────────────────────────

    #[test]
    fn missing_last_fragment_with_loss_tolerant_produces_degraded_output() {
        // No fragment has is_last_fragment = true, but LOSS_TOLERANT is set →
        // degraded output is permitted
        let f0 = make_entry(0, false, true, 0, 4, b"AAAA".to_vec());
        let f1 = make_entry(1, false, true, 4, 4, b"BBBB".to_vec());
        let (data, degraded) =
            reconstruct_fragments(vec![f0, f1], 8, &limits()).expect("reconstruct ok");
        assert!(
            degraded,
            "expected degraded=true when LAST_FRAGMENT is absent"
        );
        assert_eq!(&data[..4], b"AAAA");
        assert_eq!(&data[4..8], b"BBBB");
    }

    // ── New: loss-tolerant uses policy crate ──────────────────────────────────

    #[test]
    fn loss_tolerant_gap_uses_policy_crate() {
        use sar_loss_tolerant::gap_degraded_output_permitted;
        // Verify that the policy function is what controls gap acceptance
        assert!(!gap_degraded_output_permitted(false));
        assert!(gap_degraded_output_permitted(true));

        // Without LOSS_TOLERANT: gap → error
        let f0 = make_entry(0, false, false, 0, 4, b"AAAA".to_vec());
        let f2 = make_entry(2, true, false, 8, 4, b"CCCC".to_vec());
        assert!(matches!(
            reconstruct_fragments(vec![f0, f2], 12, &limits()),
            Err(FragmentError::FragmentGap(_))
        ));

        // With LOSS_TOLERANT: gap → degraded output
        let f0 = make_entry(0, false, true, 0, 4, b"AAAA".to_vec());
        let f2 = make_entry(2, true, true, 8, 4, b"CCCC".to_vec());
        let (_, degraded) = reconstruct_fragments(vec![f0, f2], 12, &limits())
            .expect("loss-tolerant gap should succeed");
        assert!(degraded);
    }
}
