//! Fragment-group reassembly for SAR file-fragmentation (Section 19).
//!
//! Implements sort-and-scatter reassembly using Fragment Descriptors
//! (absolute offset + fragment size) as specified in the archive format.

use serde::Serialize;

use crate::{error::SarError, limits::ResourceLimits};

/// Typed fragment descriptor extracted from an LFH.
///
/// Mirrors the `(u64, u32)` pair stored in [`crate::format::LocalFileHeader`]
/// as human-readable named fields.
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
    pub payload: Vec<u8>,
}

/// Validates fragment-group metadata consistency.
///
/// Checks that no fragment descriptor extends beyond `logical_size` and that
/// no two descriptors overlap (sorted by absolute offset).
///
/// # Errors
///
/// Returns [`SarError::Bounds`] when a fragment extends beyond `logical_size`.
/// Returns [`SarError::InvalidMap`] when two fragment descriptors overlap.
/// Returns [`SarError::Overflow`] on arithmetic overflow.
pub fn validate_fragment_group(
    fragments: &[FragmentEntry],
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<(), SarError> {
    limits.check_fragment_count(fragments.len())?;
    limits.check_fragment_group_span(logical_size)?;
    // Validate each fragment independently
    for frag in fragments {
        let end = u64::from(frag.descriptor.fragment_size)
            .checked_add(frag.descriptor.absolute_offset)
            .ok_or(SarError::Overflow("fragment descriptor end overflow"))?;
        if end > logical_size {
            return Err(SarError::Bounds(
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
            return Err(SarError::InvalidMap("fragment descriptors overlap"));
        }
        last_end = frag
            .descriptor
            .absolute_offset
            .checked_add(u64::from(frag.descriptor.fragment_size))
            .ok_or(SarError::Overflow("fragment end overflow"))?;
    }

    Ok(())
}

/// Reconstructs a logical file from a fragment group.
///
/// Algorithm:
/// 1. Sort fragments by `fragment_index`.
/// 2. Validate: check for index gaps and that the last-fragment marker is
///    present. If gaps exist and `LOSS_TOLERANT` is **not** set, return
///    [`SarError::FragmentGap`]. With `LOSS_TOLERANT`, continue and mark
///    `is_degraded = true`.
/// 3. Run [`validate_fragment_group`] for bounds/overlap checks.
/// 4. Allocate a `logical_size`-byte zero buffer.
/// 5. Scatter each fragment's `payload` at `descriptor.absolute_offset`.
///
/// Returns `(reconstructed_bytes, is_degraded)` where `is_degraded` is `true`
/// when the output is incomplete due to missing fragments permitted by
/// `LOSS_TOLERANT`.
///
/// # Errors
///
/// * [`SarError::FragmentGap`] — gap without `LOSS_TOLERANT`.
/// * [`SarError::Bounds`] / [`SarError::InvalidMap`] — from validation.
/// * [`SarError::Overflow`] — on size arithmetic overflow.
pub fn reconstruct_fragments(
    mut fragments: Vec<FragmentEntry>,
    logical_size: u64,
    limits: &ResourceLimits,
) -> Result<(Vec<u8>, bool), SarError> {
    limits.check_fragment_count(fragments.len())?;
    limits.check_fragment_group_span(logical_size)?;
    limits.check_decoded_entry_size(logical_size)?;
    limits.check_allocation_bytes(logical_size)?;
    if fragments.is_empty() {
        let buf_size =
            usize::try_from(logical_size).map_err(|_| SarError::Overflow("logical size"))?;
        return Ok((vec![0u8; buf_size], false));
    }

    // Sort by fragment_index ascending
    fragments.sort_by_key(|f| f.fragment_index);

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

    if has_gap && !is_loss_tolerant {
        return Err(SarError::FragmentGap(
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
                    .ok_or(SarError::Overflow("fragment gap"))?,
            )?;
        }
        last_end = frag
            .descriptor
            .absolute_offset
            .checked_add(u64::from(frag.descriptor.fragment_size))
            .ok_or(SarError::Overflow("fragment end overflow"))?;
    }

    // Allocate logical output buffer
    let buf_size =
        usize::try_from(logical_size).map_err(|_| SarError::Overflow("logical size usize"))?;
    let mut output = vec![0u8; buf_size];

    // Scatter-gather: each fragment's payload goes to its absolute offset
    for frag in &fragments {
        let dst_start = usize::try_from(frag.descriptor.absolute_offset)
            .map_err(|_| SarError::Overflow("fragment offset usize"))?;
        let len = frag.payload.len();
        let dst_end = dst_start
            .checked_add(len)
            .ok_or(SarError::Overflow("fragment end usize"))?;
        if dst_end > buf_size {
            return Err(SarError::Bounds(
                "fragment payload extends beyond logical file size",
            ));
        }
        output[dst_start..dst_end].copy_from_slice(&frag.payload);
    }

    Ok((output, has_gap))
}
