// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Archive-level Data Recovery TLV inspection, planning, and repair (Section 9.2).
//!
//! The protected byte range is defined as: "beginning at the first byte of
//! Global Flags and ending at the final byte before the Central Dictionary"
//! (i.e. bytes `[8, cd_offset)` in the archive).
//!
//! # Limitations
//!
//! Current archive-level recovery APIs are in-memory APIs.  They accept the
//! complete archive as `&[u8]`, inspect or repair the protected range in memory,
//! and return repaired archive bytes as `Vec<u8>`.
//!
//! Callers must enforce [`ResourceLimits`] before passing untrusted archives or
//! erasure inputs to these APIs.  In particular, `max_archive_size`,
//! `max_recovery_protected_range`, and `max_repair_working_set` bound the
//! supported repair working set.  `max_repair_working_set` is a staged,
//! conservative model enforced by [`repair_archive`] (see its documentation);
//! it is not an exact measurement of allocator or codec-internal memory, and
//! it does not bound codec CPU time (which is O(groups x erasures)).
//!
//! These APIs are suitable for bounded repair workflows, conformance tests, and
//! controlled archive sizes.  They are not streaming repair APIs and do not yet
//! support external-storage-backed repair for very large archives.
//!
//! Full archive-level repair orchestration also requires explicit,
//! block-aligned byte erasures.  See `docs/SPEC_QUESTIONS.md` for the open spec
//! questions that prevent complete arbitrary-erasure orchestration.
use serde::{Deserialize, Serialize};

use sar_core::{
    SarError,
    fec::{FecSummary, validate_recovery_tlv},
    flags::GlobalFlags,
    format::{
        GLOBAL_HEADER_FLAGS_OFFSET, parse_central_dictionary, parse_footer, parse_global_header,
    },
    limits::ResourceLimits,
};

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// A byte range that was erased or corrupted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRange {
    /// Absolute byte offset within the archive (or within the protected range,
    /// depending on context).
    pub offset: u64,
    /// Byte length of the erased region.
    pub length: u64,
}

/// A byte range protected by a FEC TLV (for reporting purposes).
#[derive(Debug, Clone, Serialize)]
pub struct ProtectedRange {
    /// Absolute byte offset where protection starts.
    pub offset: u64,
    /// Number of bytes protected.
    pub length: u64,
    /// FEC algorithm ID of the protecting TLV (`0x11` RS or `0x14` XOR).
    pub algo_id: u8,
}

/// Per-entry erasure specification (for potential future entry-level repair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryErasure {
    /// Zero-based entry index (not yet used in archive-level repair).
    pub entry_index: usize,
    /// Byte erasures within the entry payload.
    pub ranges: Vec<ErasureRange>,
}

/// Erasure input for an archive-level repair operation.
///
/// Deserialized from the JSON file passed to `sar repair --erasures`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureInput {
    /// Per-entry (file-level) erasures, indexed by `entry_index`.
    /// Not used in archive-level repair; reserved for future selective-FEC
    /// repair.
    pub entries: Vec<EntryErasure>,
    /// Archive-level byte erasures within the protected range.
    pub archive_ranges: Vec<ErasureRange>,
}

/// Summary of archive-level recovery metadata.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryMetadata {
    /// True when the `HAS_GLOBAL_EC` global flag is set.
    pub has_global_ec: bool,
    /// Protected byte range, when computable.
    pub protected_range: Option<ProtectedRange>,
    /// All RECOVERY TLVs found in the Central Dictionary (`0x10..=0x1F`).
    pub recovery_tlvs: Vec<FecSummary>,
    /// True when structural metadata indicates repair is possible.
    pub repair_possible: bool,
    /// Human-readable reason when `repair_possible` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair_unavailable_reason: Option<&'static str>,
}

/// A validated repair plan ready for execution.
#[derive(Debug, Clone)]
pub struct RecoveryPlan {
    /// Erasure input, validated against the protected range.
    pub erasures: ErasureInput,
    /// The protected range that will be repaired.
    pub protected_range: ProtectedRange,
    /// FEC algorithm ID that will be used for repair.
    pub algo_id: u8,
}

/// Summary of a completed repair operation.
#[derive(Debug, Clone, Serialize)]
pub struct RepairReport {
    /// True when repair completed successfully.
    pub success: bool,
    /// Byte ranges that were repaired.
    pub repaired_ranges: Vec<ErasureRange>,
    /// True when the output is potentially degraded (only when LOSS_TOLERANT
    /// semantics applied).
    pub degraded: bool,
    /// Error message on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parsed archive layout positions needed for recovery operations.
struct ArchiveLayout {
    global_flags: GlobalFlags,
    /// Absolute offset of the Central Dictionary (equals `data_area_end`).
    /// `None` for `NO_INDEX` archives (no CD → no recovery TLV → unavailable).
    cd_offset: Option<u64>,
    /// RECOVERY TLVs from the CD.
    recovery_tlvs: Vec<(u8, Vec<u8>)>, // (type_id, value)
}

/// Parses the layout.  When `enforce_working_set` is set, the stage-1 repair
/// working set (input archive plus a `2 × cd_len` estimate for Central
/// Dictionary parse structures and cloned RECOVERY TLVs; the estimate can be
/// exceeded by the shared parser, see [`repair_archive`]) is checked
/// against `max_repair_working_set` before the CD is parsed.
fn parse_archive_layout(
    archive_bytes: &[u8],
    limits: &ResourceLimits,
    enforce_working_set: bool,
) -> Result<ArchiveLayout, SarError> {
    limits.check_archive_size(
        u64::try_from(archive_bytes.len()).map_err(|_| SarError::Overflow("archive size"))?,
    )?;
    let (global_header, _header_len) = parse_global_header(archive_bytes, limits)?;
    let flags = global_header.flags;
    sar_core::format::require_unpartitioned_processing(flags)?;

    if flags.contains(GlobalFlags::NO_INDEX) {
        return Ok(ArchiveLayout {
            global_flags: flags,
            cd_offset: None,
            recovery_tlvs: Vec::new(),
        });
    }

    if archive_bytes.len() < 8 {
        return Err(SarError::Truncated("archive too short for footer"));
    }
    let footer_bytes = &archive_bytes[archive_bytes.len() - 8..];
    let footer = parse_footer(footer_bytes)?;
    let cd_off = footer.cd_offset;
    let archive_end = archive_bytes
        .len()
        .checked_sub(8)
        .ok_or(SarError::Bounds("archive too short for CD/footer layout"))?;
    let cd_start = usize::try_from(cd_off).map_err(|_| SarError::Overflow("cd offset usize"))?;
    if cd_start >= archive_end {
        return Err(SarError::Bounds("CD offset outside archive"));
    }

    let cd_len = archive_end
        .checked_sub(cd_start)
        .ok_or(SarError::Bounds("CD offset outside archive"))?;
    let cd_len_u64 = u64::try_from(cd_len).map_err(|_| SarError::Overflow("CD length"))?;
    limits.check_cd_bytes(cd_len_u64)?;
    if enforce_working_set {
        let archive_len = u64::try_from(archive_bytes.len())
            .map_err(|_| SarError::Overflow("archive repair working set"))?;
        let cd_estimate = cd_len_u64
            .checked_mul(2)
            .ok_or(SarError::Overflow("archive repair working set"))?;
        check_working_set(limits, &[archive_len, cd_estimate])?;
    }
    let cd_bytes = &archive_bytes[cd_start..cd_start + cd_len];
    let (cd, _) = parse_central_dictionary(cd_bytes, flags, limits)?;

    let recovery_tlvs: Vec<(u8, Vec<u8>)> = cd
        .metadata
        .iter()
        .filter(|tlv| (0x10..=0x1F).contains(&tlv.type_id))
        .map(|tlv| (tlv.type_id, tlv.value.clone()))
        .collect();

    Ok(ArchiveLayout {
        global_flags: flags,
        cd_offset: Some(cd_off),
        recovery_tlvs,
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inspects archive-level recovery metadata from raw archive bytes.
///
/// Parses the global header and Central Dictionary, locates RECOVERY TLVs
/// (`0x10..=0x1F`), and computes the protected byte range.
///
/// # Errors
///
/// Returns [`SarError`] on malformed archive structure.
pub fn inspect_recovery_metadata(
    archive_bytes: &[u8],
    limits: &ResourceLimits,
) -> Result<RecoveryMetadata, SarError> {
    let layout = parse_archive_layout(archive_bytes, limits, false)?;
    inspect_layout(&layout, limits)
}

fn inspect_layout(
    layout: &ArchiveLayout,
    limits: &ResourceLimits,
) -> Result<RecoveryMetadata, SarError> {
    let has_global_ec = layout.global_flags.contains(GlobalFlags::HAS_GLOBAL_EC);

    // Compute protected range when CD exists
    let (protected_range, recovery_tlvs) = if let Some(cd_off) = layout.cd_offset {
        let prot_len = cd_off
            .checked_sub(GLOBAL_HEADER_FLAGS_OFFSET)
            .ok_or(SarError::Bounds("CD offset lies before Global Flags"))?;
        limits.check_recovery_protected_range(prot_len)?;

        // Parse and validate all RECOVERY TLVs
        let mut summaries = Vec::new();
        for (type_id, value) in &layout.recovery_tlvs {
            let summary = validate_recovery_tlv(*type_id, value, limits)?;
            summaries.push(summary);
        }

        let first_algo = summaries.first().map_or(0, |s| match s {
            FecSummary::Xor { algo_id, .. } | FecSummary::ReedSolomon { algo_id, .. } => *algo_id,
        });

        let pr = if prot_len > 0 {
            Some(ProtectedRange {
                offset: GLOBAL_HEADER_FLAGS_OFFSET,
                length: prot_len,
                algo_id: first_algo,
            })
        } else {
            None
        };

        (pr, summaries)
    } else {
        (None, Vec::new())
    };

    let repair_possible = has_global_ec && !recovery_tlvs.is_empty() && protected_range.is_some();
    let repair_unavailable_reason: Option<&'static str> = if !has_global_ec {
        Some("archive does not have HAS_GLOBAL_EC flag set")
    } else if layout.cd_offset.is_none() {
        Some("NO_INDEX archive has no Central Dictionary and therefore no RECOVERY TLV")
    } else if recovery_tlvs.is_empty() {
        Some("no RECOVERY TLV found in Central Dictionary")
    } else {
        None
    };

    Ok(RecoveryMetadata {
        has_global_ec,
        protected_range,
        recovery_tlvs,
        repair_possible,
        repair_unavailable_reason,
    })
}

/// Validates an erasure input and builds an executable repair plan.
///
/// Returns [`SarError::RecoveryUnavailable`] when:
/// - The archive lacks `HAS_GLOBAL_EC` or a RECOVERY TLV.
/// - Any erasure range lies outside the protected range.
/// - Erasures are not aligned to the FEC block/symbol boundaries (see
///   `docs/SPEC_QUESTIONS.md` for the spec gap that requires this constraint).
///
/// # Errors
///
/// See above plus [`SarError`] on malformed archive structure.
pub fn plan_archive_repair(
    archive_bytes: &[u8],
    erasures: ErasureInput,
    limits: &ResourceLimits,
) -> Result<RecoveryPlan, SarError> {
    let layout = parse_archive_layout(archive_bytes, limits, false)?;
    let meta = inspect_layout(&layout, limits)?;
    drop(layout);

    if !meta.repair_possible {
        return Err(SarError::RecoveryUnavailable(
            meta.repair_unavailable_reason
                .unwrap_or("archive-level repair is unavailable"),
        ));
    }

    let protected_range = meta.protected_range.ok_or(SarError::RecoveryUnavailable(
        "protected range could not be determined",
    ))?;

    // Determine block/symbol size from the first (validated) RECOVERY TLV
    let first_summary = meta
        .recovery_tlvs
        .first()
        .ok_or(SarError::RecoveryUnavailable(
            "no usable RECOVERY TLV found for block-size derivation",
        ))?;
    let (algo_id, block_size_bytes) = block_size_from_summary(first_summary)?;

    validate_erasure_ranges(
        &erasures.archive_ranges,
        protected_range.offset,
        protected_range.length,
        block_size_bytes,
    )?;

    Ok(RecoveryPlan {
        erasures,
        protected_range: ProtectedRange {
            offset: protected_range.offset,
            length: protected_range.length,
            algo_id,
        },
        algo_id,
    })
}

/// Returns `(algo_id, block_size)` of the first RECOVERY TLV summary.
fn block_size_from_summary(summary: &FecSummary) -> Result<(u8, u64), SarError> {
    let (algo_id, block_size) = match summary {
        FecSummary::Xor {
            algo_id,
            block_size,
            ..
        } => (*algo_id, u64::from(*block_size)),
        FecSummary::ReedSolomon {
            algo_id,
            symbol_size,
            ..
        } => (*algo_id, u64::from(*symbol_size)),
    };
    if block_size == 0 {
        return Err(SarError::InvalidLength("recovery block size is zero"));
    }
    Ok((algo_id, block_size))
}

/// Validates erasure ranges against the protected range and block size without
/// allocating.  Every range must lie inside `[prot_offset, prot_offset +
/// prot_length)` and be block-aligned relative to `prot_offset`.
fn validate_erasure_ranges(
    ranges: &[ErasureRange],
    prot_offset: u64,
    prot_length: u64,
    block_size: u64,
) -> Result<(), SarError> {
    if block_size == 0 {
        return Err(SarError::InvalidLength("recovery block size is zero"));
    }
    let prot_end = prot_offset
        .checked_add(prot_length)
        .ok_or(SarError::Overflow("protected range end"))?;
    for er in ranges {
        let er_end = er
            .offset
            .checked_add(er.length)
            .ok_or(SarError::Overflow("erasure range end"))?;
        if er.offset < prot_offset || er_end > prot_end {
            return Err(SarError::RecoveryUnavailable(
                "erasure range lies outside the protected byte range",
            ));
        }
        let rel_off = er.offset - prot_offset;
        if !rel_off.is_multiple_of(block_size) || !er.length.is_multiple_of(block_size) {
            return Err(SarError::RecoveryUnavailable(
                "archive-level repair orchestration requires explicit block-aligned erasure \
                 mapping; see docs/SPEC_QUESTIONS.md",
            ));
        }
    }
    Ok(())
}

/// Codec-derived sizes used for working-set accounting.
struct CodecSizing {
    block_size: u64,
    /// Original protected length declared by the TLV.
    original_len: u64,
    /// Length of the buffer the codec allocates (stripe/group padded).
    padded_len: u64,
    /// Conservative estimate of codec scratch memory besides the padded output.
    scratch: u64,
    /// Maximum number of distinct erasures the parity can possibly cover.
    max_erasures: u64,
}

fn codec_sizing(summary: &FecSummary) -> Result<CodecSizing, SarError> {
    let overflow = SarError::Overflow("recovery codec sizing");
    match summary {
        FecSummary::Xor {
            stripe_size,
            block_size,
            original_protected_len,
            stripe_count,
            ..
        } => {
            let bs = u64::from(*block_size);
            let ss = u64::from(*stripe_size);
            let padded_len = u64::from(*stripe_count)
                .checked_mul(ss)
                .and_then(|v| v.checked_mul(bs))
                .ok_or(overflow)?;
            // block buffer + recovered block + per-stripe erasure list
            let scratch = bs
                .checked_mul(2)
                .and_then(|v| v.checked_add(ss.checked_mul(8)?))
                .ok_or(SarError::Overflow("recovery codec sizing"))?;
            Ok(CodecSizing {
                block_size: bs,
                original_len: *original_protected_len,
                padded_len,
                scratch,
                max_erasures: u64::from(*stripe_count),
            })
        }
        FecSummary::ReedSolomon {
            k,
            parity_count,
            symbol_size,
            original_protected_len,
            group_count,
            ..
        } => {
            let ss = u64::from(*symbol_size);
            let pc = u64::from(*parity_count);
            let padded_len = u64::from(*group_count)
                .checked_mul(u64::from(*k))
                .and_then(|v| v.checked_mul(ss))
                .ok_or(overflow)?;
            let ov = || SarError::Overflow("recovery codec sizing");
            // Erased symbols per group are `t <= min(k, parity_count)`.
            let t_max = u64::from(*k).min(pc);
            // symbol buffer + RHS rows + recovered rows (each up to `pc` symbols)
            let symbol_buffers = pc
                .checked_mul(2)
                .and_then(|v| v.checked_add(1))
                .and_then(|v| v.checked_mul(ss))
                .ok_or_else(ov)?;
            // GF matrices live together during inversion: the t x t system,
            // the t x 2t augmented matrix and the t x t inverse (4 t^2 bytes).
            let matrices = t_max
                .checked_mul(t_max)
                .and_then(|v| v.checked_mul(4))
                .ok_or_else(ov)?;
            // Vandermonde generator (`parity_count x k`).
            let vandermonde = pc.checked_mul(u64::from(*k)).ok_or_else(ov)?;
            // Per-group index vectors (erased list up to k usize with growth
            // slack, parity selection) and `Vec<Vec<u8>>` row headers.
            let index_vectors = u64::from(*k)
                .checked_mul(16)
                .and_then(|v| v.checked_add(t_max.checked_mul(64)?))
                .ok_or_else(ov)?;
            let scratch = [symbol_buffers, matrices, vandermonde, index_vectors]
                .into_iter()
                .try_fold(0u64, u64::checked_add)
                .ok_or_else(ov)?;
            let max_erasures = u64::from(*group_count)
                .checked_mul(pc)
                .ok_or(SarError::Overflow("recovery codec sizing"))?;
            Ok(CodecSizing {
                block_size: ss,
                original_len: *original_protected_len,
                padded_len,
                scratch,
                max_erasures,
            })
        }
    }
}

/// Sums `parts` with checked arithmetic and enforces `max_repair_working_set`.
fn check_working_set(limits: &ResourceLimits, parts: &[u64]) -> Result<(), SarError> {
    let mut total: u64 = 0;
    for part in parts {
        total = total
            .checked_add(*part)
            .ok_or(SarError::Overflow("archive repair working set"))?;
    }
    limits.check_repair_working_set(total)
}

/// Allocates an empty `Vec` with exactly `len` capacity, reporting allocation
/// failure as a limit error rather than aborting.
fn alloc_vec<T>(len: u64) -> Result<Vec<T>, SarError> {
    let len = usize::try_from(len).map_err(|_| SarError::Overflow("repair allocation length"))?;
    let mut v = Vec::new();
    v.try_reserve_exact(len)
        .map_err(|_| SarError::LimitExceeded("repair allocation failed"))?;
    Ok(v)
}

fn bytes_of<T>(count: u64) -> Result<u64, SarError> {
    let size = u64::try_from(std::mem::size_of::<T>())
        .map_err(|_| SarError::Overflow("repair allocation size"))?;
    count
        .checked_mul(size)
        .ok_or(SarError::Overflow("archive repair working set"))
}

/// Executes a repair plan and returns the repaired archive bytes and a report.
///
/// Applies XOR or RS erasure recovery on the protected range of `archive_bytes`
/// using explicit erasure positions from `plan`.
///
/// `plan` is treated as untrusted: its protected range, algorithm IDs and
/// erasure ranges are re-validated against the archive and the RECOVERY TLV
/// with checked arithmetic before any allocation that scales with them.
///
/// # Working-set accounting
///
/// `max_repair_working_set` is enforced before each allocation stage against a
/// conservative peak-live-memory model that includes the borrowed input
/// archive (`A`), the cloned selected RECOVERY TLV, the merged-range and
/// erasure-index buffers, the codec's padded output plus estimated scratch
/// memory, and finally the recovered buffer plus the repaired output (`2A`-ish)
/// and report ranges.  Temporary buffers are dropped before the repaired
/// output is built.  Codec scratch is a dimension-dependent conservative
/// estimate (for Reed-Solomon: symbol buffers, `4 * min(k, parity)^2` bytes of
/// GF matrices, the `parity * k` Vandermonde matrix and per-group index
/// vectors), not a measurement.
///
/// The Central Dictionary stage is only an estimate (`2 * cd_len`).  The shared
/// Central Dictionary parser may allocate more than that: per-TLV `Vec<Tlv>`
/// overhead (up to about `4 * cd_len` for minimal TLVs, plus growth slack) and
/// an offsets table sized from the declared file count (bounded by
/// `max_entry_count`, not by the CD length) can exceed the modelled amount.
/// This is a recorded limitation for later parser hardening.  The model also
/// does not cover the plan, the caller's own copies, or allocator overhead.
///
/// The caller is responsible for writing the returned bytes to a temporary file
/// and renaming to the final destination only after structural verification.
///
/// # Errors
///
/// * [`SarError::EcFailed`] — erasures exceed parity capacity.
/// * [`SarError::RecoveryUnavailable`] — repair not supported, TLV not found,
///   or an erasure lies outside the protected range or is unaligned.
/// * [`SarError::LimitExceeded`] — a configured limit would be exceeded.
/// * [`SarError::Overflow`] / [`SarError::Bounds`] /
///   [`SarError::InvalidLength`] / [`SarError::Malformed`] — the plan is
///   inconsistent with the archive or contains overflowing values.
pub fn repair_archive(
    archive_bytes: &[u8],
    plan: &RecoveryPlan,
    limits: &ResourceLimits,
) -> Result<(Vec<u8>, RepairReport), SarError> {
    use sar_fec::{Erasure, FecCodec, FecRecoverInput, RsCodec, XorCodec};

    let archive_len = u64::try_from(archive_bytes.len())
        .map_err(|_| SarError::Overflow("archive repair working set"))?;

    // Stage 1: layout parse.  The CD-size estimate is checked inside.
    let layout = parse_archive_layout(archive_bytes, limits, true)?;
    let cd_offset = layout.cd_offset.ok_or(SarError::RecoveryUnavailable(
        "RECOVERY TLV with matching algo ID not found in archive",
    ))?;

    // Keep only the selected TLV; drop the rest.
    let mut tlvs = layout.recovery_tlvs;
    let tlv_pos = tlvs
        .iter()
        .position(|(type_id, _)| *type_id == plan.algo_id)
        .ok_or(SarError::RecoveryUnavailable(
            "RECOVERY TLV with matching algo ID not found in archive",
        ))?;
    let (tlv_algo_id, tlv_value) = tlvs.swap_remove(tlv_pos);
    drop(tlvs);

    // The plan is untrusted: it must match the archive exactly.
    if plan.protected_range.algo_id != plan.algo_id {
        return Err(SarError::Malformed(
            "recovery plan algorithm IDs are inconsistent",
        ));
    }
    let expected_len = cd_offset
        .checked_sub(GLOBAL_HEADER_FLAGS_OFFSET)
        .ok_or(SarError::Bounds("CD offset lies before Global Flags"))?;
    if plan.protected_range.offset != GLOBAL_HEADER_FLAGS_OFFSET
        || plan.protected_range.length != expected_len
    {
        return Err(SarError::Bounds(
            "recovery plan protected range does not match archive",
        ));
    }
    limits.check_recovery_protected_range(plan.protected_range.length)?;
    let prot_end = plan
        .protected_range
        .offset
        .checked_add(plan.protected_range.length)
        .ok_or(SarError::Overflow("protected range end"))?;
    if prot_end > archive_len {
        return Err(SarError::Bounds("protected range exceeds archive length"));
    }
    let prot_start = usize::try_from(plan.protected_range.offset)
        .map_err(|_| SarError::Overflow("prot start"))?;
    let prot_end_idx = usize::try_from(prot_end).map_err(|_| SarError::Overflow("prot end"))?;
    let protected_bytes = &archive_bytes[prot_start..prot_end_idx];

    let summary = validate_recovery_tlv(tlv_algo_id, &tlv_value, limits)?;
    let sizing = codec_sizing(&summary)?;
    if sizing.original_len != plan.protected_range.length {
        return Err(SarError::InvalidLength(
            "RECOVERY TLV protected length does not match plan protected range",
        ));
    }
    let ranges = &plan.erasures.archive_ranges;
    validate_erasure_ranges(
        ranges,
        plan.protected_range.offset,
        plan.protected_range.length,
        sizing.block_size,
    )?;

    let tlv_len =
        u64::try_from(tlv_value.len()).map_err(|_| SarError::Overflow("recovery TLV length"))?;
    let report_bytes = bytes_of::<ErasureRange>(
        u64::try_from(ranges.len()).map_err(|_| SarError::Overflow("erasure range count"))?,
    )?;

    // Stage 2: merged, sorted copy of the non-empty ranges (relative offsets).
    let non_empty = u64::try_from(ranges.iter().filter(|r| r.length != 0).count())
        .map_err(|_| SarError::Overflow("erasure range count"))?;
    let merge_bytes = bytes_of::<(u64, u64)>(non_empty)?;
    check_working_set(limits, &[archive_len, tlv_len, merge_bytes])?;
    let mut merged: Vec<(u64, u64)> = alloc_vec(non_empty)?;
    for er in ranges.iter().filter(|r| r.length != 0) {
        let start = er.offset - plan.protected_range.offset;
        let end = start
            .checked_add(er.length)
            .ok_or(SarError::Overflow("erasure range end"))?;
        merged.push((start, end));
    }
    merged.sort_unstable();
    let mut write = 0usize;
    for read in 0..merged.len() {
        let current = merged[read];
        if write > 0 && current.0 <= merged[write - 1].1 {
            merged[write - 1].1 = merged[write - 1].1.max(current.1);
        } else {
            merged[write] = current;
            write += 1;
        }
    }
    merged.truncate(write);

    // Ranges are block-aligned, so each merged span is a whole number of blocks.
    let mut unique_blocks: u64 = 0;
    for (start, end) in &merged {
        let blocks = (end - start) / sizing.block_size;
        unique_blocks = unique_blocks
            .checked_add(blocks)
            .ok_or(SarError::Overflow("erasure block count"))?;
    }
    if unique_blocks > sizing.max_erasures {
        return Err(SarError::EcFailed(
            "erasure count exceeds the parity capacity of the RECOVERY TLV",
        ));
    }

    // Enforce every remaining peak before allocating the index list or running
    // the codec.
    let index_bytes = bytes_of::<Erasure>(unique_blocks)?;
    check_working_set(limits, &[archive_len, tlv_len, merge_bytes, index_bytes])?;
    if unique_blocks == 0 {
        // No recovery needed: output is a copy of the input.
        check_working_set(limits, &[archive_len, archive_len, report_bytes])?;
    } else {
        check_working_set(
            limits,
            &[
                archive_len,
                tlv_len,
                index_bytes,
                sizing.padded_len,
                sizing.scratch,
            ],
        )?;
        check_working_set(
            limits,
            &[archive_len, sizing.padded_len, archive_len, report_bytes],
        )?;
    }

    let recovered: Option<Vec<u8>> = if unique_blocks == 0 {
        drop(merged);
        drop(tlv_value);
        None
    } else {
        let mut erasure_indices: Vec<Erasure> = alloc_vec(unique_blocks)?;
        for (start, end) in &merged {
            for idx in (start / sizing.block_size)..(end / sizing.block_size) {
                erasure_indices.push(Erasure { index: idx });
            }
        }
        drop(merged);

        let input = FecRecoverInput {
            original_protected_len: plan.protected_range.length,
            available_data: protected_bytes,
            fec_value_data: &tlv_value,
            erasures: &erasure_indices,
        };
        let recovered = match tlv_algo_id {
            0x14 => XorCodec::from_fec_value(&tlv_value)
                .map_err(SarError::from)?
                .recover(input)
                .map_err(SarError::from)?,
            0x11 => RsCodec::from_fec_value(&tlv_value)
                .map_err(SarError::from)?
                .recover(input)
                .map_err(SarError::from)?,
            _ => {
                return Err(SarError::RecoveryUnavailable(
                    "unsupported FEC algorithm for archive repair",
                ));
            }
        };
        drop(erasure_indices);
        drop(tlv_value);
        if recovered.len() != protected_bytes.len() {
            return Err(SarError::InvalidLength(
                "recovered protected range has unexpected length",
            ));
        }
        Some(recovered)
    };

    // Rebuild archive bytes: prefix + recovered_protected + remainder (CD + footer)
    let mut repaired: Vec<u8> = alloc_vec(archive_len)?;
    match recovered {
        Some(recovered) => {
            repaired.extend_from_slice(&archive_bytes[..prot_start]);
            repaired.extend_from_slice(&recovered);
            drop(recovered);
            repaired.extend_from_slice(&archive_bytes[prot_end_idx..]);
        }
        None => repaired.extend_from_slice(archive_bytes),
    }

    let repaired_ranges = plan.erasures.archive_ranges.clone();
    let report = RepairReport {
        success: true,
        repaired_ranges,
        degraded: false,
        error: None,
    };

    Ok((repaired, report))
}
