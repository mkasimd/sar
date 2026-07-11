//! Archive-level Data Recovery TLV inspection, planning, and repair (Section 9.2).
//!
//! The protected byte range is defined as: "beginning at the first byte of
//! Global Flags and ending at the final byte before the Central Dictionary"
//! (i.e. bytes `[8, cd_offset)` in the archive).
//!
//! # Limitations
//!
//! Full archive-level repair orchestration requires explicit, block-aligned
//! byte erasures.  See `docs/SPEC_QUESTIONS.md` for the open spec questions
//! that prevent complete arbitrary-erasure orchestration.

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

fn parse_archive_layout(
    archive_bytes: &[u8],
    limits: &ResourceLimits,
) -> Result<ArchiveLayout, SarError> {
    limits.check_archive_size(
        u64::try_from(archive_bytes.len()).map_err(|_| SarError::Overflow("archive size"))?,
    )?;
    let (global_header, _header_len) = parse_global_header(archive_bytes, limits)?;
    let flags = global_header.flags;

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
    limits.check_cd_bytes(u64::try_from(cd_len).map_err(|_| SarError::Overflow("CD length"))?)?;
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
    let layout = parse_archive_layout(archive_bytes, limits)?;
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
    let meta = inspect_recovery_metadata(archive_bytes, limits)?;

    if !meta.repair_possible {
        return Err(SarError::RecoveryUnavailable(
            meta.repair_unavailable_reason
                .unwrap_or("archive-level repair is unavailable"),
        ));
    }

    let protected_range = meta.protected_range.ok_or(SarError::RecoveryUnavailable(
        "protected range could not be determined",
    ))?;

    // Determine block/symbol size from the first valid TLV
    let (algo_id, block_size_bytes) = block_size_from_tlv(archive_bytes, &protected_range, limits)?;

    let prot_end = protected_range
        .offset
        .checked_add(protected_range.length)
        .ok_or(SarError::Overflow("protected range end"))?;

    for er in &erasures.archive_ranges {
        let er_end = er
            .offset
            .checked_add(er.length)
            .ok_or(SarError::Overflow("erasure range end"))?;

        // Erasure must lie within protected range
        if er.offset < protected_range.offset || er_end > prot_end {
            return Err(SarError::RecoveryUnavailable(
                "erasure range lies outside the protected byte range",
            ));
        }

        // Relative offset within protected range
        let rel_off = er.offset - protected_range.offset;

        // Block-alignment check (conservative: spec does not define arbitrary
        // sub-block erasure handling — see docs/SPEC_QUESTIONS.md)
        if rel_off % block_size_bytes != 0 || er.length % block_size_bytes != 0 {
            return Err(SarError::RecoveryUnavailable(
                "archive-level repair orchestration requires explicit block-aligned erasure \
                 mapping; see docs/SPEC_QUESTIONS.md",
            ));
        }
    }

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

/// Extracts `(algo_id, block_size)` from the first valid RECOVERY TLV in the
/// archive.
fn block_size_from_tlv(
    archive_bytes: &[u8],
    _protected_range: &ProtectedRange,
    limits: &ResourceLimits,
) -> Result<(u8, u64), SarError> {
    let layout = parse_archive_layout(archive_bytes, limits)?;
    for (type_id, value) in &layout.recovery_tlvs {
        if let Ok(summary) = validate_recovery_tlv(*type_id, value, limits) {
            let block_size: u64 = match &summary {
                FecSummary::Xor { block_size, .. } => u64::from(*block_size),
                FecSummary::ReedSolomon { symbol_size, .. } => u64::from(*symbol_size),
            };
            if block_size == 0 {
                continue;
            }
            let algo = match &summary {
                FecSummary::Xor { algo_id, .. } | FecSummary::ReedSolomon { algo_id, .. } => {
                    *algo_id
                }
            };
            return Ok((algo, block_size));
        }
    }
    Err(SarError::RecoveryUnavailable(
        "no usable RECOVERY TLV found for block-size derivation",
    ))
}

/// Executes a repair plan and returns the repaired archive bytes and a report.
///
/// Applies XOR or RS erasure recovery on the protected range of `archive_bytes`
/// using explicit erasure positions from `plan`.
///
/// The caller is responsible for writing the returned bytes to a temporary file
/// and renaming to the final destination only after structural verification.
///
/// # Errors
///
/// * [`SarError::EcFailed`] — erasures exceed parity capacity.
/// * [`SarError::RecoveryUnavailable`] — repair not supported or TLV not found.
pub fn repair_archive(
    archive_bytes: &[u8],
    plan: &RecoveryPlan,
    limits: &ResourceLimits,
) -> Result<(Vec<u8>, RepairReport), SarError> {
    use sar_fec::{Erasure, FecCodec, FecRecoverInput, RsCodec, XorCodec};

    // Re-parse to find the TLV value bytes
    let layout = parse_archive_layout(archive_bytes, limits)?;

    let (tlv_value, tlv_algo_id) = layout
        .recovery_tlvs
        .iter()
        .find(|(type_id, _)| *type_id == plan.algo_id)
        .map(|(tid, val)| (val.as_slice(), *tid))
        .ok_or(SarError::RecoveryUnavailable(
            "RECOVERY TLV with matching algo ID not found in archive",
        ))?;

    // Extract protected range bytes
    let prot_start = usize::try_from(plan.protected_range.offset)
        .map_err(|_| SarError::Overflow("prot start"))?;
    let prot_len =
        usize::try_from(plan.protected_range.length).map_err(|_| SarError::Overflow("prot len"))?;
    if prot_start + prot_len > archive_bytes.len() {
        return Err(SarError::Bounds("protected range exceeds archive length"));
    }
    let protected_bytes = &archive_bytes[prot_start..prot_start + prot_len];
    limits.check_recovery_protected_range(plan.protected_range.length)?;
    let repair_working_set = u64::try_from(archive_bytes.len())
        .map_err(|_| SarError::Overflow("archive repair working set"))?
        .checked_add(plan.protected_range.length)
        .and_then(|value| value.checked_add(u64::try_from(tlv_value.len()).ok()?))
        .and_then(|value| value.checked_add(plan.protected_range.length))
        .ok_or(SarError::Overflow("archive repair working set"))?;
    limits.check_repair_working_set(repair_working_set)?;

    // Build erasure list (block indices)
    let block_size = block_size_from_algo(tlv_algo_id, tlv_value)?;
    let mut erasure_indices: Vec<Erasure> = Vec::new();
    for er in &plan.erasures.archive_ranges {
        let rel_off = er.offset - plan.protected_range.offset;
        let first_block = rel_off / block_size;
        let last_block = (rel_off + er.length) / block_size;
        for idx in first_block..last_block {
            erasure_indices.push(Erasure { index: idx });
        }
    }
    // Deduplicate and sort
    erasure_indices.sort_unstable_by_key(|e| e.index);
    erasure_indices.dedup_by_key(|e| e.index);

    // Perform FEC recovery
    let recovered = match tlv_algo_id {
        0x14 => {
            let codec = XorCodec::from_fec_value(tlv_value).map_err(SarError::from)?;
            codec
                .recover(FecRecoverInput {
                    original_protected_len: plan.protected_range.length,
                    available_data: protected_bytes,
                    fec_value_data: tlv_value,
                    erasures: &erasure_indices,
                })
                .map_err(SarError::from)?
        }
        0x11 => {
            let codec = RsCodec::from_fec_value(tlv_value).map_err(SarError::from)?;
            codec
                .recover(FecRecoverInput {
                    original_protected_len: plan.protected_range.length,
                    available_data: protected_bytes,
                    fec_value_data: tlv_value,
                    erasures: &erasure_indices,
                })
                .map_err(SarError::from)?
        }
        _ => {
            return Err(SarError::RecoveryUnavailable(
                "unsupported FEC algorithm for archive repair",
            ));
        }
    };

    // Rebuild archive bytes: prefix + recovered_protected + remainder (CD + footer)
    let cd_start = prot_start + prot_len;
    limits.check_repair_working_set(
        u64::try_from(archive_bytes.len())
            .map_err(|_| SarError::Overflow("repaired archive size"))?,
    )?;
    let mut repaired = Vec::with_capacity(archive_bytes.len());
    repaired.extend_from_slice(&archive_bytes[..prot_start]);
    repaired.extend_from_slice(&recovered[..prot_len.min(recovered.len())]);
    repaired.extend_from_slice(&archive_bytes[cd_start..]);

    let repaired_ranges = plan.erasures.archive_ranges.clone();
    let report = RepairReport {
        success: true,
        repaired_ranges,
        degraded: false,
        error: None,
    };

    Ok((repaired, report))
}

/// Returns the block/symbol size for a given FEC algorithm TLV value.
fn block_size_from_algo(algo_id: u8, tlv_value: &[u8]) -> Result<u64, SarError> {
    match algo_id {
        0x14 => {
            // XOR: block_size is at bytes [1] (block_size_index), resolved from table
            if tlv_value.len() < 2 {
                return Err(SarError::Truncated("XOR TLV too short for block size"));
            }
            let index = tlv_value[1];
            xor_block_size(index)
        }
        0x11 => {
            // RS: symbol_size is at bytes [2..6] (u32 LE)
            if tlv_value.len() < 6 {
                return Err(SarError::Truncated("RS TLV too short for symbol size"));
            }
            let ss = u32::from_le_bytes([tlv_value[2], tlv_value[3], tlv_value[4], tlv_value[5]]);
            if ss == 0 {
                return Err(SarError::InvalidLength("RS symbol size is zero"));
            }
            Ok(u64::from(ss))
        }
        _ => Err(SarError::RecoveryUnavailable("unsupported FEC algorithm")),
    }
}

/// Resolves an XOR block-size-index to its byte size.
fn xor_block_size(index: u8) -> Result<u64, SarError> {
    let sizes: [(u8, u32); 9] = [
        (0x00, 256),
        (0x01, 512),
        (0x02, 1_024),
        (0x03, 2_048),
        (0x04, 4_096),
        (0x05, 8_192),
        (0x06, 16_384),
        (0x07, 32_768),
        (0x08, 65_536),
    ];
    for (idx, size) in sizes {
        if idx == index {
            return Ok(u64::from(size));
        }
    }
    Err(SarError::ReservedValue("XOR block size index is reserved"))
}
