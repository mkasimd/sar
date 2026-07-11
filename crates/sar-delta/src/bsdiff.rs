//! SAR BSDIFF v1 (`SARBSD01`) patch application (spec §8.4.4).
//!
//! The decoded patch payload format is:
//!
//! ```text
//! Header (32 bytes):
//!   Magic[8]                  = "SARBSD01"
//!   Control_Block_Length[8]   signed bsdiff int, must be >= 0
//!   Diff_Block_Length[8]      signed bsdiff int, must be >= 0
//!   New_File_Size[8]          signed bsdiff int, must be >= 0
//!
//! Control_Block: uncompressed sequence of control triples
//! Diff_Block:    uncompressed diff bytes
//! Extra_Block:   uncompressed extra bytes
//! ```
//!
//! Each control triple encodes:
//! ```text
//! (diff_len[8], extra_len[8], seek_adjust[8])
//! ```
//! all in classic bsdiff sign-magnitude integer encoding.
//!
//! Application algorithm (spec §8.4.4):
//! 1. Add `diff_len` diff bytes to corresponding base bytes (mod 256), base reads beyond end → 0.
//! 2. Copy `extra_len` bytes from extra block verbatim.
//! 3. Advance base position by `seek_adjust`.
//!
//! Reject invalid magic, negative lengths, malformed triples, overreads,
//! trailing unused diff/extra bytes, base-before-0 seeks, or size mismatch.

use crate::algo::PatchError;

const SAR_BSDIFF_MAGIC: &[u8; 8] = b"SARBSD01";
const BSDIFF_HEADER_SIZE: usize = 32;
const BSDIFF_CONTROL_TRIPLE_COUNT: usize = 1;
const BSDIFF_CONTROL_ENTRY_COUNT: u64 = 3;
const BSDIFF_CONTROL_VALUE_SIZE: u64 = 8;
const BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES: u64 =
    BSDIFF_CONTROL_ENTRY_COUNT * BSDIFF_CONTROL_VALUE_SIZE;

/// Resource limits for BSDIFF patch application.
///
/// These are consumed directly by [`apply_bsdiff`] and populated by `sar-core`
/// from its unified [`ResourceLimits`][sar_core::ResourceLimits] struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BsdiffLimits {
    /// Maximum decoded patch payload size (entire BSDIFF blob). Default: 512 MiB.
    pub max_patch_size: u64,
    /// Maximum Control Block size. Default: 64 MiB.
    pub max_control_bytes: u64,
    /// Maximum Diff Block size. Default: 1 GiB.
    pub max_diff_bytes: u64,
    /// Maximum Extra Block size. Default: 1 GiB.
    pub max_extra_bytes: u64,
    /// Maximum number of control triples. Default: 4 000 000.
    pub max_control_triples: usize,
    /// Maximum reconstructed target size. Default: 1 GiB.
    pub max_target_size: u64,
}

impl Default for BsdiffLimits {
    fn default() -> Self {
        Self {
            max_patch_size: 512 * 1024 * 1024,
            max_control_bytes: 64 * 1024 * 1024,
            max_diff_bytes: 1024 * 1024 * 1024,
            max_extra_bytes: 1024 * 1024 * 1024,
            max_control_triples: 4_000_000,
            max_target_size: 1024 * 1024 * 1024,
        }
    }
}

impl BsdiffLimits {
    /// Returns a [`BsdiffLimits`] with all limits disabled (maximum values).
    ///
    /// **Warning**: Use only in controlled test environments.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_patch_size: u64::MAX,
            max_control_bytes: u64::MAX,
            max_diff_bytes: u64::MAX,
            max_extra_bytes: u64::MAX,
            max_control_triples: usize::MAX,
            max_target_size: u64::MAX,
        }
    }
}

/// Applies a SAR BSDIFF v1 patch to `base`, returning the reconstructed target.
///
/// # Arguments
///
/// * `base` – base object bytes (caller must supply; no automatic discovery).
/// * `patch` – decoded patch payload (after SAR decryption/decompression stages).
/// * `expected_target_size` – value of LFH `Uncompressed Size`; the reconstructed
///   target MUST equal this exactly.
/// * `limits` – resource limits for this operation.
///
/// # Errors
///
/// * [`PatchError::PatchFailed`] – malformed patch data, invalid magic, negative
///   field, size mismatch, block overread, trailing unused bytes, or seek-before-0.
/// * [`PatchError::LimitExceeded`] – any configured resource limit was exceeded.
pub fn apply_bsdiff(
    base: &[u8],
    patch: &[u8],
    expected_target_size: u64,
    limits: &BsdiffLimits,
) -> Result<Vec<u8>, PatchError> {
    let patch_len = u64::try_from(patch.len())
        .map_err(|_| PatchError::LimitExceeded("BSDIFF: patch length exceeds u64"))?;
    if patch_len > limits.max_patch_size {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: patch payload exceeds max_patch_size limit",
        ));
    }

    if patch.len() < BSDIFF_HEADER_SIZE {
        return Err(PatchError::PatchFailed(
            "BSDIFF: patch too short for header",
        ));
    }
    if &patch[..SAR_BSDIFF_MAGIC.len()] != SAR_BSDIFF_MAGIC {
        return Err(PatchError::PatchFailed(
            "BSDIFF: invalid magic (expected SARBSD01)",
        ));
    }

    let ctrl_len_start = SAR_BSDIFF_MAGIC.len();
    let diff_len_start = ctrl_len_start + usize::try_from(BSDIFF_CONTROL_VALUE_SIZE).unwrap();
    let new_size_start = diff_len_start + usize::try_from(BSDIFF_CONTROL_VALUE_SIZE).unwrap();
    let header_end = new_size_start + usize::try_from(BSDIFF_CONTROL_VALUE_SIZE).unwrap();

    let ctrl_len_raw = decode_bsdiff_int(&patch[ctrl_len_start..diff_len_start])?;
    let diff_len_raw = decode_bsdiff_int(&patch[diff_len_start..new_size_start])?;
    let new_size_raw = decode_bsdiff_int(&patch[new_size_start..header_end])?;

    if ctrl_len_raw < 0 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: negative Control_Block_Length",
        ));
    }
    if diff_len_raw < 0 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: negative Diff_Block_Length",
        ));
    }
    if new_size_raw < 0 {
        return Err(PatchError::PatchFailed("BSDIFF: negative New_File_Size"));
    }

    let ctrl_len = u64::try_from(ctrl_len_raw)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: invalid Control_Block_Length"))?;
    let diff_len = u64::try_from(diff_len_raw)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: invalid Diff_Block_Length"))?;
    let new_size = u64::try_from(new_size_raw)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: invalid New_File_Size"))?;

    if new_size != expected_target_size {
        return Err(PatchError::PatchFailed(
            "BSDIFF: New_File_Size does not match LFH Uncompressed Size",
        ));
    }
    if new_size > limits.max_target_size {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: target size exceeds max_target_size limit",
        ));
    }

    if ctrl_len > limits.max_control_bytes {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: Control Block exceeds max_control_bytes limit",
        ));
    }
    if diff_len > limits.max_diff_bytes {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: Diff Block exceeds max_diff_bytes limit",
        ));
    }

    let ctrl_start = u64::try_from(BSDIFF_HEADER_SIZE)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: header size exceeds u64"))?;
    let diff_start = ctrl_start
        .checked_add(ctrl_len)
        .ok_or(PatchError::PatchFailed("BSDIFF: block offset overflow"))?;
    let extra_start = diff_start
        .checked_add(diff_len)
        .ok_or(PatchError::PatchFailed("BSDIFF: block offset overflow"))?;

    if extra_start > patch_len {
        return Err(PatchError::PatchFailed(
            "BSDIFF: patch too short (diff/extra blocks truncated)",
        ));
    }

    let extra_len = patch_len
        .checked_sub(extra_start)
        .ok_or(PatchError::PatchFailed("BSDIFF: block offset underflow"))?;
    if extra_len > limits.max_extra_bytes {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: Extra Block exceeds max_extra_bytes limit",
        ));
    }

    if ctrl_len % BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES != 0 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: Control Block length not a multiple of 24",
        ));
    }

    let triple_count_u64 = ctrl_len / BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES;
    let n_triples = usize::try_from(triple_count_u64)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF: control triple count exceeds usize"))?;
    if n_triples > limits.max_control_triples {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: control triple count exceeds max_control_triples limit",
        ));
    }

    let ctrl_start_usize = usize::try_from(ctrl_start)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: control start offset overflow"))?;
    let diff_start_usize = usize::try_from(diff_start)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: diff start offset overflow"))?;
    let extra_start_usize = usize::try_from(extra_start)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: extra start offset overflow"))?;

    let ctrl_data = &patch[ctrl_start_usize..diff_start_usize];
    let diff_data = &patch[diff_start_usize..extra_start_usize];
    let extra_data = &patch[extra_start_usize..];

    let target_len = usize::try_from(new_size)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF: target size exceeds platform limits"))?;
    let mut target = vec![0u8; target_len];

    let mut old_pos: i64 = 0;
    let mut new_pos: u64 = 0;
    let mut diff_pos: u64 = 0;
    let mut extra_pos: u64 = 0;

    for triple_idx in 0..n_triples {
        let triple_offset = triple_idx
            .checked_mul(usize::try_from(BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES).unwrap())
            .ok_or(PatchError::PatchFailed(
            "BSDIFF: control triple offset overflow",
        ))?;
        let triple_end = triple_offset
            .checked_add(usize::try_from(BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES).unwrap())
            .ok_or(PatchError::PatchFailed(
                "BSDIFF: control triple end overflow",
            ))?;
        if triple_end > ctrl_data.len() {
            return Err(PatchError::PatchFailed(
                "BSDIFF: malformed or truncated control triple",
            ));
        }
        let triple = &ctrl_data[triple_offset..triple_end];

        let diff_len_end = usize::try_from(BSDIFF_CONTROL_VALUE_SIZE).unwrap();
        let extra_len_end = diff_len_end + usize::try_from(BSDIFF_CONTROL_VALUE_SIZE).unwrap();
        let seek_adjust_end = extra_len_end + usize::try_from(BSDIFF_CONTROL_VALUE_SIZE).unwrap();

        let d_len_raw = decode_bsdiff_int(&triple[..diff_len_end])?;
        let e_len_raw = decode_bsdiff_int(&triple[diff_len_end..extra_len_end])?;
        let seek_adj = decode_bsdiff_int(&triple[extra_len_end..seek_adjust_end])?;

        if d_len_raw < 0 {
            return Err(PatchError::PatchFailed(
                "BSDIFF: negative diff_len in control triple",
            ));
        }
        if e_len_raw < 0 {
            return Err(PatchError::PatchFailed(
                "BSDIFF: negative extra_len in control triple",
            ));
        }

        let d_len = u64::try_from(d_len_raw)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: invalid diff_len in control triple"))?;
        let e_len = u64::try_from(e_len_raw)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: invalid extra_len in control triple"))?;

        let new_after_diff = new_pos
            .checked_add(d_len)
            .ok_or(PatchError::PatchFailed("BSDIFF: output position overflow"))?;
        if new_after_diff > new_size {
            return Err(PatchError::PatchFailed(
                "BSDIFF: output exceeds New_File_Size during diff step",
            ));
        }

        let diff_end = diff_pos.checked_add(d_len).ok_or(PatchError::PatchFailed(
            "BSDIFF: diff block position overflow",
        ))?;
        if diff_end > diff_len {
            return Err(PatchError::PatchFailed("BSDIFF: Diff Block overread"));
        }

        let d_len_usize = usize::try_from(d_len)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: diff_len exceeds usize"))?;
        let diff_pos_usize = usize::try_from(diff_pos)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: diff position exceeds usize"))?;
        let new_pos_usize = usize::try_from(new_pos)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: output position exceeds usize"))?;

        for j in 0..d_len_usize {
            let diff_idx = diff_pos_usize
                .checked_add(j)
                .ok_or(PatchError::PatchFailed("BSDIFF: diff index overflow"))?;
            let new_idx = new_pos_usize
                .checked_add(j)
                .ok_or(PatchError::PatchFailed("BSDIFF: output index overflow"))?;
            let j_i64 = i64::try_from(j)
                .map_err(|_| PatchError::PatchFailed("BSDIFF: j index exceeds i64"))?;
            let old_byte_pos = old_pos
                .checked_add(j_i64)
                .ok_or(PatchError::PatchFailed("BSDIFF: base index overflow"))?;

            let old_byte = if old_byte_pos < 0 {
                return Err(PatchError::PatchFailed("BSDIFF: base seek before offset 0"));
            } else if let Ok(old_idx) = usize::try_from(old_byte_pos) {
                if old_idx < base.len() {
                    base[old_idx]
                } else {
                    0
                }
            } else {
                0
            };

            target[new_idx] = diff_data[diff_idx].wrapping_add(old_byte);
        }

        new_pos = new_after_diff;
        diff_pos = diff_end;
        old_pos = old_pos
            .checked_add(d_len_raw)
            .ok_or(PatchError::PatchFailed(
                "BSDIFF: old_pos overflow in diff step",
            ))?;

        let new_after_extra = new_pos
            .checked_add(e_len)
            .ok_or(PatchError::PatchFailed("BSDIFF: output position overflow"))?;
        if new_after_extra > new_size {
            return Err(PatchError::PatchFailed(
                "BSDIFF: output exceeds New_File_Size during extra step",
            ));
        }

        let extra_end = extra_pos.checked_add(e_len).ok_or(PatchError::PatchFailed(
            "BSDIFF: extra block position overflow",
        ))?;
        if extra_end > extra_len {
            return Err(PatchError::PatchFailed("BSDIFF: Extra Block overread"));
        }

        let extra_pos_usize = usize::try_from(extra_pos)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: extra position exceeds usize"))?;
        let extra_end_usize = usize::try_from(extra_end)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: extra end exceeds usize"))?;
        let new_pos_usize = usize::try_from(new_pos)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: output position exceeds usize"))?;
        let new_after_extra_usize = usize::try_from(new_after_extra)
            .map_err(|_| PatchError::PatchFailed("BSDIFF: output end exceeds usize"))?;

        target[new_pos_usize..new_after_extra_usize]
            .copy_from_slice(&extra_data[extra_pos_usize..extra_end_usize]);

        new_pos = new_after_extra;
        extra_pos = extra_end;

        old_pos = old_pos
            .checked_add(seek_adj)
            .ok_or(PatchError::PatchFailed(
                "BSDIFF: old_pos overflow in seek step",
            ))?;
        if old_pos < 0 {
            return Err(PatchError::PatchFailed("BSDIFF: base seek before offset 0"));
        }
    }

    if new_pos != new_size {
        return Err(PatchError::PatchFailed(
            "BSDIFF: output shorter than New_File_Size after all triples",
        ));
    }
    if diff_pos != diff_len {
        return Err(PatchError::PatchFailed(
            "BSDIFF: trailing unused Diff Block bytes",
        ));
    }
    if extra_pos != extra_len {
        return Err(PatchError::PatchFailed(
            "BSDIFF: trailing unused Extra Block bytes",
        ));
    }

    Ok(target)
}

// ── SAR BSDIFF v1 generator ───────────────────────────────────────────────────

/// Encodes a signed integer in the classic bsdiff sign-magnitude format.
///
/// This is the inverse of [`decode_bsdiff_int`]:
/// - Bytes 0–6: lower 56 bits of magnitude (little-endian).
/// - Byte 7 bits 0–6: upper 7 bits of magnitude.
/// - Byte 7 bit 7: sign bit (`1` = negative).
fn encode_bsdiff_int(v: i64) -> [u8; 8] {
    let magnitude = v.unsigned_abs();
    let sign_bit: u8 = if v < 0 { 0x80 } else { 0x00 };
    let mut bytes = magnitude.to_le_bytes();
    bytes[7] = (bytes[7] & 0x7F) | sign_bit;
    bytes
}

/// Generates a minimal SAR BSDIFF v1 (`SARBSD01`) patch from `base` and `target`.
///
/// The produced patch is accepted by
/// [`apply_bsdiff`]`(base, patch, target.len() as u64, limits)` and
/// reconstructs `target` exactly.
///
/// # Strategy
///
/// Emits a single control triple:
/// - `diff_len = min(base.len(), target.len())` — bytes reconstructed by XOR-diff
///   with the base (i.e. `diff[i] = target[i].wrapping_sub(base[i])`).
/// - `extra_len = target.len() - diff_len` — bytes beyond the base copied verbatim.
/// - `seek_adjust = 0`.
///
/// All arithmetic is checked; the function fails closed on limit violations.
///
/// # Memory bound
///
/// Allocates O(`target.len()`) memory only.  No suffix array, BWT, or
/// unbounded table is constructed.
///
/// # Errors
///
/// Returns [`PatchError::LimitExceeded`] when any configured limit is
/// exceeded.
pub fn generate_bsdiff_patch(
    base: &[u8],
    target: &[u8],
    limits: &BsdiffLimits,
) -> Result<Vec<u8>, PatchError> {
    let target_size = u64::try_from(target.len())
        .map_err(|_| PatchError::LimitExceeded("BSDIFF generate: target length exceeds u64"))?;
    if target_size > limits.max_target_size {
        return Err(PatchError::LimitExceeded(
            "BSDIFF generate: target length exceeds max_target_size limit",
        ));
    }

    // Single control triple: diff all overlapping bytes, then copy the rest as extra.
    let diff_step = base.len().min(target.len());
    let extra_step = target
        .len()
        .checked_sub(diff_step)
        .ok_or(PatchError::LimitExceeded(
            "BSDIFF generate: extra_step underflow",
        ))?;

    let diff_step_u64 = u64::try_from(diff_step)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF generate: diff_step exceeds u64"))?;
    let extra_step_u64 = u64::try_from(extra_step)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF generate: extra_step exceeds u64"))?;

    if diff_step_u64 > limits.max_diff_bytes {
        return Err(PatchError::LimitExceeded(
            "BSDIFF generate: diff block exceeds max_diff_bytes limit",
        ));
    }
    if extra_step_u64 > limits.max_extra_bytes {
        return Err(PatchError::LimitExceeded(
            "BSDIFF generate: extra block exceeds max_extra_bytes limit",
        ));
    }
    if limits.max_control_triples < BSDIFF_CONTROL_TRIPLE_COUNT {
        return Err(PatchError::LimitExceeded(
            "BSDIFF generate: control triple count exceeds max_control_triples limit",
        ));
    }
    if limits.max_control_bytes < BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES {
        return Err(PatchError::LimitExceeded(
            "BSDIFF generate: control block exceeds max_control_bytes limit",
        ));
    }

    // Total patch size: header + one control triple + diff_step + extra_step.
    let patch_size: usize = BSDIFF_HEADER_SIZE
        .checked_add(usize::try_from(BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES).unwrap())
        .and_then(|n| n.checked_add(diff_step))
        .and_then(|n| n.checked_add(extra_step))
        .ok_or(PatchError::LimitExceeded(
            "BSDIFF generate: total patch size overflow",
        ))?;

    let patch_size_u64 = u64::try_from(patch_size)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF generate: total patch size exceeds u64"))?;
    if patch_size_u64 > limits.max_patch_size {
        return Err(PatchError::LimitExceeded(
            "BSDIFF generate: total patch size exceeds max_patch_size limit",
        ));
    }

    // 1 control triple: (diff_step, extra_step, 0)
    let diff_step_i64 = i64::try_from(diff_step)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF generate: diff_step exceeds i64"))?;
    let extra_step_i64 = i64::try_from(extra_step)
        .map_err(|_| PatchError::LimitExceeded("BSDIFF generate: extra_step exceeds i64"))?;

    let mut patch = Vec::with_capacity(patch_size);

    // Header.
    patch.extend_from_slice(SAR_BSDIFF_MAGIC);
    patch.extend_from_slice(&encode_bsdiff_int(
        i64::try_from(BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES).expect("control bytes fit i64"),
    ));
    patch.extend_from_slice(&encode_bsdiff_int(diff_step_i64));
    patch.extend_from_slice(&encode_bsdiff_int(i64::try_from(target.len()).map_err(
        |_| PatchError::LimitExceeded("BSDIFF generate: target length exceeds i64"),
    )?));

    // Control block (one triple).
    patch.extend_from_slice(&encode_bsdiff_int(diff_step_i64));
    patch.extend_from_slice(&encode_bsdiff_int(extra_step_i64));
    patch.extend_from_slice(&encode_bsdiff_int(0i64)); // seek_adjust = 0

    // Diff block: target[i] - base[i] (mod 256) for i in 0..diff_step.
    for i in 0..diff_step {
        patch.push(target[i].wrapping_sub(base[i]));
    }

    // Extra block: target bytes beyond diff_step.
    patch.extend_from_slice(&target[diff_step..]);

    Ok(patch)
}

// ── Decoder helpers ───────────────────────────────────────────────────────────

/// Decodes a classic bsdiff signed 64-bit integer from 8 bytes.
///
/// This is **sign-magnitude** encoding, not two's complement:
/// - Bytes 0–6: lower 56 bits of magnitude (little-endian).
/// - Byte 7 bits 0–6: upper 7 bits of magnitude.
/// - Byte 7 bit 7: sign bit (1 = negative).
///
/// # Errors
///
/// Returns [`PatchError::PatchFailed`] if the slice is not exactly 8 bytes.
pub fn decode_bsdiff_int(bytes: &[u8]) -> Result<i64, PatchError> {
    if bytes.len() != 8 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: integer field is not 8 bytes",
        ));
    }

    let magnitude: u64 = u64::from_le_bytes([
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7] & 0x7F,
    ]);
    let negative = (bytes[7] & 0x80) != 0;

    if magnitude > i64::MAX as u64 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: integer magnitude overflows i64",
        ));
    }

    let value = i64::try_from(magnitude)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: integer magnitude overflows i64"))?;
    Ok(if negative { -value } else { value })
}
