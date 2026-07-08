//! SAR BSDIFF40 profile — patch application (spec §8.4.3).
//!
//! The patch format is:
//!
//! ```text
//! Header (32 bytes):
//!   Magic[8]               = "BSDIFF40"
//!   Control_Block_Length[8]   signed bsdiff int, must be >= 0
//!   Diff_Block_Length[8]      signed bsdiff int, must be >= 0
//!   New_File_Size[8]          signed bsdiff int, must be >= 0
//!
//! Control_Block: bzip2-compressed sequence of control triples
//! Diff_Block:    bzip2-compressed diff bytes
//! Extra_Block:   bzip2-compressed extra bytes
//! ```
//!
//! Each control triple encodes:
//! ```text
//! (diff_len[8], extra_len[8], seek_adjust[8])
//! ```
//! all in classic bsdiff signed integer encoding.
//!
//! Application algorithm (spec §8.4.3):
//! 1. Add `diff_len` diff bytes to corresponding base bytes (mod 256), base reads beyond end → 0.
//! 2. Copy `extra_len` bytes from extra block verbatim.
//! 3. Advance base position by `seek_adjust`.
//!
//! Reject negative lengths/sizes, overreads, base-before-0, size mismatch, or
//! malformed bzip2 data.

use std::io::Read;

use bzip2::read::BzDecoder;

use crate::algo::PatchError;

/// Resource limits for BSDIFF patch application.
///
/// These are consumed directly by [`apply_bsdiff`] and populated by `sar-core`
/// from its unified [`ResourceLimits`][sar_core::ResourceLimits] struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BsdiffLimits {
    /// Maximum compressed payload size (entire patch blob). Default: 512 MiB.
    pub max_patch_size: u64,
    /// Maximum decompressed Control Block size. Default: 64 MiB.
    pub max_control_bytes: u64,
    /// Maximum decompressed Diff Block size. Default: 1 GiB.
    pub max_diff_bytes: u64,
    /// Maximum decompressed Extra Block size. Default: 1 GiB.
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

/// Applies a SAR BSDIFF40 patch to `base`, returning the reconstructed target.
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
///   field, size mismatch, block overread, or bzip2 failure.
/// * [`PatchError::LimitExceeded`] – any configured resource limit was exceeded.
/// * [`PatchError::BaseMissing`] – `base` is empty but a diff step requires base
///   bytes (this case is handled by the caller checking the hash; missing base
///   detection belongs in the archive reader).
pub fn apply_bsdiff(
    base: &[u8],
    patch: &[u8],
    expected_target_size: u64,
    limits: &BsdiffLimits,
) -> Result<Vec<u8>, PatchError> {
    // Limit: patch payload size
    let patch_len = patch.len() as u64;
    if patch_len > limits.max_patch_size {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: patch payload exceeds max_patch_size limit",
        ));
    }

    // Header: 32 bytes
    if patch.len() < 32 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: patch too short for header",
        ));
    }
    if &patch[..8] != b"BSDIFF40" {
        return Err(PatchError::PatchFailed(
            "BSDIFF: invalid magic (expected BSDIFF40)",
        ));
    }

    let ctrl_len_raw = decode_bsdiff_int(&patch[8..16])?;
    let diff_len_raw = decode_bsdiff_int(&patch[16..24])?;
    let new_size_raw = decode_bsdiff_int(&patch[24..32])?;

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

    let ctrl_len = ctrl_len_raw as u64;
    let diff_len = diff_len_raw as u64;
    let new_size = new_size_raw as u64;

    // Spec §8.4.3: New_File_Size MUST equal LFH Uncompressed Size
    if new_size != expected_target_size {
        return Err(PatchError::PatchFailed(
            "BSDIFF: New_File_Size does not match LFH Uncompressed Size",
        ));
    }

    // Limit: target size
    if new_size > limits.max_target_size {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: target size exceeds max_target_size limit",
        ));
    }

    // Block offsets (checked arithmetic)
    let ctrl_start: u64 = 32;
    let diff_start = ctrl_start
        .checked_add(ctrl_len)
        .ok_or(PatchError::PatchFailed("BSDIFF: block offset overflow"))?;
    let extra_start = diff_start
        .checked_add(diff_len)
        .ok_or(PatchError::PatchFailed("BSDIFF: block offset overflow"))?;

    // Validate patch length
    if extra_start > patch.len() as u64 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: patch too short (diff/extra blocks truncated)",
        ));
    }

    // Limit: compressed block sizes
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

    // Decompress Control Block
    let ctrl_compressed = &patch[ctrl_start as usize..diff_start as usize];
    let ctrl_data = bzip2_decompress(ctrl_compressed, limits.max_control_bytes)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: malformed bzip2 Control Block"))?;

    // Decompress Diff Block
    let diff_compressed = &patch[diff_start as usize..extra_start as usize];
    let diff_data = bzip2_decompress(diff_compressed, limits.max_diff_bytes)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: malformed bzip2 Diff Block"))?;

    // Decompress Extra Block (remainder of patch)
    let extra_compressed = &patch[extra_start as usize..];
    let extra_data = bzip2_decompress(extra_compressed, limits.max_extra_bytes)
        .map_err(|_| PatchError::PatchFailed("BSDIFF: malformed bzip2 Extra Block"))?;

    // Control block must be a multiple of 24 bytes (3 fields × 8 bytes)
    if ctrl_data.len() % 24 != 0 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: Control Block length not a multiple of 24",
        ));
    }
    let n_triples = ctrl_data.len() / 24;

    // Limit: control triple count
    if n_triples > limits.max_control_triples {
        return Err(PatchError::LimitExceeded(
            "BSDIFF: control triple count exceeds max_control_triples limit",
        ));
    }

    // Allocate output buffer
    let target_len = new_size as usize;
    let mut target = vec![0u8; target_len];

    let mut old_pos: i64 = 0; // current position in base
    let mut new_pos: u64 = 0; // current position in output
    let mut diff_pos: u64 = 0; // current read position in decompressed diff
    let mut extra_pos: u64 = 0; // current read position in decompressed extra

    for triple_idx in 0..n_triples {
        let triple_base = &ctrl_data[triple_idx * 24..triple_idx * 24 + 24];
        let d_len_raw = decode_bsdiff_int(&triple_base[0..8])?;
        let e_len_raw = decode_bsdiff_int(&triple_base[8..16])?;
        let seek_adj = decode_bsdiff_int(&triple_base[16..24])?;

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

        let d_len = d_len_raw as u64;
        let e_len = e_len_raw as u64;

        // Bounds: output must not exceed new_size
        let new_after_diff = new_pos
            .checked_add(d_len)
            .ok_or(PatchError::PatchFailed("BSDIFF: output position overflow"))?;
        if new_after_diff > new_size {
            return Err(PatchError::PatchFailed(
                "BSDIFF: output exceeds New_File_Size during diff step",
            ));
        }

        // Bounds: diff block must not be overread
        let diff_end = diff_pos.checked_add(d_len).ok_or(PatchError::PatchFailed(
            "BSDIFF: diff block position overflow",
        ))?;
        if diff_end > diff_data.len() as u64 {
            return Err(PatchError::PatchFailed("BSDIFF: Diff Block overread"));
        }

        // Step 1: apply diff bytes to base bytes
        for j in 0..d_len as usize {
            let diff_byte = diff_data[diff_pos as usize + j];
            let old_byte_pos = old_pos + j as i64;
            let old_byte = if old_byte_pos >= 0 && (old_byte_pos as usize) < base.len() {
                base[old_byte_pos as usize]
            } else {
                0u8 // base reads beyond end (or before start) use 0x00
            };
            target[new_pos as usize + j] = diff_byte.wrapping_add(old_byte);
        }

        new_pos = new_after_diff;
        diff_pos = diff_end;
        old_pos = old_pos
            .checked_add(d_len_raw)
            .ok_or(PatchError::PatchFailed(
                "BSDIFF: old_pos overflow in diff step",
            ))?;

        // Step 2: copy extra bytes verbatim
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
        if extra_end > extra_data.len() as u64 {
            return Err(PatchError::PatchFailed("BSDIFF: Extra Block overread"));
        }

        target[new_pos as usize..new_after_extra as usize]
            .copy_from_slice(&extra_data[extra_pos as usize..extra_end as usize]);

        new_pos = new_after_extra;
        extra_pos = extra_end;

        // Step 3: seek adjustment
        old_pos = old_pos
            .checked_add(seek_adj)
            .ok_or(PatchError::PatchFailed(
                "BSDIFF: old_pos overflow in seek step",
            ))?;
        if old_pos < 0 {
            return Err(PatchError::PatchFailed("BSDIFF: base seek before offset 0"));
        }
    }

    // Exactly new_size bytes must have been written
    if new_pos != new_size {
        return Err(PatchError::PatchFailed(
            "BSDIFF: output shorter than New_File_Size after all triples",
        ));
    }

    Ok(target)
}

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
        bytes[7] & 0x7F, // mask off the sign bit
    ]);
    let negative = (bytes[7] & 0x80) != 0;

    // Reject values that can't be represented as i64 (magnitude > i64::MAX)
    if magnitude > i64::MAX as u64 {
        return Err(PatchError::PatchFailed(
            "BSDIFF: integer magnitude overflows i64",
        ));
    }

    let value = magnitude as i64;
    Ok(if negative { -value } else { value })
}

/// Decompresses a bzip2-compressed slice, enforcing an output size limit.
///
/// Returns the decompressed bytes on success, or an `io::Error` on failure.
fn bzip2_decompress(compressed: &[u8], max_output: u64) -> Result<Vec<u8>, std::io::Error> {
    let cursor = std::io::Cursor::new(compressed);
    let mut decoder = BzDecoder::new(cursor);

    let mut output = Vec::new();
    // Use Read::take to cap decompressed output at the limit
    let limit = max_output.min(usize::MAX as u64) as usize;
    // Read up to limit+1 bytes so we can detect if the limit is exceeded
    let mut limited = (&mut decoder).take(max_output.saturating_add(1));
    limited.read_to_end(&mut output)?;

    if output.len() as u64 > max_output {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bzip2 decompressed output exceeds limit",
        ));
    }
    let _ = limit; // suppress unused warning

    Ok(output)
}
