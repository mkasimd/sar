//! Unit tests for [`sar_delta::apply_bsdiff`] and [`sar_delta::decode_bsdiff_int`].
//!
//! These tests exercise the pure BSDIFF40 patcher in isolation.
//! Integration tests that go through the full archive reader pipeline live in
//! `crates/sar-core/tests/bsdiff_patch_tests.rs`.
//!
//! Spec requirements tested (spec §8.4.3):
//!
//! * Valid BSDIFF40 patch reconstructs expected target.
//! * Invalid magic fails with `PatchFailed`.
//! * Negative Control_Block_Length fails with `PatchFailed`.
//! * Negative Diff_Block_Length fails with `PatchFailed`.
//! * Negative New_File_Size fails with `PatchFailed`.
//! * New_File_Size mismatch with expected target size fails with `PatchFailed`.
//! * Malformed bzip2 Control Block fails with `PatchFailed`.
//! * Malformed bzip2 Diff Block fails with `PatchFailed`.
//! * Malformed bzip2 Extra Block fails with `PatchFailed`.
//! * Malformed / truncated control triple fails with `PatchFailed`.
//! * Negative `diff_len` fails with `PatchFailed`.
//! * Negative `extra_len` fails with `PatchFailed`.
//! * Output exceeding target size fails with `PatchFailed`.
//! * Output shorter than target size fails with `PatchFailed`.
//! * Diff block overread fails with `PatchFailed`.
//! * Extra block overread fails with `PatchFailed`.
//! * Base seek before offset 0 fails with `PatchFailed`.
//! * Base read beyond end uses `0x00`.
//! * Target above `ResourceLimits` returns `LimitExceeded`.
//! * Decompressed block above `ResourceLimits` returns `LimitExceeded`.
//! * Excessive control triple count returns `LimitExceeded`.

use bzip2::{Compression, write::BzEncoder};
use sar_delta::{PatchError, apply_bsdiff, bsdiff::BsdiffLimits, decode_bsdiff_int};
use std::io::Write;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compresses `data` with bzip2.
fn bzip2_compress(data: &[u8]) -> Vec<u8> {
    let mut enc = BzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).expect("write bzip2");
    enc.finish().expect("finish bzip2")
}

/// Encodes a value with classic bsdiff sign-magnitude encoding.
pub fn encode_bsdiff_int(v: i64) -> [u8; 8] {
    let magnitude = v.unsigned_abs();
    let sign_bit: u8 = if v < 0 { 0x80 } else { 0x00 };
    let mut bytes = magnitude.to_le_bytes();
    bytes[7] = (bytes[7] & 0x7F) | sign_bit;
    bytes
}

/// Builds a BSDIFF40 patch from raw control triples, diff bytes, and extra bytes.
///
/// `new_size` is placed directly into the header (may be intentionally wrong in some tests).
fn build_bsdiff_patch(
    ctrl_triples: &[(i64, i64, i64)],
    diff_bytes: &[u8],
    extra_bytes: &[u8],
    new_size: i64,
) -> Vec<u8> {
    let mut ctrl_raw = Vec::new();
    for &(d, e, s) in ctrl_triples {
        ctrl_raw.extend_from_slice(&encode_bsdiff_int(d));
        ctrl_raw.extend_from_slice(&encode_bsdiff_int(e));
        ctrl_raw.extend_from_slice(&encode_bsdiff_int(s));
    }

    let ctrl_compressed = bzip2_compress(&ctrl_raw);
    let diff_compressed = bzip2_compress(diff_bytes);
    let extra_compressed = bzip2_compress(extra_bytes);

    let ctrl_len = ctrl_compressed.len() as i64;
    let diff_len = diff_compressed.len() as i64;

    let mut patch = Vec::new();
    patch.extend_from_slice(b"BSDIFF40");
    patch.extend_from_slice(&encode_bsdiff_int(ctrl_len));
    patch.extend_from_slice(&encode_bsdiff_int(diff_len));
    patch.extend_from_slice(&encode_bsdiff_int(new_size));
    patch.extend_from_slice(&ctrl_compressed);
    patch.extend_from_slice(&diff_compressed);
    patch.extend_from_slice(&extra_compressed);
    patch
}

// ---------------------------------------------------------------------------
// decode_bsdiff_int
// ---------------------------------------------------------------------------

#[test]
fn decode_bsdiff_int_zero() {
    let bytes = encode_bsdiff_int(0);
    assert_eq!(decode_bsdiff_int(&bytes).expect("must succeed"), 0);
}

#[test]
fn decode_bsdiff_int_positive() {
    let bytes = encode_bsdiff_int(1234);
    assert_eq!(decode_bsdiff_int(&bytes).expect("must succeed"), 1234);
}

#[test]
fn decode_bsdiff_int_negative() {
    let bytes = encode_bsdiff_int(-5);
    assert_eq!(decode_bsdiff_int(&bytes).expect("must succeed"), -5);
}

#[test]
fn decode_bsdiff_int_i64_max() {
    let bytes = encode_bsdiff_int(i64::MAX);
    assert_eq!(decode_bsdiff_int(&bytes).expect("must succeed"), i64::MAX);
}

#[test]
fn decode_bsdiff_int_wrong_length_returns_patch_failed() {
    let err = decode_bsdiff_int(&[1u8; 7]).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Valid patches
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_identity_from_base_succeeds() {
    let base = b"hello world";
    let target = b"hello world";
    // diff = 0 XOR base, one triple: (base.len(), 0, 0)
    let diff: Vec<u8> = base.iter().map(|_| 0u8).collect();
    let patch = build_bsdiff_patch(
        &[(base.len() as i64, 0, 0)],
        &diff,
        b"",
        target.len() as i64,
    );
    let result = apply_bsdiff(
        base,
        &patch,
        target.len() as u64,
        &BsdiffLimits::unlimited(),
    )
    .expect("must succeed");
    assert_eq!(result, target);
}

#[test]
fn apply_bsdiff_with_diff_and_extra_succeeds() {
    // base = "hello", target = "Hello world"
    // diff step: 5 bytes — H = h XOR (h XOR H) = 0x00 XOR 0x20 = 0x20; rest same.
    let base = b"hello";
    let target = b"Hello world";
    // Triple: diff_len=5, extra_len=6, seek_adjust=5
    // diff bytes: XOR of base[0..5] and target[0..5]
    let diff: Vec<u8> = base
        .iter()
        .zip(target.iter())
        .map(|(b, t)| t.wrapping_sub(*b))
        .collect();
    // extra bytes: target[5..] = " world"
    let extra = &target[5..];
    let patch = build_bsdiff_patch(&[(5, 6, 5)], &diff, extra, target.len() as i64);
    let result = apply_bsdiff(
        base,
        &patch,
        target.len() as u64,
        &BsdiffLimits::unlimited(),
    )
    .expect("must succeed");
    assert_eq!(result, target);
}

#[test]
fn apply_bsdiff_empty_base_extra_only_succeeds() {
    // No base, all output comes from extra block.
    let base = b"";
    let target = b"new file content";
    let patch = build_bsdiff_patch(
        &[(0, target.len() as i64, 0)],
        b"",
        target,
        target.len() as i64,
    );
    let result = apply_bsdiff(
        base,
        &patch,
        target.len() as u64,
        &BsdiffLimits::unlimited(),
    )
    .expect("must succeed");
    assert_eq!(result, target);
}

#[test]
fn apply_bsdiff_base_read_beyond_end_uses_zero() {
    // base is shorter than the diff window; bytes beyond end must be treated as 0x00.
    let base = b"hi";
    // target = diff XOR base (extended with zeros)
    // target[0] = base[0] XOR diff[0] = 'h' XOR 0 = 'h'
    // target[1] = base[1] XOR diff[1] = 'i' XOR 0 = 'i'
    // target[2] = 0x00 XOR 0x41 = 'A'  (base OOB → 0x00)
    // target[3] = 0x00 XOR 0x42 = 'B'
    let diff = b"\x00\x00\x41\x42";
    let target = b"hiAB";
    let patch = build_bsdiff_patch(&[(4, 0, 0)], diff, b"", target.len() as i64);
    let result = apply_bsdiff(
        base,
        &patch,
        target.len() as u64,
        &BsdiffLimits::unlimited(),
    )
    .expect("must succeed");
    assert_eq!(result, target);
}

#[test]
fn apply_bsdiff_multiple_triples_succeed() {
    let base = b"abcdefgh";
    // Two triples, each covering half the base.
    // seek_adjust=0 because after applying d_len diff bytes old_pos already advances by d_len.
    let diff: Vec<u8> = base.iter().map(|_| 0u8).collect();
    let patch = build_bsdiff_patch(&[(4, 0, 0), (4, 0, 0)], &diff, b"", base.len() as i64);
    let result = apply_bsdiff(base, &patch, base.len() as u64, &BsdiffLimits::unlimited())
        .expect("must succeed");
    assert_eq!(result, base);
}

// ---------------------------------------------------------------------------
// Invalid magic
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_invalid_magic_returns_patch_failed() {
    let mut patch = build_bsdiff_patch(&[(0, 0, 0)], b"", b"", 0);
    // Overwrite the magic bytes.
    patch[0..8].copy_from_slice(b"WRONGMAG");
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)), "got {err:?}");
}

#[test]
fn apply_bsdiff_too_short_for_header_returns_patch_failed() {
    let patch = [0u8; 10];
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Negative header fields
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_negative_ctrl_len_returns_patch_failed() {
    let mut patch = build_bsdiff_patch(&[], b"", b"", 0);
    // Set Control_Block_Length to -1.
    patch[8..16].copy_from_slice(&encode_bsdiff_int(-1));
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_negative_diff_len_header_returns_patch_failed() {
    let mut patch = build_bsdiff_patch(&[], b"", b"", 0);
    // Set Diff_Block_Length to -2.
    patch[16..24].copy_from_slice(&encode_bsdiff_int(-2));
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_negative_new_file_size_returns_patch_failed() {
    let mut patch = build_bsdiff_patch(&[], b"", b"", 0);
    // Set New_File_Size to -3.
    patch[24..32].copy_from_slice(&encode_bsdiff_int(-3));
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// New_File_Size mismatch
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_new_file_size_mismatch_returns_patch_failed() {
    let patch = build_bsdiff_patch(&[], b"", b"", 10);
    // expected_target_size is 5, but header says 10.
    let err = apply_bsdiff(b"", &patch, 5, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Malformed bzip2 blocks
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_malformed_bzip2_ctrl_block_returns_patch_failed() {
    let base = b"";
    // Build a correct header pointing to 4 bytes of garbage "ctrl" data.
    let garbage_ctrl = b"GARBAGE!";
    let diff_compressed = bzip2_compress(b"");
    let extra_compressed = bzip2_compress(b"");

    let mut patch = Vec::new();
    patch.extend_from_slice(b"BSDIFF40");
    patch.extend_from_slice(&encode_bsdiff_int(garbage_ctrl.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(diff_compressed.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(0));
    patch.extend_from_slice(garbage_ctrl);
    patch.extend_from_slice(&diff_compressed);
    patch.extend_from_slice(&extra_compressed);

    let err = apply_bsdiff(base, &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_malformed_bzip2_diff_block_returns_patch_failed() {
    let ctrl_compressed = bzip2_compress(b""); // empty ctrl = no triples
    let garbage_diff = b"NOT_BZIP2";
    let extra_compressed = bzip2_compress(b"");

    let mut patch = Vec::new();
    patch.extend_from_slice(b"BSDIFF40");
    patch.extend_from_slice(&encode_bsdiff_int(ctrl_compressed.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(garbage_diff.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(0));
    patch.extend_from_slice(&ctrl_compressed);
    patch.extend_from_slice(garbage_diff);
    patch.extend_from_slice(&extra_compressed);

    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_malformed_bzip2_extra_block_returns_patch_failed() {
    let ctrl_compressed = bzip2_compress(b"");
    let diff_compressed = bzip2_compress(b"");
    let garbage_extra = b"BAD_EXTRA";

    let mut patch = Vec::new();
    patch.extend_from_slice(b"BSDIFF40");
    patch.extend_from_slice(&encode_bsdiff_int(ctrl_compressed.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(diff_compressed.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(0));
    patch.extend_from_slice(&ctrl_compressed);
    patch.extend_from_slice(&diff_compressed);
    patch.extend_from_slice(garbage_extra);

    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Malformed control triples
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_truncated_control_triple_returns_patch_failed() {
    // Control block has 23 bytes (not a multiple of 24).
    let ctrl_raw = [0u8; 23];
    let patch = {
        let ctrl_compressed = bzip2_compress(&ctrl_raw);
        let diff_compressed = bzip2_compress(b"");
        let extra_compressed = bzip2_compress(b"");
        let mut p = Vec::new();
        p.extend_from_slice(b"BSDIFF40");
        p.extend_from_slice(&encode_bsdiff_int(ctrl_compressed.len() as i64));
        p.extend_from_slice(&encode_bsdiff_int(diff_compressed.len() as i64));
        p.extend_from_slice(&encode_bsdiff_int(0));
        p.extend_from_slice(&ctrl_compressed);
        p.extend_from_slice(&diff_compressed);
        p.extend_from_slice(&extra_compressed);
        p
    };
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_negative_diff_len_in_triple_returns_patch_failed() {
    // Triple: diff_len=-1, extra_len=0, seek=0
    let patch = build_bsdiff_patch(&[(-1, 0, 0)], b"", b"", 0);
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_negative_extra_len_in_triple_returns_patch_failed() {
    // Triple: diff_len=0, extra_len=-1, seek=0
    let patch = build_bsdiff_patch(&[(0, -1, 0)], b"", b"", 0);
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Output bounds violations
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_output_exceeds_target_size_returns_patch_failed() {
    // Triple claims to write 10 bytes, but new_size = 5.
    // The patch has 10 diff bytes and new_size = 5.
    let diff = vec![0u8; 10];
    let patch = build_bsdiff_patch(&[(10, 0, 10)], &diff, b"", 5);
    let err =
        apply_bsdiff(&[0u8; 20], &patch, 5, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_output_shorter_than_target_size_returns_patch_failed() {
    // Triple writes 3 bytes but new_size = 5.
    let diff = vec![0u8; 3];
    let patch = build_bsdiff_patch(&[(3, 0, 3)], &diff, b"", 5);
    let err =
        apply_bsdiff(&[0u8; 10], &patch, 5, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Block overread
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_diff_block_overread_returns_patch_failed() {
    // Triple requests 10 diff bytes but diff block only has 5.
    let diff = vec![0u8; 5];
    let patch = build_bsdiff_patch(&[(10, 0, 10)], &diff, b"", 10);
    let err =
        apply_bsdiff(&[0u8; 20], &patch, 10, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_extra_block_overread_returns_patch_failed() {
    // Triple requests 10 extra bytes but extra block only has 3.
    let extra = b"abc";
    let patch = build_bsdiff_patch(&[(0, 10, 0)], b"", extra, 10);
    let err = apply_bsdiff(b"", &patch, 10, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Base seek before offset 0
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_base_seek_before_zero_returns_patch_failed() {
    // Triple 1: (0, 0, -5) — seek to -5 (invalid for any base)
    let patch = build_bsdiff_patch(&[(0, 0, -5)], b"", b"", 0);
    let err =
        apply_bsdiff(b"ignored", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// ResourceLimits violations
// ---------------------------------------------------------------------------

#[test]
fn apply_bsdiff_target_above_limit_returns_limit_exceeded() {
    let base = b"hello";
    let diff = vec![0u8; 5];
    let patch = build_bsdiff_patch(&[(5, 0, 5)], &diff, b"", 5);
    let limits = BsdiffLimits {
        max_target_size: 4, // target is 5 bytes → exceeds limit
        ..BsdiffLimits::unlimited()
    };
    let err = apply_bsdiff(base, &patch, 5, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn apply_bsdiff_patch_size_above_limit_returns_limit_exceeded() {
    let diff = vec![0u8; 5];
    let patch = build_bsdiff_patch(&[(5, 0, 5)], &diff, b"", 5);
    let limits = BsdiffLimits {
        max_patch_size: (patch.len() as u64) - 1,
        ..BsdiffLimits::unlimited()
    };
    let err = apply_bsdiff(b"hello", &patch, 5, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}

#[test]
fn apply_bsdiff_ctrl_block_above_limit_returns_limit_exceeded() {
    // Build a patch with a larger ctrl block, then set a limit below it.
    let triples: Vec<(i64, i64, i64)> = (0..100).map(|_| (0i64, 0, 0)).collect();
    let patch = build_bsdiff_patch(&triples, b"", b"", 0);
    let limits = BsdiffLimits {
        max_control_bytes: 1, // very small
        ..BsdiffLimits::unlimited()
    };
    let err = apply_bsdiff(b"", &patch, 0, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}

#[test]
fn apply_bsdiff_excessive_control_triple_count_returns_limit_exceeded() {
    // Build a patch with 5 triples, set limit to 3.
    let diff = vec![0u8; 5];
    let patch = build_bsdiff_patch(
        &[(1, 0, 1), (1, 0, 1), (1, 0, 1), (1, 0, 1), (1, 0, 1)],
        &diff,
        b"",
        5,
    );
    let limits = BsdiffLimits {
        max_control_triples: 3,
        ..BsdiffLimits::unlimited()
    };
    let err = apply_bsdiff(b"hello", &patch, 5, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}
