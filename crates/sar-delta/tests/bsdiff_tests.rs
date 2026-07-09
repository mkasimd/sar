//! Unit tests for [`sar_delta::apply_bsdiff`] and [`sar_delta::decode_bsdiff_int`].
//!
//! These tests exercise the SAR BSDIFF v1 (`SARBSD01`) patcher in isolation.

use sar_delta::{PatchError, apply_bsdiff, bsdiff::BsdiffLimits, decode_bsdiff_int};

fn encode_bsdiff_int(v: i64) -> [u8; 8] {
    let magnitude = v.unsigned_abs();
    let sign_bit: u8 = if v < 0 { 0x80 } else { 0x00 };
    let mut bytes = magnitude.to_le_bytes();
    bytes[7] = (bytes[7] & 0x7F) | sign_bit;
    bytes
}

fn triples_to_control(triples: &[(i64, i64, i64)]) -> Vec<u8> {
    let mut ctrl = Vec::new();
    for &(d, e, s) in triples {
        ctrl.extend_from_slice(&encode_bsdiff_int(d));
        ctrl.extend_from_slice(&encode_bsdiff_int(e));
        ctrl.extend_from_slice(&encode_bsdiff_int(s));
    }
    ctrl
}

fn build_sar_bsdiff_patch(ctrl_raw: &[u8], diff_bytes: &[u8], extra_bytes: &[u8], new_size: i64) -> Vec<u8> {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"SARBSD01");
    patch.extend_from_slice(&encode_bsdiff_int(i64::try_from(ctrl_raw.len()).expect("ctrl len")));
    patch.extend_from_slice(&encode_bsdiff_int(i64::try_from(diff_bytes.len()).expect("diff len")));
    patch.extend_from_slice(&encode_bsdiff_int(new_size));
    patch.extend_from_slice(ctrl_raw);
    patch.extend_from_slice(diff_bytes);
    patch.extend_from_slice(extra_bytes);
    patch
}

fn build_patch(triples: &[(i64, i64, i64)], diff_bytes: &[u8], extra_bytes: &[u8], new_size: i64) -> Vec<u8> {
    build_sar_bsdiff_patch(&triples_to_control(triples), diff_bytes, extra_bytes, new_size)
}

#[test]
fn decode_bsdiff_int_roundtrip() {
    for value in [0, 1, -1, 1234, -5, i64::MAX] {
        let encoded = encode_bsdiff_int(value);
        assert_eq!(decode_bsdiff_int(&encoded).expect("decode"), value);
    }
}

#[test]
fn apply_bsdiff_sarbsd01_magic_is_accepted() {
    let base = b"hello world";
    let diff: Vec<u8> = base.iter().map(|_| 0u8).collect();
    let patch = build_patch(&[(base.len() as i64, 0, 0)], &diff, b"", base.len() as i64);
    let out = apply_bsdiff(base, &patch, base.len() as u64, &BsdiffLimits::unlimited()).expect("ok");
    assert_eq!(out, base);
}

#[test]
fn apply_bsdiff40_magic_is_rejected_in_option_a() {
    let mut patch = build_patch(&[(0, 0, 0)], b"", b"", 0);
    patch[0..8].copy_from_slice(b"BSDIFF40");
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_control_diff_extra_blocks_are_uncompressed() {
    let base = b"abc";
    let target = b"aBZh9";
    let diff: Vec<u8> = vec![0, b'B'.wrapping_sub(b'b'), b'Z'.wrapping_sub(b'c')];
    let extra = b"h9";
    let patch = build_patch(&[(3, 2, 0)], &diff, extra, target.len() as i64);
    let out = apply_bsdiff(base, &patch, target.len() as u64, &BsdiffLimits::unlimited()).expect("ok");
    assert_eq!(out, target);
}

#[test]
fn apply_bsdiff_invalid_magic_returns_patch_failed() {
    let mut patch = build_patch(&[(0, 0, 0)], b"", b"", 0);
    patch[0..8].copy_from_slice(b"WRONGMAG");
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_negative_header_lengths_return_patch_failed() {
    let mut patch = build_patch(&[], b"", b"", 0);
    patch[8..16].copy_from_slice(&encode_bsdiff_int(-1));
    assert!(matches!(
        apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));

    let mut patch = build_patch(&[], b"", b"", 0);
    patch[16..24].copy_from_slice(&encode_bsdiff_int(-1));
    assert!(matches!(
        apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));

    let mut patch = build_patch(&[], b"", b"", 0);
    patch[24..32].copy_from_slice(&encode_bsdiff_int(-1));
    assert!(matches!(
        apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));
}

#[test]
fn apply_bsdiff_control_block_not_divisible_by_24_returns_patch_failed() {
    let patch = build_sar_bsdiff_patch(&[0u8; 23], b"", b"", 0);
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_truncated_control_block_returns_patch_failed() {
    let mut patch = build_patch(&[(0, 0, 0)], b"", b"", 0);
    patch.truncate(32 + 23);
    let err = apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_negative_diff_or_extra_len_returns_patch_failed() {
    let patch = build_patch(&[(-1, 0, 0)], b"", b"", 0);
    assert!(matches!(
        apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));

    let patch = build_patch(&[(0, -1, 0)], b"", b"", 0);
    assert!(matches!(
        apply_bsdiff(b"", &patch, 0, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));
}

#[test]
fn apply_bsdiff_output_over_or_under_target_returns_patch_failed() {
    let patch = build_patch(&[(10, 0, 0)], &[0u8; 10], b"", 5);
    assert!(matches!(
        apply_bsdiff(&[0u8; 10], &patch, 5, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));

    let patch = build_patch(&[(3, 0, 0)], &[0u8; 3], b"", 5);
    assert!(matches!(
        apply_bsdiff(&[0u8; 10], &patch, 5, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));
}

#[test]
fn apply_bsdiff_diff_and_extra_overread_return_patch_failed() {
    let patch = build_patch(&[(10, 0, 0)], &[0u8; 5], b"", 10);
    assert!(matches!(
        apply_bsdiff(&[0u8; 10], &patch, 10, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));

    let patch = build_patch(&[(0, 10, 0)], b"", b"abc", 10);
    assert!(matches!(
        apply_bsdiff(b"", &patch, 10, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));
}

#[test]
fn apply_bsdiff_trailing_unused_diff_or_extra_returns_patch_failed() {
    let patch = build_patch(&[(2, 0, 0)], &[0, 0, 0], b"", 2);
    assert!(matches!(
        apply_bsdiff(b"ab", &patch, 2, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));

    let patch = build_patch(&[(0, 2, 0)], b"", b"abc", 2);
    assert!(matches!(
        apply_bsdiff(b"", &patch, 2, &BsdiffLimits::unlimited()),
        Err(PatchError::PatchFailed(_))
    ));
}

#[test]
fn apply_bsdiff_base_seek_before_zero_returns_patch_failed() {
    let patch = build_patch(&[(0, 0, -1)], b"", b"", 0);
    let err = apply_bsdiff(b"abc", &patch, 0, &BsdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_bsdiff_base_read_beyond_end_uses_zero() {
    let base = b"hi";
    let diff = b"\x00\x00AB";
    let target = b"hiAB";
    let patch = build_patch(&[(4, 0, 0)], diff, b"", 4);
    let out = apply_bsdiff(base, &patch, 4, &BsdiffLimits::unlimited()).expect("ok");
    assert_eq!(out, target);
}

#[test]
fn apply_bsdiff_limits_are_enforced_before_allocation() {
    let patch = build_patch(&[(1, 0, 0)], &[0], b"", 1);

    let err = apply_bsdiff(
        b"a",
        &patch,
        1,
        &BsdiffLimits {
            max_patch_size: 1,
            ..BsdiffLimits::unlimited()
        },
    )
    .expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));

    let err = apply_bsdiff(
        b"a",
        &patch,
        1,
        &BsdiffLimits {
            max_target_size: 0,
            ..BsdiffLimits::unlimited()
        },
    )
    .expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));

    let err = apply_bsdiff(
        b"a",
        &patch,
        1,
        &BsdiffLimits {
            max_control_triples: 0,
            ..BsdiffLimits::unlimited()
        },
    )
    .expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}
