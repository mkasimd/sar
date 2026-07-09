//! Unit tests for [`sar_delta::apply_vcdiff`].
//!
//! These tests exercise the VCDIFF RFC 3284 decoder in isolation.
//! Integration tests that go through the full archive reader pipeline live in
//! `crates/sar-core/tests/vcdiff_patch_tests.rs`.
//!
//! All test vectors use only single-instruction code table entries (codes 0–162)
//! to avoid any ambiguity about double-instruction layouts.
//!
//! Spec requirements tested (spec §8.4.2, RFC 3284):
//!
//! * Valid VCDIFF ADD-only patch reconstructs expected target.
//! * Valid VCDIFF COPY-from-source patch reconstructs expected target.
//! * Valid VCDIFF RUN patch reconstructs expected target.
//! * Malformed header magic fails with `PatchFailed`.
//! * Malformed varint fails with `PatchFailed`.
//! * Invalid VCD_CODETABLE flag fails with `PatchFailed`.
//! * Unsupported secondary compressor flags fail with `Unsupported`.
//! * COPY beyond base returns `PatchFailed`.
//! * Truncated patch fails with `PatchFailed`.
//! * Output exceeding expected size fails with `PatchFailed`.
//! * Output shorter than expected size fails with `PatchFailed`.
//! * Instruction count above limit returns `LimitExceeded`.
//! * Resource-limit violations return `LimitExceeded`.

use sar_delta::{PatchError, apply_vcdiff, vcdiff::VcdiffLimits};

// ---------------------------------------------------------------------------
// Helpers — minimal VCDIFF patch builder
// ---------------------------------------------------------------------------

/// Encodes a `u64` as a big-endian base-128 varint (RFC 3284 §2).
fn encode_varint(mut v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let mut buf = Vec::new();
    // Build from least-significant 7-bit group upward.
    while v > 0 {
        buf.push((v & 0x7F) as u8);
        v >>= 7;
    }
    // Reverse so most-significant group comes first.
    buf.reverse();
    // Set continuation bit on all but the last byte.
    let last = buf.len() - 1;
    for b in &mut buf[..last] {
        *b |= 0x80;
    }
    buf
}

/// Builds a minimal VCDIFF window section for a single ADD instruction.
///
/// `add_data` is the literal bytes to emit; no source segment is used.
fn vcdiff_add_window(add_data: &[u8]) -> Vec<u8> {
    // Instructions: code 0x01 (ADD size=0) followed by size as varint.
    let mut inst = Vec::new();
    inst.push(0x01u8); // ADD code
    inst.extend_from_slice(&encode_varint(add_data.len() as u64));

    let twl = encode_varint(add_data.len() as u64); // target_window_length
    let delta_ind = 0x00u8;
    let lar = encode_varint(add_data.len() as u64); // len_add_run = data len
    let li = encode_varint(inst.len() as u64);
    let la = encode_varint(0u64); // len_addr = 0

    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&twl);
    delta_body.push(delta_ind);
    delta_body.extend_from_slice(&lar);
    delta_body.extend_from_slice(&li);
    delta_body.extend_from_slice(&la);
    delta_body.extend_from_slice(add_data);
    delta_body.extend_from_slice(&inst);
    // no addresses

    let del = encode_varint(delta_body.len() as u64);

    let mut win = Vec::new();
    win.push(0x00u8); // win_indicator (no source)
    win.extend_from_slice(&del);
    win.extend_from_slice(&delta_body);
    win
}

/// Builds a minimal VCDIFF window that copies `copy_size` bytes from source at offset 0.
///
/// Uses code 19 (0x13) = COPY mode=0 (SELF) size=0, with varint size and varint address.
fn vcdiff_copy_source_window(source_size: usize, copy_size: usize) -> Vec<u8> {
    // Instructions: code 0x13 (COPY mode=0 size=0), varint copy_size.
    let mut inst = Vec::new();
    inst.push(0x13u8);
    inst.extend_from_slice(&encode_varint(copy_size as u64));

    // Addresses: varint 0 (SELF mode, absolute address 0).
    let addr = encode_varint(0u64);

    let twl = encode_varint(copy_size as u64);
    let delta_ind = 0x00u8;
    let lar = encode_varint(0u64); // no add/run data
    let li = encode_varint(inst.len() as u64);
    let la = encode_varint(addr.len() as u64);

    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&twl);
    delta_body.push(delta_ind);
    delta_body.extend_from_slice(&lar);
    delta_body.extend_from_slice(&li);
    delta_body.extend_from_slice(&la);
    // no add/run data
    delta_body.extend_from_slice(&inst);
    delta_body.extend_from_slice(&addr);

    let del = encode_varint(delta_body.len() as u64);

    let mut win = Vec::new();
    win.push(0x01u8); // VCD_SOURCE
    win.extend_from_slice(&encode_varint(source_size as u64));
    win.extend_from_slice(&encode_varint(0u64)); // source pos 0
    win.extend_from_slice(&del);
    win.extend_from_slice(&delta_body);
    win
}

/// Wraps a window body (already built) inside a complete VCDIFF patch stream.
fn vcdiff_patch(window_bytes: &[u8]) -> Vec<u8> {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00"); // magic
    patch.push(0x00u8); // hdr_indicator
    patch.extend_from_slice(window_bytes);
    patch
}

// ---------------------------------------------------------------------------
// Valid patches — ADD
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_add_only_no_base_succeeds() {
    let target = b"hello world";
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    let result = apply_vcdiff(b"", &patch, target.len() as u64, &VcdiffLimits::unlimited())
        .expect("ADD-only must succeed");
    assert_eq!(result, target);
}

#[test]
fn apply_vcdiff_add_empty_target_succeeds() {
    // An empty target uses a window with target_window_length=0 and no instructions.
    let twl = encode_varint(0u64);
    let delta_ind = 0x00u8;
    let lar = encode_varint(0u64);
    let li = encode_varint(0u64);
    let la = encode_varint(0u64);

    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&twl);
    delta_body.push(delta_ind);
    delta_body.extend_from_slice(&lar);
    delta_body.extend_from_slice(&li);
    delta_body.extend_from_slice(&la);

    let del = encode_varint(delta_body.len() as u64);

    let mut window = Vec::new();
    window.push(0x00u8); // win_indicator
    window.extend_from_slice(&del);
    window.extend_from_slice(&delta_body);

    let patch = vcdiff_patch(&window);
    let result = apply_vcdiff(b"", &patch, 0, &VcdiffLimits::unlimited())
        .expect("empty target must succeed");
    assert!(result.is_empty());
}

// ---------------------------------------------------------------------------
// Valid patches — COPY
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_copy_from_source_succeeds() {
    let base = b"hello world";
    let window = vcdiff_copy_source_window(base.len(), base.len());
    let patch = vcdiff_patch(&window);
    let result = apply_vcdiff(base, &patch, base.len() as u64, &VcdiffLimits::unlimited())
        .expect("COPY-from-source must succeed");
    assert_eq!(result, base);
}

// ---------------------------------------------------------------------------
// Valid patches — RUN
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_run_instruction_succeeds() {
    // RUN: emit 0x41 ('A') repeated 8 times.
    let target = b"AAAAAAAA";

    // Instructions: code 0x02 (RUN size=0) followed by size as varint.
    let mut inst = Vec::new();
    inst.push(0x02u8); // RUN code
    inst.extend_from_slice(&encode_varint(8));

    let run_data = b"\x41"; // 'A'

    let twl = encode_varint(8);
    let delta_ind = 0x00u8;
    let lar = encode_varint(1u64); // 1 byte of run data
    let li = encode_varint(inst.len() as u64);
    let la = encode_varint(0u64);

    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&twl);
    delta_body.push(delta_ind);
    delta_body.extend_from_slice(&lar);
    delta_body.extend_from_slice(&li);
    delta_body.extend_from_slice(&la);
    delta_body.extend_from_slice(run_data);
    delta_body.extend_from_slice(&inst);

    let del = encode_varint(delta_body.len() as u64);

    let mut window = Vec::new();
    window.push(0x00u8); // win_indicator
    window.extend_from_slice(&del);
    window.extend_from_slice(&delta_body);

    let patch = vcdiff_patch(&window);
    let result =
        apply_vcdiff(b"", &patch, 8, &VcdiffLimits::unlimited()).expect("RUN must succeed");
    assert_eq!(result, target);
}

// ---------------------------------------------------------------------------
// Multiple windows
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_two_windows_concatenated_succeeds() {
    let part1 = b"hello";
    let part2 = b" world";
    let mut windows = Vec::new();
    windows.extend_from_slice(&vcdiff_add_window(part1));
    windows.extend_from_slice(&vcdiff_add_window(part2));
    let patch = vcdiff_patch(&windows);
    let expected = b"hello world";
    let result = apply_vcdiff(
        b"",
        &patch,
        expected.len() as u64,
        &VcdiffLimits::unlimited(),
    )
    .expect("two-window patch must succeed");
    assert_eq!(result, expected);
}

// ---------------------------------------------------------------------------
// Malformed header
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_wrong_magic_returns_patch_failed() {
    let mut patch = vcdiff_patch(&vcdiff_add_window(b"test"));
    patch[0] = 0x00; // corrupt first magic byte
    let err = apply_vcdiff(b"", &patch, 4, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)), "got {err:?}");
}

#[test]
fn apply_vcdiff_truncated_magic_returns_patch_failed() {
    let patch = b"\xD6\xC3"; // only 2 bytes
    let err = apply_vcdiff(b"", patch, 0, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_vcdiff_custom_codetable_flag_returns_patch_failed() {
    let window = vcdiff_add_window(b"x");
    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00");
    patch.push(0x02u8); // VCD_CODETABLE set
    patch.extend_from_slice(&window);
    let err = apply_vcdiff(b"", &patch, 1, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_vcdiff_header_secondary_compressor_returns_unsupported() {
    let window = vcdiff_add_window(b"x");
    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00");
    patch.push(0x01u8); // VCD_DECOMPRESS
    patch.push(0x01u8); // compressor id
    patch.extend_from_slice(&window);
    let err = apply_vcdiff(b"", &patch, 1, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::Unsupported(_)));
}

#[test]
fn apply_vcdiff_delta_section_secondary_compression_returns_unsupported() {
    let mut inst = Vec::new();
    inst.push(0x01u8);
    inst.extend_from_slice(&encode_varint(1));
    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&encode_varint(1)); // target window len
    delta_body.push(0x01u8); // delta_indicator with secondary compression bit
    delta_body.extend_from_slice(&encode_varint(1)); // len_add_run
    delta_body.extend_from_slice(&encode_varint(inst.len() as u64));
    delta_body.extend_from_slice(&encode_varint(0));
    delta_body.extend_from_slice(b"x");
    delta_body.extend_from_slice(&inst);
    let mut window = Vec::new();
    window.push(0x00u8);
    window.extend_from_slice(&encode_varint(delta_body.len() as u64));
    window.extend_from_slice(&delta_body);
    let patch = vcdiff_patch(&window);
    let err = apply_vcdiff(b"", &patch, 1, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::Unsupported(_)));
}

// ---------------------------------------------------------------------------
// Malformed varint
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_truncated_varint_returns_patch_failed() {
    // A varint with continuation bit set but stream ends.
    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00");
    patch.push(0x00u8); // hdr_indicator
    patch.push(0x00u8); // win_indicator
    patch.push(0x80u8); // varint with MSB=1 (continuation) but no following byte
    let err = apply_vcdiff(b"", &patch, 0, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// COPY beyond base
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_copy_beyond_base_returns_patch_failed() {
    // Source segment claims to be 5 bytes but the base is only 3 bytes.
    let base = b"abc";
    let window = vcdiff_copy_source_window(5, 5); // requests 5 bytes from 3-byte base
    let patch = vcdiff_patch(&window);
    let err = apply_vcdiff(base, &patch, 5, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Output size mismatch
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_output_exceeds_expected_size_returns_patch_failed() {
    let target = b"hello world"; // 11 bytes
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    // Claim expected size is 5, but patch produces 11 bytes.
    let err = apply_vcdiff(b"", &patch, 5, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_vcdiff_output_shorter_than_expected_size_returns_patch_failed() {
    let target = b"hi"; // 2 bytes
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    // Claim expected size is 10, but patch produces 2 bytes.
    let err = apply_vcdiff(b"", &patch, 10, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// Truncated patch stream
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_truncated_window_returns_patch_failed() {
    let window = vcdiff_add_window(b"hello world");
    let mut patch = vcdiff_patch(&window);
    // Truncate the patch by removing the last few bytes.
    let new_len = patch.len() - 3;
    patch.truncate(new_len);
    let err = apply_vcdiff(b"", &patch, 11, &VcdiffLimits::unlimited()).expect_err("must fail");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// ResourceLimits violations
// ---------------------------------------------------------------------------

#[test]
fn apply_vcdiff_output_above_max_output_size_returns_limit_exceeded() {
    let target = b"hello world";
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    let limits = VcdiffLimits {
        max_output_size: 5, // target is 11 bytes → exceeds limit
        ..VcdiffLimits::unlimited()
    };
    let err = apply_vcdiff(b"", &patch, 11, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn apply_vcdiff_window_count_above_limit_returns_limit_exceeded() {
    // Create 3 windows but limit to 2.
    let mut windows = Vec::new();
    for _ in 0..3 {
        windows.extend_from_slice(&vcdiff_add_window(b"x"));
    }
    let patch = vcdiff_patch(&windows);
    let limits = VcdiffLimits {
        max_window_count: 2,
        ..VcdiffLimits::unlimited()
    };
    let err = apply_vcdiff(b"", &patch, 3, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}

#[test]
fn apply_vcdiff_instruction_count_above_limit_returns_limit_exceeded() {
    // Build a window with two separate ADD instructions.
    let mut inst = Vec::new();
    inst.push(0x01u8); // ADD code
    inst.extend_from_slice(&encode_varint(5));
    inst.push(0x01u8); // second ADD
    inst.extend_from_slice(&encode_varint(5));

    let data = b"helloworld"; // 10 bytes total
    let twl = encode_varint(10);
    let delta_ind = 0x00u8;
    let lar = encode_varint(10u64);
    let li = encode_varint(inst.len() as u64);
    let la = encode_varint(0u64);

    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&twl);
    delta_body.push(delta_ind);
    delta_body.extend_from_slice(&lar);
    delta_body.extend_from_slice(&li);
    delta_body.extend_from_slice(&la);
    delta_body.extend_from_slice(data);
    delta_body.extend_from_slice(&inst);

    let del = encode_varint(delta_body.len() as u64);

    let mut window = Vec::new();
    window.push(0x00u8);
    window.extend_from_slice(&del);
    window.extend_from_slice(&delta_body);

    let patch = vcdiff_patch(&window);
    let limits = VcdiffLimits {
        max_instruction_count: 1, // only 1 instruction allowed
        ..VcdiffLimits::unlimited()
    };
    let err = apply_vcdiff(b"", &patch, 10, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}

#[test]
fn apply_vcdiff_patch_size_above_limit_returns_limit_exceeded() {
    let target = b"hello world";
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    let limits = VcdiffLimits {
        max_patch_size: (patch.len() as u64) - 1,
        ..VcdiffLimits::unlimited()
    };
    let err = apply_vcdiff(b"", &patch, target.len() as u64, &limits).expect_err("must fail");
    assert!(matches!(err, PatchError::LimitExceeded(_)));
}
