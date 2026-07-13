// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Tests for VCDIFF and SAR BSDIFF v1 patch generation.
//!
//! Spec requirements tested (spec §8.4):
//!
//! * Generated VCDIFF applies with [`apply_vcdiff`] and reconstructs target.
//! * Generated SAR BSDIFF v1 applies with [`apply_bsdiff`] and reconstructs target.
//! * VCDIFF handles small target-only (empty base) literal generation.
//! * BSDIFF handles small target-only or simple changed-target generation.
//! * Generated VCDIFF bytes are not `STORE_PATCH` bytes (magic differs).
//! * Generated BSDIFF bytes are not `STORE_PATCH` bytes (magic differs).
//! * Empty target round-trips through both generators.
//! * Excessive output/limit sizes fail closed with [`PatchError::LimitExceeded`].
//! * Zero or minimum limits reject oversized inputs.
//! * [`generate_store_patch`] rejects a length mismatch.

use sar_delta::{
    BsdiffLimits, PatchError, VcdiffLimits, apply_bsdiff, apply_vcdiff, generate_bsdiff_patch,
    generate_store_patch, generate_vcdiff_patch,
};

const VCDIFF_STREAM_HEADER: [u8; 4] = [0xD6, 0xC3, 0xC4, 0x00];
const SAR_BSDIFF_MAGIC: &[u8; 8] = b"SARBSD01";
const BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES: u64 = 24;

// ---------------------------------------------------------------------------
// VCDIFF generation round-trips
// ---------------------------------------------------------------------------

#[test]
fn generate_vcdiff_round_trip_empty_base_small_target() {
    let base = [];
    let target = b"hello, world!";
    let limits = VcdiffLimits::default();

    let patch = generate_vcdiff_patch(&base, target, &limits).expect("generate");
    let reconstructed = apply_vcdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_vcdiff_round_trip_with_base() {
    let base: Vec<u8> = (0u8..=63).collect();
    let target: Vec<u8> = (0u8..64).map(|i| i.wrapping_add(1)).collect();
    let limits = VcdiffLimits::default();

    let patch = generate_vcdiff_patch(&base, &target, &limits).expect("generate");
    let reconstructed = apply_vcdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_vcdiff_round_trip_empty_target() {
    let base = b"some base bytes";
    let target: &[u8] = b"";
    let limits = VcdiffLimits::default();

    let patch = generate_vcdiff_patch(base, target, &limits).expect("generate");
    let reconstructed = apply_vcdiff(base, &patch, 0, &limits).expect("apply empty target");

    assert!(reconstructed.is_empty());
}

#[test]
fn generate_vcdiff_round_trip_binary_data() {
    let base: Vec<u8> = (0u8..128).map(|i| i ^ 0xAA).collect();
    let target: Vec<u8> = (0u8..200).map(|i| i.wrapping_mul(3)).collect();
    let limits = VcdiffLimits::default();

    let patch = generate_vcdiff_patch(&base, &target, &limits).expect("generate");
    let reconstructed = apply_vcdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_vcdiff_output_is_not_store_patch() {
    let target = b"not a store patch";
    let limits = VcdiffLimits::default();

    let patch = generate_vcdiff_patch(b"", target, &limits).expect("generate");

    assert!(
        patch.starts_with(&VCDIFF_STREAM_HEADER),
        "VCDIFF patch must start with VCDIFF magic"
    );
    // Must not equal the target bytes (STORE_PATCH would just be target bytes)
    assert_ne!(
        patch, target,
        "generated VCDIFF must not be identical to the target (STORE_PATCH would be)"
    );
}

#[test]
fn generate_vcdiff_limit_exceeded_max_output_size() {
    let target: Vec<u8> = vec![0u8; 1024];
    let limits = VcdiffLimits {
        max_output_size: 512,
        ..VcdiffLimits::default()
    };

    let result = generate_vcdiff_patch(b"", &target, &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded for oversized target, got {:?}",
        result
    );
}

#[test]
fn generate_vcdiff_limit_exceeded_max_patch_size() {
    let target = b"hello, world!";
    let patch = generate_vcdiff_patch(b"", target, &VcdiffLimits::default()).expect("generate");
    let limits = VcdiffLimits {
        max_patch_size: u64::try_from(patch.len() - 1).expect("patch length fits u64"),
        ..VcdiffLimits::default()
    };

    let result = generate_vcdiff_patch(b"", target, &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded for oversized patch, got {:?}",
        result
    );
}

#[test]
fn generate_vcdiff_limit_exceeded_zero_window_count() {
    let limits = VcdiffLimits {
        max_window_count: 0,
        ..VcdiffLimits::default()
    };

    let result = generate_vcdiff_patch(b"", b"x", &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded when max_window_count=0, got {:?}",
        result
    );
}

#[test]
fn generate_vcdiff_limit_exceeded_zero_instruction_count() {
    let limits = VcdiffLimits {
        max_instruction_count: 0,
        ..VcdiffLimits::default()
    };

    let result = generate_vcdiff_patch(b"", b"x", &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded when max_instruction_count=0, got {:?}",
        result
    );
}

#[test]
fn generate_vcdiff_empty_target_respects_max_patch_size() {
    let patch = generate_vcdiff_patch(b"", b"", &VcdiffLimits::default()).expect("generate");
    let limits = VcdiffLimits {
        max_patch_size: u64::try_from(patch.len() - 1).expect("patch length fits u64"),
        ..VcdiffLimits::default()
    };

    let result = generate_vcdiff_patch(b"", b"", &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded for empty-target patch size, got {:?}",
        result
    );
}

#[test]
fn generate_vcdiff_does_not_panic_on_large_input() {
    // Not actually large enough to OOM, just exercises the limit path.
    let target: Vec<u8> = vec![0xABu8; 4096];
    let limits = VcdiffLimits {
        max_output_size: u64::MAX,
        ..VcdiffLimits::default()
    };

    let patch = generate_vcdiff_patch(b"", &target, &limits).expect("generate large");
    let reconstructed =
        apply_vcdiff(b"", &patch, target.len() as u64, &limits).expect("apply large");
    assert_eq!(reconstructed, target);
}

// ---------------------------------------------------------------------------
// SAR BSDIFF v1 generation round-trips
// ---------------------------------------------------------------------------

#[test]
fn generate_bsdiff_round_trip_empty_base_small_target() {
    let base: &[u8] = b"";
    let target = b"hello, BSDIFF!";
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(base, target, &limits).expect("generate");
    let reconstructed = apply_bsdiff(base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_bsdiff_round_trip_with_base() {
    let base: Vec<u8> = (0u8..=63).collect();
    let target: Vec<u8> = (0u8..64).map(|i| i.wrapping_add(5)).collect();
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(&base, &target, &limits).expect("generate");
    let reconstructed = apply_bsdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_bsdiff_round_trip_empty_target() {
    let base = b"base data here";
    let target: &[u8] = b"";
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(base, target, &limits).expect("generate");
    let reconstructed = apply_bsdiff(base, &patch, 0, &limits).expect("apply empty target");

    assert!(reconstructed.is_empty());
}

#[test]
fn generate_bsdiff_round_trip_target_longer_than_base() {
    let base: Vec<u8> = vec![0x10u8; 16];
    let target: Vec<u8> = vec![0x10u8; 32]; // twice as long
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(&base, &target, &limits).expect("generate");
    let reconstructed = apply_bsdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_bsdiff_round_trip_target_shorter_than_base() {
    let base: Vec<u8> = vec![0xFFu8; 32];
    let target: Vec<u8> = vec![0xFFu8; 16];
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(&base, &target, &limits).expect("generate");
    let reconstructed = apply_bsdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_bsdiff_round_trip_binary_data() {
    let base: Vec<u8> = (0u8..=255).collect();
    let target: Vec<u8> = (0u8..=255).map(|b| b.wrapping_add(1)).collect();
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(&base, &target, &limits).expect("generate");
    let reconstructed = apply_bsdiff(&base, &patch, target.len() as u64, &limits).expect("apply");

    assert_eq!(reconstructed, target);
}

#[test]
fn generate_bsdiff_output_is_not_store_patch() {
    let target = b"not a store patch";
    let limits = BsdiffLimits::default();

    let patch = generate_bsdiff_patch(b"", target, &limits).expect("generate");

    assert!(
        patch.starts_with(SAR_BSDIFF_MAGIC),
        "BSDIFF patch must start with SARBSD01 magic"
    );
    // Must not equal the target bytes (STORE_PATCH would just be target bytes)
    assert_ne!(
        patch, target,
        "generated BSDIFF must not be identical to the target (STORE_PATCH would be)"
    );
}

#[test]
fn generate_bsdiff_limit_exceeded_max_target_size() {
    let target: Vec<u8> = vec![0u8; 1024];
    let limits = BsdiffLimits {
        max_target_size: 512,
        ..BsdiffLimits::default()
    };

    let result = generate_bsdiff_patch(b"", &target, &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded for oversized target, got {:?}",
        result
    );
}

#[test]
fn generate_bsdiff_limit_exceeded_max_diff_bytes() {
    let base: Vec<u8> = vec![0u8; 32];
    let target: Vec<u8> = vec![1u8; 32];
    let limits = BsdiffLimits {
        max_diff_bytes: 16,
        ..BsdiffLimits::default()
    };

    let result = generate_bsdiff_patch(&base, &target, &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded for oversized diff block, got {:?}",
        result
    );
}

#[test]
fn generate_bsdiff_limit_exceeded_max_control_triples() {
    // Our generator always emits exactly 1 triple; 0 max_control_triples must fail.
    let limits = BsdiffLimits {
        max_control_triples: 0,
        ..BsdiffLimits::default()
    };

    let result = generate_bsdiff_patch(b"", b"x", &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded when max_control_triples=0, got {:?}",
        result
    );
}

#[test]
fn generate_bsdiff_limit_exceeded_max_control_bytes() {
    let limits = BsdiffLimits {
        max_control_bytes: BSDIFF_SINGLE_TRIPLE_CONTROL_BYTES - 1,
        ..BsdiffLimits::default()
    };

    let result = generate_bsdiff_patch(b"", b"x", &limits);
    assert!(
        matches!(result, Err(PatchError::LimitExceeded(_))),
        "expected LimitExceeded when max_control_bytes is below one control triple, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// generate_store_patch
// ---------------------------------------------------------------------------

#[test]
fn generate_store_patch_round_trip() {
    let target = b"store patch data";
    let patch = generate_store_patch(target, target.len() as u64).expect("generate");
    assert_eq!(patch, target);
}

#[test]
fn generate_store_patch_length_mismatch_fails() {
    let target = b"some data";
    let result = generate_store_patch(target, 100);
    assert!(
        matches!(result, Err(PatchError::PatchFailed(_))),
        "expected PatchFailed for length mismatch, got {:?}",
        result
    );
}
