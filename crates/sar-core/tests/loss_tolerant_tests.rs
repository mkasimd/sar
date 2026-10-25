// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Tests for LOSS_TOLERANT semantics: degraded reconstruction vs. hard failures.

use sar_core::error::SarError;
use sar_fragmentation::{FragmentEntry, FragmentError, reconstruct_fragments};

fn frag_unlimited() -> sar_fragmentation::FragmentLimits {
    sar_core::ResourceLimits::unlimited().fragment_limits()
}

// ---------------------------------------------------------------------------
// Core LOSS_TOLERANT rules
// ---------------------------------------------------------------------------

fn frag(index: u32, last: bool, lt: bool, data: &[u8]) -> FragmentEntry {
    FragmentEntry {
        fragment_index: index,
        is_last_fragment: last,
        is_loss_tolerant: lt,
        uncompressed_size: data.len() as u64,
        payload: data.to_vec(),
    }
}

#[test]
fn missing_data_fails_by_default() {
    // Gap in fragment indices without LOSS_TOLERANT → hard FragmentGap error.
    let frags = vec![
        frag(0, false, false, &[1u8; 4]),
        frag(2, true, false, &[3u8; 4]),
    ];
    let err = reconstruct_fragments(frags, &frag_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, FragmentError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn explicit_loss_tolerant_required() {
    // Missing last-fragment marker without LOSS_TOLERANT → FragmentGap.
    let frags = vec![frag(0, false, false, &[0u8; 4])];
    let err = reconstruct_fragments(frags, &frag_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, FragmentError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn degraded_output_is_marked() {
    // LOSS_TOLERANT with a gap → longest contiguous prefix, is_degraded = true.
    // The old zero-filled hole behavior is retired (no synthetic bytes).
    let frags = vec![frag(0, false, true, b"ABCD"), frag(2, true, true, b"IJKL")];
    let (data, degraded) = reconstruct_fragments(frags, &frag_unlimited()).expect("reconstruct");
    assert!(degraded, "is_degraded must be true for gapped output");
    assert_eq!(data, b"ABCD");
}

#[test]
fn aead_auth_failure_is_not_lossy() {
    // LOSS_TOLERANT must NOT cause AEAD auth failures to be swallowed.
    // Verify: SarError::AuthFailed carries status ErrAuthFailed.
    use sar_core::error::SarStatus;

    let auth_err = SarError::AuthFailed("AEAD tag mismatch");
    assert_eq!(auth_err.status(), SarStatus::ErrAuthFailed);

    // Confirm that FragmentGap has a different status code.
    let gap_err = SarError::FragmentGap("test gap");
    assert_ne!(gap_err.status(), SarStatus::ErrAuthFailed);
    assert_eq!(gap_err.status(), SarStatus::ErrFragmentGap);
}

#[test]
fn loss_tolerant_without_fragment_flag_is_structurally_valid() {
    use sar_core::{
        GlobalFlags,
        flags::{EntryMode, validate_entry_mode_against_global},
    };

    let mode = EntryMode::from_bits(1u16 << 7);
    validate_entry_mode_against_global(GlobalFlags::NO_INDEX, mode)
        .expect("LOSS_TOLERANT does not require IS_FRAGMENT");
}
