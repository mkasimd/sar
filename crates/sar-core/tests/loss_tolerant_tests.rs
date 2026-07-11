//! Tests for LOSS_TOLERANT semantics: degraded reconstruction vs. hard failures.

use sar_core::error::SarError;
use sar_fragmentation::{FragmentDescriptor, FragmentEntry, FragmentError, reconstruct_fragments};

fn frag_unlimited() -> sar_fragmentation::FragmentLimits {
    sar_core::ResourceLimits::unlimited().fragment_limits()
}

// ---------------------------------------------------------------------------
// Core LOSS_TOLERANT rules
// ---------------------------------------------------------------------------

#[test]
fn missing_data_fails_by_default() {
    // Gap in fragment indices without LOSS_TOLERANT → hard FragmentGap error.
    let frags = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 4,
            },
            payload: vec![1u8; 4],
        },
        // Index 1 is skipped — gap
        FragmentEntry {
            fragment_index: 2,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 8,
                fragment_size: 4,
            },
            payload: vec![3u8; 4],
        },
    ];
    let err = reconstruct_fragments(frags, 12, &frag_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, FragmentError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn explicit_loss_tolerant_required() {
    // Missing last-fragment marker without LOSS_TOLERANT → FragmentGap.
    let frags = vec![FragmentEntry {
        fragment_index: 0,
        is_last_fragment: false, // no LAST_FRAGMENT
        is_loss_tolerant: false,
        descriptor: FragmentDescriptor {
            absolute_offset: 0,
            fragment_size: 4,
        },
        payload: vec![0u8; 4],
    }];
    let err = reconstruct_fragments(frags, 4, &frag_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, FragmentError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn degraded_output_is_marked() {
    // With LOSS_TOLERANT set and a gap → success with is_degraded = true.
    let frags = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 4,
            },
            payload: b"ABCD".to_vec(),
        },
        // Index 1 is missing
        FragmentEntry {
            fragment_index: 2,
            is_last_fragment: true,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 8,
                fragment_size: 4,
            },
            payload: b"IJKL".to_vec(),
        },
    ];
    let (data, degraded) =
        reconstruct_fragments(frags, 12, &frag_unlimited()).expect("reconstruct");
    assert!(degraded, "is_degraded must be true for gapped output");
    assert_eq!(&data[0..4], b"ABCD");
    assert_eq!(&data[4..8], &[0u8; 4]); // hole
    assert_eq!(&data[8..12], b"IJKL");
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
fn loss_tolerant_without_fragment_flag_is_invalid() {
    // LOSS_TOLERANT without IS_FRAGMENT must be flagged as a conflict.
    use sar_core::{
        GlobalFlags,
        flags::{EntryMode, validate_entry_mode_against_global},
    };

    let global = GlobalFlags::NO_INDEX;
    // mode: LOSS_TOLERANT (bit 7) set but IS_FRAGMENT (bit 5) NOT set
    let mode = EntryMode::from_bits(1u16 << 7);
    let err = validate_entry_mode_against_global(global, mode).expect_err("should fail");
    assert!(
        matches!(err, SarError::FlagConflict(_)),
        "expected FlagConflict, got {err:?}"
    );
}
