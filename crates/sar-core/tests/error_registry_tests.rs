// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::{SarError, SarStatus};

#[test]
fn section10_status_registry_roundtrip_codes() {
    let all_codes = [
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, 52,
    ];
    for code in all_codes {
        let status = SarStatus::try_from(code).expect("known section 10 code");
        assert_eq!(status.code(), code);
        assert!(status.name().starts_with("SAR_"));
    }
}

#[test]
fn section10_status_rejects_unknown_code() {
    assert!(SarStatus::try_from(999).is_err());
}

#[test]
fn section10_error_mapping_includes_required_cases() {
    let cases = [
        (
            SarError::ReservedValue("reserved"),
            SarStatus::ErrReservedValue,
        ),
        (
            SarError::Unsupported("unsupported"),
            SarStatus::ErrUnsupported,
        ),
        (SarError::Malformed("malformed"), SarStatus::ErrMalformed),
        (SarError::Bounds("bounds"), SarStatus::ErrBounds),
        (SarError::Truncated("truncated"), SarStatus::ErrTruncated),
        (
            SarError::InvalidLength("length"),
            SarStatus::ErrInvalidLength,
        ),
        (SarError::Overflow("overflow"), SarStatus::ErrOverflow),
        (SarError::FlagConflict("flags"), SarStatus::ErrFlagConflict),
        (
            SarError::AuthFailed("auth placeholder"),
            SarStatus::ErrAuthFailed,
        ),
        (
            SarError::DecryptFailed("decrypt placeholder"),
            SarStatus::ErrDecryptFailed,
        ),
    ];
    for (error, status) in cases {
        assert_eq!(error.status(), status);
    }
}

#[test]
fn warning_status_is_exposed() {
    assert_eq!(SarStatus::WarnIncomplete.code(), 18);
    assert_eq!(SarStatus::WarnIncomplete.name(), "SAR_WARN_INCOMPLETE");
}

// ---------------------------------------------------------------------------
// Error conversion bridge tests: FragmentError -> SarError
// ---------------------------------------------------------------------------

/// FragmentError::Bounds converts to SarError::Bounds (ErrBounds).
#[test]
fn fragment_error_bounds_converts_to_sar_bounds() {
    let fe = sar_fragmentation::FragmentError::Bounds("test");
    let sar: SarError = fe.into();
    assert!(matches!(sar, SarError::Bounds(_)));
}

/// FragmentError::InvalidMap converts to SarError::InvalidMap (ErrInvalidMap).
#[test]
fn fragment_error_invalid_map_converts_to_sar_invalid_map() {
    let fe = sar_fragmentation::FragmentError::InvalidMap("test");
    let sar: SarError = fe.into();
    assert!(matches!(sar, SarError::InvalidMap(_)));
}

/// FragmentError::FragmentGap converts to SarError::FragmentGap (ErrFragmentGap).
#[test]
fn fragment_error_gap_converts_to_sar_fragment_gap() {
    let fe = sar_fragmentation::FragmentError::FragmentGap("test");
    let sar: SarError = fe.into();
    assert!(matches!(sar, SarError::FragmentGap(_)));
}

/// FragmentError::Overflow converts to SarError::Overflow (ErrOverflow).
#[test]
fn fragment_error_overflow_converts_to_sar_overflow() {
    let fe = sar_fragmentation::FragmentError::Overflow("test");
    let sar: SarError = fe.into();
    assert!(matches!(sar, SarError::Overflow(_)));
}

/// FragmentError::LimitExceeded converts to SarError::LimitExceeded (ErrLimitExceeded).
#[test]
fn fragment_error_limit_converts_to_sar_limit() {
    let fe = sar_fragmentation::FragmentError::LimitExceeded("test");
    let sar: SarError = fe.into();
    assert!(matches!(sar, SarError::LimitExceeded(_)));
}

/// FragmentError::PayloadSizeMismatch converts to SarError::Malformed (ErrMalformed).
/// This is always a fatal structural error — cannot be suppressed by LOSS_TOLERANT.
#[test]
fn fragment_error_payload_mismatch_converts_to_sar_malformed() {
    let fe = sar_fragmentation::FragmentError::PayloadSizeMismatch("test");
    let sar: SarError = fe.into();
    assert!(
        matches!(sar, SarError::Malformed(_)),
        "PayloadSizeMismatch must map to Malformed (fatal structural error)"
    );
}

/// FragmentError::DuplicateIndex converts to SarError::InvalidMap (ErrInvalidMap).
/// Duplicate indices represent a malformed fragment group.
#[test]
fn fragment_error_duplicate_index_converts_to_sar_invalid_map() {
    let fe = sar_fragmentation::FragmentError::DuplicateIndex("test");
    let sar: SarError = fe.into();
    assert!(
        matches!(sar, SarError::InvalidMap(_)),
        "DuplicateIndex must map to InvalidMap (structural/malformed error)"
    );
}

/// Fatal structural fragment errors must not map to degraded/warning statuses.
#[test]
fn fatal_fragment_errors_do_not_become_warnings() {
    let fatal_cases = vec![
        SarError::from(sar_fragmentation::FragmentError::PayloadSizeMismatch(
            "test",
        )),
        SarError::from(sar_fragmentation::FragmentError::DuplicateIndex("test")),
        SarError::from(sar_fragmentation::FragmentError::InvalidMap("test")),
        SarError::from(sar_fragmentation::FragmentError::Bounds("test")),
    ];
    for err in fatal_cases {
        assert_ne!(
            err.status(),
            SarStatus::WarnIncomplete,
            "fatal fragment error must not map to WarnIncomplete: {err:?}"
        );
    }
}
