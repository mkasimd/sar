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
