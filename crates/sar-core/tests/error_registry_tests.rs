// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::error::SarStatusParseError;
use sar_core::{SarError, SarStatus};

/// Section 10.2 registry: exactly the 50 standardized assignments.
const REGISTRY: [(SarStatus, u16, &str); 50] = [
    (SarStatus::Ok, 0, "SAR_OK"),
    (SarStatus::WarnIncomplete, 1, "SAR_WARN_INCOMPLETE"),
    (SarStatus::WarnDuplicate, 2, "SAR_WARN_DUPLICATE"),
    (SarStatus::WarnSkipped, 3, "SAR_WARN_SKIPPED"),
    (SarStatus::ErrMalformed, 100, "SAR_ERR_MALFORMED"),
    (SarStatus::ErrInvalidMagic, 101, "SAR_ERR_INVALID_MAGIC"),
    (SarStatus::ErrInvalidVersion, 102, "SAR_ERR_INVALID_VERSION"),
    (SarStatus::ErrTruncated, 103, "SAR_ERR_TRUNCATED"),
    (SarStatus::ErrInvalidLength, 104, "SAR_ERR_INVALID_LENGTH"),
    (SarStatus::ErrBounds, 105, "SAR_ERR_BOUNDS"),
    (SarStatus::ErrInvalidMap, 106, "SAR_ERR_INVALID_MAP"),
    (SarStatus::ErrFlagConflict, 108, "SAR_ERR_FLAG_CONFLICT"),
    (SarStatus::ErrUnsupported, 200, "SAR_ERR_UNSUPPORTED"),
    (SarStatus::ErrReservedValue, 201, "SAR_ERR_RESERVED_VALUE"),
    (SarStatus::ErrAuthFailed, 300, "SAR_ERR_AUTH_FAILED"),
    (SarStatus::ErrCrcMismatch, 301, "SAR_ERR_CRC_MISMATCH"),
    (SarStatus::ErrHashMismatch, 302, "SAR_ERR_HASH_MISMATCH"),
    (
        SarStatus::ErrSignatureFailed,
        303,
        "SAR_ERR_SIGNATURE_FAILED",
    ),
    (SarStatus::ErrKeyMissing, 304, "SAR_ERR_KEY_MISSING"),
    (SarStatus::ErrKeyRejected, 305, "SAR_ERR_KEY_REJECTED"),
    (SarStatus::ErrNonceReuse, 306, "SAR_ERR_NONCE_REUSE"),
    (SarStatus::ErrFragmentGap, 400, "SAR_ERR_FRAGMENT_GAP"),
    (
        SarStatus::ErrFragmentTimeout,
        401,
        "SAR_ERR_FRAGMENT_TIMEOUT",
    ),
    (
        SarStatus::ErrRecipeUnresolvable,
        402,
        "SAR_ERR_RECIPE_UNRESOLVABLE",
    ),
    (SarStatus::ErrEcFailed, 403, "SAR_ERR_EC_FAILED"),
    (
        SarStatus::ErrRecoveryUnavailable,
        404,
        "SAR_ERR_RECOVERY_UNAVAILABLE",
    ),
    (
        SarStatus::ErrRecoveryCorrupted,
        405,
        "SAR_ERR_RECOVERY_CORRUPTED",
    ),
    (SarStatus::ErrPatchFailed, 406, "SAR_ERR_PATCH_FAILED"),
    (SarStatus::ErrBaseMissing, 407, "SAR_ERR_BASE_MISSING"),
    (SarStatus::ErrOverflow, 500, "SAR_ERR_OVERFLOW"),
    (SarStatus::ErrLimitExceeded, 501, "SAR_ERR_LIMIT_EXCEEDED"),
    (
        SarStatus::ErrReassemblyBufferFull,
        502,
        "SAR_ERR_REASSEMBLY_BUFFER_FULL",
    ),
    (SarStatus::ErrNoSpace, 503, "SAR_ERR_NO_SPACE"),
    (SarStatus::ErrStreamState, 600, "SAR_ERR_STREAM_STATE"),
    (
        SarStatus::ErrTooManyStreams,
        601,
        "SAR_ERR_TOO_MANY_STREAMS",
    ),
    (SarStatus::ErrStreamClosed, 602, "SAR_ERR_STREAM_CLOSED"),
    (
        SarStatus::ErrPartitionMissing,
        603,
        "SAR_ERR_PARTITION_MISSING",
    ),
    (
        SarStatus::ErrPartitionMismatch,
        604,
        "SAR_ERR_PARTITION_MISMATCH",
    ),
    (SarStatus::ErrSessionTimeout, 605, "SAR_ERR_SESSION_TIMEOUT"),
    (SarStatus::ErrPathCollision, 700, "SAR_ERR_PATH_COLLISION"),
    (SarStatus::ErrPathEscape, 701, "SAR_ERR_PATH_ESCAPE"),
    (
        SarStatus::ErrMetadataMissing,
        702,
        "SAR_ERR_METADATA_MISSING",
    ),
    (
        SarStatus::ErrMetadataConflict,
        703,
        "SAR_ERR_METADATA_CONFLICT",
    ),
    (SarStatus::ErrAlreadyExists, 704, "SAR_ERR_ALREADY_EXISTS"),
    (SarStatus::ErrNotFound, 705, "SAR_ERR_NOT_FOUND"),
    (SarStatus::ErrIo, 800, "SAR_ERR_IO"),
    (SarStatus::ErrWriteProtected, 801, "SAR_ERR_WRITE_PROTECTED"),
    (SarStatus::ErrInternal, 802, "SAR_ERR_INTERNAL"),
    (SarStatus::ErrInvalidInput, 803, "SAR_ERR_INVALID_INPUT"),
    (SarStatus::ErrGeneric, 0xFFFF, "SAR_ERR_GENERIC"),
];

/// Section 10.3 retired allocations.
const RETIRED: [u16; 10] = [107, 390, 391, 392, 393, 490, 491, 590, 690, 890];

#[test]
fn section10_status_registry_has_exactly_50_assignments() {
    assert_eq!(REGISTRY.len(), 50);
    let accepted = (0..=u16::MAX)
        .filter(|code| SarStatus::try_from(*code).is_ok())
        .count();
    assert_eq!(
        accepted, 50,
        "TryFrom<u16> must accept exactly the registry"
    );
}

#[test]
fn section10_status_registry_roundtrip_codes() {
    for (status, code, name) in REGISTRY {
        assert_eq!(status.code(), code);
        assert_eq!(u16::from(status), code);
        assert_eq!(status.name(), name);
        assert_eq!(SarStatus::try_from(code), Ok(status));
        assert_eq!(status.to_string(), format!("{name} ({code})"));
    }
}

#[test]
fn section10_generic_status_is_0xffff() {
    assert_eq!(SarStatus::ErrGeneric.code(), 0xFFFF_u16);
    assert_eq!(u16::from(SarStatus::ErrGeneric), 0xFFFF_u16);
    assert_eq!(SarStatus::try_from(0xFFFF_u16), Ok(SarStatus::ErrGeneric));
}

#[test]
fn section10_only_zero_is_success() {
    for code in 0..=u16::MAX {
        if let Ok(status) = SarStatus::try_from(code) {
            assert_eq!(status == SarStatus::Ok, code == 0);
        }
    }
}

#[test]
fn section10_retired_values_are_rejected() {
    for code in RETIRED {
        assert_eq!(SarStatus::try_from(code), Err(SarStatusParseError(code)));
    }
}

#[test]
fn section10_unassigned_reserved_and_private_values_are_rejected() {
    let unassigned_in_block = [
        4, 99, 109, 199, 202, 299, 307, 399, 408, 499, 504, 599, 606, 699, 706, 799, 804, 899,
    ];
    // 900-32767 reserved; 32768-65534 implementation-private; boundaries included.
    let outside_blocks = [900, 1000, 32767, 32768, 40000, 65534];
    for code in unassigned_in_block.into_iter().chain(outside_blocks) {
        assert_eq!(SarStatus::try_from(code), Err(SarStatusParseError(code)));
    }
}

#[test]
fn section10_legacy_draft_numbers_are_not_aliases() {
    // Draft-era values 1..=52 must not resolve to the legacy meaning.
    assert_eq!(SarStatus::try_from(18), Err(SarStatusParseError(18)));
    assert_eq!(SarStatus::try_from(39), Err(SarStatusParseError(39)));
    assert_eq!(SarStatus::try_from(1), Ok(SarStatus::WarnIncomplete));
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
        (SarError::CrcMismatch("crc"), SarStatus::ErrCrcMismatch),
        (SarError::HashMismatch("hash"), SarStatus::ErrHashMismatch),
        (
            SarError::SessionTimeout("watchdog"),
            SarStatus::ErrSessionTimeout,
        ),
        (
            SarError::FragmentTimeout("fragment"),
            SarStatus::ErrFragmentTimeout,
        ),
        (
            SarError::PathCollision("collision"),
            SarStatus::ErrPathCollision,
        ),
        (SarError::PathEscape("escape"), SarStatus::ErrPathEscape),
        (SarError::InvalidInput("input"), SarStatus::ErrInvalidInput),
        (SarError::Internal("internal"), SarStatus::ErrInternal),
        (SarError::Generic, SarStatus::ErrGeneric),
        (SarError::Io(std::io::Error::other("io")), SarStatus::ErrIo),
    ];
    for (error, status) in cases {
        assert_eq!(error.status(), status);
        assert!(
            !matches!(
                status,
                SarStatus::Ok
                    | SarStatus::WarnIncomplete
                    | SarStatus::WarnDuplicate
                    | SarStatus::WarnSkipped
            ),
            "SarError must never map to a success or warning status"
        );
    }
}

#[test]
fn warning_status_is_exposed() {
    assert_eq!(SarStatus::WarnIncomplete.code(), 1);
    assert_eq!(SarStatus::WarnIncomplete.name(), "SAR_WARN_INCOMPLETE");
    assert_eq!(SarStatus::WarnDuplicate.code(), 2);
    assert_eq!(SarStatus::WarnSkipped.code(), 3);
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

/// FragmentError::PayloadSizeMismatch converts to SarError::InvalidLength
/// (contribution length vs. LFH Uncompressed Size, spec §6.1.3 / §10).
/// Always fatal — cannot be suppressed by LOSS_TOLERANT.
#[test]
fn fragment_error_payload_mismatch_converts_to_sar_invalid_length() {
    let fe = sar_fragmentation::FragmentError::PayloadSizeMismatch("test");
    let sar: SarError = fe.into();
    assert!(
        matches!(sar, SarError::InvalidLength(_)),
        "PayloadSizeMismatch must map to InvalidLength"
    );
}

/// FragmentError::DuplicateIndex converts to SarError::MetadataConflict
/// (conflicting fragment group metadata; `INVALID_MAP` is reserved for sparse maps).
#[test]
fn fragment_error_duplicate_index_converts_to_sar_metadata_conflict() {
    let fe = sar_fragmentation::FragmentError::DuplicateIndex("test");
    let sar: SarError = fe.into();
    assert!(
        matches!(sar, SarError::MetadataConflict(_)),
        "DuplicateIndex must map to MetadataConflict"
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
