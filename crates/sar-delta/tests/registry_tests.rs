// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Tests for the patch algorithm registry (`SAR_L_PATCH`, spec section 8.4).
//!
//! These tests verify:
//! * assigned algorithm IDs parse to the correct [`PatchAlgoId`] variant;
//! * reserved IDs (`0x04–0xEF`) return `SAR_ERR_RESERVED_VALUE`;
//! * custom IDs (`0xF0–0xFF`) return `SAR_ERR_UNSUPPORTED`;
//! * `PatchAlgoId::as_u8` round-trips back to the original wire byte;
//! * the display helper returns human-readable names for all ranges.

use sar_delta::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_STORE_PATCH, PATCH_ALGO_VCDIFF, PATCH_ALGO_ZSTD_PATCH,
    PatchAlgoId, PatchError, patch_algo_name, validate_patch_algo_id,
};

// ---------------------------------------------------------------------------
// Assigned IDs
// ---------------------------------------------------------------------------

#[test]
fn store_patch_parses_to_variant() {
    let result = validate_patch_algo_id(PATCH_ALGO_STORE_PATCH).expect("STORE_PATCH is assigned");
    assert_eq!(result, PatchAlgoId::StorePatch);
    assert_eq!(result.as_u8(), PATCH_ALGO_STORE_PATCH);
    assert_eq!(result.name(), "STORE_PATCH");
}

#[test]
fn vcdiff_parses_to_variant() {
    let result = validate_patch_algo_id(PATCH_ALGO_VCDIFF).expect("VCDIFF is assigned");
    assert_eq!(result, PatchAlgoId::Vcdiff);
    assert_eq!(result.as_u8(), PATCH_ALGO_VCDIFF);
    assert_eq!(result.name(), "VCDIFF");
}

#[test]
fn bsdiff_parses_to_variant() {
    let result = validate_patch_algo_id(PATCH_ALGO_BSDIFF).expect("BSDIFF is assigned optional");
    assert_eq!(result, PatchAlgoId::Bsdiff);
    assert_eq!(result.as_u8(), PATCH_ALGO_BSDIFF);
    assert_eq!(result.name(), "BSDIFF");
}

#[test]
fn zstd_patch_parses_to_variant() {
    let result =
        validate_patch_algo_id(PATCH_ALGO_ZSTD_PATCH).expect("ZSTD_PATCH is assigned optional");
    assert_eq!(result, PatchAlgoId::ZstdPatch);
    assert_eq!(result.as_u8(), PATCH_ALGO_ZSTD_PATCH);
    assert_eq!(result.name(), "ZSTD_PATCH");
}

// ---------------------------------------------------------------------------
// Reserved range 0x04–0xEF
// ---------------------------------------------------------------------------

#[test]
fn first_reserved_id_returns_reserved_value_error() {
    let err = validate_patch_algo_id(0x04).expect_err("0x04 is reserved");
    assert!(
        matches!(err, PatchError::ReservedValue(_)),
        "expected ReservedValue, got {err:?}"
    );
}

#[test]
fn middle_reserved_id_returns_reserved_value_error() {
    let err = validate_patch_algo_id(0x80).expect_err("0x80 is reserved");
    assert!(matches!(err, PatchError::ReservedValue(_)));
}

#[test]
fn last_reserved_id_returns_reserved_value_error() {
    let err = validate_patch_algo_id(0xEF).expect_err("0xEF is reserved");
    assert!(matches!(err, PatchError::ReservedValue(_)));
}

#[test]
fn all_reserved_ids_return_reserved_value_error() {
    for id in 0x04u8..=0xEF {
        let err = validate_patch_algo_id(id)
            .expect_err(&format!("0x{id:02X} is in the reserved range 0x04–0xEF"));
        assert!(
            matches!(err, PatchError::ReservedValue(_)),
            "0x{id:02X}: expected ReservedValue, got {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Custom range 0xF0–0xFF
// ---------------------------------------------------------------------------

#[test]
fn first_custom_id_returns_unsupported_error() {
    let err = validate_patch_algo_id(0xF0).expect_err("0xF0 is custom");
    assert!(
        matches!(err, PatchError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

#[test]
fn last_custom_id_returns_unsupported_error() {
    let err = validate_patch_algo_id(0xFF).expect_err("0xFF is custom");
    assert!(matches!(err, PatchError::Unsupported(_)));
}

#[test]
fn all_custom_ids_return_unsupported_error() {
    for id in 0xF0u8..=0xFF {
        let err = validate_patch_algo_id(id)
            .expect_err(&format!("0x{id:02X} is in the custom range 0xF0–0xFF"));
        assert!(
            matches!(err, PatchError::Unsupported(_)),
            "0x{id:02X}: expected Unsupported, got {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// PatchAlgoId::as_u8 round-trip
// ---------------------------------------------------------------------------

#[test]
fn patch_algo_id_as_u8_round_trips() {
    let cases: &[(u8, PatchAlgoId)] = &[
        (0x00, PatchAlgoId::StorePatch),
        (0x01, PatchAlgoId::Vcdiff),
        (0x02, PatchAlgoId::Bsdiff),
        (0x03, PatchAlgoId::ZstdPatch),
        (0xF0, PatchAlgoId::Custom(0xF0)),
        (0xFF, PatchAlgoId::Custom(0xFF)),
    ];
    for (wire, variant) in cases {
        assert_eq!(variant.as_u8(), *wire, "round-trip failed for {variant:?}");
    }
}

// ---------------------------------------------------------------------------
// patch_algo_name display helper
// ---------------------------------------------------------------------------

#[test]
fn patch_algo_name_returns_expected_strings() {
    assert_eq!(patch_algo_name(0x00), "STORE_PATCH");
    assert_eq!(patch_algo_name(0x01), "VCDIFF");
    assert_eq!(patch_algo_name(0x02), "BSDIFF");
    assert_eq!(patch_algo_name(0x03), "ZSTD_PATCH");
    assert_eq!(patch_algo_name(0xF0), "custom");
    assert_eq!(patch_algo_name(0xFF), "custom");
    // reserved
    assert_eq!(patch_algo_name(0x04), "unknown");
    assert_eq!(patch_algo_name(0xEF), "unknown");
}

// ---------------------------------------------------------------------------
// No application is implemented — validate that assigned IDs parse only
// ---------------------------------------------------------------------------

/// Confirm that `validate_patch_algo_id` for assigned IDs succeeds (registry
/// membership check only) even though no application is implemented.
/// This test must not attempt any patch computation.
#[test]
fn assigned_ids_are_registry_members_only() {
    // All four assigned IDs parse successfully; none should attempt application.
    assert!(validate_patch_algo_id(0x00).is_ok());
    assert!(validate_patch_algo_id(0x01).is_ok());
    assert!(validate_patch_algo_id(0x02).is_ok());
    assert!(validate_patch_algo_id(0x03).is_ok());
}
