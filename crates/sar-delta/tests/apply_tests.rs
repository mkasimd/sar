//! Unit tests for [`sar_delta::apply_store_patch`].
//!
//! These tests verify the pure `apply_store_patch` function in isolation,
//! without any archive reader or resource-limit context.
//!
//! Integration tests that exercise STORE_PATCH through the full archive
//! reader pipeline (including compression, encryption, sparse, and
//! fragmentation) live in `crates/sar-core/tests/store_patch_tests.rs`.

use sar_delta::{PatchError, apply_store_patch};

// ---------------------------------------------------------------------------
// Basic success
// ---------------------------------------------------------------------------

#[test]
fn apply_store_patch_empty_payload_succeeds() {
    let result = apply_store_patch(b"", 0).expect("empty payload with expected_len=0");
    assert!(result.is_empty());
}

#[test]
fn apply_store_patch_nonempty_payload_succeeds() {
    let data = b"hello world";
    let result = apply_store_patch(data, data.len() as u64).expect("matching payload/expected_len");
    assert_eq!(result, data);
}

#[test]
fn apply_store_patch_returns_owned_vec() {
    let data = b"copy me";
    let result = apply_store_patch(data, data.len() as u64).expect("success");
    // Confirm the returned Vec is independent of the input slice.
    assert_eq!(result.as_slice(), data);
}

// ---------------------------------------------------------------------------
// Length mismatch → PatchFailed
// ---------------------------------------------------------------------------

#[test]
fn apply_store_patch_shorter_payload_returns_patch_failed() {
    // Payload is shorter than expected_len.
    let data = b"short";
    let err =
        apply_store_patch(data, (data.len() as u64) + 1).expect_err("shorter payload must fail");
    assert!(
        matches!(err, PatchError::PatchFailed(_)),
        "expected PatchFailed, got {err:?}"
    );
}

#[test]
fn apply_store_patch_longer_payload_returns_patch_failed() {
    // Payload is longer than expected_len.
    let data = b"too long payload";
    let expected_len = (data.len() as u64) - 1;
    let err = apply_store_patch(data, expected_len).expect_err("longer payload must fail");
    assert!(
        matches!(err, PatchError::PatchFailed(_)),
        "expected PatchFailed, got {err:?}"
    );
}

#[test]
fn apply_store_patch_zero_expected_nonzero_actual_returns_patch_failed() {
    let err = apply_store_patch(b"x", 0).expect_err("non-empty payload with expected_len=0");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

#[test]
fn apply_store_patch_nonzero_expected_zero_actual_returns_patch_failed() {
    let err = apply_store_patch(b"", 1).expect_err("empty payload with expected_len=1");
    assert!(matches!(err, PatchError::PatchFailed(_)));
}

// ---------------------------------------------------------------------------
// PatchError::PatchFailed display
// ---------------------------------------------------------------------------

#[test]
fn patch_error_patch_failed_displays_message() {
    let err = PatchError::PatchFailed("test message");
    let s = err.to_string();
    assert!(s.contains("patch failed"), "display string: {s}");
    assert!(s.contains("test message"), "display string: {s}");
}
