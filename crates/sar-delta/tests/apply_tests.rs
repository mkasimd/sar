// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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
    let result = apply_store_patch(b"").expect("empty payload");
    assert!(result.is_empty());
}

#[test]
fn apply_store_patch_nonempty_payload_succeeds() {
    let data = b"hello world";
    let result = apply_store_patch(data).expect("matching payload/expected_len");
    assert_eq!(result, data);
}

#[test]
fn apply_store_patch_returns_owned_vec() {
    let data = b"copy me";
    let result = apply_store_patch(data).expect("success");
    // Confirm the returned Vec is independent of the input slice.
    assert_eq!(result.as_slice(), data);
}

// ---------------------------------------------------------------------------
// Output length is the payload length
// ---------------------------------------------------------------------------

#[test]
fn apply_store_patch_output_length_is_payload_length() {
    for data in [&b""[..], b"x", b"a longer decoded patch representation"] {
        let out = apply_store_patch(data).expect("STORE_PATCH is identity");
        assert_eq!(out.len(), data.len());
    }
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
