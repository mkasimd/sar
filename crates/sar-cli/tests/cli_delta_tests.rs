//! CLI tests for `inspect --json` delta metadata reporting (Milestone 9b).
//!
//! These tests verify:
//! * `inspect --json` reports `has_delta: true` when `HAS_DELTA` is set;
//! * `inspect --json` reports `has_delta: false` when `HAS_DELTA` is not set;
//! * per-entry JSON includes `patch_algo_id` and `delta_base_hash` when present;
//! * per-entry JSON includes `patch_algorithm` name;
//! * delta fields are absent in per-entry JSON when `HAS_DELTA` is not set;
//! * no patch application is attempted during inspect.

use std::fs;

use assert_cmd::Command;
use sar_core::{
    GlobalFlags,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};
use serde_json::Value;
use tempfile::tempdir;

/// Build a minimal `HAS_DELTA` archive with a single entry.
fn build_delta_archive(
    dir: &std::path::Path,
    patch_algo_id: u8,
    delta_base_hash: [u8; 32],
    payload: &[u8],
) -> std::path::PathBuf {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("write global header");

    let mut lfh = LocalFileHeader::minimal_store(b"delta_entry.bin".to_vec(), payload.len() as u64);
    lfh.patch_algo_id = Some(patch_algo_id);
    lfh.delta_base_hash = Some(delta_base_hash);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(payload);

    let path = dir.join("delta.sar");
    fs::write(&path, &bytes).expect("write archive file");
    path
}

/// Build a minimal archive without `HAS_DELTA`.
fn build_no_delta_archive(dir: &std::path::Path) -> std::path::PathBuf {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("write global header");

    let lfh = LocalFileHeader::minimal_store(b"plain.bin".to_vec(), 4);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"data");

    let path = dir.join("nodelta.sar");
    fs::write(&path, &bytes).expect("write archive file");
    path
}

// ---------------------------------------------------------------------------
// Archive-level has_delta flag
// ---------------------------------------------------------------------------

#[test]
fn inspect_json_reports_has_delta_true_when_flag_set() {
    let dir = tempdir().expect("tempdir");
    let hash = [0xABu8; 32];
    let archive = build_delta_archive(dir.path(), 0x00, hash, b"payload");

    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(
        output.status.success(),
        "inspect failed: {:?}",
        output.status
    );
    let json: Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output from inspect");

    assert_eq!(
        json["has_delta"],
        Value::Bool(true),
        "has_delta must be true when HAS_DELTA flag is set"
    );
}

#[test]
fn inspect_json_reports_has_delta_false_when_flag_not_set() {
    let dir = tempdir().expect("tempdir");
    let archive = build_no_delta_archive(dir.path());

    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(output.status.success(), "inspect failed");
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    assert_eq!(
        json["has_delta"],
        Value::Bool(false),
        "has_delta must be false when HAS_DELTA flag is not set"
    );
}

// ---------------------------------------------------------------------------
// Per-entry delta fields
// ---------------------------------------------------------------------------

#[test]
fn inspect_json_entry_includes_patch_algo_id_and_delta_base_hash() {
    let dir = tempdir().expect("tempdir");
    let hash: [u8; 32] = {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        h
    };
    // Use STORE_PATCH (0x00): the only implemented algorithm as of M9b.
    // VCDIFF (0x01) is unsupported and returns SAR_ERR_UNSUPPORTED when read.
    let archive = build_delta_archive(dir.path(), 0x00, hash, b"payload");

    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(output.status.success(), "inspect failed");
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let entry = &json["entries"][0];
    assert_eq!(
        entry["patch_algo_id"],
        Value::Number(0.into()),
        "patch_algo_id must be 0x00 (STORE_PATCH)"
    );

    let expected_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        entry["delta_base_hash"],
        Value::String(expected_hex),
        "delta_base_hash must be a lowercase hex string"
    );

    assert_eq!(
        entry["patch_algorithm"],
        Value::String("STORE_PATCH".to_string()),
        "patch_algorithm must be 'STORE_PATCH'"
    );
}

#[test]
fn inspect_json_entry_no_delta_fields_when_flag_not_set() {
    let dir = tempdir().expect("tempdir");
    let archive = build_no_delta_archive(dir.path());

    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(output.status.success(), "inspect failed");
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let entry = &json["entries"][0];
    assert!(
        entry.get("patch_algo_id").is_none() || entry["patch_algo_id"] == Value::Null,
        "patch_algo_id must be absent when HAS_DELTA is not set"
    );
    assert!(
        entry.get("delta_base_hash").is_none() || entry["delta_base_hash"] == Value::Null,
        "delta_base_hash must be absent when HAS_DELTA is not set"
    );
    assert!(
        entry.get("patch_algorithm").is_none() || entry["patch_algorithm"] == Value::Null,
        "patch_algorithm must be absent when HAS_DELTA is not set"
    );
}

/// Verify all-zero `Delta Base Hash` is serialized as a 64-character hex string
/// of zeroes with no special interpretation.
#[test]
fn inspect_json_all_zero_delta_base_hash_preserved_as_hex() {
    let dir = tempdir().expect("tempdir");
    let archive = build_delta_archive(dir.path(), 0x00, [0u8; 32], b"data");

    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(output.status.success(), "inspect failed");
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let entry = &json["entries"][0];
    let expected = "0".repeat(64);
    assert_eq!(
        entry["delta_base_hash"],
        Value::String(expected),
        "all-zero delta_base_hash must serialize as 64 hex zeros"
    );
}

/// Verify that STORE_PATCH algo is reported correctly.
#[test]
fn inspect_json_store_patch_algo_name() {
    let dir = tempdir().expect("tempdir");
    let archive = build_delta_archive(dir.path(), 0x00, [0xCCu8; 32], b"data");

    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(output.status.success(), "inspect failed");
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let entry = &json["entries"][0];
    assert_eq!(entry["patch_algo_id"], Value::Number(0.into()));
    assert_eq!(
        entry["patch_algorithm"],
        Value::String("STORE_PATCH".to_string())
    );
}

/// Verify that inspect does not attempt patch application — the payload must
/// be returned as-is.  (The entry payload is the raw bytes, not a
/// reconstructed target.)
#[test]
fn inspect_does_not_apply_patch_to_payload() {
    let dir = tempdir().expect("tempdir");
    let payload = b"raw-payload-bytes-not-a-target";
    let archive = build_delta_archive(dir.path(), 0x00, [0u8; 32], payload);

    // inspect must succeed even though no base object exists and no patch
    // application is implemented.
    let output = Command::cargo_bin("sar-cli")
        .expect("sar binary")
        .args(["inspect", "--json", archive.to_str().expect("path to str")])
        .output()
        .expect("run inspect");

    assert!(
        output.status.success(),
        "inspect must not fail when HAS_DELTA is set but application is not implemented"
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    // Entry count must be 1 — the entry was parsed without applying the patch.
    assert_eq!(json["entry_count"], Value::Number(1.into()));
}
