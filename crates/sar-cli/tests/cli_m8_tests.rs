// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! CLI integration tests for Milestone 8 (fragmentation, sparse, loss-tolerant,
//! archive-level recovery, repair command).

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sar() -> Command {
    Command::cargo_bin("sar-cli").expect("sar-cli binary")
}

fn create_simple_archive(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let input = dir.path().join("data.txt");
    fs::write(&input, b"test content for m8").expect("write");
    let archive = dir.path().join("archive.sar");
    sar()
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--indexed",
        ])
        .assert()
        .success();
    archive
}

// ---------------------------------------------------------------------------
// Inspect JSON — flags metadata
// ---------------------------------------------------------------------------

#[test]
fn inspect_json_reports_fragmentation_metadata() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");

    // fragmentation key must be present (false for a simple archive)
    assert!(
        v.get("fragmentation").is_some(),
        "fragmentation key missing from JSON"
    );
    assert_eq!(v["fragmentation"], false);
}

#[test]
fn inspect_json_reports_sparse_metadata() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");

    // sparse_files key must be present (false for a simple archive)
    assert!(
        v.get("sparse_files").is_some(),
        "sparse_files key missing from JSON"
    );
    assert_eq!(v["sparse_files"], false);
}

#[test]
fn inspect_json_reports_loss_tolerant_metadata() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");

    // Entries in a simple archive have is_loss_tolerant = false
    let entries = v["entries"].as_array().expect("entries");
    assert!(!entries.is_empty());
    let entry = &entries[0];
    assert!(
        entry.get("is_loss_tolerant").is_some(),
        "is_loss_tolerant missing"
    );
    assert_eq!(entry["is_loss_tolerant"], false);
    assert!(entry.get("is_fragment").is_some(), "is_fragment missing");
    assert_eq!(entry["is_fragment"], false);
}

#[test]
fn inspect_json_reports_recovery_metadata() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");

    // global_ec key must be present
    assert!(v.get("global_ec").is_some(), "global_ec missing");
    assert_eq!(v["global_ec"], false);
    // repair_possible must be present
    assert!(
        v.get("repair_possible").is_some(),
        "repair_possible missing"
    );
    assert_eq!(v["repair_possible"], false);
    // recovery_tlvs array must be present (empty for simple archives)
    assert!(v.get("recovery_tlvs").is_some(), "recovery_tlvs missing");
    let tlvs = v["recovery_tlvs"].as_array().expect("recovery_tlvs array");
    assert!(tlvs.is_empty());
}

#[test]
fn inspect_json_distinguishes_file_level_fec_from_archive_level_tlvs() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("d.bin");
    fs::write(&input, b"fec test data").expect("write");
    let archive = td.path().join("fec.sar");

    // Create with file-level Selective FEC
    sar()
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "xor",
            "--indexed",
        ])
        .assert()
        .success();

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");

    // selective_fec = true for file-level FEC
    assert_eq!(v["selective_fec"], true, "selective_fec must be true");
    // global_ec = false (no archive-level TLV)
    assert_eq!(v["global_ec"], false, "global_ec must be false");
    // Entry must have file-level fec field
    let entries = v["entries"].as_array().expect("entries");
    assert!(!entries[0]["fec"].is_null(), "entry fec must be present");
    // recovery_tlvs should be empty (archive-level vs file-level distinction)
    let tlvs = v["recovery_tlvs"].as_array().expect("recovery_tlvs");
    assert!(
        tlvs.is_empty(),
        "recovery_tlvs should be empty for Selective FEC only archives"
    );
}

#[test]
fn inspect_json_entries_have_sparse_extent_count() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");

    let entries = v["entries"].as_array().expect("entries");
    assert!(!entries.is_empty());
    // sparse_extent_count must be present even for non-sparse entries (= 0)
    assert!(
        entries[0].get("sparse_extent_count").is_some(),
        "sparse_extent_count missing from entry JSON"
    );
    assert_eq!(entries[0]["sparse_extent_count"], 0);
}

// ---------------------------------------------------------------------------
// Verify --recovery
// ---------------------------------------------------------------------------

#[test]
fn verify_recovery_reports_valid_metadata() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);

    sar()
        .args(["verify", archive.to_str().expect("str"), "--recovery"])
        .assert()
        .success()
        .stdout(contains("verify: valid=true"))
        .stdout(contains("recovery verify:"));
}

#[test]
fn verify_recovery_detects_malformed_recovery_metadata() {
    // A NO_INDEX archive with --recovery should succeed (no recovery TLVs to
    // validate) but report repair_possible=false.
    let td = tempdir().expect("tmp");
    let input = td.path().join("f.txt");
    fs::write(&input, b"data").expect("write");
    let archive = td.path().join("no_index.sar");

    sar()
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
        ])
        .assert()
        .success();

    sar()
        .args(["verify", archive.to_str().expect("str"), "--recovery"])
        .assert()
        .success()
        .stdout(contains("repair_possible=false"));
}

// ---------------------------------------------------------------------------
// Repair command error paths
// ---------------------------------------------------------------------------

#[test]
fn repair_fec_without_fec_flag_fails_clearly() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);
    let output = td.path().join("repaired.sar");

    // --fec not provided → error
    sar()
        .args([
            "repair",
            archive.to_str().expect("str"),
            output.to_str().expect("str"),
        ])
        .assert()
        .failure()
        .stderr(contains("repair requires --fec"));
}

#[test]
fn repair_fec_without_erasures_fails_clearly() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);
    let output = td.path().join("repaired.sar");

    // --fec provided but --erasures not → error
    sar()
        .args([
            "repair",
            archive.to_str().expect("str"),
            output.to_str().expect("str"),
            "--fec",
        ])
        .assert()
        .failure()
        .stderr(contains("repair requires --erasures"));
}

#[test]
fn repair_fec_invalid_erasure_json_fails_clearly() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);
    let output = td.path().join("repaired.sar");
    let erasures_file = td.path().join("erasures.json");
    fs::write(&erasures_file, b"not valid json {{ ").expect("write");

    sar()
        .args([
            "repair",
            archive.to_str().expect("str"),
            output.to_str().expect("str"),
            "--fec",
            "--erasures",
            erasures_file.to_str().expect("str"),
        ])
        .assert()
        .failure()
        .stderr(contains("failed to parse erasures JSON"));
}

#[test]
fn repair_fec_failure_no_final_output() {
    // Archive without HAS_GLOBAL_EC → repair should fail and NOT create the
    // output file.
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);
    let output = td.path().join("repaired.sar");
    let erasures_file = td.path().join("erasures.json");
    fs::write(&erasures_file, br#"{"entries":[],"archive_ranges":[]}"#).expect("write");

    sar()
        .args([
            "repair",
            archive.to_str().expect("str"),
            output.to_str().expect("str"),
            "--fec",
            "--erasures",
            erasures_file.to_str().expect("str"),
        ])
        .assert()
        .failure();

    // Output file must NOT have been created
    assert!(
        !output.exists(),
        "output file must not be created on repair failure"
    );
}

// ---------------------------------------------------------------------------
// Extract --allow-lossy
// ---------------------------------------------------------------------------

#[test]
fn extract_allow_lossy_flag_is_accepted() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);
    let out_dir = td.path().join("extracted");

    // --allow-lossy on a normal archive should succeed without warnings
    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--allow-lossy",
        ])
        .assert()
        .success();

    // Content must be correct
    let content = fs::read(out_dir.join("data.txt")).expect("file");
    assert_eq!(content, b"test content for m8");
}

#[test]
fn extract_without_allow_lossy_succeeds_for_normal_entries() {
    let td = tempdir().expect("tmp");
    let archive = create_simple_archive(&td);
    let out_dir = td.path().join("extracted_normal");

    // Normal archive without LOSS_TOLERANT entries → no warning, no error
    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();
}
