// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! CLI integration tests for FEC (Milestones 6–7).
//!
//! Tests cover:
//! * `sar create --fec xor` and `--fec rs` produce valid archives.
//! * `sar inspect --json` reports `selective_fec=true` and per-entry FEC summaries.
//! * `sar inspect` (plain-text) reports `selective_fec=true`.
//! * `sar verify` succeeds on FEC archives.
//! * `sar list` works on FEC archives.
//! * `sar extract` successfully recovers payloads from FEC archives.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Create + inspect JSON — XOR FEC
// ---------------------------------------------------------------------------

#[test]
fn create_xor_fec_inspect_json_shows_fec_metadata() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("data.bin");
    fs::write(&input, b"hello FEC world").expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "xor",
        ])
        .assert()
        .success();

    let out = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["selective_fec"], true, "selective_fec flag must be set");
    assert_eq!(v["entry_count"], 1);

    let entries = v["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1);
    let fec = &entries[0]["fec"];
    assert!(!fec.is_null(), "entry must have fec metadata");
    assert_eq!(fec["algorithm"], "xor", "algorithm must be xor");
}

// ---------------------------------------------------------------------------
// Create + inspect JSON — RS FEC
// ---------------------------------------------------------------------------

#[test]
fn create_rs_fec_inspect_json_shows_fec_metadata() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("payload.bin");
    fs::write(&input, vec![0xABu8; 1024]).expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "rs",
        ])
        .assert()
        .success();

    let out = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["selective_fec"], true);

    let entries = v["entries"].as_array().expect("entries");
    let fec = &entries[0]["fec"];
    assert!(!fec.is_null(), "fec metadata must be present");
    assert_eq!(fec["algorithm"], "reed-solomon");
}

// ---------------------------------------------------------------------------
// Create + inspect plain-text — selective_fec flag visible
// ---------------------------------------------------------------------------

#[test]
fn create_xor_fec_inspect_plaintext_shows_selective_fec() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("file.txt");
    fs::write(&input, b"content").expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "xor",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("selective_fec=true"));
}

// ---------------------------------------------------------------------------
// Create + inspect plain-text — per-entry FEC line printed
// ---------------------------------------------------------------------------

#[test]
fn inspect_plaintext_prints_per_entry_fec_line() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("data.bin");
    fs::write(&input, vec![1u8; 512]).expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "xor",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("fec="));
}

// ---------------------------------------------------------------------------
// FEC archive verify passes
// ---------------------------------------------------------------------------

#[test]
fn verify_fec_archive_passes() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("a.bin");
    fs::write(&input, b"verify me").expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
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

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("valid=true"));
}

// ---------------------------------------------------------------------------
// FEC archive list works
// ---------------------------------------------------------------------------

#[test]
fn list_fec_archive_shows_entry_name() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("readme.txt");
    fs::write(&input, b"hello").expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "rs",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["list", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("readme.txt"));
}

// ---------------------------------------------------------------------------
// FEC archive extract recovers correct bytes
// ---------------------------------------------------------------------------

#[test]
fn extract_fec_archive_recovers_payload() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("input.txt");
    let content = b"round-trip through FEC";
    fs::write(&input, content).expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "xor",
        ])
        .assert()
        .success();

    let extract_dir = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("input.txt")).expect("read"),
        content
    );
}

// ---------------------------------------------------------------------------
// No FEC — selective_fec=false in inspect JSON
// ---------------------------------------------------------------------------

#[test]
fn no_fec_inspect_json_selective_fec_false() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("plain.bin");
    fs::write(&input, b"no fec here").expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
        ])
        .assert()
        .success();

    let out = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["selective_fec"], false);
    let entries = v["entries"].as_array().expect("entries");
    // fec field is skipped when None
    assert!(
        entries[0].get("fec").is_none(),
        "fec must be absent when disabled"
    );
}

// ---------------------------------------------------------------------------
// FEC + compression roundtrip via CLI
// ---------------------------------------------------------------------------

#[test]
fn create_xor_fec_with_zstd_compression_roundtrip() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("data.bin");
    fs::write(&input, vec![0xFFu8; 2048]).expect("write");
    let archive = td.path().join("out.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--fec",
            "xor",
            "-Z",
        ])
        .assert()
        .success();

    let extract_dir = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("data.bin")).expect("read"),
        vec![0xFFu8; 2048]
    );
}
