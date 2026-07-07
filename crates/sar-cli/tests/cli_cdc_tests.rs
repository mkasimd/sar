/// CLI CDC tests: `inspect --json` includes CDC metadata,
/// `verify --cdc` passes/fails as expected.
use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use sar_core::{
    GlobalFlags,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};
use serde_json::Value;
use tempfile::tempdir;

/// Build a minimal CDC archive (LITERAL_MODE) with a single entry,
/// writing it to a temp file and returning the path.
fn build_cdc_archive_file(
    dir: &std::path::Path,
    algo_id: u8,
    payload: &[u8],
) -> std::path::PathBuf {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::CDC_SUPPORT;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), payload.len() as u64);
    lfh.cdc_algo_id = Some(algo_id);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(payload);

    let path = dir.join("cdc_test.sar");
    fs::write(&path, &bytes).expect("write archive");
    path
}

// ---------------------------------------------------------------------------
// inspect --json reports cdc_support = true when CDC_SUPPORT flag is active
// ---------------------------------------------------------------------------

#[test]
fn inspect_json_reports_cdc_support_true() {
    let td = tempdir().expect("tmp");
    let archive = build_cdc_archive_file(td.path(), 0x00, b"hello cdc");

    let out = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["cdc_support"], true, "cdc_support must be true");
    assert_eq!(v["entry_count"], 1);
}

// ---------------------------------------------------------------------------
// inspect --json includes cdc_algo_id in entries when CDC_SUPPORT active
// ---------------------------------------------------------------------------

#[test]
fn inspect_json_entry_includes_cdc_algo_id() {
    let td = tempdir().expect("tmp");
    // FASTCDC algo id = 0x02
    let archive = build_cdc_archive_file(td.path(), 0x02, b"fastcdc data");

    let out = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&out).expect("json");
    let entries = v["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1);
    let algo_id = &entries[0]["cdc_algo_id"];
    assert_eq!(
        algo_id,
        &Value::Number(2.into()),
        "cdc_algo_id must be 2 (FASTCDC)"
    );
}

// ---------------------------------------------------------------------------
// inspect --json reports cdc_support = false when CDC_SUPPORT flag absent
// ---------------------------------------------------------------------------

#[test]
fn inspect_json_reports_cdc_support_false_when_absent() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("plain.txt");
    fs::write(&input, b"plain content").expect("write");
    let archive = td.path().join("plain.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
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
    assert_eq!(
        v["cdc_support"], false,
        "cdc_support must be false for plain archives"
    );
}

// ---------------------------------------------------------------------------
// verify --cdc succeeds on valid CDC archive
// ---------------------------------------------------------------------------

#[test]
fn verify_cdc_succeeds_on_valid_cdc_archive() {
    let td = tempdir().expect("tmp");
    let archive = build_cdc_archive_file(td.path(), 0x00, b"valid cdc payload");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str"), "--cdc"])
        .assert()
        .success()
        .stdout(contains("cdc_support=true"));
}

// ---------------------------------------------------------------------------
// verify --cdc on archive without CDC_SUPPORT reports cdc_support=false
// ---------------------------------------------------------------------------

#[test]
fn verify_cdc_reports_not_active_for_plain_archive() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("data.bin");
    fs::write(&input, b"no cdc").expect("write");
    let archive = td.path().join("plain.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str"), "--cdc"])
        .assert()
        .success()
        .stdout(contains("cdc_support=false"));
}

// ---------------------------------------------------------------------------
// verify --cdc on archive with reserved CDC algo ID fails clearly
// ---------------------------------------------------------------------------

#[test]
fn verify_cdc_fails_on_reserved_algo_id() {
    let td = tempdir().expect("tmp");
    // 0x10 is reserved
    let archive = build_cdc_archive_file(td.path(), 0x10, b"data");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str"), "--cdc"])
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// inspect text mode (no --json) reports cdc_support
// ---------------------------------------------------------------------------

#[test]
fn inspect_text_mode_reports_cdc_support() {
    let td = tempdir().expect("tmp");
    let archive = build_cdc_archive_file(td.path(), 0x00, b"text mode cdc");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("cdc_support=true"));
}

// ---------------------------------------------------------------------------
// inspect text mode reports cdc algo for entry
// ---------------------------------------------------------------------------

#[test]
fn inspect_text_mode_reports_entry_cdc_algo() {
    let td = tempdir().expect("tmp");
    let archive = build_cdc_archive_file(td.path(), 0x00, b"text cdc algo");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("cdc_algo_id=0x00"));
}
