// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// CLI CDC tests: `inspect --json` includes CDC metadata,
/// `verify --cdc` passes/fails as expected.
use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use sar_core::{
    GlobalFlags, ResourceLimits,
    format::{
        CentralDictionary, Footer, GlobalHeader, LocalFileHeader, write_central_dictionary,
        write_footer, write_global_header, write_lfh,
    },
    make_cdc_ext_provider_tlv,
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
        flags,
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

fn build_indexed_cdc_provider_archive_file(dir: &std::path::Path) -> std::path::PathBuf {
    let flags = GlobalFlags::OPT_PRESENT | GlobalFlags::CDC_SUPPORT;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");

    let lfh_offset = bytes.len() as u64;
    let lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), 5);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"hello");

    let cd_offset = bytes.len() as u64;
    let cd = CentralDictionary {
        version: 1,
        file_count: 1,
        global_crc32: None,
        metadata: vec![
            make_cdc_ext_provider_tlv(
                "sarp+https://chunks.example/v1",
                &ResourceLimits::unlimited(),
            )
            .expect("provider tlv"),
        ],
        offsets: vec![lfh_offset],
    };
    bytes.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
    bytes.extend_from_slice(&write_footer(Footer { cd_offset }));

    let path = dir.join("cdc_provider_test.sar");
    fs::write(&path, &bytes).expect("write archive");
    path
}

// ---------------------------------------------------------------------------
// inspect reports an inventory of validated CDC TLVs; verify enforces catalog
// selection and Partition_Index rules.
// ---------------------------------------------------------------------------

fn cdc_map_value(partition: u32) -> Vec<u8> {
    let mut v = vec![1u8, 0x30, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0];
    v.extend_from_slice(&[0xAB; 32]);
    v.extend_from_slice(&partition.to_le_bytes());
    v.extend_from_slice(&100u64.to_le_bytes());
    v.extend_from_slice(&5u32.to_le_bytes());
    v
}

fn build_indexed_archive_with_cdc_maps(
    dir: &std::path::Path,
    maps: Vec<Vec<u8>>,
) -> std::path::PathBuf {
    let flags = GlobalFlags::OPT_PRESENT | GlobalFlags::CDC_SUPPORT;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    let lfh_offset = bytes.len() as u64;
    let lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), 5);
    bytes.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    bytes.extend_from_slice(b"hello");
    let cd_offset = bytes.len() as u64;
    let cd = CentralDictionary {
        version: 1,
        file_count: 1,
        global_crc32: None,
        metadata: maps
            .into_iter()
            .map(|value| sar_core::tlv::Tlv {
                type_id: sar_core::TLV_CDC_MAP,
                value,
            })
            .collect(),
        offsets: vec![lfh_offset],
    };
    bytes.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
    bytes.extend_from_slice(&write_footer(Footer { cd_offset }));
    let path = dir.join("cdc_maps.sar");
    fs::write(&path, &bytes).expect("write archive");
    path
}

#[test]
fn inspect_validates_each_cdc_tlv_but_verify_enforces_catalog_rules() {
    let td = tempdir().expect("tmp");
    let cases = [
        vec![cdc_map_value(0), cdc_map_value(0)],
        vec![cdc_map_value(1)],
    ];
    for maps in cases {
        let archive = build_indexed_archive_with_cdc_maps(td.path(), maps);
        let path = archive.to_str().expect("str");
        Command::cargo_bin("sar-cli")
            .expect("bin")
            .args(["inspect", path, "--json"])
            .assert()
            .success();
        Command::cargo_bin("sar-cli")
            .expect("bin")
            .args(["verify", path, "--cdc"])
            .assert()
            .failure();
    }

    // A malformed individual map is rejected by inspect as well.
    let mut bad = cdc_map_value(0);
    bad[8] = 47;
    let archive = build_indexed_archive_with_cdc_maps(td.path(), vec![bad]);
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .failure();
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
    let archive = build_cdc_archive_file(td.path(), 0x00, b"literal data");

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
        &Value::Number(0.into()),
        "cdc_algo_id must be 0 (LITERAL_MODE)"
    );
}

// ---------------------------------------------------------------------------
#[test]
fn inspect_non_literal_cdc_is_structural_and_reports_algo() {
    let td = tempdir().expect("tmp");
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
    assert_eq!(v["entries"][0]["cdc_algo_id"], Value::Number(2.into()));
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

#[test]
fn verify_cdc_non_literal_recipe_is_structural_only() {
    let td = tempdir().expect("tmp");
    let archive = build_cdc_archive_file(td.path(), 0x02, b"valid cdc payload");

    // Structural verification never resolves chunks; extraction does.
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str"), "--cdc"])
        .assert()
        .success();
    let out = td.path().join("out");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out.to_str().expect("str"),
        ])
        .assert()
        .failure()
        .stderr(contains("recipe"));
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

#[test]
fn inspect_json_reports_cdc_ext_provider_metadata() {
    let td = tempdir().expect("tmp");
    let archive = build_indexed_cdc_provider_archive_file(td.path());

    let out = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&out).expect("json");
    let tlvs = v["cdc_metadata_tlvs"]
        .as_array()
        .expect("cdc metadata tlvs");
    assert_eq!(tlvs.len(), 1);
    assert_eq!(tlvs[0]["type_id"], "0x41");
    assert_eq!(tlvs[0]["kind"], "cdc_ext_provider");
    assert_eq!(tlvs[0]["uri"], "sarp+https://chunks.example/v1");
    assert_eq!(tlvs[0]["resolution"], "not_implemented");
}
