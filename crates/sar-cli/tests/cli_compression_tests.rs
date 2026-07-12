// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn create_extract_verify_with_deflate_and_long_option() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("in.txt");
    fs::write(&input, b"deflate-data".repeat(64)).expect("write");
    let archive = td.path().join("out-deflate.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--compression",
            "deflate",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["list", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("DEFLATE"));

    let out_dir = td.path().join("out");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(out_dir.join("in.txt")).expect("read"),
        b"deflate-data".repeat(64)
    );

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str")])
        .assert()
        .success();
}

#[test]
fn create_with_zstd_shortcut_and_level_and_inspect_json_metadata() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("in.txt");
    fs::write(&input, b"zstd-data".repeat(64)).expect("write");
    let archive = td.path().join("out-zstd.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "-Z",
            "-9",
            "--indexed",
        ])
        .assert()
        .success();

    let inspect = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&inspect).expect("json");
    assert_eq!(v["entries"][0]["compression_algorithm"], "ZSTD");
    assert_eq!(v["entries"][0]["is_compressed"], true);
}

#[test]
fn create_with_store_shortcut_and_store_long_option() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("in.txt");
    fs::write(&input, b"store-data").expect("write");
    let archive = td.path().join("out-store.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--compression",
            "store",
            "-S",
            "--no-index",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["list", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("STORE"));
}

#[test]
fn create_with_deflate_shortcut() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("in.txt");
    fs::write(&input, b"shortcut-data".repeat(8)).expect("write");
    let archive = td.path().join("out-shortcut.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "-z",
        ])
        .assert()
        .success();
}
