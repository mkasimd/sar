// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn create_list_extract_verify_no_index_roundtrip() {
    let td = tempdir().expect("tmp");
    let input_dir = td.path().join("in");
    fs::create_dir_all(&input_dir).expect("mkdir");
    fs::write(input_dir.join("a.txt"), b"hello").expect("write");

    let archive = td.path().join("out-no-index.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["list", archive.to_str().expect("str")])
        .assert()
        .success();

    let extract = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract.to_str().expect("str"),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(extract.join("a.txt")).expect("read"), b"hello");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str")])
        .assert()
        .success();
}

#[test]
fn create_list_extract_verify_indexed_roundtrip() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("one.txt");
    fs::write(&input, b"indexed").expect("write");
    let archive = td.path().join("out-indexed.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--indexed",
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["verify", archive.to_str().expect("str")])
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
    assert_eq!(v["indexed"], true);
    assert_eq!(v["entry_count"], 1);
}
