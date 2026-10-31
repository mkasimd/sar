// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Targets without a secure extraction backend refuse extraction before any
//! filesystem mutation (specification Section 22.4) while read-only commands
//! keep working. Compiled on non-Unix targets only; its runtime behavior has
//! not been verified on a native non-Unix host.

#![cfg(not(unix))]

use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn create_archive(dir: &Path) -> std::path::PathBuf {
    let input = dir.join("in");
    fs::create_dir(&input).expect("input dir");
    fs::write(input.join("a.txt"), b"hello").expect("input file");
    let archive = dir.join("a.sar");
    Command::cargo_bin("sar-cli")
        .expect("binary")
        .arg("create")
        .arg(&input)
        .arg(&archive)
        .assert()
        .success();
    archive
}

#[test]
fn extraction_is_refused_without_touching_the_destination() {
    let dir = tempdir().expect("tempdir");
    let archive = create_archive(dir.path());
    let out = dir.path().join("out");

    Command::cargo_bin("sar-cli")
        .expect("binary")
        .arg("extract")
        .arg(&archive)
        .arg(&out)
        .assert()
        .failure()
        .stderr(contains("SAR_ERR_PATH_ESCAPE"));

    assert!(!out.exists());
}

#[test]
fn read_only_commands_still_work() {
    let dir = tempdir().expect("tempdir");
    let archive = create_archive(dir.path());

    Command::cargo_bin("sar-cli")
        .expect("binary")
        .arg("list")
        .arg(&archive)
        .assert()
        .success()
        .stdout(contains("a.txt"));
    Command::cargo_bin("sar-cli")
        .expect("binary")
        .arg("verify")
        .arg(&archive)
        .assert()
        .success();
}
