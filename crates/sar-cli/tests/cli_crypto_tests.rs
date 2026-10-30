// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

#[test]
fn encrypted_create_extract_round_trip() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("secret.txt");
    fs::write(&input, b"super-secret".repeat(32)).expect("write");
    let archive = td.path().join("secret.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--encrypt",
            "aes256-gcm",
            "--password",
            "hunter2",
        ])
        .assert()
        .success();

    let out_dir = td.path().join("out");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--password",
            "hunter2",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("secret.txt")).expect("read"),
        b"super-secret".repeat(32)
    );
}

#[test]
fn wrong_password_fails() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("secret.txt");
    fs::write(&input, b"top-secret").expect("write");
    let archive = td.path().join("secret.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--encrypt",
            "xchacha20-poly",
            "--password",
            "correct-horse",
        ])
        .assert()
        .success();

    let out_dir = td.path().join("out");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--password",
            "wrong-battery",
        ])
        .assert()
        .failure()
        .stderr(contains("SAR_ERR_AUTH_FAILED"));
}

#[test]
fn password_help_documents_precedence_and_argv_exposure() {
    for command in ["create", "extract", "verify"] {
        Command::cargo_bin("sar-cli")
            .expect("bin")
            .args([command, "--help"])
            .assert()
            .success()
            .stdout(contains("Insecure"))
            .stdout(contains("process listings"))
            .stdout(contains("--password, then the SAR_PASSWORD"))
            .stdout(contains("interactive prompt"));
    }
}

#[test]
fn password_source_precedence_is_argv_then_environment() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("secret.txt");
    fs::write(&input, b"top-secret").expect("write");
    let archive = td.path().join("secret.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .env("SAR_PASSWORD", "from-env")
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--encrypt",
            "aes256-gcm",
        ])
        .assert()
        .success();

    // Existing precedence: SAR_PASSWORD is honoured when --password is absent.
    let out_dir = td.path().join("out");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .env("SAR_PASSWORD", "from-env")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    // --password takes precedence over SAR_PASSWORD.
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .env("SAR_PASSWORD", "wrong-env-value")
        .args([
            "extract",
            archive.to_str().expect("str"),
            td.path().join("out2").to_str().expect("str"),
            "--password",
            "from-env",
        ])
        .assert()
        .success();
}
