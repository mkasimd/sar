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
