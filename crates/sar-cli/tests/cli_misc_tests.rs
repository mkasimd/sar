use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use sar_core::{
    GlobalFlags,
    format::{GlobalHeader, KmsData, write_global_header},
};
use tempfile::tempdir;

#[test]
fn help_and_version_output() {
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("create"));

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .arg("version")
        .assert()
        .success()
        .stdout(contains("sar-spec v1.0"));

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .arg("-V")
        .assert()
        .success()
        .stdout(contains("cd-v1"));
}

#[test]
fn unsupported_features_fail_clearly() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("unsupported.sar");

    let header = GlobalHeader {
        version: 1,
        flags_bytes: (GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX)
            .bits()
            .to_le_bytes()
            .to_vec(),
        flags: GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX,
        partition_descriptor: None,
        kms: Some(KmsData {
            mode_id: 0x01,
            payload: vec![1, 2, 3],
        }),
    };
    let mut bytes = write_global_header(&header).expect("header");
    bytes.extend_from_slice(&46u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&[0u8; 24]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"x");
    bytes.extend_from_slice(b"a");
    fs::write(&archive, bytes).expect("write");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["list", archive.to_str().expect("str")])
        .assert()
        .failure()
        .stderr(contains("ErrUnsupported"));
}
