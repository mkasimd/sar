use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

#[test]
fn shorthand_flags_work() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("a.txt");
    fs::write(&input, b"abc").expect("write");
    let archive = td.path().join("a.sar");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "-c",
            input.to_str().expect("str"),
            "-f",
            archive.to_str().expect("str"),
        ])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["-t", "-f", archive.to_str().expect("str")])
        .assert()
        .success();

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["-v", "-f", archive.to_str().expect("str")])
        .assert()
        .success();

    let out_dir = td.path().join("out");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "-x",
            "-f",
            archive.to_str().expect("str"),
            "-C",
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(out_dir.join("a.txt")).expect("read"), b"abc");
}

#[test]
fn ambiguous_shorthand_combinations_fail_clearly() {
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["-c", "-x", "input", "-f", "out.sar"])
        .assert()
        .failure()
        .stderr(contains("ambiguous shorthand"));
}
