use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use assert_cmd::Command;
use filetime::{FileTime, set_file_times};
use predicates::str::contains;
use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::EntryKind;
use serde_json::Value;
use tempfile::tempdir;

fn write_archive(
    archive: &Path,
    options: ArchiveWriterOptions,
    entries: Vec<EntryInput>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::File::create(archive)?;
    let mut writer = ArchiveWriter::new(&mut file, options)?;
    for entry in entries {
        writer.add_entry(entry)?;
    }
    writer.finish()?;
    Ok(())
}

fn inspect_json(archive: &Path) -> Value {
    let output = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("json")
}

#[cfg(unix)]
#[test]
fn create_inspect_json_reports_preserved_permissions_owner_and_times() {
    let td = tempdir().expect("tmp");
    let input_dir = td.path().join("in");
    fs::create_dir_all(&input_dir).expect("mkdir");
    let file_path = input_dir.join("script.sh");
    fs::write(&file_path, b"#!/bin/sh\necho hi\n").expect("write");
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o754)).expect("chmod");
    set_file_times(
        &file_path,
        FileTime::from_unix_time(1_700_000_000, 0),
        FileTime::from_unix_time(1_700_000_100, 0),
    )
    .expect("set times");

    let expected_meta = fs::metadata(&file_path).expect("metadata");
    let archive = td.path().join("meta.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
            "--preserve-permissions",
            "--preserve-owner",
            "--preserve-times",
        ])
        .assert()
        .success();

    let json = inspect_json(&archive);
    let entry = json["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["name"] == "script.sh")
        .expect("script entry");

    assert_eq!(entry["kind"], "regular_file");
    let mode = entry["permissions"]["mode"].as_u64().expect("mode");
    assert_eq!(mode & 0o777, 0o754);
    assert_eq!(
        entry["uid"].as_u64().expect("uid"),
        u64::from(expected_meta.uid())
    );
    assert_eq!(
        entry["gid"].as_u64().expect("gid"),
        u64::from(expected_meta.gid())
    );
    assert_eq!(
        entry["timestamps"]["atime"].as_u64().expect("atime"),
        1_700_000_000
    );
    assert_eq!(
        entry["timestamps"]["mtime"].as_u64().expect("mtime"),
        1_700_000_100
    );
}

#[cfg(unix)]
#[test]
fn create_archives_directories_and_extract_applies_directory_permissions() {
    let td = tempdir().expect("tmp");
    let input_dir = td.path().join("in");
    let nested_dir = input_dir.join("sub");
    fs::create_dir_all(&nested_dir).expect("mkdir");
    fs::set_permissions(&nested_dir, fs::Permissions::from_mode(0o755)).expect("chmod");
    fs::write(nested_dir.join("file.txt"), b"payload").expect("write");

    let archive = td.path().join("dirs.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
            "--preserve-permissions",
        ])
        .assert()
        .success();

    let json = inspect_json(&archive);
    let dir_entry = json["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["name"] == "sub")
        .expect("dir entry");
    assert_eq!(dir_entry["kind"], "directory");
    assert_eq!(dir_entry["payload_size"], 0);
    assert_eq!(dir_entry["uncompressed_size"], 0);

    let extract_dir = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
            "--preserve-permissions",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("sub").join("file.txt")).expect("read"),
        b"payload"
    );
    let extracted_mode = fs::metadata(extract_dir.join("sub"))
        .expect("dir metadata")
        .permissions()
        .mode();
    assert_eq!(extracted_mode & 0o777, 0o755);
}

#[cfg(unix)]
#[test]
fn archive_and_extract_symlink_policy_is_safe() {
    let td = tempdir().expect("tmp");
    let input_dir = td.path().join("in");
    fs::create_dir_all(&input_dir).expect("mkdir");
    fs::write(input_dir.join("target.txt"), b"target").expect("write");
    symlink("target.txt", input_dir.join("link.txt")).expect("symlink");

    let archive = td.path().join("links.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
            "--symlinks",
            "archive",
        ])
        .assert()
        .success();

    let json = inspect_json(&archive);
    let link_entry = json["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["name"] == "link.txt")
        .expect("symlink entry");
    assert_eq!(link_entry["kind"], "symlink");
    assert_eq!(link_entry["symlink_target"], "target.txt");

    let rejected_dir = td.path().join("reject");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            rejected_dir.to_str().expect("str"),
        ])
        .assert()
        .failure()
        .stderr(contains("--allow-symlinks"));

    let extract_dir = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
            "--allow-symlinks",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_link(extract_dir.join("link.txt")).expect("readlink"),
        Path::new("target.txt")
    );
}

#[cfg(unix)]
#[test]
fn create_skip_and_follow_symlink_policies_behave_as_expected() {
    let td = tempdir().expect("tmp");
    let input_dir = td.path().join("in");
    fs::create_dir_all(&input_dir).expect("mkdir");
    fs::write(input_dir.join("target.txt"), b"followed").expect("write");
    symlink("target.txt", input_dir.join("link.txt")).expect("symlink");

    let skipped_archive = td.path().join("skip.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            skipped_archive.to_str().expect("str"),
            "--no-index",
        ])
        .assert()
        .success();
    let skipped_json = inspect_json(&skipped_archive);
    assert!(
        skipped_json["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .all(|entry| entry["name"] != "link.txt"),
        "default symlink policy should skip symlink entries"
    );

    let followed_archive = td.path().join("follow.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            followed_archive.to_str().expect("str"),
            "--no-index",
            "--symlinks",
            "follow",
        ])
        .assert()
        .success();

    let followed_json = inspect_json(&followed_archive);
    let followed_entry = followed_json["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["name"] == "link.txt")
        .expect("followed entry");
    assert_eq!(followed_entry["kind"], "regular_file");

    let extract_dir = td.path().join("follow-extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            followed_archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(extract_dir.join("link.txt")).expect("read"),
        b"followed"
    );
}

#[test]
fn hostile_paths_are_rejected() {
    let cases = [
        ("../escape.txt", "parent directory traversal"),
        ("/absolute.txt", "absolute paths"),
        ("C:/drive.txt", "Windows drive-prefixed"),
        ("//server/share.txt", "UNC"),
    ];

    for (name, expected) in cases {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("hostile.sar");
        write_archive(
            &archive,
            ArchiveWriterOptions {
                no_index: true,
                ..Default::default()
            },
            vec![EntryInput::file(name, b"bad".to_vec())],
        )
        .expect("archive");

        let extract_dir = td.path().join("extract");
        Command::cargo_bin("sar-cli")
            .expect("bin")
            .args([
                "extract",
                archive.to_str().expect("str"),
                extract_dir.to_str().expect("str"),
            ])
            .assert()
            .failure()
            .stderr(contains(expected));
    }
}

#[cfg(unix)]
#[test]
fn unsafe_symlink_targets_are_rejected() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("unsafe-link.sar");
    write_archive(
        &archive,
        ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            ..Default::default()
        },
        vec![EntryInput {
            name: "link".into(),
            payload: b"../escape".to_vec(),
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        }],
    )
    .expect("archive");

    let extract_dir = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
            "--allow-symlinks",
        ])
        .assert()
        .failure()
        .stderr(contains("parent directory traversal"));
}

#[cfg(unix)]
#[test]
fn preserve_permissions_strips_setuid_bits_by_default() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("suid.sar");
    write_archive(
        &archive,
        ArchiveWriterOptions {
            no_index: true,
            with_permissions: true,
            ..Default::default()
        },
        vec![EntryInput {
            name: "tool.sh".into(),
            payload: b"echo secure\n".to_vec(),
            permissions: Some(0o4755),
            ..Default::default()
        }],
    )
    .expect("archive");

    let extract_dir = td.path().join("extract");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
            "--preserve-permissions",
        ])
        .assert()
        .success();

    let mode = fs::metadata(extract_dir.join("tool.sh"))
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o755);
}
