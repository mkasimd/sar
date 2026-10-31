// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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

/// Encodes a relative path as separate LFH Path String and Name String fields
/// (specification Section 6.1.5).
fn with_split_path(mut entry: EntryInput) -> EntryInput {
    if let Some((path, name)) = entry.name.rsplit_once('/') {
        entry.path = Some(path.to_string());
        entry.name = name.to_string();
    }
    entry
}

fn write_archive(
    archive: &Path,
    options: ArchiveWriterOptions,
    entries: Vec<EntryInput>,
) -> Result<(), Box<dyn std::error::Error>> {
    let options = ArchiveWriterOptions {
        with_path: true,
        ..options
    };
    let mut file = fs::File::create(archive)?;
    let mut writer = ArchiveWriter::new(&mut file, options)?;
    for entry in entries {
        writer.add_entry(with_split_path(entry))?;
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
        ("/abs/absolute.txt", "absolute paths"),
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
            .stderr(contains(expected))
            .stderr(contains("SAR_ERR_PATH_ESCAPE"));
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
        .stderr(contains("symlink target escapes"))
        .stderr(contains("SAR_ERR_PATH_ESCAPE"));
    assert!(!extract_dir.join("link").exists());
    assert!(fs::symlink_metadata(extract_dir.join("link")).is_err());
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

#[cfg(unix)]
#[test]
fn extraction_rejects_existing_symlink_parent_component() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("safe.sar");
    write_archive(
        &archive,
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        vec![EntryInput::file("safe/file.txt", b"payload".to_vec())],
    )
    .expect("archive");

    let outside = td.path().join("outside");
    fs::create_dir_all(&outside).expect("mkdir outside");
    let extract_dir = td.path().join("extract");
    fs::create_dir_all(&extract_dir).expect("mkdir extract");
    symlink(&outside, extract_dir.join("safe")).expect("symlink parent");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            extract_dir.to_str().expect("str"),
        ])
        .assert()
        .failure()
        .stderr(contains("existing symlink"))
        .stderr(contains("SAR_ERR_PATH_ESCAPE"));
    assert!(fs::read_dir(&outside).expect("outside").next().is_none());
}

#[cfg(unix)]
#[test]
fn extraction_into_symlinked_root_resolves_it_once_and_leaves_no_staging_files() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("a.sar");
    write_archive(
        &archive,
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        vec![EntryInput::file("d/file.txt", b"payload".to_vec())],
    )
    .expect("archive");
    let real = td.path().join("real");
    fs::create_dir_all(&real).expect("mkdir");
    let link = td.path().join("link");
    symlink(&real, &link).expect("symlink root");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            link.to_str().expect("str"),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(real.join("d/file.txt")).expect("read"), b"payload");
    let leftovers = fs::read_dir(real.join("d"))
        .expect("readdir")
        .filter(|entry| {
            entry
                .as_ref()
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".sar-tmp-")
        })
        .count();
    assert_eq!(leftovers, 0);
}

#[cfg(unix)]
#[test]
fn extraction_supports_maximum_length_basenames() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("long.sar");
    let names = ["a".repeat(250), "b".repeat(255)];
    write_archive(
        &archive,
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        names
            .iter()
            .map(|name| EntryInput::file(name, b"payload".to_vec()))
            .collect(),
    )
    .expect("archive");
    let out = td.path().join("out");

    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out.to_str().expect("str"),
        ])
        .assert()
        .success();

    for name in &names {
        assert_eq!(fs::read(out.join(name)).expect("read"), b"payload");
    }
    assert_eq!(fs::read_dir(&out).expect("readdir").count(), 2);
}

#[cfg(unix)]
#[test]
fn create_follow_symlink_rejects_recursive_directory_cycle() {
    let td = tempdir().expect("tmp");
    let input_dir = td.path().join("in");
    let nested = input_dir.join("nested");
    fs::create_dir_all(&nested).expect("mkdir");
    fs::write(input_dir.join("file.txt"), b"data").expect("write");
    symlink("..", nested.join("loop")).expect("symlink loop");

    let archive = td.path().join("cycle.sar");
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "create",
            input_dir.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--no-index",
            "--symlinks",
            "follow",
        ])
        .assert()
        .failure()
        .stderr(contains("recursive symlink directory cycle"));
}

#[cfg(unix)]
fn symlink_archive(dir: &Path, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
    let archive = dir.join("links.sar");
    write_archive(
        &archive,
        ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            ..Default::default()
        },
        entries
            .iter()
            .map(|(name, target)| EntryInput {
                name: (*name).into(),
                payload: target.to_vec(),
                kind: Some(EntryKind::Symlink),
                ..Default::default()
            })
            .collect(),
    )
    .expect("archive");
    archive
}

#[cfg(unix)]
fn extract_with_symlinks(archive: &Path, out: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out.to_str().expect("str"),
            "--allow-symlinks",
        ])
        .assert()
}

#[cfg(unix)]
#[test]
fn confined_symlink_targets_are_created_verbatim_including_dangling() {
    let td = tempdir().expect("tmp");
    let targets = [
        ("dot", "."),
        ("lex", "sub/../ok"),
        ("dangling", "does/not/exist"),
        ("nested/in/up", "../../top"),
        ("nested/in/root", "../.."),
    ];
    let entries: Vec<(&str, &[u8])> = targets
        .iter()
        .map(|(name, target)| (*name, target.as_bytes()))
        .collect();
    let archive = symlink_archive(td.path(), &entries);
    let out = td.path().join("out");

    extract_with_symlinks(&archive, &out).success();

    for (name, target) in targets {
        assert_eq!(
            fs::read_link(out.join(name)).expect("read_link"),
            Path::new(target),
            "{name}"
        );
    }
}

#[cfg(unix)]
#[test]
fn unsafe_symlink_targets_report_path_escape_and_create_nothing() {
    let cases: [(&str, &[u8]); 5] = [
        ("l", b".."),
        ("a/l", b"../../x"),
        ("l", b"/etc/passwd"),
        ("l", b"a\\b"),
        ("l", b"C:/x"),
    ];
    for (name, target) in cases {
        let td = tempdir().expect("tmp");
        let archive = symlink_archive(td.path(), &[(name, target)]);
        let out = td.path().join("out");
        extract_with_symlinks(&archive, &out)
            .failure()
            .stderr(contains("SAR_ERR_PATH_ESCAPE"));
        assert!(
            fs::symlink_metadata(out.join(name)).is_err(),
            "{name} -> {target:?} must not exist"
        );
    }
}

#[cfg(unix)]
#[test]
fn malformed_symlink_target_payloads_stay_malformed() {
    let td = tempdir().expect("tmp");
    let archive = symlink_archive(td.path(), &[("l", b"a\0b")]);
    let out = td.path().join("out");
    extract_with_symlinks(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_MALFORMED"));
    assert!(fs::symlink_metadata(out.join("l")).is_err());

    // Invalid UTF-8 is rejected as malformed at the library boundary.
    let err = write_archive(
        &td.path().join("bad.sar"),
        ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            ..Default::default()
        },
        vec![EntryInput {
            name: "l".into(),
            payload: vec![0xff, 0xfe],
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        }],
    )
    .expect_err("invalid UTF-8 target");
    assert!(
        matches!(
            err.downcast_ref::<sar_core::SarError>(),
            Some(sar_core::SarError::Malformed(_))
        ),
        "{err:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_entry_cannot_be_created_through_existing_symlink_directory() {
    let td = tempdir().expect("tmp");
    let archive = symlink_archive(td.path(), &[("d/l", b"x")]);
    let outside = td.path().join("outside");
    let out = td.path().join("out");
    fs::create_dir_all(&outside).expect("outside");
    fs::create_dir_all(&out).expect("out");
    symlink(&outside, out.join("d")).expect("symlink");

    extract_with_symlinks(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_PATH_ESCAPE"));
    assert!(fs::read_dir(&outside).expect("outside").next().is_none());
}
