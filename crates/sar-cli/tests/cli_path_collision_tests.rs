// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::{fs, os::unix::fs::symlink, path::Path};

use assert_cmd::Command;
use predicates::str::contains;
use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};
use tempfile::{TempDir, tempdir};

fn write_archive(archive: &Path, entries: Vec<EntryInput>) {
    let mut file = fs::File::create(archive).expect("archive file");
    let mut writer =
        ArchiveWriter::new(&mut file, ArchiveWriterOptions::default()).expect("writer");
    for entry in entries {
        writer.add_entry(entry).expect("entry");
    }
    writer.finish().expect("finish");
}

fn extract(archive: &Path, out: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out.to_str().expect("str"),
        ])
        .assert()
}

/// `SAR_TEST_FS_PROBE_DIR` may name a directory on a case-insensitive or
/// Unicode-normalizing filesystem; otherwise the default temporary directory
/// is used and the filesystem-dependent cases skip when it does not fold.
fn probe_dir() -> TempDir {
    match std::env::var_os("SAR_TEST_FS_PROBE_DIR") {
        Some(base) => tempfile::tempdir_in(base).expect("probe dir"),
        None => tempdir().expect("probe dir"),
    }
}

fn names_alias(dir: &Path, created: &str, looked_up: &str) -> bool {
    fs::write(dir.join(created), b"").expect("probe");
    let aliased = fs::symlink_metadata(dir.join(looked_up)).is_ok();
    fs::remove_file(dir.join(created)).expect("cleanup");
    aliased
}

#[test]
fn distinct_paths_extract_successfully() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("a.sar");
    write_archive(
        &archive,
        vec![
            EntryInput::file("one.txt", b"1".to_vec()),
            EntryInput::file("two.txt", b"2".to_vec()),
            EntryInput::file("sub/one.txt", b"3".to_vec()),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("one.txt")).expect("read"), b"1");
    assert_eq!(fs::read(out.join("sub/one.txt")).expect("read"), b"3");
}

#[test]
fn repeated_identical_path_is_not_a_collision() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("a.sar");
    write_archive(
        &archive,
        vec![
            EntryInput::file("d/dup", b"first".to_vec()),
            EntryInput::file("d/dup", b"second".to_vec()),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("d/dup")).expect("read"), b"second");
}

#[test]
fn existing_destination_object_alone_is_not_a_collision() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("a.sar");
    write_archive(
        &archive,
        vec![
            EntryInput::file("exists.txt", b"new".to_vec()),
            EntryInput::file("dir/inner.txt", b"x".to_vec()),
        ],
    );
    let out = td.path().join("out");
    fs::create_dir_all(out.join("dir")).expect("dir");
    fs::write(out.join("exists.txt"), b"old").expect("old");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("exists.txt")).expect("read"), b"new");
}

#[test]
fn symlink_traversal_is_still_path_escape_not_collision() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("a.sar");
    write_archive(&archive, vec![EntryInput::file("d/f", b"x".to_vec())]);
    let (out, outside) = (td.path().join("out"), td.path().join("outside"));
    fs::create_dir_all(&out).expect("out");
    fs::create_dir_all(&outside).expect("outside");
    symlink(&outside, out.join("d")).expect("symlink");
    extract(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_PATH_ESCAPE"));
    assert!(fs::read_dir(&outside).expect("read").next().is_none());
}

#[test]
fn case_insensitive_destination_reports_path_collision() {
    let probe = probe_dir();
    if !names_alias(probe.path(), "Probe-Case", "probe-case") {
        eprintln!("SKIPPED: destination filesystem is case-sensitive");
        return;
    }
    let source = tempdir().expect("tmp");
    let archive = source.path().join("a.sar");
    write_archive(
        &archive,
        vec![
            EntryInput::file("Dir/a.txt", b"first".to_vec()),
            EntryInput::file("dir/b.txt", b"second".to_vec()),
        ],
    );
    let out = probe.path().join("out");
    extract(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_PATH_COLLISION"));
    assert_eq!(fs::read(out.join("Dir/a.txt")).expect("read"), b"first");
    assert!(!out.join("Dir/b.txt").exists());
}

#[test]
fn normalizing_destination_reports_path_collision() {
    let probe = probe_dir();
    if !names_alias(probe.path(), "Probe-\u{e9}", "Probe-e\u{301}") {
        eprintln!("SKIPPED: destination filesystem does not normalize Unicode names");
        return;
    }
    let source = tempdir().expect("tmp");
    let archive = source.path().join("a.sar");
    write_archive(
        &archive,
        vec![
            EntryInput::file("caf\u{e9}.txt", b"nfc".to_vec()),
            EntryInput::file("cafe\u{301}.txt", b"nfd".to_vec()),
        ],
    );
    let out = probe.path().join("out");
    extract(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_PATH_COLLISION"));
}
