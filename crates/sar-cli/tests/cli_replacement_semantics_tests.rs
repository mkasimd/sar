// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Final logical state for repeated Full Logical Entry Paths and
//! directory/non-directory transitions (specification Sections 6.1.5, 22.4),
//! exercised archive to extraction through the CLI.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, symlink},
    path::Path,
};

use assert_cmd::Command;
use predicates::str::contains;
use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::EntryKind;
use tempfile::tempdir;

/// Encodes the relative path as separate Path String and Name String fields.
fn split(full: &str) -> (Option<String>, String) {
    match full.rsplit_once('/') {
        Some((path, name)) => (Some(path.to_string()), name.to_string()),
        None => (None, full.to_string()),
    }
}

fn file(full: &str, data: &[u8]) -> EntryInput {
    let (path, name) = split(full);
    EntryInput {
        name,
        path,
        payload: data.to_vec(),
        permissions: Some(0o644),
        ..Default::default()
    }
}

fn link(full: &str, target: &str) -> EntryInput {
    let (path, name) = split(full);
    EntryInput {
        name,
        path,
        payload: target.as_bytes().to_vec(),
        kind: Some(EntryKind::Symlink),
        permissions: Some(0o777),
        ..Default::default()
    }
}

fn dir(full: &str, mode: Option<u16>) -> EntryInput {
    let (path, name) = split(full);
    EntryInput {
        name,
        path,
        kind: Some(EntryKind::Directory),
        permissions: Some(mode.unwrap_or(0o700)),
        ..Default::default()
    }
}

fn archive(root: &Path, entries: Vec<EntryInput>) -> std::path::PathBuf {
    let archive = root.join("a.sar");
    let mut out = fs::File::create(&archive).expect("archive file");
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            with_permissions: true,
            with_path: true,
            ..Default::default()
        },
    )
    .expect("writer");
    for entry in entries {
        writer.add_entry(entry).expect("entry");
    }
    writer.finish().expect("finish");
    archive
}

fn extract(archive: &Path, out: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            archive.to_str().expect("str"),
            out.to_str().expect("str"),
            "--allow-symlinks",
            "--preserve-permissions",
        ])
        .assert()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn assert_no_staging_leftovers(out: &Path) {
    fn walk(dir: &Path) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            assert!(
                !entry.file_name().to_string_lossy().starts_with(".sar-tmp-"),
                "leftover {:?}",
                entry.path()
            );
            if entry.file_type().expect("type").is_dir() {
                walk(&entry.path());
            }
        }
    }
    walk(out);
}

fn run(entries: Vec<EntryInput>) -> (tempfile::TempDir, std::path::PathBuf) {
    let td = tempdir().expect("tmp");
    let a = archive(td.path(), entries);
    let out = td.path().join("out");
    extract(&a, &out).success();
    assert_no_staging_leftovers(&out);
    (td, out)
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).expect("stat").mode() & 0o7777
}

#[test]
fn file_replaced_by_file_symlink_and_back() {
    let (_td, out) = run(vec![
        file("f", b"one"),
        file("f", b"two"),
        file("s", b"x"),
        link("s", "target"),
        link("t", "target"),
        file("t", b"regular"),
    ]);
    assert_eq!(fs::read(out.join("f")).expect("read"), b"two");
    assert!(fs::symlink_metadata(out.join("s")).expect("s").is_symlink());
    assert_eq!(
        fs::read_link(out.join("s")).expect("link"),
        Path::new("target")
    );
    assert!(fs::symlink_metadata(out.join("t")).expect("t").is_file());
    assert_eq!(fs::read(out.join("t")).expect("read"), b"regular");
}

#[test]
fn file_or_symlink_replaced_by_explicit_directory() {
    let (_td, out) = run(vec![
        file("a", b"file"),
        dir("a", None),
        link("b", "target"),
        dir("b", None),
        file("b/child", b"c"),
    ]);
    assert!(out.join("a").is_dir());
    assert!(names(&out.join("a")).is_empty());
    assert!(out.join("b").is_dir());
    assert!(!fs::symlink_metadata(out.join("b")).expect("b").is_symlink());
    assert_eq!(names(&out.join("b")), vec!["child".to_string()]);
}

#[test]
fn file_or_symlink_replaced_by_implicit_ancestor_directory() {
    let (_td, out) = run(vec![
        file("a", b"file"),
        file("a/x", b"x"),
        link("b", "target"),
        file("b/deep/y", b"y"),
    ]);
    assert!(out.join("a").is_dir());
    assert_eq!(fs::read(out.join("a/x")).expect("read"), b"x");
    assert!(out.join("b/deep").is_dir());
    assert_eq!(fs::read(out.join("b/deep/y")).expect("read"), b"y");
    // Implicit directories carry no SAR metadata: private owner-only mode.
    assert_eq!(mode(&out.join("a")), 0o700);
    assert_eq!(mode(&out.join("b")), 0o700);
}

#[test]
fn directory_replaced_by_file_or_symlink_removes_earlier_descendants() {
    let (_td, out) = run(vec![
        dir("d", None),
        file("d/x", b"x"),
        file("d/sub/y", b"y"),
        link("d/sub/l", "t"),
        file("d", b"now a file"),
        file("e/x", b"x"),
        file("e/sub/y", b"y"),
        link("e", "sym"),
    ]);
    assert!(fs::symlink_metadata(out.join("d")).expect("d").is_file());
    assert_eq!(fs::read(out.join("d")).expect("read"), b"now a file");
    assert!(fs::symlink_metadata(out.join("e")).expect("e").is_symlink());
    assert_eq!(names(&out), vec!["d".to_string(), "e".to_string()]);
}

#[test]
fn directory_replaced_by_directory_keeps_compatible_descendants() {
    let (_td, out) = run(vec![
        dir("d", None),
        file("d/x", b"x"),
        dir("d", None),
        file("d/y", b"y"),
    ]);
    assert_eq!(
        names(&out.join("d")),
        vec!["x".to_string(), "y".to_string()]
    );
}

#[test]
fn later_descendants_recreate_a_removed_directory_as_implicit() {
    let (_td, out) = run(vec![
        dir("d", Some(0o755)),
        file("d/old", b"old"),
        file("d", b"file"),
        file("d/new", b"new"),
    ]);
    assert!(out.join("d").is_dir());
    assert_eq!(names(&out.join("d")), vec!["new".to_string()]);
    // The explicit 0o755 metadata of the removed directory must not apply.
    assert_eq!(mode(&out.join("d")), 0o700);
}

#[test]
fn last_explicit_directory_entry_determines_metadata() {
    let (_td, out) = run(vec![
        dir("d", Some(0o750)),
        file("d/x", b"x"),
        dir("d", Some(0o711)),
    ]);
    assert_eq!(mode(&out.join("d")), 0o711);
    assert_eq!(fs::read(out.join("d/x")).expect("read"), b"x");
}

#[test]
fn explicit_metadata_survives_removal_and_recreation_by_a_later_explicit_entry() {
    let (_td, out) = run(vec![
        dir("d", Some(0o755)),
        file("d", b"file"),
        dir("d", Some(0o750)),
    ]);
    assert_eq!(mode(&out.join("d")), 0o750);
}

#[test]
fn replacement_with_long_names_works() {
    let long = "n".repeat(200);
    let nested = format!("{long}/{long}");
    let (_td, out) = run(vec![
        file(&nested, b"x"),
        file(&long, b"replaced"),
        file(&format!("{long}/after"), b"y"),
    ]);
    assert!(out.join(&long).is_dir());
    assert_eq!(names(&out.join(&long)), vec!["after".to_string()]);
}

#[test]
fn preexisting_directory_content_is_never_deleted() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    fs::create_dir_all(out.join("d")).expect("d");
    fs::write(out.join("d/keep.txt"), b"keep").expect("keep");
    fs::create_dir_all(out.join("empty")).expect("empty");
    let a = archive(td.path(), vec![file("d", b"file")]);

    extract(&a, &out)
        .failure()
        .stderr(contains("SAR_ERR_ALREADY_EXISTS"));
    assert_eq!(fs::read(out.join("d/keep.txt")).expect("kept"), b"keep");

    // Even an empty pre-existing directory is not assumed to belong to the run.
    let a = archive(td.path(), vec![link("empty", "t")]);
    extract(&a, &out)
        .failure()
        .stderr(contains("SAR_ERR_ALREADY_EXISTS"));
    assert!(out.join("empty").is_dir());
}

#[test]
fn only_run_created_directories_below_a_preexisting_one_are_replaced() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    fs::create_dir_all(out.join("p")).expect("p");
    fs::write(out.join("p/keep.txt"), b"keep").expect("keep");
    let a = archive(
        td.path(),
        vec![
            file("p/q/x", b"x"),
            file("p/q/r/y", b"y"),
            file("p/q", b"f"),
        ],
    );
    extract(&a, &out).success();
    assert_eq!(fs::read(out.join("p/q")).expect("read"), b"f");
    assert_eq!(fs::read(out.join("p/keep.txt")).expect("kept"), b"keep");
    assert_no_staging_leftovers(&out);
}

#[test]
fn preexisting_file_cannot_become_an_ancestor_directory() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    fs::create_dir_all(&out).expect("out");
    fs::write(out.join("f"), b"precious").expect("f");
    let a = archive(td.path(), vec![file("f/x", b"x")]);
    extract(&a, &out)
        .failure()
        .stderr(contains("SAR_ERR_ALREADY_EXISTS"));
    assert_eq!(fs::read(out.join("f")).expect("kept"), b"precious");
}

#[test]
fn preexisting_symlink_ancestor_is_still_a_path_escape() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    let outside = td.path().join("outside");
    fs::create_dir_all(&out).expect("out");
    fs::create_dir_all(&outside).expect("outside");
    symlink(&outside, out.join("l")).expect("link");
    let a = archive(td.path(), vec![file("l/x", b"x")]);
    extract(&a, &out)
        .failure()
        .stderr(contains("SAR_ERR_PATH_ESCAPE"));
    assert!(names(&outside).is_empty());
}

#[test]
fn preexisting_file_is_still_replaced_by_a_file_entry() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    fs::create_dir_all(&out).expect("out");
    fs::write(out.join("f"), b"old").expect("f");
    let a = archive(td.path(), vec![file("f", b"new")]);
    extract(&a, &out).success();
    assert_eq!(fs::read(out.join("f")).expect("read"), b"new");
}
