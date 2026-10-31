// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Failure contract of ordinary extraction (M13b.3 Package E), through the CLI:
//! a failed extraction exits nonzero, keeps its specific status, reports that
//! partial destination changes may remain, and never touches objects it did
//! not create.

#![cfg(unix)]

use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::EntryKind;
use tempfile::tempdir;

fn file(name: &str, data: &[u8]) -> EntryInput {
    EntryInput {
        name: name.to_string(),
        payload: data.to_vec(),
        ..Default::default()
    }
}

fn link(name: &str, target: &str) -> EntryInput {
    EntryInput {
        name: name.to_string(),
        payload: target.as_bytes().to_vec(),
        kind: Some(EntryKind::Symlink),
        ..Default::default()
    }
}

fn nested(path: &str, name: &str, data: &[u8]) -> EntryInput {
    EntryInput {
        name: name.to_string(),
        path: Some(path.to_string()),
        payload: data.to_vec(),
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

/// Extraction without `--allow-symlinks`: a symlink Entry fails the run with
/// `SAR_ERR_UNSUPPORTED` at a deterministic point.
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

#[test]
fn failure_before_any_destination_change_reports_no_partial_state() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    fs::create_dir(&out).expect("out");
    let archive = archive(td.path(), vec![link("l", "t"), file("a", b"a")]);

    extract(&archive, &out)
        .failure()
        .code(1)
        .stderr(contains("SAR_ERR_UNSUPPORTED").and(contains("incomplete").not()));

    assert!(names(&out).is_empty());
}

#[test]
fn failure_after_a_published_entry_is_nonzero_and_reports_partial_changes() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    let archive = archive(td.path(), vec![file("a", b"kept"), link("l", "a")]);

    extract(&archive, &out).failure().code(1).stderr(
        contains("SAR_ERR_UNSUPPORTED")
            .and(contains("extraction is incomplete"))
            .and(contains("partial changes to the destination may remain"))
            .and(contains("kept").not()),
    );

    // Not all-or-nothing: the Entry published before the failure stays, and no
    // temporary object is left behind.
    assert_eq!(fs::read(out.join("a")).expect("a"), b"kept");
    assert_eq!(names(&out), vec!["a".to_string()]);
}

#[test]
fn a_newly_created_destination_counts_as_a_change() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("fresh");
    let archive = archive(td.path(), vec![link("l", "t")]);

    extract(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_UNSUPPORTED").and(contains("extraction is incomplete")));
    assert!(out.is_dir());
}

#[test]
fn failed_runs_never_remove_unrelated_preexisting_objects() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    fs::create_dir(&out).expect("out");
    fs::write(
        out.join(".sar-tmp-00000000000000000000000000000000"),
        b"mine",
    )
    .expect("file");
    let lookalike_dir = out.join(".sar-tmp-11111111111111111111111111111111");
    fs::create_dir(&lookalike_dir).expect("dir");
    fs::write(lookalike_dir.join("inner"), b"keep").expect("inner");
    fs::write(out.join("old"), b"old").expect("old");
    let archive = archive(td.path(), vec![file("a", b"a"), link("l", "a")]);

    extract(&archive, &out).failure();

    assert_eq!(
        fs::read(out.join(".sar-tmp-00000000000000000000000000000000")).expect("lookalike"),
        b"mine"
    );
    assert_eq!(
        fs::read(lookalike_dir.join("inner")).expect("inner"),
        b"keep"
    );
    assert_eq!(fs::read(out.join("old")).expect("old"), b"old");
}

#[test]
fn successful_extraction_leaves_no_run_owned_temporary_objects() {
    let td = tempdir().expect("tmp");
    let out = td.path().join("out");
    let archive = archive(
        td.path(),
        vec![
            nested("d/sub", "x", b"x"),
            file("d", b"file replaces the directory"),
            file("e", b"1"),
            file("e", b"2"),
        ],
    );

    extract(&archive, &out).success();

    assert_eq!(names(&out), vec!["d".to_string(), "e".to_string()]);
    assert_eq!(
        fs::read(out.join("d")).expect("d"),
        b"file replaces the directory"
    );
}
