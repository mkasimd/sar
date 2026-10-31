// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Extraction composes the Full Logical Entry Path from the separately
//! encoded LFH Path String and Name String (specification Section 6.1.5).

#![cfg(unix)]

use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::str::contains;
use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::{
    EntryKind, GlobalFlags,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};
use tempfile::tempdir;

fn entry(path: Option<&str>, name: &str, kind: EntryKind, payload: &[u8]) -> EntryInput {
    EntryInput {
        name: name.to_string(),
        path: path.map(str::to_string),
        payload: payload.to_vec(),
        kind: Some(kind),
        ..Default::default()
    }
}

fn file(path: Option<&str>, name: &str, data: &[u8]) -> EntryInput {
    entry(path, name, EntryKind::RegularFile, data)
}

fn write(root: &Path, entries: Vec<EntryInput>) -> std::path::PathBuf {
    let archive = root.join("a.sar");
    let mut out = fs::File::create(&archive).expect("archive file");
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            with_symlinks: true,
            ..Default::default()
        },
    )
    .expect("writer");
    for e in entries {
        writer.add_entry(e).expect("entry");
    }
    writer.finish().expect("finish");
    archive
}

fn extract(archive: &Path, out: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args([
            "extract",
            "--allow-symlinks",
            archive.to_str().expect("str"),
            out.to_str().expect("str"),
        ])
        .assert()
}

#[test]
fn path_and_name_compose_into_nested_files() {
    let td = tempdir().expect("tmp");
    let archive = write(
        td.path(),
        vec![
            file(None, "top.txt", b"t"),
            entry(None, "d", EntryKind::Directory, b""),
            entry(Some("d"), "e", EntryKind::Directory, b""),
            file(Some("d/e"), "leaf.txt", b"leaf"),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("top.txt")).expect("top"), b"t");
    assert_eq!(fs::read(out.join("d/e/leaf.txt")).expect("leaf"), b"leaf");
}

#[test]
fn symlink_is_materialized_at_the_composed_path() {
    let td = tempdir().expect("tmp");
    let archive = write(
        td.path(),
        vec![
            file(Some("d"), "real", b"r"),
            entry(Some("d"), "link", EntryKind::Symlink, b"real"),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(
        fs::read_link(out.join("d/link")).expect("link"),
        Path::new("real")
    );
    assert!(fs::symlink_metadata(out.join("link")).is_err());
}

#[test]
fn identical_names_under_distinct_paths_are_distinct_entries() {
    let td = tempdir().expect("tmp");
    let archive = write(
        td.path(),
        vec![
            file(Some("a"), "x", b"in-a"),
            file(Some("b"), "x", b"in-b"),
            file(None, "x", b"top"),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("a/x")).expect("a"), b"in-a");
    assert_eq!(fs::read(out.join("b/x")).expect("b"), b"in-b");
    assert_eq!(fs::read(out.join("x")).expect("x"), b"top");
}

#[test]
fn repeated_full_paths_replace_without_collision() {
    let td = tempdir().expect("tmp");
    let archive = write(
        td.path(),
        vec![
            file(Some("d"), "x", b"first"),
            file(Some("d"), "x", b"second"),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("d/x")).expect("x"), b"second");
}

#[test]
fn composed_paths_drive_directory_replacement() {
    let td = tempdir().expect("tmp");
    let archive = write(
        td.path(),
        vec![
            file(Some("d/sub"), "old", b"old"),
            file(Some("d"), "keep", b"keep"),
            file(None, "d", b"now-a-file"),
        ],
    );
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("d")).expect("d"), b"now-a-file");
}

#[test]
fn name_string_with_separator_is_rejected_not_normalized() {
    let td = tempdir().expect("tmp");
    let archive = write(td.path(), vec![file(None, "a/b.txt", b"x")]);
    let out = td.path().join("out");
    extract(&archive, &out)
        .failure()
        .stderr(contains("SAR_ERR_MALFORMED"))
        .stderr(contains("path separator"));
    assert!(!out.join("a").exists());
}

#[test]
fn invalid_path_string_components_are_rejected() {
    for (path, expected) in [
        ("..", "SAR_ERR_PATH_ESCAPE"),
        ("a/../b", "SAR_ERR_PATH_ESCAPE"),
        ("/abs", "SAR_ERR_PATH_ESCAPE"),
        ("a//b", "SAR_ERR_MALFORMED"),
        ("a/", "SAR_ERR_MALFORMED"),
        ("./a", "SAR_ERR_MALFORMED"),
    ] {
        let td = tempdir().expect("tmp");
        let archive = write(td.path(), vec![file(Some(path), "f.txt", b"x")]);
        let out = td.path().join("out");
        extract(&archive, &out).failure().stderr(contains(expected));
    }
}

const FRAG: u16 = 1 << 5;
const LAST: u16 = 1 << 6;

fn fragmented(frags: &[(u32, bool, &str, &str, &[u8])]) -> Vec<u8> {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX | GlobalFlags::HAS_PATH;
    let mut out = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    for (index, last, path, name, data) in frags {
        let mut l = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), data.len() as u64);
        l.path = path.as_bytes().to_vec();
        l.uncompressed_size = data.len() as u64;
        l.entry_mode = EntryMode::from_bits(FRAG | if *last { LAST } else { 0 });
        l.fragment_id = Some(1);
        l.fragment_index = Some(*index);
        out.extend_from_slice(&write_lfh(&flags, &l).expect("lfh"));
        out.extend_from_slice(data);
    }
    out
}

#[test]
fn fragmented_entry_uses_index0_path_and_name() {
    let td = tempdir().expect("tmp");
    let archive = td.path().join("a.sar");
    fs::write(
        &archive,
        fragmented(&[
            (0, false, "d/e", "f.bin", b"AAAA"),
            (1, true, "", "", b"BBBB"),
        ]),
    )
    .expect("write");
    let out = td.path().join("out");
    extract(&archive, &out).success();
    assert_eq!(fs::read(out.join("d/e/f.bin")).expect("f"), b"AAAABBBB");
    assert!(fs::symlink_metadata(out.join("f.bin")).is_err());
}

#[test]
fn list_shows_the_full_logical_entry_path() {
    let td = tempdir().expect("tmp");
    let archive = write(td.path(), vec![file(Some("d/e"), "f.txt", b"x")]);
    Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["list", archive.to_str().expect("str")])
        .assert()
        .success()
        .stdout(contains("d/e/f.txt"));
}
