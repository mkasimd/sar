// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! CLI parity tests for the shared WP-4 fragment-group collector.

use std::fs;

use assert_cmd::Command;
use predicates::{prelude::*, str::contains};
use sar_core::{
    GlobalFlags,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};
use tempfile::tempdir;

const FRAG: u16 = 1 << 5;
const LAST: u16 = 1 << 6;

fn archive(flags: GlobalFlags, frags: &[(u32, bool, &str, &[u8], u32)]) -> Vec<u8> {
    let flags = flags | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut out = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    for (index, last, name, data, crc) in frags {
        let mut l = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), data.len() as u64);
        l.uncompressed_size = data.len() as u64;
        l.entry_mode = EntryMode::from_bits(FRAG | if *last { LAST } else { 0 });
        l.fragment_id = Some(1);
        l.fragment_index = Some(*index);
        l.file_crc32 = Some(*crc);
        out.extend_from_slice(&write_lfh(&flags, &l).expect("lfh"));
        out.extend_from_slice(data);
    }
    out
}

fn extract(
    bytes: &[u8],
) -> (
    assert_cmd::assert::Assert,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let td = tempdir().expect("tmp");
    let a = td.path().join("a.sar");
    fs::write(&a, bytes).expect("write");
    let out = td.path().join("out");
    let assert = Command::cargo_bin("sar-cli")
        .expect("bin")
        .args(["extract", a.to_str().expect("s"), out.to_str().expect("s")])
        .assert();
    (assert, out, td)
}

#[test]
fn cli_uses_terminal_crc_and_index0_name() {
    let crc = crc32fast::hash(b"AAAABBBB");
    let bytes = archive(
        GlobalFlags::PER_FILE_CRC,
        &[(0, false, "f.bin", b"AAAA", 0), (1, true, "", b"BBBB", crc)],
    );
    let (assert, out, _td) = extract(&bytes);
    assert.success();
    assert_eq!(fs::read(out.join("f.bin")).expect("read"), b"AAAABBBB");
}

#[test]
fn cli_rejects_wrong_terminal_crc() {
    let bytes = archive(
        GlobalFlags::PER_FILE_CRC,
        &[(0, false, "f.bin", b"AAAA", 0), (1, true, "", b"BBBB", 1)],
    );
    extract(&bytes).0.failure();
}

#[test]
fn cli_rejects_name_mismatch_and_out_of_order() {
    let bytes = archive(
        GlobalFlags::empty(),
        &[(0, false, "f.bin", b"A", 0), (1, true, "g.bin", b"B", 0)],
    );
    extract(&bytes).0.failure();
    let bytes = archive(
        GlobalFlags::empty(),
        &[
            (0, false, "f.bin", b"A", 0),
            (2, true, "", b"C", 0),
            (1, false, "", b"B", 0),
        ],
    );
    extract(&bytes).0.failure();
}

#[test]
fn cli_gap_without_allow_lossy_fails_without_zero_fill_warning() {
    let bytes = archive(GlobalFlags::empty(), &[(0, false, "f.bin", b"A", 0)]);
    let (assert, _out, _td) = extract(&bytes);
    assert.failure().stderr(contains("zero bytes").not());
}

fn hashed_archive(explicit_hash: Option<[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new(
        std::io::Cursor::new(&mut out),
        sar_archive::ArchiveWriterOptions {
            sparse: true,
            with_content_hash: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let mut input = sar_archive::EntryInput::file("plain.bin", b"hello".to_vec());
    input.content_hash = explicit_hash;
    writer.add_entry(input).expect("entry");
    writer
        .write_sparse_entry(
            "sparse.bin",
            b"DATA",
            sar_archive::SparseWriteOptions {
                logical_size: 100_000,
                extents: vec![sar_core::sparse::SparseExtent {
                    offset: 50_000,
                    length: 4,
                }],
            },
        )
        .expect("sparse");
    writer.finish().expect("finish");
    out
}

#[test]
fn cli_verifies_content_hash_including_sparse_holes() {
    let (assert, out, _td) = extract(&hashed_archive(None));
    assert.success();
    assert_eq!(fs::read(out.join("plain.bin")).expect("read"), b"hello");
    assert_eq!(
        fs::metadata(out.join("sparse.bin")).expect("meta").len(),
        100_000
    );
}

#[test]
fn cli_rejects_content_hash_mismatch() {
    let (assert, out, _td) = extract(&hashed_archive(Some([0u8; 32])));
    assert.failure().stderr(contains("hash"));
    assert!(!out.join("plain.bin").exists());
}
