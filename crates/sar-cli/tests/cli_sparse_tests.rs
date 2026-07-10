//! CLI integration tests for sparse-file extraction behavior.
//!
//! These tests verify that `sar extract` reconstructs sparse holes correctly,
//! that extracted files have the exact logical size, and that malformed sparse
//! archives cause extraction failures.

use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

// Bring in library types for building test archives.
use sar_core::{
    GlobalFlags,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
    sparse::{SparseExtent, write_sparse_map},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sar() -> Command {
    Command::cargo_bin("sar-cli").expect("sar-cli binary")
}

/// Build a NO_INDEX sparse archive bytes and write to a temp file.
/// Returns the path to the archive file.
fn write_sparse_archive(
    dir: &tempfile::TempDir,
    name: &str,
    payload: &[u8],
    extents: &[SparseExtent],
    uncompressed_size: u64,
) -> std::path::PathBuf {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    let sparse_map_bytes = write_sparse_map(extents, false).expect("write sparse map ok");
    let mut lfh = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), payload.len() as u64);
    lfh.uncompressed_size = uncompressed_size;
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    let archive_path = dir.path().join("sparse.sar");
    fs::write(&archive_path, &archive).expect("write archive");
    archive_path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `sar extract` reconstructs sparse holes correctly.
/// The extracted file must contain zero bytes in hole regions.
#[test]
fn extract_sparse_holes_are_reconstructed() {
    let td = tempdir().expect("tmp");
    // Trailing-hole spec vector: payload=ABC at offset 2, logical size 10.
    let extents = [SparseExtent {
        offset: 2,
        length: 3,
    }];
    let archive = write_sparse_archive(&td, "f.bin", b"ABC", &extents, 10);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    let extracted = fs::read(out_dir.join("f.bin")).expect("read extracted");
    assert_eq!(
        extracted.len(),
        10,
        "extracted file size must equal Uncompressed Size"
    );
    assert_eq!(&extracted[0..2], &[0u8; 2], "leading hole must be zero");
    assert_eq!(&extracted[2..5], b"ABC", "data must be at extent offset");
    assert_eq!(&extracted[5..10], &[0u8; 5], "trailing hole must be zero");
}

/// Extracted file size equals LFH `Uncompressed Size`.
#[test]
fn extract_file_size_equals_uncompressed_size() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    // Logical size 20 with data only in [0,4).
    let archive = write_sparse_archive(&td, "f.bin", b"DATA", &extents, 20);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    let extracted = fs::read(out_dir.join("f.bin")).expect("read extracted");
    assert_eq!(
        extracted.len(),
        20,
        "extracted file size must equal Uncompressed Size (20)"
    );
    assert_eq!(&extracted[0..4], b"DATA");
    assert_eq!(&extracted[4..], &[0u8; 16]);
}

/// Trailing holes are preserved (zero bytes after last extent).
#[test]
fn extract_trailing_holes_preserved() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: 0,
        length: 3,
    }];
    // 8-byte file; data at [0,3), trailing hole [3,8).
    let archive = write_sparse_archive(&td, "f.bin", b"XYZ", &extents, 8);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    let extracted = fs::read(out_dir.join("f.bin")).expect("read");
    assert_eq!(extracted.len(), 8);
    assert_eq!(&extracted[0..3], b"XYZ");
    assert_eq!(&extracted[3..8], &[0u8; 5]);
}

/// Malformed sparse map (non-multiple of descriptor size) causes extraction
/// failure with a non-zero exit code.
#[test]
fn extract_malformed_sparse_map_causes_failure() {
    let td = tempdir().expect("tmp");
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // 7 bytes — not a multiple of 8 (32-bit descriptor size).
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 5);
    lfh.uncompressed_size = 5;
    lfh.sparse_map = vec![0u8; 7];
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"HELLO");

    let archive_path = td.path().join("bad.sar");
    fs::write(&archive_path, &archive).expect("write");
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive_path.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .failure();
}

/// `sar extract` on a normal (non-sparse) archive is unaffected by sparse fixes.
#[test]
fn extract_non_sparse_archive_unaffected() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("data.txt");
    fs::write(&input, b"hello sparse world").expect("write");
    let archive = td.path().join("archive.sar");

    sar()
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--indexed",
        ])
        .assert()
        .success();

    let out_dir = td.path().join("out");
    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .success();

    let extracted = fs::read(out_dir.join("data.txt")).expect("read");
    assert_eq!(extracted, b"hello sparse world");
}

/// `sar inspect --json` reports `sparse_files=false` for a normal archive.
#[test]
fn inspect_json_sparse_files_false_for_normal_archive() {
    let td = tempdir().expect("tmp");
    let input = td.path().join("data.txt");
    fs::write(&input, b"test").expect("write");
    let archive = td.path().join("a.sar");
    sar()
        .args([
            "create",
            input.to_str().expect("str"),
            archive.to_str().expect("str"),
            "--indexed",
        ])
        .assert()
        .success();

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["sparse_files"], serde_json::json!(false));
}

/// `sar inspect --json` reports correct `sparse_extent_count` for a sparse
/// entry.
#[test]
fn inspect_json_reports_sparse_extent_count() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let archive = write_sparse_archive(&td, "f.bin", b"DATA", &extents, 10);

    let out = sar()
        .args(["inspect", archive.to_str().expect("str"), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let entries = v["entries"].as_array().expect("entries array");
    assert_eq!(
        entries[0]["sparse_extent_count"],
        serde_json::json!(1),
        "sparse_extent_count must be 1"
    );
}

/// `sar extract --allow-lossy` works for a normal sparse archive (no fragments).
#[test]
fn extract_allow_lossy_with_sparse_archive_succeeds() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: 0,
        length: 5,
    }];
    let archive = write_sparse_archive(&td, "f.bin", b"HELLO", &extents, 5);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--allow-lossy",
        ])
        .assert()
        .success();

    let extracted = fs::read(out_dir.join("f.bin")).expect("read");
    assert_eq!(extracted, b"HELLO");
}
