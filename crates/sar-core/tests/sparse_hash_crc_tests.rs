//! Hash and CRC sparse-domain tests.
//!
//! File CRC32 and Content Hash must be computed against the fully
//! reconstructed logical file, including sparse holes (zero-filled bytes).
//! They must not be computed only against the stored sparse payload bytes.
//!
//! # Current implementation status
//!
//! CRC32 verification of the reconstructed output **is** implemented in
//! `read_all_logical_files` as of M8.  Verification is triggered when the
//! global `PER_FILE_CRC` flag is set and the LFH carries a non-None CRC32
//! field.  Content-hash verification is not implemented because the archive
//! format does not encode the hash algorithm; see docs/CONFORMANCE.md.
//!
//! # Tests
//!
//! 1. `EntryMetadata` preserves `file_crc32` and `content_hash` from the LFH.
//! 2. The reconstructed sparse output (which includes holes) is different from
//!    the stored payload bytes, so any CRC/hash computed only over payload
//!    bytes would produce the wrong value.
//! 3. Changing sparse map offsets without changing the stored payload changes
//!    the reconstructed file content.
//! 4. A correct CRC over reconstructed bytes passes verification.
//! 5. A wrong CRC (computed over payload only) fails verification.

use std::io::Cursor;

use sar_core::{
    ArchiveReader, GlobalFlags,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
    sparse::{SparseExtent, write_sparse_map},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_sparse_archive_with_crc(
    payload: &[u8],
    extents: &[SparseExtent],
    uncompressed_size: u64,
    file_crc32: Option<u32>,
) -> Vec<u8> {
    // Include PER_FILE_CRC only when a real CRC value is provided.
    // When file_crc32 is None, omitting PER_FILE_CRC ensures the LFH has no
    // CRC field and no verification is triggered.
    let mut flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    if file_crc32.is_some() {
        flags |= GlobalFlags::PER_FILE_CRC;
    }
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let sparse_map_bytes = write_sparse_map(extents, false);
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = uncompressed_size;
    lfh.sparse_map = sparse_map_bytes;
    lfh.file_crc32 = file_crc32;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);
    archive
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `file_crc32` stored in the LFH is preserved in `EntryMetadata`.
#[test]
fn file_crc32_preserved_in_entry_metadata() {
    let extents = [SparseExtent {
        offset: 2,
        length: 3,
    }];
    let archive = build_sparse_archive_with_crc(b"ABC", &extents, 10, Some(0xDEADBEEF));

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");

    assert_eq!(
        entry.metadata.file_crc32,
        Some(0xDEADBEEF),
        "file_crc32 must be surfaced in EntryMetadata"
    );
}

/// `content_hash` stored in the LFH is preserved in `EntryMetadata`.
#[test]
fn content_hash_preserved_in_entry_metadata() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::DEDUPLICATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let extents = [SparseExtent {
        offset: 0,
        length: 3,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false);
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 3);
    lfh.uncompressed_size = 3;
    lfh.sparse_map = sparse_map_bytes;
    let expected_hash: [u8; 32] = [0xABu8; 32];
    lfh.content_hash = Some(expected_hash);
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABC");

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");

    assert_eq!(
        entry.metadata.content_hash,
        Some(expected_hash),
        "content_hash must be surfaced in EntryMetadata"
    );
}

/// The reconstructed sparse file (including holes) differs from the stored
/// payload bytes, which demonstrates why CRC/hash must include holes.
#[test]
fn reconstructed_sparse_output_differs_from_payload_bytes() {
    // Trailing-hole vector: stored payload = "ABC" (3 bytes),
    // reconstructed = [0,0,A,B,C,0,0,0,0,0] (10 bytes).
    let extents = [SparseExtent {
        offset: 2,
        length: 3,
    }];
    let archive = build_sparse_archive_with_crc(b"ABC", &extents, 10, None);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(
        files[0].data.len(),
        10,
        "reconstructed file must be 10 bytes (Uncompressed Size)"
    );
    assert_ne!(
        files[0].data.as_slice(),
        b"ABC",
        "reconstructed file must include holes, not just payload bytes"
    );
    // Holes are zero bytes.
    assert_eq!(&files[0].data[0..2], &[0u8; 2]);
    assert_eq!(&files[0].data[5..10], &[0u8; 5]);
}

/// Changing sparse map offsets without changing stored payload produces a
/// different reconstructed file — any correct CRC/hash must detect this.
#[test]
fn different_sparse_offsets_produce_different_reconstructed_files() {
    let payload = b"XY";

    // Layout A: data at offset 0 → [X Y 0 0 0]
    let extents_a = [SparseExtent {
        offset: 0,
        length: 2,
    }];
    let archive_a = build_sparse_archive_with_crc(payload, &extents_a, 5, None);

    // Layout B: data at offset 3 → [0 0 0 X Y]
    let extents_b = [SparseExtent {
        offset: 3,
        length: 2,
    }];
    let archive_b = build_sparse_archive_with_crc(payload, &extents_b, 5, None);

    let files_a = ArchiveReader::new(Cursor::new(archive_a))
        .expect("r_a")
        .read_all_logical_files(false)
        .expect("read_a");
    let files_b = ArchiveReader::new(Cursor::new(archive_b))
        .expect("r_b")
        .read_all_logical_files(false)
        .expect("read_b");

    assert_ne!(
        files_a[0].data, files_b[0].data,
        "different sparse layouts of the same payload must produce different reconstructed files"
    );
    // Sanity check.
    assert_eq!(&files_a[0].data, b"XY\x00\x00\x00");
    assert_eq!(&files_b[0].data, b"\x00\x00\x00XY");
}

/// CRC/hash verification does not use only stored sparse payload bytes:
/// a CRC computed over just the stored payload would differ from the CRC
/// computed over the fully reconstructed file.
#[test]
fn crc_over_payload_only_differs_from_crc_over_reconstructed() {
    // Trailing-hole vector: stored payload = "ABC" (3 bytes),
    // reconstructed = [0,0,A,B,C,0,0,0,0,0] (10 bytes).
    let payload = b"ABC"; // 3 bytes stored
    let extents = [SparseExtent {
        offset: 2,
        length: 3,
    }];
    // No CRC provided — just verify that reconstruction includes holes.
    let archive = build_sparse_archive_with_crc(payload, &extents, 10, None);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    let reconstructed = &files[0].data;

    // Reconstructed must not equal stored payload.
    assert_ne!(
        reconstructed.as_slice(),
        payload as &[u8],
        "reconstructed file includes trailing hole bytes"
    );
    // Reconstructed must equal expected including holes.
    let mut expected = [0u8; 10];
    expected[2..5].copy_from_slice(b"ABC");
    assert_eq!(reconstructed.as_slice(), &expected[..]);

    // CRC over stored payload differs from CRC over reconstructed file.
    let crc_payload = crc32fast::hash(payload);
    let crc_reconstructed = crc32fast::hash(reconstructed);
    assert_ne!(
        crc_payload, crc_reconstructed,
        "CRC over payload-only must differ from CRC over reconstructed file with holes"
    );
}

/// An archive with a correct CRC32 (computed over reconstructed bytes
/// including holes) must pass verification.
#[test]
fn crc_over_reconstructed_bytes_passes_verification() {
    let payload = b"HI"; // 2 bytes stored
    let extents = [SparseExtent {
        offset: 0,
        length: 2,
    }];
    // Reconstructed = [H, I, 0, 0, 0] (5 bytes)
    let mut reconstructed = [0u8; 5];
    reconstructed[0..2].copy_from_slice(payload);
    let correct_crc = crc32fast::hash(&reconstructed);

    let archive = build_sparse_archive_with_crc(payload, &extents, 5, Some(correct_crc));
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // CRC over reconstructed bytes matches → verification passes.
    let files = reader
        .read_all_logical_files(false)
        .expect("correct CRC must pass");
    assert_eq!(files[0].data.as_slice(), &reconstructed[..]);
}

/// An archive with a wrong CRC32 (computed over payload only, not
/// reconstructed bytes) must fail with `CrcMismatch`.
#[test]
fn crc_over_payload_only_fails_verification() {
    use sar_core::SarError;

    let payload = b"HI"; // 2 bytes stored
    let extents = [SparseExtent {
        offset: 0,
        length: 2,
    }];
    // Wrong: CRC over payload bytes only, not reconstructed (which includes trailing holes).
    let wrong_crc = crc32fast::hash(payload);

    let archive = build_sparse_archive_with_crc(payload, &extents, 5, Some(wrong_crc));
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("wrong CRC must fail");
    assert!(
        matches!(err, SarError::CrcMismatch(_)),
        "expected CrcMismatch, got {err:?}"
    );
}
