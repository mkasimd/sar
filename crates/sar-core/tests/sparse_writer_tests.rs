//! Tests for the ArchiveWriter sparse entry write path.
//!
//! Covers:
//! * Writer creates sparse entry with leading/middle/trailing holes.
//! * Writer rejects overlapping sparse extents.
//! * Writer rejects extent beyond logical size.
//! * Writer rejects payload length mismatch.
//! * Writer sparse entry round-trips through reader.
//! * `write_sparse_entry` requires `ArchiveWriterOptions::sparse = true`.

use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, SarError, SparseWriteOptions,
    sparse::SparseExtent,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a sparse archive using `ArchiveWriter`, return the raw bytes.
fn build_sparse_archive_via_writer(
    name: &str,
    gathered_payload: &[u8],
    extents: Vec<SparseExtent>,
    logical_size: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..ArchiveWriterOptions::default()
        },
    )
    .expect("writer");
    writer
        .write_sparse_entry(
            name,
            gathered_payload,
            SparseWriteOptions {
                logical_size,
                extents,
            },
        )
        .expect("write_sparse_entry");
    writer.finish().expect("finish");
    out
}

/// Basic round-trip: write sparse entry with leading/middle/trailing holes,
/// read back and verify final reconstructed content.
#[test]
fn sparse_writer_round_trip_holes() {
    // Logical file (10 bytes): [A A 0 0 B B 0 0 0 0]
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 2,
        },
        SparseExtent {
            offset: 4,
            length: 2,
        },
    ];
    let archive = build_sparse_archive_via_writer("f.bin", b"AABB", extents, 10);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1, "must have one logical file");
    assert_eq!(files[0].name, "f.bin");
    let data = &files[0].data;
    assert_eq!(data.len(), 10, "reconstructed size must be logical_size=10");
    assert_eq!(&data[0..2], b"AA");
    assert_eq!(&data[2..4], &[0u8; 2], "hole must be zero");
    assert_eq!(&data[4..6], b"BB");
    assert_eq!(&data[6..10], &[0u8; 4], "trailing hole must be zero");
}

/// Trailing-hole round-trip: data at [2,5), logical size 10 → trailing hole [5,10).
#[test]
fn sparse_writer_trailing_hole_roundtrip() {
    let extents = vec![SparseExtent {
        offset: 2,
        length: 3,
    }];
    let archive = build_sparse_archive_via_writer("x.bin", b"ABC", extents, 10);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    let data = &files[0].data;
    assert_eq!(data.len(), 10);
    assert_eq!(&data[0..2], &[0u8; 2], "leading hole");
    assert_eq!(&data[2..5], b"ABC");
    assert_eq!(&data[5..10], &[0u8; 5], "trailing hole");
}

/// Multiple extents round-trip: three separate data regions.
#[test]
fn sparse_writer_three_extents_roundtrip() {
    // Logical: [AA 00 00 BB 00 00 CC 00 00 00]  (10 bytes)
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 2,
        },
        SparseExtent {
            offset: 3,
            length: 2,
        },
        SparseExtent {
            offset: 6,
            length: 2,
        },
    ];
    let archive = build_sparse_archive_via_writer("data.bin", b"AABBCC", extents, 10);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    let data = &files[0].data;
    assert_eq!(data.len(), 10);
    assert_eq!(&data[0..2], b"AA");
    assert_eq!(&data[2..3], &[0u8; 1]);
    assert_eq!(&data[3..5], b"BB");
    assert_eq!(&data[5..6], &[0u8; 1]);
    assert_eq!(&data[6..8], b"CC");
    assert_eq!(&data[8..10], &[0u8; 2]);
}

// ---------------------------------------------------------------------------
// §2 Writer validation errors
// ---------------------------------------------------------------------------

/// Writer rejects overlapping sparse extents.
#[test]
fn sparse_writer_rejects_overlapping_extents() {
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 8,
        },
        SparseExtent {
            offset: 4,
            length: 8,
        }, // overlaps [0,8)
    ];
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let err = writer
        .write_sparse_entry(
            "f.bin",
            &[0u8; 12],
            SparseWriteOptions {
                logical_size: 20,
                extents,
            },
        )
        .expect_err("must reject overlapping extents");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

/// Writer rejects extent that extends beyond logical_size.
#[test]
fn sparse_writer_rejects_extent_beyond_logical_size() {
    let extents = vec![SparseExtent {
        offset: 8,
        length: 5,
    }]; // end=13 > logical_size=10
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let err = writer
        .write_sparse_entry(
            "f.bin",
            b"XXXXX",
            SparseWriteOptions {
                logical_size: 10,
                extents,
            },
        )
        .expect_err("must reject extent beyond logical_size");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

/// Writer rejects payload length mismatch (payload shorter than sum of extents).
#[test]
fn sparse_writer_rejects_short_payload() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 8,
    }];
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let err = writer
        .write_sparse_entry(
            "f.bin",
            b"ABCD", // only 4 bytes but extents claim 8
            SparseWriteOptions {
                logical_size: 10,
                extents,
            },
        )
        .expect_err("must reject short payload");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap for payload length mismatch, got {err:?}"
    );
}

/// Writer rejects payload length mismatch (payload longer than sum of extents).
#[test]
fn sparse_writer_rejects_excess_payload() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 3,
    }];
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let err = writer
        .write_sparse_entry(
            "f.bin",
            b"ABCDE", // 5 bytes but extents claim only 3
            SparseWriteOptions {
                logical_size: 10,
                extents,
            },
        )
        .expect_err("must reject excess payload");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap for payload length mismatch, got {err:?}"
    );
}

/// `write_sparse_entry` fails with `Malformed` when `sparse` flag is not set.
#[test]
fn sparse_writer_requires_sparse_flag() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 4,
    }];
    let mut out = Vec::new();
    // sparse: false (default)
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");
    let err = writer
        .write_sparse_entry(
            "f.bin",
            b"ABCD",
            SparseWriteOptions {
                logical_size: 8,
                extents,
            },
        )
        .expect_err("must fail without sparse flag");
    assert!(
        matches!(err, SarError::Malformed(_)),
        "expected Malformed when sparse flag is not set, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §3 Edge cases
// ---------------------------------------------------------------------------

/// A single full-coverage extent (no actual holes) still round-trips correctly.
#[test]
fn sparse_writer_single_full_extent_roundtrip() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 5,
    }];
    let archive = build_sparse_archive_via_writer("full.bin", b"HELLO", extents, 5);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files[0].data, b"HELLO");
}

/// Empty extent list with zero logical_size writes an empty sparse file
/// (no stored bytes, no holes).
#[test]
fn sparse_writer_empty_extents_all_holes() {
    let extents: Vec<SparseExtent> = vec![];
    let archive = build_sparse_archive_via_writer("hole.bin", b"", extents, 0);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(
        files[0].data.len(),
        0,
        "empty sparse file must have zero bytes"
    );
}

// ---------------------------------------------------------------------------
// §4 Indexed archive sparse round-trip
// ---------------------------------------------------------------------------

/// Sparse entry in an indexed archive (with CD) also round-trips correctly.
#[test]
fn sparse_writer_indexed_archive_roundtrip() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: false, // indexed
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");

    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 3,
        },
        SparseExtent {
            offset: 6,
            length: 3,
        },
    ];
    writer
        .write_sparse_entry(
            "indexed.bin",
            b"ABCXYZ",
            SparseWriteOptions {
                logical_size: 12,
                extents,
            },
        )
        .expect("write");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(out)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(data.len(), 12);
    assert_eq!(&data[0..3], b"ABC");
    assert_eq!(&data[3..6], &[0u8; 3], "hole");
    assert_eq!(&data[6..9], b"XYZ");
    assert_eq!(&data[9..12], &[0u8; 3], "trailing hole");
}

// ---------------------------------------------------------------------------
// §5 non-sparse writer is unaffected
// ---------------------------------------------------------------------------

/// Non-sparse writer still creates correct archives (no regression).
#[test]
fn non_sparse_writer_unaffected() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");
    // write_sparse_entry should fail
    let extents = vec![SparseExtent {
        offset: 0,
        length: 5,
    }];
    let err = writer
        .write_sparse_entry(
            "f.bin",
            b"HELLO",
            SparseWriteOptions {
                logical_size: 5,
                extents,
            },
        )
        .expect_err("non-sparse writer must reject write_sparse_entry");
    assert!(matches!(err, SarError::Malformed(_)));
}
