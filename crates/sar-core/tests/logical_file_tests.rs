//! Tests for `ArchiveReader::read_all_logical_files` — fragment reassembly,
//! sparse reconstruction, and loss-tolerant integration through the high-level
//! read path.

use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput, GlobalFlags, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal indexed SAR archive with a single non-fragmented entry.
fn build_simple_archive(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: false,
            encryption: None,
            fec: None,
            sparse: false,
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: name.to_string(),
            payload: payload.to_vec(),
        })
        .expect("add entry");
    writer.finish().expect("finish");
    out
}

/// Build a NO_INDEX SAR archive with one fragment entry embedded manually.
///
/// This constructs the on-wire bytes for a FILE_FRAGMENTATION archive
/// containing two fragments of a 16-byte logical file.
fn build_two_fragment_archive() -> Vec<u8> {
    let fragment_flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;

    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: fragment_flags.bits().to_le_bytes().to_vec(),
        flags: fragment_flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // Fragment 0: payload b"AAAAAAAA" at logical offset 0, fragment_size=8
    let mut lfh0 = LocalFileHeader::minimal_store(b"file.bin".to_vec(), 8);
    lfh0.uncompressed_size = 8;
    lfh0.entry_mode = EntryMode(1u16 << 5); // IS_FRAGMENT
    lfh0.fragment_id = Some(42);
    lfh0.fragment_index = Some(0);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 8,
    });
    let lfh0_bytes = write_lfh(&fragment_flags, &lfh0).expect("write lfh0");
    archive.extend_from_slice(&lfh0_bytes);
    archive.extend_from_slice(b"AAAAAAAA");

    // Fragment 1: payload b"BBBBBBBB" at logical offset 8, fragment_size=8, IS_LAST_FRAGMENT
    let mut lfh1 = LocalFileHeader::minimal_store(b"file.bin".to_vec(), 8);
    lfh1.uncompressed_size = 8;
    lfh1.entry_mode = EntryMode((1u16 << 5) | (1u16 << 6)); // IS_FRAGMENT | LAST_FRAGMENT
    lfh1.fragment_id = Some(42);
    lfh1.fragment_index = Some(1);
    lfh1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 8,
        fragment_size: 8,
    });
    let lfh1_bytes = write_lfh(&fragment_flags, &lfh1).expect("write lfh1");
    archive.extend_from_slice(&lfh1_bytes);
    archive.extend_from_slice(b"BBBBBBBB");

    archive
}

// ---------------------------------------------------------------------------
// Non-fragmented roundtrip
// ---------------------------------------------------------------------------

#[test]
fn read_all_logical_files_simple_roundtrip() {
    let archive = build_simple_archive("hello.txt", b"world");
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("header");

    let files = reader
        .read_all_logical_files(false)
        .expect("read logical files");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "hello.txt");
    assert_eq!(files[0].data, b"world");
    assert!(!files[0].is_degraded);
    assert!(files[0].fragment_id.is_none());
}

#[test]
fn read_all_logical_files_multiple_entries() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: false,
            encryption: None,
            fec: None,
            sparse: false,
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "a.txt".into(),
            payload: b"AAAA".to_vec(),
        })
        .expect("a");
    writer
        .add_entry(EntryInput {
            name: "b.txt".into(),
            payload: b"BBBB".to_vec(),
        })
        .expect("b");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(out)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, "a.txt");
    assert_eq!(files[0].data, b"AAAA");
    assert_eq!(files[1].name, "b.txt");
    assert_eq!(files[1].data, b"BBBB");
}

// ---------------------------------------------------------------------------
// Fragment reconstruction
// ---------------------------------------------------------------------------

#[test]
fn fragment_group_reconstructs_through_reader() {
    let archive = build_two_fragment_archive();
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");

    let files = reader
        .read_all_logical_files(false)
        .expect("read logical files");

    assert_eq!(
        files.len(),
        1,
        "two fragments should produce one logical file"
    );
    assert_eq!(files[0].name, "file.bin");
    assert_eq!(files[0].fragment_id, Some(42));
    assert!(!files[0].is_degraded);
    assert_eq!(&files[0].data[..8], b"AAAAAAAA");
    assert_eq!(&files[0].data[8..], b"BBBBBBBB");
}

#[test]
fn missing_fragment_fails_without_allow_lossy() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Only one fragment (index 0) with no LAST_FRAGMENT — gap
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.entry_mode = EntryMode(1u16 << 5); // IS_FRAGMENT only
    lfh.fragment_id = Some(1);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn missing_fragment_succeeds_with_allow_lossy_and_loss_tolerant() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Fragment 0 with LOSS_TOLERANT bit; fragment 1 is intentionally absent.
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    // IS_FRAGMENT=bit5, LOSS_TOLERANT=bit7; no LAST_FRAGMENT → gap
    lfh.entry_mode = EntryMode((1u16 << 5) | (1u16 << 7));
    lfh.fragment_id = Some(5);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // Without allow_lossy: should fail
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(matches!(err, SarError::FragmentGap(_)));

    // With allow_lossy: should succeed with is_degraded=true
    let files = reader.read_all_logical_files(true).expect("read");
    assert_eq!(files.len(), 1);
    assert!(
        files[0].is_degraded,
        "must be degraded when fragment is missing"
    );
    assert_eq!(&files[0].data[..4], b"ABCD");
}

#[test]
fn overlapping_fragment_descriptors_fail() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Fragment 0 covers [0,8) and fragment 1 covers [4,12) — they overlap.
    for (idx, abs_off, is_last) in [(0u32, 0u64, false), (1u32, 4u64, true)] {
        let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 8);
        let mut mode_bits: u16 = 1 << 5; // IS_FRAGMENT
        if is_last {
            mode_bits |= 1 << 6; // LAST_FRAGMENT
        }
        lfh.entry_mode = EntryMode(mode_bits);
        lfh.fragment_id = Some(7);
        lfh.fragment_index = Some(idx);
        lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
            absolute_offset: abs_off,
            fragment_size: 8,
        });
        archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        archive.extend_from_slice(&[0u8; 8]);
    }

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap for overlapping fragments, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sparse reconstruction
// ---------------------------------------------------------------------------

#[test]
fn sparse_extents_reconstruct_with_zero_holes() {
    use sar_core::sparse::{SparseExtent, write_sparse_map};

    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Sparse file: data at [0,4) = "DATA" and [8,4) = "EXTS", hole [4,8)
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 4,
        },
        SparseExtent {
            offset: 8,
            length: 4,
        },
    ];
    let sparse_map_bytes = write_sparse_map(&extents, false);
    let payload = b"DATAEXTS"; // 8 bytes of data

    // uncompressed_size must be the full logical file size (12), not the
    // sparse payload byte count (8).
    let mut lfh = LocalFileHeader::minimal_store(b"sparse.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = 12; // logical file size including the hole
    lfh.sparse_map = sparse_map_bytes;
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(payload);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "sparse.bin");
    assert!(!files[0].is_degraded);
    // Logical layout: [DATA | 0000 | EXTS]
    assert_eq!(files[0].data.len(), 12);
    assert_eq!(&files[0].data[0..4], b"DATA");
    assert_eq!(&files[0].data[4..8], &[0u8; 4]);
    assert_eq!(&files[0].data[8..12], b"EXTS");
}

#[test]
fn overlapping_sparse_extents_fail() {
    use sar_core::sparse::{SparseExtent, write_sparse_map};

    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Overlapping extents: [0,8) and [4,8)
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 8,
        },
        SparseExtent {
            offset: 4,
            length: 8,
        }, // overlaps
    ];
    let sparse_map_bytes = write_sparse_map(&extents, false);
    let payload = vec![0u8; 16];

    let mut lfh = LocalFileHeader::minimal_store(b"bad.bin".to_vec(), payload.len() as u64);
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(&payload);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap for overlapping sparse extents, got {err:?}"
    );
}

#[test]
fn large_sparse_hole_capped_by_max_size() {
    use sar_core::ArchiveReaderOptions;
    use sar_core::sparse::{SparseExtent, write_sparse_map};

    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Set offset so logical_size = 1_000_004, far exceeding the cap
    let extents_huge = vec![SparseExtent {
        offset: 1_000_000,
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(&extents_huge, false);
    let payload = b"ABCD";

    // uncompressed_size must be the full logical file size (1_000_004).
    let mut lfh = LocalFileHeader::minimal_store(b"huge.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = 1_000_004;
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    // Use a reader with a very small max_decoded_entry_size
    let mut reader = ArchiveReader::with_options(
        Cursor::new(archive),
        ArchiveReaderOptions {
            max_decoded_entry_size: 512, // cap at 512 bytes
        },
    )
    .expect("reader");

    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail with overflow");
    assert!(
        matches!(err, SarError::Overflow(_)),
        "expected Overflow, got {err:?}"
    );

    // With a small extent, no overflow
    let flags2 = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive2 = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags2.bits().to_le_bytes().to_vec(),
        flags: flags2,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let extents_small = vec![SparseExtent {
        offset: 0,
        length: 4,
    }];
    let sparse_map_small = write_sparse_map(&extents_small, false);
    let mut lfh2 = LocalFileHeader::minimal_store(b"small.bin".to_vec(), 4);
    lfh2.sparse_map = sparse_map_small;
    archive2.extend_from_slice(&write_lfh(&flags2, &lfh2).expect("lfh2"));
    archive2.extend_from_slice(b"ABCD");

    let mut reader2 = ArchiveReader::with_options(
        Cursor::new(archive2),
        ArchiveReaderOptions {
            max_decoded_entry_size: 512,
        },
    )
    .expect("reader2");
    let files2 = reader2.read_all_logical_files(false).expect("read2");
    assert_eq!(files2.len(), 1);
    assert_eq!(files2[0].data, b"ABCD");
}

// ---------------------------------------------------------------------------
// Cursor reset
// ---------------------------------------------------------------------------

#[test]
fn read_all_logical_files_resets_cursor() {
    let archive = build_simple_archive("x.txt", b"payload");
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("header");

    // First call via next_entry
    let _ = reader.next_entry().expect("first entry").expect("some");
    // next_entry returns None now
    assert!(reader.next_entry().expect("second next_entry").is_none());

    // read_all_logical_files must reset cursor and re-read
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].data, b"payload");
}
