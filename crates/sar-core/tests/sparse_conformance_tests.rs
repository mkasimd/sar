//! Sparse-file conformance tests: scatter-gather, trailing holes, ordering,
//! compression/encryption integration, and fragmentation ordering.
//!
//! All tests work through [`ArchiveReader::read_all_logical_files`] to
//! exercise the full end-to-end reconstruction pipeline.

use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, EntryInput,
    GlobalFlags, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
    sparse::{SparseExtent, write_sparse_map},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a NO_INDEX sparse archive with a single entry.
///
/// `uncompressed_size` is the full logical file size (including holes).
/// `payload` is the raw sparse data bytes (sum of extent lengths).
/// `extents` describe the scatter-gather layout.
fn build_sparse_archive(
    name: &str,
    payload: &[u8],
    extents: &[SparseExtent],
    uncompressed_size: u64,
) -> Vec<u8> {
    build_sparse_archive_64bit(name, payload, extents, uncompressed_size, false)
}

fn build_sparse_archive_64bit(
    name: &str,
    payload: &[u8],
    extents: &[SparseExtent],
    uncompressed_size: u64,
    is_64bit: bool,
) -> Vec<u8> {
    let mut flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    if is_64bit {
        flags |= GlobalFlags::SIZE_64BIT;
    }

    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    let sparse_map_bytes = write_sparse_map(extents, is_64bit);
    let mut lfh = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), payload.len() as u64);
    lfh.uncompressed_size = uncompressed_size;
    lfh.sparse_map = sparse_map_bytes;

    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);
    archive
}

// ---------------------------------------------------------------------------
// §2 Sparse scatter-gather — spec-mandated test vectors
// ---------------------------------------------------------------------------

/// Single extent at offset 0 — degenerate non-sparse case.
#[test]
fn scatter_gather_single_extent_at_zero() {
    let payload = b"hello world!";
    let extents = [SparseExtent {
        offset: 0,
        length: 12,
    }];
    let archive = build_sparse_archive("f.bin", payload, &extents, 12);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files[0].data, b"hello world!");
}

/// Leading hole: offset 2..5 = "ABC", [0..2) are zero.
///
/// ```text
/// Uncompressed Size: 10
/// Sparse Map: offset=2, length=3
/// Stored Payload: ABC
/// Expected: 00 00 41 42 43 00 00 00 00 00
/// ```
#[test]
fn scatter_gather_trailing_hole_spec_vector() {
    let payload = b"ABC";
    let extents = [SparseExtent {
        offset: 2,
        length: 3,
    }];
    let archive = build_sparse_archive("f.bin", payload, &extents, 10);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(data.len(), 10, "final size must equal Uncompressed Size");
    assert_eq!(&data[0..2], &[0u8; 2], "leading hole must be zero");
    assert_eq!(&data[2..5], b"ABC", "extent data must be present");
    assert_eq!(&data[5..10], &[0u8; 5], "trailing hole must be zero");
}

/// Leading + middle + trailing holes.
///
/// ```text
/// Uncompressed Size: 12
/// Sparse Map: offset=2, length=3 | offset=8, length=2
/// Stored Payload: ABCDE
/// Expected: 00 00 A B C 00 00 00 D E 00 00
/// ```
#[test]
fn scatter_gather_leading_middle_trailing_holes_spec_vector() {
    let payload = b"ABCDE";
    let extents = [
        SparseExtent {
            offset: 2,
            length: 3,
        },
        SparseExtent {
            offset: 8,
            length: 2,
        },
    ];
    let archive = build_sparse_archive("f.bin", payload, &extents, 12);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(data.len(), 12, "final size must equal Uncompressed Size");
    assert_eq!(&data[0..2], &[0u8; 2]);
    assert_eq!(&data[2..5], b"ABC");
    assert_eq!(&data[5..8], &[0u8; 3]);
    assert_eq!(&data[8..10], b"DE");
    assert_eq!(&data[10..12], &[0u8; 2]);
}

/// Final reconstructed size equals exactly LFH `Uncompressed Size`.
#[test]
fn final_size_equals_uncompressed_size() {
    // Payload data fills only the first 4 bytes; logical file is 20 bytes.
    let payload = b"DATA";
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let archive = build_sparse_archive("f.bin", payload, &extents, 20);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files[0].data.len(), 20);
    assert_eq!(&files[0].data[0..4], b"DATA");
    assert_eq!(&files[0].data[4..], &[0u8; 16]);
}

/// Multiple extents consume stored payload sequentially.
#[test]
fn multiple_extents_consume_payload_sequentially() {
    // Payload "AABBCC" mapped through three extents in ascending offset order.
    // Per spec, extents must be sorted by offset ascending.
    let payload = b"AABBCC";
    let extents = [
        SparseExtent {
            offset: 0,
            length: 2,
        }, // "AA" at [0,2)
        SparseExtent {
            offset: 4,
            length: 2,
        }, // "BB" at [4,6)
        SparseExtent {
            offset: 10,
            length: 2,
        }, // "CC" at [10,12)
    ];
    let archive = build_sparse_archive("f.bin", payload, &extents, 12);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    let data = &files[0].data;
    assert_eq!(data.len(), 12);
    // Payload consumed sequentially: AA→[0,2), BB→[4,6), CC→[10,12).
    assert_eq!(&data[0..2], b"AA");
    assert_eq!(&data[4..6], b"BB");
    assert_eq!(&data[10..12], b"CC");
    // holes
    assert_eq!(&data[2..4], &[0u8; 2]);
    assert_eq!(&data[6..10], &[0u8; 4]);
}

/// Payload too short for declared extent lengths → error.
#[test]
fn too_short_payload_fails_during_extraction() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
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
        length: 8,
    }];
    let sparse_map = write_sparse_map(&extents, false);
    let payload = b"ABCD"; // only 4 bytes but extent claims 8

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = 8;
    lfh.sparse_map = sparse_map;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::Truncated(_)),
        "expected Truncated, got {err:?}"
    );
}

/// Payload has more bytes than declared extent lengths → error.
#[test]
fn excess_payload_fails_during_extraction() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
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
    let sparse_map = write_sparse_map(&extents, false);
    let payload = b"ABCDE"; // 5 bytes but only 3 consumed by extents

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = 10;
    lfh.sparse_map = sparse_map;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap for excess payload, got {err:?}"
    );
}

/// Invalid bounds: extent end > Uncompressed Size.
///
/// ```text
/// Uncompressed Size: 10
/// Sparse Map: offset=8, length=3  (end=11 > 10)
/// Expected: SAR_ERR_INVALID_MAP
/// ```
#[test]
fn extent_beyond_logical_size_returns_invalid_map() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let extents = [SparseExtent {
        offset: 8,
        length: 3,
    }]; // end = 11 > uncompressed_size = 10
    let sparse_map = write_sparse_map(&extents, false);
    let payload = b"ABC";

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = 10;
    lfh.sparse_map = sparse_map;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

/// Sparse reconstruction does not allocate beyond `max_decoded_entry_size`.
#[test]
fn sparse_allocation_bounded_by_max_size() {
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    // uncompressed_size = 2_000_000 far exceeds cap of 512
    let archive = build_sparse_archive("f.bin", b"ABCD", &extents, 2_000_000);
    let mut reader = ArchiveReader::with_options(
        Cursor::new(archive),
        ArchiveReaderOptions {
            limits: sar_core::limits::ResourceLimits {
                max_decoded_entry_size: 512,
                ..sar_core::limits::ResourceLimits::default()
            , delta_base: None },
        },
    )
    .expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §3 Sparse + compression
// ---------------------------------------------------------------------------

/// Compressed sparse entry: decompression happens before scatter-gather.
///
/// Uses ArchiveWriter with deflate compression and manually sets the sparse
/// map on the resulting archive by rebuilding the LFH.
///
/// Simpler approach: write a known compressed payload and build the archive
/// manually with the compressed bytes as the stored payload.
#[test]
fn sparse_with_compression_decompresses_then_scatters() {
    // We need to build a compressed sparse archive manually.
    // The compressed payload is the deflate encoding of b"ABCDE" (5 bytes).
    // Extents: offset=2,len=3 | offset=8,len=2 → logical size 12.
    use sar_compression::{CompressionOptions, encode_stream};
    use std::io::Cursor as IoCursor;

    let sparse_payload = b"ABCDE";
    let extents = [
        SparseExtent {
            offset: 2,
            length: 3,
        },
        SparseExtent {
            offset: 8,
            length: 2,
        },
    ];
    let sparse_map_bytes = write_sparse_map(&extents, false);

    // Compress the sparse payload.
    let mut compressed = Vec::new();
    encode_stream(
        0x01, // DEFLATE
        &mut IoCursor::new(sparse_payload),
        &mut compressed,
        CompressionOptions { level: None },
    )
    .expect("compress");

    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::COMPRESSED | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    let mut lfh = LocalFileHeader::minimal_store(b"sparse.bin".to_vec(), compressed.len() as u64);
    lfh.comp_algo_id = Some(0x01); // DEFLATE
    lfh.entry_mode = EntryMode::from_bits(1u16 << 3); // IS_COMPRESSED
    lfh.uncompressed_size = 12; // logical file size
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(&compressed);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(data.len(), 12);
    assert_eq!(&data[0..2], &[0u8; 2]);
    assert_eq!(&data[2..5], b"ABC");
    assert_eq!(&data[5..8], &[0u8; 3]);
    assert_eq!(&data[8..10], b"DE");
    assert_eq!(&data[10..12], &[0u8; 2]);
}

/// Sparse descriptor lengths apply to decompressed bytes, not compressed bytes.
///
/// Verify that after decompression the extent lengths match.
#[test]
fn sparse_descriptor_lengths_apply_to_decompressed_bytes() {
    use sar_compression::{CompressionOptions, encode_stream};
    use std::io::Cursor as IoCursor;

    // Single extent: offset=0, length=5 — entire payload.
    let sparse_payload = b"HELLO";
    let extents = [SparseExtent {
        offset: 0,
        length: 5,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false);

    let mut compressed = Vec::new();
    encode_stream(
        0x01,
        &mut IoCursor::new(sparse_payload),
        &mut compressed,
        CompressionOptions { level: None },
    )
    .expect("compress");

    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::COMPRESSED | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), compressed.len() as u64);
    lfh.comp_algo_id = Some(0x01);
    lfh.entry_mode = EntryMode::from_bits(1u16 << 3);
    lfh.uncompressed_size = 5; // logical size == data size (no holes)
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(&compressed);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files[0].data, b"HELLO");
}

/// Sparse map does not reference compressed byte offsets: a corrupted
/// compressed stream must fail before scatter-gather.
#[test]
fn corrupted_compressed_sparse_fails_before_scatter_gather() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::COMPRESSED | GlobalFlags::NO_INDEX;
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
        length: 5,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false);
    let corrupted = b"\xFF\xFF\xFF\xFF\xFF"; // not valid DEFLATE

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), corrupted.len() as u64);
    lfh.comp_algo_id = Some(0x01);
    lfh.entry_mode = EntryMode::from_bits(1u16 << 3);
    lfh.uncompressed_size = 5;
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(corrupted);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    // Must be a decompression error, not an InvalidMap or wrong data.
    assert!(
        matches!(
            err,
            SarError::DecompressionFailed(_) | SarError::InvalidLength(_) | SarError::Io(_)
        ),
        "expected decompression error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §5 Sparse + fragmentation — ordering tests
// ---------------------------------------------------------------------------

/// Fragment reassembly happens before sparse reconstruction (§13.7.6 / §19.6).
///
/// A two-fragment sparse file:
/// * Fragment 0: payload b"AAB", absolute_offset=0, fragment_size=3.
///   Carries the Sparse Map and the full logical file size in `uncompressed_size`.
/// * Fragment 1: payload b"BCC", absolute_offset=3, fragment_size=3.  No sparse map.
///
/// After reassembly the gathered payload is b"AABBCC" (6 bytes).
/// Sparse map: offset=0,len=2 | offset=4,len=2 | offset=8,len=2.
/// Logical size (from fragment-0 `Uncompressed Size`): 10.
///
/// Expected reconstructed file (10 bytes):
/// ```text
/// AA 00 00 BB 00 00 CC 00
/// ```
/// → [A A 0 0 B B 0 0 C C]
#[test]
fn sparse_fragmentation_reassembly_before_scatter_gather() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Sparse map: offset=0,len=2 | offset=4,len=2 | offset=8,len=2.
    // Sum of lengths = 6 = assembled gathered payload length.
    // Full logical file size = 10 (includes hole regions).
    let extents = [
        SparseExtent {
            offset: 0,
            length: 2,
        },
        SparseExtent {
            offset: 4,
            length: 2,
        },
        SparseExtent {
            offset: 8,
            length: 2,
        },
    ];
    let sparse_map_bytes = write_sparse_map(&extents, false);

    // Fragment 0: first 3 bytes b"AAB" at absolute offset 0, fragment_size=3.
    // `uncompressed_size` = 10 = full logical file size including sparse holes.
    // Sparse map MUST be on fragment index 0 only.
    let mut lfh0 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 3);
    lfh0.uncompressed_size = 10; // full logical file size including holes
    lfh0.entry_mode = EntryMode::from_bits(1u16 << 5); // IS_FRAGMENT
    lfh0.fragment_id = Some(99);
    lfh0.fragment_index = Some(0);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 3,
    });
    lfh0.sparse_map = sparse_map_bytes.clone();
    archive.extend_from_slice(&write_lfh(&flags, &lfh0).expect("lfh0"));
    archive.extend_from_slice(b"AAB");

    // Fragment 1: next 3 bytes b"BCC" at absolute offset 3.
    // No sparse map (must not appear on non-zero fragment index).
    let mut lfh1 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 3);
    lfh1.uncompressed_size = 3;
    lfh1.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6)); // IS_FRAGMENT | LAST_FRAGMENT
    lfh1.fragment_id = Some(99);
    lfh1.fragment_index = Some(1);
    lfh1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 3,
        fragment_size: 3,
    });
    // No sparse map on fragment index != 0.
    archive.extend_from_slice(&write_lfh(&flags, &lfh1).expect("lfh1"));
    archive.extend_from_slice(b"BCC");

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "f.bin");

    // After fragment reassembly + sparse reconstruction, the final file is
    // 10 bytes with the three data regions scattered at offsets 0, 4, and 8.
    let data = &files[0].data;
    assert_eq!(data.len(), 10, "final size must equal logical_size = 10");
    assert_eq!(&data[0..2], b"AA", "extent [0,2) must contain AA");
    assert_eq!(&data[2..4], &[0u8; 2], "hole [2,4) must be zero");
    assert_eq!(&data[4..6], b"BB", "extent [4,6) must contain BB");
    assert_eq!(&data[6..8], &[0u8; 2], "hole [6,8) must be zero");
    assert_eq!(&data[8..10], b"CC", "extent [8,10) must contain CC");
}

/// Sparse Map alignment error (non-multiple of descriptor size) is detected.
#[test]
fn malformed_sparse_map_alignment_caught_during_read() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // 5 bytes is not a multiple of 8 (32-bit descriptor size).
    let bad_sparse_map = vec![0u8; 5];
    let payload = b"HELLO";

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
    lfh.uncompressed_size = 5;
    lfh.sparse_map = bad_sparse_map;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidLength(_) | SarError::InvalidMap(_)),
        "expected alignment error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §6 Sparse + loss-tolerant
// ---------------------------------------------------------------------------

/// Missing fragment without allow_lossy fails before sparse reconstruction.
#[test]
fn sparse_missing_fragment_without_allow_lossy_fails() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Only fragment 0; no LAST_FRAGMENT.
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.entry_mode = EntryMode::from_bits(1u16 << 5); // IS_FRAGMENT
    lfh.fragment_id = Some(77);
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

/// Missing fragment with allow_lossy and LOSS_TOLERANT: succeeds with
/// is_degraded = true; malformed sparse maps are still rejected.
#[test]
fn sparse_missing_fragment_with_allow_lossy_and_loss_tolerant_succeeds() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    // IS_FRAGMENT | LOSS_TOLERANT; no LAST_FRAGMENT.
    lfh.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 7));
    lfh.fragment_id = Some(78);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(true).expect("read");
    assert_eq!(files.len(), 1);
    assert!(
        files[0].is_degraded,
        "must be degraded with missing fragment"
    );
}

/// Loss-tolerant behavior does not suppress malformed sparse map errors.
#[test]
fn loss_tolerant_does_not_suppress_malformed_sparse_map() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Malformed sparse map (7 bytes, not multiple of 8).
    // LOSS_TOLERANT requires IS_FRAGMENT; use a plain non-fragment entry here
    // to test that allow_lossy=true still rejects format errors.
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 5);
    lfh.uncompressed_size = 5;
    lfh.sparse_map = vec![0u8; 7];
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"HELLO");

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // Even with allow_lossy=true, a malformed sparse map must fail.
    let err = reader
        .read_all_logical_files(true)
        .expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidLength(_) | SarError::InvalidMap(_)),
        "expected format error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §1 Sparse descriptor parsing — archive-level
// ---------------------------------------------------------------------------

/// 32-bit sparse map round-trips through archive encode/decode path.
#[test]
fn sparse_32bit_descriptor_parse_via_archive() {
    let extents = [
        SparseExtent {
            offset: 0,
            length: 4,
        },
        SparseExtent {
            offset: 8,
            length: 4,
        },
    ];
    let archive = build_sparse_archive("f.bin", b"DATAEXTS", &extents, 12);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let entry = reader
        .read_global_header()
        .and_then(|_| reader.next_entry())
        .expect("entry")
        .expect("some");
    let sparse = entry.metadata.sparse_extents.expect("sparse extents");
    assert_eq!(sparse.len(), 2);
    assert_eq!(sparse[0].offset, 0);
    assert_eq!(sparse[0].length, 4);
    assert_eq!(sparse[1].offset, 8);
    assert_eq!(sparse[1].length, 4);
}

/// 64-bit sparse map round-trips through archive encode/decode path.
#[test]
fn sparse_64bit_descriptor_parse_via_archive() {
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let archive = build_sparse_archive_64bit("f.bin", b"DATA", &extents, 4, true);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let entry = reader
        .read_global_header()
        .and_then(|_| reader.next_entry())
        .expect("entry")
        .expect("some");
    let sparse = entry.metadata.sparse_extents.expect("sparse extents");
    assert_eq!(sparse.len(), 1);
    assert_eq!(sparse[0].offset, 0);
    assert_eq!(sparse[0].length, 4);
}

/// Writer (ArchiveWriterOptions default) roundtrip for non-sparse entry still works.
#[test]
fn non_sparse_writer_roundtrip_unaffected() {
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
            name: "x.txt".into(),
            payload: b"hello".to_vec(),
        })
        .expect("add");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(out)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files[0].data, b"hello");
}
