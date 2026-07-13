// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_imports)]
//! Tests for sparse reconstruction across fragment groups (§13.7.6 / §19.6).
//!
//! Spec requirements tested:
//! * Sparse Map MUST appear only in fragment with Fragment Index = 0.
//! * Sparse Map on non-zero fragment index MUST return `SAR_ERR_INVALID_MAP`.
//! * Fragment reassembly happens before sparse reconstruction.
//! * The Sparse Map from fragment index 0 applies to the fully assembled group.
//! * Trailing holes after sparse reconstruction across fragments are zero-filled.
//! * Missing fragments fail without `allow_lossy`.
//! * Missing fragments with `allow_lossy` + `LOSS_TOLERANT` succeed (is_degraded=true).
//! * Degraded sparse+fragment output is clearly marked.

use std::io::Cursor;

use sar_archive::ArchiveReader;
use sar_core::{
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

/// Parameters for building a two-fragment sparse test archive.
struct TwoFragmentArchiveParams<'a> {
    name: &'a str,
    frag0_payload: &'a [u8],
    frag1_payload: &'a [u8],
    extents: &'a [SparseExtent],
    logical_size: u64,
    frag0_index: u32,
    frag1_index: u32,
    frag1_is_last: bool,
    frag0_loss_tolerant: bool,
    frag1_loss_tolerant: bool,
    frag0_has_sparse_map: bool,
    frag1_has_sparse_map: bool,
}

/// Build a two-fragment sparse archive.
///
/// Fragment 0 carries the sparse map and the full logical size in
/// `uncompressed_size`.  Fragment 1 carries no sparse map.
///
/// The extents describe the fully reassembled logical payload.
fn build_two_fragment_sparse_archive(p: TwoFragmentArchiveParams<'_>) -> Vec<u8> {
    let TwoFragmentArchiveParams {
        name,
        frag0_payload,
        frag1_payload,
        extents,
        logical_size,
        frag0_index,
        frag1_index,
        frag1_is_last,
        frag0_loss_tolerant,
        frag1_loss_tolerant,
        frag0_has_sparse_map,
        frag1_has_sparse_map,
    } = p;
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let sparse_map_bytes = write_sparse_map(extents, false).expect("write sparse map ok");

    // Fragment 0
    let mut mode0 = 1u16 << 5; // IS_FRAGMENT
    if frag0_loss_tolerant {
        mode0 |= 1u16 << 7;
    }
    let mut lfh0 =
        LocalFileHeader::minimal_store(name.as_bytes().to_vec(), frag0_payload.len() as u64);
    // uncompressed_size = logical_size only when frag0 carries the sparse map;
    // otherwise set it to the actual fragment payload length so the reader's
    // size check (payload len == uncompressed_size for non-sparse entries) passes.
    lfh0.uncompressed_size = if frag0_has_sparse_map {
        logical_size
    } else {
        frag0_payload.len() as u64
    };
    lfh0.entry_mode = EntryMode::from_bits(mode0);
    lfh0.fragment_id = Some(42);
    lfh0.fragment_index = Some(frag0_index);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: frag0_payload.len() as u32,
    });
    if frag0_has_sparse_map {
        lfh0.sparse_map = sparse_map_bytes.clone();
    }
    archive.extend_from_slice(&write_lfh(&flags, &lfh0).expect("lfh0"));
    archive.extend_from_slice(frag0_payload);

    // Fragment 1
    let mut mode1 = 1u16 << 5; // IS_FRAGMENT
    if frag1_is_last {
        mode1 |= 1u16 << 6;
    }
    if frag1_loss_tolerant {
        mode1 |= 1u16 << 7;
    }
    let mut lfh1 =
        LocalFileHeader::minimal_store(name.as_bytes().to_vec(), frag1_payload.len() as u64);
    // Similarly, set logical_size only when frag1 carries the sparse map.
    lfh1.uncompressed_size = if frag1_has_sparse_map {
        logical_size
    } else {
        frag1_payload.len() as u64
    };
    lfh1.entry_mode = EntryMode::from_bits(mode1);
    lfh1.fragment_id = Some(42);
    lfh1.fragment_index = Some(frag1_index);
    lfh1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: frag0_payload.len() as u64,
        fragment_size: frag1_payload.len() as u32,
    });
    if frag1_has_sparse_map {
        lfh1.sparse_map = sparse_map_bytes.clone();
    }
    archive.extend_from_slice(&write_lfh(&flags, &lfh1).expect("lfh1"));
    archive.extend_from_slice(frag1_payload);

    archive
}

// ---------------------------------------------------------------------------
// §1 Sparse Map on fragment index 0 applies to entire reassembled group
// ---------------------------------------------------------------------------

/// Sparse Map on fragment index 0 is applied to the fully assembled payload.
///
/// Assembled payload: b"XXYY" (4 bytes).
/// Extents: offset=0,len=2 | offset=6,len=2 → logical size 8.
/// Expected: [X X 0 0 0 0 Y Y]
#[test]
fn sparse_map_from_fragment_index_0_applies_to_full_group() {
    let extents = [
        SparseExtent {
            offset: 0,
            length: 2,
        },
        SparseExtent {
            offset: 6,
            length: 2,
        },
    ];
    // Assembled payload b"XXYY": frag0=b"XX", frag1=b"YY"
    let archive = build_two_fragment_sparse_archive(TwoFragmentArchiveParams {
        name: "f.bin",
        frag0_payload: b"XX",
        frag1_payload: b"YY",
        extents: &extents,
        logical_size: 8,
        frag0_index: 0,
        frag1_index: 1,
        frag1_is_last: true,
        frag0_loss_tolerant: false,
        frag1_loss_tolerant: false,
        frag0_has_sparse_map: true,
        frag1_has_sparse_map: false,
    });
    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(data.len(), 8, "final size must be logical_size = 8");
    assert_eq!(&data[0..2], b"XX");
    assert_eq!(&data[2..6], &[0u8; 4], "holes must be zero");
    assert_eq!(&data[6..8], b"YY");
}

// ---------------------------------------------------------------------------
// §2 Sparse Map on non-zero fragment index must return SAR_ERR_INVALID_MAP
// ---------------------------------------------------------------------------

/// Sparse Map on fragment index 1 (non-zero) must return SAR_ERR_INVALID_MAP.
#[test]
fn sparse_map_on_nonzero_fragment_index_returns_invalid_map() {
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    // frag0 has no sparse map; frag1 has it (invalid placement)
    let archive = build_two_fragment_sparse_archive(TwoFragmentArchiveParams {
        name: "f.bin",
        frag0_payload: b"ABCD",
        frag1_payload: b"EFGH",
        extents: &extents,
        logical_size: 8,
        frag0_index: 0,
        frag1_index: 1,
        frag1_is_last: true,
        frag0_loss_tolerant: false,
        frag1_loss_tolerant: false,
        frag0_has_sparse_map: false,
        frag1_has_sparse_map: true,
    });
    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail with sparse map on non-zero fragment");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected SAR_ERR_INVALID_MAP, got {err:?}"
    );
}

/// Sparse Map on fragment index 2 (non-zero) must return SAR_ERR_INVALID_MAP,
/// even with allow_lossy = true.
#[test]
fn sparse_map_on_nonzero_fragment_not_suppressed_by_allow_lossy() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
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
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    // Only fragment index 1 with a sparse map (no fragment index 0 present)
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.uncompressed_size = 4;
    lfh.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6)); // IS_FRAGMENT | LAST_FRAGMENT
    lfh.fragment_id = Some(55);
    lfh.fragment_index = Some(1); // non-zero index with sparse map
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // allow_lossy=true must not suppress the invalid-map error
    let err = reader
        .read_all_logical_files(true)
        .expect_err("should fail regardless of allow_lossy");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected SAR_ERR_INVALID_MAP even with allow_lossy, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §3 Reassembled payload scattered by group sparse map
// ---------------------------------------------------------------------------

/// Three-fragment sparse file: assembled payload b"AABBCC" (6 bytes).
/// Sparse extents scatter the 6 bytes into a 12-byte logical file.
#[test]
fn reassembled_three_fragment_payload_scattered_by_sparse_map() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Assembled payload b"AABBCC"; extents scatter into 12-byte logical file:
    // [0,2)=AA, [4,2)=BB, [8,2)=CC   → holes at [2,4) and [6,8) and [10,12)
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
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    // Fragment 0: b"AA" at offset 0
    let mut lfh0 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
    lfh0.uncompressed_size = 12; // logical file size
    lfh0.entry_mode = EntryMode::from_bits(1u16 << 5);
    lfh0.fragment_id = Some(10);
    lfh0.fragment_index = Some(0);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 2,
    });
    lfh0.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh0).expect("lfh0"));
    archive.extend_from_slice(b"AA");

    // Fragment 1: b"BB" at offset 2
    let mut lfh1 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
    lfh1.uncompressed_size = 2;
    lfh1.entry_mode = EntryMode::from_bits(1u16 << 5);
    lfh1.fragment_id = Some(10);
    lfh1.fragment_index = Some(1);
    lfh1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 2,
        fragment_size: 2,
    });
    archive.extend_from_slice(&write_lfh(&flags, &lfh1).expect("lfh1"));
    archive.extend_from_slice(b"BB");

    // Fragment 2: b"CC" at offset 4 (last)
    let mut lfh2 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
    lfh2.uncompressed_size = 2;
    lfh2.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6));
    lfh2.fragment_id = Some(10);
    lfh2.fragment_index = Some(2);
    lfh2.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 4,
        fragment_size: 2,
    });
    archive.extend_from_slice(&write_lfh(&flags, &lfh2).expect("lfh2"));
    archive.extend_from_slice(b"CC");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(data.len(), 12, "final logical size must be 12");
    assert_eq!(&data[0..2], b"AA");
    assert_eq!(&data[2..4], &[0u8; 2], "hole [2,4) must be zero");
    assert_eq!(&data[4..6], b"BB");
    assert_eq!(&data[6..8], &[0u8; 2], "hole [6,8) must be zero");
    assert_eq!(&data[8..10], b"CC");
    assert_eq!(
        &data[10..12],
        &[0u8; 2],
        "trailing hole [10,12) must be zero"
    );
}

// ---------------------------------------------------------------------------
// §4 Trailing holes after sparse reconstruction across fragments
// ---------------------------------------------------------------------------

/// Trailing hole after the last sparse extent is zero-filled up to logical_size.
///
/// Assembled payload b"DATA" (4 bytes).
/// Extent: offset=0, length=4.
/// Logical size = 10 (trailing hole [4,10) = 6 zero bytes).
#[test]
fn sparse_fragment_trailing_hole_preserved() {
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let archive = build_two_fragment_sparse_archive(TwoFragmentArchiveParams {
        name: "f.bin",
        frag0_payload: b"DA",
        frag1_payload: b"TA",
        extents: &extents,
        logical_size: 10,
        frag0_index: 0,
        frag1_index: 1,
        frag1_is_last: true,
        frag0_loss_tolerant: false,
        frag1_loss_tolerant: false,
        frag0_has_sparse_map: true,
        frag1_has_sparse_map: false,
    });
    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    let data = &files[0].data;
    assert_eq!(data.len(), 10, "logical size must be 10");
    assert_eq!(&data[0..4], b"DATA");
    assert_eq!(&data[4..10], &[0u8; 6], "trailing hole must be zero");
}

// ---------------------------------------------------------------------------
// §5 Missing fragment behavior
// ---------------------------------------------------------------------------

/// Missing fragment without allow_lossy fails with SAR_ERR_FRAGMENT_GAP.
/// Sparse is irrelevant; the error must occur before reconstruction.
#[test]
fn sparse_fragment_missing_without_allow_lossy_fails() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
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
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    // Only fragment 0, no LAST_FRAGMENT marker (missing fragment 1)
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.uncompressed_size = 8; // logical size
    lfh.entry_mode = EntryMode::from_bits(1u16 << 5); // IS_FRAGMENT only
    lfh.fragment_id = Some(11);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("must fail without allow_lossy");
    assert!(
        matches!(err, SarError::FragmentGap(_)),
        "expected SAR_ERR_FRAGMENT_GAP, got {err:?}"
    );
}

/// Missing fragment with allow_lossy + LOSS_TOLERANT succeeds; output is degraded.
#[test]
fn sparse_fragment_missing_with_allow_lossy_loss_tolerant_succeeds() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
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
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    // Only fragment 0, LOSS_TOLERANT, no LAST_FRAGMENT
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.uncompressed_size = 8; // logical size
    // IS_FRAGMENT | LOSS_TOLERANT
    lfh.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 7));
    lfh.fragment_id = Some(12);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader
        .read_all_logical_files(true)
        .expect("degraded output is allowed");
    assert_eq!(files.len(), 1);
    assert!(
        files[0].is_degraded,
        "output must be marked degraded when fragment is missing"
    );
    // Sparse reconstruction is applied over the degraded assembled payload.
    // Fragment 0 placed b"ABCD" at offset 0; sparse extent {0,4} maps it to
    // output[0..4]. Remaining bytes (0..8 in logical file) are zero or from
    // placed fragments.
    let data = &files[0].data;
    assert_eq!(
        data.len(),
        8,
        "logical size must be 8 even for degraded output"
    );
    assert_eq!(&data[0..4], b"ABCD", "present fragment data must appear");
}

/// Degraded output is clearly marked (is_degraded = true) for sparse+fragment.
#[test]
fn sparse_fragment_degraded_output_is_marked() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
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
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    // Fragment index 0 with LOSS_TOLERANT; no other fragment present
    let mut lfh = LocalFileHeader::minimal_store(b"sparse.bin".to_vec(), 3);
    lfh.uncompressed_size = 10;
    lfh.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 7)); // IS_FRAGMENT | LOSS_TOLERANT
    lfh.fragment_id = Some(99);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 3,
    });
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABC");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(true).expect("read");
    assert_eq!(files.len(), 1);
    assert!(
        files[0].is_degraded,
        "sar_archive::LogicalFile::is_degraded must be true for degraded sparse+fragment output"
    );
}
