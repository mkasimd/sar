// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_imports)]
//! Tests for sparse reconstruction across fragment groups (§13.7.6 / §19.6).
//!
//! Spec requirements tested:
//! * Sparse Map MUST appear only in fragment with Fragment Index = 0.
//! * Sparse Map on non-zero fragment index MUST return `SAR_ERR_METADATA_CONFLICT`.
//! * Fragment reassembly happens before sparse reconstruction.
//! * The Sparse Map from fragment index 0 applies to the fully assembled group.
//! * Trailing holes after sparse reconstruction across fragments are zero-filled.
//! * Missing fragments fail without `allow_lossy`.
//! * Incomplete sparse groups return `SAR_ERR_FRAGMENT_GAP`, including with
//!   `allow_lossy` + `LOSS_TOLERANT`; no degraded sparse output is produced.
//! * Fragment `Uncompressed Size` is the contribution length; the final size is
//!   the Sparse Logical Size carried by the Sparse Map.

use std::io::Cursor;

use sar_archive::ArchiveReader;
use sar_core::{
    GlobalFlags, SarError,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
    sparse::{SparseExtent, SparseMap, write_sparse_map},
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
/// Fragment 0 carries the complete Sparse Map (including the Sparse Logical
/// Size).  Each fragment's `Uncompressed Size` is its own contribution length.
/// Fragment 1 carries no sparse map.
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
        flags,
        kms: None,
    })
    .expect("header");

    let sparse_map_bytes = write_sparse_map(
        &SparseMap {
            logical_size,
            extents: extents.to_vec(),
        },
        false,
    )
    .expect("write sparse map ok");

    // Fragment 0
    let mut mode0 = 1u16 << 5; // IS_FRAGMENT
    if frag0_loss_tolerant {
        mode0 |= 1u16 << 7;
    }
    let mut lfh0 =
        LocalFileHeader::minimal_store(name.as_bytes().to_vec(), frag0_payload.len() as u64);
    lfh0.entry_mode = EntryMode::from_bits(mode0);
    lfh0.fragment_id = Some(42);
    lfh0.fragment_index = Some(frag0_index);
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
    lfh1.entry_mode = EntryMode::from_bits(mode1);
    lfh1.fragment_id = Some(42);
    lfh1.fragment_index = Some(frag1_index);
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
// §2 Sparse Map on non-zero fragment index must return SAR_ERR_METADATA_CONFLICT
// ---------------------------------------------------------------------------

/// Sparse Map on fragment index 1 (non-zero) must return SAR_ERR_METADATA_CONFLICT.
#[test]
fn sparse_map_on_nonzero_fragment_index_returns_metadata_conflict() {
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
        matches!(err, SarError::MetadataConflict(_)),
        "expected SAR_ERR_METADATA_CONFLICT, got {err:?}"
    );
}

/// Sparse Map on fragment index 2 (non-zero) must return SAR_ERR_METADATA_CONFLICT,
/// even with allow_lossy = true.
#[test]
fn sparse_map_on_nonzero_fragment_not_suppressed_by_allow_lossy() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");

    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(
        &sar_core::sparse::SparseMap {
            logical_size: 4,
            extents: extents.to_vec(),
        },
        false,
    )
    .expect("write sparse map ok");

    // Only fragment index 1 with a sparse map (no fragment index 0 present)
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.uncompressed_size = 4;
    lfh.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6)); // IS_FRAGMENT | LAST_FRAGMENT
    lfh.fragment_id = Some(55);
    lfh.fragment_index = Some(1); // non-zero index with sparse map
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(b"ABCD");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // allow_lossy=true must not suppress the invalid-map error
    let err = reader
        .read_all_logical_files(true)
        .expect_err("should fail regardless of allow_lossy");
    assert!(
        matches!(err, SarError::MetadataConflict(_)),
        "expected SAR_ERR_METADATA_CONFLICT even with allow_lossy, got {err:?}"
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
        flags,
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
    let sparse_map_bytes = write_sparse_map(
        &sar_core::sparse::SparseMap {
            logical_size: 12,
            extents: extents.to_vec(),
        },
        false,
    )
    .expect("write sparse map ok");

    // Fragment 0: b"AA" at offset 0
    let mut lfh0 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
    lfh0.entry_mode = EntryMode::from_bits(1u16 << 5);
    lfh0.fragment_id = Some(10);
    lfh0.fragment_index = Some(0);
    lfh0.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh0).expect("lfh0"));
    archive.extend_from_slice(b"AA");

    // Fragment 1: b"BB" at offset 2
    let mut lfh1 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
    lfh1.entry_mode = EntryMode::from_bits(1u16 << 5);
    lfh1.fragment_id = Some(10);
    lfh1.fragment_index = Some(1);
    archive.extend_from_slice(&write_lfh(&flags, &lfh1).expect("lfh1"));
    archive.extend_from_slice(b"BB");

    // Fragment 2: b"CC" at offset 4 (last)
    let mut lfh2 = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
    lfh2.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6));
    lfh2.fragment_id = Some(10);
    lfh2.fragment_index = Some(2);
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
        flags,
        kms: None,
    })
    .expect("header");

    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(
        &sar_core::sparse::SparseMap {
            logical_size: 8,
            extents: extents.to_vec(),
        },
        false,
    )
    .expect("write sparse map ok");

    // Only fragment 0, no LAST_FRAGMENT marker (missing fragment 1)
    let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
    lfh.entry_mode = EntryMode::from_bits(1u16 << 5); // IS_FRAGMENT only
    lfh.fragment_id = Some(11);
    lfh.fragment_index = Some(0);
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

/// An incomplete fragmented sparse group fails with SAR_ERR_FRAGMENT_GAP even
/// with `allow_lossy` and `LOSS_TOLERANT`; no degraded sparse file is emitted
/// (spec 19.4.5).
#[test]
fn sparse_fragment_missing_with_allow_lossy_loss_tolerant_is_fragment_gap() {
    for allow_lossy in [false, true] {
        let flags =
            GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
        let mut archive = write_global_header(&GlobalHeader {
            version: 1,
            flags,
            kms: None,
        })
        .expect("header");
        let map = SparseMap {
            logical_size: 8,
            extents: vec![SparseExtent {
                offset: 0,
                length: 4,
            }],
        };
        // Only fragment 0, IS_FRAGMENT | LOSS_TOLERANT, no LAST_FRAGMENT.
        let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
        lfh.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 7));
        lfh.fragment_id = Some(12);
        lfh.fragment_index = Some(0);
        lfh.sparse_map = write_sparse_map(&map, false).expect("map");
        archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        archive.extend_from_slice(b"ABCD");

        let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
        let result = reader.read_all_logical_files(allow_lossy);
        assert!(
            matches!(result, Err(SarError::FragmentGap(_))),
            "allow_lossy={allow_lossy}: expected FragmentGap, got {:?}",
            result.map(|f| f.len())
        );
    }
}

/// A missing middle fragment (non-terminal gap) is also a FragmentGap for a
/// sparse group, never a degraded sparse file.
#[test]
fn sparse_fragment_missing_middle_is_fragment_gap() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    let map = SparseMap {
        logical_size: 8,
        extents: vec![SparseExtent {
            offset: 0,
            length: 4,
        }],
    };
    // Fragments 0 and 2 (last) present; fragment 1 missing.
    for (idx, payload) in [(0u32, &b"AB"[..]), (2, &b"CD"[..])] {
        let mut mode = (1u16 << 5) | (1u16 << 7);
        if idx == 2 {
            mode |= 1u16 << 6;
        }
        let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 2);
        lfh.entry_mode = EntryMode::from_bits(mode);
        lfh.fragment_id = Some(13);
        lfh.fragment_index = Some(idx);
        if idx == 0 {
            lfh.sparse_map = write_sparse_map(&map, false).expect("map");
        }
        archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        archive.extend_from_slice(payload);
    }
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let result = reader.read_all_logical_files(true);
    assert!(
        matches!(result, Err(SarError::FragmentGap(_))),
        "expected FragmentGap, got {:?}",
        result.map(|f| f.len())
    );
}

// ---------------------------------------------------------------------------
// Canonical fragmented sparse reconstruction (WP-5, spec 6.1.3 / 17.2)
// ---------------------------------------------------------------------------

/// Build a canonical two-fragment archive: each LFH `Uncompressed Size` is the
/// fragment's decoded contribution length; fragment 0 carries the Sparse Map.
fn build_canonical_sparse_fragment_archive(
    frag0: &[u8],
    frag1: &[u8],
    map: &SparseMap,
    is_64bit: bool,
    loss_tolerant: bool,
) -> Vec<u8> {
    let mut flags =
        GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    if is_64bit {
        flags |= GlobalFlags::SIZE_64BIT;
    }
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    let lt = if loss_tolerant { 1u16 << 7 } else { 0 };
    for (idx, payload) in [frag0, frag1].into_iter().enumerate() {
        let mut mode = (1u16 << 5) | lt;
        if idx == 1 {
            mode |= 1u16 << 6;
        }
        let len = u64::try_from(payload.len()).expect("len");
        let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), len);
        lfh.entry_mode = EntryMode::from_bits(mode);
        lfh.fragment_id = Some(42);
        lfh.fragment_index = Some(u32::try_from(idx).expect("idx"));
        if idx == 0 {
            lfh.sparse_map = write_sparse_map(map, is_64bit).expect("sparse map");
        }
        archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        archive.extend_from_slice(payload);
    }
    archive
}

fn ext(offset: u64, length: u64) -> SparseExtent {
    SparseExtent { offset, length }
}

fn read_one(archive: Vec<u8>, allow_lossy: bool) -> Result<Vec<u8>, SarError> {
    let mut reader = ArchiveReader::new(Cursor::new(archive))?;
    let mut files = reader.read_all_logical_files(allow_lossy)?;
    assert_eq!(files.len(), 1);
    Ok(files.remove(0).data)
}

/// Fragment-local contribution lengths never determine the logical size; the
/// Sparse Logical Size does, for 32-bit and 64-bit maps, with leading, interior,
/// trailing holes, all-hole entries and an empty terminal contribution.
#[test]
fn canonical_fragmented_sparse_group_reconstructs_with_sparse_logical_size() {
    // (frag0, frag1, logical_size, extents, expected)
    type Case = (
        &'static [u8],
        &'static [u8],
        u64,
        Vec<SparseExtent>,
        Vec<u8>,
    );
    let cases: Vec<Case> = vec![
        // interior + trailing hole
        (
            b"XX",
            b"YY",
            10,
            vec![ext(0, 2), ext(6, 2)],
            b"XX\0\0\0\0YY\0\0".to_vec(),
        ),
        // leading hole
        (
            b"XX",
            b"YY",
            8,
            vec![ext(2, 2), ext(4, 2)],
            b"\0\0XXYY\0\0".to_vec(),
        ),
        // fully populated
        (b"XX", b"YY", 4, vec![ext(0, 4)], b"XXYY".to_vec()),
        // empty terminal contribution
        (b"XX", b"", 5, vec![ext(1, 2)], b"\0XX\0\0".to_vec()),
        // empty extent list: all-hole entry, empty contributions
        (b"", b"", 6, vec![], vec![0u8; 6]),
        // zero logical size
        (b"", b"", 0, vec![], vec![]),
    ];
    for is_64bit in [false, true] {
        for (frag0, frag1, logical_size, extents, expected) in &cases {
            let map = SparseMap {
                logical_size: *logical_size,
                extents: extents.clone(),
            };
            let archive =
                build_canonical_sparse_fragment_archive(frag0, frag1, &map, is_64bit, false);
            let got = read_one(archive, false).unwrap_or_else(|e| {
                panic!("64bit={is_64bit} size={logical_size} extents={extents:?}: {e:?}")
            });
            assert_eq!(&got, expected, "64bit={is_64bit} extents={extents:?}");
        }
    }
}

/// Sparse reconstruction output is identical regardless of how the gathered
/// bytes are split across fragments.
#[test]
fn sparse_fragment_split_point_does_not_change_output() {
    let map = SparseMap {
        logical_size: 9,
        extents: vec![ext(1, 3), ext(6, 2)],
    };
    let gathered = b"ABCDE";
    let expected = b"\0ABC\0\0DE\0".to_vec();
    for split in 0..=gathered.len() {
        let archive = build_canonical_sparse_fragment_archive(
            &gathered[..split],
            &gathered[split..],
            &map,
            false,
            false,
        );
        assert_eq!(read_one(archive, false).expect("read"), expected, "{split}");
    }
}

/// Σ contribution lengths must equal Σ extent lengths (SAR_ERR_INVALID_LENGTH),
/// independent of `allow_lossy`.
#[test]
fn sparse_fragment_gathered_length_mismatch_is_invalid_length() {
    let map = SparseMap {
        logical_size: 8,
        extents: vec![ext(0, 4)],
    };
    for (f0, f1) in [(&b"XX"[..], &b"Y"[..]), (b"XX", b"YYY")] {
        for allow_lossy in [false, true] {
            let archive = build_canonical_sparse_fragment_archive(f0, f1, &map, false, true);
            let err = read_one(archive, allow_lossy).expect_err("mismatch");
            assert!(
                matches!(err, SarError::InvalidLength(_)),
                "allow_lossy={allow_lossy}: expected InvalidLength, got {err:?}"
            );
        }
    }
}

/// Malformed maps and extents in a complete group keep their statuses.
#[test]
fn sparse_fragment_invalid_map_statuses() {
    // extent end beyond logical size
    let map = SparseMap {
        logical_size: 3,
        extents: vec![ext(0, 4)],
    };
    let archive = build_canonical_sparse_fragment_archive(b"XX", b"YY", &map, false, false);
    assert!(matches!(
        read_one(archive, false),
        Err(SarError::InvalidMap(_))
    ));

    // overlapping extents
    let map = SparseMap {
        logical_size: 8,
        extents: vec![ext(0, 3), ext(2, 1)],
    };
    let archive = build_canonical_sparse_fragment_archive(b"XX", b"YY", &map, false, false);
    assert!(matches!(
        read_one(archive, false),
        Err(SarError::InvalidMap(_))
    ));
}

/// The Sparse Logical Size is checked against `max_decoded_entry_size`.
#[test]
fn sparse_fragment_logical_size_limit_is_enforced() {
    let map = SparseMap {
        logical_size: 1_000_000,
        extents: vec![ext(0, 4)],
    };
    let archive = build_canonical_sparse_fragment_archive(b"XX", b"YY", &map, false, false);
    let mut reader = ArchiveReader::with_options(
        Cursor::new(archive),
        sar_archive::ArchiveReaderOptions {
            limits: sar_core::limits::ResourceLimits {
                max_decoded_entry_size: 512,
                ..sar_core::limits::ResourceLimits::default()
            },
            delta_base: None,
        },
    )
    .expect("reader");
    let result = reader.read_all_logical_files(false);
    assert!(
        matches!(result, Err(SarError::LimitExceeded(_))),
        "expected LimitExceeded, got {:?}",
        result.map(|f| f.len())
    );
}

/// Index-0 authority: a Sparse Map on a later fragment is METADATA_CONFLICT
/// even when fragment 0 carries a valid map.
#[test]
fn sparse_fragment_later_map_conflicts_with_index_zero_map() {
    let archive = build_two_fragment_sparse_archive(TwoFragmentArchiveParams {
        name: "f.bin",
        frag0_payload: b"XX",
        frag1_payload: b"YY",
        extents: &[ext(0, 4)],
        logical_size: 4,
        frag0_index: 0,
        frag1_index: 1,
        frag1_is_last: true,
        frag0_loss_tolerant: false,
        frag1_loss_tolerant: false,
        frag0_has_sparse_map: true,
        frag1_has_sparse_map: true,
    });
    let result = read_one(archive, false);
    assert!(
        matches!(result, Err(SarError::MetadataConflict(_))),
        "expected MetadataConflict, got {result:?}"
    );
}

/// Terminal-fragment CRC32 is verified over the reconstructed logical bytes
/// (holes included), after sparse reconstruction.
#[test]
fn sparse_fragment_crc32_covers_reconstructed_bytes() {
    let map = SparseMap {
        logical_size: 8,
        extents: vec![ext(1, 2), ext(5, 1)],
    };
    let logical = b"\0XY\0\0Z\0\0".to_vec();
    let build = |crc: u32| {
        let flags = GlobalFlags::SPARSE_FILES
            | GlobalFlags::FILE_FRAGMENTATION
            | GlobalFlags::NO_INDEX
            | GlobalFlags::PER_FILE_CRC;
        let mut archive = write_global_header(&GlobalHeader {
            version: 1,
            flags,
            kms: None,
        })
        .expect("header");
        for (idx, payload) in [&b"XY"[..], &b"Z"[..]].into_iter().enumerate() {
            let mut mode = 1u16 << 5;
            if idx == 1 {
                mode |= 1u16 << 6;
            }
            let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
            lfh.entry_mode = EntryMode::from_bits(mode);
            lfh.fragment_id = Some(7);
            lfh.fragment_index = Some(idx as u32);
            if idx == 0 {
                lfh.sparse_map = write_sparse_map(&map, false).expect("map");
                lfh.file_crc32 = Some(0);
            } else {
                lfh.file_crc32 = Some(crc);
            }
            archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
            archive.extend_from_slice(payload);
        }
        archive
    };
    assert_eq!(
        read_one(build(crc32fast::hash(&logical)), false).expect("valid crc"),
        logical
    );
    // A CRC over the gathered bytes only (no holes) must fail.
    assert!(read_one(build(crc32fast::hash(b"XYZ")), false).is_err());
}

/// A fragmented sparse group that still requires a non-STORE patch stage fails
/// closed; the stage is never silently skipped.
#[test]
fn sparse_fragment_group_with_non_store_patch_is_unsupported() {
    let map = SparseMap {
        logical_size: 6,
        extents: vec![ext(0, 4)],
    };
    let flags = GlobalFlags::SPARSE_FILES
        | GlobalFlags::FILE_FRAGMENTATION
        | GlobalFlags::NO_INDEX
        | GlobalFlags::HAS_DELTA;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    for (idx, payload) in [&b"XX"[..], &b"YY"[..]].into_iter().enumerate() {
        let mut mode = 1u16 << 5;
        if idx == 1 {
            mode |= 1u16 << 6;
        }
        let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), payload.len() as u64);
        lfh.entry_mode = EntryMode::from_bits(mode);
        lfh.fragment_id = Some(8);
        lfh.fragment_index = Some(idx as u32);
        lfh.patch_algo_id = Some(0x01);
        lfh.delta_base_hash = Some([0u8; 32]);
        if idx == 0 {
            lfh.sparse_map = write_sparse_map(&map, false).expect("map");
        }
        archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        archive.extend_from_slice(payload);
    }
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // Fragment-local decode (no delta base) or the group-level guard rejects it;
    // either way no sparse output is produced.
    assert!(reader.read_all_logical_files(false).is_err());
}
