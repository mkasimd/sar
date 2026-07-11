#![allow(unused_imports)]
//! Empty Area invariant tests.
//!
//! An entry with `Name Length == 0` and `IS_FRAGMENT == 0` is treated as an
//! Empty Area and must be invisible to high-level consumers.

use std::io::Cursor;

use sar_archive::ArchiveReader;
use sar_core::{
    GlobalFlags, SarError,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a NO_INDEX archive containing one named entry and one empty-name entry.
fn build_archive_with_empty_area() -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // Normal entry.
    let lfh_normal = LocalFileHeader::minimal_store(b"real.txt".to_vec(), 4);
    archive.extend_from_slice(&write_lfh(&flags, &lfh_normal).expect("lfh_normal"));
    archive.extend_from_slice(b"DATA");

    // Empty Area: name is empty, IS_FRAGMENT = 0.
    let lfh_empty = LocalFileHeader::minimal_store(b"".to_vec(), 0);
    archive.extend_from_slice(&write_lfh(&flags, &lfh_empty).expect("lfh_empty"));
    // No payload bytes for a zero-length entry.

    archive
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Empty Area (Name Length == 0, IS_FRAGMENT == 0) is not included in logical
/// file output from `read_all_logical_files`.
#[test]
fn empty_area_excluded_from_logical_file_output() {
    let archive = build_archive_with_empty_area();
    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");

    assert_eq!(
        files.len(),
        1,
        "only the named entry should appear; empty area must be filtered"
    );
    assert_eq!(files[0].name, "real.txt");
    assert_eq!(files[0].data, b"DATA");
}

/// `next_entry` still surfaces the raw empty-name entry (it returns all
/// physical entries; filtering is the responsibility of high-level APIs).
#[test]
fn next_entry_returns_empty_area_as_raw_entry() {
    let archive = build_archive_with_empty_area();
    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("header");

    let e1 = reader.next_entry().expect("first").expect("some");
    assert_eq!(e1.metadata.name, "real.txt");

    let e2 = reader.next_entry().expect("second").expect("some");
    assert_eq!(e2.metadata.name, "");
    assert!(
        !e2.metadata.is_fragment,
        "empty area must not be a fragment"
    );

    assert!(reader.next_entry().expect("third").is_none());
}

/// Empty area in a sparse archive: the empty-area entry must not be returned
/// in `read_all_logical_files`, even when SPARSE_FILES is enabled.
#[test]
fn empty_area_not_included_when_sparse_flag_active() {
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

    // Real sparse entry.
    let extents = [SparseExtent {
        offset: 0,
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");
    let mut lfh_real = LocalFileHeader::minimal_store(b"file.bin".to_vec(), 4);
    lfh_real.uncompressed_size = 4;
    lfh_real.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh_real).expect("lfh_real"));
    archive.extend_from_slice(b"DATA");

    // Empty Area entry.
    let lfh_empty = LocalFileHeader::minimal_store(b"".to_vec(), 0);
    archive.extend_from_slice(&write_lfh(&flags, &lfh_empty).expect("lfh_empty"));

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1, "empty area must be filtered");
    assert_eq!(files[0].name, "file.bin");
}

/// Empty Area (IS_FRAGMENT == 0) does not participate in fragment grouping.
#[test]
fn empty_area_does_not_participate_in_fragment_grouping() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // An empty-area entry that has the same fragment_id as a real fragment
    // but IS_FRAGMENT clear.
    let mut lfh_empty = LocalFileHeader::minimal_store(b"".to_vec(), 0);
    lfh_empty.fragment_id = Some(42); // technically set but IS_FRAGMENT is off
    archive.extend_from_slice(&write_lfh(&flags, &lfh_empty).expect("lfh_empty"));

    // Real two-fragment group.
    use sar_core::format::LfhFragmentDescriptor;
    for (idx, abs_off, is_last, data) in [
        (0u32, 0u64, false, b"AAAA" as &[u8]),
        (1u32, 4u64, true, b"BBBB"),
    ] {
        let mut lfh = LocalFileHeader::minimal_store(b"f.bin".to_vec(), 4);
        lfh.uncompressed_size = 4;
        let mode: u16 = if is_last {
            (1u16 << 5) | (1u16 << 6)
        } else {
            1u16 << 5
        };
        lfh.entry_mode = EntryMode::from_bits(mode);
        lfh.fragment_id = Some(42);
        lfh.fragment_index = Some(idx);
        lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
            absolute_offset: abs_off,
            fragment_size: 4,
        });
        archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        archive.extend_from_slice(data);
    }

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    // Only the real two-fragment group must appear.
    assert_eq!(files.len(), 1, "empty area must not appear");
    assert_eq!(files[0].name, "f.bin");
    assert_eq!(&files[0].data[..4], b"AAAA");
    assert_eq!(&files[0].data[4..], b"BBBB");
}

/// Multiple consecutive empty areas are all filtered.
#[test]
fn multiple_empty_areas_all_filtered() {
    let flags = GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    for _ in 0..3 {
        let lfh_empty = LocalFileHeader::minimal_store(b"".to_vec(), 0);
        archive.extend_from_slice(&write_lfh(&flags, &lfh_empty).expect("lfh_empty"));
    }
    let lfh_real = LocalFileHeader::minimal_store(b"a.txt".to_vec(), 1);
    archive.extend_from_slice(&write_lfh(&flags, &lfh_real).expect("lfh_real"));
    archive.extend_from_slice(b"X");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader.read_all_logical_files(false).expect("read");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].data, b"X");
}

/// An archive with only empty areas produces an empty logical file list —
/// not an error.
#[test]
fn archive_with_only_empty_areas_produces_no_logical_files() {
    let flags = GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let lfh_empty = LocalFileHeader::minimal_store(b"".to_vec(), 0);
    archive.extend_from_slice(&write_lfh(&flags, &lfh_empty).expect("lfh"));

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let files = reader
        .read_all_logical_files(false)
        .expect("should succeed");
    assert!(files.is_empty(), "expected zero logical files");
}

/// An entry with IS_FRAGMENT set (even if name is empty) is treated as a
/// fragment entry and not as an Empty Area.  The Empty Area check only applies
/// when IS_FRAGMENT == 0.  A fragment with no matching LAST_FRAGMENT produces
/// a FragmentGap error rather than being silently dropped.
#[test]
fn empty_area_with_is_fragment_set_is_treated_as_fragment_not_silently_dropped() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // IS_FRAGMENT set, no LAST_FRAGMENT → fragment group with no end marker.
    let mut lfh = LocalFileHeader::minimal_store(b"".to_vec(), 0);
    lfh.entry_mode = EntryMode::from_bits(1u16 << 5); // IS_FRAGMENT
    // fragment_id defaults to 0 when written with FILE_FRAGMENTATION flag.
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(archive)).expect("reader");
    // IS_FRAGMENT takes precedence: the entry is routed to fragment-group
    // processing, not silently dropped as an empty area.
    let err = reader
        .read_all_logical_files(false)
        .expect_err("should fail");
    // FragmentGap because there is no LAST_FRAGMENT in the group.
    assert!(
        matches!(err, SarError::FragmentGap(_) | SarError::Malformed(_)),
        "expected FragmentGap or Malformed, got {err:?}"
    );
}
