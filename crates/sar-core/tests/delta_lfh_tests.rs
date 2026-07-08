//! Tests for delta LFH field parsing, writing, and structural validation
//! (spec section 6.1, `HAS_DELTA`).
//!
//! These tests verify:
//! * LFH round-trips for `Patch Algo ID` and `Delta Base Hash`;
//! * Header Size accounting includes the delta fields;
//! * Delta fields are absent when `HAS_DELTA` is not set;
//! * Field ordering when `HAS_DELTA` is combined with other global flags;
//! * Registry validation propagates through the archive reader pipeline;
//! * Delta Base Hash is preserved as opaque bytes regardless of content.
//!
//! No patch application is attempted.  No hash algorithm is assumed for
//! `Delta Base Hash`.  All-zero `Delta Base Hash` has no special meaning.

use sar_core::{
    GlobalFlags, SarError,
    format::LfhFragmentDescriptor,
    format::{LocalFileHeader, compute_lfh_size, parse_lfh, write_lfh},
};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

// ---------------------------------------------------------------------------
// Round-trip: Patch Algo ID
// ---------------------------------------------------------------------------

#[test]
fn lfh_round_trip_has_delta_store_patch() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let mut lfh = LocalFileHeader::minimal_store(b"a.bin".to_vec(), 4);
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh.delta_base_hash = Some([1u8; 32]);

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.patch_algo_id, Some(0x00));
    assert_eq!(parsed.delta_base_hash, Some([1u8; 32]));
}

#[test]
fn lfh_round_trip_has_delta_vcdiff() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let mut lfh = LocalFileHeader::minimal_store(b"b.bin".to_vec(), 4);
    lfh.patch_algo_id = Some(0x01); // VCDIFF
    lfh.delta_base_hash = Some([0xABu8; 32]);

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(parsed.patch_algo_id, Some(0x01));
    assert_eq!(parsed.delta_base_hash, Some([0xABu8; 32]));
}

// ---------------------------------------------------------------------------
// Round-trip: Delta Base Hash — opaque bytes
// ---------------------------------------------------------------------------

#[test]
fn lfh_round_trip_nonzero_delta_base_hash() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let hash: [u8; 32] = (0u8..32)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("slice to array");
    let mut lfh = LocalFileHeader::minimal_store(b"c.bin".to_vec(), 4);
    lfh.patch_algo_id = Some(0x00);
    lfh.delta_base_hash = Some(hash);

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(
        parsed.delta_base_hash,
        Some(hash),
        "hash must round-trip exactly"
    );
}

/// All-zero `Delta Base Hash` is preserved without any special interpretation.
/// No sentinel meaning is applied; this is just opaque bytes.
#[test]
fn lfh_round_trip_all_zero_delta_base_hash_no_special_meaning() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let mut lfh = LocalFileHeader::minimal_store(b"d.bin".to_vec(), 4);
    lfh.patch_algo_id = Some(0x00);
    lfh.delta_base_hash = Some([0u8; 32]); // all-zero, no special semantics

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(
        parsed.delta_base_hash,
        Some([0u8; 32]),
        "all-zero delta base hash must be preserved without special interpretation"
    );
}

// ---------------------------------------------------------------------------
// Header Size includes Patch Algo ID (1B) + Delta Base Hash (32B) = 33 bytes
// ---------------------------------------------------------------------------

#[test]
fn lfh_header_size_includes_delta_fields() {
    let flags_no_delta = GlobalFlags::NO_INDEX;
    let flags_with_delta = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;

    let lfh = LocalFileHeader::minimal_store(b"e.bin".to_vec(), 4);
    let size_no_delta = compute_lfh_size(&flags_no_delta, &lfh).expect("size_no_delta");
    let size_with_delta = compute_lfh_size(&flags_with_delta, &lfh).expect("size_with_delta");

    // Patch Algo ID = 1 byte, Delta Base Hash = 32 bytes → 33 bytes total
    assert_eq!(
        size_with_delta,
        size_no_delta + 1 + 32,
        "HAS_DELTA must add exactly 33 bytes to the fixed LFH prefix"
    );
}

// ---------------------------------------------------------------------------
// Field ordering: HAS_DELTA combined with other global flags
// ---------------------------------------------------------------------------

/// When all major global flags are set, the LFH must still round-trip
/// correctly with delta fields present in the correct positions.
#[test]
fn lfh_field_ordering_has_delta_combined_with_all_flags() {
    let flags = GlobalFlags::NO_INDEX
        | GlobalFlags::COMPRESSED
        | GlobalFlags::HAS_DELTA
        | GlobalFlags::ENCRYPTED
        | GlobalFlags::CDC_SUPPORT
        | GlobalFlags::SELECTIVE_FEC
        | GlobalFlags::FILE_FRAGMENTATION
        | GlobalFlags::PER_FILE_CRC
        | GlobalFlags::DEDUPLICATION
        | GlobalFlags::EXT_UID_GID
        | GlobalFlags::EXT_TIME
        | GlobalFlags::HAS_PERMS
        | GlobalFlags::HAS_PATH
        | GlobalFlags::SPARSE_FILES;

    let hash: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[31] = 0xAD;
        h
    };

    let mut lfh = LocalFileHeader::minimal_store(b"multi.bin".to_vec(), 4);
    lfh.comp_algo_id = Some(0x00);
    lfh.patch_algo_id = Some(0x01); // VCDIFF
    lfh.encr_algo_id = Some(0x00);
    lfh.cdc_algo_id = Some(0x00);
    lfh.fec_algo_id = Some(0x00);
    lfh.fragment_id = Some(7);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    lfh.iv_nonce = Some([0u8; 24]);
    lfh.delta_base_hash = Some(hash);
    lfh.file_crc32 = Some(0xDEAD_BEEF);
    lfh.content_hash = Some([2u8; 32]);
    lfh.uid_gid = Some(0x1000_2000);
    lfh.timestamps = Some([100, 200, 300]);
    lfh.permissions = Some(0o755);
    lfh.path = b"sub/dir".to_vec();
    lfh.sparse_map = vec![0u8; 8]; // one 32-bit extent descriptor
    lfh.fec_value = vec![0u8; 4];

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(consumed, bytes.len(), "consumed must equal total bytes");
    assert_eq!(
        parsed.patch_algo_id,
        Some(0x01),
        "Patch Algo ID must survive multi-flag round-trip"
    );
    assert_eq!(
        parsed.delta_base_hash,
        Some(hash),
        "Delta Base Hash must survive multi-flag round-trip"
    );
}

// ---------------------------------------------------------------------------
// Delta fields absent when HAS_DELTA is not set
// ---------------------------------------------------------------------------

#[test]
fn lfh_no_delta_fields_when_flag_not_set() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"nodelta.bin".to_vec(), 4);

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(
        parsed.patch_algo_id, None,
        "patch_algo_id must be None without HAS_DELTA"
    );
    assert_eq!(
        parsed.delta_base_hash, None,
        "delta_base_hash must be None without HAS_DELTA"
    );
}

// ---------------------------------------------------------------------------
// Registry validation via archive reader
// ---------------------------------------------------------------------------

/// An archive with `HAS_DELTA` set and a reserved `Patch Algo ID` (0x04–0xEF)
/// must produce `SAR_ERR_RESERVED_VALUE` when the entry is read.
#[test]
fn archive_reader_reserved_patch_algo_id_returns_reserved_value_error() {
    use sar_core::{
        ArchiveReader, ArchiveReaderOptions,
        format::{GlobalHeader, write_global_header},
    };
    use std::io::Cursor;

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;

    // Build a minimal valid archive with a reserved Patch Algo ID.
    let global_header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive_bytes = write_global_header(&global_header).expect("write header");

    let mut lfh = LocalFileHeader::minimal_store(b"reserved.bin".to_vec(), 0);
    lfh.patch_algo_id = Some(0x80); // reserved range 0x04–0xEF
    lfh.delta_base_hash = Some([0u8; 32]);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive_bytes.extend_from_slice(&lfh_bytes);

    let cursor = Cursor::new(archive_bytes);
    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(cursor, opts).expect("open reader");
    let _ = reader.read_global_header().expect("read global header");
    let err = reader
        .next_entry()
        .expect_err("must fail with reserved algo");
    assert!(
        matches!(err, SarError::ReservedValue(_)),
        "expected ReservedValue for reserved Patch Algo ID 0x80, got {err:?}"
    );
}

/// An archive with `HAS_DELTA` set and a custom `Patch Algo ID` (0xF0–0xFF)
/// must produce `SAR_ERR_UNSUPPORTED` when the entry is read.
#[test]
fn archive_reader_custom_patch_algo_id_returns_unsupported_error() {
    use sar_core::{
        ArchiveReader, ArchiveReaderOptions,
        format::{GlobalHeader, write_global_header},
    };
    use std::io::Cursor;

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;

    let global_header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive_bytes = write_global_header(&global_header).expect("write header");

    let mut lfh = LocalFileHeader::minimal_store(b"custom.bin".to_vec(), 0);
    lfh.patch_algo_id = Some(0xF5); // custom range 0xF0–0xFF
    lfh.delta_base_hash = Some([0u8; 32]);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive_bytes.extend_from_slice(&lfh_bytes);

    let cursor = Cursor::new(archive_bytes);
    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(cursor, opts).expect("open reader");
    let _ = reader.read_global_header().expect("read global header");
    let err = reader.next_entry().expect_err("must fail with custom algo");
    assert!(
        matches!(err, SarError::Unsupported(_)),
        "expected Unsupported for custom Patch Algo ID 0xF5, got {err:?}"
    );
}

/// An archive with `HAS_DELTA` and an assigned `Patch Algo ID` (STORE_PATCH)
/// must parse successfully — registry validation passes for assigned IDs.
/// No patch application is attempted.
#[test]
fn archive_reader_assigned_patch_algo_id_passes_registry_check() {
    use sar_core::{
        ArchiveReader, ArchiveReaderOptions,
        format::{GlobalHeader, write_global_header},
    };
    use std::io::Cursor;

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;

    let global_header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive_bytes = write_global_header(&global_header).expect("write header");

    let mut lfh = LocalFileHeader::minimal_store(b"assigned.bin".to_vec(), 0);
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH — assigned
    lfh.delta_base_hash = Some([0xBBu8; 32]);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive_bytes.extend_from_slice(&lfh_bytes);

    let cursor = Cursor::new(archive_bytes);
    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(cursor, opts).expect("open reader");
    let _ = reader.read_global_header().expect("read global header");
    let entry = reader
        .next_entry()
        .expect("must succeed for assigned algo")
        .expect("entry must be present");
    assert_eq!(entry.metadata.patch_algo_id, Some(0x00));
    assert_eq!(entry.metadata.delta_base_hash, Some([0xBBu8; 32]));
}

// ---------------------------------------------------------------------------
// EntryMetadata delta field exposure
// ---------------------------------------------------------------------------

/// Confirms that `EntryMetadata` exposes `patch_algo_id` and `delta_base_hash`
/// when the archive has `HAS_DELTA` set.
#[test]
fn entry_metadata_exposes_delta_fields_when_has_delta_set() {
    use sar_core::{
        ArchiveReader, ArchiveReaderOptions,
        format::{GlobalHeader, write_global_header},
    };
    use std::io::Cursor;

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let expected_hash: [u8; 32] = {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        h
    };

    let global_header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive_bytes = write_global_header(&global_header).expect("write header");

    let mut lfh = LocalFileHeader::minimal_store(b"meta.bin".to_vec(), 0);
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH (VCDIFF/0x01 is unsupported since M9b)
    lfh.delta_base_hash = Some(expected_hash);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive_bytes.extend_from_slice(&lfh_bytes);

    let cursor = Cursor::new(archive_bytes);
    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(cursor, opts).expect("open reader");
    let _ = reader.read_global_header().expect("read global header");
    let entry = reader
        .next_entry()
        .expect("must succeed")
        .expect("entry present");

    assert_eq!(entry.metadata.patch_algo_id, Some(0x00));
    assert_eq!(entry.metadata.delta_base_hash, Some(expected_hash));
}

/// Confirms that `EntryMetadata.patch_algo_id` and `delta_base_hash` are
/// `None` when the archive does not have `HAS_DELTA` set.
#[test]
fn entry_metadata_delta_fields_none_when_has_delta_not_set() {
    use sar_core::{
        ArchiveReader, ArchiveReaderOptions,
        format::{GlobalHeader, write_global_header},
    };
    use std::io::Cursor;

    let flags = GlobalFlags::NO_INDEX;

    let global_header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive_bytes = write_global_header(&global_header).expect("write header");

    let lfh = LocalFileHeader::minimal_store(b"nodelta.bin".to_vec(), 0);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive_bytes.extend_from_slice(&lfh_bytes);

    let cursor = Cursor::new(archive_bytes);
    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(cursor, opts).expect("open reader");
    let _ = reader.read_global_header().expect("read global header");
    let entry = reader
        .next_entry()
        .expect("must succeed")
        .expect("entry present");

    assert_eq!(entry.metadata.patch_algo_id, None);
    assert_eq!(entry.metadata.delta_base_hash, None);
}

// ---------------------------------------------------------------------------
// No patch application during archive reader pipeline
// ---------------------------------------------------------------------------

/// Even with HAS_DELTA set and a payload present, the reader must not attempt
/// to apply any patch.  The payload bytes must be returned as-is.
#[test]
fn archive_reader_does_not_apply_patch_to_payload() {
    use sar_core::{
        ArchiveReader, ArchiveReaderOptions,
        format::{GlobalHeader, write_global_header},
    };
    use std::io::Cursor;

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let payload = b"raw-payload-bytes".to_vec();

    let global_header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive_bytes = write_global_header(&global_header).expect("write header");

    let mut lfh = LocalFileHeader::minimal_store(b"noapply.bin".to_vec(), payload.len() as u64);
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh.delta_base_hash = Some([0u8; 32]);

    let mut lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    lfh_bytes.extend_from_slice(&payload);
    archive_bytes.extend_from_slice(&lfh_bytes);

    let cursor = Cursor::new(archive_bytes);
    let opts = ArchiveReaderOptions::default();
    let mut reader = ArchiveReader::with_options(cursor, opts).expect("open reader");
    let _ = reader.read_global_header().expect("read global header");
    let entry = reader
        .next_entry()
        .expect("must succeed — no patch is applied")
        .expect("entry present");

    assert_eq!(
        entry.payload, payload,
        "payload must be returned as-is; no patch must be applied"
    );
}
