//! M11a metadata API completeness tests.
//!
//! Tests the expanded `EntryInput`, `EntryMetadata`, `FieldPresence`, and all
//! related metadata structs introduced in Milestone 11a.

use std::io::Cursor;

use sar_core::format::{GlobalHeader, write_global_header};
use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EntryCdcMetadata,
    EntryCompressionMetadata, EntryDeltaMetadata, EntryEncryptionMetadata, EntryFecMetadata,
    EntryFragmentMetadata, EntryHashMetadata, EntryInput, EntryKind, EntryOwnerMetadata,
    EntryPermissionMetadata, EntrySparseMetadata, EntryTimestampMetadata, FecSettings,
    FieldPresence, GlobalFlags, SarError, SparseExtent,
};

// ---------------------------------------------------------------------------
// Helper: write and read back a single entry
// ---------------------------------------------------------------------------

fn write_read_entry(
    opts: ArchiveWriterOptions,
    entry: EntryInput,
) -> Result<sar_core::EntryReader, SarError> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, opts)?;
    writer.add_entry(entry)?;
    writer.finish()?;

    let mut reader = ArchiveReader::new(Cursor::new(buf))?;
    reader.read_global_header()?;
    reader.next_entry()?.ok_or(SarError::Malformed("no entry"))
}

// ---------------------------------------------------------------------------
// 1. Simple file entry still works
// ---------------------------------------------------------------------------

#[test]
fn entry_input_file_constructor_writes_regular_file_entry() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("hello.txt", b"world".to_vec()),
    )
    .expect("roundtrip");
    assert_eq!(entry.metadata.name, "hello.txt");
    assert_eq!(entry.payload, b"world");
    assert!(matches!(entry.metadata.entry_kind, EntryKind::RegularFile));
}

// ---------------------------------------------------------------------------
// 2. Reader exposes name and payload as before
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_name_and_payload() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("data.bin", b"ABCDEF".to_vec()),
    )
    .expect("roundtrip");
    assert_eq!(entry.metadata.name, "data.bin");
    assert_eq!(entry.payload, b"ABCDEF");
}

// ---------------------------------------------------------------------------
// 3. Reader exposes raw Entry Mode
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_raw_entry_mode() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.txt", b"x".to_vec()),
    )
    .expect("roundtrip");
    // raw entry mode should be a u16 (just verify the field is accessible)
    let _raw: u16 = entry.metadata.entry_mode_raw;
}

// ---------------------------------------------------------------------------
// 4. Reader exposes Stream ID and Sequence No
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_stream_id_and_sequence_no() {
    let mut entry_in = EntryInput::file("f.txt", b"data".to_vec());
    entry_in.stream_id = Some(7);
    entry_in.sequence_no = Some(42);

    let entry = write_read_entry(ArchiveWriterOptions::default(), entry_in).expect("roundtrip");
    assert_eq!(entry.metadata.stream_id, 7);
    assert_eq!(entry.metadata.sequence_no, 42);
}

// ---------------------------------------------------------------------------
// 5. Reader exposes compression metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_compression_metadata_absent_when_no_global_flag() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");
    // COMPRESSED global flag not set → compression field is absent
    assert!(matches!(
        entry.metadata.compression_presence,
        FieldPresence::Absent
    ));
}

#[test]
fn reader_exposes_compression_metadata_active_when_compressed() {
    let _entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("f.txt", b"data".to_vec().repeat(100)),
    );
    // default opts don't have COMPRESSED - use compression writer
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        CompressionSettings {
            algo_id: 0x02,
            level: None,
        }, // ZSTD
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("f.txt", b"data".to_vec().repeat(100)))
        .expect("add");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    // COMPRESSED flag set and IS_COMPRESSED active → PresentActive
    assert!(matches!(
        entry.metadata.compression_presence,
        FieldPresence::PresentActive(_)
    ));
    if let FieldPresence::PresentActive(cm) = &entry.metadata.compression_presence {
        assert_eq!(cm.algo_id, 0x02);
        assert_ne!(cm.algorithm_name, "STORE");
    }
}

// ---------------------------------------------------------------------------
// 6. Reader exposes encryption metadata (present-inactive and present-active)
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_encryption_metadata_absent_when_no_global_flag() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");
    assert!(matches!(
        entry.metadata.encryption_presence,
        FieldPresence::Absent
    ));
}

#[test]
fn reader_exposes_encryption_metadata_present_inactive_without_is_encrypted() {
    // Build an archive with ENCRYPTED global flag but no IS_ENCRYPTED entry mode.
    // Do this by constructing the raw bytes manually.
    let flags = GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: Some(sar_core::format::KmsData {
            mode_id: 0x01,
            payload: {
                let mut p = vec![1, 16];
                p.extend_from_slice(&[0x11; 16]);
                p.extend_from_slice(&100_000u32.to_le_bytes());
                p.extend_from_slice(&32u16.to_le_bytes());
                p
            },
        }),
    })
    .expect("header bytes");

    // LFH for ENCRYPTED global flag, IV present, but IS_ENCRYPTED entry mode bit NOT set.
    // Fixed fields:
    //   header_size:u32(4) + entry_mode:u16(2) + stream_id:u16(2) + sequence_no:u16(2)
    //   + uncompressed_size:u32(4) + payload_size:u32(4)
    //   + encr_algo_id:u8(1) + iv_nonce:[u8;24](24)
    //   + name_len:u16(2)
    // Trailing: name(1) = "x"
    // Total header_size = 4+2+2+2+4+4+1+24+2+1 = 46
    let header_size: u32 = 4 + 2 + 2 + 2 + 4 + 4 + 1 + 24 + 2 + 1;
    bytes.extend_from_slice(&header_size.to_le_bytes()); // header_size
    bytes.extend_from_slice(&0u16.to_le_bytes()); // entry_mode (no IS_ENCRYPTED)
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&1u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&1u32.to_le_bytes()); // payload_size
    bytes.push(0x01); // encr_algo_id
    bytes.extend_from_slice(&[0u8; 24]); // iv_nonce
    bytes.extend_from_slice(&1u16.to_le_bytes()); // name_len (u16)
    bytes.push(b'x'); // name
    bytes.push(b'a'); // payload

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    // IS_ENCRYPTED not set → PresentInactive
    assert!(matches!(
        entry.metadata.encryption_presence,
        FieldPresence::PresentInactive(_)
    ));
    if let FieldPresence::PresentInactive(em) = &entry.metadata.encryption_presence {
        assert_eq!(em.algo_id, 0x01);
    }
}

// ---------------------------------------------------------------------------
// 7. Reader exposes CDC metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_cdc_metadata_when_cdc_support_enabled() {
    use sar_core::CdcMap;
    use sar_core::ResourceLimits;
    use sar_core::cdc::make_cdc_map_tlv;

    let cdc_map = CdcMap {
        hash_algorithm_id: 0x31, // BLAKE3
        records: vec![],
    };
    let limits = ResourceLimits::default();
    let cd_tlv = make_cdc_map_tlv(&cdc_map, &limits).expect("cdc map tlv");

    let mut buf = Vec::new();
    let mut writer = sar_core::ArchiveWriter::new_with_cd_metadata(
        &mut buf,
        ArchiveWriterOptions {
            no_index: false,
            ..Default::default()
        },
        vec![cd_tlv],
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("f.bin", b"abc".to_vec()))
        .expect("add");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    // CDC_SUPPORT enabled → cdc_algo_id and cdc field should be present
    assert!(entry.metadata.cdc_algo_id.is_some());
    let cdc = entry.metadata.cdc.expect("cdc metadata");
    assert_eq!(cdc.algo_id, 0x00); // LITERAL_MODE
}

// ---------------------------------------------------------------------------
// 8. Reader exposes FEC metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_fec_metadata_absent_when_no_selective_fec() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.bin", b"data".to_vec()),
    )
    .expect("roundtrip");
    assert!(matches!(entry.metadata.fec_presence, FieldPresence::Absent));
}

#[test]
fn reader_exposes_fec_metadata_active_when_selective_fec_enabled() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            fec: Some(FecSettings::default_xor()),
            ..Default::default()
        },
        EntryInput::file("f.bin", b"data for fec encoding".to_vec()),
    )
    .expect("roundtrip");
    assert!(matches!(
        entry.metadata.fec_presence,
        FieldPresence::PresentActive(_)
    ));
    if let FieldPresence::PresentActive(fm) = &entry.metadata.fec_presence {
        assert_ne!(fm.algo_id, 0);
        assert!(fm.summary.is_some());
    }
}

// ---------------------------------------------------------------------------
// 9. Reader exposes delta metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_delta_metadata_absent_when_no_has_delta() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.bin", b"data".to_vec()),
    )
    .expect("roundtrip");
    assert!(entry.metadata.patch_algo_id.is_none());
    assert!(entry.metadata.delta.is_none());
}

// ---------------------------------------------------------------------------
// 10. Reader exposes fragment metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_fragment_metadata_absent_when_no_file_fragmentation() {
    let entry = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.bin", b"data".to_vec()),
    )
    .expect("roundtrip");
    assert!(matches!(
        entry.metadata.fragment_presence,
        FieldPresence::Absent
    ));
}

// ---------------------------------------------------------------------------
// 11. Reader exposes sparse metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_sparse_metadata_when_sparse_enabled() {
    use sar_core::SparseWriteOptions;

    let extents = vec![SparseExtent {
        offset: 0,
        length: 4,
    }];
    let opts = ArchiveWriterOptions {
        no_index: true,
        sparse: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, opts).expect("writer");
    writer
        .write_sparse_entry(
            "sparse.bin",
            b"data",
            SparseWriteOptions {
                logical_size: 4,
                extents: extents.clone(),
            },
        )
        .expect("sparse write");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    assert!(entry.metadata.sparse_extents.is_some());
    let sm = entry.metadata.sparse.expect("sparse metadata");
    assert_eq!(sm.extents.len(), 1);
    assert_eq!(sm.extents[0].offset, 0);
    assert_eq!(sm.extents[0].length, 4);
}

// ---------------------------------------------------------------------------
// 12. Reader exposes CRC32 metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_crc32_metadata_when_per_file_crc_enabled() {
    let payload = b"test-payload";
    let crc = crc32fast::hash(payload);

    let entry_in = EntryInput {
        name: "f.bin".into(),
        payload: payload.to_vec(),
        file_crc32: Some(crc),
        ..Default::default()
    };
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_per_file_crc: true,
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");

    assert_eq!(entry.metadata.file_crc32, Some(crc));
    let hash_meta = entry.metadata.hash.expect("hash metadata");
    assert_eq!(hash_meta.crc32, Some(crc));
    assert!(hash_meta.content_hash.is_none());
}

// ---------------------------------------------------------------------------
// 13. Reader exposes content hash metadata
// ---------------------------------------------------------------------------

#[test]
fn reader_exposes_content_hash_metadata_when_deduplication_enabled() {
    let hash_bytes = [0x42u8; 32];
    let entry_in = EntryInput {
        name: "f.bin".into(),
        payload: b"some data".to_vec(),
        content_hash: Some(hash_bytes),
        ..Default::default()
    };
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_content_hash: true,
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");

    assert_eq!(entry.metadata.content_hash, Some(hash_bytes));
    let hash_meta = entry.metadata.hash.expect("hash metadata");
    assert_eq!(hash_meta.content_hash, Some(hash_bytes));
}

// ---------------------------------------------------------------------------
// 14. Field presence: absent vs present-inactive vs present-active
// ---------------------------------------------------------------------------

#[test]
fn field_presence_absent_present_inactive_present_active_distinguishable() {
    // Build a plain archive without COMPRESSED flag → Absent
    let entry_plain = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("plain");
    assert!(entry_plain.metadata.compression_presence.is_absent());
    assert!(!entry_plain.metadata.compression_presence.is_present());
    assert!(!entry_plain.metadata.compression_presence.is_active());

    // Build a compressed archive → PresentActive
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        CompressionSettings {
            algo_id: 0x02,
            level: None,
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("f.txt", b"data".to_vec().repeat(50)))
        .expect("add");
    writer.finish().expect("finish");
    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry_compressed = reader.next_entry().expect("ok").expect("entry");

    assert!(!entry_compressed.metadata.compression_presence.is_absent());
    assert!(entry_compressed.metadata.compression_presence.is_present());
    assert!(entry_compressed.metadata.compression_presence.is_active());

    // Build a COMPRESSED-but-inactive archive: COMPRESSED global flag but
    // IS_COMPRESSED entry mode bit not set.  This is done manually because
    // the normal writer sets IS_COMPRESSED when the global flag is set.
    let flags = GlobalFlags::COMPRESSED | GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header bytes");
    // LFH: COMPRESSED global (so comp_algo_id physically present), IS_COMPRESSED NOT set.
    // Fixed header = 4+2+2+2+4+4 = 18; comp_algo_id = 1 byte; name_len = 2 bytes; name = 1 byte
    let header_size: u32 = 18 + 1 + 2 + 1;
    bytes.extend_from_slice(&header_size.to_le_bytes()); // header_size
    bytes.extend_from_slice(&0u16.to_le_bytes()); // entry_mode = 0 (no IS_COMPRESSED)
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&1u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&1u32.to_le_bytes()); // payload_size
    bytes.push(0x02); // comp_algo_id = ZSTD (physically present, but IS_COMPRESSED=0)
    bytes.extend_from_slice(&1u16.to_le_bytes()); // name_len
    bytes.push(b'x'); // name
    bytes.push(b'a'); // payload

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry_inactive = reader.next_entry().expect("ok").expect("entry");

    // COMPRESSED global set but IS_COMPRESSED not set → PresentInactive
    assert!(!entry_inactive.metadata.compression_presence.is_absent());
    assert!(entry_inactive.metadata.compression_presence.is_present());
    assert!(!entry_inactive.metadata.compression_presence.is_active());
    if let FieldPresence::PresentInactive(cm) = &entry_inactive.metadata.compression_presence {
        assert_eq!(cm.algo_id, 0x02); // raw ZSTD preserved
    } else {
        panic!("expected PresentInactive");
    }
    // Effective compression is STORE because IS_COMPRESSED is not set
    assert_eq!(entry_inactive.metadata.compression_algo_id, 0x00);
}

// ---------------------------------------------------------------------------
// 15. Unsupported metadata (missing flag) returns error, not silent drop
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_path_without_has_path_flag() {
    let entry = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        path: Some("some/dir".into()),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(
        matches!(err, SarError::FlagConflict(_)),
        "expected FlagConflict, got: {err:?}"
    );
}

#[test]
fn writer_rejects_permissions_without_has_perms_flag() {
    let entry = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        permissions: Some(0o644),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn writer_rejects_symlink_without_has_symlinks_flag() {
    let entry = EntryInput {
        name: "link".into(),
        payload: b"/target/path".to_vec(),
        kind: Some(EntryKind::Symlink),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 16. Directory entry can be represented at API level
// ---------------------------------------------------------------------------

#[test]
fn directory_entry_can_be_represented() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        ..Default::default()
    };
    let entry_in = EntryInput {
        name: "mydir".into(),
        payload: vec![], // directory payload MUST be empty
        kind: Some(EntryKind::Directory),
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    assert_eq!(entry.metadata.name, "mydir");
    assert!(matches!(entry.metadata.entry_kind, EntryKind::Directory));
    // IS_DIRECTORY entry mode bit should be set
    assert_ne!(
        entry.metadata.entry_mode_raw & sar_core::EntryMode::IS_DIRECTORY,
        0
    );
}

// ---------------------------------------------------------------------------
// 17. Symlink entry can be represented at API level
// ---------------------------------------------------------------------------

#[test]
fn symlink_entry_can_be_represented() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_symlinks: true,
        ..Default::default()
    };
    let entry_in = EntryInput {
        name: "mylink".into(),
        payload: b"/some/target".to_vec(),
        kind: Some(EntryKind::Symlink),
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    assert_eq!(entry.metadata.name, "mylink");
    assert!(matches!(entry.metadata.entry_kind, EntryKind::Symlink));
    // IS_SYMLINK entry mode bit should be set
    assert_ne!(
        entry.metadata.entry_mode_raw & sar_core::EntryMode::IS_SYMLINK,
        0
    );
    // Payload is the symlink target
    assert_eq!(entry.payload, b"/some/target");
}

// ---------------------------------------------------------------------------
// 18. Hidden attribute can be represented at API level
// ---------------------------------------------------------------------------

#[test]
fn hidden_attribute_can_be_represented() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        ..Default::default()
    };
    let entry_in = EntryInput {
        name: ".hidden".into(),
        payload: b"secret".to_vec(),
        is_hidden: true,
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    assert!(entry.metadata.is_hidden, "is_hidden should be true");
    // HIDDEN_ATTR entry mode bit
    assert_ne!(
        entry.metadata.entry_mode_raw & sar_core::EntryMode::HIDDEN_ATTR,
        0
    );
}

// ---------------------------------------------------------------------------
// 19. Metadata structs use named fields, not public multi-field tuples
// ---------------------------------------------------------------------------

#[test]
fn metadata_structs_use_named_fields() {
    // Compile-time check that all M11a structs have named fields
    // (this test will fail to compile if any struct is changed to a tuple).
    let _ = EntryPermissionMetadata { mode: 0o644 };
    let _ = EntryOwnerMetadata { uid_gid: 0 };
    let _ = EntryTimestampMetadata {
        mtime: 0,
        atime: 0,
        ctime: 0,
    };
    let _ = EntryCompressionMetadata {
        algo_id: 0,
        algorithm_name: "STORE",
    };
    let _ = EntryEncryptionMetadata {
        algo_id: 0,
        iv_nonce: [0u8; 24],
    };
    let _ = EntryFecMetadata {
        algo_id: 0,
        summary: None,
    };
    let _ = EntryCdcMetadata { algo_id: 0 };
    let _ = EntryDeltaMetadata {
        patch_algo_id: 0,
        base_hash: [0u8; 32],
    };
    let _ = EntryFragmentMetadata {
        fragment_id: 0,
        fragment_index: 0,
        descriptor: None,
        is_last: false,
        is_loss_tolerant: false,
    };
    let _ = EntrySparseMetadata { extents: vec![] };
    let _ = EntryHashMetadata {
        crc32: None,
        content_hash: None,
    };
}

// ---------------------------------------------------------------------------
// 20. Permissions round-trip
// ---------------------------------------------------------------------------

#[test]
fn permissions_round_trip() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_permissions: true,
        ..Default::default()
    };
    let entry_in = EntryInput {
        name: "script.sh".into(),
        payload: b"#!/bin/sh".to_vec(),
        permissions: Some(0o755),
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    let perms = entry.metadata.permissions.expect("permissions metadata");
    assert_eq!(perms.mode, 0o755);
}

// ---------------------------------------------------------------------------
// 21. UID/GID round-trip
// ---------------------------------------------------------------------------

#[test]
fn uid_gid_round_trip() {
    let uid: u32 = 1000;
    let gid: u32 = 1000;
    let uid_gid = uid | (gid << 16);
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_uid_gid: true,
        ..Default::default()
    };
    let entry_in = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        uid_gid: Some(uid_gid),
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    let owner = entry.metadata.owner.expect("owner metadata");
    assert_eq!(owner.uid_gid, uid_gid);
    assert_eq!(u32::from(owner.uid()), uid);
    assert_eq!(u32::from(owner.gid()), gid);
}

// ---------------------------------------------------------------------------
// 22. Timestamps round-trip
// ---------------------------------------------------------------------------

#[test]
fn timestamps_round_trip() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_timestamps: true,
        ..Default::default()
    };
    let ts = [1_700_000_000u64, 1_700_001_000, 1_700_002_000];
    let entry_in = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        timestamps: Some(ts),
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    let tsmeta = entry.metadata.timestamps.expect("timestamp metadata");
    assert_eq!(tsmeta.mtime, ts[0]);
    assert_eq!(tsmeta.atime, ts[1]);
    assert_eq!(tsmeta.ctime, ts[2]);
}

// ---------------------------------------------------------------------------
// 23. Path round-trip
// ---------------------------------------------------------------------------

#[test]
fn path_round_trip() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        with_path: true,
        ..Default::default()
    };
    let entry_in = EntryInput {
        name: "file.txt".into(),
        payload: b"contents".to_vec(),
        path: Some("subdir/nested".into()),
        ..Default::default()
    };
    let entry = write_read_entry(opts, entry_in).expect("roundtrip");
    assert_eq!(entry.metadata.path, Some("subdir/nested".into()));
}

// ---------------------------------------------------------------------------
// 24. Empty area entry is identified correctly
// ---------------------------------------------------------------------------

#[test]
fn empty_area_entry_kind_derived_correctly() {
    // Build an empty-area LFH manually (name length = 0, IS_FRAGMENT = 0)
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header bytes");
    // Minimal LFH: header_size=18, entry_mode=0, stream=0, seq=0,
    // uncompressed_size=0, payload_size=0, name_len=0 → 18 + 2 = 20 bytes
    let header_size: u32 = 18 + 2;
    bytes.extend_from_slice(&header_size.to_le_bytes()); // header_size
    bytes.extend_from_slice(&0u16.to_le_bytes()); // entry_mode
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&0u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&0u32.to_le_bytes()); // payload_size
    bytes.extend_from_slice(&0u16.to_le_bytes()); // name_len = 0

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry_opt = reader.next_entry().expect("ok");
    // Empty areas are skipped by read_all_logical_files but returned by next_entry
    if let Some(entry) = entry_opt {
        assert!(matches!(entry.metadata.entry_kind, EntryKind::EmptyArea));
    }
}

// ---------------------------------------------------------------------------
// 25. EntryKind::from_mode_and_name covers all branches
// ---------------------------------------------------------------------------

#[test]
fn entry_kind_from_mode_covers_all_variants() {
    use sar_core::EntryMode;
    assert!(matches!(
        EntryKind::from_mode_and_name(EntryMode::from_bits(0), true),
        EntryKind::EmptyArea
    ));
    assert!(matches!(
        EntryKind::from_mode_and_name(EntryMode::from_bits(EntryMode::IS_DIRECTORY), false),
        EntryKind::Directory
    ));
    assert!(matches!(
        EntryKind::from_mode_and_name(EntryMode::from_bits(EntryMode::IS_SYMLINK), false),
        EntryKind::Symlink
    ));
    assert!(matches!(
        EntryKind::from_mode_and_name(EntryMode::from_bits(0), false),
        EntryKind::RegularFile
    ));
}

// ---------------------------------------------------------------------------
// 26. FieldPresence helpers work correctly
// ---------------------------------------------------------------------------

#[test]
fn field_presence_helpers_work() {
    let absent: FieldPresence<u32> = FieldPresence::Absent;
    assert!(absent.is_absent());
    assert!(!absent.is_present());
    assert!(!absent.is_active());
    assert!(absent.value().is_none());

    let inactive = FieldPresence::PresentInactive(42u32);
    assert!(!inactive.is_absent());
    assert!(inactive.is_present());
    assert!(!inactive.is_active());
    assert_eq!(inactive.value(), Some(&42u32));

    let active = FieldPresence::PresentActive(99u32);
    assert!(!active.is_absent());
    assert!(active.is_present());
    assert!(active.is_active());
    assert_eq!(active.value(), Some(&99u32));
}

// ---------------------------------------------------------------------------
// 27. EntryOwnerMetadata uid/gid accessors
// ---------------------------------------------------------------------------

#[test]
fn entry_owner_metadata_uid_gid_accessors() {
    let uid = 500u32;
    let gid = 1000u32;
    let packed = uid | (gid << 16);
    let meta = EntryOwnerMetadata { uid_gid: packed };
    assert_eq!(u32::from(meta.uid()), uid);
    assert_eq!(u32::from(meta.gid()), gid);
}

// ---------------------------------------------------------------------------
// 28. Writer rejects uid_gid without EXT_UID_GID flag
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_uid_gid_without_ext_uid_gid_flag() {
    let entry = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        uid_gid: Some(1000),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 29. Writer rejects timestamps without EXT_TIME flag
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_timestamps_without_ext_time_flag() {
    let entry = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        timestamps: Some([0, 0, 0]),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 30. Writer rejects content_hash without DEDUPLICATION flag
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_content_hash_without_deduplication_flag() {
    let entry = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        content_hash: Some([0u8; 32]),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 31. Writer rejects file_crc32 without PER_FILE_CRC flag
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_crc32_without_per_file_crc_flag() {
    let entry = EntryInput {
        name: "f.txt".into(),
        payload: b"data".to_vec(),
        file_crc32: Some(0xDEAD_BEEF),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer.add_entry(entry).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}
