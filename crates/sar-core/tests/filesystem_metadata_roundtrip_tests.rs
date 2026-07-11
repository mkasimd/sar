//! M11b — Filesystem Metadata Encode/Decode Round-Trip Tests.
//!
//! Validates HAS_PATH, HAS_PERMS, EXT_UID_GID, EXT_TIME, HAS_SYMLINKS,
//! IS_DIRECTORY, HIDDEN_ATTR, and physically-present-inactive field behavior.
//!
//! These tests cover:
//!
//! * Deterministic round-trips for every metadata field.
//! * FieldPresence three-state model for path/permissions/uid_gid/timestamps.
//! * Directory entry payload rule (IS_DIRECTORY → Payload Size MUST be 0).
//! * Symlink entry encoding/decoding.
//! * Hidden attribute encoding/decoding.
//! * Combined metadata round-trips.
//! * Physically-present-but-inactive metadata (zero/default values).
//! * NO_INDEX archive metadata.
//! * Indexed archive metadata.
//! * Compressed-entry + metadata interaction.
//! * Encrypted-entry + metadata interaction (where practical without full KMS).
//! * Fragmented-entry + metadata interaction.
//! * Sparse-entry + metadata interaction.
//! * Validation: IS_SYMLINK without HAS_SYMLINKS, directory with non-zero payload.
//! * Validation: invalid UTF-8 name/path in reader.
//!
//! No filesystem restoration is performed; all tests verify archive-level
//! metadata only.

use std::io::Cursor;

use sar_core::format::{GlobalHeader, write_global_header, write_lfh};
use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EntryInput, EntryKind,
    EntryMode, FieldPresence, GlobalFlags, SarError, SparseExtent, SparseWriteOptions,
};

// ---------------------------------------------------------------------------
// Helper: write one entry and read it back.
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
// 1. HAS_PATH — round-trip with non-empty path
// ---------------------------------------------------------------------------

#[test]
fn path_round_trip_with_has_path() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            ..Default::default()
        },
        EntryInput {
            name: "file.txt".into(),
            payload: b"hello".to_vec(),
            path: Some("docs/subdir".into()),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert_eq!(entry.metadata.path, Some("docs/subdir".into()));
    match &entry.metadata.path_presence {
        FieldPresence::PresentActive(p) => assert_eq!(p, "docs/subdir"),
        other => panic!("expected PresentActive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. HAS_PATH — physically present but inactive (path length == 0)
// ---------------------------------------------------------------------------

#[test]
fn path_present_inactive_when_has_path_set_but_no_path_provided() {
    // Writer sets HAS_PATH globally; this entry has no path → path_len = 0 in LFH.
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            ..Default::default()
        },
        EntryInput {
            name: "nopath.txt".into(),
            payload: b"data".to_vec(),
            path: None, // no path for this entry
            ..Default::default()
        },
    )
    .expect("roundtrip");

    // Legacy path field: None (empty path → None for backward compat).
    assert_eq!(entry.metadata.path, None);

    // Presence model: HAS_PATH set + path_len == 0 → PresentInactive.
    match &entry.metadata.path_presence {
        FieldPresence::PresentInactive(p) => assert!(p.is_empty(), "inactive path must be empty"),
        other => panic!("expected PresentInactive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. HAS_PATH absent (flag not set)
// ---------------------------------------------------------------------------

#[test]
fn path_absent_when_has_path_not_set() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");

    assert_eq!(entry.metadata.path, None);
    assert!(
        matches!(entry.metadata.path_presence, FieldPresence::Absent),
        "path_presence must be Absent when HAS_PATH is not set"
    );
}

// ---------------------------------------------------------------------------
// 4. HAS_PERMS — round-trip with known permission value
// ---------------------------------------------------------------------------

#[test]
fn permissions_round_trip_with_has_perms() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_permissions: true,
            ..Default::default()
        },
        EntryInput {
            name: "script.sh".into(),
            payload: b"#!/bin/sh".to_vec(),
            permissions: Some(0o755),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    let perms = entry.metadata.permissions.expect("permissions field");
    assert_eq!(perms.mode, 0o755);

    match &entry.metadata.permissions_presence {
        FieldPresence::PresentActive(p) => assert_eq!(p.mode, 0o755),
        other => panic!("expected PresentActive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. HAS_PERMS — zero permissions are preserved, not collapsed to None
// ---------------------------------------------------------------------------

#[test]
fn permissions_zero_value_not_collapsed_to_none() {
    // When HAS_PERMS is set but no permissions are provided by the entry,
    // the writer emits zero; the reader must not collapse this to Absent.
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_permissions: true,
            ..Default::default()
        },
        EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            permissions: None, // no permissions → writer writes 0
            ..Default::default()
        },
    )
    .expect("roundtrip");

    // Field is physically present; value is zero but must not be Absent.
    assert!(
        matches!(
            entry.metadata.permissions_presence,
            FieldPresence::PresentActive(_)
        ),
        "zero permissions must be PresentActive, not Absent"
    );
    if let FieldPresence::PresentActive(p) = &entry.metadata.permissions_presence {
        assert_eq!(p.mode, 0);
    }

    // Legacy field: Some({mode:0}) when HAS_PERMS is set.
    let perms = entry.metadata.permissions.expect("permissions present");
    assert_eq!(perms.mode, 0);
}

// ---------------------------------------------------------------------------
// 6. HAS_PERMS absent
// ---------------------------------------------------------------------------

#[test]
fn permissions_absent_when_has_perms_not_set() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");

    assert!(entry.metadata.permissions.is_none());
    assert!(
        matches!(entry.metadata.permissions_presence, FieldPresence::Absent),
        "permissions_presence must be Absent"
    );
}

// ---------------------------------------------------------------------------
// 7. EXT_UID_GID — round-trip
// ---------------------------------------------------------------------------

#[test]
fn uid_gid_round_trip() {
    let uid: u32 = 1001;
    let gid: u32 = 2002;
    let packed = uid | (gid << 16);

    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_uid_gid: true,
            ..Default::default()
        },
        EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            uid_gid: Some(packed),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    let owner = entry.metadata.owner.expect("owner field");
    assert_eq!(owner.uid_gid, packed);
    assert_eq!(u32::from(owner.uid()), uid);
    assert_eq!(u32::from(owner.gid()), gid);

    match &entry.metadata.owner_presence {
        FieldPresence::PresentActive(o) => {
            assert_eq!(o.uid_gid, packed);
            assert_eq!(u32::from(o.uid()), uid);
            assert_eq!(u32::from(o.gid()), gid);
        }
        other => panic!("expected PresentActive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 8. EXT_UID_GID — zero uid/gid preserved (not collapsed to None)
// ---------------------------------------------------------------------------

#[test]
fn uid_gid_zero_value_preserved() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_uid_gid: true,
            ..Default::default()
        },
        EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            uid_gid: None, // writer writes 0
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert!(
        matches!(
            entry.metadata.owner_presence,
            FieldPresence::PresentActive(_)
        ),
        "zero uid_gid must be PresentActive"
    );
    if let FieldPresence::PresentActive(o) = &entry.metadata.owner_presence {
        assert_eq!(o.uid_gid, 0);
    }

    let owner = entry.metadata.owner.expect("owner present");
    assert_eq!(owner.uid_gid, 0);
}

// ---------------------------------------------------------------------------
// 9. EXT_UID_GID absent
// ---------------------------------------------------------------------------

#[test]
fn uid_gid_absent_when_flag_not_set() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");

    assert!(entry.metadata.owner.is_none());
    assert!(
        matches!(entry.metadata.owner_presence, FieldPresence::Absent),
        "owner_presence must be Absent"
    );
}

// ---------------------------------------------------------------------------
// 10. EXT_TIME — round-trip
// ---------------------------------------------------------------------------

#[test]
fn timestamps_round_trip() {
    let ts = [1_700_000_000u64, 1_700_001_000, 1_700_002_000];

    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_timestamps: true,
            ..Default::default()
        },
        EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            timestamps: Some(ts),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    let tsmeta = entry.metadata.timestamps.expect("timestamp field");
    assert_eq!(tsmeta.mtime, ts[0]);
    assert_eq!(tsmeta.atime, ts[1]);
    assert_eq!(tsmeta.ctime, ts[2]);

    match &entry.metadata.timestamps_presence {
        FieldPresence::PresentActive(t) => {
            assert_eq!(t.mtime, ts[0]);
            assert_eq!(t.atime, ts[1]);
            assert_eq!(t.ctime, ts[2]);
        }
        other => panic!("expected PresentActive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 11. EXT_TIME — all-zero timestamps preserved (not collapsed to None)
// ---------------------------------------------------------------------------

#[test]
fn timestamps_zero_value_preserved() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_timestamps: true,
            ..Default::default()
        },
        EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            timestamps: None, // writer writes [0, 0, 0]
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert!(
        matches!(
            entry.metadata.timestamps_presence,
            FieldPresence::PresentActive(_)
        ),
        "all-zero timestamps must be PresentActive"
    );
    if let FieldPresence::PresentActive(t) = &entry.metadata.timestamps_presence {
        assert_eq!(t.mtime, 0);
        assert_eq!(t.atime, 0);
        assert_eq!(t.ctime, 0);
    }

    let ts = entry.metadata.timestamps.expect("timestamps present");
    assert_eq!(ts.mtime, 0);
    assert_eq!(ts.atime, 0);
    assert_eq!(ts.ctime, 0);
}

// ---------------------------------------------------------------------------
// 12. EXT_TIME absent
// ---------------------------------------------------------------------------

#[test]
fn timestamps_absent_when_flag_not_set() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");

    assert!(entry.metadata.timestamps.is_none());
    assert!(
        matches!(entry.metadata.timestamps_presence, FieldPresence::Absent),
        "timestamps_presence must be Absent"
    );
}

// ---------------------------------------------------------------------------
// 13. Symlink entry — round-trip (target via payload)
// ---------------------------------------------------------------------------

#[test]
fn symlink_round_trip_target_via_payload() {
    let target = b"/some/target/path";
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            ..Default::default()
        },
        EntryInput {
            name: "mylink".into(),
            payload: target.to_vec(),
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert_eq!(entry.metadata.name, "mylink");
    assert!(matches!(entry.metadata.entry_kind, EntryKind::Symlink));
    assert_ne!(
        entry.metadata.entry_mode_raw & EntryMode::IS_SYMLINK,
        0,
        "IS_SYMLINK mode bit must be set"
    );
    // Payload is the symlink target; no filesystem restoration performed.
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// 14. Symlink entry requires HAS_SYMLINKS global flag
// ---------------------------------------------------------------------------

#[test]
fn symlink_without_has_symlinks_flag_is_rejected_by_writer() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "link".into(),
            payload: b"/target".to_vec(),
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        })
        .expect_err("must fail");
    assert!(
        matches!(err, SarError::FlagConflict(_)),
        "expected FlagConflict, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 15. IS_SYMLINK in LFH without HAS_SYMLINKS global flag is rejected by reader
// ---------------------------------------------------------------------------

#[test]
fn reader_rejects_is_symlink_without_has_symlinks_global_flag() {
    // Build a raw LFH with IS_SYMLINK set but HAS_SYMLINKS global flag NOT set.
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // LFH: header_size=22 (4+2+2+2+4+4+2+2), entry_mode=IS_SYMLINK, name="lnk"
    // Fixed: 4+2+2+2+4+4 = 18; name_len:u16 = 2; name:3 = total 23
    let header_size: u32 = 18 + 2 + 3;
    bytes.extend_from_slice(&header_size.to_le_bytes());
    bytes.extend_from_slice(&EntryMode::IS_SYMLINK.to_le_bytes()); // entry_mode = IS_SYMLINK
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&3u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&3u32.to_le_bytes()); // payload_size
    bytes.extend_from_slice(&3u16.to_le_bytes()); // name_len
    bytes.extend_from_slice(b"lnk"); // name
    bytes.extend_from_slice(b"abc"); // payload (3 bytes)

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("global header");
    let err = reader
        .next_entry()
        .expect_err("must reject IS_SYMLINK without HAS_SYMLINKS");
    assert!(
        matches!(err, SarError::FlagConflict(_)),
        "expected FlagConflict, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 16. Directory entry — round-trip (zero payload)
// ---------------------------------------------------------------------------

#[test]
fn directory_entry_round_trip_zero_payload() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput {
            name: "mydir".into(),
            payload: vec![],
            kind: Some(EntryKind::Directory),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert_eq!(entry.metadata.name, "mydir");
    assert!(matches!(entry.metadata.entry_kind, EntryKind::Directory));
    assert_ne!(
        entry.metadata.entry_mode_raw & EntryMode::IS_DIRECTORY,
        0,
        "IS_DIRECTORY mode bit must be set"
    );
    assert_eq!(entry.metadata.payload_size, 0);
    assert!(entry.payload.is_empty());
}

// ---------------------------------------------------------------------------
// 17. Directory entry with non-zero payload is rejected by writer
// ---------------------------------------------------------------------------

#[test]
fn directory_entry_with_nonzero_payload_rejected_by_writer() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "mydir".into(),
            payload: b"unexpected data".to_vec(),
            kind: Some(EntryKind::Directory),
            ..Default::default()
        })
        .expect_err("must reject non-zero directory payload");
    assert!(
        matches!(err, SarError::Malformed(_)),
        "expected Malformed, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 18. Directory entry with non-zero payload is rejected by reader
// ---------------------------------------------------------------------------

#[test]
fn reader_rejects_directory_entry_with_nonzero_payload() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // IS_DIRECTORY set, payload_size = 3 (must be rejected).
    let header_size: u32 = 18 + 2 + 3;
    bytes.extend_from_slice(&header_size.to_le_bytes());
    bytes.extend_from_slice(&EntryMode::IS_DIRECTORY.to_le_bytes()); // IS_DIRECTORY
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&3u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&3u32.to_le_bytes()); // payload_size = 3 (MUST be 0)
    bytes.extend_from_slice(&3u16.to_le_bytes()); // name_len
    bytes.extend_from_slice(b"dir"); // name
    bytes.extend_from_slice(b"bad"); // payload (must be rejected)

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("global header");
    let err = reader
        .next_entry()
        .expect_err("must reject IS_DIRECTORY with non-zero payload");
    assert!(
        matches!(err, SarError::Malformed(_)),
        "expected Malformed, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 19. Hidden attribute — round-trip
// ---------------------------------------------------------------------------

#[test]
fn hidden_attribute_round_trip() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput {
            name: "hidden_file".into(),
            payload: b"secret".to_vec(),
            is_hidden: true,
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert!(entry.metadata.is_hidden, "is_hidden must be true");
    assert_ne!(
        entry.metadata.entry_mode_raw & EntryMode::HIDDEN_ATTR,
        0,
        "HIDDEN_ATTR mode bit must be set"
    );
}

// ---------------------------------------------------------------------------
// 20. Hidden attribute false when not set
// ---------------------------------------------------------------------------

#[test]
fn hidden_attribute_absent_when_not_set() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("visible.txt", b"data".to_vec()),
    )
    .expect("roundtrip");

    assert!(!entry.metadata.is_hidden, "is_hidden must be false");
    assert_eq!(
        entry.metadata.entry_mode_raw & EntryMode::HIDDEN_ATTR,
        0,
        "HIDDEN_ATTR mode bit must be unset"
    );
}

// ---------------------------------------------------------------------------
// 21. Combined metadata round-trip (all filesystem metadata flags together)
// ---------------------------------------------------------------------------

#[test]
fn combined_metadata_round_trip() {
    let ts = [1_600_000_000u64, 1_600_001_000, 1_600_002_000];
    let uid: u32 = 500;
    let gid: u32 = 1000;
    let uid_gid = uid | (gid << 16);

    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            with_permissions: true,
            with_uid_gid: true,
            with_timestamps: true,
            ..Default::default()
        },
        EntryInput {
            name: "combined.txt".into(),
            payload: b"combined test".to_vec(),
            path: Some("a/b/c".into()),
            permissions: Some(0o644),
            uid_gid: Some(uid_gid),
            timestamps: Some(ts),
            is_hidden: false,
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert_eq!(entry.metadata.name, "combined.txt");
    assert_eq!(entry.metadata.path, Some("a/b/c".into()));

    // Path presence.
    match &entry.metadata.path_presence {
        FieldPresence::PresentActive(p) => assert_eq!(p, "a/b/c"),
        other => panic!("path_presence: expected PresentActive, got {other:?}"),
    }

    // Permissions.
    let perms = entry.metadata.permissions.expect("permissions");
    assert_eq!(perms.mode, 0o644);
    match &entry.metadata.permissions_presence {
        FieldPresence::PresentActive(p) => assert_eq!(p.mode, 0o644),
        other => panic!("permissions_presence: expected PresentActive, got {other:?}"),
    }

    // UID/GID.
    let owner = entry.metadata.owner.expect("owner");
    assert_eq!(owner.uid_gid, uid_gid);
    match &entry.metadata.owner_presence {
        FieldPresence::PresentActive(o) => assert_eq!(o.uid_gid, uid_gid),
        other => panic!("owner_presence: expected PresentActive, got {other:?}"),
    }

    // Timestamps.
    let tsmeta = entry.metadata.timestamps.expect("timestamps");
    assert_eq!(tsmeta.mtime, ts[0]);
    assert_eq!(tsmeta.atime, ts[1]);
    assert_eq!(tsmeta.ctime, ts[2]);
    match &entry.metadata.timestamps_presence {
        FieldPresence::PresentActive(t) => {
            assert_eq!(t.mtime, ts[0]);
            assert_eq!(t.atime, ts[1]);
            assert_eq!(t.ctime, ts[2]);
        }
        other => panic!("timestamps_presence: expected PresentActive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 22. Indexed archive metadata (no_index = false)
// ---------------------------------------------------------------------------

#[test]
fn metadata_round_trip_indexed_archive() {
    let ts = [999u64, 1000, 1001];
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: false,
            with_path: true,
            with_permissions: true,
            with_timestamps: true,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "indexed.txt".into(),
            payload: b"indexed data".to_vec(),
            path: Some("docs".into()),
            permissions: Some(0o755),
            timestamps: Some(ts),
            ..Default::default()
        })
        .expect("add entry");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    assert_eq!(entry.metadata.path, Some("docs".into()));
    match &entry.metadata.path_presence {
        FieldPresence::PresentActive(p) => assert_eq!(p, "docs"),
        other => panic!("expected PresentActive, got {other:?}"),
    }
    let perms = entry.metadata.permissions.expect("permissions");
    assert_eq!(perms.mode, 0o755);
    let tsmeta = entry.metadata.timestamps.expect("timestamps");
    assert_eq!(tsmeta.mtime, ts[0]);
}

// ---------------------------------------------------------------------------
// 23. NO_INDEX archive metadata
// ---------------------------------------------------------------------------

#[test]
fn metadata_round_trip_no_index_archive() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            with_permissions: true,
            with_uid_gid: true,
            with_timestamps: true,
            ..Default::default()
        },
    )
    .expect("writer");

    let ts = [12345u64, 23456, 34567];
    writer
        .add_entry(EntryInput {
            name: "noindex.txt".into(),
            payload: b"no index data".to_vec(),
            path: Some("mydir".into()),
            permissions: Some(0o600),
            uid_gid: Some(1u32 | (2u32 << 16)),
            timestamps: Some(ts),
            ..Default::default()
        })
        .expect("add entry");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    assert_eq!(entry.metadata.path, Some("mydir".into()));
    assert_eq!(entry.metadata.permissions.expect("perms").mode, 0o600);
    assert_eq!(
        entry.metadata.owner.expect("owner").uid_gid,
        1u32 | (2u32 << 16)
    );
    let tsmeta = entry.metadata.timestamps.expect("timestamps");
    assert_eq!(tsmeta.mtime, ts[0]);
    assert_eq!(tsmeta.atime, ts[1]);
    assert_eq!(tsmeta.ctime, ts[2]);
}

// ---------------------------------------------------------------------------
// 24. Metadata with compressed entry
// ---------------------------------------------------------------------------

#[test]
fn metadata_present_in_lfh_before_compressed_payload() {
    let ts = [111u64, 222, 333];
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            with_permissions: true,
            with_timestamps: true,
            ..Default::default()
        },
        CompressionSettings {
            algo_id: 0x02, // ZSTD
            level: None,
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "compressed.txt".into(),
            payload: b"compress me!".repeat(200),
            path: Some("comp/dir".into()),
            permissions: Some(0o644),
            timestamps: Some(ts),
            ..Default::default()
        })
        .expect("add");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    // LFH metadata must be parseable before payload decompression.
    assert_eq!(entry.metadata.path, Some("comp/dir".into()));
    match &entry.metadata.path_presence {
        FieldPresence::PresentActive(p) => assert_eq!(p, "comp/dir"),
        other => panic!("expected PresentActive, got {other:?}"),
    }
    let perms = entry.metadata.permissions.expect("permissions");
    assert_eq!(perms.mode, 0o644);
    let tsmeta = entry.metadata.timestamps.expect("timestamps");
    assert_eq!(tsmeta.mtime, ts[0]);

    // Compression was active.
    assert!(entry.metadata.is_compressed);
}

// ---------------------------------------------------------------------------
// 25. Metadata with fragmented entry
// ---------------------------------------------------------------------------

#[test]
fn metadata_with_fragmented_entry() {
    use sar_core::format::{LfhFragmentDescriptor, LocalFileHeader};

    // Build a two-fragment archive manually: each fragment carries metadata.
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::HAS_PERMS;

    let mut buf = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // Fragment 0
    let frag0_mode = EntryMode::from_bits(EntryMode::FRAGMENT);
    let mut frag0 = LocalFileHeader::minimal_store(b"multipart.bin".to_vec(), 6);
    frag0.entry_mode = frag0_mode;
    frag0.fragment_id = Some(42);
    frag0.fragment_index = Some(0);
    frag0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 6,
    });
    frag0.permissions = Some(0o755);
    let frag0_bytes = write_lfh(&flags, &frag0).expect("frag0 lfh");
    buf.extend_from_slice(&frag0_bytes);
    buf.extend_from_slice(b"hello ");

    // Fragment 1 (LAST_FRAGMENT)
    let frag1_mode = EntryMode::from_bits(EntryMode::FRAGMENT | EntryMode::LAST_FRAGMENT);
    let mut frag1 = LocalFileHeader::minimal_store(b"".to_vec(), 5);
    frag1.entry_mode = frag1_mode;
    frag1.fragment_id = Some(42);
    frag1.fragment_index = Some(1);
    frag1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 6,
        fragment_size: 5,
    });
    frag1.permissions = Some(0o755);
    let frag1_bytes = write_lfh(&flags, &frag1).expect("frag1 lfh");
    buf.extend_from_slice(&frag1_bytes);
    buf.extend_from_slice(b"world");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");

    // Read fragment 0.
    let e0 = reader.next_entry().expect("ok").expect("frag0");
    assert_eq!(e0.metadata.name, "multipart.bin");
    assert_eq!(e0.metadata.permissions.expect("perms frag0").mode, 0o755);
    assert!(matches!(
        e0.metadata.permissions_presence,
        FieldPresence::PresentActive(_)
    ));

    // Read fragment 1.
    let e1 = reader.next_entry().expect("ok").expect("frag1");
    assert_eq!(e1.metadata.permissions.expect("perms frag1").mode, 0o755);
}

// ---------------------------------------------------------------------------
// 26. Metadata with sparse entry (field-order coexistence)
// ---------------------------------------------------------------------------

#[test]
fn metadata_with_sparse_entry() {
    // write_sparse_entry does not accept EntryInput, so we test that
    // sparse extents are present alongside whatever metadata the writer emits.
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .write_sparse_entry(
            "sparse.bin",
            b"data",
            SparseWriteOptions {
                logical_size: 100,
                extents: vec![SparseExtent {
                    offset: 0,
                    length: 4,
                }],
            },
        )
        .expect("sparse write");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    assert_eq!(entry.metadata.name, "sparse.bin");
    // Sparse extents must be present even without other metadata flags.
    assert!(
        entry.metadata.sparse_extents.is_some(),
        "sparse_extents must be present"
    );
    assert!(
        entry.metadata.sparse.is_some(),
        "sparse metadata must be present"
    );
    let extents = entry
        .metadata
        .sparse_extents
        .expect("sparse_extents must be present");
    assert_eq!(extents.len(), 1);
    assert_eq!(extents[0].offset, 0);
    assert_eq!(extents[0].length, 4);
}

// ---------------------------------------------------------------------------
// 27. Metadata with sparse + metadata flags via write_sparse_entry workaround
// ---------------------------------------------------------------------------
//
// write_sparse_entry does not accept EntryInput directly, so we verify that
// the permissions/timestamps presence model correctly shows Absent when
// HAS_PERMS / EXT_TIME are NOT set in the sparse archive.
#[test]
fn sparse_entry_permissions_absent_when_flag_not_set() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .write_sparse_entry(
            "s.bin",
            b"abcd",
            SparseWriteOptions {
                logical_size: 100,
                extents: vec![SparseExtent {
                    offset: 0,
                    length: 4,
                }],
            },
        )
        .expect("sparse write");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("ok").expect("entry");

    assert!(
        matches!(entry.metadata.permissions_presence, FieldPresence::Absent),
        "permissions_presence must be Absent when HAS_PERMS is not set"
    );
    assert!(
        matches!(entry.metadata.timestamps_presence, FieldPresence::Absent),
        "timestamps_presence must be Absent when EXT_TIME is not set"
    );
}

// ---------------------------------------------------------------------------
// 28. Invalid UTF-8 name bytes rejected by reader
// ---------------------------------------------------------------------------

#[test]
fn reader_rejects_invalid_utf8_name() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // LFH with invalid UTF-8 bytes as name.
    let invalid_name = b"\xFF\xFE"; // invalid UTF-8
    let name_len = invalid_name.len() as u16;
    let header_size: u32 = 18 + 2 + u32::from(name_len);
    bytes.extend_from_slice(&header_size.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // entry_mode
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&2u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&2u32.to_le_bytes()); // payload_size
    bytes.extend_from_slice(&name_len.to_le_bytes()); // name_len
    bytes.extend_from_slice(invalid_name); // invalid UTF-8 name
    bytes.extend_from_slice(b"AB"); // payload

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader
        .next_entry()
        .expect_err("must reject invalid UTF-8 name");
    assert!(
        matches!(err, SarError::Malformed(_)),
        "expected Malformed for invalid UTF-8 name, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 29. Invalid UTF-8 path bytes rejected by reader
// ---------------------------------------------------------------------------

#[test]
fn reader_rejects_invalid_utf8_path() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_PATH;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // LFH with HAS_PATH, valid name, invalid UTF-8 path.
    let name = b"ok";
    let invalid_path = b"\xFF\xFE";
    let header_size: u32 = 18 + 2 + 2 + name.len() as u32 + invalid_path.len() as u32;
    bytes.extend_from_slice(&header_size.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // entry_mode
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&2u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&2u32.to_le_bytes()); // payload_size
    bytes.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    bytes.extend_from_slice(&(invalid_path.len() as u16).to_le_bytes()); // path_len
    bytes.extend_from_slice(name); // name
    bytes.extend_from_slice(invalid_path); // invalid UTF-8 path
    bytes.extend_from_slice(b"AB"); // payload

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader
        .next_entry()
        .expect_err("must reject invalid UTF-8 path");
    assert!(
        matches!(err, SarError::Malformed(_)),
        "expected Malformed for invalid UTF-8 path, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 30. Path length validation in writer
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_path_exceeding_u16_capacity() {
    let long_path = "x".repeat(65536); // exceeds u16::MAX
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            path: Some(long_path),
            ..Default::default()
        })
        .expect_err("must reject path exceeding u16 capacity");
    assert!(
        matches!(err, SarError::Overflow(_)),
        "expected Overflow, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 31. Name length validation in writer
// ---------------------------------------------------------------------------

#[test]
fn writer_rejects_name_exceeding_u16_capacity() {
    let long_name = "n".repeat(65536); // exceeds u16::MAX
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: long_name,
            payload: b"data".to_vec(),
            ..Default::default()
        })
        .expect_err("must reject name exceeding u16 capacity");
    assert!(
        matches!(err, SarError::Overflow(_)),
        "expected Overflow, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 32. Multiple entries — metadata correct for each entry independently
// ---------------------------------------------------------------------------

#[test]
fn multiple_entries_metadata_independent() {
    let ts_a = [100u64, 200, 300];
    let ts_b = [400u64, 500, 600];

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            with_permissions: true,
            with_timestamps: true,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "a.txt".into(),
            payload: b"aaa".to_vec(),
            path: Some("alpha".into()),
            permissions: Some(0o644),
            timestamps: Some(ts_a),
            ..Default::default()
        })
        .expect("add a");
    writer
        .add_entry(EntryInput {
            name: "b.txt".into(),
            payload: b"bbb".to_vec(),
            path: Some("beta".into()),
            permissions: Some(0o755),
            timestamps: Some(ts_b),
            ..Default::default()
        })
        .expect("add b");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(buf)).expect("reader");
    reader.read_global_header().expect("header");

    let ea = reader.next_entry().expect("ok").expect("entry a");
    assert_eq!(ea.metadata.name, "a.txt");
    assert_eq!(ea.metadata.path, Some("alpha".into()));
    assert_eq!(ea.metadata.permissions.expect("perms a").mode, 0o644);
    assert_eq!(ea.metadata.timestamps.expect("ts a").mtime, ts_a[0]);

    let eb = reader.next_entry().expect("ok").expect("entry b");
    assert_eq!(eb.metadata.name, "b.txt");
    assert_eq!(eb.metadata.path, Some("beta".into()));
    assert_eq!(eb.metadata.permissions.expect("perms b").mode, 0o755);
    assert_eq!(eb.metadata.timestamps.expect("ts b").mtime, ts_b[0]);
}

// ---------------------------------------------------------------------------
// 33. Symlink + metadata flags together
// ---------------------------------------------------------------------------

#[test]
fn symlink_with_all_metadata_flags() {
    let ts = [777u64, 888, 999];
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            with_path: true,
            with_permissions: true,
            with_timestamps: true,
            ..Default::default()
        },
        EntryInput {
            name: "a_link".into(),
            payload: b"/usr/bin/target".to_vec(),
            kind: Some(EntryKind::Symlink),
            path: Some("links/dir".into()),
            permissions: Some(0o777),
            timestamps: Some(ts),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert!(matches!(entry.metadata.entry_kind, EntryKind::Symlink));
    assert_eq!(entry.payload, b"/usr/bin/target");
    assert_eq!(entry.metadata.path, Some("links/dir".into()));
    assert_eq!(entry.metadata.permissions.expect("perms").mode, 0o777);
    assert_eq!(entry.metadata.timestamps.expect("ts").mtime, ts[0]);
}

// ---------------------------------------------------------------------------
// 34. Directory + metadata flags together
// ---------------------------------------------------------------------------

#[test]
fn directory_with_all_metadata_flags() {
    let ts = [1u64, 2, 3];
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            with_permissions: true,
            with_uid_gid: true,
            with_timestamps: true,
            ..Default::default()
        },
        EntryInput {
            name: "adir".into(),
            payload: vec![],
            kind: Some(EntryKind::Directory),
            path: Some("parent/adir".into()),
            permissions: Some(0o755),
            uid_gid: Some(100u32 << 16),
            timestamps: Some(ts),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert!(matches!(entry.metadata.entry_kind, EntryKind::Directory));
    assert_eq!(entry.payload, b"");
    assert_eq!(entry.metadata.payload_size, 0);
    assert_eq!(entry.metadata.path, Some("parent/adir".into()));
    assert_eq!(entry.metadata.permissions.expect("perms").mode, 0o755);
    assert_eq!(entry.metadata.timestamps.expect("ts").mtime, ts[0]);
}

// ---------------------------------------------------------------------------
// 35. FieldPresence Absent means neither value() nor is_active()
// ---------------------------------------------------------------------------

#[test]
fn field_presence_absent_means_no_value_and_not_active() {
    let entry = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        EntryInput::file("f.txt", b"data".to_vec()),
    )
    .expect("roundtrip");

    // All filesystem metadata FieldPresence fields must be Absent when flags not set.
    assert!(entry.metadata.path_presence.is_absent());
    assert!(!entry.metadata.path_presence.is_active());
    assert!(entry.metadata.path_presence.value().is_none());

    assert!(entry.metadata.permissions_presence.is_absent());
    assert!(entry.metadata.owner_presence.is_absent());
    assert!(entry.metadata.timestamps_presence.is_absent());
}

// ---------------------------------------------------------------------------
// 36. Writer rejects path without HAS_PATH (fail-closed, no silent drop)
// ---------------------------------------------------------------------------

#[test]
fn writer_fails_closed_for_path_without_flag() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            path: Some("somewhere".into()),
            ..Default::default()
        })
        .expect_err("must fail");
    assert!(
        matches!(err, SarError::FlagConflict(_)),
        "expected FlagConflict, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 37. Writer rejects permissions without HAS_PERMS (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn writer_fails_closed_for_permissions_without_flag() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            permissions: Some(0o644),
            ..Default::default()
        })
        .expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 38. Writer rejects uid_gid without EXT_UID_GID (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn writer_fails_closed_for_uid_gid_without_flag() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            uid_gid: Some(1000),
            ..Default::default()
        })
        .expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 39. Writer rejects timestamps without EXT_TIME (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn writer_fails_closed_for_timestamps_without_flag() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf, ArchiveWriterOptions::default()).expect("writer");
    let err = writer
        .add_entry(EntryInput {
            name: "f.txt".into(),
            payload: b"data".to_vec(),
            timestamps: Some([0, 0, 0]),
            ..Default::default()
        })
        .expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

// ---------------------------------------------------------------------------
// 40. Path presence model is authoritative over the legacy path field
// ---------------------------------------------------------------------------

#[test]
fn path_presence_model_is_authoritative() {
    // When HAS_PATH is set and path is empty, path = None (legacy compat)
    // but path_presence = PresentInactive (authoritative model).
    let entry_no_path = write_read_entry(
        ArchiveWriterOptions {
            no_index: true,
            with_path: true,
            ..Default::default()
        },
        EntryInput {
            name: "x.txt".into(),
            payload: b"data".to_vec(),
            path: None,
            ..Default::default()
        },
    )
    .expect("roundtrip");
    assert_eq!(entry_no_path.metadata.path, None); // legacy: None
    assert!(
        entry_no_path.metadata.path_presence.is_present(),
        "path_presence must be present (HAS_PATH is set)"
    );
    assert!(
        !entry_no_path.metadata.path_presence.is_active(),
        "path_presence must be inactive (no path provided)"
    );

    // When HAS_PATH is not set, both should be None/Absent.
    let entry_no_flag = write_read_entry(
        ArchiveWriterOptions::default(),
        EntryInput::file("y.txt", b"data".to_vec()),
    )
    .expect("roundtrip");
    assert_eq!(entry_no_flag.metadata.path, None);
    assert!(entry_no_flag.metadata.path_presence.is_absent());
}
