#![allow(unused_imports)]
use std::io::Cursor;

use tempfile::tempdir;

use sar_archive::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::format::{GlobalHeader, write_global_header};
use sar_core::{EntryKind, EntryMode, GlobalFlags, SarError};

fn write_read_entry(
    opts: sar_archive::ArchiveWriterOptions,
    entry: sar_archive::EntryInput,
) -> Result<sar_archive::EntryReader, SarError> {
    let mut buf = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new(&mut buf, opts)?;
    writer.add_entry(entry)?;
    writer.finish()?;

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(buf))?;
    reader.read_global_header()?;
    reader.next_entry()?.ok_or(SarError::Malformed("no entry"))
}

#[test]
fn symlink_utf8_target_round_trips_in_metadata_and_payload() {
    let target = "target/✅";
    let entry = write_read_entry(
        sar_archive::ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            ..Default::default()
        },
        sar_archive::EntryInput {
            name: "link".into(),
            payload: target.as_bytes().to_vec(),
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert_eq!(entry.metadata.symlink_target.as_deref(), Some(target));
    assert_eq!(entry.payload, target.as_bytes());
}

#[test]
fn non_symlink_entry_has_no_symlink_target_metadata() {
    let entry = write_read_entry(
        sar_archive::ArchiveWriterOptions {
            no_index: true,
            ..Default::default()
        },
        sar_archive::EntryInput::file("file.txt", b"payload".to_vec()),
    )
    .expect("roundtrip");

    assert!(entry.metadata.symlink_target.is_none());
}

#[test]
fn writer_rejects_symlink_payload_with_invalid_utf8() {
    let mut buf = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new(
        &mut buf,
        sar_archive::ArchiveWriterOptions {
            with_symlinks: true,
            ..Default::default()
        },
    )
    .expect("writer");

    let err = writer
        .add_entry(sar_archive::EntryInput {
            name: "link".into(),
            payload: vec![0xFF, 0xFE],
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        })
        .expect_err("must reject invalid UTF-8 symlink payload");
    assert!(matches!(err, SarError::Malformed(_)));
}

#[test]
fn reader_rejects_raw_symlink_lfh_with_invalid_utf8_payload() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_SYMLINKS;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    // LFH: fixed 18 + name_len field 2 + name bytes 3 = 23.
    bytes.extend_from_slice(&23u32.to_le_bytes());
    bytes.extend_from_slice(&EntryMode::IS_SYMLINK.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&2u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&2u32.to_le_bytes()); // payload_size
    bytes.extend_from_slice(&3u16.to_le_bytes()); // name_len
    bytes.extend_from_slice(b"lnk");
    bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8 symlink target payload

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("global header");
    let err = reader
        .next_entry()
        .expect_err("must reject invalid UTF-8 symlink payload");
    assert!(matches!(err, SarError::Malformed(_)));
}

#[test]
fn is_symlink_without_has_symlinks_remains_rejected() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    bytes.extend_from_slice(&23u32.to_le_bytes());
    bytes.extend_from_slice(&EntryMode::IS_SYMLINK.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // stream_id
    bytes.extend_from_slice(&0u16.to_le_bytes()); // sequence_no
    bytes.extend_from_slice(&3u32.to_le_bytes()); // uncompressed_size
    bytes.extend_from_slice(&3u32.to_le_bytes()); // payload_size
    bytes.extend_from_slice(&3u16.to_le_bytes()); // name_len
    bytes.extend_from_slice(b"lnk");
    bytes.extend_from_slice(b"abc");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("global header");
    let err = reader
        .next_entry()
        .expect_err("must reject IS_SYMLINK without HAS_SYMLINKS");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn reading_symlink_entry_does_not_create_filesystem_symlink() {
    let dir = tempdir().expect("tempdir");
    let link_path = dir.path().join("should_not_exist_link");
    assert!(!link_path.exists());

    let _ = write_read_entry(
        sar_archive::ArchiveWriterOptions {
            no_index: true,
            with_symlinks: true,
            ..Default::default()
        },
        sar_archive::EntryInput {
            name: "virtual_link".into(),
            payload: b"/virtual/target".to_vec(),
            kind: Some(EntryKind::Symlink),
            ..Default::default()
        },
    )
    .expect("roundtrip");

    assert!(!link_path.exists(), "reader must not create host symlinks");
}
