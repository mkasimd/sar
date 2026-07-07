use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput, GlobalFlags, SarError,
    format::{GlobalHeader, KmsData, write_global_header},
};

#[test]
fn payload_out_of_bounds_is_rejected() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    // LFH with payload size 10, but only 3 bytes present.
    bytes.extend_from_slice(&17u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"x");
    bytes.extend_from_slice(b"abc");

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header parse");
    let err = reader.next_entry().expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn encrypted_archive_rejected_as_unsupported() {
    let header = GlobalHeader {
        version: 1,
        flags_bytes: (GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX)
            .bits()
            .to_le_bytes()
            .to_vec(),
        flags: GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX,
        partition_descriptor: None,
        kms: Some(KmsData {
            mode_id: 0x01,
            payload: vec![1, 2, 3],
        }),
    };
    let mut bytes = write_global_header(&header).expect("header");
    bytes.extend_from_slice(&46u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&[0u8; 24]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"x");
    bytes.extend_from_slice(b"a");

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let _ = reader.read_global_header().expect("header");
    let err = reader.next_entry().expect_err("must fail");
    assert!(matches!(err, SarError::Unsupported(_)));
}

#[test]
fn writer_reader_store_no_index_roundtrip() {
    let mut out = Vec::new();
    let mut writer =
        ArchiveWriter::new(&mut out, ArchiveWriterOptions { no_index: true }).expect("writer");
    writer
        .add_entry(EntryInput {
            name: "a.txt".into(),
            payload: b"abc".to_vec(),
        })
        .expect("entry");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(out)).expect("reader");
    reader.read_global_header().expect("header");
    let e = reader.next_entry().expect("next").expect("entry");
    assert_eq!(e.metadata.name, "a.txt");
    assert_eq!(e.payload, b"abc");
}
