// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_imports)]
use std::io::Cursor;

use sar_archive::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::{
    GlobalFlags, SarError,
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

    bytes.extend_from_slice(&17u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"x");
    bytes.extend_from_slice(b"abc");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header parse");
    let err = reader.next_entry().expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn global_encrypted_with_plaintext_entry_passes_through() {
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
            payload: {
                let mut payload = vec![1, 16];
                payload.extend_from_slice(&[0x11; 16]);
                payload.extend_from_slice(&100_000u32.to_le_bytes());
                payload.extend_from_slice(&32u16.to_le_bytes());
                payload
            },
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

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let _ = reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("next").expect("entry");
    assert_eq!(entry.payload, b"a");
}

#[test]
fn writer_reader_store_no_index_roundtrip() {
    let mut out = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new(
        &mut out,
        sar_archive::ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(sar_archive::EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(out)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("next").expect("entry");
    assert_eq!(entry.metadata.name, "a.txt");
    assert_eq!(entry.payload, b"abc");
}
