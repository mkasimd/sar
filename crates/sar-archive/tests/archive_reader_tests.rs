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

fn read_vector(rel: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .join(rel);
    std::fs::read(path).expect("read vector")
}

#[test]
fn truncated_global_header_vector_is_truncated() {
    let bytes = read_vector("invalid/structure/truncated-gh/truncated_global_header.sar");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader.read_global_header().expect_err("truncated");
    assert!(matches!(err, SarError::Truncated(_)), "{err:?}");
}

#[test]
fn truncated_lfh_vector_is_truncated() {
    let bytes = read_vector("invalid/structure/truncated-lfh/truncated_lfh.sar");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader
        .read_global_header()
        .and_then(|_| reader.next_entry().map(|_| ()))
        .expect_err("truncated");
    assert!(matches!(err, SarError::Truncated(_)), "{err:?}");
}

#[test]
fn clean_end_of_data_area_is_not_truncation() {
    let flags = GlobalFlags::NO_INDEX;
    let bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    assert!(reader.next_entry().expect("clean eof").is_none());
}

struct FailingReader {
    inner: Cursor<Vec<u8>>,
    fail_after: u64,
}

impl std::io::Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inner.position() >= self.fail_after {
            return Err(std::io::Error::other("injected failure"));
        }
        self.inner.read(buf)
    }
}

impl std::io::Seek for FailingReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn non_eof_io_failure_stays_io() {
    let bytes = read_vector("invalid/structure/truncated-gh/truncated_global_header.sar");
    let mut reader = ArchiveReader::new(FailingReader {
        inner: Cursor::new(bytes),
        fail_after: 0,
    })
    .expect("reader");
    let err = reader.read_global_header().expect_err("io");
    assert!(matches!(err, SarError::Io(_)), "{err:?}");
}
