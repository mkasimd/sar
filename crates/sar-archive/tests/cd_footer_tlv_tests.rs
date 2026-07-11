#![allow(unused_imports)]
use std::io::Cursor;

use sar_archive::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput};
use sar_core::{
    GlobalFlags, SarError,
    format::{
        CentralDictionary, Footer, parse_central_dictionary, parse_footer,
        write_central_dictionary, write_footer,
    },
    tlv::{Tlv, parse_tlvs, write_tlvs},
};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

#[test]
fn valid_indexed_archive_roundtrip_offsets_verify() {
    let mut out = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new(
        &mut out,
        sar_archive::ArchiveWriterOptions {
            no_index: false,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(sar_archive::EntryInput::file("one.txt", b"one".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(out)).expect("reader");
    reader.read_global_header().expect("header");
    let report = reader.verify().expect("verify");
    assert!(report.valid);
    assert!(report.indexed);
}

#[test]
fn valid_no_index_archive_roundtrip_verify() {
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
        .add_entry(sar_archive::EntryInput::file("one.txt", b"one".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(out)).expect("reader");
    reader.read_global_header().expect("header");
    let report = reader.verify().expect("verify");
    assert!(report.valid);
    assert!(!report.indexed);
}

#[test]
fn footer_missing_when_no_index_unset_fails() {
    let mut broken = b"SAR!\x01\x00\x04\x00".to_vec();
    broken.extend_from_slice(&0u32.to_le_bytes());
    let err = sar_archive::ArchiveReader::new(Cursor::new(broken))
        .expect("reader")
        .read_global_header()
        .expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_) | SarError::Bounds(_)));
}

#[test]
fn cd_offset_out_of_bounds_fails() {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&write_footer(Footer { cd_offset: 9_999 }));
    let err = sar_archive::ArchiveReader::new(Cursor::new(bytes))
        .expect("reader")
        .read_global_header()
        .expect_err("must fail");
    assert!(matches!(
        err,
        SarError::Bounds(_) | SarError::Truncated(_) | SarError::InvalidVersion(_)
    ));
}

#[test]
fn cd_overlap_footer_fails() {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 4]);
    bytes.extend_from_slice(&write_footer(Footer {
        cd_offset: (bytes.len() as u64) - 4,
    }));
    let err = sar_archive::ArchiveReader::new(Cursor::new(bytes))
        .expect("reader")
        .read_global_header()
        .expect_err("must fail");
    assert!(matches!(
        err,
        SarError::Bounds(_) | SarError::Truncated(_) | SarError::InvalidVersion(_)
    ));
}

#[test]
fn invalid_cd_padding_fails() {
    let cd = CentralDictionary {
        version: 1,
        file_count: 0,
        partition_info: None,
        global_crc32: None,
        metadata: Vec::new(),
        offsets: Vec::new(),
    };
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let cd_offset = bytes.len() as u64;
    let cd_bytes = write_central_dictionary(&cd, GlobalFlags::empty()).expect("cd");
    bytes.extend_from_slice(&cd_bytes);
    bytes.push(1);
    bytes.extend_from_slice(&write_footer(Footer { cd_offset }));

    let err = sar_archive::ArchiveReader::new(Cursor::new(bytes))
        .expect("reader")
        .read_global_header()
        .expect_err("must fail");
    assert!(matches!(err, SarError::InvalidAlignment(_)));
}

#[test]
fn tlv_alignment_and_zero_padding_roundtrip() {
    let encoded = write_tlvs(&[Tlv {
        type_id: 0x30,
        value: vec![1, 2, 3],
    }])
    .expect("encode");
    assert_eq!(encoded.len() % 8, 0);
    let parsed = parse_tlvs(&encoded, &unlimited_limits()).expect("parse");
    assert_eq!(parsed[0].value, vec![1, 2, 3]);
}

#[test]
fn tlv_reserved_length_rejected() {
    let mut bytes = Vec::new();
    bytes.push(0x30);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let err = parse_tlvs(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn tlv_reserved_and_unsupported_types() {
    let mut reserved = vec![0x00];
    reserved.extend_from_slice(&0u32.to_le_bytes());
    reserved.extend_from_slice(&[0, 0, 0]);
    let err = parse_tlvs(&reserved, &unlimited_limits()).expect_err("reserved type");
    assert!(matches!(err, SarError::ReservedValue(_)));

    let mut unsupported = vec![0x20];
    unsupported.extend_from_slice(&0u32.to_le_bytes());
    unsupported.extend_from_slice(&[0, 0, 0]);
    let err = parse_tlvs(&unsupported, &unlimited_limits()).expect_err("unsupported type");
    assert!(matches!(err, SarError::Unsupported(_)));
}

#[test]
fn parse_write_footer_helpers() {
    let footer = Footer { cd_offset: 42 };
    let encoded = write_footer(footer);
    let parsed = parse_footer(&encoded).expect("parse");
    assert_eq!(parsed.cd_offset, 42);
}

#[test]
fn parse_write_cd_helpers() {
    let cd = CentralDictionary {
        version: 1,
        file_count: 1,
        partition_info: None,
        global_crc32: None,
        metadata: vec![],
        offsets: vec![8],
    };
    let bytes = write_central_dictionary(&cd, GlobalFlags::empty()).expect("write");
    let (parsed, consumed) =
        parse_central_dictionary(&bytes, GlobalFlags::empty(), &unlimited_limits()).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.offsets, vec![8]);
}
