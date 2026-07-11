use std::io::Cursor;

use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD};
use sar_archive::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EntryInput};
use sar_core::{
 EntryMode,
    GlobalFlags, SarError,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};

fn read_single_entry(bytes: Vec<u8>) -> Result<Vec<u8>, SarError> {
    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes))?;
    let _ = reader.read_global_header()?;
    let entry = reader.next_entry()?.expect("entry");
    Ok(entry.payload)
}

#[test]
fn writer_reader_deflate_roundtrip_no_index() {
    let mut out = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new_with_compression(
        &mut out,
        sar_archive::ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
        sar_archive::CompressionSettings {
            algo_id: COMP_ALGO_DEFLATE,
            level: Some(6),
        },
    )
    .expect("writer");
    writer
        .add_entry(sar_archive::EntryInput::file("a.txt", b"deflate payload".repeat(64)))
        .expect("entry");
    writer.finish().expect("finish");

    let payload = read_single_entry(out).expect("read");
    assert_eq!(payload, b"deflate payload".repeat(64));
}

#[test]
fn writer_reader_zstd_roundtrip_indexed() {
    let mut out = Vec::new();
    let mut writer = sar_archive::ArchiveWriter::new_with_compression(
        &mut out,
        sar_archive::ArchiveWriterOptions {
            no_index: false,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
        sar_archive::CompressionSettings {
            algo_id: COMP_ALGO_ZSTD,
            level: Some(7),
        },
    )
    .expect("writer");
    writer
        .add_entry(sar_archive::EntryInput::file("b.txt", b"zstd payload".repeat(64)))
        .expect("entry");
    writer.finish().expect("finish");

    let payload = read_single_entry(out).expect("read");
    assert_eq!(payload, b"zstd payload".repeat(64));
}

#[test]
fn global_compressed_with_inert_entry_mode_is_effective_store() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let mut lfh = LocalFileHeader::minimal_store(b"x.bin".to_vec(), 5);
    lfh.comp_algo_id = Some(COMP_ALGO_ZSTD);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"12345");

    let mut reader = sar_archive::ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let _ = reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("next").expect("entry");
    assert_eq!(entry.payload, b"12345");
    assert_eq!(entry.metadata.compression_algo_id, COMP_ALGO_STORE);
    assert_eq!(entry.metadata.compression_algorithm, "STORE");
}

#[test]
fn compressed_entry_without_global_compressed_fails_flag_conflict() {
    let flags = GlobalFlags::NO_INDEX;
    let mut lfh = LocalFileHeader::minimal_store(b"y.bin".to_vec(), 1);
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    let err = write_lfh(&flags, &lfh).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn assigned_unsupported_compression_returns_unsupported() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let mut lfh = LocalFileHeader::minimal_store(b"u.bin".to_vec(), 3);
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    lfh.comp_algo_id = Some(0x03);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"abc");

    let err = read_single_entry(bytes).expect_err("must fail");
    assert!(matches!(err, SarError::Unsupported(_)));
}

#[test]
fn reserved_compression_returns_reserved_value() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let mut lfh = LocalFileHeader::minimal_store(b"r.bin".to_vec(), 3);
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    lfh.comp_algo_id = Some(0x80);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"abc");

    let err = read_single_entry(bytes).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn corrupted_deflate_data_returns_sar_error() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let mut lfh = LocalFileHeader::minimal_store(b"d.bin".to_vec(), 4);
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    lfh.comp_algo_id = Some(COMP_ALGO_DEFLATE);
    lfh.payload_size = 8;
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"bad-data");

    let err = read_single_entry(bytes).expect_err("must fail");
    assert!(
        matches!(
            err,
            SarError::DecompressionFailed(_)
                | SarError::InvalidLength(_)
                | SarError::Io(_)
                | SarError::LimitExceeded(_)
        ),
        "{err:?}"
    );
}

#[test]
fn corrupted_zstd_data_returns_sar_error() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let mut lfh = LocalFileHeader::minimal_store(b"z.bin".to_vec(), 4);
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    lfh.comp_algo_id = Some(COMP_ALGO_ZSTD);
    lfh.payload_size = 8;
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"bad-data");

    let err = read_single_entry(bytes).expect_err("must fail");
    assert!(matches!(err, SarError::DecompressionFailed(_)));
}

#[test]
fn decompressed_length_mismatch_returns_invalid_length() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let payload = b"length-check".repeat(16);
    let mut encoded = Vec::new();
    sar_compression::encode_stream(
        COMP_ALGO_DEFLATE,
        &mut payload.as_slice(),
        &mut encoded,
        sar_compression::CompressionOptions { level: Some(6) },
    )
    .expect("encode");
    let mut lfh = LocalFileHeader::minimal_store(
        b"m.bin".to_vec(),
        u64::try_from(encoded.len()).expect("len"),
    );
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    lfh.comp_algo_id = Some(COMP_ALGO_DEFLATE);
    lfh.uncompressed_size = u64::try_from(payload.len() + 1).expect("len");
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(&encoded);

    let err = read_single_entry(bytes).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)));
}
