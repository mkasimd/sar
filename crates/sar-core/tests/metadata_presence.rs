use sar_core::{
    ArchiveReader, ArchiveWriter, CompressionAlgorithm, EntryCompressionMetadata, EntryInput,
    FieldPresence, GlobalFlags, SarError,
};

#[test]
fn compression_absent_when_global_flag_not_set() {
    let mut writer = ArchiveWriter::new(GlobalFlags::empty());
    writer
        .add_entry(EntryInput::file("plain.txt", b"abc".to_vec()))
        .unwrap();

    let mut bytes = Vec::new();
    writer.write_to(&mut bytes).unwrap();

    let mut reader = ArchiveReader::new(bytes.as_slice()).unwrap();
    let (metadata, _) = reader.next_entry().unwrap().unwrap();
    assert_eq!(metadata.compression, FieldPresence::Absent);
}

#[test]
fn compression_present_inactive_when_global_flag_set_but_entry_omits_metadata() {
    let mut writer = ArchiveWriter::new(GlobalFlags::COMPRESSION);
    writer
        .add_entry(EntryInput::file("plain.txt", b"abc".to_vec()))
        .unwrap();

    let mut bytes = Vec::new();
    writer.write_to(&mut bytes).unwrap();

    let mut reader = ArchiveReader::new(bytes.as_slice()).unwrap();
    let (metadata, payload) = reader.next_entry().unwrap().unwrap();
    assert_eq!(payload, b"abc");
    assert_eq!(
        metadata.compression,
        FieldPresence::PresentInactive(EntryCompressionMetadata {
            algorithm: CompressionAlgorithm::None,
            compressed_size: 0,
        })
    );
}

#[test]
fn compression_present_active_when_entry_supplies_metadata() {
    let mut entry = EntryInput::file("compressed.bin", vec![1, 2, 3]);
    entry.compression = Some(EntryCompressionMetadata {
        algorithm: CompressionAlgorithm::Zstd,
        compressed_size: 3,
    });

    let mut writer = ArchiveWriter::new(GlobalFlags::COMPRESSION);
    writer.add_entry(entry).unwrap();

    let mut bytes = Vec::new();
    writer.write_to(&mut bytes).unwrap();

    let mut reader = ArchiveReader::new(bytes.as_slice()).unwrap();
    let (metadata, payload) = reader.next_entry().unwrap().unwrap();
    assert_eq!(payload, vec![1, 2, 3]);
    assert_eq!(
        metadata.compression,
        FieldPresence::PresentActive(EntryCompressionMetadata {
            algorithm: CompressionAlgorithm::Zstd,
            compressed_size: 3,
        })
    );
}

#[test]
fn writer_rejects_missing_compression_flag() {
    let mut entry = EntryInput::file("compressed.bin", vec![1, 2, 3]);
    entry.compression = Some(EntryCompressionMetadata {
        algorithm: CompressionAlgorithm::Deflate,
        compressed_size: 3,
    });

    let mut writer = ArchiveWriter::new(GlobalFlags::empty());
    let err = writer.add_entry(entry).unwrap_err();

    match err {
        SarError::EntryMetadataRequiresFlag {
            field,
            required_flag,
        } => {
            assert_eq!(field, "compression");
            assert_eq!(required_flag, GlobalFlags::COMPRESSION.bits());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
