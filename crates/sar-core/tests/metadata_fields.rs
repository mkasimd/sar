use sar_core::{
    ArchiveReader, ArchiveWriter, CdcAlgorithm, CompressionAlgorithm, DeltaAlgorithm,
    EncryptionAlgorithm, EntryCdcMetadata, EntryCompressionMetadata, EntryDeltaMetadata,
    EntryEncryptionMetadata, EntryFecMetadata, EntryFragmentMetadata, EntryHashMetadata,
    EntryInput, EntryOwnerMetadata, EntryPermissionMetadata, EntrySparseMetadata, EntryTimestamp,
    EntryTimestampMetadata, FecAlgorithm, FieldPresence, GlobalFlags, HashAlgorithm, SarError,
    SparseHole,
};

#[test]
fn metadata_fields_roundtrip_individually() {
    assert_eq!(
        roundtrip_one(GlobalFlags::STREAM_ID, |e| e.stream_id = Some(11))
            .0
            .stream_id,
        FieldPresence::PresentActive(11)
    );
    assert_eq!(
        roundtrip_one(GlobalFlags::SEQ_NO, |e| e.sequence_no = Some(22))
            .0
            .sequence_no,
        FieldPresence::PresentActive(22)
    );

    assert_eq!(
        roundtrip_one(GlobalFlags::PERMISSIONS, |e| {
            e.permissions = Some(EntryPermissionMetadata { mode: 0o755 });
        })
        .0
        .permissions,
        FieldPresence::PresentActive(EntryPermissionMetadata { mode: 0o755 })
    );

    assert_eq!(
        roundtrip_one(GlobalFlags::OWNER, |e| {
            e.owner = Some(EntryOwnerMetadata {
                uid: 1000,
                gid: 1001,
            });
        })
        .0
        .owner,
        FieldPresence::PresentActive(EntryOwnerMetadata {
            uid: 1000,
            gid: 1001
        })
    );

    let timestamps = EntryTimestampMetadata {
        mtime: EntryTimestamp { secs: 1, nsecs: 2 },
        atime: EntryTimestamp { secs: 3, nsecs: 4 },
        ctime: EntryTimestamp { secs: 5, nsecs: 6 },
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::TIMESTAMPS, |e| e.timestamps = Some(timestamps))
            .0
            .timestamps,
        FieldPresence::PresentActive(timestamps)
    );

    let fragment = EntryFragmentMetadata {
        fragment_index: 1,
        fragment_count: 4,
        fragment_id: 99,
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::FRAGMENT, |e| e.fragment = Some(fragment))
            .0
            .fragment,
        FieldPresence::PresentActive(fragment)
    );

    let sparse = EntrySparseMetadata {
        holes: vec![
            SparseHole {
                offset: 10,
                length: 5,
            },
            SparseHole {
                offset: 50,
                length: 8,
            },
        ],
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::SPARSE, |e| e.sparse = Some(sparse.clone()))
            .0
            .sparse,
        FieldPresence::PresentActive(sparse)
    );

    let fec = EntryFecMetadata {
        algorithm: FecAlgorithm::ReedSolomon,
        block_size: 4096,
        data_shards: 10,
        parity_shards: 4,
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::FEC, |e| e.fec = Some(fec)).0.fec,
        FieldPresence::PresentActive(fec)
    );

    let cdc = EntryCdcMetadata {
        algorithm: CdcAlgorithm::FastCdc,
        min_chunk_size: 1024,
        avg_chunk_size: 2048,
        max_chunk_size: 4096,
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::CDC, |e| e.cdc = Some(cdc)).0.cdc,
        FieldPresence::PresentActive(cdc)
    );

    let delta = EntryDeltaMetadata {
        algorithm: DeltaAlgorithm::ZstdDelta,
        base_stream_id: 7,
        base_sequence_no: 8,
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::DELTA, |e| e.delta = Some(delta))
            .0
            .delta,
        FieldPresence::PresentActive(delta)
    );

    let encryption = EntryEncryptionMetadata {
        algorithm: EncryptionAlgorithm::Aes256Gcm,
        key_id: 123,
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::ENCRYPTION, |e| e.encryption = Some(encryption))
            .0
            .encryption,
        FieldPresence::PresentActive(encryption)
    );

    assert_eq!(
        roundtrip_one(GlobalFlags::CRC32, |e| e.crc32 = Some(0x12345678))
            .0
            .crc32,
        FieldPresence::PresentActive(0x12345678)
    );

    let content_hash = EntryHashMetadata {
        algorithm: HashAlgorithm::Blake3,
        hash: vec![1, 2, 3, 4],
    };
    assert_eq!(
        roundtrip_one(GlobalFlags::HASH, |e| e.content_hash =
            Some(content_hash.clone()))
        .0
        .content_hash,
        FieldPresence::PresentActive(content_hash)
    );

    assert_eq!(
        roundtrip_one(GlobalFlags::PATH, |e| e.path =
            Some("nested/file.txt".to_string()))
        .0
        .path,
        FieldPresence::PresentActive("nested/file.txt".to_string())
    );
}

#[test]
fn representative_presence_states_are_distinct() {
    let absent = roundtrip_one(GlobalFlags::empty(), |_| {}).0.path;
    assert_eq!(absent, FieldPresence::Absent);

    let inactive = roundtrip_one(GlobalFlags::PATH, |_| {}).0.path;
    assert_eq!(inactive, FieldPresence::PresentInactive(String::new()));

    let active = roundtrip_one(GlobalFlags::PATH, |e| {
        e.path = Some("active/path".to_string())
    })
    .0
    .path;
    assert_eq!(
        active,
        FieldPresence::PresentActive("active/path".to_string())
    );

    let compression_inactive = roundtrip_one(GlobalFlags::COMPRESSION, |_| {})
        .0
        .compression;
    assert_eq!(
        compression_inactive,
        FieldPresence::PresentInactive(EntryCompressionMetadata {
            algorithm: CompressionAlgorithm::None,
            compressed_size: 0,
        })
    );
}

#[test]
fn named_metadata_fields_are_accessible() {
    let (metadata, _) = roundtrip_one(GlobalFlags::STREAM_ID | GlobalFlags::PATH, |entry| {
        entry.stream_id = Some(55);
        entry.path = Some("foo/bar".into());
    });

    assert_eq!(metadata.name, "entry.bin");
    assert_eq!(metadata.payload_size, 4);
    assert!(metadata.path.is_active());
    assert!(metadata.stream_id.is_active());
}

#[test]
fn unsupported_field_requires_global_flag() {
    let mut entry = EntryInput::file("entry.bin", vec![1, 2, 3, 4]);
    entry.stream_id = Some(99);

    let mut writer = ArchiveWriter::new(GlobalFlags::empty());
    let err = writer.add_entry(entry).unwrap_err();

    match err {
        SarError::EntryMetadataRequiresFlag {
            field,
            required_flag,
        } => {
            assert_eq!(field, "stream_id");
            assert_eq!(required_flag, GlobalFlags::STREAM_ID.bits());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

fn roundtrip_one(
    flags: GlobalFlags,
    configure: impl FnOnce(&mut EntryInput),
) -> (sar_core::EntryMetadata, Vec<u8>) {
    let mut entry = EntryInput::file("entry.bin", vec![1, 2, 3, 4]);
    configure(&mut entry);

    let mut writer = ArchiveWriter::new(flags);
    writer.add_entry(entry).unwrap();

    let mut bytes = Vec::new();
    writer.write_to(&mut bytes).unwrap();

    let mut reader = ArchiveReader::new(bytes.as_slice()).unwrap();
    reader.next_entry().unwrap().unwrap()
}
