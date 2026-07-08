use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput, GlobalFlags, ResourceLimits,
    SarError, TLV_CDC_CUSTOM, TLV_CDC_EXT_PROVIDER, TLV_DATA_HASH_BLAKE3,
    format::write_lfh,
    make_cdc_ext_provider_tlv, make_cdc_map_tlv, parse_cdc_ext_provider_tlv, parse_entry_cdc_map,
    tlv::{Tlv, parse_tlvs, write_tlvs},
    validate_cdc_metadata_tlv,
};

fn unlimited_limits() -> ResourceLimits {
    ResourceLimits::unlimited()
}

#[test]
fn tlv_0x31_remains_data_hash_not_cdc_metadata() {
    let encoded = write_tlvs(&[Tlv {
        type_id: TLV_DATA_HASH_BLAKE3,
        value: vec![0xAB; 32],
    }])
    .expect("encode data-hash tlv");
    let parsed = parse_tlvs(&encoded, &unlimited_limits()).expect("parse tlvs");

    assert_eq!(parsed[0].type_id, TLV_DATA_HASH_BLAKE3);
    assert!(
        parse_entry_cdc_map(&parsed, &unlimited_limits())
            .expect("parse cdc map")
            .is_none()
    );
    assert!(matches!(
        parse_cdc_ext_provider_tlv(&parsed[0], &unlimited_limits()),
        Err(SarError::Unsupported(_))
    ));
}

#[test]
fn cdc_ext_provider_uses_0x41_when_emitted() {
    let tlv = make_cdc_ext_provider_tlv("sarp+https://chunks.example/v1", &unlimited_limits())
        .expect("build provider tlv");
    assert_eq!(tlv.type_id, TLV_CDC_EXT_PROVIDER);

    let parsed = parse_cdc_ext_provider_tlv(&tlv, &unlimited_limits()).expect("parse provider");
    assert_eq!(parsed.uri, "sarp+https://chunks.example/v1");
}

#[test]
fn cdc_ext_provider_invalid_utf8_rejected() {
    let tlv = Tlv {
        type_id: TLV_CDC_EXT_PROVIDER,
        value: vec![0xFF, 0xFE, 0xFD],
    };
    assert!(matches!(
        parse_cdc_ext_provider_tlv(&tlv, &unlimited_limits()),
        Err(SarError::Malformed(_))
    ));
}

#[test]
fn cdc_ext_provider_resource_limit_enforced() {
    let tlv = Tlv {
        type_id: TLV_CDC_EXT_PROVIDER,
        value: b"sarp+https://chunks.example/v1".to_vec(),
    };
    let limits = ResourceLimits {
        max_cdc_metadata_bytes: 4,
        ..Default::default()
    };
    assert!(matches!(
        parse_cdc_ext_provider_tlv(&tlv, &limits),
        Err(SarError::LimitExceeded(_))
    ));
}

#[test]
fn reserved_cdc_tlv_range_rejected() {
    for type_id in 0x42u8..=0x4E {
        let encoded = write_tlvs(&[Tlv {
            type_id,
            value: vec![1, 2, 3],
        }]);
        assert!(
            matches!(encoded, Err(SarError::ReservedValue(_))),
            "type 0x{type_id:02X} should be reserved"
        );
    }
}

#[test]
fn cdc_custom_tlv_is_parsed_and_preserved() {
    let encoded = write_tlvs(&[Tlv {
        type_id: TLV_CDC_CUSTOM,
        value: vec![1, 2, 3, 4],
    }])
    .expect("encode custom tlv");
    let parsed = parse_tlvs(&encoded, &unlimited_limits()).expect("parse custom tlv");
    assert_eq!(parsed[0].type_id, TLV_CDC_CUSTOM);
    validate_cdc_metadata_tlv(&parsed[0], &unlimited_limits()).expect("validate custom tlv");
}

#[test]
fn archive_writer_auto_sets_cdc_support_for_cdc_metadata() {
    let mut out = Vec::new();
    let cdc_map = sar_core::CdcMap {
        hash_algorithm_id: 0x31, // BLAKE3
        records: vec![],
    };
    let cd_metadata = vec![make_cdc_map_tlv(&cdc_map, &unlimited_limits()).expect("cdc map tlv")];

    let mut writer = ArchiveWriter::new_with_cd_metadata(
        &mut out,
        ArchiveWriterOptions {
            no_index: false,
            encryption: None,
            fec: None,
            sparse: false,
        },
        cd_metadata,
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "one.bin".into(),
            payload: b"abc".to_vec(),
        })
        .expect("entry");
    writer.finish().expect("finish");

    let mut reader = ArchiveReader::new(Cursor::new(out)).expect("reader");
    let header = reader.read_global_header().expect("header");
    assert!(header.flags.contains(GlobalFlags::CDC_SUPPORT));
    assert!(header.flags.contains(GlobalFlags::OPT_PRESENT));

    let entry = reader
        .next_entry()
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.metadata.cdc_algo_id, Some(0x00));
}

#[test]
fn archive_writer_rejects_cd_metadata_for_no_index_archives() {
    let mut out = Vec::new();
    let cd_metadata = vec![
        make_cdc_ext_provider_tlv("sarp+https://chunks.example/v1", &unlimited_limits())
            .expect("provider tlv"),
    ];
    let err = ArchiveWriter::new_with_cd_metadata(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
        },
        cd_metadata,
    )
    .err()
    .expect("must reject no-index metadata");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn verify_rejects_cdc_metadata_without_cdc_support_flag() {
    use sar_core::format::{
        CentralDictionary, Footer, GlobalHeader, LocalFileHeader, write_central_dictionary,
        write_footer, write_global_header,
    };

    let flags = GlobalFlags::OPT_PRESENT;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let lfh_offset = bytes.len() as u64;
    let lfh = LocalFileHeader::minimal_store(b"plain.bin".to_vec(), 3);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"abc");

    let cd_offset = bytes.len() as u64;
    let cd = CentralDictionary {
        version: 1,
        file_count: 1,
        partition_info: None,
        global_crc32: None,
        metadata: vec![
            make_cdc_ext_provider_tlv("sarp+https://chunks.example/v1", &unlimited_limits())
                .expect("provider tlv"),
        ],
        offsets: vec![lfh_offset],
    };
    bytes.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
    bytes.extend_from_slice(&write_footer(Footer { cd_offset }));

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader.verify().expect_err("verify must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}
