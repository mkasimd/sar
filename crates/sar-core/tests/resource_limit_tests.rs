use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveReaderOptions, GlobalFlags, ResourceLimits, SarError,
    format::{
        CentralDictionary, LocalFileHeader, lfh_bytes_for_aad, parse_central_dictionary,
        parse_global_header, parse_lfh, write_central_dictionary, write_lfh,
    },
    fragment::{FragmentDescriptor, FragmentEntry, reconstruct_fragments},
    sparse::{SparseExtent, apply_sparse_reconstruction, parse_sparse_map, validate_sparse_extents},
    tlv::{Tlv, parse_tlvs, write_tlvs},
};

fn base_limits() -> ResourceLimits {
    ResourceLimits::default()
}

fn unlimited_limits() -> ResourceLimits {
    ResourceLimits::unlimited()
}

#[test]
fn excessive_global_flags_size_fails() {
    let mut bytes = b"SAR!\x01\x00\x08\x00".to_vec();
    bytes.extend_from_slice(&[0; 8]);

    let limits = ResourceLimits {
        max_global_flags_bytes: 4,
        ..base_limits()
    };
    let err = parse_global_header(&bytes, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_kms_payload_size_fails() {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&GlobalFlags::ENCRYPTED.bits().to_le_bytes());
    bytes.push(sar_crypto::KMS_PBKDF2);
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&[7; 8]);

    let limits = ResourceLimits {
        max_kms_payload_bytes: 4,
        ..base_limits()
    };
    let err = parse_global_header(&bytes, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_lfh_header_size_fails() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"entry.bin".to_vec(), 1);
    let bytes = write_lfh(&flags, &lfh).expect("lfh");
    let limits = ResourceLimits {
        max_lfh_header_bytes: 8,
        ..base_limits()
    };

    let err = parse_lfh(&bytes, &flags, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_path_length_fails() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_PATH;
    let mut lfh = LocalFileHeader::minimal_store(b"entry".to_vec(), 1);
    lfh.path = b"folder".to_vec();
    let bytes = write_lfh(&flags, &lfh).expect("lfh");
    let limits = ResourceLimits {
        max_path_bytes: 4,
        ..base_limits()
    };

    let err = parse_lfh(&bytes, &flags, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_tlv_length_fails_before_allocation() {
    let bytes = write_tlvs(&[Tlv {
        type_id: 0x30,
        value: vec![1; 8],
    }])
    .expect("tlv");
    let limits = ResourceLimits {
        max_tlv_bytes: 4,
        ..base_limits()
    };

    let err = parse_tlvs(&bytes, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_tlv_count_fails() {
    let bytes = write_tlvs(&[
        Tlv {
            type_id: 0x30,
            value: Vec::new(),
        },
        Tlv {
            type_id: 0x31,
            value: Vec::new(),
        },
    ])
    .expect("tlvs");
    let limits = ResourceLimits {
        max_tlv_count: 1,
        ..base_limits()
    };

    let err = parse_tlvs(&bytes, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_cd_size_fails() {
    let cd = CentralDictionary {
        version: 1,
        file_count: 1,
        partition_info: None,
        global_crc32: None,
        metadata: Vec::new(),
        offsets: vec![8],
    };
    let bytes = write_central_dictionary(&cd, GlobalFlags::empty()).expect("cd");
    let limits = ResourceLimits {
        max_cd_bytes: 8,
        ..base_limits()
    };

    let err = parse_central_dictionary(&bytes, GlobalFlags::empty(), &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn archive_reader_rejects_excessive_cd_region() {
    let mut archive = Vec::new();
    {
        let mut writer = sar_core::ArchiveWriter::new(
            &mut archive,
            sar_core::ArchiveWriterOptions {
                no_index: false,
                encryption: None,
                fec: None,
                sparse: false,
            },
        )
        .expect("writer");
        writer
            .add_entry(sar_core::EntryInput {
                name: "a.txt".into(),
                payload: b"abc".to_vec(),
            })
            .expect("entry");
        writer.finish().expect("finish");
    }

    let mut reader = ArchiveReader::with_options(
        Cursor::new(archive),
        ArchiveReaderOptions {
            limits: ResourceLimits {
                max_cd_bytes: 8,
                ..base_limits()
            },
        },
    )
    .expect("reader");

    let err = reader.read_global_header().expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_cd_entry_count_fails() {
    let cd = CentralDictionary {
        version: 1,
        file_count: 2,
        partition_info: None,
        global_crc32: None,
        metadata: Vec::new(),
        offsets: vec![8, 16],
    };
    let bytes = write_central_dictionary(&cd, GlobalFlags::empty()).expect("cd");
    let limits = ResourceLimits {
        max_entry_count: 1,
        ..base_limits()
    };

    let err =
        parse_central_dictionary(&bytes, GlobalFlags::empty(), &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn malformed_alignment_arithmetic_fails_safely() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SELECTIVE_FEC;
    let mut lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 1);
    lfh.fec_algo_id = Some(0x14);
    let bytes = write_lfh(&flags, &lfh).expect("lfh");

    let err = lfh_bytes_for_aad(flags, &bytes, 0x14, bytes.len() + 1).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)));
}

#[test]
fn excessive_sparse_map_byte_size_fails() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SPARSE_FILES;
    let mut lfh = LocalFileHeader::minimal_store(b"sparse.bin".to_vec(), 1);
    lfh.sparse_map = vec![0; 8];
    let bytes = write_lfh(&flags, &lfh).expect("lfh");
    let limits = ResourceLimits {
        max_sparse_map_bytes: 4,
        ..base_limits()
    };

    let err = parse_lfh(&bytes, &flags, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_sparse_descriptor_count_fails() {
    let bytes = vec![0; 16];
    let limits = ResourceLimits {
        max_sparse_descriptors: 1,
        ..base_limits()
    };

    let err = parse_sparse_map(&bytes, false, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_fragment_count_fails() {
    let fragments = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 1,
            },
            payload: vec![1],
        },
        FragmentEntry {
            fragment_index: 1,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 1,
                fragment_size: 1,
            },
            payload: vec![2],
        },
    ];
    let limits = ResourceLimits {
        max_fragment_count: 1,
        ..base_limits()
    };

    let err = reconstruct_fragments(fragments, 2, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn excessive_fec_value_size_fails() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SELECTIVE_FEC;
    let mut lfh = LocalFileHeader::minimal_store(b"fec.bin".to_vec(), 1);
    lfh.fec_algo_id = Some(0x14);
    lfh.fec_value = vec![0; 14];
    let bytes = write_lfh(&flags, &lfh).expect("lfh");
    let limits = ResourceLimits {
        max_fec_value_bytes: 4,
        ..base_limits()
    };

    let err = parse_lfh(&bytes, &flags, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn checked_arithmetic_catches_offset_plus_length_overflow() {
    let extents = vec![SparseExtent {
        offset: u64::MAX,
        length: 1,
    }];

    let err =
        validate_sparse_extents(&extents, u64::MAX, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::Overflow(_)));
}

#[test]
fn unsafe_u64_to_usize_conversion_fails_safely() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 1,
    }];

    let err = apply_sparse_reconstruction(&[1], &extents, u64::MAX, &unlimited_limits())
        .expect_err("must fail");
    assert!(matches!(err, SarError::Overflow(_)));
}
