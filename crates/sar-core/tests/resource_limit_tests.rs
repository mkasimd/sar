use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveReaderOptions, GlobalFlags, ResourceLimits, SarError,
    format::{
        CentralDictionary, GlobalHeader, LocalFileHeader, lfh_bytes_for_aad,
        parse_central_dictionary, parse_global_header, parse_lfh, write_central_dictionary,
        write_global_header, write_lfh,
    },
    sparse::{SparseExtent, parse_sparse_map},
    tlv::{Tlv, parse_tlvs, write_tlvs},
};
use sar_fragmentation::{FragmentDescriptor, FragmentEntry, FragmentError, reconstruct_fragments};
use sar_sparse::{SparseError, apply_sparse_reconstruction, validate_sparse_extents};

fn base_limits() -> ResourceLimits {
    ResourceLimits::default()
}

fn unlimited_limits() -> ResourceLimits {
    ResourceLimits::unlimited()
}

fn build_xor_tlv_value(protected_len: u64) -> Vec<u8> {
    let stripe_size = 1u8;
    let block_size = 256u64;
    let stripe_count = protected_len.div_ceil(block_size);
    let mut value = vec![stripe_size, 0x00];
    value.extend_from_slice(&protected_len.to_le_bytes());
    value.extend_from_slice(&(u32::try_from(stripe_count).expect("stripe count")).to_le_bytes());
    value.extend(vec![
        0u8;
        usize::try_from(stripe_count * block_size)
            .expect("parity len")
    ]);
    value
}

fn build_archive_with_global_ec() -> Vec<u8> {
    let flags = GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
    let header = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let cd_offset = u64::try_from(header.len()).expect("cd offset");
    let recovery_tlv = Tlv {
        type_id: 0x14,
        value: build_xor_tlv_value(cd_offset - 8),
    };
    let cd = CentralDictionary {
        version: 1,
        file_count: 0,
        partition_info: None,
        global_crc32: None,
        metadata: vec![recovery_tlv],
        offsets: Vec::new(),
    };
    let mut archive = header;
    archive.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
    archive.extend_from_slice(&u64::to_le_bytes(cd_offset));
    archive
}

fn minimal_global_header(flags: GlobalFlags) -> Vec<u8> {
    write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header")
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
fn excessive_payload_size_fails_before_allocation() {
    let mut archive = minimal_global_header(GlobalFlags::NO_INDEX);
    let lfh = LocalFileHeader::minimal_store(b"entry.bin".to_vec(), 8);
    archive.extend_from_slice(&write_lfh(&GlobalFlags::NO_INDEX, &lfh).expect("lfh"));
    archive.extend_from_slice(&[0; 8]);

    let mut reader = ArchiveReader::with_options(
        Cursor::new(archive),
        ArchiveReaderOptions {
            limits: ResourceLimits {
                max_in_memory_buffer: 4,
                ..base_limits()
            },
            delta_base: None,
        },
    )
    .expect("reader");
    reader.read_global_header().expect("header");
    let err = reader.next_entry().expect_err("must fail");
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

    let err =
        parse_central_dictionary(&bytes, GlobalFlags::empty(), &limits).expect_err("must fail");
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
                ..Default::default()
            },
        )
        .expect("writer");
        writer
            .add_entry(sar_core::EntryInput::file("a.txt", b"abc".to_vec()))
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
            delta_base: None,
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

    let err =
        reconstruct_fragments(fragments, 2, &limits.fragment_limits()).expect_err("must fail");
    assert!(matches!(err, FragmentError::LimitExceeded(_)));
}

#[test]
fn excessive_loss_tolerant_gap_fails() {
    let fragments = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 1,
            },
            payload: vec![1],
        },
        FragmentEntry {
            fragment_index: 2,
            is_last_fragment: true,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 10,
                fragment_size: 1,
            },
            payload: vec![2],
        },
    ];
    let limits = ResourceLimits {
        max_loss_tolerant_gap: 4,
        ..base_limits()
    };

    let err =
        reconstruct_fragments(fragments, 11, &limits.fragment_limits()).expect_err("must fail");
    assert!(matches!(err, FragmentError::LimitExceeded(_)));
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

    let err = validate_sparse_extents(&extents, u64::MAX, &unlimited_limits().sparse_limits())
        .expect_err("must fail");
    assert!(matches!(err, SparseError::Overflow(_)));
}

#[test]
fn unsafe_u64_to_usize_conversion_fails_safely() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 1,
    }];

    let err = apply_sparse_reconstruction(
        &[1],
        &extents,
        u64::MAX,
        &unlimited_limits().sparse_limits(),
    )
    .expect_err("must fail");
    assert!(matches!(err, SparseError::Overflow(_)));
}

#[test]
fn repair_working_set_limit_fails() {
    let archive = build_archive_with_global_ec();
    let plan = sar_core::plan_archive_repair(
        &archive,
        sar_core::ErasureInput {
            entries: Vec::new(),
            archive_ranges: Vec::new(),
        },
        &unlimited_limits(),
    )
    .expect("plan");
    let limits = ResourceLimits {
        max_repair_working_set: 1,
        ..base_limits()
    };

    let err = sar_core::repair_archive(&archive, &plan, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}
