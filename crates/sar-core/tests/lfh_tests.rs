// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::{
    EntryMode, GlobalFlags, SarError,
    format::{LfhFragmentDescriptor, LocalFileHeader, parse_lfh, write_lfh},
};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

#[test]
fn parses_minimal_lfh() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"a.txt".to_vec(), 3);
    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    let (parsed, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.name, b"a.txt");
    assert_eq!(parsed.payload_size, 3);
}

#[test]
fn parses_lfh_with_conditional_fields() {
    let flags = GlobalFlags::COMPRESSED
        | GlobalFlags::HAS_DELTA
        | GlobalFlags::CDC_SUPPORT
        | GlobalFlags::SELECTIVE_FEC
        | GlobalFlags::FILE_FRAGMENTATION
        | GlobalFlags::PER_FILE_CRC
        | GlobalFlags::DEDUPLICATION
        | GlobalFlags::EXT_UID_GID
        | GlobalFlags::EXT_TIME
        | GlobalFlags::HAS_PERMS
        | GlobalFlags::HAS_PATH
        | GlobalFlags::SPARSE_FILES;

    let mut lfh = LocalFileHeader::minimal_store(b"file.bin".to_vec(), 4);
    lfh.comp_algo_id = Some(0);
    lfh.patch_algo_id = Some(0);
    lfh.cdc_algo_id = Some(0);
    lfh.fec_algo_id = Some(0);
    lfh.fragment_id = Some(1);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 4,
    });
    lfh.delta_base_hash = Some([1u8; 32]);
    lfh.file_crc32 = Some(0xAABBCCDD);
    lfh.content_hash = Some([2u8; 32]);
    lfh.uid_gid = Some(0x1234_5678);
    lfh.timestamps = Some([1, 2, 3]);
    lfh.permissions = Some(0o644);
    lfh.path = b"nested".to_vec();
    lfh.sparse_map = vec![9, 9];
    lfh.fec_value = vec![7, 7, 7];

    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(parsed.path, b"nested");
    assert_eq!(parsed.fec_value.len(), 3);
}

#[test]
fn rejects_incorrect_header_size() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"b".to_vec(), 1);
    let mut bytes = write_lfh(&flags, &lfh).expect("write");
    bytes[0] = 0xFF;
    let err = parse_lfh(&bytes, &flags, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(
        err,
        SarError::Truncated(_) | SarError::InvalidLength(_)
    ));
}

#[test]
fn rejects_header_size_smaller_than_fixed_prefix() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = vec![0u8; 10];
    bytes[..4].copy_from_slice(&2u32.to_le_bytes());
    let err = parse_lfh(&bytes, &flags, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(
        err,
        SarError::InvalidLength(_) | SarError::Truncated(_)
    ));
}

#[test]
fn zero_name_length_omits_name_string() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(Vec::new(), 0);
    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert!(parsed.name.is_empty());
}

#[test]
fn path_field_required_only_when_global_has_path() {
    let mut lfh = LocalFileHeader::minimal_store(b"n".to_vec(), 0);
    lfh.path = b"p".to_vec();

    let without = write_lfh(&GlobalFlags::NO_INDEX, &lfh).expect("write without path");
    let (parsed_without, _) =
        parse_lfh(&without, &GlobalFlags::NO_INDEX, &unlimited_limits()).expect("parse without");
    assert!(parsed_without.path.is_empty());

    let with =
        write_lfh(&(GlobalFlags::NO_INDEX | GlobalFlags::HAS_PATH), &lfh).expect("write with");
    let (parsed_with, _) = parse_lfh(
        &(with),
        &(GlobalFlags::NO_INDEX | GlobalFlags::HAS_PATH),
        &unlimited_limits(),
    )
    .expect("parse with");
    assert_eq!(parsed_with.path, b"p");
}

#[test]
fn supports_64bit_sizes() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SIZE_64BIT;
    let mut lfh = LocalFileHeader::minimal_store(b"big".to_vec(), u64::from(u32::MAX) + 1);
    lfh.uncompressed_size = u64::from(u32::MAX) + 1;
    let bytes = write_lfh(&flags, &lfh).expect("write");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(parsed.payload_size, u64::from(u32::MAX) + 1);
}

#[test]
fn rejects_invalid_global_entry_flag_combination() {
    let flags = GlobalFlags::NO_INDEX;
    let mut lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 1);
    lfh.entry_mode = EntryMode::from_bits(1 << 3);
    let err = write_lfh(&flags, &lfh).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}
