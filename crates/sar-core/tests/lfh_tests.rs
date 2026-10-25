// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::{
    EntryMode, GlobalFlags, SarError,
    format::{LocalFileHeader, compute_lfh_size, fec_size_field_offset, parse_lfh, write_lfh},
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
    assert!(matches!(err, SarError::InvalidLength(_)), "got {err:?}");
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

// ---------------------------------------------------------------------------
// Canonical fragment LFH layout (spec §6.1, §6.1.3, Appendix A)
// ---------------------------------------------------------------------------

const FRAG_FLAGS: GlobalFlags = GlobalFlags::NO_INDEX.union(GlobalFlags::FILE_FRAGMENTATION);

fn frag_lfh(id: u32, index: u32, usize_: u64) -> LocalFileHeader {
    let mut lfh = LocalFileHeader::minimal_store(b"f".to_vec(), usize_);
    lfh.entry_mode = EntryMode::from_bits(1 << 5);
    lfh.fragment_id = Some(id);
    lfh.fragment_index = Some(index);
    lfh
}

#[test]
fn fragment_fields_are_exactly_eight_bytes() {
    let plain = write_lfh(
        &GlobalFlags::NO_INDEX,
        &LocalFileHeader::minimal_store(b"f".to_vec(), 3),
    )
    .expect("plain");
    let frag = write_lfh(&FRAG_FLAGS, &frag_lfh(0x0102_0304, 0x0A0B_0C0D, 3)).expect("frag");
    assert_eq!(frag.len(), plain.len() + 8);
    // Fragment ID / Index immediately follow Payload Size (u32 sizes), LE.
    let off = 4 + 2 + 2 + 2 + 4 + 4;
    assert_eq!(&frag[off..off + 4], &0x0102_0304u32.to_le_bytes());
    assert_eq!(&frag[off + 4..off + 8], &0x0A0B_0C0Du32.to_le_bytes());
    assert_eq!(
        u64::try_from(frag.len()).expect("ok"),
        compute_lfh_size(&FRAG_FLAGS, &frag_lfh(0x0102_0304, 0x0A0B_0C0D, 3)).expect("ok")
    );
    let hs = u32::from_le_bytes(frag[..4].try_into().expect("ok"));
    assert_eq!(usize::try_from(hs).expect("ok"), frag.len());
}

#[test]
fn fragment_fields_stay_32_bit_under_64bit_size() {
    let flags = FRAG_FLAGS | GlobalFlags::SIZE_64BIT;
    let bytes = write_lfh(&flags, &frag_lfh(7, 9, 5)).expect("write");
    let narrow = write_lfh(&FRAG_FLAGS, &frag_lfh(7, 9, 5)).expect("write narrow");
    // Only the two size fields widen (4 bytes each).
    assert_eq!(bytes.len(), narrow.len() + 8);
    let off = 4 + 2 + 2 + 2 + 8 + 8;
    assert_eq!(&bytes[off..off + 4], &7u32.to_le_bytes());
    assert_eq!(&bytes[off + 4..off + 8], &9u32.to_le_bytes());
    let (parsed, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        (parsed.fragment_id, parsed.fragment_index),
        (Some(7), Some(9))
    );
}

#[test]
fn fragment_fields_present_when_not_is_fragment() {
    let mut lfh = LocalFileHeader::minimal_store(b"f".to_vec(), 1);
    lfh.fragment_id = Some(0);
    lfh.fragment_index = Some(0);
    let bytes = write_lfh(&FRAG_FLAGS, &lfh).expect("write");
    let plain = write_lfh(&GlobalFlags::NO_INDEX, &lfh).expect("plain");
    assert_eq!(bytes.len(), plain.len() + 8);
    let (parsed, _) = parse_lfh(&bytes, &FRAG_FLAGS, &unlimited_limits()).expect("parse");
    assert!(!parsed.entry_mode.is_fragment());
}

#[test]
fn unfragmented_lfh_bytes_unchanged() {
    let lfh = LocalFileHeader::minimal_store(b"a".to_vec(), 2);
    let bytes = write_lfh(&GlobalFlags::NO_INDEX, &lfh).expect("write");
    let mut expected = Vec::new();
    expected.extend_from_slice(&21u32.to_le_bytes()); // header size
    expected.extend_from_slice(&[0, 0]); // entry mode
    expected.extend_from_slice(&[0, 0]); // stream id
    expected.extend_from_slice(&[0, 0]); // sequence
    expected.extend_from_slice(&2u32.to_le_bytes()); // uncompressed
    expected.extend_from_slice(&2u32.to_le_bytes()); // payload
    expected.extend_from_slice(&1u16.to_le_bytes()); // name len
    expected.push(b'a');
    assert_eq!(bytes, expected);
}

/// Spec Appendix A fragment LFH (ENCRYPTED | FILE_FRAGMENTATION | HAS_PATH).
fn appendix_a_lfh() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x37u32.to_le_bytes());
    b.extend_from_slice(&0x0024u16.to_le_bytes());
    b.extend_from_slice(&5u16.to_le_bytes());
    b.extend_from_slice(&42u16.to_le_bytes());
    b.extend_from_slice(&1008u32.to_le_bytes());
    b.extend_from_slice(&1024u32.to_le_bytes());
    b.push(0x04);
    b.extend_from_slice(&0xDEAD_C0DEu32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&[0xAA; 24]);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b
}

#[test]
fn appendix_a_fragment_lfh_parses_canonically() {
    let flags = GlobalFlags::ENCRYPTED | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::HAS_PATH;
    let mut bytes = appendix_a_lfh();
    assert_eq!(bytes.len(), 0x37);
    let payload_pos = bytes.len();
    bytes.extend_from_slice(&[0u8; 1024]);
    bytes.extend_from_slice(b"NEXT");
    let (lfh, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse");
    assert_eq!(consumed, 0x37);
    assert_eq!(consumed, payload_pos);
    assert_eq!(lfh.header_size, 0x37);
    assert_eq!(lfh.stream_id, 5);
    assert_eq!(lfh.sequence_no, 42);
    assert_eq!(lfh.uncompressed_size, 1008);
    assert_eq!(lfh.payload_size, 1024);
    assert_eq!(lfh.encr_algo_id, Some(0x04));
    assert_eq!(lfh.fragment_id, Some(0xDEAD_C0DE));
    assert_eq!(lfh.fragment_index, Some(1));
    // Next LFH begins after Header Size + Payload Size.
    assert_eq!(&bytes[consumed + 1024..], b"NEXT");
    // Writer reproduces the exact Appendix A bytes.
    let rewritten = write_lfh(&flags, &lfh).expect("write");
    assert_eq!(rewritten, appendix_a_lfh());
    assert_eq!(
        u64::try_from(rewritten.len()).expect("ok"),
        compute_lfh_size(&flags, &lfh).expect("ok")
    );
}

#[test]
fn fec_size_field_offset_counts_eight_fragment_bytes() {
    let base = fec_size_field_offset(GlobalFlags::NO_INDEX | GlobalFlags::SELECTIVE_FEC);
    let frag = fec_size_field_offset(FRAG_FLAGS | GlobalFlags::SELECTIVE_FEC);
    assert_eq!(frag, base + 8);
}

#[test]
fn truncation_at_each_fragment_field_boundary() {
    let bytes = write_lfh(&FRAG_FLAGS, &frag_lfh(1, 2, 3)).expect("write");
    let start = 4 + 2 + 2 + 2 + 4 + 4;
    for cut in [start - 1, start, start + 4, start + 7, bytes.len() - 1] {
        let err = parse_lfh(&bytes[..cut], &FRAG_FLAGS, &unlimited_limits()).expect_err("cut");
        assert!(matches!(err, SarError::Truncated(_)), "cut {cut}: {err:?}");
    }
}

#[test]
fn header_size_below_fragment_minimum_is_invalid_length() {
    // Minimum for NO_INDEX|FILE_FRAGMENTATION with empty name is 4+2+2+2+4+4+8+2 = 28.
    let mut bytes = write_lfh(&FRAG_FLAGS, &frag_lfh(1, 2, 3)).expect("write");
    bytes[..4].copy_from_slice(&27u32.to_le_bytes());
    let err = parse_lfh(&bytes, &FRAG_FLAGS, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)), "got {err:?}");
}

#[test]
fn obsolete_descriptor_layout_is_rejected() {
    // Obsolete layout: 12 extra descriptor bytes after Fragment Index, with
    // Header Size inflated by 12.  Canonical parsing treats them as trailing
    // data inconsistent with the name length and rejects the header.
    let canonical = write_lfh(&FRAG_FLAGS, &frag_lfh(1, 2, 3)).expect("write");
    let fixed_end = 4 + 2 + 2 + 2 + 4 + 4 + 8;
    let mut obsolete = canonical[..fixed_end].to_vec();
    obsolete.extend_from_slice(&[0u8; 12]);
    obsolete.extend_from_slice(&canonical[fixed_end..]);
    let size = u32::try_from(obsolete.len()).expect("ok");
    obsolete[..4].copy_from_slice(&size.to_le_bytes());
    let err = parse_lfh(&obsolete, &FRAG_FLAGS, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)), "got {err:?}");
}
