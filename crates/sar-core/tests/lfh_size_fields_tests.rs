use sar_core::{
    GlobalFlags, ResourceLimits, SarError,
    format::{LocalFileHeader, compute_lfh_size, parse_lfh, write_lfh},
};

fn unlimited_limits() -> ResourceLimits {
    ResourceLimits::unlimited()
}

#[test]
fn parse_lfh_reads_32bit_size_fields() {
    let flags = GlobalFlags::NO_INDEX;
    let mut lfh = LocalFileHeader::minimal_store(b"a".to_vec(), 0x1122_3344);
    lfh.uncompressed_size = 0x5566_7788;

    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    let (parsed, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");

    assert_eq!(parsed.uncompressed_size, 0x5566_7788);
    assert_eq!(parsed.payload_size, 0x1122_3344);
    assert_eq!(consumed, bytes.len());
}

#[test]
fn parse_lfh_reads_64bit_size_fields() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SIZE_64BIT;
    let mut lfh = LocalFileHeader::minimal_store(b"a".to_vec(), 0x1122_3344_5566_7788);
    lfh.uncompressed_size = 0x99aa_bbcc_ddee_ff00;

    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    let (parsed, consumed) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");

    assert_eq!(parsed.uncompressed_size, 0x99aa_bbcc_ddee_ff00);
    assert_eq!(parsed.payload_size, 0x1122_3344_5566_7788);
    assert_eq!(consumed, bytes.len());
}

#[test]
fn write_lfh_uses_32bit_size_layout_when_flag_unset() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"xy".to_vec(), 7);
    let bytes = write_lfh(&flags, &lfh).expect("write lfh");

    let expected_len = 4 + 2 + 2 + 2 + 4 + 4 + 2 + 2;
    assert_eq!(bytes.len(), expected_len);
}

#[test]
fn write_lfh_uses_64bit_size_layout_when_flag_set() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SIZE_64BIT;
    let lfh = LocalFileHeader::minimal_store(b"xy".to_vec(), 7);
    let bytes = write_lfh(&flags, &lfh).expect("write lfh");

    let expected_len = 4 + 2 + 2 + 2 + 8 + 8 + 2 + 2;
    assert_eq!(bytes.len(), expected_len);
}

#[test]
fn compute_lfh_size_differs_between_32bit_and_64bit_layouts() {
    let lfh = LocalFileHeader::minimal_store(b"name".to_vec(), 5);

    let size32 = compute_lfh_size(&GlobalFlags::NO_INDEX, &lfh).expect("size32");
    let size64 =
        compute_lfh_size(&(GlobalFlags::NO_INDEX | GlobalFlags::SIZE_64BIT), &lfh).expect("size64");

    assert_eq!(size64 - size32, 8);
}

#[test]
fn parser_cursor_alignment_after_32bit_size_fields() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"z".to_vec(), 3);
    let bytes = write_lfh(&flags, &lfh).expect("write lfh");

    let name_len_offset = 4 + 2 + 2 + 2 + 4 + 4;
    assert_eq!(
        u16::from_le_bytes([bytes[name_len_offset], bytes[name_len_offset + 1]]),
        1
    );

    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");
    assert_eq!(parsed.name, b"z");
}

#[test]
fn parser_cursor_alignment_after_64bit_size_fields() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SIZE_64BIT;
    let lfh = LocalFileHeader::minimal_store(b"z".to_vec(), 3);
    let bytes = write_lfh(&flags, &lfh).expect("write lfh");

    let name_len_offset = 4 + 2 + 2 + 2 + 8 + 8;
    assert_eq!(
        u16::from_le_bytes([bytes[name_len_offset], bytes[name_len_offset + 1]]),
        1
    );

    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse lfh");
    assert_eq!(parsed.name, b"z");
}

#[test]
fn write_lfh_rejects_32bit_overflow() {
    let flags = GlobalFlags::NO_INDEX;
    let mut lfh = LocalFileHeader::minimal_store(b"x".to_vec(), u64::from(u32::MAX) + 1);
    lfh.uncompressed_size = u64::from(u32::MAX) + 1;

    let err = write_lfh(&flags, &lfh).expect_err("must fail");
    assert!(matches!(err, SarError::Overflow(_)));
}

#[test]
fn parse_lfh_rejects_truncated_32bit_size_fields() {
    let flags = GlobalFlags::NO_INDEX;
    let lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 1);
    let mut bytes = write_lfh(&flags, &lfh).expect("write lfh");
    bytes.truncate(4 + 2 + 2 + 2 + 4 + 3);

    let err = parse_lfh(&bytes, &flags, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn parse_lfh_rejects_truncated_64bit_size_fields() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::SIZE_64BIT;
    let lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 1);
    let mut bytes = write_lfh(&flags, &lfh).expect("write lfh");
    bytes.truncate(4 + 2 + 2 + 2 + 8 + 7);

    let err = parse_lfh(&bytes, &flags, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn parse_lfh_rejects_oversized_physical_header_size() {
    let flags = GlobalFlags::NO_INDEX;
    let bytes = u32::MAX.to_le_bytes().to_vec();

    let err = parse_lfh(&bytes, &flags, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::Truncated(_)));
}
