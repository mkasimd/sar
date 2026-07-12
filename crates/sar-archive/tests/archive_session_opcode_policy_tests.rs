use std::io::Cursor;

use sar_archive::ArchiveReader;
use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, SarError, SarStatus,
    format::{write_global_header, write_lfh},
};

fn make_no_index_archive_with_single_entry(
    entry_mode: EntryMode,
    stream_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    let mut lfh = LocalFileHeader::minimal_store(b"entry".to_vec(), payload.len() as u64);
    lfh.entry_mode = entry_mode;
    lfh.stream_id = stream_id;
    lfh.sequence_no = 7;
    bytes.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    bytes.extend_from_slice(payload);
    bytes
}

fn parse_first_entry(bytes: &[u8]) -> Result<Option<sar_archive::EntryReader>, SarError> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    reader.next_entry()
}

#[test]
fn default_archive_reader_rejects_session_control_entries() {
    let mode = EntryMode::from_bits(EntryMode::SESSION_CONTROL);
    let bytes = make_no_index_archive_with_single_entry(mode, 1, &[]);
    let err = parse_first_entry(&bytes).expect_err("must reject SESSION_CONTROL");
    assert_eq!(err.status(), SarStatus::ErrUnsupported);
}

#[test]
fn default_archive_reader_rejects_nonzero_opcode_entries() {
    let mode = EntryMode::from_bits(0x1 << 8);
    let bytes = make_no_index_archive_with_single_entry(mode, 1, b"x");
    let err = parse_first_entry(&bytes).expect_err("must reject OP_CODE");
    assert_eq!(err.status(), SarStatus::ErrUnsupported);
}

#[test]
fn default_archive_reader_rejects_session_control_with_nonzero_opcode() {
    let mode = EntryMode::from_bits((0x1 << 8) | EntryMode::SESSION_CONTROL);
    let bytes = make_no_index_archive_with_single_entry(mode, 1, b"x");
    let err = parse_first_entry(&bytes).expect_err("must reject SESSION_CONTROL+OP_CODE");
    assert_eq!(err.status(), SarStatus::ErrUnsupported);
}

#[test]
fn classic_no_index_archive_without_session_opcode_content_parses() {
    let mode = EntryMode::from_bits(0);
    let bytes = make_no_index_archive_with_single_entry(mode, 0, b"ok");
    let first = parse_first_entry(&bytes).expect("first entry");
    assert!(first.is_some(), "expected one parsed entry");
}

#[test]
fn classic_no_index_archive_does_not_require_session_init() {
    let mode = EntryMode::from_bits(0);
    let bytes = make_no_index_archive_with_single_entry(mode, 9, b"payload");
    let first = parse_first_entry(&bytes).expect("entry should parse without SESSION_INIT");
    assert!(first.is_some(), "expected one parsed entry");
}
