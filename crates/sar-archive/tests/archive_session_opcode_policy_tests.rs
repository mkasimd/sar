// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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
        flags,
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

fn archive_with_patched_entry_mode(bits: u16) -> Vec<u8> {
    let mut bytes = make_no_index_archive_with_single_entry(EntryMode::from_bits(0), 1, b"x");
    let header_len = write_global_header(&GlobalHeader {
        version: 1,
        flags: GlobalFlags::NO_INDEX,
        kms: None,
    })
    .expect("global header")
    .len();
    // Entry Mode follows the 4-byte Header Size.
    bytes[header_len + 4..header_len + 6].copy_from_slice(&bits.to_le_bytes());
    bytes
}

#[test]
fn reserved_opcodes_return_reserved_value_in_reader_and_audit() {
    for bits in [
        0x5u16 << 8,
        0xFu16 << 8,
        (0x8u16 << 8) | EntryMode::SESSION_CONTROL,
        (0xFu16 << 8) | EntryMode::SESSION_CONTROL,
    ] {
        let bytes = archive_with_patched_entry_mode(bits);
        let err = parse_first_entry(&bytes).expect_err("reserved opcode");
        assert_eq!(err.status(), SarStatus::ErrReservedValue, "{bits:#06x}");

        for policy in [
            sar_archive::ControlEntryPolicy::Reject,
            sar_archive::ControlEntryPolicy::PreserveInert,
        ] {
            let mut reader = ArchiveReader::new(Cursor::new(&bytes)).expect("reader");
            let err = reader
                .audit(sar_archive::ArchiveAuditOptions {
                    control_entry_policy: policy,
                    ..Default::default()
                })
                .expect_err("audit must reject reserved opcode");
            assert_eq!(err.status(), SarStatus::ErrReservedValue, "{bits:#06x}");
        }
    }
}

#[test]
fn assigned_session_opcode_remains_inert_under_preserve_policy() {
    let bytes = archive_with_patched_entry_mode((0x5 << 8) | EntryMode::SESSION_CONTROL);
    let mut reader = ArchiveReader::new(Cursor::new(&bytes)).expect("reader");
    reader
        .audit(sar_archive::ArchiveAuditOptions {
            control_entry_policy: sar_archive::ControlEntryPolicy::PreserveInert,
            ..Default::default()
        })
        .expect("assigned opcode is inert, not reserved");
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
