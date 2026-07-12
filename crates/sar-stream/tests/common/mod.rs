// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use sar_core::{EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader};
use sar_stream::{SessionEntry, SessionFlags, SessionInitFrame};

pub fn no_index_header() -> GlobalHeader {
    GlobalHeader {
        version: 1,
        flags_bytes: GlobalFlags::NO_INDEX.bits().to_le_bytes().to_vec(),
        flags: GlobalFlags::NO_INDEX,
        partition_descriptor: None,
        kms: None,
    }
}

pub fn fragmented_no_index_header() -> GlobalHeader {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::FILE_FRAGMENTATION;
    GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    }
}

pub fn indexed_header() -> GlobalHeader {
    GlobalHeader {
        version: 1,
        flags_bytes: GlobalFlags::empty().bits().to_le_bytes().to_vec(),
        flags: GlobalFlags::empty(),
        partition_descriptor: None,
        kms: None,
    }
}

pub fn init_entry(stream_id: u16, sequence_no: u16, uuid: [u8; 16], flags: u16) -> SessionEntry {
    let payload = SessionInitFrame {
        session_uuid: uuid,
        flags: SessionFlags::from_bits(flags),
    }
    .to_bytes()
    .expect("valid init frame");
    let mut header = LocalFileHeader::minimal_store(b"init".to_vec(), payload.len() as u64);
    header.stream_id = stream_id;
    header.sequence_no = sequence_no;
    header.entry_mode = EntryMode::from_bits(EntryMode::SESSION_CONTROL);
    header.payload_size = payload.len() as u64;
    header.uncompressed_size = payload.len() as u64;
    SessionEntry {
        header,
        payload,
        degraded: false,
    }
}

pub fn control_entry(
    stream_id: u16,
    sequence_no: u16,
    opcode: u8,
    payload: Vec<u8>,
) -> SessionEntry {
    let mut header = LocalFileHeader::minimal_store(b"ctl".to_vec(), payload.len() as u64);
    header.stream_id = stream_id;
    header.sequence_no = sequence_no;
    header.entry_mode = EntryMode::from_bits((u16::from(opcode) << 8) | EntryMode::SESSION_CONTROL);
    header.payload_size = payload.len() as u64;
    header.uncompressed_size = payload.len() as u64;
    SessionEntry {
        header,
        payload,
        degraded: false,
    }
}

pub fn fs_entry(
    stream_id: u16,
    sequence_no: u16,
    opcode: u8,
    mode_bits: u16,
    payload: Vec<u8>,
) -> SessionEntry {
    let mut header = LocalFileHeader::minimal_store(b"file".to_vec(), payload.len() as u64);
    header.stream_id = stream_id;
    header.sequence_no = sequence_no;
    header.entry_mode = EntryMode::from_bits((u16::from(opcode) << 8) | mode_bits);
    header.payload_size = payload.len() as u64;
    header.uncompressed_size = payload.len() as u64;
    SessionEntry {
        header,
        payload,
        degraded: false,
    }
}
