#![allow(dead_code)]

use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, ResourceLimits, SarStatus,
    write_global_header, write_lfh,
};
use sar_stream::{
    AckFlags, CapabilityFlags, SessionAckFrame, SessionCapabilitiesFrame, SessionFlags,
    SessionInitFrame, SessionOpCode, SessionStatusFrame,
};

pub fn no_index_global_header_bytes() -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX;
    let header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    write_global_header(&header).expect("global header encoding")
}

pub fn session_init_entry_bytes(
    stream_id: u16,
    sequence_no: u16,
    session_uuid: [u8; 16],
    flags_bits: u16,
) -> Vec<u8> {
    let payload = SessionInitFrame {
        session_uuid,
        flags: SessionFlags::from_bits(flags_bits),
    }
    .to_bytes()
    .expect("session init payload");
    session_control_entry_bytes(stream_id, sequence_no, SessionOpCode::Init as u8, payload)
}

pub fn session_control_entry_bytes(
    stream_id: u16,
    sequence_no: u16,
    opcode: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut header = LocalFileHeader::minimal_store(b"ctl".to_vec(), payload.len() as u64);
    header.stream_id = stream_id;
    header.sequence_no = sequence_no;
    header.entry_mode = EntryMode::from_bits((u16::from(opcode) << 8) | EntryMode::SESSION_CONTROL);
    header.payload_size = payload.len() as u64;
    header.uncompressed_size = payload.len() as u64;
    let mut bytes = write_lfh(&GlobalFlags::NO_INDEX, &header).expect("session-control LFH");
    bytes.extend_from_slice(&payload);
    bytes
}

pub fn session_close_entry_bytes(stream_id: u16, sequence_no: u16) -> Vec<u8> {
    session_control_entry_bytes(
        stream_id,
        sequence_no,
        SessionOpCode::Close as u8,
        Vec::new(),
    )
}

pub fn session_heartbeat_entry_bytes(stream_id: u16, sequence_no: u16) -> Vec<u8> {
    session_control_entry_bytes(
        stream_id,
        sequence_no,
        SessionOpCode::Heartbeat as u8,
        Vec::new(),
    )
}

pub fn session_capabilities_entry_bytes(
    stream_id: u16,
    sequence_no: u16,
    flags: CapabilityFlags,
) -> Vec<u8> {
    let payload = SessionCapabilitiesFrame { flags }
        .to_bytes()
        .expect("capabilities payload");
    session_control_entry_bytes(
        stream_id,
        sequence_no,
        SessionOpCode::Capabilities as u8,
        payload,
    )
}

pub fn filesystem_data_entry_bytes(stream_id: u16, sequence_no: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut header = LocalFileHeader::minimal_store(b"data".to_vec(), payload.len() as u64);
    header.stream_id = stream_id;
    header.sequence_no = sequence_no;
    header.entry_mode = EntryMode::from_bits(0);
    header.payload_size = payload.len() as u64;
    header.uncompressed_size = payload.len() as u64;
    let mut bytes = write_lfh(&GlobalFlags::NO_INDEX, &header).expect("filesystem LFH");
    bytes.extend_from_slice(&payload);
    bytes
}

pub fn session_archive_init_bytes(
    stream_id: u16,
    sequence_no: u16,
    session_uuid: [u8; 16],
) -> Vec<u8> {
    let mut bytes = no_index_global_header_bytes();
    bytes.extend_from_slice(&session_init_entry_bytes(
        stream_id,
        sequence_no,
        session_uuid,
        0,
    ));
    bytes
}

pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

pub fn malformed_lfh_prefix() -> Vec<u8> {
    3u32.to_le_bytes().to_vec()
}

pub fn additional_control_ack_bytes(stream_id: u16, sequence_no: u16) -> Vec<u8> {
    let payload = SessionAckFrame {
        ref_sequence: sequence_no,
        flags: AckFlags::from_bits(0),
    }
    .to_bytes()
    .expect("ack frame");
    session_control_entry_bytes(stream_id, sequence_no, SessionOpCode::Ack as u8, payload)
}

pub fn additional_control_status_bytes(stream_id: u16, sequence_no: u16) -> Vec<u8> {
    let limits = ResourceLimits::default();
    let payload = SessionStatusFrame {
        ref_sequence: sequence_no,
        status: SarStatus::Ok,
        message: Vec::new(),
    }
    .to_bytes(&limits)
    .expect("status frame");
    session_control_entry_bytes(stream_id, sequence_no, SessionOpCode::Status as u8, payload)
}

pub fn additional_control_capabilities_bytes(
    stream_id: u16,
    sequence_no: u16,
    flags: CapabilityFlags,
) -> Vec<u8> {
    session_capabilities_entry_bytes(stream_id, sequence_no, flags)
}
