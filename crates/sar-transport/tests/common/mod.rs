#![allow(dead_code)]

use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, ResourceLimits, SarStatus,
    write_global_header, write_lfh,
};
use sar_stream::{
    AckFlags, CapabilityFlags, SessionAckFrame, SessionCapabilitiesFrame, SessionFlags,
    SessionInitFrame, SessionOpCode, SessionStatusFrame,
};

// ── Re-export CTL! constants for test use ─────────────────────────────────
pub use sar_transport::{CTL_STREAM_HEADER_LEN, CTL_STREAM_MAGIC};

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

// ── CTL! additional control-stream helpers ────────────────────────────────

/// Build the 22-byte CTL! association header for the given stream ID and UUID.
/// Format: `CTL!` (4 bytes) + stream_id LE u16 (2 bytes) + UUID (16 bytes).
pub fn ctl_stream_assoc_header_bytes(stream_id: u16, session_uuid: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CTL_STREAM_HEADER_LEN);
    bytes.extend_from_slice(&CTL_STREAM_MAGIC);
    bytes.extend_from_slice(&stream_id.to_le_bytes());
    bytes.extend_from_slice(&session_uuid);
    bytes
}

/// Build a SAR global header + SESSION_ACK entry suitable for delivery on an
/// additional CTL! control stream after the association header.
pub fn ctl_stream_sar_ack_bytes(stream_id: u16, sequence_no: u16) -> Vec<u8> {
    let payload = SessionAckFrame {
        ref_sequence: sequence_no,
        flags: AckFlags::from_bits(0),
    }
    .to_bytes()
    .expect("ack frame");
    let mut bytes = no_index_global_header_bytes();
    bytes.extend_from_slice(&session_control_entry_bytes(
        stream_id,
        sequence_no,
        SessionOpCode::Ack as u8,
        payload,
    ));
    bytes
}

/// Build a SAR global header + SESSION_STATUS entry suitable for delivery on
/// an additional CTL! control stream after the association header.
pub fn ctl_stream_sar_status_bytes(stream_id: u16, sequence_no: u16) -> Vec<u8> {
    let limits = ResourceLimits::default();
    let payload = SessionStatusFrame {
        ref_sequence: sequence_no,
        status: SarStatus::Ok,
        message: Vec::new(),
    }
    .to_bytes(&limits)
    .expect("status frame");
    let mut bytes = no_index_global_header_bytes();
    bytes.extend_from_slice(&session_control_entry_bytes(
        stream_id,
        sequence_no,
        SessionOpCode::Status as u8,
        payload,
    ));
    bytes
}

/// Build a complete CTL! stream carrying a SESSION_ACK:
/// association header + SAR global header + ACK entry.
pub fn ctl_stream_with_ack(stream_id: u16, session_uuid: [u8; 16], sequence_no: u16) -> Vec<u8> {
    let mut bytes = ctl_stream_assoc_header_bytes(stream_id, session_uuid);
    bytes.extend_from_slice(&ctl_stream_sar_ack_bytes(stream_id, sequence_no));
    bytes
}

/// Build a complete CTL! stream carrying a SESSION_STATUS:
/// association header + SAR global header + STATUS entry.
pub fn ctl_stream_with_status(stream_id: u16, session_uuid: [u8; 16], sequence_no: u16) -> Vec<u8> {
    let mut bytes = ctl_stream_assoc_header_bytes(stream_id, session_uuid);
    bytes.extend_from_slice(&ctl_stream_sar_status_bytes(stream_id, sequence_no));
    bytes
}
