#![allow(dead_code)]

use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, KmsData, LocalFileHeader, ResourceLimits, SarStatus,
    write_global_header, write_lfh,
};
use sar_crypto::{
    ENCR_AES256_GCM, KMS_TLS_EXPORTER, TLS_EXPORTER_CONTEXT_VERSION_1, TLS_EXPORTER_KDF_DIRECT,
    TlsExporterParams, serialize_tls_exporter_kms_payload,
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

/// Builds a Global Header with `NO_INDEX | ENCRYPTED` and KMS Mode `0x04
/// TLS_EXPORTER`.  This is the bootstrap global header for TLS_EXPORTER SAR
/// sessions used in M10i post-binding enforcement tests.
pub fn tls_exporter_global_header_bytes() -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
    let kms_payload = serialize_tls_exporter_kms_payload(&TlsExporterParams {
        exporter_label: "EXPORTER-SAR-v1-QUIC-AEAD".to_string(),
        context_version: TLS_EXPORTER_CONTEXT_VERSION_1,
        aead_algo_id: ENCR_AES256_GCM,
        kdf_algo_id: TLS_EXPORTER_KDF_DIRECT,
        global_header_hash_algo_id: 0x01,
        salt: vec![],
        derived_key_length: 32,
        flags: 0,
    });
    let header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: Some(KmsData {
            mode_id: KMS_TLS_EXPORTER,
            payload: kms_payload,
        }),
    };
    write_global_header(&header).expect("tls_exporter global header encoding")
}

/// Builds a SESSION_INIT entry for a TLS_EXPORTER session.
///
/// SESSION_INIT is the only mandatory plaintext bootstrap entry for KMS Mode
/// `0x04 TLS_EXPORTER`.  It must NOT carry `EntryMode::ENCRYPTED`.  In the
/// ENCRYPTED global header context the LFH will have the `encr_algo_id` field
/// (set to `0x00` = no entry-level encryption) and a zeroed IV/nonce.
pub fn tls_exporter_session_init_bytes(
    stream_id: u16,
    sequence_no: u16,
    session_uuid: [u8; 16],
) -> Vec<u8> {
    let payload = SessionInitFrame {
        session_uuid,
        flags: SessionFlags::from_bits(0),
    }
    .to_bytes()
    .expect("session init payload");

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
    // Plaintext bootstrap: entry_mode has NO EntryMode::ENCRYPTED bit.
    let mut lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), payload.len() as u64);
    lfh.stream_id = stream_id;
    lfh.sequence_no = sequence_no;
    lfh.entry_mode = EntryMode::from_bits(
        (u16::from(SessionOpCode::Init as u8) << 8) | EntryMode::SESSION_CONTROL,
    );
    lfh.payload_size = payload.len() as u64;
    lfh.uncompressed_size = payload.len() as u64;
    // ENCRYPTED global flags require encr_algo_id and iv_nonce fields in LFH.
    // For the plaintext SESSION_INIT, encr_algo_id = 0 (no per-entry AEAD).
    lfh.encr_algo_id = Some(0x00);
    lfh.iv_nonce = Some([0u8; 24]);
    let mut bytes = write_lfh(&flags, &lfh).expect("tls_exporter SESSION_INIT LFH");
    bytes.extend_from_slice(&payload);
    bytes
}

/// Builds the canonical TLS_EXPORTER session bootstrap bytes (global header +
/// plaintext SESSION_INIT).
pub fn tls_exporter_session_archive_init_bytes(
    stream_id: u16,
    session_uuid: [u8; 16],
) -> Vec<u8> {
    let mut bytes = tls_exporter_global_header_bytes();
    bytes.extend_from_slice(&tls_exporter_session_init_bytes(stream_id, 0, session_uuid));
    bytes
}

/// Builds a post-binding SESSION_CONTROL entry with `EntryMode::ENCRYPTED` set,
/// simulating a properly AEAD-protected entry for a TLS_EXPORTER session.
///
/// The payload is not truly AEAD-encrypted in test helpers — the transport
/// harness only enforces the structural `EntryMode::ENCRYPTED` bit.  Actual
/// AEAD verification is tested separately via `sar-crypto` unit tests.
pub fn tls_exporter_encrypted_control_entry_bytes(
    stream_id: u16,
    sequence_no: u16,
    opcode: u8,
    inner_payload: Vec<u8>,
) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
    let mut lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), inner_payload.len() as u64);
    lfh.stream_id = stream_id;
    lfh.sequence_no = sequence_no;
    // Set EntryMode::ENCRYPTED to signal that this entry is AEAD-protected.
    lfh.entry_mode = EntryMode::from_bits(
        (u16::from(opcode) << 8)
            | EntryMode::SESSION_CONTROL
            | EntryMode::ENCRYPTED,
    );
    lfh.payload_size = inner_payload.len() as u64;
    lfh.uncompressed_size = inner_payload.len() as u64;
    lfh.encr_algo_id = Some(ENCR_AES256_GCM);
    lfh.iv_nonce = Some([0xAAu8; 24]); // non-zero dummy nonce
    let mut bytes = write_lfh(&flags, &lfh).expect("tls_exporter encrypted LFH");
    bytes.extend_from_slice(&inner_payload);
    bytes
}

/// Builds a post-binding SESSION_CONTROL entry WITHOUT `EntryMode::ENCRYPTED`.
///
/// This simulates a plaintext entry arriving after TLS_EXPORTER binding is
/// active.  The transport layer MUST reject this with `SarError::AuthFailed`.
pub fn tls_exporter_plaintext_control_entry_bytes(
    stream_id: u16,
    sequence_no: u16,
    opcode: u8,
    inner_payload: Vec<u8>,
) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
    let mut lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), inner_payload.len() as u64);
    lfh.stream_id = stream_id;
    lfh.sequence_no = sequence_no;
    // No EntryMode::ENCRYPTED bit — this is a plaintext entry.
    lfh.entry_mode = EntryMode::from_bits(
        (u16::from(opcode) << 8) | EntryMode::SESSION_CONTROL,
    );
    lfh.payload_size = inner_payload.len() as u64;
    lfh.uncompressed_size = inner_payload.len() as u64;
    lfh.encr_algo_id = Some(0x00); // 0 = no per-entry AEAD
    lfh.iv_nonce = Some([0u8; 24]);
    let mut bytes = write_lfh(&flags, &lfh).expect("tls_exporter plaintext LFH");
    bytes.extend_from_slice(&inner_payload);
    bytes
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

