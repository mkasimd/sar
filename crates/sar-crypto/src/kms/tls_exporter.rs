//! TLS_EXPORTER KMS mode (0x04) types and context encoding.
//!
//! Provides the parsed payload structure for KMS Mode `0x04 TLS_EXPORTER`,
//! constants for transport profile IDs and key usage IDs, and the canonical
//! [`Context Version 0x01`](encode_tls_exporter_context_v1) exporter context
//! encoder.
//!
//! This module contains **no TLS or QUIC dependencies**.  The actual TLS
//! exporter invocation is performed by the transport layer (`sar-transport`)
//! using the context bytes produced here.

use crate::error::SarCryptoError;

// ──────────────────────────────────────────────────────────────────────────────
// Registry constants
// ──────────────────────────────────────────────────────────────────────────────

/// Context Version `0x01` — the only defined exporter context version.
pub const TLS_EXPORTER_CONTEXT_VERSION_1: u8 = 0x01;

/// KDF Algo ID `0x00` — direct TLS exporter output (no post-export KDF).
pub const TLS_EXPORTER_KDF_DIRECT: u8 = 0x00;

/// Transport Profile ID `0x01` — SAR-over-QUIC.
pub const TLS_EXPORTER_TRANSPORT_QUIC: u8 = 0x01;

/// Transport Profile ID `0x02` — SAR-over-TCP wrapped in TLS (future).
pub const TLS_EXPORTER_TRANSPORT_TCP_TLS: u8 = 0x02;

/// Key Usage ID `0x01` — SAR entry protection for the TLS-client direction.
///
/// `CLIENT_TO_SERVER_ENTRY` refers to the TLS transport role, not the SAR
/// Sender/Receiver role.
pub const TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER: u8 = 0x01;

/// Key Usage ID `0x02` — SAR entry protection for the TLS-server direction.
///
/// `SERVER_TO_CLIENT_ENTRY` refers to the TLS transport role, not the SAR
/// Sender/Receiver role.
pub const TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT: u8 = 0x02;

/// Recommended TLS exporter label for SAR-over-QUIC.
pub const EXPORTER_LABEL_QUIC_AEAD: &[u8] = b"EXPORTER-SAR-v1-QUIC-AEAD";

/// Recommended TLS exporter label for SAR-over-TCP+TLS.
pub const EXPORTER_LABEL_TCP_TLS_AEAD: &[u8] = b"EXPORTER-SAR-v1-TLS-AEAD";

// ──────────────────────────────────────────────────────────────────────────────
// KMS payload structure
// ──────────────────────────────────────────────────────────────────────────────

/// Parsed Mode `0x04 TLS_EXPORTER` KMS payload.
///
/// Contains derivation metadata only.  Does not contain any raw keys,
/// wrapping keys, private keys, or TLS exporter output.
///
/// This type is independent of any TLS or QUIC library.  The actual TLS
/// exporter invocation is performed by `sar-transport` using the exporter
/// context produced by [`encode_tls_exporter_context_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExporterParams {
    /// ASCII TLS exporter label.
    pub exporter_label: String,
    /// Context version; MUST be `0x01` ([`TLS_EXPORTER_CONTEXT_VERSION_1`]).
    pub context_version: u8,
    /// SAR AEAD algorithm identifier.
    pub aead_algo_id: u8,
    /// Post-export KDF algorithm identifier.  MUST be `0x00`
    /// ([`TLS_EXPORTER_KDF_DIRECT`]); nonzero values are reserved.
    pub kdf_algo_id: u8,
    /// Hash algorithm used for Global Header binding.
    pub global_header_hash_algo_id: u8,
    /// Non-secret salt / context bytes.
    pub salt: Vec<u8>,
    /// Required AEAD key length in bytes.  MUST match the selected AEAD algorithm.
    pub derived_key_length: u16,
    /// Profile flags.  All bits are reserved and MUST be `0`.
    pub flags: u16,
}

/// Parses a raw Mode `0x04 TLS_EXPORTER` KMS payload byte slice.
///
/// Validates structural constraints (ASCII label, reserved bits, supported
/// context version and KDF Algo ID) but does **not** perform AEAD key
/// derivation.
///
/// # Errors
///
/// Returns [`SarCryptoError::Malformed`] for structural violations,
/// [`SarCryptoError::ReservedValue`] for nonzero reserved fields, and
/// [`SarCryptoError::Unsupported`] for unimplemented extension points.
pub fn parse_tls_exporter_kms_payload(payload: &[u8]) -> Result<TlsExporterParams, SarCryptoError> {
    // Wire format:
    // [0]       Exporter Label Length (u8)
    // [1..]     Exporter Label (var, ASCII)
    // [+0]      Context Version (u8)
    // [+1]      AEAD Algo ID (u8)
    // [+2]      KDF Algo ID (u8)
    // [+3]      Global Header Hash Algo ID (u8)
    // [+4]      Salt Length (u8)
    // [+5..]    Salt (var)
    // [+0]      Derived Key Length (u16 LE)
    // [+2]      Flags (u16 LE)

    if payload.is_empty() {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER KMS payload too short: missing label length",
        ));
    }
    let label_len = usize::from(payload[0]);
    let label_end = 1usize
        .checked_add(label_len)
        .ok_or(SarCryptoError::Malformed(
            "TLS_EXPORTER label length overflow",
        ))?;
    if payload.len() < label_end + 7 {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER KMS payload too short: truncated before fixed fields",
        ));
    }
    let label_bytes = &payload[1..label_end];
    if !label_bytes.is_ascii() {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER exporter label must be ASCII",
        ));
    }
    if label_bytes.is_empty() {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER exporter label must not be empty",
        ));
    }
    let exporter_label = String::from_utf8(label_bytes.to_vec())
        .map_err(|_| SarCryptoError::Malformed("TLS_EXPORTER label is not valid UTF-8"))?;

    let mut pos = label_end;
    let context_version = payload[pos];
    pos += 1;
    if context_version != TLS_EXPORTER_CONTEXT_VERSION_1 {
        return Err(SarCryptoError::Unsupported(
            "TLS_EXPORTER: only context version 0x01 is supported",
        ));
    }

    let aead_algo_id = payload[pos];
    pos += 1;
    let kdf_algo_id = payload[pos];
    pos += 1;
    if kdf_algo_id != TLS_EXPORTER_KDF_DIRECT {
        return Err(SarCryptoError::ReservedValue(
            "TLS_EXPORTER: nonzero KDF Algo ID is reserved",
        ));
    }

    let global_header_hash_algo_id = payload[pos];
    pos += 1;

    // Salt Length
    if pos >= payload.len() {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER KMS payload too short: missing salt length",
        ));
    }
    let salt_len = usize::from(payload[pos]);
    pos += 1;
    let salt_end = pos.checked_add(salt_len).ok_or(SarCryptoError::Malformed(
        "TLS_EXPORTER salt length overflow",
    ))?;
    if payload.len() < salt_end + 4 {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER KMS payload too short: truncated in salt / derived key length",
        ));
    }
    let salt = payload[pos..salt_end].to_vec();
    pos = salt_end;

    // Derived Key Length (u16 LE)
    let derived_key_length = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
    pos += 2;
    if derived_key_length == 0 {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER derived_key_length must be nonzero",
        ));
    }

    // Flags (u16 LE) — all bits reserved
    let flags = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
    if flags != 0 {
        return Err(SarCryptoError::ReservedValue(
            "TLS_EXPORTER flags: reserved bits must be zero",
        ));
    }

    Ok(TlsExporterParams {
        exporter_label,
        context_version,
        aead_algo_id,
        kdf_algo_id,
        global_header_hash_algo_id,
        salt,
        derived_key_length,
        flags,
    })
}

/// Serialises a [`TlsExporterParams`] into the on-wire KMS payload bytes.
#[must_use]
pub fn serialize_tls_exporter_kms_payload(params: &TlsExporterParams) -> Vec<u8> {
    let label = params.exporter_label.as_bytes();
    let mut out = Vec::new();
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.push(params.context_version);
    out.push(params.aead_algo_id);
    out.push(params.kdf_algo_id);
    out.push(params.global_header_hash_algo_id);
    out.push(params.salt.len() as u8);
    out.extend_from_slice(&params.salt);
    out.extend_from_slice(&params.derived_key_length.to_le_bytes());
    out.extend_from_slice(&params.flags.to_le_bytes());
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Context Version 0x01 encoder
// ──────────────────────────────────────────────────────────────────────────────

/// Input for the canonical `Context Version = 0x01` TLS exporter context.
///
/// Encodes the exporter context that binds the derived SAR AEAD keying
/// material to the SAR session, transport binding, cryptographic profile,
/// and key usage.  Produce the encoded bytes using
/// [`encode_tls_exporter_context_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExporterContextV1 {
    /// Transport binding profile identifier (e.g. [`TLS_EXPORTER_TRANSPORT_QUIC`]).
    pub transport_profile_id: u8,
    /// SAR major protocol version.
    pub sar_major_version: u8,
    /// SAR minor protocol version.
    pub sar_minor_version: u8,
    /// Hash algorithm used for Global Header binding.
    pub global_header_hash_algo_id: u8,
    /// Hash of the complete encoded Global Header (including KMS fields,
    /// excluding LFH bytes).
    pub global_header_hash: Vec<u8>,
    /// SAR AEAD algorithm identifier.
    pub aead_algo_id: u8,
    /// SAR Stream ID (little-endian).
    pub stream_id: u16,
    /// Session UUID from `SESSION_INIT`.
    pub session_uuid: [u8; 16],
    /// Key-usage direction identifier (e.g.
    /// [`TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER`]).
    pub key_usage_id: u8,
    /// Salt / context bytes from the `TLS_EXPORTER` KMS Data.
    pub salt: Vec<u8>,
}

/// Encodes a [`TlsExporterContextV1`] into the canonical on-wire byte sequence.
///
/// The returned bytes are suitable for passing as the `context` argument to
/// the TLS exporter (e.g. `quinn::Connection::export_keying_material`).
///
/// # Encoding (Context Version = `0x01`)
///
/// ```text
/// 0  Context Version            1B  = 0x01
/// 1  Transport Profile ID       1B
/// 2  SAR Major Version          1B
/// 3  SAR Minor Version          1B
/// 4  GH Hash Algo ID            1B
/// 5  GH Hash Length             1B
/// 6  GH Hash                    Var
/// +  KMS Mode ID                1B  = 0x04
/// +  AEAD Algo ID               1B
/// +  Stream ID                  2B  (little-endian)
/// +  Session UUID               16B
/// +  Key Usage ID               1B
/// +  Salt Length                1B
/// +  Salt                       Var
/// ```
#[must_use]
pub fn encode_tls_exporter_context_v1(ctx: &TlsExporterContextV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        1 + 1
            + 1
            + 1
            + 1
            + 1
            + ctx.global_header_hash.len()
            + 1
            + 1
            + 2
            + 16
            + 1
            + 1
            + ctx.salt.len(),
    );
    out.push(TLS_EXPORTER_CONTEXT_VERSION_1); // Context Version
    out.push(ctx.transport_profile_id);
    out.push(ctx.sar_major_version);
    out.push(ctx.sar_minor_version);
    out.push(ctx.global_header_hash_algo_id);
    out.push(ctx.global_header_hash.len() as u8); // GH Hash Length
    out.extend_from_slice(&ctx.global_header_hash);
    out.push(0x04u8); // KMS Mode ID = TLS_EXPORTER
    out.push(ctx.aead_algo_id);
    out.extend_from_slice(&ctx.stream_id.to_le_bytes());
    out.extend_from_slice(&ctx.session_uuid);
    out.push(ctx.key_usage_id);
    out.push(ctx.salt.len() as u8); // Salt Length
    out.extend_from_slice(&ctx.salt);
    out
}
