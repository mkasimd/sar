// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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

/// The exact TLS exporter label for Context Version `0x01` (Section 18.6.3).
pub const TLS_EXPORTER_LABEL_V1: &[u8; 15] = b"EXPORTER-SAR-v1";

/// Pre-WP-6 exporter label used by the legacy directional exporter test
/// harness.  It does not match Section 18.6.3; the directional exporter
/// remediation is assigned to M13b.4.
pub const EXPORTER_LABEL_QUIC_AEAD: &[u8] = b"EXPORTER-SAR-v1-QUIC-AEAD";

/// Pre-WP-6 exporter label (see [`EXPORTER_LABEL_QUIC_AEAD`]).
pub const EXPORTER_LABEL_TCP_TLS_AEAD: &[u8] = b"EXPORTER-SAR-v1-TLS-AEAD";

// ──────────────────────────────────────────────────────────────────────────────
// KMS payload structure
// ──────────────────────────────────────────────────────────────────────────────

/// Parsed Mode `0x04 TLS_EXPORTER` KMS payload (Section 5.3.3).
///
/// Contains derivation metadata only.  Does not contain any raw keys,
/// wrapping keys, private keys, or TLS exporter output.
///
/// This type is independent of any TLS or QUIC library.  The actual TLS
/// exporter invocation is performed by `sar-transport` using the exporter
/// context produced by [`encode_tls_exporter_context_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExporterParams {
    /// Context version; MUST be `0x01` ([`TLS_EXPORTER_CONTEXT_VERSION_1`]).
    pub context_version: u8,
    /// Post-export KDF algorithm identifier.  MUST be `0x00`
    /// ([`TLS_EXPORTER_KDF_DIRECT`]); nonzero values are reserved.
    pub kdf_algo_id: u8,
    /// Hash algorithm used for Global Header binding.
    pub global_header_hash_algo_id: u8,
    /// Directional KMS Master Secret length; MUST be `32`.
    pub derived_key_length: u16,
    /// ASCII exporter label; MUST be `EXPORTER-SAR-v1` for Context Version `0x01`.
    pub exporter_label: String,
    /// Non-secret salt bytes; MUST be empty for Context Version `0x01`.
    pub salt: Vec<u8>,
}

/// Validates a Global Header Hash Algo ID against the SAR hash registry.
///
/// # Errors
///
/// `Unsupported` for assigned-but-unimplemented identifiers, `ReservedValue`
/// for unassigned identifiers.
pub fn validate_exporter_hash_algo_id(id: u8) -> Result<(), SarCryptoError> {
    match id {
        crate::algorithm::HASH_SHA256 | crate::algorithm::HASH_BLAKE3 => Ok(()),
        crate::algorithm::HASH_SHA3_256 => Err(SarCryptoError::Unsupported(
            "TLS_EXPORTER Global Header Hash Algo ID SHA3-256 not implemented",
        )),
        _ => Err(SarCryptoError::ReservedValue(
            "TLS_EXPORTER Global Header Hash Algo ID is reserved",
        )),
    }
}

/// Parses a raw Mode `0x04 TLS_EXPORTER` KMS payload byte slice.
///
/// Validates structure and registry values (Context Version, KDF Algo ID,
/// hash algorithm, Derived Key Length, label, salt) but does **not** perform
/// key derivation.
///
/// # Errors
///
/// * [`SarCryptoError::Malformed`] for truncation, trailing bytes or a wrong label.
/// * [`SarCryptoError::ReservedValue`] for a reserved Context Version, KDF
///   Algo ID or hash identifier.
/// * [`SarCryptoError::Unsupported`] for an assigned but unimplemented hash.
/// * [`SarCryptoError::InvalidLength`] for a wrong Derived Key Length, label
///   length or salt length.
pub fn parse_tls_exporter_kms_payload(payload: &[u8]) -> Result<TlsExporterParams, SarCryptoError> {
    // Wire format (Section 5.3.3):
    // Context Version(1) KDF Algo ID(1) Global Header Hash Algo ID(1)
    // Derived Key Length(2 LE) Exporter Label Length(1) Salt Length(1)
    // Exporter Label(var) Salt(var)
    let mut cur = crate::kms::types::Cursor::new(payload);
    let context_version = cur.u8("TLS_EXPORTER KMS payload truncated")?;
    let kdf_algo_id = cur.u8("TLS_EXPORTER KMS payload truncated")?;
    let global_header_hash_algo_id = cur.u8("TLS_EXPORTER KMS payload truncated")?;
    let derived_key_length = cur.u16("TLS_EXPORTER KMS payload truncated")?;
    let label_len = usize::from(cur.u8("TLS_EXPORTER KMS payload truncated")?);
    let salt_len = usize::from(cur.u8("TLS_EXPORTER KMS payload truncated")?);
    let label_bytes = cur.take(label_len, "TLS_EXPORTER exporter label truncated")?;
    let salt = cur.take(salt_len, "TLS_EXPORTER salt truncated")?.to_vec();
    cur.finish("TLS_EXPORTER KMS payload has trailing bytes")?;

    if context_version != TLS_EXPORTER_CONTEXT_VERSION_1 {
        return Err(SarCryptoError::ReservedValue(
            "TLS_EXPORTER reserved Context Version",
        ));
    }
    if kdf_algo_id != TLS_EXPORTER_KDF_DIRECT {
        return Err(SarCryptoError::ReservedValue(
            "TLS_EXPORTER: nonzero KDF Algo ID is reserved",
        ));
    }
    validate_exporter_hash_algo_id(global_header_hash_algo_id)?;
    if usize::from(derived_key_length) != crate::algorithm::KMS_MASTER_SECRET_SIZE {
        return Err(SarCryptoError::InvalidLength(
            "TLS_EXPORTER Derived Key Length must be 32",
        ));
    }
    if label_bytes.len() != TLS_EXPORTER_LABEL_V1.len() {
        return Err(SarCryptoError::InvalidLength(
            "TLS_EXPORTER Exporter Label Length must be 15",
        ));
    }
    if label_bytes != TLS_EXPORTER_LABEL_V1 {
        return Err(SarCryptoError::Malformed(
            "TLS_EXPORTER Exporter Label must be EXPORTER-SAR-v1",
        ));
    }
    if !salt.is_empty() {
        return Err(SarCryptoError::InvalidLength(
            "TLS_EXPORTER Salt Length must be 0 for Context Version 0x01",
        ));
    }
    let exporter_label = String::from_utf8(label_bytes.to_vec())
        .map_err(|_| SarCryptoError::Malformed("TLS_EXPORTER label is not valid UTF-8"))?;

    Ok(TlsExporterParams {
        context_version,
        kdf_algo_id,
        global_header_hash_algo_id,
        derived_key_length,
        exporter_label,
        salt,
    })
}

/// Serialises a [`TlsExporterParams`] into the on-wire KMS payload bytes.
///
/// # Errors
///
/// Returns [`SarCryptoError::InvalidLength`] when the label or salt length
/// does not fit its one-byte wire field.
pub fn serialize_tls_exporter_kms_payload(
    params: &TlsExporterParams,
) -> Result<Vec<u8>, SarCryptoError> {
    let label = params.exporter_label.as_bytes();
    let label_len = u8::try_from(label.len())
        .map_err(|_| SarCryptoError::InvalidLength("exporter label length exceeds 255"))?;
    let salt_len = u8::try_from(params.salt.len())
        .map_err(|_| SarCryptoError::InvalidLength("salt length exceeds 255"))?;
    let mut out = Vec::with_capacity(8 + label.len() + params.salt.len());
    out.push(params.context_version);
    out.push(params.kdf_algo_id);
    out.push(params.global_header_hash_algo_id);
    out.extend_from_slice(&params.derived_key_length.to_le_bytes());
    out.push(label_len);
    out.push(salt_len);
    out.extend_from_slice(label);
    out.extend_from_slice(&params.salt);
    Ok(out)
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
