// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_name_repetitions)]

use crate::algorithm::{
    ARGON2_VARIANT_ID, ARGON2_VERSION_0X13, KMS_ARGON2, KMS_ASYMMETRIC_WRAP,
    KMS_MASTER_SECRET_SIZE, KMS_PBKDF2, KMS_TLS_EXPORTER, PBKDF2_PRF_HMAC_SHA3_256,
    PBKDF2_PRF_HMAC_SHA256, PBKDF2_PRF_HMAC_SHA512,
};
use crate::error::SarCryptoError;
use crate::kms::tls_exporter::{TlsExporterParams, serialize_tls_exporter_kms_payload};

/// Parsed PBKDF2 KMS payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbkdf2Params {
    /// PRF algorithm identifier.
    pub prf_algo_id: u8,
    /// PBKDF2 salt bytes.
    pub salt: Vec<u8>,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Derived key length in bytes.
    pub derived_key_length: u16,
}

/// Parsed Argon2 KMS payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Params {
    /// Argon2 variant identifier.
    pub variant: u8,
    /// Argon2 version byte.
    pub version: u8,
    /// Argon2 salt bytes.
    pub salt: Vec<u8>,
    /// Memory cost in KiB.
    pub memory_cost_kib: u32,
    /// Iteration/time cost.
    pub time_cost: u32,
    /// Parallelism lanes.
    pub parallelism: u16,
    /// Derived key length in bytes.
    pub derived_key_length: u16,
}

/// One recipient entry for asymmetric key wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsymmetricRecipient {
    /// Recipient identifier bytes.
    pub recipient_id: Vec<u8>,
    /// Wrapped KMS Master Secret bytes.
    pub wrapped_key: Vec<u8>,
}

/// Parsed ASYMMETRIC_WRAP KMS payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsymmetricWrapParams {
    /// Wrap algorithm identifier.
    pub wrap_algo_id: u8,
    /// Per-recipient wrapped keys.
    pub recipients: Vec<AsymmetricRecipient>,
}

/// Parsed KMS payload variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsParams {
    /// PBKDF2 parameters.
    Pbkdf2(Pbkdf2Params),
    /// Argon2 parameters.
    Argon2(Argon2Params),
    /// Asymmetric wrap parameters.
    AsymmetricWrap(AsymmetricWrapParams),
    /// TLS_EXPORTER derivation parameters (Mode 0x04).
    ///
    /// The payload contains derivation metadata only; no raw keys or TLS
    /// exporter output.  Key derivation is performed by the transport layer
    /// via the TLS exporter API.
    TlsExporter(TlsExporterParams),
}

/// Key-resolution context passed to `KeyProvider` implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsContext {
    /// KMS mode identifier.
    pub mode_id: u8,
    /// Parsed mode-specific parameters.
    pub params: KmsParams,
}

/// Wrap Algo ID `0x01`: RSA-OAEP-2048.
pub const WRAP_RSA_OAEP_2048: u8 = 0x01;
/// Wrap Algo ID `0x02`: RSA-OAEP-4096.
pub const WRAP_RSA_OAEP_4096: u8 = 0x02;
/// Wrap Algo ID `0x03`: X25519 HPKE.
pub const WRAP_X25519_HPKE: u8 = 0x03;
/// Wrap Algo ID `0x04`: ML-KEM-768 (assigned, unsupported).
pub const WRAP_ML_KEM_768: u8 = 0x04;
/// Wrap Algo ID `0x05`: ML-KEM-1024 (assigned, unsupported).
pub const WRAP_ML_KEM_1024: u8 = 0x05;

/// Returns the required Wrapped Key Blob length for an implemented wrap algorithm.
///
/// Assigned-but-unsupported identifiers return `Unsupported`; everything else
/// is `ReservedValue`.
///
/// # Errors
///
/// See above.
pub fn wrapped_key_len_for(wrap_algo_id: u8) -> Result<usize, SarCryptoError> {
    match wrap_algo_id {
        WRAP_RSA_OAEP_2048 => Ok(256),
        WRAP_RSA_OAEP_4096 => Ok(512),
        WRAP_X25519_HPKE => Ok(80),
        WRAP_ML_KEM_768 | WRAP_ML_KEM_1024 => Err(SarCryptoError::Unsupported(
            "ML-KEM wrap algorithm not implemented",
        )),
        _ => Err(SarCryptoError::ReservedValue("reserved Wrap Algo ID")),
    }
}

fn len_u8(len: usize, what: &'static str) -> Result<u8, SarCryptoError> {
    u8::try_from(len).map_err(|_| SarCryptoError::InvalidLength(what))
}

/// Serialize `params` into the canonical on-wire KMS payload bytes (Section 5.3.3).
///
/// # Errors
///
/// Returns [`SarCryptoError::InvalidLength`] when a length does not fit its
/// wire field.
pub fn serialize_kms_payload(params: &KmsParams) -> Result<Vec<u8>, SarCryptoError> {
    match params {
        KmsParams::Pbkdf2(p) => {
            let mut out = Vec::with_capacity(9 + p.salt.len());
            out.push(p.prf_algo_id);
            out.extend_from_slice(&p.iterations.to_le_bytes());
            out.extend_from_slice(&p.derived_key_length.to_le_bytes());
            out.push(len_u8(p.salt.len(), "PBKDF2 salt length exceeds 255")?);
            out.extend_from_slice(&p.salt);
            Ok(out)
        }
        KmsParams::Argon2(p) => {
            let mut out = Vec::with_capacity(15 + p.salt.len());
            out.push(p.variant);
            out.push(p.version);
            out.extend_from_slice(&p.memory_cost_kib.to_le_bytes());
            out.extend_from_slice(&p.time_cost.to_le_bytes());
            out.extend_from_slice(&p.parallelism.to_le_bytes());
            out.extend_from_slice(&p.derived_key_length.to_le_bytes());
            out.push(len_u8(p.salt.len(), "Argon2 salt length exceeds 255")?);
            out.extend_from_slice(&p.salt);
            Ok(out)
        }
        KmsParams::AsymmetricWrap(p) => {
            let mut out = Vec::new();
            out.push(p.wrap_algo_id);
            out.push(len_u8(p.recipients.len(), "recipient count exceeds 255")?);
            for recipient in &p.recipients {
                out.push(len_u8(
                    recipient.recipient_id.len(),
                    "Recipient ID length exceeds 255",
                )?);
                out.extend_from_slice(&recipient.recipient_id);
                let wrapped_len = u16::try_from(recipient.wrapped_key.len())
                    .map_err(|_| SarCryptoError::InvalidLength("wrapped key length exceeds u16"))?;
                out.extend_from_slice(&wrapped_len.to_le_bytes());
                out.extend_from_slice(&recipient.wrapped_key);
            }
            Ok(out)
        }
        KmsParams::TlsExporter(p) => serialize_tls_exporter_kms_payload(p),
    }
}

/// Parse a KMS payload using its `mode_id`.
///
/// Parsing validates structure, registry values and the Section 5.3.3 /
/// 5.3.4 minimums only.  Local resource limits are applied separately by
/// [`crate::kms::limits::KdfLimits`] before derivation.
///
/// Returns [`SarCryptoError::Unsupported`] for Mode `0x04 TLS_EXPORTER`,
/// which requires a transport-layer TLS session.  To parse TLS_EXPORTER
/// payload bytes directly, use
/// [`crate::kms::tls_exporter::parse_tls_exporter_kms_payload`].
pub fn parse_kms_payload(mode_id: u8, payload: &[u8]) -> Result<KmsParams, SarCryptoError> {
    match mode_id {
        KMS_PBKDF2 => parse_pbkdf2(payload),
        KMS_ARGON2 => parse_argon2(payload),
        KMS_ASYMMETRIC_WRAP => parse_asymmetric_wrap(payload),
        KMS_TLS_EXPORTER => Err(SarCryptoError::Unsupported(
            "KMS_TLS_EXPORTER requires an authenticated TLS session; unsupported on plaintext TCP",
        )),
        0xF0..=0xFF => Err(SarCryptoError::Unsupported("custom KMS mode")),
        _ => Err(SarCryptoError::ReservedValue("unknown KMS mode ID")),
    }
}

/// Bounds-checked little-endian cursor over a KMS payload.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn take(
        &mut self,
        len: usize,
        what: &'static str,
    ) -> Result<&'a [u8], SarCryptoError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SarCryptoError::Malformed(what))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(SarCryptoError::Malformed(what))?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self, what: &'static str) -> Result<u8, SarCryptoError> {
        Ok(self.take(1, what)?[0])
    }

    pub(crate) fn u16(&mut self, what: &'static str) -> Result<u16, SarCryptoError> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self, what: &'static str) -> Result<u32, SarCryptoError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn finish(&self, what: &'static str) -> Result<(), SarCryptoError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(SarCryptoError::Malformed(what))
        }
    }
}

fn check_derived_key_length(value: u16, what: &'static str) -> Result<(), SarCryptoError> {
    if usize::from(value) == KMS_MASTER_SECRET_SIZE {
        Ok(())
    } else {
        Err(SarCryptoError::InvalidLength(what))
    }
}

fn parse_pbkdf2(payload: &[u8]) -> Result<KmsParams, SarCryptoError> {
    let mut cur = Cursor::new(payload);
    let prf_algo_id = cur.u8("PBKDF2 payload truncated")?;
    match prf_algo_id {
        PBKDF2_PRF_HMAC_SHA256 => {}
        PBKDF2_PRF_HMAC_SHA512 | PBKDF2_PRF_HMAC_SHA3_256 => {
            return Err(SarCryptoError::Unsupported(
                "PBKDF2 PRF algorithm not implemented",
            ));
        }
        _ => {
            return Err(SarCryptoError::ReservedValue(
                "unknown PBKDF2 PRF algorithm ID",
            ));
        }
    }
    let iterations = cur.u32("PBKDF2 payload truncated")?;
    let derived_key_length = cur.u16("PBKDF2 payload truncated")?;
    let salt_len = usize::from(cur.u8("PBKDF2 payload truncated")?);
    let salt = cur.take(salt_len, "PBKDF2 salt truncated")?.to_vec();
    cur.finish("PBKDF2 payload has trailing bytes")?;
    check_derived_key_length(derived_key_length, "PBKDF2 Derived Key Length must be 32")?;
    if salt_len < 16 {
        return Err(SarCryptoError::InvalidLength(
            "PBKDF2 salt length must be >= 16",
        ));
    }
    if iterations < 100_000 {
        return Err(SarCryptoError::InvalidLength(
            "PBKDF2 iterations must be >= 100000",
        ));
    }
    Ok(KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id,
        salt,
        iterations,
        derived_key_length,
    }))
}

fn parse_argon2(payload: &[u8]) -> Result<KmsParams, SarCryptoError> {
    let mut cur = Cursor::new(payload);
    let variant = cur.u8("Argon2 payload truncated")?;
    if variant != ARGON2_VARIANT_ID {
        return Err(SarCryptoError::ReservedValue("reserved Argon2 variant"));
    }
    let version = cur.u8("Argon2 payload truncated")?;
    if version != ARGON2_VERSION_0X13 {
        return Err(SarCryptoError::Unsupported(
            "only Argon2 version 0x13 is supported",
        ));
    }
    let memory_cost_kib = cur.u32("Argon2 payload truncated")?;
    let time_cost = cur.u32("Argon2 payload truncated")?;
    let parallelism = cur.u16("Argon2 payload truncated")?;
    let derived_key_length = cur.u16("Argon2 payload truncated")?;
    let salt_len = usize::from(cur.u8("Argon2 payload truncated")?);
    let salt = cur.take(salt_len, "Argon2 salt truncated")?.to_vec();
    cur.finish("Argon2 payload has trailing bytes")?;
    check_derived_key_length(derived_key_length, "Argon2 Derived Key Length must be 32")?;
    if memory_cost_kib == 0 || time_cost == 0 || parallelism == 0 {
        return Err(SarCryptoError::InvalidLength(
            "Argon2 memory, time and parallelism must be > 0",
        ));
    }
    if salt_len < 16 {
        return Err(SarCryptoError::InvalidLength(
            "Argon2 salt length must be >= 16",
        ));
    }
    Ok(KmsParams::Argon2(Argon2Params {
        variant,
        version,
        salt,
        memory_cost_kib,
        time_cost,
        parallelism,
        derived_key_length,
    }))
}

fn parse_asymmetric_wrap(payload: &[u8]) -> Result<KmsParams, SarCryptoError> {
    let mut cur = Cursor::new(payload);
    let wrap_algo_id = cur.u8("ASYMMETRIC_WRAP payload truncated")?;
    let expected_wrapped_len = wrapped_key_len_for(wrap_algo_id)?;
    let recipient_count = usize::from(cur.u8("ASYMMETRIC_WRAP payload truncated")?);
    if recipient_count < 1 {
        return Err(SarCryptoError::Malformed(
            "ASYMMETRIC_WRAP must have at least 1 recipient",
        ));
    }
    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        let id_len = usize::from(cur.u8("ASYMMETRIC_WRAP recipient truncated")?);
        if id_len == 0 {
            return Err(SarCryptoError::InvalidLength(
                "ASYMMETRIC_WRAP Recipient ID Len must be > 0",
            ));
        }
        let recipient_id = cur
            .take(id_len, "ASYMMETRIC_WRAP Recipient ID truncated")?
            .to_vec();
        let wrapped_len = usize::from(cur.u16("ASYMMETRIC_WRAP wrapped key length truncated")?);
        if wrapped_len == 0 {
            return Err(SarCryptoError::InvalidLength(
                "ASYMMETRIC_WRAP Wrapped Key Len must be > 0",
            ));
        }
        let wrapped_key = cur
            .take(wrapped_len, "ASYMMETRIC_WRAP wrapped key truncated")?
            .to_vec();
        if wrapped_len != expected_wrapped_len {
            return Err(SarCryptoError::InvalidLength(
                "ASYMMETRIC_WRAP Wrapped Key Len does not match the Wrap Algo ID",
            ));
        }
        recipients.push(AsymmetricRecipient {
            recipient_id,
            wrapped_key,
        });
    }
    cur.finish("ASYMMETRIC_WRAP payload has trailing bytes")?;
    Ok(KmsParams::AsymmetricWrap(AsymmetricWrapParams {
        wrap_algo_id,
        recipients,
    }))
}
