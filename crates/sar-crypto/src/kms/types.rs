#![allow(clippy::module_name_repetitions)]

use crate::algorithm::{
    ARGON2_VARIANT_D, ARGON2_VARIANT_I, ARGON2_VARIANT_ID, KMS_ARGON2, KMS_ASYMMETRIC_WRAP,
    KMS_PBKDF2, PBKDF2_PRF_HMAC_SHA3_256, PBKDF2_PRF_HMAC_SHA256, PBKDF2_PRF_HMAC_SHA512,
};
use crate::error::SarCryptoError;

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
    /// Wrapped CEK bytes.
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
}

/// Key-resolution context passed to `KeyProvider` implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsContext {
    /// KMS mode identifier.
    pub mode_id: u8,
    /// Parsed mode-specific parameters.
    pub params: KmsParams,
}

/// Serialize `params` into the on-wire KMS payload bytes.
pub fn serialize_kms_payload(params: &KmsParams) -> Vec<u8> {
    match params {
        KmsParams::Pbkdf2(p) => {
            let mut out = Vec::new();
            out.push(p.prf_algo_id);
            out.push(p.salt.len() as u8);
            out.extend_from_slice(&p.salt);
            out.extend_from_slice(&p.iterations.to_le_bytes());
            out.extend_from_slice(&p.derived_key_length.to_le_bytes());
            out
        }
        KmsParams::Argon2(p) => {
            let mut out = Vec::new();
            out.push(p.variant);
            out.push(p.version);
            out.push(p.salt.len() as u8);
            out.extend_from_slice(&p.salt);
            out.extend_from_slice(&p.memory_cost_kib.to_le_bytes());
            out.extend_from_slice(&p.time_cost.to_le_bytes());
            out.extend_from_slice(&p.parallelism.to_le_bytes());
            out.extend_from_slice(&p.derived_key_length.to_le_bytes());
            out
        }
        KmsParams::AsymmetricWrap(p) => {
            let mut out = Vec::new();
            out.push(p.wrap_algo_id);
            out.push(p.recipients.len() as u8);
            for recipient in &p.recipients {
                out.push(recipient.recipient_id.len() as u8);
                out.extend_from_slice(&recipient.recipient_id);
                let wrapped_key_len = recipient.wrapped_key.len() as u16;
                out.extend_from_slice(&wrapped_key_len.to_le_bytes());
                out.extend_from_slice(&recipient.wrapped_key);
            }
            out
        }
    }
}

/// Parse a KMS payload using its `mode_id`.
pub fn parse_kms_payload(mode_id: u8, payload: &[u8]) -> Result<KmsParams, SarCryptoError> {
    match mode_id {
        KMS_PBKDF2 => parse_pbkdf2(payload),
        KMS_ARGON2 => parse_argon2(payload),
        KMS_ASYMMETRIC_WRAP => parse_asymmetric_wrap(payload),
        0xF0..=0xFF => Err(SarCryptoError::Unsupported("custom KMS mode")),
        _ => Err(SarCryptoError::ReservedValue("unknown KMS mode ID")),
    }
}

fn parse_pbkdf2(payload: &[u8]) -> Result<KmsParams, SarCryptoError> {
    if payload.len() < 2 {
        return Err(SarCryptoError::Malformed("PBKDF2 payload too short"));
    }
    let prf_algo_id = payload[0];
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
    let salt_len = usize::from(payload[1]);
    if salt_len < 16 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 salt length must be >= 16",
        ));
    }
    let salt_end = 2 + salt_len;
    if payload.len() < salt_end + 6 {
        return Err(SarCryptoError::Malformed("PBKDF2 payload truncated"));
    }
    let salt = payload[2..salt_end].to_vec();
    let iterations = u32::from_le_bytes([
        payload[salt_end],
        payload[salt_end + 1],
        payload[salt_end + 2],
        payload[salt_end + 3],
    ]);
    if iterations < 100_000 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 iterations must be >= 100,000",
        ));
    }
    if iterations > 10_000_000 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 iterations exceeds DoS limit",
        ));
    }
    let derived_key_length = u16::from_le_bytes([payload[salt_end + 4], payload[salt_end + 5]]);
    if derived_key_length != 32 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 derived_key_length must be 32",
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
    if payload.len() < 3 {
        return Err(SarCryptoError::Malformed("Argon2 payload too short"));
    }
    let variant = payload[0];
    match variant {
        ARGON2_VARIANT_D | ARGON2_VARIANT_I => {
            return Err(SarCryptoError::Unsupported(
                "only Argon2id (0x03) is supported",
            ));
        }
        ARGON2_VARIANT_ID => {}
        _ => return Err(SarCryptoError::ReservedValue("unknown Argon2 variant")),
    }
    let version = payload[1];
    if version == 0 {
        return Err(SarCryptoError::Malformed("Argon2 version must be non-zero"));
    }
    let salt_len = usize::from(payload[2]);
    if salt_len < 16 {
        return Err(SarCryptoError::Malformed(
            "Argon2 salt length must be >= 16",
        ));
    }
    let salt_end = 3 + salt_len;
    if payload.len() < salt_end + 12 {
        return Err(SarCryptoError::Malformed("Argon2 payload truncated"));
    }
    let salt = payload[3..salt_end].to_vec();
    let memory_cost_kib = u32::from_le_bytes([
        payload[salt_end],
        payload[salt_end + 1],
        payload[salt_end + 2],
        payload[salt_end + 3],
    ]);
    if memory_cost_kib < 65_536 {
        return Err(SarCryptoError::Malformed(
            "Argon2 memory_cost_kib must be >= 65536 (64 MiB)",
        ));
    }
    if memory_cost_kib > 2_097_152 {
        return Err(SarCryptoError::Malformed(
            "Argon2 memory_cost_kib exceeds DoS limit (2 GiB)",
        ));
    }
    let time_cost = u32::from_le_bytes([
        payload[salt_end + 4],
        payload[salt_end + 5],
        payload[salt_end + 6],
        payload[salt_end + 7],
    ]);
    if time_cost < 1 {
        return Err(SarCryptoError::Malformed("Argon2 time_cost must be >= 1"));
    }
    if time_cost > 100 {
        return Err(SarCryptoError::Malformed(
            "Argon2 time_cost exceeds DoS limit",
        ));
    }
    let parallelism = u16::from_le_bytes([payload[salt_end + 8], payload[salt_end + 9]]);
    if parallelism < 1 {
        return Err(SarCryptoError::Malformed("Argon2 parallelism must be >= 1"));
    }
    if parallelism > 256 {
        return Err(SarCryptoError::Malformed(
            "Argon2 parallelism exceeds limit",
        ));
    }
    let derived_key_length = u16::from_le_bytes([payload[salt_end + 10], payload[salt_end + 11]]);
    if derived_key_length != 32 {
        return Err(SarCryptoError::Malformed(
            "Argon2 derived_key_length must be 32",
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
    if payload.len() < 2 {
        return Err(SarCryptoError::Malformed(
            "ASYMMETRIC_WRAP payload too short",
        ));
    }
    let wrap_algo_id = payload[0];
    let recipient_count = usize::from(payload[1]);
    if recipient_count < 1 {
        return Err(SarCryptoError::Malformed(
            "ASYMMETRIC_WRAP must have at least 1 recipient",
        ));
    }
    let mut pos = 2;
    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        if pos >= payload.len() {
            return Err(SarCryptoError::Malformed(
                "ASYMMETRIC_WRAP recipient data truncated",
            ));
        }
        let recipient_id_len = usize::from(payload[pos]);
        pos += 1;
        if pos + recipient_id_len > payload.len() {
            return Err(SarCryptoError::Malformed(
                "ASYMMETRIC_WRAP recipient_id truncated",
            ));
        }
        let recipient_id = payload[pos..pos + recipient_id_len].to_vec();
        pos += recipient_id_len;
        if pos + 2 > payload.len() {
            return Err(SarCryptoError::Malformed(
                "ASYMMETRIC_WRAP wrapped_key_len truncated",
            ));
        }
        let wrapped_key_len = usize::from(u16::from_le_bytes([payload[pos], payload[pos + 1]]));
        pos += 2;
        if wrapped_key_len == 0 {
            return Err(SarCryptoError::Malformed(
                "ASYMMETRIC_WRAP wrapped_key must not be empty (would expose plaintext CEK)",
            ));
        }
        if pos + wrapped_key_len > payload.len() {
            return Err(SarCryptoError::Malformed(
                "ASYMMETRIC_WRAP wrapped_key truncated",
            ));
        }
        let wrapped_key = payload[pos..pos + wrapped_key_len].to_vec();
        pos += wrapped_key_len;
        recipients.push(AsymmetricRecipient {
            recipient_id,
            wrapped_key,
        });
    }
    Ok(KmsParams::AsymmetricWrap(AsymmetricWrapParams {
        wrap_algo_id,
        recipients,
    }))
}
