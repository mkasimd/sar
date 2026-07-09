#![allow(clippy::module_name_repetitions)]

use crate::error::SarCryptoError;

/// SHA-256 DATA_HASH algorithm identifier.
pub const HASH_SHA256: u8 = 0x30;
/// BLAKE3 DATA_HASH algorithm identifier.
pub const HASH_BLAKE3: u8 = 0x31;
/// SHA3-256 DATA_HASH algorithm identifier (assigned, unsupported).
pub const HASH_SHA3_256: u8 = 0x32;

/// Plaintext entry algorithm identifier.
pub const ENCR_PLAINTEXT: u8 = 0x00;
/// AES-256-GCM entry encryption identifier.
pub const ENCR_AES256_GCM: u8 = 0x01;
/// ChaCha20 identifier (assigned, unsupported).
pub const ENCR_CHACHA20: u8 = 0x02;
/// AES-256-CBC identifier (assigned, unsupported).
pub const ENCR_AES256_CBC: u8 = 0x03;
/// XChaCha20-Poly1305 entry encryption identifier.
pub const ENCR_XCHACHA20_POLY: u8 = 0x04;
/// ChaCha20-Poly1305 identifier (assigned, unsupported).
pub const ENCR_CHACHA20_POLY1305: u8 = 0x05;

/// PBKDF2 KMS mode identifier.
pub const KMS_PBKDF2: u8 = 0x01;
/// Argon2 KMS mode identifier.
pub const KMS_ARGON2: u8 = 0x02;
/// Asymmetric wrap KMS mode identifier.
pub const KMS_ASYMMETRIC_WRAP: u8 = 0x03;
/// TLS-exporter key derivation KMS mode identifier (spec-defined; unsupported on plaintext TCP).
pub const KMS_TLS_EXPORTER: u8 = 0x04;

/// PBKDF2 HMAC-SHA256 PRF identifier.
pub const PBKDF2_PRF_HMAC_SHA256: u8 = 0x01;
/// PBKDF2 HMAC-SHA512 PRF identifier (assigned, unsupported).
pub const PBKDF2_PRF_HMAC_SHA512: u8 = 0x02;
/// PBKDF2 HMAC-SHA3-256 PRF identifier (assigned, unsupported).
pub const PBKDF2_PRF_HMAC_SHA3_256: u8 = 0x03;

/// Argon2d variant identifier (assigned, unsupported).
pub const ARGON2_VARIANT_D: u8 = 0x01;
/// Argon2i variant identifier (assigned, unsupported).
pub const ARGON2_VARIANT_I: u8 = 0x02;
/// Argon2id variant identifier.
pub const ARGON2_VARIANT_ID: u8 = 0x03;

/// AEAD tag size for supported algorithms.
pub const AEAD_TAG_SIZE: usize = 16;
/// AEAD key size for supported algorithms.
pub const AEAD_KEY_SIZE: usize = 32;

/// Validate an encryption algorithm identifier.
pub fn validate_encr_algo_id(id: u8) -> Result<(), SarCryptoError> {
    match id {
        ENCR_PLAINTEXT => Ok(()),
        ENCR_AES256_GCM => Ok(()),
        ENCR_CHACHA20 => Err(SarCryptoError::Unsupported("ENCR_CHACHA20 not implemented")),
        ENCR_AES256_CBC => Err(SarCryptoError::Unsupported(
            "ENCR_AES256_CBC not implemented",
        )),
        ENCR_XCHACHA20_POLY => Ok(()),
        ENCR_CHACHA20_POLY1305 => Err(SarCryptoError::Unsupported(
            "ENCR_CHACHA20_POLY1305 not implemented",
        )),
        0x06..=0x1F => Err(SarCryptoError::ReservedValue(
            "reserved encryption algorithm ID",
        )),
        0x20..=0x3F => Err(SarCryptoError::ReservedValue(
            "reserved encryption algorithm range 0x20-0x3F",
        )),
        0x40..=0x5F => Err(SarCryptoError::ReservedValue(
            "reserved encryption algorithm range 0x40-0x5F",
        )),
        0x60..=0xEF => Err(SarCryptoError::ReservedValue(
            "reserved encryption algorithm range 0x60-0xEF",
        )),
        0xF0..=0xFF => Err(SarCryptoError::Unsupported(
            "custom encryption algorithm range 0xF0-0xFF",
        )),
    }
}

/// Validate a KMS mode identifier.
pub fn validate_kms_mode_id(id: u8) -> Result<(), SarCryptoError> {
    match id {
        KMS_PBKDF2 | KMS_ARGON2 | KMS_ASYMMETRIC_WRAP => Ok(()),
        KMS_TLS_EXPORTER => Err(SarCryptoError::Unsupported(
            "KMS_TLS_EXPORTER requires an authenticated TLS session; unsupported on plaintext TCP",
        )),
        0xF0..=0xFF => Err(SarCryptoError::Unsupported("custom KMS mode")),
        _ => Err(SarCryptoError::ReservedValue("unknown KMS mode ID")),
    }
}
