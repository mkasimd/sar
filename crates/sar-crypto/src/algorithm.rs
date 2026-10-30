// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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
/// XChaCha20-Poly1305 entry encryption identifier.
pub const ENCR_XCHACHA20_POLY: u8 = 0x04;
/// ChaCha20-Poly1305 identifier (assigned, unsupported).
pub const ENCR_CHACHA20_POLY1305: u8 = 0x05;
/// ASCON-AEAD128 identifier (assigned, unsupported).
pub const ENCR_ASCON_AEAD128: u8 = 0x06;

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

/// Argon2id variant identifier (the only assigned variant; all others are reserved).
pub const ARGON2_VARIANT_ID: u8 = 0x03;
/// Argon2 version 0x13 (the only supported version).
pub const ARGON2_VERSION_0X13: u8 = 0x13;

/// Size in bytes of a KMS Master Secret.
pub const KMS_MASTER_SECRET_SIZE: usize = 32;

/// AEAD tag size for supported algorithms.
pub const AEAD_TAG_SIZE: usize = 16;
/// AEAD key size for supported algorithms.
pub const AEAD_KEY_SIZE: usize = 32;

/// Validate an encryption algorithm identifier against the Section 8.2 registry.
///
/// `0x00`, `0x01` and `0x04` are implemented.  `0x05` and `0x06` are assigned
/// but not implemented (`Unsupported`).  `0xF0..=0xFF` is CUSTOM
/// (`Unsupported`).  Every other value, including `0x02` and `0x03`, is
/// reserved (`ReservedValue`).
pub fn validate_encr_algo_id(id: u8) -> Result<(), SarCryptoError> {
    match id {
        ENCR_PLAINTEXT | ENCR_AES256_GCM | ENCR_XCHACHA20_POLY => Ok(()),
        ENCR_CHACHA20_POLY1305 => Err(SarCryptoError::Unsupported(
            "ENCR_CHACHA20_POLY1305 not implemented",
        )),
        ENCR_ASCON_AEAD128 => Err(SarCryptoError::Unsupported(
            "ENCR_ASCON_AEAD128 not implemented",
        )),
        0xF0..=0xFF => Err(SarCryptoError::Unsupported(
            "custom encryption algorithm range 0xF0-0xFF",
        )),
        _ => Err(SarCryptoError::ReservedValue(
            "reserved encryption algorithm ID",
        )),
    }
}

/// Validates the `Encr Algo ID` of an Entry whose `IS_ENCRYPTED` flag is set.
///
/// Identical to [`validate_encr_algo_id`] except that `PLAINTEXT` is a
/// [`SarCryptoError::FlagConflict`]: an encrypted Entry cannot select the
/// plaintext algorithm.
pub fn validate_entry_encr_algo_id(id: u8) -> Result<(), SarCryptoError> {
    if id == ENCR_PLAINTEXT {
        return Err(SarCryptoError::FlagConflict(
            "IS_ENCRYPTED conflicts with PLAINTEXT Encr Algo ID",
        ));
    }
    validate_encr_algo_id(id)
}

/// Returns the native AEAD key length for an assigned encryption algorithm.
///
/// # Errors
///
/// Returns the registry status of `id` when it is not an implemented AEAD
/// algorithm (`PLAINTEXT` is reported as `FlagConflict` because it has no key).
pub fn native_key_len(id: u8) -> Result<usize, SarCryptoError> {
    match id {
        ENCR_AES256_GCM | ENCR_XCHACHA20_POLY => Ok(AEAD_KEY_SIZE),
        ENCR_PLAINTEXT => Err(SarCryptoError::FlagConflict(
            "PLAINTEXT has no encryption key",
        )),
        _ => validate_encr_algo_id(id).and(Err(SarCryptoError::Unsupported(
            "unsupported AEAD algorithm",
        ))),
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
