#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR Crypto: hash, AEAD, KMS, and key-provider support for Milestone 5.

/// AAD (additional authenticated data) helpers.
pub mod aad;
/// AEAD encryption and decryption helpers.
pub mod aead;
/// Registry constants and algorithm validators.
pub mod algorithm;
/// Error types.
pub mod error;
/// Hash functions and streaming hashing.
pub mod hash;
/// Key-management types and KDF helpers.
pub mod kms;
/// Key-provider abstraction and CEK resolution.
pub mod provider;
/// Zeroizing secret containers.
pub mod secret;

pub use algorithm::{
    AEAD_KEY_SIZE, AEAD_TAG_SIZE, ARGON2_VARIANT_D, ARGON2_VARIANT_I, ARGON2_VARIANT_ID,
    ENCR_AES256_CBC, ENCR_AES256_GCM, ENCR_CHACHA20, ENCR_CHACHA20_POLY1305, ENCR_PLAINTEXT,
    ENCR_XCHACHA20_POLY, HASH_BLAKE3, HASH_SHA3_256, HASH_SHA256, KMS_ARGON2, KMS_ASYMMETRIC_WRAP,
    KMS_PBKDF2, PBKDF2_PRF_HMAC_SHA3_256, PBKDF2_PRF_HMAC_SHA256, PBKDF2_PRF_HMAC_SHA512,
    validate_encr_algo_id, validate_kms_mode_id,
};
pub use error::SarCryptoError;
pub use kms::types::{
    Argon2Params, AsymmetricRecipient, AsymmetricWrapParams, KmsContext, KmsParams, Pbkdf2Params,
    parse_kms_payload, serialize_kms_payload,
};
pub use provider::{KeyProvider, resolve_cek};
pub use secret::{SecretBytes, SecretString};
