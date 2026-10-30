// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR Crypto: hash, AEAD, KMS, and key-provider support for Milestone 5.

/// AAD (additional authenticated data) helpers.
pub mod aad;
/// AEAD encryption and decryption helpers.
pub mod aead;
/// Registry constants and algorithm validators.
pub mod algorithm;
/// Standard Entry-key derivation (HKDF-SHA256).
pub mod entry_key;
/// Error types.
pub mod error;
/// Hash functions and streaming hashing.
pub mod hash;
/// Key-management types and KDF helpers.
pub mod kms;
/// Context-owned KMS Master Secret retention.
pub mod master_secret_scope;
/// Key-provider abstraction and KMS Master Secret resolution.
pub mod provider;
/// Zeroizing secret containers.
pub mod secret;

pub use algorithm::{
    AEAD_KEY_SIZE, AEAD_TAG_SIZE, ARGON2_VARIANT_ID, ARGON2_VERSION_0X13, ENCR_AES256_GCM,
    ENCR_ASCON_AEAD128, ENCR_CHACHA20_POLY1305, ENCR_PLAINTEXT, ENCR_XCHACHA20_POLY, HASH_BLAKE3,
    HASH_SHA3_256, HASH_SHA256, KMS_ARGON2, KMS_ASYMMETRIC_WRAP, KMS_MASTER_SECRET_SIZE,
    KMS_PBKDF2, KMS_TLS_EXPORTER, PBKDF2_PRF_HMAC_SHA3_256, PBKDF2_PRF_HMAC_SHA256,
    PBKDF2_PRF_HMAC_SHA512, native_key_len, validate_encr_algo_id, validate_entry_encr_algo_id,
    validate_kms_mode_id,
};
pub use entry_key::{ENTRY_KEY_INFO_LABEL, derive_entry_key, hkdf_sha256_empty_salt};
pub use error::SarCryptoError;
pub use kms::limits::KdfLimits;
pub use kms::tls_exporter::{
    EXPORTER_LABEL_QUIC_AEAD, EXPORTER_LABEL_TCP_TLS_AEAD, TLS_EXPORTER_CONTEXT_VERSION_1,
    TLS_EXPORTER_KDF_DIRECT, TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER,
    TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT, TLS_EXPORTER_LABEL_V1, TLS_EXPORTER_TRANSPORT_QUIC,
    TLS_EXPORTER_TRANSPORT_TCP_TLS, TlsExporterContextV1, TlsExporterParams,
    encode_tls_exporter_context_v1, parse_tls_exporter_kms_payload,
    serialize_tls_exporter_kms_payload,
};
pub use kms::types::{
    Argon2Params, AsymmetricRecipient, AsymmetricWrapParams, KmsContext, KmsParams, Pbkdf2Params,
    parse_kms_payload, serialize_kms_payload,
};
pub use master_secret_scope::MasterSecretScope;
pub use provider::{KeyProvider, resolve_master_secret};
pub use secret::{SecretBytes, SecretString};
