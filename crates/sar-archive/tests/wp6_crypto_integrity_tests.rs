// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! WP-6 (`SAR-M13b-WP6-IMPLEMENTATION-001`): HKDF Entry keys, complete
//! Global Header AAD, KDF resource limits and final Content Hash handling
//! through the real writer/reader.

use std::io::Cursor;

use sar_archive::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, CompressionSettings,
    EncryptionSettings, EntryInput, SparseWriteOptions,
};
use sar_core::{ResourceLimits, SarError, sparse::SparseExtent};
use sar_crypto::{
    ENCR_AES256_GCM, KeyProvider, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params,
    SarCryptoError, SecretBytes, SecretString,
};

struct Pw(SecretString);

impl KeyProvider for Pw {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(self.0.clone()))
    }
    fn unwrap_key(
        &self,
        _ctx: &KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
    fn external_key(&self, _ctx: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

fn provider(password: &str) -> Box<dyn KeyProvider> {
    Box::new(Pw(SecretString::new(password.to_string())))
}

fn encryption(iterations: u32) -> EncryptionSettings {
    EncryptionSettings {
        algo_id: ENCR_AES256_GCM,
        kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
            prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
            salt: vec![0x42; 16],
            iterations,
            derived_key_length: 32,
        }),
    }
}

fn write_encrypted(content_hash: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            encryption: Some(encryption(100_000)),
            with_content_hash: content_hash,
            ..Default::default()
        },
        CompressionSettings::store(),
        Some(provider("pw")),
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.bin", b"secret payload".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");
    out
}

fn read_all(
    bytes: &[u8],
    limits: ResourceLimits,
    password: &str,
) -> Result<Vec<sar_archive::LogicalFile>, SarError> {
    ArchiveReader::with_options(
        Cursor::new(bytes.to_vec()),
        ArchiveReaderOptions {
            limits,
            ..Default::default()
        },
    )?
    .with_key_provider(provider(password))
    .read_all_logical_files(false)
}

#[test]
fn encrypted_round_trip_with_content_hash() {
    let bytes = write_encrypted(true);
    let files = read_all(&bytes, ResourceLimits::default(), "pw").expect("round trip");
    assert_eq!(files[0].data, b"secret payload");
}

#[test]
fn wrong_password_is_auth_failed() {
    let bytes = write_encrypted(false);
    let err = read_all(&bytes, ResourceLimits::default(), "other").expect_err("wrong key");
    assert!(matches!(err, SarError::AuthFailed(_)));
}

#[test]
fn every_single_bit_flip_in_headers_is_rejected() {
    // The Global Header (including KMS Extension) and the LFH (including the
    // Hash Algo ID and Content Hash) are all bound by the AEAD AAD; no
    // single-bit modification of those bytes may be accepted.
    let bytes = write_encrypted(true);
    let (_, global_len) =
        sar_core::format::parse_global_header(&bytes, &ResourceLimits::default()).expect("header");
    let header_end = bytes.len().min(global_len + 160);
    for pos in 0..header_end {
        // Skip the Magic/version prefix handled by structural parse errors;
        // those are still rejected, but with a non-crypto status.
        let mut tampered = bytes.clone();
        tampered[pos] ^= 0x01;
        let result = read_all(&tampered, ResourceLimits::default(), "pw");
        if let Ok(files) = result {
            // Only bytes outside AAD (payload-size neutral fields) could pass;
            // none exist in this layout, so fail loudly if one does.
            panic!("bit flip at {pos} accepted: {:?}", files[0].data);
        }
    }
}

#[test]
fn content_hash_mismatch_is_reported_for_unfragmented_entry() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            with_content_hash: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let mut input = EntryInput::file("a.bin", b"hello".to_vec());
    input.content_hash = Some([0u8; 32]);
    writer.add_entry(input).expect("entry");
    writer.finish().expect("finish");
    // An explicit all-zero digest is an ordinary (mismatching) digest.
    let err = read_all(&out, ResourceLimits::default(), "").expect_err("mismatch");
    assert!(matches!(err, SarError::HashMismatch(_)));
}

#[test]
fn sparse_content_hash_covers_holes() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            sparse: true,
            with_content_hash: true,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .write_sparse_entry(
            "s.bin",
            b"DATA",
            SparseWriteOptions {
                logical_size: 20_000,
                extents: vec![SparseExtent {
                    offset: 10_000,
                    length: 4,
                }],
            },
        )
        .expect("sparse");
    writer.finish().expect("finish");
    let files = read_all(&out, ResourceLimits::default(), "").expect("verifies");
    assert_eq!(files[0].data.len(), 20_000);
    assert_eq!(&files[0].data[10_000..10_004], b"DATA");
}

#[test]
fn kdf_limits_are_enforced_before_derivation() {
    let bytes = write_encrypted(false);
    let limits = ResourceLimits {
        max_pbkdf2_iterations: 99_999,
        ..ResourceLimits::default()
    };
    let err = read_all(&bytes, limits, "pw").expect_err("limit");
    assert!(matches!(err, SarError::LimitExceeded(_)));

    let limits = ResourceLimits {
        max_kdf_salt_bytes: 8,
        ..ResourceLimits::default()
    };
    let err = read_all(&bytes, limits, "pw").expect_err("salt limit");
    assert!(matches!(err, SarError::LimitExceeded(_)));

    read_all(&bytes, ResourceLimits::unlimited(), "pw").expect("unlimited");
}

#[test]
fn writer_limits_reject_excessive_kdf_work() {
    let limits = ResourceLimits {
        max_pbkdf2_iterations: 99_999,
        ..ResourceLimits::default()
    };
    let mut out = Vec::new();
    let result = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            encryption: Some(encryption(100_000)),
            limits,
            ..Default::default()
        },
        CompressionSettings::store(),
        Some(provider("pw")),
    )
    .and_then(|mut w| {
        w.add_entry(EntryInput::file("a", b"x".to_vec()))?;
        w.finish()
    });
    assert!(matches!(result, Err(SarError::LimitExceeded(_))));
}

fn write_with_explicit_hash(payload: &[u8], hash: Option<[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            with_content_hash: true,
            ..Default::default()
        },
    )
    .expect("writer");
    let mut input = EntryInput::file("a.bin", payload.to_vec());
    input.hash_algo_id = Some(sar_crypto::HASH_SHA256);
    input.content_hash = hash;
    writer.add_entry(input).expect("entry");
    writer.finish().expect("finish");
    out
}

fn stored_content_hash(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes.to_vec())).expect("reader");
    reader.read_global_header().expect("header");
    reader
        .next_entry()
        .expect("entry")
        .expect("one entry")
        .metadata
        .content_hash
}

#[test]
fn explicit_content_hash_is_written_verbatim_and_verified() {
    let correct = sar_crypto::hash::sha256(b"hello");
    // Omitted: generated by the writer.
    let generated = write_with_explicit_hash(b"hello", None);
    assert_eq!(stored_content_hash(&generated), Some(correct));
    // Supplied correct value: written unchanged and accepted by the reader.
    let supplied = write_with_explicit_hash(b"hello", Some(correct));
    assert_eq!(stored_content_hash(&supplied), Some(correct));
    read_all(&supplied, ResourceLimits::default(), "").expect("verifies");
    // Supplied non-zero wrong value: written unchanged, rejected on read.
    let wrong = [0xA5u8; 32];
    let bad = write_with_explicit_hash(b"hello", Some(wrong));
    assert_eq!(stored_content_hash(&bad), Some(wrong));
    let err = read_all(&bad, ResourceLimits::default(), "").expect_err("mismatch");
    assert!(matches!(err, SarError::HashMismatch(_)));
    // An all-zero value is not treated as absent.
    let zero = write_with_explicit_hash(b"hello", Some([0u8; 32]));
    assert_eq!(stored_content_hash(&zero), Some([0u8; 32]));
}
