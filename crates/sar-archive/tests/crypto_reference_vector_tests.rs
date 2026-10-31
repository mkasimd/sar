// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Deterministic cryptographic reference vectors (`SAR-M13b2-EVIDENCE-IMPLEMENTATION-001`).
//!
//! The vectors in `test-vectors/crypto-reference/crypto_reference_vectors.json`
//! are produced by `tools/generate_crypto_reference_vectors.py` from
//! third-party libraries and the specification field layout.  Agreement here
//! is independent-library agreement for the primitives and an independent
//! byte-layout derivation for the Global Header, LFH and AAD.  It is not
//! second-implementation SAR archive interoperability.

use sar_archive::verify_content_hash;
use sar_core::{
    GlobalFlags, GlobalHeader, KmsData, LocalFileHeader, ResourceLimits, SarError, SarStatus,
    parse_global_header, parse_lfh, sparse::SparseExtent, write_global_header, write_lfh,
};
use sar_crypto::aad::build_aead_aad;
use sar_crypto::aead::{aead_decrypt, aead_encrypt};
use sar_crypto::kms::{argon2, pbkdf2};
use sar_crypto::{
    ARGON2_VARIANT_ID, ARGON2_VERSION_0X13, Argon2Params, KdfLimits, PBKDF2_PRF_HMAC_SHA256,
    Pbkdf2Params, SarCryptoError, SecretBytes, derive_entry_key, parse_kms_payload,
};
use serde_json::Value;
use zeroize::Zeroizing;

const VECTORS: &str =
    include_str!("../../../test-vectors/crypto-reference/crypto_reference_vectors.json");

fn vectors() -> Value {
    serde_json::from_str::<Value>(VECTORS).expect("vector JSON")["vectors"].clone()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn field(v: &Value, name: &str) -> Vec<u8> {
    unhex(v[name].as_str().unwrap_or_else(|| panic!("missing {name}")))
}

fn num(v: &Value, name: &str) -> u64 {
    v[name].as_u64().unwrap_or_else(|| panic!("missing {name}"))
}

fn secret(bytes: Vec<u8>) -> SecretBytes {
    Zeroizing::new(bytes)
}

fn iv_array(v: &[u8]) -> [u8; 24] {
    v.try_into().expect("24-byte IV field")
}

#[test]
fn pbkdf2_hmac_sha256_mandatory_range_vectors() {
    let list = vectors()["pbkdf2_hmac_sha256"].clone();
    let cases = list.as_array().expect("array");
    assert!(cases.len() >= 5);
    for case in cases {
        let params = Pbkdf2Params {
            prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
            salt: field(case, "salt"),
            iterations: u32::try_from(num(case, "iterations")).expect("u32"),
            derived_key_length: 32,
        };
        let key = pbkdf2::derive_key(&params, &field(case, "password_hex"), &KdfLimits::default())
            .expect("derive");
        assert_eq!(key.as_slice(), field(case, "derived_key").as_slice());
    }
}

#[test]
fn argon2id_v13_mandatory_range_vectors() {
    let list = vectors()["argon2id_v13"].clone();
    let cases = list.as_array().expect("array");
    assert!(cases.len() >= 6);
    for case in cases {
        let params = Argon2Params {
            variant: ARGON2_VARIANT_ID,
            version: ARGON2_VERSION_0X13,
            salt: field(case, "salt"),
            memory_cost_kib: u32::try_from(num(case, "memory_kib")).expect("u32"),
            time_cost: u32::try_from(num(case, "time")).expect("u32"),
            parallelism: u16::try_from(num(case, "parallelism")).expect("u16"),
            derived_key_length: 32,
        };
        let key = argon2::derive_key(&params, &field(case, "password_hex"), &KdfLimits::default())
            .expect("derive");
        assert_eq!(key.as_slice(), field(case, "derived_key").as_slice());
    }
}

#[test]
fn hkdf_entry_key_vectors() {
    let list = vectors()["entry_key_hkdf_sha256"].clone();
    for case in list.as_array().expect("array") {
        let algo = u8::try_from(num(case, "encr_algo_id")).expect("u8");
        let key = derive_entry_key(
            &secret(field(case, "master_secret")),
            algo,
            &iv_array(&field(case, "iv_nonce_field")),
        )
        .expect("entry key");
        assert_eq!(key.as_slice(), field(case, "entry_key").as_slice());
    }
}

#[test]
fn aead_fixed_nonce_vectors_and_tamper_detection() {
    let list = vectors()["aead"].clone();
    for case in list.as_array().expect("array") {
        let algo = u8::try_from(num(case, "encr_algo_id")).expect("u8");
        let key = secret(field(case, "key"));
        let iv = iv_array(&field(case, "iv_nonce_field"));
        let aad = field(case, "aad");
        let pt = field(case, "plaintext_hex");
        let expected = field(case, "ciphertext_and_tag");

        assert_eq!(
            aead_encrypt(algo, &key, &iv, &aad, &pt).expect("enc"),
            expected
        );
        assert_eq!(
            aead_decrypt(algo, &key, &iv, &aad, &expected).expect("dec"),
            pt
        );

        let mut bad_tag = expected.clone();
        *bad_tag.last_mut().expect("tag") ^= 1;
        let err = aead_decrypt(algo, &key, &iv, &aad, &bad_tag).expect_err("tag");
        assert!(matches!(err, SarCryptoError::AuthFailed(_)));
    }
}

#[test]
fn archive_entry_vectors_cover_header_lfh_aad_and_payload() {
    let list = vectors()["archive_entries"].clone();
    let cases = list.as_array().expect("array");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let mode = u8::try_from(num(case, "kms_mode")).expect("u8");
        let algo = u8::try_from(num(case, "encr_algo_id")).expect("u8");
        let hash_algo = u8::try_from(num(case, "hash_algo_id")).expect("u8");
        let kms_payload = field(case, "kms_payload");
        let iv = iv_array(&field(case, "iv_nonce_field"));
        let plaintext = field(case, "plaintext_hex");
        let digest: [u8; 32] = field(case, "content_hash").try_into().expect("digest");

        // Global Header and LFH bytes written by SAR must equal the bytes laid
        // out independently from the specification.
        let flags = GlobalFlags::ENCRYPTED | GlobalFlags::DEDUPLICATION;
        let header = GlobalHeader {
            version: 1,
            flags,
            kms: Some(KmsData {
                mode_id: mode,
                payload: kms_payload.clone(),
            }),
        };
        let header_bytes = write_global_header(&header).expect("header");
        assert_eq!(header_bytes, field(case, "global_header"), "{id}: header");

        let mut lfh = LocalFileHeader::minimal_store(
            field(case, "entry_name_hex"),
            u64::try_from(plaintext.len() + 16).expect("len"),
        );
        lfh.uncompressed_size = u64::try_from(plaintext.len()).expect("len");
        lfh.entry_mode = sar_core::EntryMode::from_bits(sar_core::EntryMode::ENCRYPTED);
        lfh.encr_algo_id = Some(algo);
        lfh.iv_nonce = Some(iv);
        lfh.hash_algo_id = Some(hash_algo);
        lfh.content_hash = Some(digest);
        let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
        assert_eq!(lfh_bytes, field(case, "lfh"), "{id}: lfh");

        let limits = ResourceLimits::default();
        let (parsed_header, consumed) = parse_global_header(&header_bytes, &limits).expect("parse");
        assert_eq!(consumed, header_bytes.len());
        assert_eq!(parsed_header, header);
        let (parsed_lfh, _) = parse_lfh(&lfh_bytes, &flags, &limits).expect("parse lfh");
        assert_eq!(parsed_lfh.content_hash, Some(digest));

        // KMS Master Secret from the encoded KMS payload, then Entry key.
        let password = field(case, "password_hex");
        let master = match parse_kms_payload(mode, &kms_payload).expect("kms") {
            sar_crypto::KmsParams::Pbkdf2(p) => {
                pbkdf2::derive_key(&p, &password, &KdfLimits::default()).expect("pbkdf2")
            }
            sar_crypto::KmsParams::Argon2(p) => {
                argon2::derive_key(&p, &password, &KdfLimits::default()).expect("argon2")
            }
            _ => panic!("unexpected KMS mode"),
        };
        assert_eq!(
            master.as_slice(),
            field(case, "master_secret").as_slice(),
            "{id}"
        );
        let key = derive_entry_key(&master, algo, &iv).expect("entry key");
        assert_eq!(key.as_slice(), field(case, "entry_key").as_slice(), "{id}");

        // Complete Global Header || LFH is the AAD.
        let aad = build_aead_aad(&header_bytes, &lfh_bytes);
        assert_eq!(aad, field(case, "aad"), "{id}: aad");
        let expected = field(case, "ciphertext_and_tag");
        assert_eq!(
            aead_encrypt(algo, &key, &iv, &aad, &plaintext).expect("enc"),
            expected
        );
        assert_eq!(
            aead_decrypt(algo, &key, &iv, &aad, &expected).expect("dec"),
            plaintext
        );

        // Authentication failures: tampered ciphertext, any Global Header
        // byte (including the KMS extension) and any LFH byte.
        let mut bad_ct = expected.clone();
        bad_ct[0] ^= 0x80;
        assert!(matches!(
            aead_decrypt(algo, &key, &iv, &aad, &bad_ct),
            Err(SarCryptoError::AuthFailed(_))
        ));
        for position in [0, header_bytes.len() - 1, header_bytes.len(), aad.len() - 1] {
            let mut bad_aad = aad.clone();
            bad_aad[position] ^= 1;
            let err = aead_decrypt(algo, &key, &iv, &bad_aad, &expected).expect_err("aad");
            assert!(
                matches!(err, SarCryptoError::AuthFailed(_)),
                "{id}@{position}"
            );
            assert_eq!(SarError::from(err).status(), SarStatus::ErrAuthFailed);
        }

        // Final Content Hash over the decrypted logical Entry.
        verify_content_hash(Some(hash_algo), Some(digest), &plaintext, None).expect("hash");
        let mut wrong = digest;
        wrong[31] ^= 1;
        let err = verify_content_hash(Some(hash_algo), Some(wrong), &plaintext, None)
            .expect_err("mismatch");
        assert_eq!(err.status(), SarStatus::ErrHashMismatch);
    }
}

#[test]
fn content_hash_vectors_plain_fragmented_and_sparse() {
    let list = vectors()["content_hash"].clone();
    let (mut plain, mut fragmented, mut sparse) = (0, 0, 0);
    for case in list.as_array().expect("array") {
        let algo = u8::try_from(num(case, "hash_algo_id")).expect("u8");
        let digest: [u8; 32] = field(case, "digest").try_into().expect("digest");
        let mut wrong = digest;
        wrong[0] ^= 1;
        match case["kind"].as_str().expect("kind") {
            "plain" | "fragmented" => {
                let data = if case["kind"] == "plain" {
                    plain += 1;
                    field(case, "data")
                } else {
                    fragmented += 1;
                    case["fragments"]
                        .as_array()
                        .expect("fragments")
                        .iter()
                        .flat_map(|f| unhex(f.as_str().expect("hex")))
                        .collect()
                };
                verify_content_hash(Some(algo), Some(digest), &data, None).expect("hash");
                assert!(matches!(
                    verify_content_hash(Some(algo), Some(wrong), &data, None),
                    Err(SarError::HashMismatch(_))
                ));
            }
            _ => {
                sparse += 1;
                let extents: Vec<SparseExtent> = case["extents"]
                    .as_array()
                    .expect("extents")
                    .iter()
                    .map(|e| SparseExtent {
                        offset: num(e, "offset"),
                        length: u64::try_from(field(e, "data").len()).expect("len"),
                    })
                    .collect();
                let gathered = field(case, "gathered");
                let logical = num(case, "logical_size");
                verify_content_hash(
                    Some(algo),
                    Some(digest),
                    &gathered,
                    Some((&extents, logical)),
                )
                .expect("sparse hash");
                // Holes are part of the hashed logical content: hashing only
                // the gathered bytes must not match.
                assert!(matches!(
                    verify_content_hash(Some(algo), Some(digest), &gathered, None),
                    Err(SarError::HashMismatch(_))
                ));
            }
        }
    }
    assert_eq!((plain, fragmented), (2, 2));
    assert_eq!(sparse, 4);
}
