// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use sar_crypto::kms::asymmetric::unwrap_cek;
use sar_crypto::kms::types::{
    Argon2Params, AsymmetricRecipient, AsymmetricWrapParams, KmsParams, Pbkdf2Params,
    parse_kms_payload, serialize_kms_payload,
};
use sar_crypto::{
    ARGON2_VARIANT_ID, KMS_ARGON2, KMS_ASYMMETRIC_WRAP, KMS_PBKDF2, KMS_TLS_EXPORTER,
    PBKDF2_PRF_HMAC_SHA256, SarCryptoError, validate_kms_mode_id,
};

#[test]
fn pbkdf2_parse_serialize_round_trip() {
    let params = KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: vec![0xA5; 32],
        iterations: 100_000,
        derived_key_length: 32,
    });
    let encoded = serialize_kms_payload(&params);
    let parsed = parse_kms_payload(KMS_PBKDF2, &encoded).expect("parse");
    assert_eq!(parsed, params);
}

#[test]
fn pbkdf2_validation_errors() {
    let too_short = [PBKDF2_PRF_HMAC_SHA256, 0x0F];
    let err = parse_kms_payload(KMS_PBKDF2, &too_short).expect_err("salt too short");
    assert!(matches!(err, SarCryptoError::Malformed(_)));

    let mut low_iters = vec![PBKDF2_PRF_HMAC_SHA256, 16];
    low_iters.extend_from_slice(&[0u8; 16]);
    low_iters.extend_from_slice(&99_999u32.to_le_bytes());
    low_iters.extend_from_slice(&32u16.to_le_bytes());
    let err = parse_kms_payload(KMS_PBKDF2, &low_iters).expect_err("low iterations");
    assert!(matches!(err, SarCryptoError::Malformed(_)));
}

#[test]
fn argon2_parse_serialize_round_trip() {
    let params = KmsParams::Argon2(Argon2Params {
        variant: ARGON2_VARIANT_ID,
        version: 0x13,
        salt: vec![0x5A; 16],
        memory_cost_kib: 65_536,
        time_cost: 3,
        parallelism: 4,
        derived_key_length: 32,
    });
    let encoded = serialize_kms_payload(&params);
    let parsed = parse_kms_payload(KMS_ARGON2, &encoded).expect("parse");
    assert_eq!(parsed, params);
}

#[test]
fn argon2_validation_errors() {
    let mut low_memory = vec![ARGON2_VARIANT_ID, 0x13, 16];
    low_memory.extend_from_slice(&[0u8; 16]);
    low_memory.extend_from_slice(&32_768u32.to_le_bytes());
    low_memory.extend_from_slice(&1u32.to_le_bytes());
    low_memory.extend_from_slice(&1u16.to_le_bytes());
    low_memory.extend_from_slice(&32u16.to_le_bytes());
    let err = parse_kms_payload(KMS_ARGON2, &low_memory).expect_err("low memory");
    assert!(matches!(err, SarCryptoError::Malformed(_)));
}

#[test]
fn asymmetric_wrap_round_trip_and_unwrap() {
    let params = KmsParams::AsymmetricWrap(AsymmetricWrapParams {
        wrap_algo_id: 0x01,
        recipients: vec![
            AsymmetricRecipient {
                recipient_id: b"alice".to_vec(),
                wrapped_key: vec![1, 2, 3],
            },
            AsymmetricRecipient {
                recipient_id: b"bob".to_vec(),
                wrapped_key: vec![4, 5, 6],
            },
        ],
    });
    let encoded = serialize_kms_payload(&params);
    let parsed = parse_kms_payload(KMS_ASYMMETRIC_WRAP, &encoded).expect("parse");
    assert_eq!(parsed, params);

    let KmsParams::AsymmetricWrap(parsed_params) = parsed else {
        panic!("expected asymmetric params");
    };
    let cek = unwrap_cek(&parsed_params, b"bob", |algo, recipient_id, wrapped_key| {
        assert_eq!(algo, 0x01);
        assert_eq!(recipient_id, b"bob");
        assert_eq!(wrapped_key, &[4, 5, 6]);
        Ok(Some(Zeroizing::new(vec![9u8; 32])))
    })
    .expect("unwrap");
    assert_eq!(&*cek, &vec![9u8; 32]);
}

#[test]
fn asymmetric_wrap_errors() {
    let params = AsymmetricWrapParams {
        wrap_algo_id: 0x01,
        recipients: vec![AsymmetricRecipient {
            recipient_id: b"alice".to_vec(),
            wrapped_key: vec![1, 2, 3],
        }],
    };
    let err = unwrap_cek(&params, b"bob", |_algo, _recipient, _wrapped| Ok(None))
        .expect_err("missing recipient");
    assert!(matches!(err, SarCryptoError::KeyMissing(_)));
}

// ── KMS_TLS_EXPORTER (0x04) recognition tests ─────────────────────────────────

#[test]
fn tls_exporter_mode_id_constant_is_0x04() {
    assert_eq!(KMS_TLS_EXPORTER, 0x04);
}

#[test]
fn tls_exporter_parse_returns_unsupported_not_reserved() {
    // 0x04 must be recognized as a defined-but-unsupported mode, not as an
    // unknown/reserved value.  SAR_ERR_UNSUPPORTED is the correct fail-closed
    // error for a plaintext TCP context without TLS exporter material.
    let err = parse_kms_payload(KMS_TLS_EXPORTER, &[]).expect_err("TLS_EXPORTER unsupported");
    assert!(
        matches!(err, SarCryptoError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

#[test]
fn tls_exporter_validate_returns_unsupported_not_reserved() {
    let err = validate_kms_mode_id(KMS_TLS_EXPORTER).expect_err("TLS_EXPORTER unsupported");
    assert!(
        matches!(err, SarCryptoError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

#[test]
fn unknown_kms_mode_still_returns_reserved_value() {
    // Modes 0x05–0xEF (excluding 0xF0–0xFF) remain reserved.
    let err = parse_kms_payload(0x05, &[]).expect_err("reserved mode");
    assert!(
        matches!(err, SarCryptoError::ReservedValue(_)),
        "expected ReservedValue for 0x05, got {err:?}"
    );
    let err = validate_kms_mode_id(0xEF).expect_err("reserved mode");
    assert!(
        matches!(err, SarCryptoError::ReservedValue(_)),
        "expected ReservedValue for 0xEF, got {err:?}"
    );
}
