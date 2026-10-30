// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use sar_crypto::kms::asymmetric::unwrap_cek;
use sar_crypto::kms::pbkdf2::derive_key;
use sar_crypto::kms::types::{
    Argon2Params, AsymmetricRecipient, AsymmetricWrapParams, KmsParams, Pbkdf2Params,
    parse_kms_payload, serialize_kms_payload,
};
use sar_crypto::{
    ARGON2_VARIANT_ID, KMS_ARGON2, KMS_ASYMMETRIC_WRAP, KMS_PBKDF2, KMS_TLS_EXPORTER, KdfLimits,
    PBKDF2_PRF_HMAC_SHA256, SarCryptoError, validate_kms_mode_id,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pbkdf2_payload(iterations: u32, dkl: u16, salt: &[u8]) -> Vec<u8> {
    let mut out = vec![PBKDF2_PRF_HMAC_SHA256];
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&dkl.to_le_bytes());
    out.push(u8::try_from(salt.len()).expect("salt len"));
    out.extend_from_slice(salt);
    out
}

#[allow(clippy::too_many_arguments)]
fn argon2_payload(
    variant: u8,
    version: u8,
    mem: u32,
    time: u32,
    par: u16,
    dkl: u16,
    salt: &[u8],
) -> Vec<u8> {
    let mut out = vec![variant, version];
    out.extend_from_slice(&mem.to_le_bytes());
    out.extend_from_slice(&time.to_le_bytes());
    out.extend_from_slice(&par.to_le_bytes());
    out.extend_from_slice(&dkl.to_le_bytes());
    out.push(u8::try_from(salt.len()).expect("salt len"));
    out.extend_from_slice(salt);
    out
}

#[test]
fn pbkdf2_wire_layout_matches_section_5_3_3() {
    let params = KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: vec![0xA5; 16],
        iterations: 600_000,
        derived_key_length: 32,
    });
    let encoded = serialize_kms_payload(&params).expect("serialize");
    assert_eq!(encoded, pbkdf2_payload(600_000, 32, &[0xA5; 16]));
    assert_eq!(
        parse_kms_payload(KMS_PBKDF2, &encoded).expect("parse"),
        params
    );
}

#[test]
fn pbkdf2_validation_errors() {
    let err =
        parse_kms_payload(KMS_PBKDF2, &[PBKDF2_PRF_HMAC_SHA256, 0x0F]).expect_err("truncated");
    assert!(matches!(err, SarCryptoError::Malformed(_)));

    let err = parse_kms_payload(KMS_PBKDF2, &pbkdf2_payload(99_999, 32, &[0; 16]))
        .expect_err("low iterations");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));

    let err = parse_kms_payload(KMS_PBKDF2, &pbkdf2_payload(100_000, 32, &[0; 15]))
        .expect_err("short salt");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));

    let err = parse_kms_payload(KMS_PBKDF2, &pbkdf2_payload(100_000, 16, &[0; 16]))
        .expect_err("wrong derived key length");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));

    let mut trailing = pbkdf2_payload(100_000, 32, &[0; 16]);
    trailing.push(0);
    let err = parse_kms_payload(KMS_PBKDF2, &trailing).expect_err("trailing byte");
    assert!(matches!(err, SarCryptoError::Malformed(_)));

    let mut bad_prf = pbkdf2_payload(100_000, 32, &[0; 16]);
    bad_prf[0] = 0x7F;
    let err = parse_kms_payload(KMS_PBKDF2, &bad_prf).expect_err("reserved PRF");
    assert!(matches!(
        err,
        SarCryptoError::ReservedValue(_) | SarCryptoError::Unsupported(_)
    ));
}

#[test]
fn pbkdf2_hmac_sha256_known_vector() {
    let params = Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: b"0123456789abcdef".to_vec(),
        iterations: 100_000,
        derived_key_length: 32,
    };

    let key = derive_key(
        &params,
        b"correct horse battery staple",
        &KdfLimits::default(),
    )
    .expect("derive key");

    assert_eq!(
        hex(&key),
        "090105d3788cadab9c12509fa1ba1d46a91a158d7a1779b114322f3fd5a825cb"
    );
}

#[test]
fn pbkdf2_limits_apply_after_validation_and_cover_mandatory_range() {
    let mandatory = Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: vec![1; 64],
        iterations: 600_000,
        derived_key_length: 32,
    };
    let defaults = KdfLimits::default();
    defaults
        .check_pbkdf2(&mandatory)
        .expect("default limits admit the mandatory range");

    let tight = KdfLimits {
        max_pbkdf2_iterations: 100_000,
        ..KdfLimits::default()
    };
    let err = derive_key(&mandatory, b"pw", &tight).expect_err("limit");
    assert!(matches!(err, SarCryptoError::LimitExceeded(_)));

    let tight_salt = KdfLimits {
        max_kdf_salt_bytes: 32,
        ..KdfLimits::default()
    };
    let err = derive_key(&mandatory, b"pw", &tight_salt).expect_err("salt limit");
    assert!(matches!(err, SarCryptoError::LimitExceeded(_)));

    // Structural errors outrank limits.
    let invalid = Pbkdf2Params {
        derived_key_length: 16,
        ..mandatory
    };
    let err = derive_key(&invalid, b"pw", &tight).expect_err("invalid");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));
}

#[test]
fn argon2_wire_layout_matches_section_5_3_3() {
    let params = KmsParams::Argon2(Argon2Params {
        variant: ARGON2_VARIANT_ID,
        version: 0x13,
        salt: vec![0x5A; 16],
        memory_cost_kib: 19_456,
        time_cost: 2,
        parallelism: 1,
        derived_key_length: 32,
    });
    let encoded = serialize_kms_payload(&params).expect("serialize");
    assert_eq!(
        encoded,
        argon2_payload(ARGON2_VARIANT_ID, 0x13, 19_456, 2, 1, 32, &[0x5A; 16])
    );
    assert_eq!(
        parse_kms_payload(KMS_ARGON2, &encoded).expect("parse"),
        params
    );
}

#[test]
fn argon2_validation_errors() {
    let ok = |v: u8, ver: u8, dkl: u16| argon2_payload(v, ver, 19_456, 2, 1, dkl, &[0; 16]);
    parse_kms_payload(KMS_ARGON2, &ok(ARGON2_VARIANT_ID, 0x13, 32)).expect("baseline");

    let err = parse_kms_payload(KMS_ARGON2, &ok(ARGON2_VARIANT_ID, 0x13, 16)).expect_err("dkl");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));
    let err = parse_kms_payload(KMS_ARGON2, &ok(0x01, 0x13, 32)).expect_err("variant");
    assert!(matches!(err, SarCryptoError::ReservedValue(_)));
    let err = parse_kms_payload(KMS_ARGON2, &ok(ARGON2_VARIANT_ID, 0x10, 32)).expect_err("version");
    assert!(matches!(err, SarCryptoError::Unsupported(_)));
    let err = parse_kms_payload(
        KMS_ARGON2,
        &argon2_payload(ARGON2_VARIANT_ID, 0x13, 0, 2, 1, 32, &[0; 16]),
    )
    .expect_err("zero memory");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));
}

#[test]
fn argon2_limits_cover_mandatory_range_and_reject_larger() {
    let defaults = KdfLimits::default();
    let params = Argon2Params {
        variant: ARGON2_VARIANT_ID,
        version: 0x13,
        salt: vec![0x5A; 64],
        memory_cost_kib: 65_536,
        time_cost: 3,
        parallelism: 4,
        derived_key_length: 32,
    };
    defaults
        .check_argon2(&params)
        .expect("default limits admit the mandatory range");
    for limits in [
        KdfLimits {
            max_argon2_memory_kib: 19_456,
            ..KdfLimits::default()
        },
        KdfLimits {
            max_argon2_time_cost: 2,
            ..KdfLimits::default()
        },
        KdfLimits {
            max_argon2_parallelism: 1,
            ..KdfLimits::default()
        },
        KdfLimits {
            max_kdf_salt_bytes: 8,
            ..KdfLimits::default()
        },
    ] {
        let err = sar_crypto::kms::argon2::derive_key(&params, b"pw", &limits)
            .expect_err("limit exceeded");
        assert!(matches!(err, SarCryptoError::LimitExceeded(_)));
    }
}

#[test]
fn argon2_derives_32_byte_master_secret_at_baseline_memory() {
    let params = Argon2Params {
        variant: ARGON2_VARIANT_ID,
        version: 0x13,
        salt: vec![0x5A; 16],
        memory_cost_kib: 19_456,
        time_cost: 2,
        parallelism: 1,
        derived_key_length: 32,
    };
    let key =
        sar_crypto::kms::argon2::derive_key(&params, b"pw", &KdfLimits::default()).expect("derive");
    assert_eq!(key.len(), 32);
}

fn wrapped_params(wrap_algo_id: u8, wrapped_len: usize) -> Vec<u8> {
    let mut out = vec![wrap_algo_id, 1];
    out.push(5);
    out.extend_from_slice(b"alice");
    out.extend_from_slice(&u16::try_from(wrapped_len).expect("len").to_le_bytes());
    out.extend(std::iter::repeat_n(7u8, wrapped_len));
    out
}

#[test]
fn asymmetric_wrap_structure_and_lengths() {
    let params = KmsParams::AsymmetricWrap(AsymmetricWrapParams {
        wrap_algo_id: 0x01,
        recipients: vec![
            AsymmetricRecipient {
                recipient_id: b"alice".to_vec(),
                wrapped_key: vec![1; 256],
            },
            AsymmetricRecipient {
                recipient_id: b"bob".to_vec(),
                wrapped_key: vec![4; 256],
            },
        ],
    });
    let encoded = serialize_kms_payload(&params).expect("serialize");
    let parsed = parse_kms_payload(KMS_ASYMMETRIC_WRAP, &encoded).expect("parse");
    assert_eq!(parsed, params);

    let KmsParams::AsymmetricWrap(parsed_params) = parsed else {
        panic!("expected asymmetric params");
    };
    let cek = unwrap_cek(&parsed_params, b"bob", |algo, recipient_id, wrapped_key| {
        assert_eq!(algo, 0x01);
        assert_eq!(recipient_id, b"bob");
        assert_eq!(wrapped_key.len(), 256);
        Ok(Some(Zeroizing::new(vec![9u8; 32])))
    })
    .expect("unwrap");
    assert_eq!(&*cek, &vec![9u8; 32]);

    // Wrong wrapped-key length for the Wrap Algo ID.
    let err = parse_kms_payload(KMS_ASYMMETRIC_WRAP, &wrapped_params(0x01, 255))
        .expect_err("wrapped length");
    assert!(matches!(err, SarCryptoError::InvalidLength(_)));
    parse_kms_payload(KMS_ASYMMETRIC_WRAP, &wrapped_params(0x02, 512)).expect("rsa-4096");
    // Reserved and assigned-unsupported Wrap Algo IDs.
    let err = parse_kms_payload(KMS_ASYMMETRIC_WRAP, &wrapped_params(0x7E, 256))
        .expect_err("reserved wrap");
    assert!(matches!(err, SarCryptoError::ReservedValue(_)));
    let err =
        parse_kms_payload(KMS_ASYMMETRIC_WRAP, &wrapped_params(0x04, 256)).expect_err("ml-kem");
    assert!(matches!(err, SarCryptoError::Unsupported(_)));
    // Truncated record.
    let mut truncated = wrapped_params(0x01, 256);
    truncated.truncate(truncated.len() - 1);
    let err = parse_kms_payload(KMS_ASYMMETRIC_WRAP, &truncated).expect_err("truncated");
    assert!(matches!(
        err,
        SarCryptoError::Malformed(_) | SarCryptoError::InvalidLength(_)
    ));
}

#[test]
fn asymmetric_wrap_errors() {
    let params = AsymmetricWrapParams {
        wrap_algo_id: 0x01,
        recipients: vec![AsymmetricRecipient {
            recipient_id: b"alice".to_vec(),
            wrapped_key: vec![1; 256],
        }],
    };
    let err = unwrap_cek(&params, b"bob", |_algo, _recipient, _wrapped| Ok(None))
        .expect_err("missing recipient");
    assert!(matches!(err, SarCryptoError::KeyMissing(_)));

    let err = unwrap_cek(&params, b"alice", |_algo, _recipient, _wrapped| {
        Ok(Some(Zeroizing::new(vec![0u8; 31])))
    })
    .expect_err("recovered secret must be 32 bytes");
    assert!(matches!(err, SarCryptoError::KeyRejected(_)));
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

#[test]
fn default_kdf_limits_are_finite_and_cover_the_mandatory_range_exactly_as_documented() {
    assert_eq!(KdfLimits::DEFAULT_MAX_PBKDF2_ITERATIONS, 2_000_000);
    assert_eq!(KdfLimits::DEFAULT_MAX_KDF_SALT_BYTES, 64);
    assert_eq!(KdfLimits::DEFAULT_MAX_ARGON2_MEMORY_KIB, 262_144);
    assert_eq!(KdfLimits::DEFAULT_MAX_ARGON2_TIME_COST, 6);
    assert_eq!(KdfLimits::DEFAULT_MAX_ARGON2_PARALLELISM, 8);
    let d = KdfLimits::default();
    assert!(d.max_pbkdf2_iterations >= 600_000 && d.max_kdf_salt_bytes >= 64);
    assert!(d.max_argon2_memory_kib >= 65_536);
    assert!(d.max_argon2_time_cost >= 3 && d.max_argon2_parallelism >= 4);
    // Out-of-baseline values stay valid when a caller raises the limits.
    let raised = KdfLimits {
        max_argon2_memory_kib: 1_048_576,
        max_argon2_time_cost: 16,
        ..KdfLimits::default()
    };
    let beyond = Argon2Params {
        variant: ARGON2_VARIANT_ID,
        version: 0x13,
        salt: vec![1; 16],
        memory_cost_kib: 1_048_576,
        time_cost: 16,
        parallelism: 4,
        derived_key_length: 32,
    };
    assert!(d.check_argon2(&beyond).is_err());
    raised.check_argon2(&beyond).expect("caller-raised limits");
}
