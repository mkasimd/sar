use std::io::Cursor;

use zeroize::Zeroizing;

use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD};
use sar_core::{
    DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, SarError, decode_payload_v2,
    encode_payload_v2,
};
use sar_crypto::aad::build_aead_aad;
use sar_crypto::{ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, SecretBytes};

fn key(fill: u8) -> SecretBytes {
    Zeroizing::new(vec![fill; 32])
}

#[test]
fn store_aes256_gcm_round_trip() {
    let payload = b"store-payload".repeat(8);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"0123456789ab");
    let aad = build_aead_aad(b"global", b"lfh");
    let encoded = encode_payload_v2(
        &payload,
        EncodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            compression_level: None,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad: aad.clone(),
                key: key(1),
            }),
        },
    )
    .expect("encode");
    let decoded = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            expected_output_size: payload.len() as u64,
            max_output_size: payload.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key: key(1),
            }),
        },
    )
    .expect("decode");
    assert_eq!(decoded, payload);
}

#[test]
fn deflate_aes256_gcm_round_trip() {
    let payload = b"deflate-payload".repeat(64);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"feedfacecafe");
    let aad = build_aead_aad(b"global-2", b"lfh-2");
    let encoded = encode_payload_v2(
        &payload,
        EncodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_DEFLATE,
            compression_level: Some(6),
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad: aad.clone(),
                key: key(2),
            }),
        },
    )
    .expect("encode");
    let decoded = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_DEFLATE,
            expected_output_size: payload.len() as u64,
            max_output_size: payload.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key: key(2),
            }),
        },
    )
    .expect("decode");
    assert_eq!(decoded, payload);
}

#[test]
fn zstd_xchacha20_poly_round_trip() {
    let payload = b"zstd-payload".repeat(64);
    let mut nonce = [0u8; 24];
    for (idx, byte) in nonce.iter_mut().enumerate() {
        *byte = (idx * 7) as u8;
    }
    let aad = build_aead_aad(b"global-3", b"lfh-3");
    let encoded = encode_payload_v2(
        &payload,
        EncodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_ZSTD,
            compression_level: Some(7),
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_XCHACHA20_POLY,
                iv_nonce: nonce,
                aad: aad.clone(),
                key: key(3),
            }),
        },
    )
    .expect("encode");
    let decoded = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_ZSTD,
            expected_output_size: payload.len() as u64,
            max_output_size: payload.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_XCHACHA20_POLY,
                iv_nonce: nonce,
                aad,
                key: key(3),
            }),
        },
    )
    .expect("decode");
    assert_eq!(decoded, payload);
}

#[test]
fn auth_failure_happens_before_decompression() {
    let payload = b"auth-failure".repeat(32);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"authfailure!");
    let aad = build_aead_aad(b"global-4", b"lfh-4");
    let mut encoded = encode_payload_v2(
        &payload,
        EncodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_DEFLATE,
            compression_level: Some(6),
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad: aad.clone(),
                key: key(4),
            }),
        },
    )
    .expect("encode");
    encoded[0] ^= 0x55;
    let err = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_DEFLATE,
            expected_output_size: payload.len() as u64,
            max_output_size: payload.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key: key(4),
            }),
        },
    )
    .expect_err("must fail");
    assert!(matches!(err, SarError::AuthFailed(_)));
    let _ = Cursor::new(encoded);
}
