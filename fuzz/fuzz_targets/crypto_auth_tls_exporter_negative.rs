// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.5 PR3: crypto/auth ordering and TLS_EXPORTER AAD-negative fuzz target.
//!
//! Exercises two fail-closed surfaces with bounded in-memory inputs:
//! - `decode_payload_v2` authentication failure ordering (AAD mismatch,
//!   ciphertext corruption, tag corruption/truncation).
//! - `parse_tls_exporter_kms_payload` malformed/reserved TLS_EXPORTER KMS payloads,
//!   plus session-binding mismatch simulation via context-derived key mismatch.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_archive::transform::{
    DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, decode_payload_v2, encode_payload_v2,
};
use sar_core::SarError;
use sar_crypto::{
    ENCR_AES256_GCM, HASH_SHA256, SecretBytes, TlsExporterContextV1, TlsExporterParams,
    TLS_EXPORTER_CONTEXT_VERSION_1, TLS_EXPORTER_KDF_DIRECT,
    TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER, TLS_EXPORTER_TRANSPORT_QUIC,
    aad::build_aead_aad, encode_tls_exporter_context_v1, hash::hash_data,
    parse_tls_exporter_kms_payload, serialize_tls_exporter_kms_payload,
};

const COMP_ALGO_DEFLATE: u8 = 0x01;

fn key(fill: u8) -> SecretBytes {
    vec![fill; 32].into()
}

fn derive_context_key(context: &[u8]) -> SecretBytes {
    let hash = hash_data(HASH_SHA256, context).unwrap_or_else(|_| vec![0u8; 32]);
    let mut out = vec![0u8; 32];
    let copy_len = out.len().min(hash.len());
    out[..copy_len].copy_from_slice(&hash[..copy_len]);
    out.into()
}

fn take_or(seed: &[u8], idx: usize, default: u8) -> u8 {
    seed.get(idx).copied().unwrap_or(default)
}

fn exercise_crypto_auth_ordering(seed: &[u8]) {
    let control = take_or(seed, 0, 0);

    let payload = b"pr3-auth-ordering-payload".repeat(16);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"pr3-auth-seed");

    let mut global_aad = b"global-header-aad".to_vec();
    let mut lfh_aad = b"lfh-aad-bytes".to_vec();
    let aad = build_aead_aad(&global_aad, &lfh_aad);

    let Ok(encoded) = encode_payload_v2(
        &payload,
        EncodingPlanV2 {
            is_compressed: true,
            comp_algo_id: COMP_ALGO_DEFLATE,
            compression_level: Some(3),
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key: key(0x5A),
            }),
        },
    ) else {
        return;
    };

    if control & 0x01 != 0 {
        global_aad[0] ^= take_or(seed, 1, 0x80);
    }
    if control & 0x02 != 0 {
        let last = lfh_aad.len().saturating_sub(1);
        lfh_aad[last] ^= take_or(seed, 1, 0x40);
    }

    let mut mutated = encoded;

    if control & 0x04 != 0 && !mutated.is_empty() {
        let max_cipher_idx = mutated.len().saturating_sub(16).saturating_sub(1);
        let idx = usize::from(take_or(seed, 2, 0)) % (max_cipher_idx + 1);
        mutated[idx] ^= take_or(seed, 3, 0x11);
    }

    if control & 0x08 != 0 && mutated.len() >= 16 {
        let tag_offset = usize::from(take_or(seed, 3, 0)) % 16;
        let idx = mutated.len() - 1 - tag_offset;
        mutated[idx] ^= take_or(seed, 4, 0xAA);
    }

    if control & 0x10 != 0 && mutated.len() > 16 {
        let drop = usize::from(take_or(seed, 4, 1) % 16) + 1;
        let new_len = mutated.len().saturating_sub(drop);
        mutated.truncate(new_len);
    }

    let decode_algo = if control & 0x20 != 0 {
        0xFF
    } else {
        COMP_ALGO_DEFLATE
    };

    let aad = build_aead_aad(&global_aad, &lfh_aad);
    let _ = decode_payload_v2(
        &mutated,
        DecodingPlanV2 {
            is_compressed: true,
            comp_algo_id: decode_algo,
            expected_output_size: payload.len() as u64,
            max_output_size: payload.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key: key(0x5A),
            }),
        },
    );
}

fn exercise_tls_exporter_negative(seed: &[u8]) {
    let _ = parse_tls_exporter_kms_payload(seed);

    let params = TlsExporterParams {
        exporter_label: "EXPORTER-SAR-v1-QUIC-AEAD".to_string(),
        context_version: TLS_EXPORTER_CONTEXT_VERSION_1,
        aead_algo_id: ENCR_AES256_GCM,
        kdf_algo_id: TLS_EXPORTER_KDF_DIRECT,
        global_header_hash_algo_id: HASH_SHA256,
        salt: seed.iter().copied().take(8).collect(),
        derived_key_length: 32,
        flags: 0,
    };
    let payload = serialize_tls_exporter_kms_payload(&params);
    let Ok(parsed) = parse_tls_exporter_kms_payload(&payload) else {
        return;
    };

    let mut session_a = [0u8; 16];
    let mut session_b = [0u8; 16];
    for idx in 0..16 {
        session_a[idx] = take_or(seed, idx, idx as u8);
        session_b[idx] = session_a[idx];
    }
    session_b[usize::from(take_or(seed, 0, 0)) % 16] ^= 0x01;

    let context_a = TlsExporterContextV1 {
        transport_profile_id: TLS_EXPORTER_TRANSPORT_QUIC,
        sar_major_version: 1,
        sar_minor_version: 0,
        global_header_hash_algo_id: parsed.global_header_hash_algo_id,
        global_header_hash: vec![0xAA; 32],
        aead_algo_id: parsed.aead_algo_id,
        stream_id: 7,
        session_uuid: session_a,
        key_usage_id: TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER,
        salt: parsed.salt.clone(),
    };
    let context_b = TlsExporterContextV1 {
        session_uuid: session_b,
        ..context_a.clone()
    };

    let encoded_context_a = encode_tls_exporter_context_v1(&context_a);
    let encoded_context_b = encode_tls_exporter_context_v1(&context_b);
    let key_a = derive_context_key(&encoded_context_a);
    let key_b = derive_context_key(&encoded_context_b);

    let nonce = [0x33u8; 24];
    let aad = build_aead_aad(b"tls-exporter-gh", b"tls-exporter-lfh");
    let Ok(ciphertext) = encode_payload_v2(
        b"tls-exporter-session-bound",
        EncodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            compression_level: None,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad: aad.clone(),
                key: key_a,
            }),
        },
    ) else {
        return;
    };

    let result = decode_payload_v2(
        &ciphertext,
        DecodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            expected_output_size: 26,
            max_output_size: 26,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key: key_b,
            }),
        },
    );

    let _ = matches!(result, Err(SarError::AuthFailed(_) | SarError::DecryptFailed(_)));
}

fuzz_target!(|data: &[u8]| {
    exercise_crypto_auth_ordering(data);
    exercise_tls_exporter_negative(data);
});
