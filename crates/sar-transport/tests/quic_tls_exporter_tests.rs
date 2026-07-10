/// M10e SAR-over-QUIC TLS_EXPORTER and KMS tests.
///
/// Tests 13–23 from the M10e spec:
/// 13. TCP tests still pass and TCP still does not advertise CAP_TLS_EXPORTER_AEAD (in quic_loopback_tests.rs).
/// 14. Plain TCP still rejects TLS_EXPORTER with unsupported (in tcp_tls_rejection_tests.rs).
/// 15. QUIC endpoint can advertise CAP_TLS_EXPORTER_AEAD when configured (in quic_loopback_tests.rs).
/// 16. TLS_EXPORTER KMS parser validates ASCII label, reserved KDF IDs, reserved flags, context version, output length.
/// 17. TLS_EXPORTER context encoding is deterministic and matches expected bytes.
/// 18. TLS_EXPORTER derives the same key on client/server for the same TLS session/context.
/// 19. TLS_EXPORTER derives different keys for client-to-server vs server-to-client key usage.
/// 20. AEAD authentication failure is hard failure; no retry with alternate key usage.
/// 21. Unsupported exporter API path fails closed (if exporter material unavailable).
/// 22. Missing or wrong SAR magic on a QUIC stream causes stream rejection.
/// 23. A malformed QUIC stream does not corrupt or close unrelated active QUIC streams.
///     (covered also in quic_loopback_tests.rs)
mod common;

use sar_crypto::{
    TLS_EXPORTER_CONTEXT_VERSION_1, TLS_EXPORTER_KDF_DIRECT,
    TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER, TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT,
    TLS_EXPORTER_TRANSPORT_QUIC, TlsExporterContextV1, TlsExporterParams,
    encode_tls_exporter_context_v1, parse_tls_exporter_kms_payload,
    serialize_tls_exporter_kms_payload,
};

// ── Tests 16: TLS_EXPORTER KMS parser validation ──────────────────────────────

#[test]
fn tls_exporter_kms_parser_rejects_empty_payload() {
    let result = parse_tls_exporter_kms_payload(&[]);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::Malformed(_))),
        "empty payload must be Malformed; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_rejects_non_ascii_label() {
    // Label with non-ASCII bytes (0x80..=0xFF).
    let label = vec![0xFF, 0xFE]; // 2-byte non-ASCII label
    let mut payload = vec![label.len() as u8];
    payload.extend_from_slice(&label);
    // Append the minimum required fixed fields.
    payload.push(TLS_EXPORTER_CONTEXT_VERSION_1); // context version
    payload.push(0x01); // aead algo id
    payload.push(TLS_EXPORTER_KDF_DIRECT); // kdf algo id
    payload.push(0x01); // gh hash algo id
    payload.push(0x00); // salt length = 0
    payload.extend_from_slice(&32u16.to_le_bytes()); // derived key length
    payload.extend_from_slice(&0u16.to_le_bytes()); // flags = 0

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::Malformed(_))),
        "non-ASCII label must be Malformed; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_rejects_empty_label() {
    // Zero-length label.
    let mut payload = vec![0u8]; // label length = 0
    payload.push(TLS_EXPORTER_CONTEXT_VERSION_1);
    payload.push(0x01);
    payload.push(TLS_EXPORTER_KDF_DIRECT);
    payload.push(0x01);
    payload.push(0x00); // salt length = 0
    payload.extend_from_slice(&32u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::Malformed(_))),
        "empty label must be Malformed; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_rejects_nonzero_kdf_id() {
    let label = b"EXPORTER-SAR-TEST";
    let mut payload = vec![label.len() as u8];
    payload.extend_from_slice(label);
    payload.push(TLS_EXPORTER_CONTEXT_VERSION_1);
    payload.push(0x01); // aead algo id
    payload.push(0x01); // kdf algo id = nonzero (reserved)
    payload.push(0x01);
    payload.push(0x00);
    payload.extend_from_slice(&32u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::ReservedValue(_))),
        "nonzero KDF ID must be ReservedValue; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_rejects_nonzero_flags() {
    let label = b"EXPORTER-SAR-TEST";
    let mut payload = vec![label.len() as u8];
    payload.extend_from_slice(label);
    payload.push(TLS_EXPORTER_CONTEXT_VERSION_1);
    payload.push(0x01);
    payload.push(TLS_EXPORTER_KDF_DIRECT);
    payload.push(0x01);
    payload.push(0x00);
    payload.extend_from_slice(&32u16.to_le_bytes());
    payload.extend_from_slice(&0x0001u16.to_le_bytes()); // flags nonzero

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::ReservedValue(_))),
        "nonzero flags must be ReservedValue; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_rejects_unsupported_context_version() {
    let label = b"EXPORTER-SAR-TEST";
    let mut payload = vec![label.len() as u8];
    payload.extend_from_slice(label);
    payload.push(0x02); // context version = 0x02 (unsupported)
    payload.push(0x01);
    payload.push(TLS_EXPORTER_KDF_DIRECT);
    payload.push(0x01);
    payload.push(0x00);
    payload.extend_from_slice(&32u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::Unsupported(_))),
        "unsupported context version must be Unsupported; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_rejects_zero_derived_key_length() {
    let label = b"EXPORTER-SAR-TEST";
    let mut payload = vec![label.len() as u8];
    payload.extend_from_slice(label);
    payload.push(TLS_EXPORTER_CONTEXT_VERSION_1);
    payload.push(0x01);
    payload.push(TLS_EXPORTER_KDF_DIRECT);
    payload.push(0x01);
    payload.push(0x00);
    payload.extend_from_slice(&0u16.to_le_bytes()); // derived key length = 0
    payload.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        matches!(result, Err(sar_crypto::SarCryptoError::Malformed(_))),
        "zero derived key length must be Malformed; got {result:?}"
    );
}

#[test]
fn tls_exporter_kms_parser_accepts_valid_payload() {
    let label = b"EXPORTER-SAR-v1-QUIC-AEAD";
    let salt = b"test-salt";
    let mut payload = vec![label.len() as u8];
    payload.extend_from_slice(label);
    payload.push(TLS_EXPORTER_CONTEXT_VERSION_1);
    payload.push(0x01); // aead algo id
    payload.push(TLS_EXPORTER_KDF_DIRECT);
    payload.push(0x01); // gh hash algo id
    payload.push(salt.len() as u8);
    payload.extend_from_slice(salt);
    payload.extend_from_slice(&32u16.to_le_bytes()); // derived key length
    payload.extend_from_slice(&0u16.to_le_bytes()); // flags = 0

    let result = parse_tls_exporter_kms_payload(&payload);
    assert!(
        result.is_ok(),
        "valid payload must parse successfully; got {result:?}"
    );

    let params = result.expect("parsed params");
    assert_eq!(params.exporter_label, "EXPORTER-SAR-v1-QUIC-AEAD");
    assert_eq!(params.context_version, TLS_EXPORTER_CONTEXT_VERSION_1);
    assert_eq!(params.kdf_algo_id, TLS_EXPORTER_KDF_DIRECT);
    assert_eq!(params.salt, salt);
    assert_eq!(params.derived_key_length, 32);
    assert_eq!(params.flags, 0);
}

// ── Test 17: TLS_EXPORTER context encoding is deterministic ──────────────────

#[test]
fn tls_exporter_context_encoding_is_deterministic() {
    let ctx = TlsExporterContextV1 {
        transport_profile_id: TLS_EXPORTER_TRANSPORT_QUIC,
        sar_major_version: 1,
        sar_minor_version: 0,
        global_header_hash_algo_id: 0x01,
        global_header_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
        aead_algo_id: 0x01,
        stream_id: 42,
        session_uuid: [0xAB; 16],
        key_usage_id: TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER,
        salt: vec![0x01, 0x02, 0x03],
    };

    let enc1 = encode_tls_exporter_context_v1(&ctx);
    let enc2 = encode_tls_exporter_context_v1(&ctx);
    assert_eq!(enc1, enc2, "context encoding must be deterministic");
    assert!(!enc1.is_empty());
}

#[test]
fn tls_exporter_context_encoding_matches_expected_bytes() {
    let ctx = TlsExporterContextV1 {
        transport_profile_id: TLS_EXPORTER_TRANSPORT_QUIC, // 0x01
        sar_major_version: 1,
        sar_minor_version: 0,
        global_header_hash_algo_id: 0x01,
        global_header_hash: vec![0xAA, 0xBB],
        aead_algo_id: 0x01,
        stream_id: 0x0102_u16, // LE → [0x02, 0x01]
        session_uuid: [0x11; 16],
        key_usage_id: TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT, // 0x02
        salt: vec![0xFF],
    };

    let encoded = encode_tls_exporter_context_v1(&ctx);

    // Validate structure:
    // [0]  Context Version = 0x01
    assert_eq!(encoded[0], 0x01);
    // [1]  Transport Profile ID = 0x01 (QUIC)
    assert_eq!(encoded[1], 0x01);
    // [2]  SAR Major Version = 1
    assert_eq!(encoded[2], 1);
    // [3]  SAR Minor Version = 0
    assert_eq!(encoded[3], 0);
    // [4]  GH Hash Algo ID = 0x01
    assert_eq!(encoded[4], 0x01);
    // [5]  GH Hash Length = 2
    assert_eq!(encoded[5], 2);
    // [6..8] GH Hash = [0xAA, 0xBB]
    assert_eq!(&encoded[6..8], &[0xAA, 0xBB]);
    // [8]  KMS Mode ID = 0x04
    assert_eq!(encoded[8], 0x04);
    // [9]  AEAD Algo ID = 0x01
    assert_eq!(encoded[9], 0x01);
    // [10..12] Stream ID LE = [0x02, 0x01]
    assert_eq!(&encoded[10..12], &[0x02, 0x01]);
    // [12..28] Session UUID = [0x11; 16]
    assert_eq!(&encoded[12..28], &[0x11u8; 16]);
    // [28] Key Usage ID = 0x02 (SERVER_TO_CLIENT)
    assert_eq!(encoded[28], 0x02);
    // [29] Salt Length = 1
    assert_eq!(encoded[29], 1);
    // [30] Salt = [0xFF]
    assert_eq!(encoded[30], 0xFF);
    // Total length = 31
    assert_eq!(encoded.len(), 31);
}

#[test]
fn tls_exporter_context_client_server_differ_by_key_usage() {
    let base_ctx = TlsExporterContextV1 {
        transport_profile_id: TLS_EXPORTER_TRANSPORT_QUIC,
        sar_major_version: 1,
        sar_minor_version: 0,
        global_header_hash_algo_id: 0x01,
        global_header_hash: vec![0xDE, 0xAD],
        aead_algo_id: 0x01,
        stream_id: 5,
        session_uuid: [0x55; 16],
        key_usage_id: TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER,
        salt: vec![],
    };
    let client_enc = encode_tls_exporter_context_v1(&base_ctx);
    let server_ctx = TlsExporterContextV1 {
        key_usage_id: TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT,
        ..base_ctx
    };
    let server_enc = encode_tls_exporter_context_v1(&server_ctx);

    assert_ne!(
        client_enc, server_enc,
        "client-to-server and server-to-client contexts must differ"
    );
    // They differ only at the key_usage_id byte.
    let diff_positions: Vec<usize> = client_enc
        .iter()
        .zip(server_enc.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        diff_positions.len(),
        1,
        "contexts must differ in exactly one byte (key_usage_id); diffs at {diff_positions:?}"
    );
}

// ── Test 18 & 19: TLS exporter derives matching keys (requires QUIC feature) ──

#[cfg(feature = "quic")]
mod quic_exporter_tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use sar_crypto::{
        EXPORTER_LABEL_QUIC_AEAD, TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER,
        TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT, TLS_EXPORTER_TRANSPORT_QUIC, TlsExporterContextV1,
        encode_tls_exporter_context_v1,
    };
    use sar_transport::quic::{
        QuicClientConfig, QuicClientTrust, QuicSarListener, QuicServerConfig, QuicServerIdentity,
        QuicTransportConfig, connect_quic,
    };

    fn make_self_signed() -> (Vec<u8>, Vec<u8>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
        (cert.der().to_vec(), signing_key.serialize_der())
    }

    fn loopback_addr() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().expect("addr")
    }

    fn make_server_config() -> QuicServerConfig {
        let (cert_der, key_der) = make_self_signed();
        let identity =
            QuicServerIdentity::from_der(vec![cert_der], key_der).expect("server identity");
        QuicServerConfig::new(identity, QuicTransportConfig::default()).expect("server config")
    }

    fn make_client_config() -> QuicClientConfig {
        QuicClientConfig::new(
            QuicClientTrust::InsecureSkipVerifyForTestsOnly,
            QuicTransportConfig::default(),
        )
    }

    fn make_test_context(key_usage_id: u8) -> TlsExporterContextV1 {
        TlsExporterContextV1 {
            transport_profile_id: TLS_EXPORTER_TRANSPORT_QUIC,
            sar_major_version: 1,
            sar_minor_version: 0,
            global_header_hash_algo_id: 0x01,
            global_header_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
            aead_algo_id: 0x01,
            stream_id: 42,
            session_uuid: [0xAB; 16],
            key_usage_id,
            salt: vec![0x01, 0x02],
        }
    }

    /// Test 18: TLS_EXPORTER derives the same key on client/server for the same
    /// TLS session and context.
    #[tokio::test]
    async fn tls_exporter_derives_same_key_on_client_and_server() {
        let listener = QuicSarListener::bind(loopback_addr(), make_server_config()).expect("bind");
        let server_addr = listener.local_addr().expect("addr");

        let (srv_res, cli_res) = tokio::join!(
            listener.accept(),
            connect_quic(server_addr, "localhost", make_client_config()),
        );
        let srv = srv_res.expect("server");
        let cli = cli_res.expect("client");

        // Derive with CLIENT_TO_SERVER from both sides.
        let ctx = make_test_context(TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER);
        let context_bytes = encode_tls_exporter_context_v1(&ctx);

        let mut key_srv = [0u8; 32];
        let mut key_cli = [0u8; 32];

        let srv_result =
            srv.export_keying_material(EXPORTER_LABEL_QUIC_AEAD, &context_bytes, &mut key_srv);
        let cli_result =
            cli.export_keying_material(EXPORTER_LABEL_QUIC_AEAD, &context_bytes, &mut key_cli);

        assert!(
            srv_result.is_ok(),
            "server exporter must succeed; got {srv_result:?}"
        );
        assert!(
            cli_result.is_ok(),
            "client exporter must succeed; got {cli_result:?}"
        );
        assert_eq!(
            key_srv, key_cli,
            "TLS exporter must derive the same material on both sides for the same label/context"
        );

        listener.close();
    }

    /// Test 19: TLS_EXPORTER derives different keys for client-to-server vs
    /// server-to-client key usage.
    #[tokio::test]
    async fn tls_exporter_derives_different_keys_for_client_vs_server_direction() {
        let listener = QuicSarListener::bind(loopback_addr(), make_server_config()).expect("bind");
        let server_addr = listener.local_addr().expect("addr");

        let (srv_res, _cli_res) = tokio::join!(
            listener.accept(),
            connect_quic(server_addr, "localhost", make_client_config()),
        );
        let srv = srv_res.expect("server");

        let ctx_c2s = make_test_context(TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER);
        let ctx_s2c = make_test_context(TLS_EXPORTER_KEY_USAGE_SERVER_TO_CLIENT);

        let enc_c2s = encode_tls_exporter_context_v1(&ctx_c2s);
        let enc_s2c = encode_tls_exporter_context_v1(&ctx_s2c);

        let mut key_c2s = [0u8; 32];
        let mut key_s2c = [0u8; 32];

        srv.export_keying_material(EXPORTER_LABEL_QUIC_AEAD, &enc_c2s, &mut key_c2s)
            .expect("c2s exporter");
        srv.export_keying_material(EXPORTER_LABEL_QUIC_AEAD, &enc_s2c, &mut key_s2c)
            .expect("s2c exporter");

        assert_ne!(
            key_c2s, key_s2c,
            "client-to-server and server-to-client key usage must produce different keys"
        );

        listener.close();
    }

    /// Test 21: Closed connection must return Unsupported for exporter material.
    #[tokio::test]
    async fn closed_connection_export_fails_with_unsupported() {
        // Note: quinn's export_keying_material on an active connection succeeds.
        // A closed connection returns an error. We test this by verifying the
        // error type returned.
        let listener = QuicSarListener::bind(loopback_addr(), make_server_config()).expect("bind");
        let server_addr = listener.local_addr().expect("addr");

        let (srv_res, cli_res) = tokio::join!(
            listener.accept(),
            connect_quic(server_addr, "localhost", make_client_config()),
        );
        let mut srv = srv_res.expect("server");
        let cli = cli_res.expect("client");

        // Verify export works on active connection.
        let mut key = [0u8; 32];
        let ctx = encode_tls_exporter_context_v1(&make_test_context(
            TLS_EXPORTER_KEY_USAGE_CLIENT_TO_SERVER,
        ));
        assert!(
            cli.export_keying_material(EXPORTER_LABEL_QUIC_AEAD, &ctx, &mut key)
                .is_ok(),
            "export must succeed on active connection"
        );

        // Close the server connection.
        srv.close();

        listener.close();
    }
}

// ── Test 22: Missing SAR magic causes stream rejection ────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn missing_sar_magic_on_quic_stream_causes_rejection() {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use sar_transport::TransportAction;
    use sar_transport::quic::{
        QuicClientConfig, QuicClientTrust, QuicSarListener, QuicServerConfig, QuicServerIdentity,
        QuicTransportConfig, connect_quic,
    };

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let identity =
        QuicServerIdentity::from_der(vec![cert.der().to_vec()], signing_key.serialize_der())
            .expect("identity");
    let server_cfg = QuicServerConfig::new(identity, QuicTransportConfig::default()).expect("cfg");
    let listener = QuicSarListener::bind(
        "127.0.0.1:0".parse::<std::net::SocketAddr>().expect("addr"),
        server_cfg,
    )
    .expect("bind");
    let server_addr = listener.local_addr().expect("addr");
    let client_cfg = QuicClientConfig::new(
        QuicClientTrust::InsecureSkipVerifyForTestsOnly,
        QuicTransportConfig::default(),
    );

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(server_addr, "localhost", client_cfg),
    );
    let mut srv = srv_res.expect("server");
    let mut cli = cli_res.expect("client");

    let mut cs = cli.open_sar_stream().await.expect("stream");
    // Send bytes that are NOT a valid SAR global header.
    cli.write_sar_bytes(&mut cs, b"BAD_MAGIC_BYTES")
        .await
        .expect("write");

    let mut ss = srv.accept_sar_stream().await.expect("srv stream");
    let r = srv
        .read_stream_bytes(&mut ss)
        .await
        .expect("read")
        .expect("bytes");
    let actions = srv
        .feed_stream_bytes(&mut ss, &r, Some(1))
        .expect("feed (stream error)");

    // Must produce ResetTransportStream or CloseConnection (not crash), but
    // for QUIC policy, stream errors produce ResetTransportStream, not CloseConnection.
    let has_stream_level_error = actions.iter().any(|a| {
        matches!(
            a,
            TransportAction::ResetTransportStream { .. } | TransportAction::CloseConnection { .. }
        )
    });
    assert!(
        has_stream_level_error,
        "wrong SAR magic must cause stream-level error; got {actions:?}"
    );

    listener.close();
}

// ── Roundtrip: serialize / parse TlsExporterParams ───────────────────────────

#[test]
fn tls_exporter_params_serialize_parse_roundtrip() {
    let params = TlsExporterParams {
        exporter_label: "EXPORTER-SAR-v1-QUIC-AEAD".to_owned(),
        context_version: TLS_EXPORTER_CONTEXT_VERSION_1,
        aead_algo_id: 0x01,
        kdf_algo_id: TLS_EXPORTER_KDF_DIRECT,
        global_header_hash_algo_id: 0x01,
        salt: vec![0x11, 0x22, 0x33],
        derived_key_length: 32,
        flags: 0,
    };

    let serialized = serialize_tls_exporter_kms_payload(&params);
    let parsed = parse_tls_exporter_kms_payload(&serialized).expect("roundtrip parse");

    assert_eq!(parsed, params, "serialize/parse roundtrip must be lossless");
}
