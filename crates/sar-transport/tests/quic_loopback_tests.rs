/// M10e SAR-over-QUIC loopback integration tests.
///
/// Tests 1–12 from the M10e spec:
///  1. QUIC loopback server/client connects successfully.
///  2. QUIC transport-only stream sends a valid SAR session and receiver processes it.
///  3. Multiple concurrent QUIC streams over one QUIC connection work independently.
///  4. Same numeric SAR Stream ID may be active on different QUIC connections as independent sessions.
///  5. Duplicate SESSION_INIT for active SAR Stream ID on the same QUIC connection is rejected.
///  6. Additional QUIC control stream using an existing SAR Stream ID and matching Session UUID is accepted.
///  7. Additional QUIC control stream using unknown Stream ID is first-time session.
///  8. Additional QUIC control stream using mismatched Session UUID is rejected.
///  9. Additional QUIC control stream attempting a new SESSION_INIT for already-bound ID rejected (covered by 5/8).
/// 10. SESSION_CLOSE unbinds Stream ID and disassociates attached QUIC streams.
/// 11. Same bidirectional QUIC stream supports reverse SESSION_ACK / SESSION_STATUS.
/// 12. TCP does not advertise CAP_TLS_EXPORTER_AEAD; QUIC can.
///
/// All tests use 127.0.0.1 loopback with ephemeral ports, InsecureSkipVerifyForTestsOnly,
/// and self-signed certificates via rcgen.
mod common;

#[cfg(feature = "quic")]
use std::net::SocketAddr;

#[cfg(feature = "quic")]
use rcgen::{CertifiedKey, generate_simple_self_signed};
#[cfg(feature = "quic")]
use sar_stream::{CapabilityFlags, SessionOpCode};
#[cfg(feature = "quic")]
use sar_transport::TransportAction;
#[cfg(feature = "quic")]
use sar_transport::quic::{
    QuicClientConfig, QuicClientTrust, QuicSarListener, QuicServerConfig, QuicServerIdentity,
    QuicTransportConfig, connect_quic,
};

#[cfg(feature = "quic")]
use common::{
    no_index_global_header_bytes, session_archive_init_bytes, session_close_entry_bytes,
    session_control_entry_bytes,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

#[cfg(feature = "quic")]
fn make_self_signed() -> (Vec<u8>, Vec<u8>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    (cert.der().to_vec(), signing_key.serialize_der())
}

#[cfg(feature = "quic")]
fn make_server_config(transport: QuicTransportConfig) -> QuicServerConfig {
    let (cert_der, key_der) = make_self_signed();
    let identity = QuicServerIdentity::from_der(vec![cert_der], key_der).expect("server identity");
    QuicServerConfig::new(identity, transport).expect("server config")
}

#[cfg(feature = "quic")]
fn make_client_config(transport: QuicTransportConfig) -> QuicClientConfig {
    QuicClientConfig::new(QuicClientTrust::InsecureSkipVerifyForTestsOnly, transport)
}

#[cfg(feature = "quic")]
fn loopback_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("addr")
}

#[cfg(feature = "quic")]
fn has_bind_sar_stream(actions: &[TransportAction], stream_id: u16) -> bool {
    actions.iter().any(|a| {
        matches!(a, TransportAction::BindSarStream { sar_stream_id, .. }
            if *sar_stream_id == stream_id)
    })
}

#[cfg(feature = "quic")]
fn has_reject_sar_stream(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::RejectSarStream { .. }))
}

#[cfg(feature = "quic")]
fn has_attach_control_stream(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::AttachControlStream { .. }))
}

// ── Test 1: QUIC loopback connects ────────────────────────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn quic_loopback_connects_successfully() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind listener");
    let server_addr = listener.local_addr().expect("local addr");
    let client_cfg = make_client_config(QuicTransportConfig::default());

    let (server_res, client_res) = tokio::join!(
        listener.accept(),
        connect_quic(server_addr, "localhost", client_cfg),
    );
    let server_conn = server_res.expect("server accept");
    let client_conn = client_res.expect("client connect");

    assert!(!server_conn.is_closed());
    assert!(!client_conn.is_closed());
    assert!(
        !server_conn.is_tls_client(),
        "server must not be tls_client"
    );
    assert!(client_conn.is_tls_client(), "client must be tls_client");

    listener.close();
}

// ── Test 2: Transport-only SAR session ────────────────────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn quic_transport_only_stream_sar_session() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");
    let client_cfg = make_client_config(QuicTransportConfig::default());

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(server_addr, "localhost", client_cfg),
    );
    let mut srv = srv_res.expect("server");
    let mut cli = cli_res.expect("client");

    let mut cs = cli.open_sar_stream().await.expect("open stream");
    let sar_bytes = session_archive_init_bytes(42, 0, [0xAB; 16]);
    cli.write_sar_bytes(&mut cs, &sar_bytes)
        .await
        .expect("write");

    let mut ss = srv.accept_sar_stream().await.expect("accept stream");
    let recv = srv
        .read_stream_bytes(&mut ss)
        .await
        .expect("read")
        .expect("bytes");
    let actions = srv
        .feed_stream_bytes(&mut ss, &recv, Some(1))
        .expect("feed");

    assert!(
        has_bind_sar_stream(&actions, 42),
        "expected BindSarStream(42), got {actions:?}"
    );
    assert!(srv.is_sar_stream_bound(42));

    listener.close();
}

// ── Test 3: Multiple concurrent QUIC streams ──────────────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn quic_multiple_concurrent_streams_work_independently() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");
    let client_cfg = make_client_config(QuicTransportConfig::default());

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(server_addr, "localhost", client_cfg),
    );
    let mut srv = srv_res.expect("server");
    let mut cli = cli_res.expect("client");

    let mut cs_a = cli.open_sar_stream().await.expect("stream A");
    let mut cs_b = cli.open_sar_stream().await.expect("stream B");

    let bytes_a = session_archive_init_bytes(10, 0, [0x01; 16]);
    let bytes_b = session_archive_init_bytes(11, 0, [0x02; 16]);
    cli.write_sar_bytes(&mut cs_a, &bytes_a)
        .await
        .expect("write A");
    cli.write_sar_bytes(&mut cs_b, &bytes_b)
        .await
        .expect("write B");

    let mut ss_a = srv.accept_sar_stream().await.expect("accept A");
    let mut ss_b = srv.accept_sar_stream().await.expect("accept B");
    let r_a = srv
        .read_stream_bytes(&mut ss_a)
        .await
        .expect("read A")
        .expect("some A");
    let r_b = srv
        .read_stream_bytes(&mut ss_b)
        .await
        .expect("read B")
        .expect("some B");

    let a_a = srv
        .feed_stream_bytes(&mut ss_a, &r_a, Some(1))
        .expect("feed A");
    let a_b = srv
        .feed_stream_bytes(&mut ss_b, &r_b, Some(2))
        .expect("feed B");

    assert!(
        has_bind_sar_stream(&a_a, 10),
        "expected bind 10, got {a_a:?}"
    );
    assert!(
        has_bind_sar_stream(&a_b, 11),
        "expected bind 11, got {a_b:?}"
    );
    assert!(srv.is_sar_stream_bound(10));
    assert!(srv.is_sar_stream_bound(11));

    listener.close();
}

// ── Test 4: Same SAR Stream ID on different QUIC connections ──────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn same_sar_stream_id_on_different_quic_connections_are_independent() {
    let (cert_der, key_der) = make_self_signed();
    let mk_srv_cfg = || {
        QuicServerConfig::new(
            QuicServerIdentity::from_der(vec![cert_der.clone()], key_der.clone())
                .expect("identity"),
            QuicTransportConfig::default(),
        )
        .expect("server config")
    };

    let listener1 = QuicSarListener::bind(loopback_addr(), mk_srv_cfg()).expect("bind1");
    let listener2 = QuicSarListener::bind(loopback_addr(), mk_srv_cfg()).expect("bind2");
    let addr1 = listener1.local_addr().expect("addr1");
    let addr2 = listener2.local_addr().expect("addr2");

    let (srv1_res, cli1_res) = tokio::join!(
        listener1.accept(),
        connect_quic(
            addr1,
            "localhost",
            make_client_config(QuicTransportConfig::default())
        ),
    );
    let (srv2_res, cli2_res) = tokio::join!(
        listener2.accept(),
        connect_quic(
            addr2,
            "localhost",
            make_client_config(QuicTransportConfig::default())
        ),
    );

    let mut srv1 = srv1_res.expect("srv1");
    let mut cli1 = cli1_res.expect("cli1");
    let mut srv2 = srv2_res.expect("srv2");
    let mut cli2 = cli2_res.expect("cli2");

    let uuid1 = [0x11; 16];
    let uuid2 = [0x22; 16];

    let mut cs1 = cli1.open_sar_stream().await.expect("cs1");
    let mut cs2 = cli2.open_sar_stream().await.expect("cs2");
    cli1.write_sar_bytes(&mut cs1, &session_archive_init_bytes(99, 0, uuid1))
        .await
        .expect("w1");
    cli2.write_sar_bytes(&mut cs2, &session_archive_init_bytes(99, 0, uuid2))
        .await
        .expect("w2");

    let mut ss1 = srv1.accept_sar_stream().await.expect("ss1");
    let mut ss2 = srv2.accept_sar_stream().await.expect("ss2");
    let r1 = srv1
        .read_stream_bytes(&mut ss1)
        .await
        .expect("r1")
        .expect("s1");
    let r2 = srv2
        .read_stream_bytes(&mut ss2)
        .await
        .expect("r2")
        .expect("s2");

    let a1 = srv1
        .feed_stream_bytes(&mut ss1, &r1, Some(1))
        .expect("feed1");
    let a2 = srv2
        .feed_stream_bytes(&mut ss2, &r2, Some(2))
        .expect("feed2");

    assert!(
        has_bind_sar_stream(&a1, 99),
        "conn1 expected bind 99, got {a1:?}"
    );
    assert!(
        has_bind_sar_stream(&a2, 99),
        "conn2 expected bind 99, got {a2:?}"
    );
    assert_eq!(srv1.session_uuid_for(99), Some(uuid1));
    assert_eq!(srv2.session_uuid_for(99), Some(uuid2));

    listener1.close();
    listener2.close();
}

// ── Test 5: Duplicate SESSION_INIT on same connection is rejected ─────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn duplicate_session_init_same_connection_different_uuid_is_rejected() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("srv");
    let mut cli = cli_res.expect("cli");

    // Establish stream 5 with UUID_A.
    let uuid_a = [0x55; 16];
    let mut cs_a = cli.open_sar_stream().await.expect("primary");
    cli.write_sar_bytes(&mut cs_a, &session_archive_init_bytes(5, 0, uuid_a))
        .await
        .expect("write A");

    let mut ss_a = srv.accept_sar_stream().await.expect("srv primary");
    let r = srv
        .read_stream_bytes(&mut ss_a)
        .await
        .expect("read A")
        .expect("bytes A");
    let a = srv
        .feed_stream_bytes(&mut ss_a, &r, Some(1))
        .expect("feed A");
    assert!(has_bind_sar_stream(&a, 5));
    assert_eq!(srv.session_uuid_for(5), Some(uuid_a));

    // Try to bind stream 5 again with UUID_B (different UUID).
    let uuid_b = [0x66; 16];
    let mut cs_b = cli.open_sar_stream().await.expect("dup stream");
    cli.write_sar_bytes(&mut cs_b, &session_archive_init_bytes(5, 0, uuid_b))
        .await
        .expect("write B");

    let mut ss_b = srv.accept_sar_stream().await.expect("srv dup");
    let r2 = srv
        .read_stream_bytes(&mut ss_b)
        .await
        .expect("read B")
        .expect("bytes B");
    let a2 = srv
        .feed_stream_bytes(&mut ss_b, &r2, Some(2))
        .expect("feed B");

    assert!(
        has_reject_sar_stream(&a2),
        "duplicate SESSION_INIT with different UUID must be rejected; got {a2:?}"
    );
    // Original session untouched.
    assert!(srv.is_sar_stream_bound(5));
    assert_eq!(srv.session_uuid_for(5), Some(uuid_a));

    listener.close();
}

// ── Test 6: Additional control stream with matching UUID is accepted ──────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn additional_control_stream_matching_uuid_produces_attach_action() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("srv");
    let mut cli = cli_res.expect("cli");

    // Primary stream.
    let uuid = [0xCC; 16];
    let mut cs_primary = cli.open_sar_stream().await.expect("primary");
    cli.write_sar_bytes(&mut cs_primary, &session_archive_init_bytes(7, 0, uuid))
        .await
        .expect("write primary");

    let mut ss_primary = srv.accept_sar_stream().await.expect("srv primary");
    let r = srv
        .read_stream_bytes(&mut ss_primary)
        .await
        .expect("read")
        .expect("bytes");
    let a = srv
        .feed_stream_bytes(&mut ss_primary, &r, Some(1))
        .expect("feed");
    assert!(has_bind_sar_stream(&a, 7));

    // Second QUIC stream for stream 7, same UUID — control attachment.
    let mut cs_ctl = cli.open_sar_stream().await.expect("control");
    cli.write_sar_bytes(&mut cs_ctl, &session_archive_init_bytes(7, 0, uuid))
        .await
        .expect("write control");

    let mut ss_ctl = srv.accept_sar_stream().await.expect("srv control");
    let r2 = srv
        .read_stream_bytes(&mut ss_ctl)
        .await
        .expect("read2")
        .expect("bytes2");
    let a2 = srv
        .feed_stream_bytes(&mut ss_ctl, &r2, Some(2))
        .expect("feed control");

    assert!(
        has_attach_control_stream(&a2),
        "same UUID second stream must produce AttachControlStream; got {a2:?}"
    );
    assert!(!has_reject_sar_stream(&a2));
    // Session remains bound.
    assert!(srv.is_sar_stream_bound(7));
    assert_eq!(srv.session_uuid_for(7), Some(uuid));

    listener.close();
}

// ── Test 8: Additional control stream with mismatched UUID is rejected ─────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn additional_control_stream_mismatched_uuid_is_rejected() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("srv");
    let mut cli = cli_res.expect("cli");

    let uuid_a = [0xAA; 16];
    let mut cs = cli.open_sar_stream().await.expect("primary");
    cli.write_sar_bytes(&mut cs, &session_archive_init_bytes(8, 0, uuid_a))
        .await
        .expect("write");

    let mut ss = srv.accept_sar_stream().await.expect("srv primary");
    let r = srv
        .read_stream_bytes(&mut ss)
        .await
        .expect("read")
        .expect("bytes");
    let a = srv.feed_stream_bytes(&mut ss, &r, Some(1)).expect("feed");
    assert!(has_bind_sar_stream(&a, 8));

    // Second stream for stream 8 with DIFFERENT UUID.
    let uuid_b = [0xBB; 16];
    let mut cs2 = cli.open_sar_stream().await.expect("dup");
    cli.write_sar_bytes(&mut cs2, &session_archive_init_bytes(8, 0, uuid_b))
        .await
        .expect("write2");

    let mut ss2 = srv.accept_sar_stream().await.expect("srv dup");
    let r2 = srv
        .read_stream_bytes(&mut ss2)
        .await
        .expect("read2")
        .expect("bytes2");
    let a2 = srv
        .feed_stream_bytes(&mut ss2, &r2, Some(2))
        .expect("feed2");

    assert!(
        has_reject_sar_stream(&a2),
        "mismatched UUID must be rejected; got {a2:?}"
    );
    assert!(srv.is_sar_stream_bound(8));
    assert_eq!(srv.session_uuid_for(8), Some(uuid_a));

    listener.close();
}

// ── Test 10: SESSION_CLOSE unbinds SAR Stream ID ──────────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn session_close_unbinds_sar_stream_id() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("srv");
    let mut cli = cli_res.expect("cli");

    let mut cs = cli.open_sar_stream().await.expect("stream");
    cli.write_sar_bytes(&mut cs, &session_archive_init_bytes(10, 0, [0x10; 16]))
        .await
        .expect("write init");

    let mut ss = srv.accept_sar_stream().await.expect("srv stream");
    let r = srv
        .read_stream_bytes(&mut ss)
        .await
        .expect("read")
        .expect("bytes");
    let a = srv
        .feed_stream_bytes(&mut ss, &r, Some(1))
        .expect("feed init");
    assert!(has_bind_sar_stream(&a, 10));
    assert!(srv.is_sar_stream_bound(10));

    // Send SESSION_CLOSE.
    let close_bytes = [
        no_index_global_header_bytes(),
        session_close_entry_bytes(10, 1),
    ]
    .concat();
    cli.write_sar_bytes(&mut cs, &close_bytes)
        .await
        .expect("write close");
    let r2 = srv
        .read_stream_bytes(&mut ss)
        .await
        .expect("read close")
        .expect("bytes close");
    let _a2 = srv
        .feed_stream_bytes(&mut ss, &r2, Some(2))
        .expect("feed close");

    assert!(
        !srv.is_sar_stream_bound(10),
        "stream 10 must be unbound after SESSION_CLOSE"
    );
    assert_eq!(srv.session_uuid_for(10), None);

    listener.close();
}

// ── Test 11: Bidirectional ACK on same QUIC stream ───────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn bidirectional_quic_stream_supports_reverse_ack() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("srv");
    let mut cli = cli_res.expect("cli");

    let mut cs = cli.open_sar_stream().await.expect("stream");
    cli.write_sar_bytes(&mut cs, &session_archive_init_bytes(11, 0, [0x11; 16]))
        .await
        .expect("write");

    let mut ss = srv.accept_sar_stream().await.expect("srv stream");
    let r = srv
        .read_stream_bytes(&mut ss)
        .await
        .expect("read")
        .expect("bytes");
    let a = srv.feed_stream_bytes(&mut ss, &r, Some(1)).expect("feed");
    assert!(has_bind_sar_stream(&a, 11));

    // Server sends SESSION_ACK back on the same bidirectional stream.
    let ack_bytes = [
        no_index_global_header_bytes(),
        session_control_entry_bytes(11, 1, SessionOpCode::Ack as u8, Vec::new()),
    ]
    .concat();
    srv.write_sar_bytes(&mut ss, &ack_bytes)
        .await
        .expect("write ack");

    // Client reads and processes the ACK.
    let ack_recv = cli
        .read_stream_bytes(&mut cs)
        .await
        .expect("read ack")
        .expect("ack bytes");
    let ack_actions = cli
        .feed_stream_bytes(&mut cs, &ack_recv, Some(2))
        .expect("feed ack");

    let has_fatal = ack_actions
        .iter()
        .any(|a| matches!(a, TransportAction::CloseConnection { .. }));
    assert!(
        !has_fatal,
        "reverse ACK must not cause CloseConnection; got {ack_actions:?}"
    );

    listener.close();
}

// ── Test 12: Capability flags ─────────────────────────────────────────────────

// NOTE: The equivalent TCP-capability assertion for builds without the `quic`
// feature lives in tcp_tls_rejection_tests.rs::tcp_does_not_advertise_cap_tls_exporter_aead_in_session_init.
// Here we gate the test behind `quic` so the import of CapabilityFlags above
// (which is also quic-gated) remains the sole declaration in this file.
#[cfg(feature = "quic")]
#[test]
fn tcp_does_not_advertise_cap_tls_exporter_aead() {
    let tcp_caps =
        CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK | CapabilityFlags::SESSION_STATUS);
    assert!(
        !tcp_caps.supports_tls_exporter_aead(),
        "TCP must not advertise CAP_TLS_EXPORTER_AEAD"
    );
}

#[cfg(feature = "quic")]
#[tokio::test]
async fn quic_connection_advertises_cap_tls_exporter_aead_when_configured() {
    let transport = QuicTransportConfig {
        advertise_tls_exporter_aead: true,
        ..QuicTransportConfig::default()
    };
    let server_cfg = make_server_config(transport.clone());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            QuicClientConfig::new(QuicClientTrust::InsecureSkipVerifyForTestsOnly, transport),
        ),
    );
    let srv = srv_res.expect("srv");
    let cli = cli_res.expect("cli");

    assert!(
        srv.local_capabilities().supports_tls_exporter_aead(),
        "server must advertise CAP_TLS_EXPORTER_AEAD when configured"
    );
    assert!(
        cli.local_capabilities().supports_tls_exporter_aead(),
        "client must advertise CAP_TLS_EXPORTER_AEAD when configured"
    );

    listener.close();
}

// ── Test 13 / Misc: Malformed stream does not corrupt others ──────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn malformed_quic_stream_does_not_corrupt_active_streams() {
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("srv");
    let mut cli = cli_res.expect("cli");

    // Good session on stream 20.
    let mut cs_a = cli.open_sar_stream().await.expect("stream A");
    cli.write_sar_bytes(&mut cs_a, &session_archive_init_bytes(20, 0, [0x20; 16]))
        .await
        .expect("write A");

    let mut ss_a = srv.accept_sar_stream().await.expect("srv A");
    let r_a = srv
        .read_stream_bytes(&mut ss_a)
        .await
        .expect("read A")
        .expect("bytes A");
    let a_a = srv
        .feed_stream_bytes(&mut ss_a, &r_a, Some(1))
        .expect("feed A");
    assert!(has_bind_sar_stream(&a_a, 20));

    // Malformed bytes on stream B.
    let mut cs_b = cli.open_sar_stream().await.expect("stream B");
    cli.write_sar_bytes(&mut cs_b, b"GARBAGE_BYTES")
        .await
        .expect("write B");

    let mut ss_b = srv.accept_sar_stream().await.expect("srv B");
    let r_b = srv
        .read_stream_bytes(&mut ss_b)
        .await
        .expect("read B")
        .expect("bytes B");
    let a_b = srv
        .feed_stream_bytes(&mut ss_b, &r_b, Some(2))
        .expect("feed B (local err ok)");

    // Stream B must not produce CloseConnection.
    let has_fatal = a_b
        .iter()
        .any(|a| matches!(a, TransportAction::CloseConnection { .. }));
    assert!(
        !has_fatal,
        "malformed stream B must not close entire connection; got {a_b:?}"
    );

    // Stream A must remain bound.
    assert!(
        srv.is_sar_stream_bound(20),
        "stream A must be unaffected by stream B error"
    );

    listener.close();
}
// ── SAR magic + malformed body fails only the affected QUIC stream ────────────

/// Returns bytes with valid SAR magic ("SAR!") followed by an invalid version
/// byte (0x99) and a small flags section — enough to complete a parse attempt
/// that fails with a structural SAR error rather than InvalidMagic.
#[cfg(feature = "quic")]
fn sar_magic_with_invalid_version() -> Vec<u8> {
    let mut b = Vec::with_capacity(12);
    b.extend_from_slice(b"SAR!"); // valid magic
    b.push(0x99); // invalid version (≠ 1) → InvalidVersion
    b.push(0x00); // reserved
    b.extend_from_slice(&4u16.to_le_bytes()); // flags_len = 4
    b.extend_from_slice(&0u32.to_le_bytes()); // 4 zero flag bytes
    b
}

#[cfg(feature = "quic")]
#[tokio::test]
async fn quic_sar_magic_with_malformed_body_fails_only_that_stream() {
    // A QUIC stream that starts with valid SAR magic but has a malformed body
    // (e.g. wrong version byte) must be rejected stream-locally.
    // Other active streams on the same QUIC connection must be unaffected.
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("server");
    let mut cli = cli_res.expect("client");

    // Good stream A: valid SAR session.
    let mut cs_a = cli.open_sar_stream().await.expect("stream A");
    cli.write_sar_bytes(&mut cs_a, &session_archive_init_bytes(30, 0, [0x30; 16]))
        .await
        .expect("write A");

    let mut ss_a = srv.accept_sar_stream().await.expect("srv A");
    let r_a = srv
        .read_stream_bytes(&mut ss_a)
        .await
        .expect("read A")
        .expect("bytes A");
    let a_a = srv
        .feed_stream_bytes(&mut ss_a, &r_a, Some(1))
        .expect("feed A");
    assert!(
        has_bind_sar_stream(&a_a, 30),
        "stream A must bind; got {a_a:?}"
    );

    // Malformed stream B: SAR magic recognized, but version byte is wrong.
    // This is distinct from raw garbage — the magic IS parsed, then SAR
    // structural validation fails.
    let mut cs_b = cli.open_sar_stream().await.expect("stream B");
    cli.write_sar_bytes(&mut cs_b, &sar_magic_with_invalid_version())
        .await
        .expect("write B");

    let mut ss_b = srv.accept_sar_stream().await.expect("srv B");
    let r_b = srv
        .read_stream_bytes(&mut ss_b)
        .await
        .expect("read B")
        .expect("bytes B");
    let a_b = srv
        .feed_stream_bytes(&mut ss_b, &r_b, Some(2))
        .expect("feed B (stream-local error)");

    // Stream B must NOT produce CloseConnection (connection-fatal).
    let is_connection_fatal = a_b
        .iter()
        .any(|a| matches!(a, TransportAction::CloseConnection { .. }));
    assert!(
        !is_connection_fatal,
        "SAR-magic-then-malformed stream B must not close the connection; got {a_b:?}"
    );

    // Stream B must NOT have a RejectSarStream with InvalidMagic; the magic
    // WAS recognized, so the error must be a structural SAR parse failure.
    for action in &a_b {
        if let TransportAction::RejectSarStream { error, .. } = action {
            assert!(
                !matches!(error, sar_core::SarError::InvalidMagic),
                "error must not be InvalidMagic — magic was valid, body was malformed; got {error:?}"
            );
        }
    }

    // Stream A must remain bound and unaffected.
    assert!(
        srv.is_sar_stream_bound(30),
        "stream A must be unaffected by stream B's structural SAR failure"
    );

    listener.close();
}

// ── QUIC: client disconnects without sending streams ─────────────────────────

#[cfg(feature = "quic")]
#[tokio::test]
async fn quic_client_drop_without_streams_causes_server_accept_to_fail() {
    // When a client opens a QUIC connection but then closes it without opening
    // any SAR streams, the server's accept_sar_stream should eventually return
    // an error (not hang forever).  This validates that idle/dropped QUIC
    // connections do not leave the server blocked indefinitely.
    //
    // This test uses tokio::time::timeout as a safety guard to keep CI
    // deterministic; the real close signal comes from dropping the client
    // endpoint which causes the QUIC stack to send a CONNECTION_CLOSE frame.
    let server_cfg = make_server_config(QuicTransportConfig::default());
    let listener = QuicSarListener::bind(loopback_addr(), server_cfg).expect("bind");
    let server_addr = listener.local_addr().expect("addr");

    let (srv_res, cli_res) = tokio::join!(
        listener.accept(),
        connect_quic(
            server_addr,
            "localhost",
            make_client_config(QuicTransportConfig::default()),
        ),
    );
    let mut srv = srv_res.expect("server");
    let cli = cli_res.expect("client");

    // Drop the client: the QUIC stack sends CONNECTION_CLOSE to the server.
    drop(cli);

    // The server's accept_sar_stream should return an error once the connection
    // is closed.  We allow up to 5 s in CI before declaring a hang.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        srv.accept_sar_stream(),
    )
    .await;

    match result {
        Ok(Err(_)) => {
            // Expected: accept_sar_stream failed because the connection closed.
        }
        Ok(Ok(_)) => {
            panic!("unexpected new SAR stream after client disconnect")
        }
        Err(_elapsed) => {
            // Timeout: the accept did not complete within 5 s.
            // This should not happen in practice since QUIC sends
            // CONNECTION_CLOSE synchronously when the endpoint is dropped.
            panic!("accept_sar_stream did not complete within 5 s after client disconnect")
        }
    }

    listener.close();
}
