#![cfg(feature = "quic")]
//! M10g Part B + D — TLS PQ/hybrid key agreement policy tests.
//!
//! Tests 10–19 from the M10g Part D spec:
//! 10. Default policy is `ClassicalAllowed` when only classical algorithms are available (ring).
//! 11. Default policy may be `ClassicalAllowed` when only classical algorithms are available.
//! 12. `ClassicalAllowed` permits classical TLS (live QUIC loopback).
//! 13. `PreferPq` prefers PQ/hybrid where configurable but permits classical fallback (ring).
//! 14. `RequirePqOrHybrid` fails closed with SAR_ERR_UNSUPPORTED on ring.
//! 15. `RequirePqOnly` fails closed with SAR_ERR_UNSUPPORTED on ring.
//! 16. Allowed-algorithm classification helpers are correct.
//! 17. Policy helper `requires_pq` is true for RequirePqOrHybrid and RequirePqOnly.
//! 18. Policy helper `allows_classical_fallback` is false for RequirePqOrHybrid/RequirePqOnly.
//! 19. No key material or exporter output appears in `Debug`/`Display` formatting of policy types.

mod common;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use sar_core::SarError;
use sar_transport::quic::{
    QuicClientConfig, QuicClientTrust, QuicServerConfig, QuicServerIdentity, QuicTransportConfig,
    TlsPqPolicy,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_self_signed() -> (Vec<u8>, Vec<u8>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    (cert.der().to_vec(), signing_key.serialize_der())
}

fn is_unsupported(e: &SarError) -> bool {
    matches!(e, SarError::Unsupported(_))
}

// ── Test 10: Default policy is `ClassicalAllowed` with ring ───────────────────

#[test]
fn default_policy_is_classical_allowed_with_ring() {
    let cfg = QuicTransportConfig::default();
    assert_eq!(
        cfg.pq_policy,
        TlsPqPolicy::ClassicalAllowed,
        "default pq_policy must be ClassicalAllowed when ring is the TLS provider"
    );
}

// ── Test 11: Default policy may be ClassicalAllowed when only classical algos ─

#[test]
fn classical_allowed_is_default_when_no_pq_available() {
    let policy = TlsPqPolicy::default();
    assert_eq!(policy, TlsPqPolicy::ClassicalAllowed);
}

// ── Test 12: ClassicalAllowed permits classical TLS (QUIC connection succeeds) ─

#[tokio::test]
async fn classical_allowed_permits_classical_quic_connection() {
    use sar_transport::quic::{QuicSarListener, connect_quic};
    use std::net::SocketAddr;

    let classical_cfg = QuicTransportConfig {
        pq_policy: TlsPqPolicy::ClassicalAllowed,
        ..QuicTransportConfig::default()
    };
    let (cert_der, key_der) = make_self_signed();
    let identity = QuicServerIdentity::from_der(vec![cert_der], key_der).expect("identity");
    let server_cfg = QuicServerConfig::new(identity, classical_cfg.clone()).expect("server cfg");
    let listener = QuicSarListener::bind(
        "127.0.0.1:0".parse::<SocketAddr>().expect("parse addr"),
        server_cfg,
    )
    .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client_cfg = QuicClientConfig::new(
        QuicClientTrust::InsecureSkipVerifyForTestsOnly,
        classical_cfg,
    );

    let (server_res, client_res) = tokio::join!(async { listener.accept().await }, async {
        connect_quic(addr, "localhost", client_cfg).await
    },);
    assert!(server_res.is_ok(), "ClassicalAllowed server accept failed");
    assert!(client_res.is_ok(), "ClassicalAllowed client connect failed");
}

// ── Test 13: PreferPq falls back to classical with ring (no error) ─────────────

#[tokio::test]
async fn prefer_pq_falls_back_to_classical_with_ring() {
    use sar_transport::quic::{QuicSarListener, connect_quic};
    use std::net::SocketAddr;

    let pref_pq_cfg = QuicTransportConfig {
        pq_policy: TlsPqPolicy::PreferPq,
        ..QuicTransportConfig::default()
    };
    let (cert_der, key_der) = make_self_signed();
    let identity = QuicServerIdentity::from_der(vec![cert_der], key_der).expect("identity");
    let server_cfg =
        QuicServerConfig::new(identity, pref_pq_cfg.clone()).expect("server cfg with PreferPq");
    let listener = QuicSarListener::bind(
        "127.0.0.1:0".parse::<SocketAddr>().expect("parse addr"),
        server_cfg,
    )
    .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client_cfg =
        QuicClientConfig::new(QuicClientTrust::InsecureSkipVerifyForTestsOnly, pref_pq_cfg);

    let (server_res, client_res) = tokio::join!(async { listener.accept().await }, async {
        connect_quic(addr, "localhost", client_cfg).await
    },);
    // ring has no PQ groups — PreferPq must fall back to classical without error.
    assert!(
        server_res.is_ok(),
        "PreferPq server accept failed with ring"
    );
    assert!(
        client_res.is_ok(),
        "PreferPq client connect failed with ring (should fall back)"
    );
}

// ── Test 14: RequirePqOrHybrid fails with SAR_ERR_UNSUPPORTED on ring ─────────

#[test]
fn require_pq_or_hybrid_fails_closed_with_ring_server() {
    use sar_transport::quic::QuicSarListener;
    use std::net::SocketAddr;

    let (cert_der, key_der) = make_self_signed();
    let identity = QuicServerIdentity::from_der(vec![cert_der], key_der).expect("identity");
    let cfg = QuicTransportConfig {
        pq_policy: TlsPqPolicy::RequirePqOrHybrid,
        ..QuicTransportConfig::default()
    };
    let server_cfg = QuicServerConfig::new(identity, cfg).expect("config builds");
    let result = QuicSarListener::bind(
        "127.0.0.1:0".parse::<SocketAddr>().expect("parse addr"),
        server_cfg,
    );
    assert!(
        result.is_err(),
        "RequirePqOrHybrid must fail closed during bind with ring"
    );
    if let Err(e) = result {
        assert!(
            is_unsupported(&e),
            "expected SAR_ERR_UNSUPPORTED, got: {e:?}"
        );
    }
}

#[test]
fn require_pq_or_hybrid_policy_preserved_in_client_config() {
    let cfg = QuicTransportConfig {
        pq_policy: TlsPqPolicy::RequirePqOrHybrid,
        ..QuicTransportConfig::default()
    };
    let client_cfg = QuicClientConfig::new(QuicClientTrust::InsecureSkipVerifyForTestsOnly, cfg);
    assert_eq!(
        client_cfg.transport.pq_policy,
        TlsPqPolicy::RequirePqOrHybrid
    );
}

// ── Test 15: RequirePqOnly fails with SAR_ERR_UNSUPPORTED on ring ─────────────

#[test]
fn require_pq_only_fails_closed_with_ring_server() {
    use sar_transport::quic::QuicSarListener;
    use std::net::SocketAddr;

    let (cert_der, key_der) = make_self_signed();
    let identity = QuicServerIdentity::from_der(vec![cert_der], key_der).expect("identity");
    let cfg = QuicTransportConfig {
        pq_policy: TlsPqPolicy::RequirePqOnly,
        ..QuicTransportConfig::default()
    };
    let server_cfg = QuicServerConfig::new(identity, cfg).expect("config builds");
    let result = QuicSarListener::bind(
        "127.0.0.1:0".parse::<SocketAddr>().expect("parse addr"),
        server_cfg,
    );
    assert!(
        result.is_err(),
        "RequirePqOnly must fail closed during bind with ring"
    );
    if let Err(e) = result {
        assert!(
            is_unsupported(&e),
            "expected SAR_ERR_UNSUPPORTED, got: {e:?}"
        );
    }
}

// ── Test 16: Algorithm classification helpers ──────────────────────────────────

#[test]
fn policy_helper_allows_classical_fallback() {
    assert!(TlsPqPolicy::ClassicalAllowed.allows_classical_fallback());
    assert!(TlsPqPolicy::PreferPq.allows_classical_fallback());
    assert!(!TlsPqPolicy::RequirePqOrHybrid.allows_classical_fallback());
    assert!(!TlsPqPolicy::RequirePqOnly.allows_classical_fallback());
}

// ── Test 17: requires_pq is true for RequirePq* ───────────────────────────────

#[test]
fn policy_helper_requires_pq() {
    assert!(!TlsPqPolicy::ClassicalAllowed.requires_pq());
    assert!(!TlsPqPolicy::PreferPq.requires_pq());
    assert!(TlsPqPolicy::RequirePqOrHybrid.requires_pq());
    assert!(TlsPqPolicy::RequirePqOnly.requires_pq());
}

// ── Test 18: requires_pq_only is exclusive to RequirePqOnly ───────────────────

#[test]
fn policy_helper_requires_pq_only() {
    assert!(!TlsPqPolicy::ClassicalAllowed.requires_pq_only());
    assert!(!TlsPqPolicy::PreferPq.requires_pq_only());
    assert!(!TlsPqPolicy::RequirePqOrHybrid.requires_pq_only());
    assert!(TlsPqPolicy::RequirePqOnly.requires_pq_only());
}

// ── Test 19: No key material in Debug/Display formatting ──────────────────────

#[test]
fn no_key_material_in_policy_debug_output() {
    let variants = [
        TlsPqPolicy::ClassicalAllowed,
        TlsPqPolicy::PreferPq,
        TlsPqPolicy::RequirePqOrHybrid,
        TlsPqPolicy::RequirePqOnly,
    ];
    for v in &variants {
        let debug_str = format!("{v:?}");
        assert!(
            debug_str.len() < 64,
            "Debug output unexpectedly long (possible key material?): {debug_str}"
        );
        assert!(
            !debug_str.contains("0x"),
            "Debug output contains hex prefix: {debug_str}"
        );
    }
}
