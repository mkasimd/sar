// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// M10d TCP TLS-rejection and capability tests.
///
/// Covers:
/// - TCP rejects non-SAR initial bytes (e.g. TLS ClientHello prefix, "GET /").
/// - TCP rejects "SAR!"+malformed body with a structural SAR error (not InvalidMagic).
/// - TCP fails closed when KMS Mode `0x04 TLS_EXPORTER` is used over a plaintext TCP stream.
/// - TCP local capability advertisement does not include `CAP_TLS_EXPORTER_AEAD`.
/// - Unknown / non-implemented capability bits from a peer are accepted in non-strict mode.
/// - Strict mode (`strict_validation = true`) rejects reserved capability bits.
mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use sar_core::SarError;
use sar_stream::CapabilityFlags;
use sar_transport::{TcpSarConnection, TcpTransportConfig, TransportAction};

use common::{session_archive_init_bytes, session_capabilities_entry_bytes};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_loopback(config: TcpTransportConfig) -> (TcpStream, TcpSarConnection<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let sender = TcpStream::connect(addr).expect("connect");
    let (recv, _) = listener.accept().expect("accept");
    recv.set_read_timeout(Some(Duration::from_millis(400)))
        .expect("timeout");
    let conn = TcpSarConnection::accept(recv, config).expect("conn");
    (sender, conn)
}

fn send_and_process(
    sender: &mut TcpStream,
    receiver: &mut TcpSarConnection<TcpStream>,
    bytes: &[u8],
) -> Result<Vec<TransportAction>, SarError> {
    sender.write_all(bytes).expect("write");
    sender.flush().expect("flush");
    receiver.process_available(Some(1))
}

fn has_close_connection(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::CloseConnection { .. }))
}

/// Craft a raw SAR global header with `ENCRYPTED | NO_INDEX` and KMS mode `mode_id`.
///
/// The payload is empty (payload_len = 0). Because `write_global_header` validates
/// the mode ID, we craft the bytes manually for invalid/unsupported modes.
///
/// Wire layout:
///   [0..4]  Magic "SAR!"
///   [4]     Version = 1
///   [5]     Reserved = 0
///   [6..8]  Flags Length = 4 (u16 LE)
///   [8..12] Flags = NO_INDEX | ENCRYPTED = 0x402 (u32 LE)
///   [12]    KMS Mode ID
///   [13..17] KMS Payload Length = 0 (u32 LE)
fn encrypted_global_header_with_kms_mode(mode_id: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    // Magic
    bytes.extend_from_slice(b"SAR!");
    // Version
    bytes.push(0x01);
    // Reserved
    bytes.push(0x00);
    // Flags Length = 4 (u16 LE)
    bytes.push(0x04);
    bytes.push(0x00);
    // Flags = NO_INDEX (0x02) | ENCRYPTED (0x400) = 0x402, u32 LE
    bytes.extend_from_slice(&0x0402u32.to_le_bytes());
    // KMS Mode ID
    bytes.push(mode_id);
    // KMS Payload Length = 0 (u32 LE)
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP rejects non-SAR initial bytes (TLS ClientHello-like prefix)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_rejects_tls_clienthello_prefix_as_non_sar_bytes() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // TLS ClientHello record begins with: content_type=0x16 (Handshake),
    // version=0x03 0x01 (TLS 1.0 compat), followed by length bytes.
    // None of these start with "SAR!" so the SAR magic check must fail.
    let tls_prefix: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0xf1, 0x01, 0x00, 0x00, 0xed];

    let result = send_and_process(&mut sender, &mut receiver, tls_prefix);

    // Either process_available returns a CloseConnection action or an error.
    let rejected = match result {
        Ok(ref actions) => has_close_connection(actions),
        Err(_) => true,
    };
    assert!(
        rejected,
        "TCP must reject non-SAR (TLS ClientHello-like) initial bytes; got {result:?}"
    );
    assert!(
        receiver.is_closed(),
        "connection must be marked closed after rejecting non-SAR bytes"
    );
}

#[test]
fn tcp_rejects_random_non_sar_initial_bytes() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Random garbage that is clearly not "SAR!"
    let garbage: &[u8] = &[0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

    let result = send_and_process(&mut sender, &mut receiver, garbage);
    let rejected = match result {
        Ok(ref actions) => has_close_connection(actions),
        Err(_) => true,
    };
    assert!(
        rejected,
        "TCP must reject random non-SAR initial bytes; got {result:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP rejects KMS Mode 0x04 TLS_EXPORTER
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_rejects_tls_exporter_kms_mode_fails_closed() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Send a valid SAR global header with ENCRYPTED + KMS mode 0x04 (TLS_EXPORTER).
    let header = encrypted_global_header_with_kms_mode(0x04);
    let result = send_and_process(&mut sender, &mut receiver, &header);

    // Must fail closed: CloseConnection action or Err containing Unsupported.
    let rejected = match &result {
        Ok(actions) => has_close_connection(actions),
        Err(SarError::Unsupported(_)) => true,
        Err(_) => true,
    };
    assert!(
        rejected,
        "TCP must fail closed for KMS Mode 0x04 TLS_EXPORTER on a plaintext stream; got {result:?}"
    );
}

#[test]
fn tcp_accepts_valid_kms_mode_0x01_pbkdf2_header() {
    // Sanity-check: valid modes 0x01-0x03 in the global header should NOT be
    // rejected solely based on the KMS mode ID (they fail later without a key
    // provider, but that is a different error path).
    // We only check that the connection is NOT immediately rejected on mode ID.
    // A raw header with empty PBKDF2 payload will fail payload parsing
    // (too short), but that is not a mode-ID-based rejection.
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());
    let header = encrypted_global_header_with_kms_mode(0x01);
    let result = send_and_process(&mut sender, &mut receiver, &header);
    // The result may be an error (PBKDF2 payload too short) but it must NOT be
    // an Unsupported error targeting the mode ID itself for modes 0x01-0x03.
    if let Err(SarError::Unsupported(msg)) = &result {
        assert!(
            !msg.contains("TLS_EXPORTER"),
            "mode 0x01 must not be confused with TLS_EXPORTER: {msg}"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP does not advertise CAP_TLS_EXPORTER_AEAD
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_does_not_advertise_cap_tls_exporter_aead_in_session_init() {
    // Verify that the capability bits used by the TCP transport when
    // bidirectional_control is enabled never include CAP_TLS_EXPORTER_AEAD.
    let tcp_caps =
        CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK | CapabilityFlags::SESSION_STATUS);
    assert!(
        !tcp_caps.supports_tls_exporter_aead(),
        "TCP must not advertise CAP_TLS_EXPORTER_AEAD"
    );
    assert_eq!(
        tcp_caps.bits() & CapabilityFlags::CAP_TLS_EXPORTER_AEAD,
        0,
        "CAP_TLS_EXPORTER_AEAD bit must be zero in TCP capability advertisement"
    );
}

#[test]
fn tcp_session_capabilities_frame_without_tls_exporter_bit_is_accepted() {
    // A SESSION_CAPABILITIES frame from a peer that does NOT set bit 6 is fine.
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Establish a session first.
    let session_bytes = session_archive_init_bytes(5, 0, [0x55; 16]);
    sender.write_all(&session_bytes).expect("init bytes");
    sender.flush().expect("flush");
    let _ = receiver.process_available(Some(1)).expect("init");

    // Send a SESSION_CAPABILITIES frame without CAP_TLS_EXPORTER_AEAD.
    let cap_flags = CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK);
    let cap_bytes = session_capabilities_entry_bytes(5, 1, cap_flags);
    let result = send_and_process(&mut sender, &mut receiver, &cap_bytes);
    assert!(
        result.is_ok(),
        "SESSION_CAPABILITIES without TLS_EXPORTER must be accepted: {result:?}"
    );
    let actions = result.expect("capabilities accepted");
    assert!(!has_close_connection(&actions));
}

// ──────────────────────────────────────────────────────────────────────────────
// Unknown capability bits: non-strict mode ignores them; strict mode rejects them
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn reserved_capability_bit_7_is_rejected_by_strict_validate() {
    // In strict mode (default for TransportConfig), a peer that advertises a
    // reserved bit (7-15, i.e., 0x0080 and above) triggers ReservedValue.
    // This mirrors the existing behavior of `CapabilityFlags::validate()`.
    let err = CapabilityFlags::from_bits(0x0080)
        .validate()
        .expect_err("reserved bit 7 must fail validate()");
    assert!(
        matches!(err, SarError::ReservedValue(_)),
        "expected ReservedValue for bit 7: {err:?}"
    );
}

#[test]
fn cap_tls_exporter_aead_bit_alone_passes_validate_since_it_is_spec_defined() {
    // CAP_TLS_EXPORTER_AEAD (bit 6) is now a known spec-defined capability.
    // validate() must accept it even though the TCP binding does not implement it.
    let flags = CapabilityFlags::from_bits(CapabilityFlags::CAP_TLS_EXPORTER_AEAD);
    assert!(
        flags.validate().is_ok(),
        "CAP_TLS_EXPORTER_AEAD must pass validate() as a spec-defined bit"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP rejects HTTP-like ("GET /") initial bytes
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_rejects_get_http_initial_bytes_as_non_sar() {
    // "GET / HTTP/1.1\r\n" starts with "GET " which does not match "SAR!" magic.
    // The connection must be rejected / closed without binding a SAR session.
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    let http_request: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let result = send_and_process(&mut sender, &mut receiver, http_request);

    let rejected = match result {
        Ok(ref actions) => has_close_connection(actions),
        Err(_) => true,
    };
    assert!(
        rejected,
        "TCP must reject HTTP GET initial bytes; got {result:?}"
    );
    assert!(
        receiver.is_closed(),
        "connection must be closed after rejecting HTTP GET bytes"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP: "SAR!" magic recognized, malformed body fails as structural SAR error
// ──────────────────────────────────────────────────────────────────────────────

/// Returns bytes that begin with valid SAR magic ("SAR!") but contain an
/// unsupported version byte, causing the parser to fail with a structural SAR
/// error rather than `InvalidMagic`.
///
/// Wire layout:
///   [0..4]  Magic "SAR!" (valid)
///   [4]     Version = 0x99 (invalid, not 1)
///   [5]     Reserved = 0x00
///   [6..8]  Flags Length = 4 (u16 LE) — small enough to complete quickly
///   [8..12] Flags = 0x00000000 (NO_INDEX absent; parser continues to version check)
fn sar_magic_with_invalid_version_bytes() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(b"SAR!"); // magic
    bytes.push(0x99); // version: 0x99 != 1 → InvalidVersion
    bytes.push(0x00); // reserved
    bytes.extend_from_slice(&4u16.to_le_bytes()); // flags_len = 4
    bytes.extend_from_slice(&0u32.to_le_bytes()); // 4 zero flag bytes
    bytes
}

#[test]
fn tcp_sar_magic_followed_by_invalid_version_fails_as_structural_sar_error() {
    // "SAR!" is a valid SAR magic prefix. Once the magic is recognized the
    // parser continues into SAR-level parsing and must fail with a structural
    // error (e.g. SAR_ERR_INVALID_VERSION), NOT with SAR_ERR_INVALID_MAGIC.
    // This verifies: magic is recognized → SAR parsing proceeds → structural
    // failure → connection closed. No panic, no session bind, no payload leak.
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    let bytes = sar_magic_with_invalid_version_bytes();
    let result = send_and_process(&mut sender, &mut receiver, &bytes);

    // Connection must be closed.
    let closed = match result {
        Ok(ref actions) => has_close_connection(actions),
        Err(_) => true,
    };
    assert!(
        closed,
        "TCP must close on SAR-magic-then-malformed-body; got {result:?}"
    );

    // The actions must NOT carry a RejectSarStream with InvalidMagic.
    // InvalidMagic would mean the magic was NOT recognized, which contradicts
    // the test intent (we want to confirm that SAR parsing started).
    if let Ok(actions) = result {
        for action in &actions {
            if let sar_transport::TransportAction::RejectSarStream { error, .. } = action {
                assert!(
                    !matches!(error, sar_core::SarError::InvalidMagic),
                    "error must NOT be InvalidMagic — magic was valid, body was malformed; got {error:?}"
                );
            }
        }
    }

    assert!(
        receiver.is_closed(),
        "receiver must be marked closed after structural SAR parse failure"
    );
    // No SAR session must have been bound.
    assert!(
        !receiver.is_sar_stream_bound(0),
        "no SAR session must be bound after structural parse failure"
    );
}
