// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// M10i additional-control-stream AEAD decryption tests.
///
/// These tests exercise the real `InMemoryTransport::feed_bytes` →
/// `run_additional_control_stream_loop` path and verify that:
///
/// 1. Truly AEAD-encrypted `SESSION_ACK`, `SESSION_STATUS`, and
///    `SESSION_CAPABILITIES` entries are **decrypted** and successfully
///    processed (decrypted plaintext, not ciphertext, is passed to
///    `SessionManager`).
/// 2. Plaintext entries on an additional control stream after TLS_EXPORTER
///    binding is active are rejected with `AuthFailed`.
/// 3. Structurally-encrypted entries (ENCRYPTED bit set) with random or
///    malformed payload are rejected with `AuthFailed`.
/// 4. Entries encrypted with an incorrect AEAD tag are rejected.
/// 5. Entries encrypted with wrong LFH bytes as AAD are rejected.
/// 6. Entries encrypted with wrong Global Header bytes as AAD are rejected.
/// 7. AEAD failure does not expose plaintext (the result is always `Err`).
/// 8. `CTL!` remains rejected.
///
/// **Test quality invariant**: every test in this file MUST fail if
/// `run_additional_control_stream_loop` merely checks `EntryMode::ENCRYPTED`
/// and forwards the raw (ciphertext) bytes to `SessionManager::process_entry`
/// without performing AEAD decryption.
mod common;

use std::sync::Arc;

use sar_core::SarStatus;
use sar_stream::{AckFlags, CapabilityFlags, SessionAckFrame, SessionOpCode, SessionStatusFrame};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

use common::{
    MockTlsExporterKeyProvider, TEST_KEY, tls_exporter_encrypted_control_entry_bad_tag,
    tls_exporter_encrypted_control_entry_bytes,
    tls_exporter_encrypted_control_entry_random_payload,
    tls_exporter_encrypted_control_entry_wrong_gh_aad,
    tls_exporter_encrypted_control_entry_wrong_lfh_aad, tls_exporter_plaintext_control_entry_bytes,
    tls_exporter_session_archive_init_bytes,
};

// ── Shared setup helpers ──────────────────────────────────────────────────────

fn setup_tls_exporter_session(stream_id: u16, session_uuid: [u8; 16]) -> InMemoryTransport {
    let mut t = InMemoryTransport::new_quic(TransportConfig {
        bidirectional_control: true,
        ..TransportConfig::default()
    })
    .with_key_provider(Arc::new(MockTlsExporterKeyProvider { key: TEST_KEY }));
    t.open_transport_stream(TransportStreamId(1))
        .expect("open primary stream");
    let actions = t
        .feed_bytes(
            TransportStreamId(1),
            &tls_exporter_session_archive_init_bytes(stream_id, session_uuid),
            Some(1),
        )
        .expect("feed archive init");
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == stream_id)),
        "SESSION_INIT must bind; actions: {actions:?}"
    );
    assert!(t.is_tls_exporter_bound(stream_id));
    t
}

fn open_control_stream(t: &mut InMemoryTransport, tsid: TransportStreamId) {
    t.open_transport_stream(tsid).expect("open control stream");
}

fn ack_payload(ref_seq: u16) -> Vec<u8> {
    SessionAckFrame {
        ref_sequence: ref_seq,
        flags: AckFlags::from_bits(0),
    }
    .to_bytes()
    .expect("ack payload")
}

fn status_payload(ref_seq: u16) -> Vec<u8> {
    SessionStatusFrame {
        ref_sequence: ref_seq,
        status: sar_core::SarStatus::Ok,
        message: vec![],
    }
    .to_bytes(&sar_core::ResourceLimits::default())
    .expect("status payload")
}

fn capabilities_payload() -> Vec<u8> {
    sar_stream::SessionCapabilitiesFrame {
        flags: CapabilityFlags::from_bits(CapabilityFlags::BIDIRECTIONAL_CONTROL),
    }
    .to_bytes()
    .expect("caps payload")
}

fn has_auth_failed(actions: &[TransportAction]) -> bool {
    actions.iter().any(|a| match a {
        TransportAction::RejectSarStream { error, .. }
        | TransportAction::ResetTransportStream { error, .. }
        | TransportAction::CloseConnection { error } => error.status() == SarStatus::ErrAuthFailed,
        _ => false,
    })
}

fn has_any_reject_or_reset(actions: &[TransportAction]) -> bool {
    actions.iter().any(|a| {
        matches!(
            a,
            TransportAction::RejectSarStream { .. }
                | TransportAction::ResetTransportStream { .. }
                | TransportAction::CloseConnection { .. }
        )
    })
}

// ── Test 1: Encrypted SESSION_ACK is decrypted and processed ─────────────────

/// A truly AEAD-encrypted `SESSION_ACK` on an additional control stream MUST
/// be authenticated, decrypted, and successfully processed by `SessionManager`.
///
/// **Quality invariant**: if the implementation forwards the raw ciphertext
/// bytes to `SessionManager` without decryption, `SessionManager` will fail to
/// parse the ACK frame (ciphertext ≠ valid session frame) and emit a
/// `ResetTransportStream`.  The test checks `!has_any_reject_or_reset`, which
/// would fail in that case.
#[test]
fn aead_encrypted_session_ack_on_additional_control_stream_is_decrypted_and_processed() {
    let mut t = setup_tls_exporter_session(1, [0x01; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let entry = tls_exporter_encrypted_control_entry_bytes(
        1,
        0,
        SessionOpCode::Ack as u8,
        ack_payload(0),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed encrypted ACK");

    assert!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::AttachControlStream {
                sar_stream_id: 1,
                ..
            }
        )),
        "AttachControlStream must be emitted on first entry; actions: {actions:?}"
    );
    assert!(
        !has_any_reject_or_reset(&actions),
        "encrypted SESSION_ACK must be decrypted and processed without rejection; \
         actions: {actions:?}"
    );
}

// ── Test 2: Encrypted SESSION_STATUS is decrypted and processed ───────────────

/// A truly AEAD-encrypted `SESSION_STATUS` MUST be authenticated, decrypted,
/// and processed.
///
/// **Quality invariant**: ciphertext forwarded to `SessionManager` without
/// decryption would fail to parse as a `SessionStatusFrame` and cause a reset.
#[test]
fn aead_encrypted_session_status_on_additional_control_stream_is_decrypted_and_processed() {
    let mut t = setup_tls_exporter_session(3, [0x03; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let entry = tls_exporter_encrypted_control_entry_bytes(
        3,
        0,
        SessionOpCode::Status as u8,
        status_payload(0),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed encrypted STATUS");

    assert!(
        !has_any_reject_or_reset(&actions),
        "encrypted SESSION_STATUS must be decrypted and processed without rejection; \
         actions: {actions:?}"
    );
}

// ── Test 3: Encrypted SESSION_CAPABILITIES is decrypted and processed ────────

/// A truly AEAD-encrypted `SESSION_CAPABILITIES` MUST be authenticated,
/// decrypted, and processed.
///
/// **Quality invariant**: ciphertext forwarded without decryption would fail
/// to parse as a `SessionCapabilitiesFrame` and cause a reset.
#[test]
fn aead_encrypted_session_capabilities_on_additional_control_stream_is_decrypted_and_processed() {
    let mut t = setup_tls_exporter_session(5, [0x05; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let entry = tls_exporter_encrypted_control_entry_bytes(
        5,
        0,
        SessionOpCode::Capabilities as u8,
        capabilities_payload(),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed encrypted CAPABILITIES");

    assert!(
        !has_any_reject_or_reset(&actions),
        "encrypted SESSION_CAPABILITIES must be decrypted and processed without rejection; \
         actions: {actions:?}"
    );
}

// ── Test 4: Plaintext post-binding entry is rejected ─────────────────────────

/// A plaintext `SESSION_ACK` arriving on an additional control stream after
/// TLS_EXPORTER binding is active MUST be rejected with `AuthFailed`.
#[test]
fn plaintext_post_binding_additional_control_stream_entry_is_rejected() {
    let mut t = setup_tls_exporter_session(7, [0x07; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let entry =
        tls_exporter_plaintext_control_entry_bytes(7, 0, SessionOpCode::Ack as u8, ack_payload(0));
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed plaintext ACK");

    assert!(
        has_auth_failed(&actions),
        "plaintext post-binding additional control entry must cause AuthFailed; \
         actions: {actions:?}"
    );
}

// ── Test 5: Structurally-encrypted entry with random payload is rejected ──────

/// An entry with `EntryMode::ENCRYPTED` set but with random (non-AEAD)
/// payload bytes MUST be rejected with `AuthFailed`.
///
/// **Quality invariant**: if only the structural bit is checked and the random
/// bytes are forwarded to `SessionManager`, the manager fails with a parse
/// error (not `AuthFailed`).  This test checks for `ErrAuthFailed` status,
/// which is only produced by the AEAD path.
#[test]
fn structurally_encrypted_with_random_payload_is_rejected_with_auth_failed() {
    let mut t = setup_tls_exporter_session(9, [0x09; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    // 32 random bytes — definitely not a valid AEAD ciphertext+tag pair.
    let entry =
        tls_exporter_encrypted_control_entry_random_payload(9, 0, SessionOpCode::Ack as u8, 32);
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed random payload");

    assert!(
        has_auth_failed(&actions),
        "random payload with ENCRYPTED bit must cause AuthFailed; actions: {actions:?}"
    );
}

// ── Test 6: Ciphertext with a bad tag is rejected ────────────────────────────

/// A properly-structured AEAD entry with a corrupted tag (last byte flipped)
/// MUST be rejected with `AuthFailed`.
///
/// **Quality invariant**: without AEAD decryption, a bad tag would not be
/// detected at the transport layer; the ciphertext would be forwarded to
/// `SessionManager` which would fail with a parse error (wrong status).
#[test]
fn ciphertext_with_bad_tag_is_rejected_with_auth_failed() {
    let mut t = setup_tls_exporter_session(11, [0x0B; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let entry = tls_exporter_encrypted_control_entry_bad_tag(
        11,
        0,
        SessionOpCode::Ack as u8,
        ack_payload(0),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed bad-tag ciphertext");

    assert!(
        has_auth_failed(&actions),
        "ciphertext with bad tag must cause AuthFailed; actions: {actions:?}"
    );
}

// ── Test 7: Ciphertext with wrong LFH bytes as AAD is rejected ───────────────

/// An entry encrypted with a different LFH sequence number as the AAD
/// MUST be rejected with `AuthFailed`.  The receiver constructs the AAD
/// from the actual LFH bytes on the wire; the tag mismatch causes failure.
///
/// **Quality invariant**: without AEAD, the ciphertext (encrypted with wrong
/// AAD) is forwarded as-is to `SessionManager`, which fails with a parse
/// error — not `AuthFailed`.
#[test]
fn ciphertext_encrypted_with_wrong_lfh_aad_is_rejected_with_auth_failed() {
    let mut t = setup_tls_exporter_session(13, [0x0D; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    // Wire has sequence_no=0, but encryption used sequence_no=99 as AAD.
    let entry = tls_exporter_encrypted_control_entry_wrong_lfh_aad(
        13,
        0,  // wire_sequence_no
        99, // aad_sequence_no (different)
        SessionOpCode::Ack as u8,
        ack_payload(0),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed wrong-lfh-aad ciphertext");

    assert!(
        has_auth_failed(&actions),
        "ciphertext encrypted with wrong LFH AAD must cause AuthFailed; actions: {actions:?}"
    );
}

// ── Test 8: Ciphertext with wrong Global Header bytes as AAD is rejected ──────

/// An entry encrypted with different global-header flags in the AAD MUST be
/// rejected with `AuthFailed`.  The receiver uses the active session's global
/// header to compute the AAD; using the wrong flags breaks authentication.
///
/// **Quality invariant**: without AEAD, the ciphertext is forwarded to
/// `SessionManager` which fails with a parse error — not `AuthFailed`.
#[test]
fn ciphertext_encrypted_with_wrong_global_header_aad_is_rejected_with_auth_failed() {
    let mut t = setup_tls_exporter_session(15, [0x0F; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    // Encrypt with NO_INDEX-only flags (0x01) instead of NO_INDEX|ENCRYPTED (0x03).
    let entry = tls_exporter_encrypted_control_entry_wrong_gh_aad(
        15,
        0,
        SessionOpCode::Ack as u8,
        ack_payload(0),
        &TEST_KEY,
        0x0000_0001, // wrong: only NO_INDEX, not ENCRYPTED
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed wrong-gh-aad ciphertext");

    assert!(
        has_auth_failed(&actions),
        "ciphertext encrypted with wrong Global Header AAD must cause AuthFailed; \
         actions: {actions:?}"
    );
}

// ── Test 9: AEAD failure does not expose plaintext ────────────────────────────

/// When AEAD authentication fails on an additional control stream, the
/// transport MUST emit `AuthFailed` without exposing any plaintext in its
/// output.  All `TransportAction` variants are inspected: none must carry
/// decrypted payload bytes.
#[test]
fn aead_failure_on_additional_control_stream_does_not_expose_plaintext() {
    let mut t = setup_tls_exporter_session(17, [0x11; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let entry = tls_exporter_encrypted_control_entry_random_payload(
        17,
        0,
        SessionOpCode::Ack as u8,
        64, // longer random payload — clearly not valid ciphertext
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed invalid ciphertext");

    assert!(
        has_auth_failed(&actions),
        "AEAD failure must produce AuthFailed; actions: {actions:?}"
    );
    // Verify no action exposes a payload that looks like decrypted content.
    // All actions on auth failure must be policy/error actions, not data.
    for action in &actions {
        assert!(
            matches!(
                action,
                TransportAction::RejectSarStream { .. }
                    | TransportAction::ResetTransportStream { .. }
                    | TransportAction::AttachControlStream { .. }
                    | TransportAction::EmitSessionStatus { .. }
                    | TransportAction::Warning { .. }
            ),
            "unexpected action after AEAD failure: {action:?}"
        );
    }
}

// ── Test 10: CTL! remains rejected ───────────────────────────────────────────

/// `CTL!` as the first bytes on a new QUIC stream MUST be rejected with
/// `ErrInvalidMagic`, even when a TLS_EXPORTER session is active.
#[test]
fn ctl_magic_remains_rejected_in_tls_exporter_context() {
    let mut t = setup_tls_exporter_session(19, [0x13; 16]);
    open_control_stream(&mut t, TransportStreamId(2));

    let actions = t
        .feed_bytes(TransportStreamId(2), b"CTL!\0\0\0\0", Some(2))
        .expect("feed CTL!");

    assert!(
        actions.iter().any(|a| match a {
            TransportAction::RejectSarStream { error, .. }
            | TransportAction::ResetTransportStream { error, .. } =>
                error.status() == SarStatus::ErrInvalidMagic,
            _ => false,
        }),
        "CTL! must be rejected with ErrInvalidMagic; actions: {actions:?}"
    );
}
