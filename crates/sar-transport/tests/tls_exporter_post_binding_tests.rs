/// M10i TLS_EXPORTER post-binding SAR-AEAD enforcement tests.
///
/// Verifies that the transport layer correctly enforces:
///
/// 1. `SESSION_INIT` is the only permitted plaintext entry in a KMS Mode
///    `0x04 TLS_EXPORTER` session; it must NOT be rejected.
/// 2. After `SESSION_INIT` binds the session, every subsequent SAR entry on
///    the primary stream MUST carry `EntryMode::ENCRYPTED`.  Any unencrypted
///    entry arriving after binding is active MUST be rejected with
///    `SarError::AuthFailed`.
/// 3. Additional QUIC control streams attached to a `TLS_EXPORTER` session
///    inherit the same enforcement: encrypted entries are accepted, plaintext
///    entries are rejected.
/// 4. An AEAD failure on one additional control stream is stream-local; it
///    does not affect other active sessions or streams.
/// 5. `CTL!` remains rejected, unaffected by KMS mode.
mod common;

use std::sync::Arc;

use sar_core::SarStatus;
use sar_stream::{AckFlags, CapabilityFlags, SessionAckFrame, SessionOpCode, SessionStatusFrame};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

use common::{
    MockTlsExporterKeyProvider, TEST_KEY, additional_control_ack_bytes,
    tls_exporter_aead_primary_stream_entry_bytes, tls_exporter_encrypted_control_entry_bytes,
    tls_exporter_plaintext_control_entry_bytes, tls_exporter_session_archive_init_bytes,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

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
        "session must bind after SESSION_INIT; actions: {actions:?}",
    );
    assert!(
        t.is_tls_exporter_bound(stream_id),
        "TLS_EXPORTER binding must be active after SESSION_INIT"
    );
    t
}

fn capabilities_payload() -> Vec<u8> {
    sar_stream::SessionCapabilitiesFrame {
        flags: CapabilityFlags::from_bits(CapabilityFlags::BIDIRECTIONAL_CONTROL),
    }
    .to_bytes()
    .expect("caps payload")
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

// ── Test 1: SESSION_INIT accepted as plaintext ─────────────────────────────

/// SESSION_INIT MUST be accepted as plaintext in a KMS Mode 0x04
/// TLS_EXPORTER session.  The binding must activate after SESSION_INIT.
#[test]
fn tls_exporter_session_init_is_accepted_as_plaintext() {
    let mut t = InMemoryTransport::new_quic(TransportConfig {
        bidirectional_control: true,
        ..TransportConfig::default()
    });
    t.open_transport_stream(TransportStreamId(1))
        .expect("open stream");

    let actions = t
        .feed_bytes(
            TransportStreamId(1),
            &tls_exporter_session_archive_init_bytes(1, [0x01; 16]),
            Some(1),
        )
        .expect("feed");

    assert!(
        !has_any_reject_or_reset(&actions),
        "SESSION_INIT must not be rejected in TLS_EXPORTER session; actions: {actions:?}"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::BindSarStream {
                sar_stream_id: 1,
                ..
            }
        )),
        "BindSarStream must be emitted; actions: {actions:?}"
    );
    assert!(
        t.is_tls_exporter_bound(1),
        "TLS_EXPORTER binding must be active after SESSION_INIT"
    );
}

// ── Test 2: Encrypted post-binding entry accepted ─────────────────────────

/// First post-binding SESSION_CAPABILITIES MUST be accepted when
/// `EntryMode::ENCRYPTED` is set and the entry is truly AEAD-encrypted.
///
/// The transport must pass the entry through its `StreamArchiveParser`,
/// which decrypts it using the key provider before processing the session
/// frame.  This proves that encrypted entries are fully accepted, not just
/// structurally flagged.
#[test]
fn tls_exporter_encrypted_post_binding_capabilities_is_accepted() {
    let mut t = setup_tls_exporter_session(3, [0x03; 16]);

    let entry = tls_exporter_aead_primary_stream_entry_bytes(
        3,
        1,
        SessionOpCode::Capabilities as u8,
        capabilities_payload(),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(1), &entry, Some(2))
        .expect("feed capabilities");

    assert!(
        !has_any_reject_or_reset(&actions),
        "encrypted post-binding SESSION_CAPABILITIES must be accepted; actions: {actions:?}"
    );
}

// ── Test 3: Plaintext post-binding SESSION_CAPABILITIES rejected ──────────

/// Plaintext `SESSION_CAPABILITIES` received after TLS_EXPORTER binding is
/// active MUST be rejected with `SarError::AuthFailed`.
#[test]
fn tls_exporter_plaintext_post_binding_capabilities_is_rejected() {
    let mut t = setup_tls_exporter_session(5, [0x05; 16]);

    let entry = tls_exporter_plaintext_control_entry_bytes(
        5,
        1,
        SessionOpCode::Capabilities as u8,
        capabilities_payload(),
    );
    let actions = t
        .feed_bytes(TransportStreamId(1), &entry, Some(2))
        .expect("feed plaintext capabilities");

    assert!(
        has_auth_failed(&actions),
        "plaintext post-binding SESSION_CAPABILITIES must cause AuthFailed; \
         actions: {actions:?}"
    );
}

// ── Test 4: Plaintext post-binding SESSION_ACK rejected ───────────────────

/// Plaintext `SESSION_ACK` after TLS_EXPORTER binding MUST cause
/// `SarError::AuthFailed`.
#[test]
fn tls_exporter_plaintext_post_binding_ack_is_rejected() {
    let mut t = setup_tls_exporter_session(7, [0x07; 16]);

    let entry =
        tls_exporter_plaintext_control_entry_bytes(7, 1, SessionOpCode::Ack as u8, ack_payload(0));
    let actions = t
        .feed_bytes(TransportStreamId(1), &entry, Some(2))
        .expect("feed plaintext ack");

    assert!(
        has_auth_failed(&actions),
        "plaintext post-binding SESSION_ACK must cause AuthFailed; actions: {actions:?}"
    );
}

// ── Test 5: Plaintext post-binding SESSION_STATUS rejected ────────────────

/// Plaintext `SESSION_STATUS` after TLS_EXPORTER binding MUST cause
/// `SarError::AuthFailed`.
#[test]
fn tls_exporter_plaintext_post_binding_status_is_rejected() {
    let mut t = setup_tls_exporter_session(9, [0x09; 16]);

    let entry = tls_exporter_plaintext_control_entry_bytes(
        9,
        1,
        SessionOpCode::Status as u8,
        status_payload(0),
    );
    let actions = t
        .feed_bytes(TransportStreamId(1), &entry, Some(2))
        .expect("feed plaintext status");

    assert!(
        has_auth_failed(&actions),
        "plaintext post-binding SESSION_STATUS must cause AuthFailed; actions: {actions:?}"
    );
}

// ── Test 6: Encrypted additional-control-stream entry accepted ────────────

/// LFH-direct additional QUIC control stream entry with `EntryMode::ENCRYPTED`
/// is accepted after TLS_EXPORTER binding is active.
#[test]
fn tls_exporter_additional_control_stream_encrypted_entry_is_accepted() {
    let mut t = setup_tls_exporter_session(11, [0x0B; 16]);
    t.open_transport_stream(TransportStreamId(2))
        .expect("open control stream");

    // Feed the encrypted entry — this is also the first entry, triggering
    // the control-stream attachment probe.  The LFH has stream_id=11 and
    // EntryMode::ENCRYPTED set.
    let entry = tls_exporter_encrypted_control_entry_bytes(
        11,
        0,
        SessionOpCode::Ack as u8,
        ack_payload(0),
        &TEST_KEY,
    );
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed encrypted ack");

    assert!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::AttachControlStream {
                sar_stream_id: 11,
                ..
            }
        )),
        "AttachControlStream must be emitted; actions: {actions:?}"
    );
    assert!(
        !has_auth_failed(&actions),
        "encrypted additional-control-stream entry must be accepted; actions: {actions:?}"
    );
}

// ── Test 7: Plaintext additional-control-stream entry rejected ────────────

/// LFH-direct additional QUIC control stream entry without
/// `EntryMode::ENCRYPTED` MUST be rejected after TLS_EXPORTER binding is
/// active.
#[test]
fn tls_exporter_additional_control_stream_plaintext_entry_is_rejected() {
    let mut t = setup_tls_exporter_session(13, [0x0D; 16]);
    t.open_transport_stream(TransportStreamId(2))
        .expect("open control stream");

    // The plaintext entry uses stream_id=13, no ENCRYPTED bit.
    let entry =
        tls_exporter_plaintext_control_entry_bytes(13, 0, SessionOpCode::Ack as u8, ack_payload(0));
    let actions = t
        .feed_bytes(TransportStreamId(2), &entry, Some(2))
        .expect("feed plaintext ack");

    assert!(
        has_auth_failed(&actions),
        "plaintext additional-control-stream entry must cause AuthFailed; \
         actions: {actions:?}"
    );
}

// ── Test 8: AEAD failure on one control stream is stream-local ────────────

/// An authentication failure on one additional QUIC control stream MUST NOT
/// affect other active sessions or streams.
#[test]
fn tls_exporter_aead_failure_on_control_stream_is_stream_local() {
    let mut t = setup_tls_exporter_session(15, [0x0F; 16]);

    // Open two additional control streams.
    t.open_transport_stream(TransportStreamId(2))
        .expect("open B");
    t.open_transport_stream(TransportStreamId(3))
        .expect("open C");

    // Feed a plaintext (auth-failing) entry to stream B.
    let bad_entry =
        tls_exporter_plaintext_control_entry_bytes(15, 0, SessionOpCode::Ack as u8, ack_payload(0));
    let actions_b = t
        .feed_bytes(TransportStreamId(2), &bad_entry, Some(2))
        .expect("feed bad entry");

    assert!(
        has_auth_failed(&actions_b),
        "stream B must fail with AuthFailed; actions: {actions_b:?}"
    );
    // Stream-local: the reset targets stream B, not a global close.
    assert!(
        actions_b.iter().any(|a| matches!(
            a,
            TransportAction::ResetTransportStream { transport_stream_id, .. }
                if *transport_stream_id == TransportStreamId(2)
        )),
        "ResetTransportStream must target stream B; actions_b: {actions_b:?}"
    );
    assert!(
        !actions_b
            .iter()
            .any(|a| matches!(a, TransportAction::CloseConnection { .. })),
        "CloseConnection must NOT be emitted for QUIC stream-local AEAD failure; \
         actions_b: {actions_b:?}"
    );

    // Stream C must still be usable: feed a valid unencrypted ACK from a
    // non-TLS session to ensure no session-wide contamination.
    // We re-open stream C to a non-TLS-exporter session on a fresh stream.
    // (The primary session [15] is TLS-exporter-bound; we verify it remains bound.)
    assert!(
        t.is_sar_stream_bound(15),
        "primary session must remain bound after stream B failure"
    );
    assert!(
        t.is_tls_exporter_bound(15),
        "TLS_EXPORTER binding must remain active on session 15"
    );

    // Feed an encrypted entry to stream C — must be accepted.
    let good_entry = tls_exporter_encrypted_control_entry_bytes(
        15,
        0,
        SessionOpCode::Ack as u8,
        ack_payload(0),
        &TEST_KEY,
    );
    let actions_c = t
        .feed_bytes(TransportStreamId(3), &good_entry, Some(3))
        .expect("feed good entry to C");
    assert!(
        !has_auth_failed(&actions_c),
        "stream C must not inherit stream B failure; actions_c: {actions_c:?}"
    );
}

// ── Test 9: CTL! remains rejected in TLS_EXPORTER sessions ───────────────

/// A stream beginning with `CTL!` MUST be rejected regardless of whether any
/// TLS_EXPORTER sessions are active.
#[test]
fn tls_exporter_ctl_magic_is_still_rejected() {
    let mut t = setup_tls_exporter_session(17, [0x11; 16]);
    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

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

// ── Test 10: Non-TLS sessions unaffected by TLS_EXPORTER session ──────────

/// A plaintext (non-TLS_EXPORTER) session on a separate transport stream
/// MUST NOT be affected by a co-existing TLS_EXPORTER session.
#[test]
fn non_tls_session_coexists_with_tls_exporter_session() {
    let mut t = setup_tls_exporter_session(19, [0x13; 16]);

    // Open a second transport stream for a plain session.
    t.open_transport_stream(TransportStreamId(2))
        .expect("open plain stream");
    let plain_init = common::session_archive_init_bytes(20, 0, [0x14; 16]);
    let actions = t
        .feed_bytes(TransportStreamId(2), &plain_init, Some(2))
        .expect("feed plain session init");

    assert!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::BindSarStream {
                sar_stream_id: 20,
                ..
            }
        )),
        "plain session must bind; actions: {actions:?}"
    );
    assert!(
        !t.is_tls_exporter_bound(20),
        "plain session must not be TLS_EXPORTER-bound"
    );

    // Feed plaintext control entries to the plain session — must be accepted.
    let plain_ack = additional_control_ack_bytes(20, 1);
    let t2_actions = t
        .feed_bytes(TransportStreamId(2), &plain_ack, Some(3))
        .expect("feed plain ack");
    assert!(
        !has_auth_failed(&t2_actions),
        "plaintext entries on a non-TLS session must not fail auth; \
         actions: {t2_actions:?}"
    );
}
