/// M10g Part A + D — Additional QUIC control-stream interoperability tests.
///
/// These tests use `InMemoryTransport::new_quic` (QUIC policy mode) so that
/// the CTL! framing path is active without requiring a live QUIC connection.
///
/// Tests 1–9 from the M10g Part D spec:
///  1. CTL! stream carrying SESSION_ACK for an active Stream ID + matching UUID is accepted.
///  2. CTL! stream carrying SESSION_STATUS for an active Stream ID + matching UUID is accepted.
///  3. CTL! stream does NOT start with `SAR!` — no SAR_ERR_INVALID_MAGIC is emitted.
///  4. CTL! stream does not create a new SAR session.
///  5. CTL! stream does not reinitialise the active SAR session.
///  6. CTL! stream referencing an unknown Stream ID is rejected with SAR_ERR_STREAM_STATE.
///  7. CTL! stream with a mismatched Session UUID is rejected with SAR_ERR_STREAM_STATE.
///  8. SESSION_INIT on a CTL!-attached control stream is rejected with SAR_ERR_STREAM_STATE.
///  9. Malformed CTL! bytes are stream-local and do not corrupt an unrelated stream.
mod common;

use common::{
    ctl_stream_assoc_header_bytes, ctl_stream_with_ack, ctl_stream_with_status,
    no_index_global_header_bytes, session_archive_init_bytes, session_capabilities_entry_bytes,
};
use sar_core::SarStatus;
use sar_stream::CapabilityFlags;
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a transport pre-loaded with one active SAR session on stream A.
/// Returns (transport, sar_stream_id, session_uuid).
fn setup_active_session(sar_stream_id: u16, session_uuid: [u8; 16]) -> InMemoryTransport {
    let config = TransportConfig {
        bidirectional_control: true,
        ..TransportConfig::default()
    };
    let mut t = InMemoryTransport::new_quic(config);
    t.open_transport_stream(TransportStreamId(1))
        .expect("open stream A");
    t.feed_bytes(
        TransportStreamId(1),
        &session_archive_init_bytes(sar_stream_id, 0, session_uuid),
        Some(1),
    )
    .expect("init stream A");
    // Feed CAPABILITIES so the session recognises bidirectional control.
    t.feed_bytes(
        TransportStreamId(1),
        &session_capabilities_entry_bytes(
            sar_stream_id,
            1,
            CapabilityFlags::from_bits(CapabilityFlags::BIDIRECTIONAL_CONTROL),
        ),
        Some(1),
    )
    .expect("capabilities");
    t
}

fn has_attach_control_stream(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::AttachControlStream { .. }))
}

fn has_reset_transport_stream(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::ResetTransportStream { .. }))
}

fn has_reject_sar_stream(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::RejectSarStream { .. }))
}

fn has_stream_state_error_in_actions(actions: &[TransportAction]) -> bool {
    actions.iter().any(|a| match a {
        TransportAction::RejectSarStream { error, .. }
        | TransportAction::ResetTransportStream { error, .. }
        | TransportAction::CloseConnection { error } => error.status() == SarStatus::ErrStreamState,
        TransportAction::EmitSessionStatus { frame, .. } => {
            frame.status == SarStatus::ErrStreamState
        }
        _ => false,
    })
}

// ── Test 1: CTL! + SESSION_ACK accepted ───────────────────────────────────────

#[test]
fn ctl_stream_with_ack_is_accepted() {
    let uuid = [0xAA; 16];
    let sar_stream_id = 3u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &ctl_stream_with_ack(sar_stream_id, uuid, 1),
            Some(1),
        )
        .expect("CTL! ACK feed");

    assert!(
        has_attach_control_stream(&actions),
        "expected AttachControlStream action, got: {actions:?}"
    );
    // No rejection.
    assert!(
        !has_reject_sar_stream(&actions),
        "unexpected RejectSarStream: {actions:?}"
    );
    assert!(
        !has_reset_transport_stream(&actions),
        "unexpected ResetTransportStream: {actions:?}"
    );
}

// ── Test 2: CTL! + SESSION_STATUS accepted ────────────────────────────────────

#[test]
fn ctl_stream_with_status_is_accepted() {
    let uuid = [0xBB; 16];
    let sar_stream_id = 5u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &ctl_stream_with_status(sar_stream_id, uuid, 2),
            Some(2),
        )
        .expect("CTL! STATUS feed");

    assert!(
        has_attach_control_stream(&actions),
        "expected AttachControlStream action, got: {actions:?}"
    );
    assert!(
        !has_reject_sar_stream(&actions),
        "unexpected RejectSarStream: {actions:?}"
    );
}

// ── Test 3: CTL! stream does NOT start with `SAR!` — no InvalidMagic ─────────

#[test]
fn ctl_stream_does_not_require_sar_magic() {
    let uuid = [0xCC; 16];
    let sar_stream_id = 7u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    let ctl_bytes = ctl_stream_assoc_header_bytes(sar_stream_id, uuid);
    // Verify the CTL! header does NOT start with "SAR!".
    assert_ne!(
        &ctl_bytes[..4],
        b"SAR!",
        "CTL! header should not start with SAR! magic"
    );
    assert_eq!(
        &ctl_bytes[..4],
        b"CTL!",
        "CTL! header should start with CTL! magic"
    );

    // Feeding the CTL! header should not produce an InvalidMagic error.
    let result = t.feed_bytes(TransportStreamId(2), &ctl_bytes, Some(2));
    assert!(
        result.is_ok(),
        "CTL! header feed returned error: {result:?}"
    );

    let actions = result.expect("CTL! header feed should succeed");
    // After a partial header feed (22 bytes exactly), we expect either
    // AttachControlStream (if remaining bytes are appended in this call) or
    // an Ok([]) waiting for the SAR payload.  There must be no magic error.
    let has_invalid_magic = actions.iter().any(|a| {
        matches!(a,
            TransportAction::RejectSarStream { error, .. }
            | TransportAction::ResetTransportStream { error, .. }
            | TransportAction::CloseConnection { error }
            if format!("{error:?}").contains("magic") || format!("{error:?}").contains("Magic")
        )
    });
    assert!(
        !has_invalid_magic,
        "CTL! stream should not produce InvalidMagic: {actions:?}"
    );
}

// ── Test 4: CTL! stream does not create a new SAR session ────────────────────

#[test]
fn ctl_stream_does_not_create_new_sar_session() {
    let uuid = [0xDD; 16];
    let sar_stream_id = 9u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &ctl_stream_with_ack(sar_stream_id, uuid, 0),
            Some(1),
        )
        .expect("CTL! feed");

    // Must not emit BindSarStream for the control stream.
    let has_bind = actions.iter().any(|a| {
        matches!(a, TransportAction::BindSarStream { transport_stream_id, .. }
            if *transport_stream_id == TransportStreamId(2))
    });
    assert!(
        !has_bind,
        "CTL! stream must not create a new BindSarStream: {actions:?}"
    );
}

// ── Test 5: CTL! stream does not reinitialise the active SAR session ──────────

#[test]
fn ctl_stream_does_not_reinitialise_session() {
    let uuid = [0xEE; 16];
    let sar_stream_id = 11u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    // Primary stream is now active and bound.
    // Feed a CTL! control stream with ACK.
    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    t.feed_bytes(
        TransportStreamId(2),
        &ctl_stream_with_ack(sar_stream_id, uuid, 1),
        Some(1),
    )
    .expect("CTL! attach");

    // After the CTL! stream is attached, the primary stream must remain bound.
    // Feeding more data on the primary stream must still work.
    let extra = {
        let mut b = no_index_global_header_bytes();
        b.extend_from_slice(&session_capabilities_entry_bytes(
            sar_stream_id,
            2,
            CapabilityFlags::from_bits(0),
        ));
        b
    };
    // Primary stream should still be usable (no session reinitialization error).
    // (TransportStreamId(1) carries the primary stream.)
    // We just verify it doesn't error and doesn't produce a new BindSarStream.
    let actions = t
        .feed_bytes(TransportStreamId(1), &extra, Some(2))
        .expect("primary stream still usable");

    let has_reinit = actions.iter().any(|a| {
        matches!(a, TransportAction::BindSarStream { transport_stream_id, sar_stream_id: sid, .. }
            if *transport_stream_id == TransportStreamId(1) && *sid == sar_stream_id)
    });
    assert!(
        !has_reinit,
        "primary stream must not emit a second BindSarStream after CTL! attach: {actions:?}"
    );
}

// ── Test 6: Unknown Stream ID in CTL! header → SAR_ERR_STREAM_STATE ──────────

#[test]
fn ctl_stream_unknown_stream_id_rejected() {
    let uuid = [0xFF; 16];
    let sar_stream_id = 13u16;
    let unknown_stream_id = 99u16; // not registered
    let mut t = setup_active_session(sar_stream_id, uuid);

    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    let ctl_bytes = ctl_stream_with_ack(unknown_stream_id, uuid, 0);
    let actions = t
        .feed_bytes(TransportStreamId(2), &ctl_bytes, Some(1))
        .expect("feed should not Err");

    assert!(
        has_stream_state_error_in_actions(&actions),
        "unknown Stream ID must produce SAR_ERR_STREAM_STATE: {actions:?}"
    );
}

// ── Test 7: Mismatched Session UUID in CTL! header → SAR_ERR_STREAM_STATE ────

#[test]
fn ctl_stream_mismatched_uuid_rejected() {
    let uuid = [0x11; 16];
    let wrong_uuid = [0x22; 16];
    let sar_stream_id = 15u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");

    let ctl_bytes = ctl_stream_with_ack(sar_stream_id, wrong_uuid, 0);
    let actions = t
        .feed_bytes(TransportStreamId(2), &ctl_bytes, Some(1))
        .expect("feed should not Err");

    assert!(
        has_stream_state_error_in_actions(&actions),
        "mismatched UUID must produce SAR_ERR_STREAM_STATE: {actions:?}"
    );
}

// ── Test 8: SESSION_INIT on a CTL!-attached stream → SAR_ERR_STREAM_STATE ────

#[test]
fn session_init_on_ctl_attached_stream_rejected() {
    let uuid = [0x33; 16];
    let sar_stream_id = 17u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    // Attach a CTL! control stream.
    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");
    t.feed_bytes(
        TransportStreamId(2),
        &ctl_stream_assoc_header_bytes(sar_stream_id, uuid),
        Some(1),
    )
    .expect("CTL! header feed");

    // Now send a SESSION_INIT for the same stream_id on the attached stream.
    let init_bytes = session_archive_init_bytes(sar_stream_id, 0, uuid);
    let actions = t
        .feed_bytes(TransportStreamId(2), &init_bytes, Some(2))
        .expect("SESSION_INIT on attached stream should not panic");

    assert!(
        has_stream_state_error_in_actions(&actions),
        "SESSION_INIT on attached control stream must produce SAR_ERR_STREAM_STATE: {actions:?}"
    );
}

// ── Test 9: Malformed CTL! bytes are stream-local ─────────────────────────────

#[test]
fn malformed_ctl_stream_does_not_corrupt_unrelated_streams() {
    let uuid = [0x44; 16];
    let sar_stream_id = 19u16;
    let mut t = setup_active_session(sar_stream_id, uuid);

    // Open a second stream that will be the malformed one.
    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");
    // Open a third stream that should remain unaffected.
    t.open_transport_stream(TransportStreamId(3))
        .expect("open stream C");
    t.feed_bytes(
        TransportStreamId(3),
        &session_archive_init_bytes(21, 0, [0x55; 16]),
        Some(3),
    )
    .expect("stream C init");

    // Feed garbage starting with CTL! to stream B, but with a truncated header
    // followed by garbage bytes that can't be a valid SAR stream.
    let mut malformed = b"CTL!".to_vec();
    malformed.extend_from_slice(&sar_stream_id.to_le_bytes()); // stream_id
    malformed.extend_from_slice(&uuid); // uuid — valid so far (22 bytes total)
    // Append garbage that won't parse as a SAR global header.
    malformed.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // The CTL! header association is valid, so it attaches.  The garbage
    // bytes after the header get fed to the SAR parser and may produce an
    // error or reset on stream B.
    let result_b = t.feed_bytes(TransportStreamId(2), &malformed, Some(1));
    // We allow Ok (with reset action) or an Err; both are stream-local.
    // What matters is that stream C remains functional.
    let _ = result_b; // don't assert: malformed SAR parse may reset or error

    // Stream C (unrelated session 21) must still be functional.  Feeding a
    // heartbeat entry should succeed and not produce a connection-fatal action.
    let hb = common::session_heartbeat_entry_bytes(21, 1);
    let actions_c = t
        .feed_bytes(TransportStreamId(3), &hb, Some(3))
        .expect("stream C must remain functional after stream B error");

    let has_fatal = actions_c
        .iter()
        .any(|a| matches!(a, TransportAction::CloseConnection { .. }));
    assert!(
        !has_fatal,
        "stream C should not receive a CloseConnection after stream B error: {actions_c:?}"
    );
    let has_reset_c = actions_c.iter().any(|a| {
        matches!(a, TransportAction::ResetTransportStream { transport_stream_id, .. }
            if *transport_stream_id == TransportStreamId(3))
    });
    assert!(
        !has_reset_c,
        "stream C should not be reset after stream B error: {actions_c:?}"
    );
}
