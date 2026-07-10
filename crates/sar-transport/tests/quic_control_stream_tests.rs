mod common;

use common::{
    additional_control_ack_bytes, additional_control_capabilities_bytes,
    additional_control_status_bytes, filesystem_data_entry_bytes, session_archive_init_bytes,
    session_init_entry_bytes,
};
use sar_core::{SarError, SarStatus};
use sar_stream::CapabilityFlags;
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

fn setup_active_session(sar_stream_id: u16, session_uuid: [u8; 16]) -> InMemoryTransport {
    let mut t = InMemoryTransport::new_quic(TransportConfig {
        bidirectional_control: true,
        ..TransportConfig::default()
    });
    t.open_transport_stream(TransportStreamId(1))
        .expect("open stream A");
    t.feed_bytes(
        TransportStreamId(1),
        &session_archive_init_bytes(sar_stream_id, 0, session_uuid),
        Some(1),
    )
    .expect("init stream A");
    t.feed_bytes(
        TransportStreamId(1),
        &additional_control_capabilities_bytes(
            sar_stream_id,
            1,
            CapabilityFlags::from_bits(
                CapabilityFlags::BIDIRECTIONAL_CONTROL
                    | CapabilityFlags::SESSION_ACK
                    | CapabilityFlags::SESSION_STATUS,
            ),
        ),
        Some(2),
    )
    .expect("capabilities");
    t
}

fn open_control_stream(t: &mut InMemoryTransport) {
    t.open_transport_stream(TransportStreamId(2))
        .expect("open stream B");
}

fn has_attach_control_stream(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::AttachControlStream { .. }))
}

fn has_reject_or_reset(actions: &[TransportAction], status: SarStatus) -> bool {
    actions.iter().any(|a| match a {
        TransportAction::RejectSarStream { error, .. }
        | TransportAction::ResetTransportStream { error, .. }
        | TransportAction::CloseConnection { error } => error.status() == status,
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

#[test]
fn lfh_direct_session_ack_on_additional_quic_control_stream_is_accepted() {
    let mut t = setup_active_session(3, [0xAA; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_ack_bytes(3, 2),
            Some(3),
        )
        .expect("ack feed");
    assert!(has_attach_control_stream(&actions));
    assert!(!has_reject_or_reset(&actions, SarStatus::ErrStreamState));
}

#[test]
fn lfh_direct_session_status_on_additional_quic_control_stream_is_accepted() {
    let mut t = setup_active_session(5, [0xBB; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_status_bytes(5, 2),
            Some(3),
        )
        .expect("status feed");
    assert!(has_attach_control_stream(&actions));
    assert!(!has_reject_or_reset(&actions, SarStatus::ErrStreamState));
}

#[test]
fn lfh_direct_session_capabilities_on_additional_quic_control_stream_is_accepted() {
    let mut t = setup_active_session(7, [0xCC; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_capabilities_bytes(
                7,
                2,
                CapabilityFlags::from_bits(CapabilityFlags::BIDIRECTIONAL_CONTROL),
            ),
            Some(3),
        )
        .expect("capabilities feed");
    assert!(has_attach_control_stream(&actions));
}

#[test]
fn stream_beginning_with_ctl_magic_is_rejected() {
    let mut t = setup_active_session(9, [0xDD; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(TransportStreamId(2), b"CTL!\0\0\0\0", Some(3))
        .expect("ctl rejection");
    assert!(has_reject_or_reset(&actions, SarStatus::ErrInvalidMagic));
}

#[test]
fn unknown_stream_id_on_lfh_direct_control_stream_is_rejected() {
    let mut t = setup_active_session(11, [0xEE; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_ack_bytes(99, 0),
            Some(3),
        )
        .expect("unknown stream id");
    assert!(has_reject_or_reset(&actions, SarStatus::ErrStreamState));
}

#[test]
fn session_init_on_additional_control_stream_is_rejected() {
    let mut t = setup_active_session(13, [0xF0; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &session_init_entry_bytes(13, 2, [0xF0; 16], 0),
            Some(3),
        )
        .expect("session init rejection");
    assert!(has_attach_control_stream(&actions));
    assert!(has_reject_or_reset(&actions, SarStatus::ErrStreamState));
}

#[test]
fn filesystem_entry_on_additional_control_stream_is_rejected() {
    let mut t = setup_active_session(15, [0x11; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &filesystem_data_entry_bytes(15, 2, b"payload".to_vec()),
            Some(3),
        )
        .expect("filesystem rejection");
    assert!(has_reject_or_reset(&actions, SarStatus::ErrInvalidMagic));
}

#[test]
fn malformed_lfh_direct_control_stream_is_stream_local() {
    let mut t = setup_active_session(17, [0x22; 16]);
    t.open_transport_stream(TransportStreamId(2))
        .expect("open B");
    t.open_transport_stream(TransportStreamId(3))
        .expect("open C");

    let actions_b = t
        .feed_bytes(TransportStreamId(2), &[1, 0, 0, 0, 0, 0, 17, 0], Some(3))
        .expect("malformed feed");
    assert!(actions_b
        .iter()
        .any(|a| matches!(a, TransportAction::ResetTransportStream { transport_stream_id, .. } if *transport_stream_id == TransportStreamId(2))));

    let actions_c = t
        .feed_bytes(
            TransportStreamId(3),
            &additional_control_ack_bytes(17, 2),
            Some(4),
        )
        .expect("unrelated stream feed");
    assert!(has_attach_control_stream(&actions_c));
}

#[test]
fn duplicate_session_init_for_active_stream_id_fails_closed() {
    let mut t = setup_active_session(19, [0x33; 16]);
    t.open_transport_stream(TransportStreamId(2))
        .expect("open B");
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(19, 0, [0x44; 16]),
            Some(3),
        )
        .expect("duplicate stream");
    assert!(has_reject_or_reset(&actions, SarStatus::ErrStreamState));
}

#[test]
fn non_sar_non_lfh_stream_is_rejected() {
    let mut t = setup_active_session(21, [0x55; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(TransportStreamId(2), b"GET / HT", Some(3))
        .expect("invalid bytes");
    assert!(has_any_reject_or_reset(&actions));
}

#[test]
fn additional_control_stream_does_not_create_new_sar_session() {
    let mut t = setup_active_session(23, [0x66; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_ack_bytes(23, 2),
            Some(3),
        )
        .expect("ack feed");
    assert!(!actions.iter().any(|a| matches!(
        a,
        TransportAction::BindSarStream {
            transport_stream_id,
            ..
        } if *transport_stream_id == TransportStreamId(2)
    )));
}

#[test]
fn closed_stream_id_on_lfh_direct_control_stream_is_rejected() {
    let mut t = setup_active_session(25, [0x77; 16]);
    t.close_transport_stream(TransportStreamId(1))
        .expect("close primary");
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_ack_bytes(25, 0),
            Some(3),
        )
        .expect("closed stream id");
    assert!(has_reject_or_reset(&actions, SarStatus::ErrStreamState));
}

#[test]
fn additional_control_stream_does_not_affect_other_sessions() {
    let mut t = setup_active_session(27, [0x88; 16]);
    t.open_transport_stream(TransportStreamId(3))
        .expect("open C");
    t.feed_bytes(
        TransportStreamId(3),
        &session_archive_init_bytes(28, 0, [0x99; 16]),
        Some(3),
    )
    .expect("init C");
    open_control_stream(&mut t);
    let _ = t
        .feed_bytes(
            TransportStreamId(2),
            &additional_control_ack_bytes(27, 2),
            Some(4),
        )
        .expect("ack feed");
    assert!(t.is_sar_stream_bound(27));
    assert!(t.is_sar_stream_bound(28));
}

#[test]
fn invalid_magic_rejection_is_stream_local_error() {
    let mut t = setup_active_session(29, [0xAB; 16]);
    open_control_stream(&mut t);
    let actions = t
        .feed_bytes(TransportStreamId(2), b"CTL!", Some(3))
        .expect("ctl reject");
    assert!(actions.iter().any(|a| matches!(
        a,
        TransportAction::ResetTransportStream {
            error: SarError::StreamState(_),
            ..
        } | TransportAction::ResetTransportStream {
            error: SarError::InvalidMagic,
            ..
        }
    )));
}
