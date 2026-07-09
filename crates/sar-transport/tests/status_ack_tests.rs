mod common;

use common::{
    session_archive_init_bytes, session_capabilities_entry_bytes, session_close_entry_bytes,
};
use sar_stream::CapabilityFlags;
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

#[test]
fn bidirectional_control_active_emits_status_for_stream_state_error() {
    let mut config = TransportConfig::default();
    config.bidirectional_control = true;
    let mut transport = InMemoryTransport::new_quic(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open1");
    transport
        .open_transport_stream(TransportStreamId(2))
        .expect("open2");

    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(1, 0, [1; 16]),
            Some(1),
        )
        .expect("bind stream1");

    let actions = transport
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(1, 0, [2; 16]),
            Some(2),
        )
        .expect("duplicate reject");

    assert!(actions.iter().any(|action| {
        matches!(action, TransportAction::EmitSessionStatus { frame, .. } if frame.status == sar_core::SarStatus::ErrStreamState)
    }));
}

#[test]
fn bidirectional_control_inactive_does_not_emit_status() {
    let mut config = TransportConfig::default();
    config.bidirectional_control = false;
    let mut transport = InMemoryTransport::new_quic(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open1");
    transport
        .open_transport_stream(TransportStreamId(2))
        .expect("open2");

    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(1, 0, [1; 16]),
            Some(1),
        )
        .expect("bind stream1");

    let actions = transport
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(1, 0, [2; 16]),
            Some(2),
        )
        .expect("duplicate reject");

    assert!(!actions
        .iter()
        .any(|action| matches!(action, TransportAction::EmitSessionStatus { .. })));
}

#[test]
fn ack_support_active_emits_session_ack() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");

    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(8, 0, [8; 16]),
            Some(1),
        )
        .expect("bind");

    let caps = [
        common::no_index_global_header_bytes(),
        session_capabilities_entry_bytes(
            8,
            1,
            CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK),
        ),
        common::no_index_global_header_bytes(),
        session_close_entry_bytes(8, 2),
    ]
    .concat();

    let actions = transport
        .feed_bytes(TransportStreamId(1), &caps, Some(2))
        .expect("capabilities + close");

    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::EmitSessionAck { sar_stream_id, .. } if *sar_stream_id == 8)));
}

#[test]
fn unsupported_ack_does_not_emit_ack() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");

    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(9, 0, [9; 16]),
            Some(1),
        )
        .expect("bind");

    let close = [common::no_index_global_header_bytes(), session_close_entry_bytes(9, 1)].concat();
    let actions = transport
        .feed_bytes(TransportStreamId(1), &close, Some(2))
        .expect("close");

    assert!(!actions
        .iter()
        .any(|action| matches!(action, TransportAction::EmitSessionAck { .. })));
}
