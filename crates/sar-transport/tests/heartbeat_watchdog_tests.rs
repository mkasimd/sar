mod common;

use common::{session_archive_init_bytes, session_heartbeat_entry_bytes};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

#[test]
fn heartbeat_too_soon_is_suppressed() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");
    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(2, 0, [2; 16]),
            Some(0),
        )
        .expect("bind");

    transport
        .record_valid_activity(TransportStreamId(1), 0)
        .expect("record activity");
    let first = transport
        .maybe_emit_heartbeat(TransportStreamId(1), 60_000)
        .expect("heartbeat due");
    assert!(first
        .iter()
        .any(|action| matches!(action, TransportAction::EmitHeartbeat { sar_stream_id } if *sar_stream_id == 2)));

    let second = transport
        .maybe_emit_heartbeat(TransportStreamId(1), 62_000)
        .expect("heartbeat suppressed");
    assert!(second.is_empty());
}

#[test]
fn missing_heartbeat_beyond_timeout_returns_timeout() {
    let transport = InMemoryTransport::new_quic(TransportConfig::default());
    let err = transport
        .check_inactivity(181_000)
        .expect("no activity yet so no timeout");
    assert!(err.is_empty());

    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");
    transport
        .record_valid_activity(TransportStreamId(1), 0)
        .expect("record");
    let timeout = transport.check_inactivity(180_001).expect_err("timeout expected");
    assert!(matches!(timeout, sar_core::SarError::Timeout(_)));
}

#[test]
fn valid_lfh_activity_resets_watchdog() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");
    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(3, 0, [3; 16]),
            Some(100),
        )
        .expect("bind");
    transport
        .check_inactivity(170_000)
        .expect("within timeout after activity");
}

#[test]
fn heartbeat_sequence_continuity_is_enforced_by_sar_stream() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");
    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(4, 0, [4; 16]),
            Some(1),
        )
        .expect("bind");

    let bad_heartbeat = [
        common::no_index_global_header_bytes(),
        session_heartbeat_entry_bytes(4, 7),
    ]
    .concat();
    let actions = transport
        .feed_bytes(TransportStreamId(1), &bad_heartbeat, Some(2))
        .expect("policy error actions");

    assert!(actions.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::StreamState(_)))
    }));
}
