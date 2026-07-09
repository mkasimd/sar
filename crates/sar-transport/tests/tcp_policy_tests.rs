mod common;

use common::{
    concat, malformed_lfh_prefix, no_index_global_header_bytes, session_archive_init_bytes,
    session_close_entry_bytes, session_init_entry_bytes,
};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

#[test]
fn tcp_policy_accepts_first_valid_sar_stream() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");
    let bytes = session_archive_init_bytes(1, 0, [1; 16]);
    let actions = transport
        .feed_bytes(TransportStreamId(1), &bytes, Some(1))
        .expect("feed bytes");
    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 1)));
}

#[test]
fn tcp_policy_rejects_byte_interleaved_streams() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream1");
    let actions = transport
        .open_transport_stream(TransportStreamId(2))
        .expect("open stream2 still action-level rejected");
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, TransportAction::CloseConnection { .. }))
    );
}

#[test]
fn tcp_policy_permits_new_stream_after_session_close() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");

    let first = session_archive_init_bytes(1, 0, [2; 16]);
    transport
        .feed_bytes(TransportStreamId(1), &first, Some(10))
        .expect("first bind");

    let close_archive = concat(&[
        no_index_global_header_bytes(),
        session_close_entry_bytes(1, 1),
        no_index_global_header_bytes(),
        session_init_entry_bytes(1, 0, [3; 16], 0),
    ]);
    let actions = transport
        .feed_bytes(TransportStreamId(1), &close_archive, Some(20))
        .expect("close and reopen");

    let bind_count = actions
        .iter()
        .filter(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 1))
        .count();
    assert!(bind_count >= 1);
}

#[test]
fn tcp_invalid_unskippable_stream_emits_close_connection() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");
    let bytes = concat(&[no_index_global_header_bytes(), malformed_lfh_prefix()]);
    let actions = transport
        .feed_bytes(TransportStreamId(1), &bytes, Some(1))
        .expect("policy rejection as actions");
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, TransportAction::CloseConnection { .. }))
    );
}

#[test]
fn tcp_duplicate_active_sar_stream_id_is_rejected() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");

    let bytes = concat(&[
        session_archive_init_bytes(4, 0, [9; 16]),
        no_index_global_header_bytes(),
        session_init_entry_bytes(4, 0, [8; 16], 0),
    ]);
    let actions = transport
        .feed_bytes(TransportStreamId(1), &bytes, Some(1))
        .expect("duplicate actions");

    assert!(actions.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::StreamState(_)))
    }));
}

#[test]
fn tcp_too_many_active_sar_streams_is_rejected() {
    let config = TransportConfig {
        max_active_sar_streams: 1,
        ..TransportConfig::default()
    };
    let mut transport = InMemoryTransport::new_tcp(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");

    let bytes = concat(&[
        session_archive_init_bytes(1, 0, [1; 16]),
        no_index_global_header_bytes(),
        session_init_entry_bytes(2, 0, [2; 16], 0),
    ]);
    let actions = transport
        .feed_bytes(TransportStreamId(1), &bytes, Some(1))
        .expect("too many actions");

    assert!(actions.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::TooManyStreams(_)))
    }));
}

#[test]
fn tcp_rejected_stream_id_remains_unbound_and_close_unbinds() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");

    let bind = session_archive_init_bytes(7, 0, [7; 16]);
    transport
        .feed_bytes(TransportStreamId(1), &bind, Some(1))
        .expect("bind");
    assert!(transport.is_sar_stream_bound(7));

    let close = concat(&[
        no_index_global_header_bytes(),
        session_close_entry_bytes(7, 1),
    ]);
    transport
        .feed_bytes(TransportStreamId(1), &close, Some(2))
        .expect("close");
    assert!(!transport.is_sar_stream_bound(7));
}
