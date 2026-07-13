// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use common::{malformed_lfh_prefix, session_archive_init_bytes, session_close_entry_bytes};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

#[test]
fn quic_policy_allows_concurrent_transport_streams() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open1");
    transport
        .open_transport_stream(TransportStreamId(2))
        .expect("open2");
    transport
        .open_transport_stream(TransportStreamId(3))
        .expect("open3");

    let a1 = transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(10, 0, [1; 16]),
            Some(1),
        )
        .expect("feed1");
    let a2 = transport
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(11, 0, [2; 16]),
            Some(2),
        )
        .expect("feed2");

    assert!(a1
        .iter()
        .any(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 10)));
    assert!(a2
        .iter()
        .any(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 11)));
}

#[test]
fn quic_policy_resets_only_affected_stream_on_local_error() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
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

    let bad = [
        session_archive_init_bytes(2, 0, [2; 16]),
        malformed_lfh_prefix(),
    ]
    .concat();
    let actions = transport
        .feed_bytes(TransportStreamId(2), &bad, Some(2))
        .expect("stream-local reset");

    assert!(actions.iter().any(|action| {
        matches!(action, TransportAction::ResetTransportStream { transport_stream_id, .. } if *transport_stream_id == TransportStreamId(2))
    }));
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, TransportAction::CloseConnection { .. }))
    );
}

#[test]
fn quic_duplicate_and_too_many_stream_handling_and_reuse_after_close() {
    let config = TransportConfig {
        max_active_sar_streams: 1,
        ..TransportConfig::default()
    };
    let mut transport = InMemoryTransport::new_quic(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open1");
    transport
        .open_transport_stream(TransportStreamId(2))
        .expect("open2");
    transport
        .open_transport_stream(TransportStreamId(3))
        .expect("open3");

    transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(5, 0, [9; 16]),
            Some(1),
        )
        .expect("bind stream 5");

    let duplicate = transport
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(5, 0, [8; 16]),
            Some(2),
        )
        .expect("duplicate reject");
    assert!(duplicate.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::StreamState(_)))
    }));
    assert!(transport.is_sar_stream_bound(5));

    let close = [
        common::no_index_global_header_bytes(),
        session_close_entry_bytes(5, 1),
    ]
    .concat();
    transport
        .feed_bytes(TransportStreamId(1), &close, Some(3))
        .expect("close stream 5");
    assert!(!transport.is_sar_stream_bound(5));

    let reuse = transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(5, 0, [7; 16]),
            Some(4),
        )
        .expect("reuse after close");
    assert!(reuse
        .iter()
        .any(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 5)));

    let too_many = transport
        .feed_bytes(
            TransportStreamId(3),
            &session_archive_init_bytes(6, 0, [6; 16]),
            Some(5),
        )
        .expect("too many reject");
    assert!(too_many.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::TooManyStreams(_)))
    }));
}
