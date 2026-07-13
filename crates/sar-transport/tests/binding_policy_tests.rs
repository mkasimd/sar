// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use common::{filesystem_data_entry_bytes, session_archive_init_bytes, session_init_entry_bytes};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

#[test]
fn new_global_header_without_valid_session_init_does_not_bind() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");

    let bytes = [
        common::no_index_global_header_bytes(),
        filesystem_data_entry_bytes(3, 0, b"payload".to_vec()),
    ]
    .concat();
    let actions = transport
        .feed_bytes(TransportStreamId(1), &bytes, Some(1))
        .expect("policy actions");

    assert!(!transport.is_sar_stream_bound(3));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, TransportAction::RejectSarStream { .. }))
    );
}

#[test]
fn new_global_header_followed_by_valid_session_init_binds() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");

    let actions = transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(9, 0, [9; 16]),
            Some(1),
        )
        .expect("bind");

    assert!(transport.is_sar_stream_bound(9));
    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 9)));
}

#[test]
fn stream_id_zero_duplicate_and_too_many_are_rejected() {
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
        .open_transport_stream(TransportStreamId(4))
        .expect("open4");

    let zero = transport
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(0, 0, [1; 16]),
            Some(1),
        )
        .expect("stream id zero reject");
    assert!(zero.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::StreamState(_)))
    }));

    transport
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(4, 0, [2; 16]),
            Some(2),
        )
        .expect("bind stream 4");

    let duplicate = transport
        .feed_bytes(
            TransportStreamId(3),
            &session_archive_init_bytes(4, 0, [3; 16]),
            Some(3),
        )
        .expect("duplicate reject");
    assert!(duplicate.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::StreamState(_)))
    }));

    let too_many = transport
        .feed_bytes(
            TransportStreamId(4),
            &session_archive_init_bytes(5, 0, [4; 16]),
            Some(4),
        )
        .expect("too many reject");
    assert!(too_many.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::TooManyStreams(_)))
    }));

    // Duplicate/too-many rejections must not create a binding.
    assert!(!transport.is_sar_stream_bound(5));
    let direct = session_init_entry_bytes(4, 0, [6; 16], 0);
    let _ = direct;
}
