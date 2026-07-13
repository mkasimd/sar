// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use common::{
    filesystem_data_entry_bytes, no_index_global_header_bytes, session_archive_init_bytes,
};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

#[test]
fn max_active_transport_stream_limit_is_enforced() {
    let config = TransportConfig {
        max_active_transport_streams: 1,
        ..TransportConfig::default()
    };
    let mut transport = InMemoryTransport::new_quic(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open first");
    let err = transport
        .open_transport_stream(TransportStreamId(2))
        .expect_err("second stream must exceed limit");
    assert!(matches!(err, sar_core::SarError::TooManyStreams(_)));
}

#[test]
fn max_active_sar_stream_limit_is_enforced() {
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
        .feed_bytes(
            TransportStreamId(1),
            &session_archive_init_bytes(1, 0, [1; 16]),
            Some(1),
        )
        .expect("bind first");
    let actions = transport
        .feed_bytes(
            TransportStreamId(2),
            &session_archive_init_bytes(2, 0, [2; 16]),
            Some(2),
        )
        .expect("too many actions");
    assert!(actions.iter().any(|action| {
        matches!(action, TransportAction::RejectSarStream { error, .. } if matches!(error, sar_core::SarError::TooManyStreams(_)))
    }));
}

#[test]
fn max_buffered_bytes_per_stream_is_enforced() {
    let config = TransportConfig {
        max_buffered_bytes_per_transport_stream: 4,
        ..TransportConfig::default()
    };
    let mut transport = InMemoryTransport::new_quic(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");
    let err = transport
        .feed_bytes(TransportStreamId(1), &[1, 2, 3, 4, 5], Some(1))
        .expect_err("must exceed feed bound");
    assert!(matches!(err, sar_core::SarError::LimitExceeded(_)));
}

#[test]
fn max_pending_action_limit_is_enforced() {
    let config = TransportConfig {
        max_pending_actions: 1,
        ..TransportConfig::default()
    };
    let mut transport = InMemoryTransport::new_quic(config);
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open action count == 1");

    let err = transport
        .feed_bytes(
            TransportStreamId(1),
            &[
                no_index_global_header_bytes(),
                filesystem_data_entry_bytes(1, 0, b"x".to_vec()),
            ]
            .concat(),
            Some(1),
        )
        .expect_err("reject+reset should overflow per-call action bound");
    assert!(matches!(err, sar_core::SarError::LimitExceeded(_)));
}

#[test]
fn malformed_transport_fed_bytes_do_not_panic() {
    let mut transport = InMemoryTransport::new_quic(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open");
    let actions = transport
        .feed_bytes(TransportStreamId(1), &[0x01, 0x02, 0x03, 0x04], Some(1))
        .expect("handled as policy actions or need-more");
    assert!(
        actions.is_empty()
            || actions.iter().any(|action| {
                matches!(
                    action,
                    TransportAction::RejectSarStream { .. }
                        | TransportAction::ResetTransportStream { .. }
                )
            })
    );
}
