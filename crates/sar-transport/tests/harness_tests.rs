mod common;

use common::{no_index_global_header_bytes, session_init_entry_bytes};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportHarness,
    TransportStreamId,
};

#[test]
fn harness_can_create_tcp_like_binding() {
    let transport = InMemoryTransport::new_tcp(TransportConfig::default());
    assert_eq!(transport.policy_kind(), sar_transport::TransportBindingKind::Tcp);
}

#[test]
fn harness_can_create_quic_like_binding() {
    let transport = InMemoryTransport::new_quic(TransportConfig::default());
    assert_eq!(transport.policy_kind(), sar_transport::TransportBindingKind::Quic);
}

#[test]
fn harness_opens_stream_and_collects_actions() {
    let mut harness = TransportHarness::tcp(TransportConfig::default());
    harness.open(TransportStreamId(1)).expect("open stream");
    let actions = harness.drain_actions();
    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::AcceptTransportStream { transport_stream_id } if *transport_stream_id == TransportStreamId(1))));
}

#[test]
fn harness_feeds_partial_chunks_deterministically() {
    let mut harness = TransportHarness::tcp(TransportConfig::default());
    harness.open(TransportStreamId(1)).expect("open stream");
    let header = no_index_global_header_bytes();
    let init = session_init_entry_bytes(5, 0, [0x11; 16], 0);
    harness
        .feed(TransportStreamId(1), &header[..4], Some(1))
        .expect("feed partial header");
    harness
        .feed(TransportStreamId(1), &header[4..], Some(2))
        .expect("feed remaining header");
    harness
        .feed(TransportStreamId(1), &init[..3], Some(3))
        .expect("feed partial init");
    harness
        .feed(TransportStreamId(1), &init[3..], Some(4))
        .expect("feed final init");

    let actions = harness.drain_actions();
    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::BindSarStream { sar_stream_id, .. } if *sar_stream_id == 5)));
}

#[test]
fn harness_does_not_bind_before_complete_bytes_arrive() {
    let mut transport = InMemoryTransport::new_tcp(TransportConfig::default());
    transport
        .open_transport_stream(TransportStreamId(1))
        .expect("open stream");
    let init = session_init_entry_bytes(7, 0, [0x33; 16], 0);
    let partial = &init[..8];
    let actions = transport
        .feed_bytes(TransportStreamId(1), partial, Some(1))
        .expect("partial feed");
    assert!(actions
        .iter()
        .all(|action| !matches!(action, TransportAction::BindSarStream { .. })));
}
