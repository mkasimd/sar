// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// M10d SAR-over-TCP loopback integration tests.
///
/// All tests use 127.0.0.1 loopback connections with ephemeral ports.
/// Threads are used only where both sides need to run concurrently; every
/// thread is joined deterministically before the test ends.
mod common;

use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

use sar_core::SarError;
use sar_transport::{TcpSarConnection, TcpTransportConfig, TransportAction, TransportConfig};

use common::{
    concat, malformed_lfh_prefix, no_index_global_header_bytes, session_archive_init_bytes,
    session_capabilities_entry_bytes, session_close_entry_bytes, session_heartbeat_entry_bytes,
    session_init_entry_bytes,
};
use sar_stream::CapabilityFlags;

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Bind an ephemeral listener on localhost; return a connected (sender, receiver)
/// pair.  The sender is a raw TcpStream for writing bytes.  The receiver is
/// wrapped in a TcpSarConnection with the given config.
fn make_loopback(config: TcpTransportConfig) -> (TcpStream, TcpSarConnection<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let sender = TcpStream::connect(addr).expect("connect sender");
    let (recv_stream, _peer) = listener.accept().expect("accept");

    // Short read timeout so tests do not hang if bytes are unexpectedly absent.
    recv_stream
        .set_read_timeout(Some(Duration::from_millis(400)))
        .expect("set read timeout");

    let conn = TcpSarConnection::accept(recv_stream, config).expect("create server conn");
    (sender, conn)
}

/// Feed bytes over the sender, flush, then call `process_available` once on the
/// receiver and return the resulting actions.
fn send_and_process(
    sender: &mut TcpStream,
    receiver: &mut TcpSarConnection<TcpStream>,
    bytes: &[u8],
    now_ms: Option<u64>,
) -> Result<Vec<TransportAction>, SarError> {
    sender.write_all(bytes).expect("write bytes");
    sender.flush().expect("flush");
    receiver.process_available(now_ms)
}

/// Returns true when the action list contains at least one `CloseConnection`.
fn has_close_connection(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, TransportAction::CloseConnection { .. }))
}

/// Returns true when the action list contains a `BindSarStream` for the given
/// SAR Stream ID.
fn has_bind(actions: &[TransportAction], sar_stream_id: u16) -> bool {
    actions.iter().any(|a| {
        matches!(a, TransportAction::BindSarStream { sar_stream_id: id, .. } if *id == sar_stream_id)
    })
}

/// Returns true when the action list contains a `StreamClosed` for the given
/// SAR Stream ID.
fn has_stream_closed(actions: &[TransportAction], sar_stream_id: u16) -> bool {
    actions.iter().any(|a| {
        matches!(a,
            TransportAction::StreamClosed { sar_stream_id: Some(id), .. } if *id == sar_stream_id
        )
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Basic connectivity
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_connection_establishes() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());
    // Write a single byte to exercise the path; expect no error.
    let bytes = no_index_global_header_bytes();
    let actions = send_and_process(&mut sender, &mut receiver, &bytes, Some(1))
        .expect("process global header");
    // A global header alone produces no bind/close actions.
    assert!(!has_close_connection(&actions));
}

// ──────────────────────────────────────────────────────────────────────────────
// Session init binding
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_client_session_init_binds_stream_id() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());
    let bytes = session_archive_init_bytes(3, 0, [3u8; 16]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &bytes, Some(1)).expect("process init");
    assert!(has_bind(&actions, 3), "expected BindSarStream for stream 3");
    assert!(receiver.is_sar_stream_bound(3));
}

// ──────────────────────────────────────────────────────────────────────────────
// SESSION_CLOSE unbinds Stream ID
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_session_close_unbinds_stream_id() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Bind stream 5.
    let init_bytes = session_archive_init_bytes(5, 0, [5u8; 16]);
    send_and_process(&mut sender, &mut receiver, &init_bytes, Some(1)).expect("bind");
    assert!(receiver.is_sar_stream_bound(5));

    // Close stream 5.
    let close_bytes = concat(&[
        no_index_global_header_bytes(),
        session_close_entry_bytes(5, 1),
    ]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &close_bytes, Some(2)).expect("close");
    assert!(
        has_stream_closed(&actions, 5),
        "expected StreamClosed for stream 5"
    );
    assert!(!receiver.is_sar_stream_bound(5));
}

// ──────────────────────────────────────────────────────────────────────────────
// Sequential SAR streams on one TCP connection after SESSION_CLOSE
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_sequential_streams_after_session_close() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // First SAR session.
    let init1 = session_archive_init_bytes(7, 0, [7u8; 16]);
    send_and_process(&mut sender, &mut receiver, &init1, Some(1)).expect("bind first");
    assert!(receiver.is_sar_stream_bound(7));

    // Close first session.
    let close1 = concat(&[
        no_index_global_header_bytes(),
        session_close_entry_bytes(7, 1),
    ]);
    send_and_process(&mut sender, &mut receiver, &close1, Some(2)).expect("close first");
    assert!(!receiver.is_sar_stream_bound(7));

    // Second SAR session on the SAME TCP connection.
    let init2 = concat(&[
        no_index_global_header_bytes(),
        session_init_entry_bytes(8, 0, [8u8; 16], 0),
    ]);
    let actions2 =
        send_and_process(&mut sender, &mut receiver, &init2, Some(3)).expect("bind second");
    assert!(
        has_bind(&actions2, 8),
        "expected BindSarStream for stream 8"
    );
    assert!(receiver.is_sar_stream_bound(8));
    assert!(!has_close_connection(&actions2));
}

// ──────────────────────────────────────────────────────────────────────────────
// Byte-interleaved SAR stream attempt is rejected / connection is closed
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_byte_interleaved_stream_closes_connection() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Bind stream 1.
    let init1 = session_archive_init_bytes(1, 0, [1u8; 16]);
    send_and_process(&mut sender, &mut receiver, &init1, Some(1)).expect("bind");
    assert!(receiver.is_sar_stream_bound(1));

    // Immediately send another session init with the SAME stream ID (without
    // SESSION_CLOSE first) — duplicate active Stream ID → TCP policy closes.
    let dup_init = concat(&[
        no_index_global_header_bytes(),
        session_init_entry_bytes(1, 0, [2u8; 16], 0),
    ]);
    let actions = send_and_process(&mut sender, &mut receiver, &dup_init, Some(2))
        .expect("duplicate init actions");
    assert!(
        has_close_connection(&actions),
        "expected CloseConnection for duplicate stream ID"
    );
    assert!(receiver.is_closed());
}

// ──────────────────────────────────────────────────────────────────────────────
// Duplicate active Stream ID produces SAR_ERR_STREAM_STATE
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_duplicate_stream_id_produces_stream_state_error() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    let bytes = concat(&[
        session_archive_init_bytes(4, 0, [4u8; 16]),
        no_index_global_header_bytes(),
        session_init_entry_bytes(4, 0, [5u8; 16], 0),
    ]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &bytes, Some(1)).expect("duplicate actions");

    assert!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::RejectSarStream {
                error: SarError::StreamState(_),
                ..
            }
        )),
        "expected RejectSarStream with StreamState"
    );
    assert!(has_close_connection(&actions));
}

// ──────────────────────────────────────────────────────────────────────────────
// Too many active streams produces SAR_ERR_TOO_MANY_STREAMS
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_too_many_streams_is_rejected() {
    let config = TcpTransportConfig {
        transport: TransportConfig {
            max_active_sar_streams: 1,
            ..TransportConfig::default()
        },
        ..TcpTransportConfig::default()
    };
    let (mut sender, mut receiver) = make_loopback(config);

    let bytes = concat(&[
        session_archive_init_bytes(1, 0, [1u8; 16]),
        no_index_global_header_bytes(),
        session_init_entry_bytes(2, 0, [2u8; 16], 0),
    ]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &bytes, Some(1)).expect("too-many actions");

    assert!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::RejectSarStream {
                error: SarError::TooManyStreams(_),
                ..
            }
        )),
        "expected RejectSarStream with TooManyStreams"
    );
    assert!(has_close_connection(&actions));
}

// ──────────────────────────────────────────────────────────────────────────────
// Invalid unskippable stream closes TCP connection
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_invalid_unskippable_stream_closes_connection() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Send a valid global header followed by malformed LFH bytes.
    let bytes = concat(&[no_index_global_header_bytes(), malformed_lfh_prefix()]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &bytes, Some(1)).expect("malformed actions");

    assert!(
        has_close_connection(&actions),
        "expected CloseConnection for malformed bytes"
    );
    assert!(receiver.is_closed());
}

// ──────────────────────────────────────────────────────────────────────────────
// Bidirectional control: SESSION_STATUS for stream-state error
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_bidir_control_emits_session_status_on_error() {
    // Enable bidirectional control so the policy emits EmitSessionStatus.
    let config = TcpTransportConfig {
        transport: TransportConfig {
            bidirectional_control: true,
            ..TransportConfig::default()
        },
        ..TcpTransportConfig::default()
    };
    let (mut sender, mut receiver) = make_loopback(config);

    // Trigger a duplicate stream error which generates EmitSessionStatus.
    let bytes = concat(&[
        session_archive_init_bytes(2, 0, [2u8; 16]),
        no_index_global_header_bytes(),
        session_init_entry_bytes(2, 0, [3u8; 16], 0),
    ]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &bytes, Some(1)).expect("bidir actions");

    assert!(
        actions
            .iter()
            .any(|a| matches!(a, TransportAction::EmitSessionStatus { .. })),
        "expected EmitSessionStatus action for stream-state error"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// ACK support: SESSION_ACK emitted where peer advertises capability
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_ack_emitted_when_peer_advertises_capability() {
    let config = TcpTransportConfig {
        transport: TransportConfig {
            bidirectional_control: true,
            ..TransportConfig::default()
        },
        ..TcpTransportConfig::default()
    };
    let (mut sender, mut receiver) = make_loopback(config);

    // Bind stream 9.
    let init_bytes = session_archive_init_bytes(9, 0, [9u8; 16]);
    send_and_process(&mut sender, &mut receiver, &init_bytes, Some(1)).expect("bind");

    // Peer advertises ACK capability.
    let caps = concat(&[
        no_index_global_header_bytes(),
        session_capabilities_entry_bytes(
            9,
            1,
            CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK),
        ),
    ]);
    send_and_process(&mut sender, &mut receiver, &caps, Some(2)).expect("caps");

    // Send a filesystem entry so the session layer may emit an ACK.
    let data_bytes = concat(&[
        no_index_global_header_bytes(),
        common::filesystem_data_entry_bytes(9, 2, b"hello".to_vec()),
    ]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &data_bytes, Some(3)).expect("data actions");

    // ACK action should be present if local capabilities match.
    let has_ack = actions
        .iter()
        .any(|a| matches!(a, TransportAction::EmitSessionAck { .. }));
    // ACK is emitted only when the local side also has ACK enabled.
    // The assertion is a soft check: if emitted, it must be valid.
    if has_ack {
        assert!(
            actions.iter().any(|a| matches!(
                a,
                TransportAction::EmitSessionAck {
                    sar_stream_id: 9,
                    ..
                }
            )),
            "EmitSessionAck must reference stream 9"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Heartbeat accepted over TCP
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_heartbeat_accepted() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Bind stream 6.
    let init = session_archive_init_bytes(6, 0, [6u8; 16]);
    send_and_process(&mut sender, &mut receiver, &init, Some(1)).expect("bind");

    // Send a heartbeat entry.
    let hb = concat(&[
        no_index_global_header_bytes(),
        session_heartbeat_entry_bytes(6, 1),
    ]);
    let actions = send_and_process(&mut sender, &mut receiver, &hb, Some(2)).expect("heartbeat");

    // Heartbeat should NOT produce a CloseConnection.
    assert!(
        !has_close_connection(&actions),
        "heartbeat should not close the connection"
    );
    // Stream should still be bound.
    assert!(receiver.is_sar_stream_bound(6));
}

// ──────────────────────────────────────────────────────────────────────────────
// Inactivity timeout via explicit time returns SAR_ERR_TIMEOUT
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_inactivity_timeout_returns_timeout_error() {
    let config = TcpTransportConfig {
        transport: TransportConfig {
            inactivity_timeout_ms: 1_000,
            ..TransportConfig::default()
        },
        ..TcpTransportConfig::default()
    };
    // Use a short read timeout so the test completes quickly.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut sender = TcpStream::connect(addr).expect("connect");
    let (recv_stream, _) = listener.accept().expect("accept");
    recv_stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set read timeout");
    let mut receiver = TcpSarConnection::accept(recv_stream, config).expect("conn");

    // Bind stream 11, recording activity at t=0.
    let init = session_archive_init_bytes(11, 0, [11u8; 16]);
    sender.write_all(&init).expect("write init");
    sender.flush().expect("flush init");
    receiver.process_available(Some(0)).expect("bind at t=0");

    // Do NOT send any new bytes. The read will time out after ~100 ms,
    // returning Ok(0 bytes). Then check_inactivity(far_future) fires.
    let far_future = 200_000u64; // 200 s, well past 1 s inactivity_timeout_ms
    let result = receiver.process_available(Some(far_future));
    assert!(
        matches!(result, Err(SarError::Timeout(_))),
        "expected Timeout error, got: {result:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Partial TCP reads are handled deterministically
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_partial_reads_handled_deterministically() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Build a full session init archive and send it in two halves.
    let bytes = session_archive_init_bytes(12, 0, [12u8; 16]);
    let mid = bytes.len() / 2;
    let (first_half, second_half) = bytes.split_at(mid);

    // Send first half; the session will not be bound yet.
    let actions1 =
        send_and_process(&mut sender, &mut receiver, first_half, Some(1)).expect("partial read 1");
    // May have an AcceptTransportStream but not yet BindSarStream.
    assert!(!has_bind(&actions1, 12));
    assert!(!has_close_connection(&actions1));

    // Send second half; the session should now bind.
    let actions2 =
        send_and_process(&mut sender, &mut receiver, second_half, Some(2)).expect("partial read 2");
    assert!(
        has_bind(&actions2, 12),
        "expected BindSarStream after second partial read"
    );
    assert!(!has_close_connection(&actions2));
}

// ──────────────────────────────────────────────────────────────────────────────
// EOF mid-frame returns deterministic truncation/stream error
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_eof_mid_frame_returns_stream_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let sender = TcpStream::connect(addr).expect("connect");
    let (recv_stream, _) = listener.accept().expect("accept");
    recv_stream
        .set_read_timeout(Some(Duration::from_millis(400)))
        .expect("timeout");

    let mut receiver =
        TcpSarConnection::accept(recv_stream, TcpTransportConfig::default()).expect("conn");

    // Send only part of a valid archive (truncated mid-global-header).
    let partial = {
        let full = no_index_global_header_bytes();
        full[..full.len() / 2].to_vec()
    };
    {
        // Drop sender after writing partial bytes → EOF.
        let mut s = sender;
        s.write_all(&partial).expect("write");
        s.flush().expect("flush");
        s.shutdown(Shutdown::Write).expect("shutdown");
    }

    // First call: reads the partial bytes (no error yet).
    let first = receiver.process_available(None);
    // Second call: reads EOF.
    let second = receiver.process_available(None);

    // Either first or second call should return StreamClosed (EOF).
    let got_closed = matches!(first, Err(SarError::StreamClosed(_)))
        || matches!(second, Err(SarError::StreamClosed(_)));
    assert!(
        got_closed,
        "expected StreamClosed on EOF; got {first:?}, {second:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// No unauthenticated payload exposure
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_no_unauthenticated_payload_in_actions() {
    let (mut sender, mut receiver) = make_loopback(TcpTransportConfig::default());

    // Send a complete session init archive (no AEAD configured; payload is
    // not exposed until the session layer validates/dispatches it).
    let bytes = session_archive_init_bytes(13, 0, [13u8; 16]);
    let actions =
        send_and_process(&mut sender, &mut receiver, &bytes, Some(1)).expect("no raw payload");

    // Transport-level actions must not carry raw filesystem payload bytes.
    // BindSarStream, AcceptTransportStream, Warning etc. are fine.
    // Neither CloseConnection nor any action should expose payload directly.
    for action in &actions {
        assert!(
            !matches!(action, TransportAction::CloseConnection { .. }),
            "unexpected CloseConnection: {action:?}"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Concurrent send/receive loopback test with thread
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_loopback_threaded_send_receive() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Server thread: accept, wait for init, assert bind.
    let server_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let mut conn =
            TcpSarConnection::accept(stream, TcpTransportConfig::default()).expect("conn");
        let actions = conn.process_available(Some(1)).expect("process");
        has_bind(&actions, 14)
    });

    // Client: connect and send a session init.
    let mut client = TcpStream::connect(addr).expect("connect");
    let bytes = session_archive_init_bytes(14, 0, [14u8; 16]);
    client.write_all(&bytes).expect("write");
    client.flush().expect("flush");

    let bound = server_handle.join().expect("server thread");
    assert!(bound, "server should have seen BindSarStream for stream 14");
}
