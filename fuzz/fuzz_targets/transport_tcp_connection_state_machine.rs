// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.4: Stateful transport write/process/close state-machine fuzz target.
//!
//! Drives `TransportHarness` (TCP-policy, in-memory) through arbitrary bounded
//! operation sequences to exercise the transport stream lifecycle: open, feed
//! bytes, close, reset, inactivity check.  No real sockets, no async runtime,
//! no QUIC features.
//!
//! The session behavior covered here goes through `sar-transport`'s public
//! `TransportHarness` and `InMemoryTransport` APIs.  Direct `SessionManager`
//! fuzzing is not attempted; session state is exercised indirectly as
//! `InMemoryTransport` drives `SessionManager` internally during `feed_bytes`.
//!
//! ## Public APIs used
//!
//! - `TransportHarness::tcp(TransportConfig)` — construct TCP-policy harness.
//! - `TransportHarness::open(TransportStreamId)` — open a transport stream.
//! - `TransportHarness::feed(TransportStreamId, &[u8], Option<u64>)` — feed bytes.
//! - `TransportHarness::close(TransportStreamId)` — close a transport stream.
//! - `TransportHarness::reset(TransportStreamId, SarError)` — reset with error.
//! - `TransportHarness::check_inactivity(u64)` — evaluate watchdog.
//! - `TransportHarness::drain_actions()` — drain emitted transport actions.
//!
//! ## Bounds enforced before use
//!
//! - Byte chunks are truncated to 64 KiB.
//! - Operation count is truncated to 256 operations.
//! - Transport config uses small buffer caps.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sar_core::SarError;
use sar_transport::{TransportConfig, TransportHarness, TransportStreamId};

const MAX_CHUNK_BYTES: usize = 64 * 1024;
const MAX_OPS: usize = 256;
/// Stream IDs used in the harness.  Keep the set small to concentrate
/// operations on a few streams rather than always opening new ones.
const MAX_STREAM_ID: u64 = 4;

/// One fuzzer-generated transport operation.
#[derive(Debug, Arbitrary)]
enum TransportOp {
    /// Open a transport stream.
    Open { stream_id: u8 },
    /// Feed raw bytes to a transport stream with an optional simulated timestamp.
    Feed {
        stream_id: u8,
        bytes: Vec<u8>,
        now_ms: Option<u64>,
    },
    /// Close a transport stream.
    Close { stream_id: u8 },
    /// Reset a transport stream.
    Reset { stream_id: u8 },
    /// Check the inactivity watchdog.
    CheckInactivity { now_ms: u64 },
    /// Drain accumulated transport actions (side-effect-free read).
    DrainActions,
}

fn bounded_stream_id(raw: u8) -> TransportStreamId {
    TransportStreamId(u64::from(raw) % (MAX_STREAM_ID + 1))
}

fn fuzz_transport_config() -> TransportConfig {
    TransportConfig {
        max_active_transport_streams: 8,
        max_active_sar_streams: 4,
        max_buffered_bytes_per_transport_stream: MAX_CHUNK_BYTES,
        max_pending_actions: 64,
        max_status_ack_actions: 16,
        max_rejected_stream_ids: 64,
        max_control_streams_per_sar_session: 2,
        bidirectional_control: false,
        bidirectional_stream: false,
        strict_validation: true,
        heartbeat_min_interval_ms: 5_000,
        heartbeat_required_interval_ms: 60_000,
        inactivity_timeout_ms: 180_000,
    }
}

fuzz_target!(|ops: Vec<TransportOp>| {
    let mut harness = TransportHarness::tcp(fuzz_transport_config());

    for op in ops.into_iter().take(MAX_OPS) {
        match op {
            TransportOp::Open { stream_id } => {
                let _ = harness.open(bounded_stream_id(stream_id));
            }

            TransportOp::Feed {
                stream_id,
                bytes,
                now_ms,
            } => {
                let bytes = if bytes.len() > MAX_CHUNK_BYTES {
                    &bytes[..MAX_CHUNK_BYTES]
                } else {
                    &bytes[..]
                };
                let _ = harness.feed(bounded_stream_id(stream_id), bytes, now_ms);
            }

            TransportOp::Close { stream_id } => {
                let _ = harness.close(bounded_stream_id(stream_id));
            }

            TransportOp::Reset { stream_id } => {
                let _ = harness.reset(
                    bounded_stream_id(stream_id),
                    SarError::Malformed("fuzz-induced reset"),
                );
            }

            TransportOp::CheckInactivity { now_ms } => {
                let _ = harness.check_inactivity(now_ms);
            }

            TransportOp::DrainActions => {
                // Drain and drop actions; prevent unbounded accumulation.
                let _ = harness.drain_actions();
            }
        }
    }

    // Final drain to exercise any pending action accumulation.
    let _ = harness.drain_actions();
});
