// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// M13-CRYPTO-001: a malformed TLS_EXPORTER KMS payload in a streamed Global
/// Header is rejected on header receipt, before `SESSION_INIT`, with the
/// canonical KMS parser statuses.  Exporter acquisition and directional
/// bootstrap are outside this test (M13b.4).
mod common;

use sar_core::{SarStatus, SarStatus::*};
use sar_transport::{
    InMemoryTransport, SarTransportBinding, TransportAction, TransportConfig, TransportStreamId,
};

use common::tls_exporter_global_header_bytes;

/// Offset of the KMS payload within the encoded header:
/// magic(4) version(1) reserved(1) flags size(2) flags(4) mode(1) len(4).
const KMS_PAYLOAD_OFFSET: usize = 17;

fn feed_mutated(mutate: impl FnOnce(&mut [u8])) -> SarStatus {
    let mut bytes = tls_exporter_global_header_bytes();
    mutate(&mut bytes[KMS_PAYLOAD_OFFSET..]);
    let mut t = InMemoryTransport::new_quic(TransportConfig::default());
    t.open_transport_stream(TransportStreamId(1)).expect("open");
    let actions = t
        .feed_bytes(TransportStreamId(1), &bytes, Some(1))
        .expect("rejection is reported as transport actions");
    actions
        .iter()
        .find_map(|action| match action {
            TransportAction::RejectSarStream { error, .. } => Some(error.status()),
            _ => None,
        })
        .expect("malformed TLS_EXPORTER header must be rejected")
}

#[test]
fn valid_header_is_accepted_before_session_init() {
    let mut t = InMemoryTransport::new_quic(TransportConfig::default());
    t.open_transport_stream(TransportStreamId(1)).expect("open");
    t.feed_bytes(
        TransportStreamId(1),
        &tls_exporter_global_header_bytes(),
        Some(1),
    )
    .expect("valid header");
}

#[test]
fn reserved_context_version_kdf_and_hash_are_rejected() {
    assert_eq!(feed_mutated(|p| p[0] = 0x02), ErrReservedValue);
    assert_eq!(feed_mutated(|p| p[1] = 0x01), ErrReservedValue);
    assert_eq!(feed_mutated(|p| p[2] = 0x7F), ErrReservedValue);
}

#[test]
fn assigned_unimplemented_hash_is_unsupported() {
    assert_eq!(feed_mutated(|p| p[2] = 0x32), ErrUnsupported);
}

#[test]
fn wrong_derived_length_and_label_are_rejected() {
    assert_eq!(feed_mutated(|p| p[3] = 16), ErrInvalidLength);
    assert_eq!(feed_mutated(|p| p[7] ^= 0x01), ErrMalformed);
}
