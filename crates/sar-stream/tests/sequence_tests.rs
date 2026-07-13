// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use sar_core::SarStatus;
use sar_stream::{SessionEvent, SessionManager, SessionManagerConfig};

use common::{control_entry, fs_entry, init_entry, no_index_header};

#[test]
fn sequence_increments_and_wraps() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(2, u16::MAX, [0xaa; 16], 0))
        .expect("init");

    let heartbeat = manager
        .process_entry(&control_entry(2, 0, 0x3, Vec::new()))
        .expect("wrapped heartbeat");
    assert_eq!(
        heartbeat.events,
        vec![SessionEvent::Heartbeat {
            stream_id: 2,
            sequence_no: 0,
        }]
    );

    manager
        .process_entry(&fs_entry(2, 1, 0x0, 0, b"ok".to_vec()))
        .expect("next sequence");
    assert_eq!(
        manager.active_session(2).expect("active").last_sequence_no,
        1
    );
}

#[test]
fn sequence_discontinuity_fails_closed() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(4, 10, [0xbb; 16], 0))
        .expect("init");

    let err = manager
        .process_entry(&control_entry(4, 12, 0x3, Vec::new()))
        .expect_err("gap must fail");
    assert_eq!(err.status(), SarStatus::ErrStreamState);
}
