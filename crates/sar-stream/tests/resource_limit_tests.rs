// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use sar_core::{EntryMode, ResourceLimits, SarStatus};
use sar_stream::{SessionManager, SessionManagerConfig, SessionMetadataFrame, SessionStatusFrame};

use common::{control_entry, fragmented_no_index_header, fs_entry, init_entry, no_index_header};

#[test]
fn active_stream_limit_is_enforced() {
    let config = SessionManagerConfig {
        limits: ResourceLimits {
            max_active_streams: 1,
            ..ResourceLimits::default()
        },
        ..SessionManagerConfig::default()
    };
    let mut manager = SessionManager::new(config);
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(1, 0, [1; 16], 0))
        .expect("first init");
    let err = manager
        .process_entry(&init_entry(2, 0, [2; 16], 0))
        .expect_err("second stream exceeds limit");
    assert_eq!(err.status(), SarStatus::ErrTooManyStreams);
}

#[test]
fn status_metadata_fragment_and_session_memory_limits_are_enforced() {
    let limits = ResourceLimits {
        max_session_status_message_bytes: 3,
        max_session_metadata_bytes: 2,
        max_session_fragment_buffer_bytes: 1,
        max_session_memory_bytes: 40,
        ..ResourceLimits::default()
    };
    let mut manager = SessionManager::new(SessionManagerConfig {
        limits,
        ..SessionManagerConfig::default()
    });
    manager
        .observe_global_header(&fragmented_no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(3, 0, [3; 16], 0))
        .expect("init");

    let status_err = manager
        .process_entry(&control_entry(
            3,
            1,
            0x4,
            SessionStatusFrame {
                ref_sequence: 0,
                status: SarStatus::Ok,
                message: b"toolong".to_vec(),
            }
            .to_bytes(&ResourceLimits::default())
            .expect("status bytes"),
        ))
        .expect_err("status too large");
    assert_eq!(status_err.status(), SarStatus::ErrLimitExceeded);

    let metadata_err = manager
        .process_entry(&control_entry(
            3,
            1,
            0x6,
            SessionMetadataFrame {
                content_type: "a".to_string(),
                metadata: b"xyz".to_vec(),
            }
            .to_bytes(&ResourceLimits::default())
            .expect("metadata bytes"),
        ))
        .expect_err("metadata too large");
    assert_eq!(metadata_err.status(), SarStatus::ErrLimitExceeded);

    let mut fragment = fs_entry(3, 1, 0x0, EntryMode::FRAGMENT, b"xx".to_vec());
    fragment.header.uncompressed_size = 2;
    let fragment_err = manager
        .process_entry(&fragment)
        .expect_err("fragment buffer too large");
    assert_eq!(fragment_err.status(), SarStatus::ErrLimitExceeded);

    let mut memory_manager = SessionManager::new(SessionManagerConfig {
        limits: ResourceLimits {
            max_session_memory_bytes: 28,
            ..ResourceLimits::default()
        },
        ..SessionManagerConfig::default()
    });
    memory_manager
        .observe_global_header(&no_index_header())
        .expect("header");
    memory_manager
        .process_entry(&init_entry(4, 0, [4; 16], 0))
        .expect("init");
    let memory_err = memory_manager
        .process_entry(&control_entry(
            4,
            1,
            0x6,
            SessionMetadataFrame {
                content_type: "text/plain".to_string(),
                metadata: b"a".to_vec(),
            }
            .to_bytes(&ResourceLimits::default())
            .expect("metadata bytes"),
        ))
        .expect_err("session memory too large");
    assert_eq!(memory_err.status(), SarStatus::ErrLimitExceeded);
}
