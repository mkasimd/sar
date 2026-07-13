// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use sar_core::{EntryMode, ResourceLimits, SarError, SarStatus};
use sar_stream::{
    AckFlags, CapabilityFlags, FilesystemAction, ProcessResult, SessionAckFrame,
    SessionCapabilitiesFrame, SessionEvent, SessionManager, SessionManagerConfig,
    SessionMetadataFrame, SessionResumeFrame, SessionStatusFrame,
};

use common::{control_entry, fs_entry, init_entry, no_index_header};

#[test]
fn close_emits_ack_when_supported() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(3, 10, [0x44; 16], 0))
        .expect("init");

    let result = manager
        .process_entry(&control_entry(3, 11, 0x1, Vec::new()))
        .expect("close");
    assert_eq!(
        result.actions,
        vec![sar_stream::SessionAction::EmitAck {
            stream_id: 3,
            frame: SessionAckFrame {
                ref_sequence: 11,
                flags: AckFlags::from_bits(AckFlags::ACK | AckFlags::OK | AckFlags::SUCCESS),
            },
        }]
    );
    assert!(matches!(
        &result.events[0],
        SessionEvent::SessionClosed {
            stream_id: 3,
            session_uuid: _
        }
    ));
    assert!(manager.active_session(3).is_none());
}

#[test]
fn resume_rules_are_enforced() {
    let config = SessionManagerConfig {
        support_resume: false,
        ..SessionManagerConfig::default()
    };
    let mut manager = SessionManager::new(config);
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(5, 0, [0x55; 16], 0))
        .expect("init");

    let mismatch = manager
        .process_entry(&control_entry(
            5,
            1,
            0x2,
            SessionResumeFrame {
                session_uuid: [0x56; 16],
            }
            .to_bytes(),
        ))
        .expect_err("uuid mismatch");
    assert_eq!(mismatch.status(), SarStatus::ErrStreamState);

    let unsupported = manager
        .process_entry(&control_entry(
            5,
            2,
            0x2,
            SessionResumeFrame {
                session_uuid: [0x55; 16],
            }
            .to_bytes(),
        ))
        .expect_err("resume unsupported");
    assert_eq!(unsupported.status(), SarStatus::ErrUnsupported);
}

#[test]
fn status_ack_metadata_and_capabilities_are_parsed_and_stored() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(7, 100, [0x77; 16], 0))
        .expect("init");

    let capabilities = SessionCapabilitiesFrame {
        flags: CapabilityFlags::from_bits(
            CapabilityFlags::SESSION_ACK | CapabilityFlags::BIDIRECTIONAL_CONTROL,
        ),
    };
    let metadata = SessionMetadataFrame {
        content_type: "application/json".to_string(),
        metadata: br#"{"ok":true}"#.to_vec(),
    };
    let status = SessionStatusFrame {
        ref_sequence: 100,
        status: SarStatus::WarnIncomplete,
        message: b"partial".to_vec(),
    };
    let ack = SessionAckFrame {
        ref_sequence: 102,
        flags: AckFlags::from_bits(AckFlags::ACK | AckFlags::OK),
    };

    let capability_result = manager
        .process_entry(&control_entry(
            7,
            101,
            0x7,
            capabilities.to_bytes().expect("capabilities"),
        ))
        .expect("capabilities");
    assert!(matches!(
        &capability_result.events[0],
        SessionEvent::CapabilitiesUpdated { stream_id: 7, .. }
    ));

    let metadata_result = manager
        .process_entry(&control_entry(
            7,
            102,
            0x6,
            metadata
                .to_bytes(&ResourceLimits::default())
                .expect("metadata bytes"),
        ))
        .expect("metadata");
    assert!(matches!(
        &metadata_result.events[0],
        SessionEvent::MetadataUpdated { stream_id: 7, .. }
    ));

    let status_result = manager
        .process_entry(&control_entry(
            7,
            103,
            0x4,
            status.to_bytes(&ResourceLimits::default()).expect("status"),
        ))
        .expect("status");
    assert!(matches!(
        &status_result.events[0],
        SessionEvent::Status { stream_id: 7, .. }
    ));

    let ack_result = manager
        .process_entry(&control_entry(7, 104, 0x5, ack.to_bytes().expect("ack")))
        .expect("ack");
    assert!(matches!(
        &ack_result.events[0],
        SessionEvent::Ack { stream_id: 7, .. }
    ));

    let active = manager.active_session(7).expect("active session");
    assert_eq!(
        active.peer_capabilities,
        CapabilityFlags::from_bits(
            CapabilityFlags::SESSION_ACK | CapabilityFlags::BIDIRECTIONAL_CONTROL,
        )
    );
    assert_eq!(
        active.metadata.as_ref().expect("metadata").content_type,
        "application/json"
    );
}

#[test]
fn control_frame_validation_is_strict() {
    let err = SessionAckFrame::parse(&[0, 0, AckFlags::OK]).expect_err("OK requires ACK");
    assert!(matches!(err, SarError::FlagConflict(_)));

    let err = SessionCapabilitiesFrame::parse(&(0x8000u16).to_le_bytes())
        .expect_err("reserved capability bits");
    assert!(matches!(err, SarError::ReservedValue(_)));

    let err = SessionMetadataFrame::parse(&[0, 0, 0, 0, 0], &ResourceLimits::default())
        .expect_err("empty content type");
    assert!(matches!(err, SarError::InvalidLength(_)));
}

#[test]
fn filesystem_opcode_validation_and_exposure_work() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(9, 1, [0x99; 16], 0))
        .expect("init");

    let err = manager
        .process_entry(&fs_entry(9, 2, 0x9, 0, Vec::new()))
        .expect_err("reserved fs opcode");
    assert_eq!(err.status(), SarStatus::ErrReservedValue);

    let err = manager
        .process_entry(&fs_entry(9, 2, 0x1, 0, b"not-empty".to_vec()))
        .expect_err("delete payload must be empty");
    assert!(matches!(err, SarError::InvalidLength(_)));

    let mut rename = fs_entry(
        9,
        2,
        0x2,
        EntryMode::ATOMIC_WRITE | EntryMode::FORCE_SYNC,
        b"new/path".to_vec(),
    );
    rename.header.name = b"old.txt".to_vec();
    rename.header.path = b"dir/".to_vec();
    let ProcessResult { events, .. } = manager.process_entry(&rename).expect("rename");
    match &events[0] {
        SessionEvent::FilesystemAction(FilesystemAction::Rename(action)) => {
            assert_eq!(action.old_name, b"old.txt");
            assert_eq!(action.old_path, b"dir/");
            assert_eq!(action.new_path, b"new/path");
            assert!(action.atomic_write);
            assert!(action.force_sync);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}
