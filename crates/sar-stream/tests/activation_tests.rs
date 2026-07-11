mod common;

use sar_core::{SarError, SarStatus};
use sar_stream::{SessionEvent, SessionManager, SessionManagerConfig};

use common::{fs_entry, indexed_header, init_entry, no_index_header};

#[test]
fn activation_requires_no_index_nonzero_stream_id_and_session_init() {
    let uuid = [0x11; 16];
    let mut manager = SessionManager::new(SessionManagerConfig::default());

    manager
        .observe_global_header(&indexed_header())
        .expect("header");
    let result = manager
        .process_entry(&init_entry(7, 0, uuid, 0))
        .expect("inactive init");
    assert_eq!(
        result.events,
        vec![SessionEvent::StatefulInactive {
            stream_id: 7,
            op_code: 0,
            session_control: true,
        }]
    );
    assert_eq!(manager.active_stream_count(), 0);

    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    let result = manager
        .process_entry(&init_entry(0, 0, uuid, 0))
        .expect("zero stream id");
    assert_eq!(
        result.events,
        vec![SessionEvent::StatefulInactive {
            stream_id: 0,
            op_code: 0,
            session_control: true,
        }]
    );
    assert_eq!(manager.active_stream_count(), 0);

    let err = manager
        .process_entry(&fs_entry(9, 0, 0x0, 0, b"payload".to_vec()))
        .expect_err("filesystem without session must fail in stateful context");
    assert_eq!(err.status(), SarStatus::ErrStreamState);
    assert_eq!(manager.active_stream_count(), 0);
}

#[test]
fn session_init_validates_flags_and_duplicate_streams() {
    let uuid = [0x22; 16];
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");

    let mut reserved = init_entry(1, 0, uuid, 0);
    reserved.payload[16] = 0;
    reserved.payload[17] = 0x80;
    let err = manager
        .process_entry(&reserved)
        .expect_err("reserved session flags must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));

    let mut invalid_combo = init_entry(1, 0, uuid, 0);
    invalid_combo.payload[16] = 1 << 3;
    invalid_combo.payload[17] = 0;
    let err = manager
        .process_entry(&invalid_combo)
        .expect_err("invalid flag combo must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));

    let activated = manager
        .process_entry(&init_entry(1, 5, uuid, 0))
        .expect("valid init");
    assert_eq!(
        activated.events,
        vec![SessionEvent::SessionActivated {
            stream_id: 1,
            session_uuid: uuid,
            flags: sar_stream::SessionFlags::from_bits(0),
        }]
    );
    assert_eq!(
        manager.active_session(1).expect("active").last_sequence_no,
        5
    );

    let err = manager
        .process_entry(&init_entry(1, 0, [0x33; 16], 0))
        .expect_err("duplicate stream id must fail");
    assert_eq!(err.status(), SarStatus::ErrStreamState);
}
