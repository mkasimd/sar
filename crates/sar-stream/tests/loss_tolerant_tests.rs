// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

mod common;

use sar_core::{EntryMode, SarError, SarStatus};
use sar_stream::{
    FilesystemAction, SessionEntry, SessionEvent, SessionManager, SessionManagerConfig,
};

use common::{fragmented_no_index_header, fs_entry, init_entry, no_index_header};

#[test]
fn degraded_loss_tolerant_output_emits_warning() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&fragmented_no_index_header())
        .expect("header");
    manager
        .process_entry(&init_entry(6, 0, [0xcc; 16], 0))
        .expect("init");

    let mut entry = fs_entry(
        6,
        1,
        0x0,
        EntryMode::FRAGMENT | EntryMode::LOSS_TOLERANT,
        b"partial".to_vec(),
    );
    entry.degraded = true;
    let result = manager.process_entry(&entry).expect("loss tolerant");

    assert!(matches!(
        &result.events[0],
        SessionEvent::FilesystemAction(FilesystemAction::DataWrite(_))
    ));
    assert!(matches!(
        &result.events[1],
        SessionEvent::Warning {
            stream_id: 6,
            status: SarStatus::WarnIncomplete,
            ..
        }
    ));
}

#[test]
fn degraded_output_without_loss_tolerant_is_rejected() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");
    let err = manager
        .process_entry(&SessionEntry {
            header: fs_entry(0, 0, 0x0, 0, b"x".to_vec()).header,
            payload: b"x".to_vec(),
            degraded: true,
        })
        .expect_err("degraded output without LOSS_TOLERANT");
    assert!(matches!(err, SarError::FragmentGap(_)));
}

#[test]
fn loss_tolerant_does_not_suppress_crypto_or_structural_failures() {
    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager
        .observe_global_header(&no_index_header())
        .expect("header");

    let auth = manager
        .process_entry_result(Err(SarError::AuthFailed("tag mismatch")))
        .expect_err("auth failure");
    assert_eq!(auth.status(), SarStatus::ErrAuthFailed);

    let malformed = manager
        .process_entry_result(Err(SarError::Malformed("bad structure")))
        .expect_err("structural failure");
    assert_eq!(malformed.status(), SarStatus::ErrMalformed);
}
