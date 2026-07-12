use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, SarStatus,
    format::{write_global_header, write_lfh},
};
use sar_stream::{
    SessionFlags, SessionInitFrame, StreamTranscriptValidationOptions, TranscriptRecording,
    validate_stream_transcript, validate_stream_transcript_with_options,
};

const TEST_SESSION_UUID: [u8; 16] = [0x11; 16];

fn unique_temp_path(file_name: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("sar-stream-{ts}-{file_name}"))
}

fn build_valid_transcript() -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let init_payload = SessionInitFrame {
        session_uuid: TEST_SESSION_UUID,
        flags: SessionFlags::from_bits(0),
    }
    .to_bytes()
    .expect("init");
    let mut init_lfh = LocalFileHeader::minimal_store(
        b"init".to_vec(),
        u64::try_from(init_payload.len()).expect("len"),
    );
    init_lfh.stream_id = 0x42;
    init_lfh.sequence_no = 0;
    init_lfh.entry_mode = EntryMode::from_bits(EntryMode::SESSION_CONTROL);
    bytes.extend_from_slice(&write_lfh(&flags, &init_lfh).expect("lfh"));
    bytes.extend_from_slice(&init_payload);

    let payload = b"abc";
    let mut data_lfh = LocalFileHeader::minimal_store(
        b"data".to_vec(),
        u64::try_from(payload.len()).expect("len"),
    );
    data_lfh.stream_id = 0x42;
    data_lfh.sequence_no = 1;
    data_lfh.entry_mode = EntryMode::from_bits(0);
    bytes.extend_from_slice(&write_lfh(&flags, &data_lfh).expect("lfh"));
    bytes.extend_from_slice(payload);

    bytes
}

fn build_invalid_data_before_init_transcript() -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let payload = b"abc";
    let mut data_lfh = LocalFileHeader::minimal_store(
        b"data".to_vec(),
        u64::try_from(payload.len()).expect("len"),
    );
    data_lfh.stream_id = 0x42;
    data_lfh.sequence_no = 0;
    data_lfh.entry_mode = EntryMode::from_bits(0);
    bytes.extend_from_slice(&write_lfh(&flags, &data_lfh).expect("lfh"));
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn recording_is_disabled_by_default() {
    let transcript = build_valid_transcript();
    let path = unique_temp_path("disabled-default.sar");
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let _ = validate_stream_transcript(&transcript).expect("valid");
    assert!(
        !path.exists(),
        "default validation must not write transcript"
    );
}

#[test]
fn recording_writes_exact_bytes_when_enabled() {
    let transcript = build_valid_transcript();
    let path = unique_temp_path("record-enabled.sar");
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let options = StreamTranscriptValidationOptions {
        recording: TranscriptRecording::Path {
            path: path.clone(),
            overwrite: false,
        },
    };
    let _ = validate_stream_transcript_with_options(&transcript, &options).expect("valid");
    let written = fs::read(&path).expect("written file");
    assert_eq!(written, transcript);

    let _ = fs::remove_file(&path);
}

#[test]
fn recording_does_not_weaken_validation() {
    let transcript = build_invalid_data_before_init_transcript();
    let path = unique_temp_path("record-invalid.sar");
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let options = StreamTranscriptValidationOptions {
        recording: TranscriptRecording::Path {
            path: path.clone(),
            overwrite: false,
        },
    };
    let err = validate_stream_transcript_with_options(&transcript, &options).expect_err("invalid");
    assert_eq!(err.status(), SarStatus::ErrStreamState);
    assert_eq!(fs::read(&path).expect("written file"), transcript);

    let _ = fs::remove_file(&path);
}

#[test]
fn recording_reports_io_failure_distinctly() {
    let transcript = build_valid_transcript();
    let path = unique_temp_path("already-exists.sar");
    fs::write(&path, b"old").expect("precreate file");

    let options = StreamTranscriptValidationOptions {
        recording: TranscriptRecording::Path {
            path: path.clone(),
            overwrite: false,
        },
    };
    let err = validate_stream_transcript_with_options(&transcript, &options).expect_err("io fail");
    assert_eq!(err.status(), SarStatus::ErrIo);

    let _ = fs::remove_file(&path);
}
