use std::fs;
use std::io::Cursor;
use std::path::Path;

use sar_archive::{
    ArchiveAuditEntryKind, ArchiveAuditOptions, ArchiveAuditPayloadStatus, ArchiveReader,
    ArchiveWriter, ArchiveWriterOptions, CompressionSettings, ControlEntryPolicy, EntryInput,
    PayloadAuditPolicy,
};
use sar_core::{
    EntryMode, GlobalFlags, GlobalHeader, LocalFileHeader, SarError, SarStatus,
    format::{write_global_header, write_lfh},
};
use sar_crypto::{
    ENCR_AES256_GCM, KeyProvider, KmsContext, KmsParams, SarCryptoError, SecretBytes, SecretString,
    kms::types::Pbkdf2Params,
};

#[derive(Clone)]
struct TestKeyProvider {
    password: SecretString,
}

impl KeyProvider for TestKeyProvider {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(self.password.clone()))
    }

    fn unwrap_key(
        &self,
        _ctx: &KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }

    fn external_key(&self, _ctx: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

fn make_no_index_archive_with_single_entry(entry_mode: EntryMode, payload: &[u8]) -> Vec<u8> {
    let mut lfh = LocalFileHeader::minimal_store(
        b"entry".to_vec(),
        u64::try_from(payload.len()).expect("payload length"),
    );
    lfh.entry_mode = entry_mode;
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    make_archive_with_single_lfh(GlobalFlags::NO_INDEX, lfh, payload)
}

fn make_archive_with_single_lfh(
    flags: GlobalFlags,
    lfh: LocalFileHeader,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");
    bytes.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    bytes.extend_from_slice(payload);
    bytes
}

fn parse_first_entry(bytes: &[u8]) -> Result<Option<sar_archive::EntryReader>, SarError> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes.to_vec())).expect("reader");
    reader.read_global_header().expect("header");
    reader.next_entry()
}

fn assert_require_decode_matches_next_entry(bytes: &[u8], expected_status: SarStatus) {
    let ordinary_err = parse_first_entry(bytes).expect_err("ordinary archive read must fail");
    assert_eq!(ordinary_err.status(), expected_status);

    let mut audit_reader = ArchiveReader::new(Cursor::new(bytes.to_vec())).expect("reader");
    let audit_err = audit_reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::Reject,
            payload_policy: PayloadAuditPolicy::RequireDecode,
            include_inert_payload_bytes: false,
        })
        .expect_err("require-decode audit must fail");
    assert_eq!(audit_err.status(), ordinary_err.status());

    let mut best_effort_reader = ArchiveReader::new(Cursor::new(bytes.to_vec())).expect("reader");
    let report = best_effort_reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::Reject,
            payload_policy: PayloadAuditPolicy::DecodeWhenKeysAvailable,
            include_inert_payload_bytes: false,
        })
        .expect("best-effort audit report");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Failed);
    assert_eq!(
        entry.payload_error_status.as_deref(),
        Some(expected_status.name())
    );
}

fn read_stream_fixture(name: &str) -> Vec<u8> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    let path = workspace
        .join("test-vectors")
        .join("valid")
        .join("stream-session")
        .join(name)
        .join("manifest.json");
    let raw = fs::read_to_string(path).expect("manifest");
    let manifest: serde_json::Value = serde_json::from_str(&raw).expect("manifest json");
    let file_name = manifest
        .get("file")
        .and_then(serde_json::Value::as_str)
        .expect("manifest file");
    let fixture = workspace
        .join("test-vectors")
        .join("valid")
        .join("stream-session")
        .join(name)
        .join(file_name);
    fs::read(fixture).expect("fixture")
}

fn encrypted_no_index_archive(password: &SecretString) -> Vec<u8> {
    let mut out = Vec::new();
    let writer_key_provider: Box<dyn KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });
    let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            no_index: true,
            encryption: Some(sar_archive::EncryptionSettings {
                algo_id: ENCR_AES256_GCM,
                kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                    prf_algo_id: sar_crypto::PBKDF2_PRF_HMAC_SHA256,
                    salt: vec![0x44; 32],
                    iterations: 100_000,
                    derived_key_length: 32,
                }),
            }),
            fec: None,
            sparse: false,
            ..Default::default()
        },
        CompressionSettings::store(),
        Some(writer_key_provider),
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("enc.txt", b"encrypted payload".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");
    out
}

#[test]
fn default_audit_rejects_session_control() {
    let bytes = make_no_index_archive_with_single_entry(
        EntryMode::from_bits(EntryMode::SESSION_CONTROL),
        b"",
    );
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader
        .audit(ArchiveAuditOptions::default())
        .expect_err("reject");
    assert_eq!(err.status(), SarStatus::ErrUnsupported);
}

#[test]
fn default_audit_rejects_nonzero_opcode() {
    let bytes = make_no_index_archive_with_single_entry(EntryMode::from_bits(0x01 << 8), b"x");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader
        .audit(ArchiveAuditOptions::default())
        .expect_err("reject");
    assert_eq!(err.status(), SarStatus::ErrUnsupported);
}

#[test]
fn inert_audit_parses_stream_transcript_fixture_structurally() {
    let bytes = read_stream_fixture("session-init");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::PreserveInert,
            payload_policy: PayloadAuditPolicy::MetadataOnly,
            include_inert_payload_bytes: false,
        })
        .expect("audit");

    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.kind == ArchiveAuditEntryKind::InertSessionControl)
    );
}

#[test]
fn inert_audit_reports_nonzero_opcode_entries_as_inert() {
    let bytes = make_no_index_archive_with_single_entry(EntryMode::from_bits(0x04 << 8), b"abc");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::PreserveInert,
            payload_policy: PayloadAuditPolicy::RequireDecode,
            include_inert_payload_bytes: false,
        })
        .expect("audit");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.kind, ArchiveAuditEntryKind::InertOpcodeEntry);
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Skipped);
    assert!(entry.decoded_payload_size.is_none());
}

#[test]
fn inert_audit_decodes_ordinary_archive_entries() {
    let bytes = make_no_index_archive_with_single_entry(EntryMode::from_bits(0), b"abc");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::PreserveInert,
            payload_policy: PayloadAuditPolicy::RequireDecode,
            include_inert_payload_bytes: false,
        })
        .expect("audit");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.kind, ArchiveAuditEntryKind::OrdinaryEntry);
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Decoded);
    assert_eq!(entry.decoded_payload_size, Some(3));
}

#[test]
fn metadata_only_does_not_require_decryption_keys() {
    let password = SecretString::new("audit-pass".to_string());
    let bytes = encrypted_no_index_archive(&password);

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::Reject,
            payload_policy: PayloadAuditPolicy::MetadataOnly,
            include_inert_payload_bytes: false,
        })
        .expect("audit");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Skipped);
    assert!(entry.decoded_payload_size.is_none());
}

#[test]
fn decode_when_keys_available_reports_unavailable_for_missing_key_provider() {
    let password = SecretString::new("audit-pass".to_string());
    let bytes = encrypted_no_index_archive(&password);

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::Reject,
            payload_policy: PayloadAuditPolicy::DecodeWhenKeysAvailable,
            include_inert_payload_bytes: false,
        })
        .expect("audit");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Unavailable);
    assert_eq!(
        entry.payload_error_status.as_deref(),
        Some(SarStatus::ErrKeyMissing.name())
    );
}

#[test]
fn require_decode_fails_when_keys_missing() {
    let password = SecretString::new("audit-pass".to_string());
    let bytes = encrypted_no_index_archive(&password);

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let err = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::Reject,
            payload_policy: PayloadAuditPolicy::RequireDecode,
            include_inert_payload_bytes: false,
        })
        .expect_err("missing key provider should fail");
    assert!(matches!(err, SarError::KeyMissing(_)));
}

#[test]
fn inert_payload_bytes_captured_when_requested() {
    let payload = b"session-payload-data";
    let bytes = make_no_index_archive_with_single_entry(
        EntryMode::from_bits(EntryMode::SESSION_CONTROL),
        payload,
    );
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::PreserveInert,
            payload_policy: PayloadAuditPolicy::MetadataOnly,
            include_inert_payload_bytes: true,
        })
        .expect("audit");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.kind, ArchiveAuditEntryKind::InertSessionControl);
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Skipped);
    let captured = entry
        .inert_payload_bytes
        .as_deref()
        .expect("captured bytes");
    assert_eq!(captured, payload);
}

#[test]
fn require_decode_with_valid_key_provider_succeeds() {
    let password = SecretString::new("audit-pass".to_string());
    let bytes = encrypted_no_index_archive(&password);
    let key_provider: Box<dyn KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });

    let mut reader = ArchiveReader::new(Cursor::new(bytes))
        .expect("reader")
        .with_key_provider(key_provider);
    let report = reader
        .audit(ArchiveAuditOptions {
            control_entry_policy: ControlEntryPolicy::Reject,
            payload_policy: PayloadAuditPolicy::RequireDecode,
            include_inert_payload_bytes: false,
        })
        .expect("audit");
    let entry = report.entries.first().expect("entry");
    assert_eq!(entry.payload_status, ArchiveAuditPayloadStatus::Decoded);
    assert_eq!(entry.payload_error_status, None);
}

#[test]
fn require_decode_rejects_directory_with_payload() {
    let mut lfh = LocalFileHeader::minimal_store(b"dir".to_vec(), 1);
    lfh.entry_mode = EntryMode::from_bits(EntryMode::IS_DIRECTORY);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    let bytes = make_archive_with_single_lfh(GlobalFlags::NO_INDEX, lfh, b"x");
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrMalformed);
}

#[test]
fn require_decode_rejects_invalid_symlink_target_utf8() {
    let mut lfh = LocalFileHeader::minimal_store(b"lnk".to_vec(), 2);
    lfh.entry_mode = EntryMode::from_bits(EntryMode::IS_SYMLINK);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    let bytes = make_archive_with_single_lfh(
        GlobalFlags::NO_INDEX | GlobalFlags::HAS_SYMLINKS,
        lfh,
        &[0xFF, 0xFE],
    );
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrMalformed);
}

#[test]
fn require_decode_rejects_invalid_name_utf8() {
    let mut lfh = LocalFileHeader::minimal_store(vec![0xFF], 0);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    let bytes = make_archive_with_single_lfh(GlobalFlags::NO_INDEX, lfh, b"");
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrMalformed);
}

#[test]
fn require_decode_rejects_invalid_path_utf8() {
    let mut lfh = LocalFileHeader::minimal_store(b"entry".to_vec(), 0);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    lfh.path = vec![0xFF];
    let bytes =
        make_archive_with_single_lfh(GlobalFlags::NO_INDEX | GlobalFlags::HAS_PATH, lfh, b"");
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrMalformed);
}

#[test]
fn require_decode_rejects_invalid_cdc_algorithm_metadata() {
    let mut lfh = LocalFileHeader::minimal_store(b"entry".to_vec(), 0);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    lfh.cdc_algo_id = Some(0x10);
    let bytes =
        make_archive_with_single_lfh(GlobalFlags::NO_INDEX | GlobalFlags::CDC_SUPPORT, lfh, b"");
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrReservedValue);
}

#[test]
fn require_decode_rejects_invalid_fec_value_metadata() {
    let mut lfh = LocalFileHeader::minimal_store(b"entry".to_vec(), 0);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    lfh.fec_algo_id = Some(0x14);
    let bytes =
        make_archive_with_single_lfh(GlobalFlags::NO_INDEX | GlobalFlags::SELECTIVE_FEC, lfh, b"");
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrInvalidLength);
}

#[test]
fn require_decode_rejects_invalid_sparse_map_metadata() {
    let mut lfh = LocalFileHeader::minimal_store(b"entry".to_vec(), 0);
    lfh.stream_id = 1;
    lfh.sequence_no = 1;
    lfh.sparse_map = vec![0; 7];
    lfh.uncompressed_size = 1;
    let bytes =
        make_archive_with_single_lfh(GlobalFlags::NO_INDEX | GlobalFlags::SPARSE_FILES, lfh, b"");
    assert_require_decode_matches_next_entry(&bytes, SarStatus::ErrInvalidLength);
}
