use std::io::Cursor;

use sar_core::{
    ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EncryptionSettings, EntryInput,
    EntryMode, GlobalFlags, SarError, StreamArchiveParser, StreamEvent, StreamParseState,
    StreamStep,
    format::{
        GlobalHeader, LocalFileHeader, parse_global_header, parse_lfh, write_global_header,
        write_lfh,
    },
};
use sar_crypto::{
    ENCR_AES256_GCM, KmsContext, KmsParams, SarCryptoError, SecretBytes, SecretString,
    kms::types::Pbkdf2Params,
};

fn no_index_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");
    for (name, payload) in entries {
        writer
            .add_entry(EntryInput::file((*name).to_string(), payload.to_vec()))
            .expect("entry");
    }
    writer.finish().expect("finish");
    out
}

fn next_ready(parser: &mut StreamArchiveParser) -> StreamEvent {
    match parser.step().expect("step") {
        StreamStep::Ready(event) => event,
        StreamStep::NeedMore { .. } => panic!("unexpected NeedMore"),
        StreamStep::Complete => panic!("unexpected Complete"),
    }
}

#[test]
fn parser_starts_in_need_global_header() {
    let parser = StreamArchiveParser::new();
    assert_eq!(parser.state(), StreamParseState::NeedGlobalHeader);
}

#[test]
fn partial_global_header_returns_need_more_until_finalized() {
    let archive = no_index_archive(&[("a", b"x")]);
    let mut parser = StreamArchiveParser::new();

    parser.push_bytes(&archive[..6]).expect("push");
    assert!(matches!(
        parser.step().expect("step"),
        StreamStep::NeedMore { .. }
    ));

    parser.finalize_input();
    let err = parser.step().expect_err("must fail after finalize");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn global_header_resolution_establishes_lfh_layout_and_entry_mode_semantics() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 1);
    lfh.comp_algo_id = Some(0xFF); // physically present, semantically ignored
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"a");

    let mut parser = StreamArchiveParser::new();
    parser.push_bytes(&bytes).expect("push");

    let header = match next_ready(&mut parser) {
        StreamEvent::GlobalHeader(h) => h,
        other => panic!("unexpected event: {other:?}"),
    };
    assert!(header.flags.contains(GlobalFlags::COMPRESSED));

    let entry = match next_ready(&mut parser) {
        StreamEvent::Entry(e) => e,
        other => panic!("unexpected event: {other:?}"),
    };
    assert_eq!(entry.payload, b"a");
    assert_eq!(entry.metadata.compression_algo_id, 0x00);
    assert!(!entry.metadata.is_compressed);
}

#[test]
fn partial_lfh_and_payload_return_need_more() {
    let archive = no_index_archive(&[("a", b"abc")]);
    let mut parser = StreamArchiveParser::new();

    let split = 16usize.min(archive.len());
    parser.push_bytes(&archive[..split]).expect("push");
    let _ = next_ready(&mut parser); // global header

    assert!(matches!(
        parser.step().expect("step"),
        StreamStep::NeedMore { .. }
    ));

    parser.push_bytes(&archive[split..]).expect("push rest");
    let _ = next_ready(&mut parser);
    assert_eq!(parser.state(), StreamParseState::EntryReady);
}

#[test]
fn lfhs_are_parsed_sequentially_and_forward_only_from_chunks() {
    let archive = no_index_archive(&[("a", b"1"), ("b", b"2")]);
    let mut parser = StreamArchiveParser::new();
    let mut names = Vec::new();

    for chunk in archive.chunks(3) {
        parser.push_bytes(chunk).expect("chunk");
        loop {
            match parser.step().expect("step") {
                StreamStep::NeedMore { .. } | StreamStep::Complete => break,
                StreamStep::Ready(StreamEvent::Entry(entry)) => {
                    names.push(entry.metadata.name.clone())
                }
                StreamStep::Ready(_) => {}
            }
        }
    }
    parser.finalize_input();

    loop {
        match parser.step().expect("step") {
            StreamStep::Ready(StreamEvent::Entry(entry)) => names.push(entry.metadata.name.clone()),
            StreamStep::Ready(_) => {}
            StreamStep::NeedMore { .. } => continue,
            StreamStep::Complete => break,
        }
    }

    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn parser_handles_multiple_concatenated_archives() {
    let mut combined = no_index_archive(&[("a", b"x")]);
    combined.extend_from_slice(&no_index_archive(&[("b", b"y")]));

    let mut parser = StreamArchiveParser::new();
    parser.push_bytes(&combined).expect("push");
    parser.finalize_input();

    let mut complete_count = 0;
    let mut names = Vec::new();
    loop {
        match parser.step().expect("step") {
            StreamStep::Ready(StreamEvent::Entry(entry)) => names.push(entry.metadata.name),
            StreamStep::Ready(StreamEvent::ArchiveComplete(_)) => complete_count += 1,
            StreamStep::Ready(StreamEvent::GlobalHeader(_)) => {}
            StreamStep::NeedMore { .. } => {}
            StreamStep::Complete => break,
        }
    }

    assert_eq!(names, vec!["a", "b"]);
    assert_eq!(complete_count, 2);
}

#[test]
fn unset_is_encrypted_treats_payload_as_plaintext_with_physical_fields_present() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
    let kms_payload = {
        let mut payload = vec![1, 16];
        payload.extend_from_slice(&[0x11; 16]);
        payload.extend_from_slice(&100_000u32.to_le_bytes());
        payload.extend_from_slice(&32u16.to_le_bytes());
        payload
    };

    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: Some(sar_core::format::KmsData {
            mode_id: 0x01,
            payload: kms_payload,
        }),
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"x".to_vec(), 1);
    lfh.encr_algo_id = Some(0xFE); // physically present but ignored
    lfh.iv_nonce = Some([0u8; 24]);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"p");

    let mut parser = StreamArchiveParser::new();
    parser.push_bytes(&bytes).expect("push");
    let _ = next_ready(&mut parser);
    let entry = match next_ready(&mut parser) {
        StreamEvent::Entry(e) => e,
        _ => unreachable!(),
    };
    assert_eq!(entry.payload, b"p");
}

#[test]
fn opcode_and_session_control_are_parsed_structurally_only() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut session_lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), 0);
    session_lfh.entry_mode = EntryMode::from_bits((0x6 << 8) | EntryMode::SESSION_CONTROL);
    bytes.extend_from_slice(&write_lfh(&flags, &session_lfh).expect("lfh"));

    let normal_lfh = LocalFileHeader::minimal_store(b"data".to_vec(), 1);
    bytes.extend_from_slice(&write_lfh(&flags, &normal_lfh).expect("lfh2"));
    bytes.extend_from_slice(b"z");

    let mut parser = StreamArchiveParser::new();
    parser.push_bytes(&bytes).expect("push");
    let _ = next_ready(&mut parser);

    let first = match next_ready(&mut parser) {
        StreamEvent::Entry(e) => e,
        _ => unreachable!(),
    };
    assert!(first.header.entry_mode.is_session_control());
    assert_eq!(first.header.entry_mode.op_code(), 0x6);

    let second = match next_ready(&mut parser) {
        StreamEvent::Entry(e) => e,
        _ => unreachable!(),
    };
    assert_eq!(second.metadata.name, "data");
}

#[derive(Clone)]
struct TestKeyProvider {
    password: SecretString,
}

impl sar_core::KeyProvider for TestKeyProvider {
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

#[test]
fn transform_order_and_aead_auth_before_plaintext_are_preserved() {
    let password = SecretString::new("m10a-pass".to_string());
    let mut archive = Vec::new();
    {
        let writer_key_provider: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider {
            password: password.clone(),
        });
        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut archive),
            ArchiveWriterOptions {
                no_index: true,
                encryption: Some(EncryptionSettings {
                    algo_id: ENCR_AES256_GCM,
                    kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                        prf_algo_id: sar_crypto::PBKDF2_PRF_HMAC_SHA256,
                        salt: vec![0x33; 32],
                        iterations: 100_000,
                        derived_key_length: 32,
                    }),
                }),
                fec: None,
                sparse: false,
                ..Default::default()
            },
            CompressionSettings {
                algo_id: 0x01,
                level: Some(3),
            },
            Some(writer_key_provider),
        )
        .expect("writer");
        writer
            .add_entry(EntryInput::file("enc", b"secret-compressed-payload".to_vec()))
            .expect("entry");
        writer.finish().expect("finish");
    }

    let (header, header_len) =
        parse_global_header(&archive, &sar_core::ResourceLimits::unlimited())
            .expect("parse global header");
    let (lfh, _) = parse_lfh(
        &archive[header_len..],
        &header.flags,
        &sar_core::ResourceLimits::unlimited(),
    )
    .expect("parse lfh");
    let payload_start = header_len + usize::try_from(lfh.header_size).expect("usize");
    archive[payload_start] ^= 0x01; // tamper ciphertext

    let reader_key_provider: Box<dyn sar_core::KeyProvider> =
        Box::new(TestKeyProvider { password });
    let mut parser = StreamArchiveParser::new().with_key_provider(reader_key_provider);
    parser.push_bytes(&archive).expect("push");
    let _ = next_ready(&mut parser);
    let err = parser
        .step()
        .expect_err("tampered ciphertext must fail authentication");
    assert!(matches!(err, SarError::AuthFailed(_)));
}

#[test]
fn malformed_structural_data_returns_structural_error() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    bytes.extend_from_slice(&2u32.to_le_bytes()); // invalid LFH header size
    bytes.extend_from_slice(&[0u8; 2]);

    let mut parser = StreamArchiveParser::new();
    parser.push_bytes(&bytes).expect("push");
    let _ = next_ready(&mut parser);

    let err = parser.step().expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)));
}

#[test]
fn incomplete_data_is_not_corruption_until_finalized() {
    let archive = no_index_archive(&[("a", b"abc")]);
    let mut parser = StreamArchiveParser::new();

    parser.push_bytes(&archive[..20]).expect("push partial");
    let _ = next_ready(&mut parser);

    assert!(matches!(
        parser.step().expect("step"),
        StreamStep::NeedMore { .. }
    ));

    parser.finalize_input();
    let err = parser.step().expect_err("must fail when finalized");
    assert!(matches!(err, SarError::Truncated(_)));
}

#[test]
fn compressed_store_patch_requires_decompress_before_patch() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED | GlobalFlags::HAS_DELTA;
    let payload = b"logical-target";
    let encoded = sar_core::encode_payload_v2(
        payload,
        sar_core::EncodingPlanV2 {
            is_compressed: true,
            comp_algo_id: 0x01,
            compression_level: Some(3),
            crypto: None,
        },
    )
    .expect("encode");

    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(
        b"patched".to_vec(),
        u64::try_from(encoded.len()).expect("encoded len"),
    );
    lfh.entry_mode = EntryMode::from_bits(EntryMode::COMPRESSED);
    lfh.comp_algo_id = Some(0x01);
    lfh.patch_algo_id = Some(sar_core::PATCH_ALGO_STORE_PATCH);
    lfh.delta_base_hash = Some([0u8; 32]);
    lfh.uncompressed_size = u64::try_from(payload.len()).expect("payload len");

    bytes.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    bytes.extend_from_slice(&encoded);

    let mut parser = StreamArchiveParser::new();
    parser.push_bytes(&bytes).expect("push");
    let _ = next_ready(&mut parser);
    let entry = match next_ready(&mut parser) {
        StreamEvent::Entry(e) => e,
        _ => unreachable!(),
    };
    assert_eq!(entry.payload, payload);
}

#[test]
fn archive_writer_exposes_structural_stream_state_model() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
            ..Default::default()
        },
    )
    .expect("writer");

    assert_eq!(
        writer.stream_state(),
        sar_core::StreamWriteState::NeedLocalFileHeader
    );
    writer
        .add_entry(EntryInput::file("x", b"1".to_vec()))
        .expect("entry");
    assert_eq!(
        writer.stream_state(),
        sar_core::StreamWriteState::EntryReady
    );
}
