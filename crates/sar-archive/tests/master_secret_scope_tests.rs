// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `SAR-M13b-WP6-IMPLEMENTATION-REVIEW-002`: one expensive KDF per KMS scope.
//!
//! The PBKDF2 password lookup (`password_for`) happens exactly once per KMS
//! Master Secret resolution, so its call count is the number of KDF runs.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sar_archive::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EncryptionSettings,
    EntryInput, StreamArchiveParser, StreamEvent, StreamStep,
};
use sar_crypto::{
    ENCR_AES256_GCM, KeyProvider, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params,
    SarCryptoError, SecretBytes, SecretString,
};

const ENTRIES: usize = 4;

struct Counting {
    password: String,
    calls: Arc<AtomicUsize>,
}

impl KeyProvider for Counting {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(SecretString::new(self.password.clone())))
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

fn counting(calls: &Arc<AtomicUsize>) -> Box<dyn KeyProvider> {
    Box::new(Counting {
        password: "pw".to_string(),
        calls: calls.clone(),
    })
}

fn payload(i: usize) -> Vec<u8> {
    format!("entry payload number {i}").into_bytes()
}

fn write_archive(salt: u8, calls: &Arc<AtomicUsize>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut out),
        ArchiveWriterOptions {
            encryption: Some(EncryptionSettings {
                algo_id: ENCR_AES256_GCM,
                kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                    prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                    salt: vec![salt; 16],
                    iterations: 100_000,
                    derived_key_length: 32,
                }),
            }),
            ..Default::default()
        },
        CompressionSettings::store(),
        Some(counting(calls)),
    )
    .expect("writer");
    for i in 0..ENTRIES {
        writer
            .add_entry(EntryInput::file(format!("f{i}.bin"), payload(i)))
            .expect("entry");
    }
    writer.finish().expect("finish");
    out
}

#[test]
fn writer_derives_master_secret_once_for_many_entries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let _ = write_archive(1, &calls);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn reader_derives_master_secret_once_for_many_entries() {
    let bytes = write_archive(1, &Arc::new(AtomicUsize::new(0)));
    let calls = Arc::new(AtomicUsize::new(0));
    let files = ArchiveReader::new(Cursor::new(bytes))
        .expect("reader")
        .with_key_provider(counting(&calls))
        .read_all_logical_files(false)
        .expect("read");
    assert_eq!(files.len(), ENTRIES);
    for (i, file) in files.iter().enumerate() {
        assert_eq!(file.data, payload(i));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn stream_parser_derives_master_secret_once_for_many_entries() {
    let bytes = write_archive(1, &Arc::new(AtomicUsize::new(0)));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut parser = StreamArchiveParser::new().with_key_provider(counting(&calls));
    parser.push_bytes(&bytes).expect("push");
    parser.finalize_input();
    let mut entries = 0;
    loop {
        match parser.step().expect("step") {
            StreamStep::Ready(StreamEvent::Entry(_)) => entries += 1,
            StreamStep::Complete => break,
            _ => {}
        }
    }
    assert_eq!(entries, ENTRIES);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn separate_archives_and_readers_never_share_a_master_secret() {
    let a = write_archive(1, &Arc::new(AtomicUsize::new(0)));
    let b = write_archive(2, &Arc::new(AtomicUsize::new(0)));
    let calls = Arc::new(AtomicUsize::new(0));
    for bytes in [&a, &b, &a] {
        let files = ArchiveReader::new(Cursor::new(bytes.clone()))
            .expect("reader")
            .with_key_provider(counting(&calls))
            .read_all_logical_files(false)
            .expect("read");
        assert_eq!(files.len(), ENTRIES);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn stream_parser_starts_a_new_scope_for_each_archive() {
    let a = write_archive(1, &Arc::new(AtomicUsize::new(0)));
    let b = write_archive(2, &Arc::new(AtomicUsize::new(0)));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut parser = StreamArchiveParser::new().with_key_provider(counting(&calls));
    parser.push_bytes(&a).expect("push a");
    parser.push_bytes(&b).expect("push b");
    parser.finalize_input();
    let mut entries = 0;
    loop {
        match parser.step().expect("step") {
            StreamStep::Ready(StreamEvent::Entry(_)) => entries += 1,
            StreamStep::Complete => break,
            _ => {}
        }
    }
    assert_eq!(entries, 2 * ENTRIES);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
