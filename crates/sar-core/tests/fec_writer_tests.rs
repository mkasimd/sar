//! End-to-end tests for the `ArchiveWriter` with `SELECTIVE_FEC` (Milestones 6–7).
//!
//! Each test round-trips an archive through the writer and reader, verifying that:
//! * The global `SELECTIVE_FEC` flag is set.
//! * The `EntryMetadata.fec` field is populated with the correct algorithm summary.
//! * The decoded payload matches the original.
//! * `verify()` succeeds.

use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EncryptionSettings,
    EntryInput, FecSettings, GlobalFlags, SarError, fec::FecSummary,
};
use sar_crypto::{ENCR_AES256_GCM, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_payload(size: usize) -> Vec<u8> {
    (0u8..=255).cycle().take(size).collect()
}

type FecRoundtripResults = Vec<(String, Vec<u8>, Option<FecSummary>)>;

fn write_and_read(
    opts: ArchiveWriterOptions,
    payloads: &[(&str, Vec<u8>)],
) -> Result<FecRoundtripResults, SarError> {
    let mut buf = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut buf), opts)?;
        for (name, payload) in payloads {
            writer.add_entry(EntryInput::file(name.to_string(), payload.clone()))?;
        }
        writer.finish()?;
    }

    let mut reader = ArchiveReader::new(Cursor::new(&buf))?;
    let _ = reader.read_global_header()?;
    let mut results = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        results.push((
            entry.metadata.name.clone(),
            entry.payload,
            entry.metadata.fec,
        ));
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// XOR FEC — basic roundtrip
// ---------------------------------------------------------------------------

#[test]
fn xor_fec_roundtrip_no_index() {
    let payload = make_payload(1024);
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: None,
        fec: Some(FecSettings::default_xor()),
        sparse: false,
        ..Default::default()
    };
    let results = write_and_read(opts, &[("hello.bin", payload.clone())]).expect("roundtrip");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, payload);

    let fec = results[0].2.as_ref().expect("fec summary present");
    assert!(
        matches!(fec, FecSummary::Xor { algo_id, .. } if *algo_id == FEC_ALGO_XOR),
        "expected XOR FEC summary"
    );
}

// ---------------------------------------------------------------------------
// XOR FEC — indexed archive
// ---------------------------------------------------------------------------

#[test]
fn xor_fec_roundtrip_indexed() {
    let payload = make_payload(512);
    let opts = ArchiveWriterOptions {
        no_index: false,
        encryption: None,
        fec: Some(FecSettings::default_xor()),
        sparse: false,
        ..Default::default()
    };
    let results = write_and_read(opts, &[("data.txt", payload.clone())]).expect("roundtrip");

    assert_eq!(results[0].1, payload);
    assert!(results[0].2.is_some(), "fec summary present");
}

// ---------------------------------------------------------------------------
// Reed-Solomon FEC — basic roundtrip
// ---------------------------------------------------------------------------

#[test]
fn rs_fec_roundtrip_no_index() {
    let payload = make_payload(2048);
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: None,
        fec: Some(FecSettings::default_rs()),
        sparse: false,
        ..Default::default()
    };
    let results = write_and_read(opts, &[("data.bin", payload.clone())]).expect("roundtrip");

    assert_eq!(results[0].1, payload);

    let fec = results[0].2.as_ref().expect("fec summary present");
    assert!(
        matches!(fec, FecSummary::ReedSolomon { algo_id, .. } if *algo_id == FEC_ALGO_REED_SOLOMON),
        "expected RS FEC summary"
    );
}

// ---------------------------------------------------------------------------
// XOR FEC + compression
// ---------------------------------------------------------------------------

#[test]
fn xor_fec_with_compression_roundtrip() {
    let payload = make_payload(4096);
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: None,
        fec: Some(FecSettings::default_xor()),
        sparse: false,
        ..Default::default()
    };
    let mut buf = Vec::new();
    {
        let mut writer = ArchiveWriter::new_with_compression(
            Cursor::new(&mut buf),
            opts,
            CompressionSettings {
                algo_id: sar_compression::COMP_ALGO_ZSTD,
                level: None,
            },
        )
        .expect("writer");
        writer
            .add_entry(EntryInput::file("file.bin".to_string(), payload.clone()))
            .expect("add");
        writer.finish().expect("finish");
    }

    let mut reader = ArchiveReader::new(Cursor::new(&buf)).expect("reader");
    let hdr = reader.read_global_header().expect("header");
    assert!(hdr.flags.contains(GlobalFlags::SELECTIVE_FEC));
    assert!(hdr.flags.contains(GlobalFlags::COMPRESSED));

    let entry = reader.next_entry().expect("ok").expect("some");
    assert_eq!(entry.payload, payload);
    assert!(entry.metadata.fec.is_some());
}

// ---------------------------------------------------------------------------
// FEC + AEAD encryption roundtrip
// ---------------------------------------------------------------------------

struct TestKeyProvider {
    password: sar_crypto::SecretString,
}

impl sar_core::KeyProvider for TestKeyProvider {
    fn password_for(
        &self,
        _ctx: &sar_core::KmsContext,
    ) -> Result<Option<sar_crypto::SecretString>, sar_core::SarCryptoError> {
        Ok(Some(self.password.clone()))
    }

    fn unwrap_key(
        &self,
        _ctx: &sar_core::KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<sar_core::SecretBytes>, sar_core::SarCryptoError> {
        Ok(None)
    }

    fn external_key(
        &self,
        _ctx: &sar_core::KmsContext,
    ) -> Result<Option<sar_core::SecretBytes>, sar_core::SarCryptoError> {
        Ok(None)
    }
}

#[test]
fn xor_fec_with_aead_encryption_roundtrip() {
    let payload = make_payload(512);
    let salt = [0x42u8; 32];
    let kms_params = sar_core::KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: salt.to_vec(),
        iterations: 100_000,
        derived_key_length: 32,
    });
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: Some(EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params,
        }),
        fec: Some(FecSettings::default_xor()),
        sparse: false,
        ..Default::default()
    };

    let password = sar_crypto::SecretString::new("test-password".to_string());
    let key_provider: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });

    let mut buf = Vec::new();
    {
        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut buf),
            opts,
            CompressionSettings::store(),
            Some(key_provider),
        )
        .expect("writer");
        writer
            .add_entry(EntryInput::file("secret.bin".to_string(), payload.clone()))
            .expect("add");
        writer.finish().expect("finish");
    }

    let mut reader = ArchiveReader::new(Cursor::new(&buf)).expect("reader");
    let hdr = reader.read_global_header().expect("header");
    assert!(hdr.flags.contains(GlobalFlags::SELECTIVE_FEC));
    assert!(hdr.flags.contains(GlobalFlags::ENCRYPTED));

    let key_provider2: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });
    let reader = reader.with_key_provider(key_provider2);
    let mut reader = reader;
    let entry = reader.next_entry().expect("ok").expect("some");
    assert_eq!(entry.payload, payload, "decrypted payload must match");
    assert!(entry.metadata.fec.is_some(), "FEC summary must be present");
}

// ---------------------------------------------------------------------------
// RS FEC + AEAD encryption roundtrip
// ---------------------------------------------------------------------------

#[test]
fn rs_fec_with_aead_encryption_roundtrip() {
    let payload = make_payload(1024);
    let salt = [0x33u8; 32];
    let kms_params = sar_core::KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: salt.to_vec(),
        iterations: 100_000,
        derived_key_length: 32,
    });
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: Some(EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params,
        }),
        fec: Some(FecSettings::default_rs()),
        sparse: false,
        ..Default::default()
    };

    let password = sar_crypto::SecretString::new("pass123".to_string());
    let key_provider: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });

    let mut buf = Vec::new();
    {
        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut buf),
            opts,
            CompressionSettings::store(),
            Some(key_provider),
        )
        .expect("writer");
        writer
            .add_entry(EntryInput::file("file.bin".to_string(), payload.clone()))
            .expect("add");
        writer.finish().expect("finish");
    }

    let mut reader = ArchiveReader::new(Cursor::new(&buf)).expect("reader");
    let _ = reader.read_global_header().expect("header");
    let key_provider2: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });
    let mut reader = reader.with_key_provider(key_provider2);
    let entry = reader.next_entry().expect("ok").expect("some");
    assert_eq!(entry.payload, payload);
    assert!(entry.metadata.fec.is_some());
}

// ---------------------------------------------------------------------------
// verify() succeeds on FEC archives
// ---------------------------------------------------------------------------

#[test]
fn verify_fec_archive_succeeds() {
    let opts = ArchiveWriterOptions {
        no_index: false,
        encryption: None,
        fec: Some(FecSettings::default_xor()),
        sparse: false,
        ..Default::default()
    };
    let payloads: &[(&str, Vec<u8>)] =
        &[("a.bin", make_payload(256)), ("b.bin", make_payload(512))];
    let mut buf = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut buf), opts).expect("writer");
        for (name, payload) in payloads {
            writer
                .add_entry(EntryInput::file(name.to_string(), payload.clone()))
                .expect("add");
        }
        writer.finish().expect("finish");
    }

    let mut reader = ArchiveReader::new(Cursor::new(&buf)).expect("reader");
    let report = reader.verify().expect("verify");
    assert!(report.valid);
    assert_eq!(report.entry_count, 2);
    assert!(report.indexed);
}

// ---------------------------------------------------------------------------
// SELECTIVE_FEC flag is set in global header
// ---------------------------------------------------------------------------

#[test]
fn selective_fec_flag_is_set_in_global_header() {
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: None,
        fec: Some(FecSettings::default_xor()),
        sparse: false,
        ..Default::default()
    };
    let mut buf = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut buf), opts).expect("writer");
        writer
            .add_entry(EntryInput::file("x".to_string(), vec![1u8, 2, 3]))
            .expect("add");
        writer.finish().expect("finish");
    }

    let mut reader = ArchiveReader::new(Cursor::new(&buf)).expect("reader");
    let hdr = reader.read_global_header().expect("header");
    assert!(
        hdr.flags.contains(GlobalFlags::SELECTIVE_FEC),
        "SELECTIVE_FEC flag must be set"
    );
}

// ---------------------------------------------------------------------------
// Multiple entries all receive FEC metadata
// ---------------------------------------------------------------------------

#[test]
fn all_entries_receive_fec_metadata() {
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("a.bin", make_payload(100)),
        ("b.bin", make_payload(500)),
        ("c.bin", make_payload(1000)),
    ];
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: None,
        fec: Some(FecSettings::default_rs()),
        sparse: false,
        ..Default::default()
    };
    let results = write_and_read(opts, &payloads).expect("roundtrip");

    for (i, (_, payload, fec)) in results.iter().enumerate() {
        assert_eq!(*payload, payloads[i].1, "payload mismatch for entry {i}");
        assert!(fec.is_some(), "entry {i} must have FEC metadata");
    }
}

// ---------------------------------------------------------------------------
// No FEC when fec option is None
// ---------------------------------------------------------------------------

#[test]
fn no_fec_when_option_is_none() {
    let payload = make_payload(256);
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: None,
        fec: None,
        sparse: false,
        ..Default::default()
    };
    let results = write_and_read(opts, &[("file.bin", payload.clone())]).expect("roundtrip");
    assert_eq!(results[0].1, payload);
    assert!(
        results[0].2.is_none(),
        "fec must be None when not configured"
    );
}
