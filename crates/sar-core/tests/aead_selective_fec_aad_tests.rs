use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, DecodingPlanV2,
    EncodingPlanV2, EncryptionSettings, EntryCryptoContext, EntryInput, FecSettings, GlobalFlags,
    KmsContext, KmsParams, LocalFileHeader, SarCryptoError, SarError, decode_payload_v2,
    encode_payload_v2, fec_size_field_offset, global_header_flags_bytes, lfh_bytes_for_aad,
    parse_global_header, parse_lfh, write_lfh,
};
use sar_crypto::{
    ENCR_AES256_GCM, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params, SecretBytes, SecretString,
};
use sar_fec::FEC_ALGO_XOR;
use zeroize::Zeroizing;

fn key(fill: u8) -> SecretBytes {
    Zeroizing::new(vec![fill; 32])
}

fn sample_lfh(fec_value: Vec<u8>) -> (GlobalFlags, LocalFileHeader, Vec<u8>) {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED | GlobalFlags::SELECTIVE_FEC;
    let mut lfh = LocalFileHeader::minimal_store(b"entry.bin".to_vec(), 32);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"aad-selectiv");
    lfh.encr_algo_id = Some(ENCR_AES256_GCM);
    lfh.iv_nonce = Some(nonce);
    lfh.fec_algo_id = Some(FEC_ALGO_XOR);
    lfh.fec_value = fec_value;
    let bytes = write_lfh(&flags, &lfh).expect("write lfh");
    (flags, lfh, bytes)
}

#[test]
fn lfh_aad_preserves_on_wire_header_size_and_excludes_only_fec_ranges() {
    let fec_value = vec![0xAB; 14];
    let (flags, lfh, lfh_bytes) = sample_lfh(fec_value.clone());

    let aad_lfh_bytes = lfh_bytes_for_aad(flags, &lfh_bytes, FEC_ALGO_XOR, fec_value.len());
    let fec_size_offset = fec_size_field_offset(flags);

    let mut expected = Vec::new();
    expected.extend_from_slice(&lfh_bytes[..fec_size_offset]);
    expected.extend_from_slice(&lfh_bytes[fec_size_offset + 3..lfh_bytes.len() - fec_value.len()]);

    assert_eq!(aad_lfh_bytes, expected);
    assert_eq!(&aad_lfh_bytes[..4], &lfh_bytes[..4]);

    let header_size = u32::from_le_bytes(lfh_bytes[..4].try_into().expect("header size bytes"));
    assert_eq!(header_size as usize, lfh_bytes.len());
    assert_eq!(
        header_size as usize,
        aad_lfh_bytes.len() + 3 + lfh.fec_value.len()
    );
}

#[test]
fn fec_value_bytes_do_not_change_aad() {
    let (flags, _, first_lfh_bytes) = sample_lfh(vec![0x11; 14]);
    let (_, _, second_lfh_bytes) = sample_lfh(vec![0xEE; 14]);

    let first = lfh_bytes_for_aad(flags, &first_lfh_bytes, FEC_ALGO_XOR, 14);
    let second = lfh_bytes_for_aad(flags, &second_lfh_bytes, FEC_ALGO_XOR, 14);

    assert_eq!(first, second);
}

#[test]
fn changing_header_size_bytes_breaks_aead_authentication() {
    let payload = b"authenticated-payload".repeat(4);
    let (flags, lfh, lfh_bytes) = sample_lfh(vec![0xAA; 14]);

    let aad = sar_crypto::aad::build_aead_aad(
        b"global-flags",
        &lfh_bytes_for_aad(flags, &lfh_bytes, FEC_ALGO_XOR, lfh.fec_value.len()),
    );
    let encoded = encode_payload_v2(
        &payload,
        EncodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            compression_level: None,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: lfh.iv_nonce.expect("nonce"),
                aad: aad.clone(),
                key: key(9),
            }),
        },
    )
    .expect("encode");

    let mut tampered_lfh_bytes = lfh_bytes.clone();
    tampered_lfh_bytes[0] ^= 0x01;
    let tampered_aad = sar_crypto::aad::build_aead_aad(
        b"global-flags",
        &lfh_bytes_for_aad(
            flags,
            &tampered_lfh_bytes,
            FEC_ALGO_XOR,
            lfh.fec_value.len(),
        ),
    );

    let err = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            expected_output_size: payload.len() as u64,
            max_output_size: payload.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: ENCR_AES256_GCM,
                iv_nonce: lfh.iv_nonce.expect("nonce"),
                aad: tampered_aad,
                key: key(9),
            }),
        },
    )
    .expect_err("must fail");

    assert!(matches!(err, SarError::AuthFailed(_)));
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

fn write_encrypted_selective_fec_archive() -> (Vec<u8>, SecretString, Vec<u8>) {
    let payload = b"archive-entry-payload".repeat(32);
    let password = SecretString::new("test-password".to_string());
    let opts = ArchiveWriterOptions {
        no_index: true,
        encryption: Some(EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                salt: vec![0x44; 32],
                iterations: 100_000,
                derived_key_length: 32,
            }),
        }),
        fec: Some(FecSettings::default_xor()),
        sparse: false,
    };

    let mut archive = Vec::new();
    let key_provider: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider {
        password: password.clone(),
    });
    {
        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut archive),
            opts,
            CompressionSettings::store(),
            Some(key_provider),
        )
        .expect("writer");
        writer
            .add_entry(EntryInput {
                name: "entry.bin".to_string(),
                payload: payload.clone(),
            })
            .expect("add entry");
        writer.finish().expect("finish");
    }

    (archive, password, payload)
}

#[test]
fn writer_and_reader_compute_identical_aad_for_aead_selective_fec() {
    let (archive, password, payload) = write_encrypted_selective_fec_archive();

    let (header, global_len) = parse_global_header(&archive).expect("global header");
    let (lfh, lfh_len) = parse_lfh(&archive[global_len..], &header.flags).expect("lfh");
    let final_lfh_bytes = &archive[global_len..global_len + lfh_len];

    let global_aad = global_header_flags_bytes(&header);
    let reader_aad = sar_crypto::aad::build_aead_aad(
        &global_aad,
        &lfh_bytes_for_aad(
            header.flags,
            final_lfh_bytes,
            lfh.fec_algo_id.unwrap_or(0),
            lfh.fec_value.len(),
        ),
    );

    let mut placeholder_lfh = lfh.clone();
    placeholder_lfh.fec_value = vec![0u8; lfh.fec_value.len()];
    let placeholder_lfh_bytes =
        write_lfh(&header.flags, &placeholder_lfh).expect("placeholder lfh");
    let writer_aad = sar_crypto::aad::build_aead_aad(
        &global_aad,
        &lfh_bytes_for_aad(
            header.flags,
            &placeholder_lfh_bytes,
            placeholder_lfh.fec_algo_id.unwrap_or(0),
            placeholder_lfh.fec_value.len(),
        ),
    );

    assert_eq!(writer_aad, reader_aad);

    let key_provider: Box<dyn sar_core::KeyProvider> = Box::new(TestKeyProvider { password });
    let mut reader = ArchiveReader::new(Cursor::new(&archive))
        .expect("reader")
        .with_key_provider(key_provider);
    let _ = reader.read_global_header().expect("read global header");
    let entry = reader.next_entry().expect("next entry").expect("entry");
    assert_eq!(entry.payload, payload);
}

#[test]
fn payload_data_starts_at_lfh_start_plus_header_size() {
    let payload = b"payload-offset".repeat(8);
    let mut archive = Vec::new();
    {
        let mut writer = ArchiveWriter::new(
            Cursor::new(&mut archive),
            ArchiveWriterOptions {
                no_index: true,
                encryption: None,
                fec: Some(FecSettings::default_xor()),
                sparse: false,
            },
        )
        .expect("writer");
        writer
            .add_entry(EntryInput {
                name: "offset.bin".to_string(),
                payload: payload.clone(),
            })
            .expect("add entry");
        writer.finish().expect("finish");
    }

    let (header, global_len) = parse_global_header(&archive).expect("global header");
    let (lfh, lfh_len) = parse_lfh(&archive[global_len..], &header.flags).expect("lfh");

    let header_size = usize::try_from(lfh.header_size).expect("header size");
    let payload_start = global_len + header_size;

    assert_eq!(header_size, lfh_len);
    assert_eq!(
        &archive[payload_start..payload_start + payload.len()],
        payload.as_slice()
    );
}
