// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M13-CRYPTO-001: malformed TLS_EXPORTER KMS payloads are rejected while
//! parsing archive Global Headers, reusing the canonical KMS parser.

use std::io::Cursor;

use sar_archive::ArchiveReader;
use sar_core::{GlobalFlags, GlobalHeader, KmsData, SarError, SarStatus, write_global_header};
use sar_crypto::{HASH_BLAKE3, HASH_SHA3_256, HASH_SHA256};
use sar_crypto::{
    KMS_TLS_EXPORTER, TLS_EXPORTER_CONTEXT_VERSION_1, TLS_EXPORTER_KDF_DIRECT,
    TLS_EXPORTER_LABEL_V1, TlsExporterParams, serialize_tls_exporter_kms_payload,
};

fn valid_params() -> TlsExporterParams {
    TlsExporterParams {
        context_version: TLS_EXPORTER_CONTEXT_VERSION_1,
        kdf_algo_id: TLS_EXPORTER_KDF_DIRECT,
        global_header_hash_algo_id: HASH_SHA256,
        derived_key_length: 32,
        exporter_label: String::from_utf8(TLS_EXPORTER_LABEL_V1.to_vec()).expect("ascii"),
        salt: Vec::new(),
    }
}

fn header_bytes(payload: Vec<u8>) -> Vec<u8> {
    write_global_header(&GlobalHeader {
        version: 0x01,
        flags: GlobalFlags::ENCRYPTED | GlobalFlags::NO_INDEX,
        kms: Some(KmsData {
            mode_id: KMS_TLS_EXPORTER,
            payload,
        }),
    })
    .expect("header")
}

fn read_header(payload: Vec<u8>) -> Result<GlobalHeader, SarError> {
    ArchiveReader::new(Cursor::new(header_bytes(payload)))?.read_global_header()
}

fn mutated(f: impl FnOnce(&mut TlsExporterParams)) -> Vec<u8> {
    let mut params = valid_params();
    f(&mut params);
    serialize_tls_exporter_kms_payload(&params).expect("serialize")
}

fn assert_status(payload: Vec<u8>, status: SarStatus) {
    let err = read_header(payload).expect_err("must be rejected");
    assert_eq!(err.status(), status, "{err:?}");
}

#[test]
fn valid_payloads_are_accepted() {
    for hash in [HASH_SHA256, HASH_BLAKE3] {
        let payload = mutated(|p| p.global_header_hash_algo_id = hash);
        let header = read_header(payload).expect("valid TLS_EXPORTER header");
        assert_eq!(header.kms.expect("kms").mode_id, KMS_TLS_EXPORTER);
    }
}

#[test]
fn truncated_and_trailing_payloads_are_malformed() {
    let valid = mutated(|_| {});
    for len in [0, 1, 6, 7, valid.len() - 1] {
        assert_status(valid[..len].to_vec(), SarStatus::ErrMalformed);
    }
    let mut trailing = valid;
    trailing.push(0);
    assert_status(trailing, SarStatus::ErrMalformed);
}

#[test]
fn reserved_identifiers_are_rejected() {
    assert_status(
        mutated(|p| p.context_version = 0x00),
        SarStatus::ErrReservedValue,
    );
    assert_status(
        mutated(|p| p.context_version = 0x02),
        SarStatus::ErrReservedValue,
    );
    assert_status(
        mutated(|p| p.kdf_algo_id = 0x01),
        SarStatus::ErrReservedValue,
    );
    assert_status(
        mutated(|p| p.kdf_algo_id = 0xFF),
        SarStatus::ErrReservedValue,
    );
    assert_status(
        mutated(|p| p.global_header_hash_algo_id = 0x00),
        SarStatus::ErrReservedValue,
    );
    assert_status(
        mutated(|p| p.global_header_hash_algo_id = 0x33),
        SarStatus::ErrReservedValue,
    );
}

#[test]
fn assigned_but_unimplemented_hash_is_unsupported() {
    assert_status(
        mutated(|p| p.global_header_hash_algo_id = HASH_SHA3_256),
        SarStatus::ErrUnsupported,
    );
}

#[test]
fn malformed_length_label_and_salt_fields_are_rejected() {
    for len in [0u16, 16, 31, 33, 64] {
        assert_status(
            mutated(|p| p.derived_key_length = len),
            SarStatus::ErrInvalidLength,
        );
    }
    assert_status(
        mutated(|p| p.exporter_label = "EXPORTER-SAR-v1x".to_string()),
        SarStatus::ErrInvalidLength,
    );
    assert_status(
        mutated(|p| p.exporter_label = "EXPORTER-SAR-v2".to_string()),
        SarStatus::ErrMalformed,
    );
    assert_status(
        mutated(|p| p.exporter_label = "exporter-sar-v1".to_string()),
        SarStatus::ErrMalformed,
    );
    assert_status(
        mutated(|p| p.salt = vec![0x11; 16]),
        SarStatus::ErrInvalidLength,
    );
}

#[test]
fn unsupported_field_combinations_are_rejected_before_any_entry_is_read() {
    // A reserved Context Version takes precedence over an unsupported hash.
    let payload = mutated(|p| {
        p.context_version = 0x02;
        p.global_header_hash_algo_id = HASH_SHA3_256;
    });
    assert_status(payload, SarStatus::ErrReservedValue);
}
