// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::{
    GlobalFlags, SarError,
    format::{GlobalHeader, KmsData, parse_global_header, write_global_header},
};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

#[test]
fn parses_valid_minimal_global_header() {
    let header = GlobalHeader {
        version: 1,
        flags_bytes: GlobalFlags::NO_INDEX.bits().to_le_bytes().to_vec(),
        flags: GlobalFlags::NO_INDEX,
        partition_descriptor: None,
        kms: None,
    };

    let bytes = write_global_header(&header).expect("write header");
    let (parsed, consumed) =
        parse_global_header(&bytes, &unlimited_limits()).expect("parse header");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.flags, GlobalFlags::NO_INDEX);
}

#[test]
fn rejects_wrong_magic() {
    let mut bytes = b"BAD!\x01\x00\x04\x00\x00\x00\x00\x00".to_vec();
    bytes[0] = b'X';
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidMagic));
}

#[test]
fn rejects_non_zero_reserved_byte() {
    let mut bytes = b"SAR!\x01\x01\x04\x00\x00\x00\x00\x00".to_vec();
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
    bytes[5] = 0;
}

#[test]
fn rejects_flags_size_less_than_four() {
    let bytes = b"SAR!\x01\x00\x03\x00\x00\x00\x00".to_vec();
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)));
}

#[test]
fn rejects_unsupported_version() {
    let bytes = b"SAR!\x02\x00\x04\x00\x00\x00\x00\x00".to_vec();
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidVersion(_)));
}

#[test]
fn rejects_encrypted_header_with_invalid_kms_mode() {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&GlobalFlags::ENCRYPTED.bits().to_le_bytes());
    bytes.push(0x10);
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn requires_kms_when_encrypted_on_write() {
    let header = GlobalHeader {
        version: 1,
        flags_bytes: GlobalFlags::ENCRYPTED.bits().to_le_bytes().to_vec(),
        flags: GlobalFlags::ENCRYPTED,
        partition_descriptor: None,
        kms: None,
    };

    let err = write_global_header(&header).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn supports_structural_kms_but_not_custom_mode() {
    let header = GlobalHeader {
        version: 1,
        flags_bytes: GlobalFlags::ENCRYPTED.bits().to_le_bytes().to_vec(),
        flags: GlobalFlags::ENCRYPTED,
        partition_descriptor: None,
        kms: Some(KmsData {
            mode_id: 0xF0,
            payload: vec![1, 2, 3],
        }),
    };

    let bytes = write_global_header(&header).expect("write header");
    let err = parse_global_header(&bytes, &unlimited_limits())
        .expect_err("custom mode should be unsupported");
    assert!(matches!(err, SarError::Unsupported(_)));
}
