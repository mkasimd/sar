// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::{
    GlobalFlags, SarError,
    format::{GlobalHeader, KmsData, parse_global_header, write_global_header},
};

/// Build a minimal valid-magic byte stream with the given 4-byte flags value.
///
/// Used by PR5 profile-rejection regression tests to construct global headers
/// that pass magic/version/reserved checks but fail flag-validation checks.
fn make_header_bytes(flags: GlobalFlags) -> Vec<u8> {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&flags.bits().to_le_bytes());
    bytes
}

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

#[test]
fn parses_valid_minimal_global_header() {
    let header = GlobalHeader {
        version: 1,
        flags: GlobalFlags::NO_INDEX,
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
fn rejects_unassigned_version_as_reserved_value() {
    for version in [0x00u8, 0x02, 0xFF] {
        let mut bytes = b"SAR!\x01\x00\x04\x00\x00\x00\x00\x00".to_vec();
        bytes[4] = version;
        let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
        assert!(
            matches!(err, SarError::ReservedValue(_)),
            "version {version:#x}"
        );
    }
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
        flags: GlobalFlags::ENCRYPTED,
        kms: None,
    };

    let err = write_global_header(&header).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn supports_structural_kms_but_not_custom_mode() {
    let header = GlobalHeader {
        version: 1,
        flags: GlobalFlags::ENCRYPTED,
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

// ---------------------------------------------------------------------------
// PR5 profile-rejection regression tests: flag-conflict and parse-level checks
// ---------------------------------------------------------------------------

#[test]
fn rejects_no_index_combined_with_opt_present() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::OPT_PRESENT;
    let bytes = make_header_bytes(flags);
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn rejects_no_index_combined_with_global_crc32() {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_GLOBAL_CRC32;
    let bytes = make_header_bytes(flags);
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn rejects_has_global_ec_without_opt_present() {
    let flags = GlobalFlags::HAS_GLOBAL_EC;
    let bytes = make_header_bytes(flags);
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn rejects_signed_without_opt_present() {
    let flags = GlobalFlags::SIGNED;
    let bytes = make_header_bytes(flags);
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::FlagConflict(_)));
}

#[test]
fn version_is_checked_before_flags() {
    let bytes = b"SAR!\xff\x00\x04\x00\x02\x00\x00\x00".to_vec();
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn rejects_kms_mode_in_reserved_range() {
    // KMS mode 0x05 is in the reserved range (0x05..0xEF).
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&GlobalFlags::ENCRYPTED.bits().to_le_bytes());
    bytes.push(0x05);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

const RESERVED_BITS: [u32; 11] = [6, 7, 11, 12, 13, 14, 15, 21, 22, 23, 31];

fn raw_header(flags: u32) -> Vec<u8> {
    let mut bytes = b"SAR!\x01\x00\x04\x00".to_vec();
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes
}

#[test]
fn rejects_each_reserved_flag_bit_individually() {
    for bit in RESERVED_BITS {
        let bytes = raw_header(1 << bit);
        let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
        assert!(matches!(err, SarError::ReservedValue(_)), "bit {bit}");
    }
}

#[test]
fn reserved_bit_takes_precedence_over_flag_conflict() {
    let flags = (GlobalFlags::NO_INDEX | GlobalFlags::OPT_PRESENT).bits() | (1 << 6);
    let err = parse_global_header(&raw_header(flags), &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}

#[test]
fn rejects_every_flags_size_other_than_four() {
    for size in [0u16, 1, 2, 3, 5, 8, 65_535] {
        let mut bytes = raw_header(0);
        bytes[6..8].copy_from_slice(&size.to_le_bytes());
        let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
        assert!(matches!(err, SarError::InvalidLength(_)), "size {size}");
    }
}

#[test]
fn flags_size_is_checked_before_flag_bits() {
    let mut bytes = raw_header(1 << 6);
    bytes[6] = 5;
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::InvalidLength(_)));
}

#[test]
fn truncated_fixed_header_is_rejected_at_every_boundary() {
    let bytes = raw_header(GlobalFlags::NO_INDEX.bits());
    for len in 0..bytes.len() {
        let err = parse_global_header(&bytes[..len], &unlimited_limits()).expect_err("must fail");
        assert!(matches!(err, SarError::Truncated(_)), "len {len}");
    }
}

#[test]
fn header_length_is_twelve_without_kms_and_extended_with_kms() {
    let plain = GlobalHeader {
        version: 1,
        flags: GlobalFlags::NO_INDEX,
        kms: None,
    };
    let bytes = write_global_header(&plain).expect("write");
    assert_eq!(bytes.len(), 12);
    assert_eq!(
        sar_core::format::global_header_flags_bytes(&plain)
            .expect("aad")
            .len(),
        12
    );

    let kms = GlobalHeader {
        version: 1,
        flags: GlobalFlags::ENCRYPTED,
        kms: Some(KmsData {
            mode_id: sar_crypto::KMS_PBKDF2,
            payload: vec![9; 7],
        }),
    };
    let bytes = write_global_header(&kms).expect("write");
    assert_eq!(bytes.len(), 12 + 5 + 7);
    let (parsed, consumed) = parse_global_header(&bytes, &unlimited_limits()).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.kms.expect("kms").payload, vec![9; 7]);
    assert_eq!(
        sar_core::format::global_header_flags_bytes(&kms)
            .expect("aad")
            .len(),
        12
    );
}

#[test]
fn partitioned_header_parses_without_descriptor() {
    let bytes = raw_header((GlobalFlags::NO_INDEX | GlobalFlags::PARTITIONED_ARCHIVE).bits());
    let (parsed, consumed) = parse_global_header(&bytes, &unlimited_limits()).expect("parse");
    assert_eq!(consumed, 12);
    assert!(parsed.flags.contains(GlobalFlags::PARTITIONED_ARCHIVE));
    assert!(matches!(
        sar_core::require_unpartitioned_processing(parsed.flags),
        Err(SarError::Unsupported(_))
    ));
}

#[test]
fn writer_and_aad_reject_bad_version_and_reserved_bits() {
    let bad_version = GlobalHeader {
        version: 2,
        flags: GlobalFlags::NO_INDEX,
        kms: None,
    };
    assert!(matches!(
        write_global_header(&bad_version),
        Err(SarError::ReservedValue(_))
    ));
    assert!(matches!(
        sar_core::format::global_header_flags_bytes(&bad_version),
        Err(SarError::ReservedValue(_))
    ));
    let reserved = GlobalHeader {
        version: 1,
        flags: GlobalFlags::from_bits_retain(1 << 6),
        kms: None,
    };
    assert!(matches!(
        write_global_header(&reserved),
        Err(SarError::ReservedValue(_))
    ));
    assert!(matches!(
        sar_core::format::global_header_flags_bytes(&reserved),
        Err(SarError::ReservedValue(_))
    ));
}

#[test]
fn nonzero_reserved_header_byte_takes_precedence_over_flags_size() {
    let mut bytes = raw_header(0);
    bytes[5] = 1;
    bytes[6] = 9;
    let err = parse_global_header(&bytes, &unlimited_limits()).expect_err("must fail");
    assert!(matches!(err, SarError::ReservedValue(_)));
}
