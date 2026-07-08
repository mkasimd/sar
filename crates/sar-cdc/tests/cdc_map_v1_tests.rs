//! CDC_MAP v1 header format tests.
//!
//! Tests cover:
//! * valid BLAKE3 CDC_MAP v1 parses;
//! * valid SHA256 CDC_MAP v1 parses;
//! * unsupported assigned hash algorithm (`0x32` SHA3-256) returns `SAR_ERR_UNSUPPORTED`;
//! * reserved hash algorithm ID returns `SAR_ERR_RESERVED_VALUE`;
//! * unsupported `Map_Version` fails deterministically;
//! * non-zero `Flags` fail;
//! * non-zero `Reserved` bytes fail;
//! * wrong `Record_Size` fails;
//! * TLV Length mismatch fails;
//! * `Record_Count × Record_Size` overflow fails;
//! * `Absolute_Offset + Compressed_Size` overflow fails;
//! * hash verification succeeds for a valid referenced byte range;
//! * hash verification fails for corrupted referenced bytes;
//! * structural validation can run without hash verification.

use sar_cdc::{
    CDC_MAP_HEADER_SIZE, CDC_MAP_RECORD_LEN, CDC_MAP_V1_RECORD_SIZE, CDC_MAP_VERSION_V1,
    map::{parse_cdc_map, verify_cdc_map_record_hash, write_cdc_map},
    types::{CdcMap, CdcMapRecord},
    validate::{CdcError, validate_cdc_map_bytes, validate_cdc_map_hash_algo_id},
};

// ---------------------------------------------------------------------------
// Helper: build a minimal v1 CDC_MAP byte payload from scratch
// ---------------------------------------------------------------------------

/// Build a raw CDC_MAP v1 TLV value from raw parts (no round-trip through the
/// type system, so we can inject invalid fields).
fn build_raw_v1(
    map_version: u8,
    hash_algo_id: u8,
    flags: u16,
    record_count: u32,
    record_size: u16,
    reserved: [u8; 6],
    record_payloads: Vec<u8>, // exactly record_count * record_size bytes
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CDC_MAP_HEADER_SIZE + record_payloads.len());
    out.push(map_version);
    out.push(hash_algo_id);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&record_count.to_le_bytes());
    out.extend_from_slice(&record_size.to_le_bytes());
    out.extend_from_slice(&reserved);
    out.extend_from_slice(&record_payloads);
    out
}

// ---------------------------------------------------------------------------
// Valid parse tests
// ---------------------------------------------------------------------------

#[test]
fn valid_blake3_cdc_map_v1_parses() {
    let record = CdcMapRecord {
        hash: [0xAA; 32],
        partition_id: 1,
        absolute_offset: 0,
        compressed_size: 512,
    };
    let map = CdcMap {
        hash_algorithm_id: 0x31, // BLAKE3
        records: vec![record.clone()],
    };
    let bytes = write_cdc_map(&map).expect("write");
    let parsed = parse_cdc_map(&bytes, 100).expect("parse BLAKE3 CDC_MAP v1");

    assert_eq!(parsed.hash_algorithm_id, 0x31);
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0], record);
}

#[test]
fn valid_sha256_cdc_map_v1_parses() {
    let record = CdcMapRecord {
        hash: [0xBB; 32],
        partition_id: 2,
        absolute_offset: 1024,
        compressed_size: 256,
    };
    let map = CdcMap {
        hash_algorithm_id: 0x30, // SHA-256
        records: vec![record.clone()],
    };
    let bytes = write_cdc_map(&map).expect("write");
    let parsed = parse_cdc_map(&bytes, 100).expect("parse SHA256 CDC_MAP v1");

    assert_eq!(parsed.hash_algorithm_id, 0x30);
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0], record);
}

#[test]
fn valid_empty_blake3_cdc_map_v1_parses() {
    let map = CdcMap {
        hash_algorithm_id: 0x31,
        records: vec![],
    };
    let bytes = write_cdc_map(&map).expect("write");
    assert_eq!(
        bytes.len(),
        CDC_MAP_HEADER_SIZE,
        "header-only map is 16 bytes"
    );
    let parsed = parse_cdc_map(&bytes, 100).expect("parse empty BLAKE3 CDC_MAP");
    assert_eq!(parsed.records.len(), 0);
    assert_eq!(parsed.hash_algorithm_id, 0x31);
}

#[test]
fn round_trip_preserves_all_fields() {
    let records: Vec<CdcMapRecord> = (0u8..5)
        .map(|i| CdcMapRecord {
            hash: [i; 32],
            partition_id: u32::from(i) * 7,
            absolute_offset: u64::from(i) * 4096,
            compressed_size: u32::from(i) * 128 + 64,
        })
        .collect();
    let map = CdcMap {
        hash_algorithm_id: 0x31,
        records: records.clone(),
    };
    let bytes = write_cdc_map(&map).expect("write");
    let parsed = parse_cdc_map(&bytes, 100).expect("parse");
    assert_eq!(parsed.records, records);
}

// ---------------------------------------------------------------------------
// Hash algorithm ID validation
// ---------------------------------------------------------------------------

#[test]
fn blake3_hash_algo_id_accepted() {
    assert!(validate_cdc_map_hash_algo_id(0x31).is_ok());
}

#[test]
fn sha256_hash_algo_id_accepted() {
    assert!(validate_cdc_map_hash_algo_id(0x30).is_ok());
}

#[test]
fn sha3_256_hash_algo_id_is_unsupported() {
    assert!(
        matches!(
            validate_cdc_map_hash_algo_id(0x32),
            Err(CdcError::Unsupported(_))
        ),
        "SHA3-256 (0x32) is assigned but unsupported → SAR_ERR_UNSUPPORTED"
    );
}

#[test]
fn reserved_hash_algo_ids_rejected() {
    // All IDs that are not 0x30, 0x31, or 0x32 are reserved.
    for id in (0x00u8..=0x2F).chain(0x33u8..=0xFF) {
        assert!(
            matches!(
                validate_cdc_map_hash_algo_id(id),
                Err(CdcError::ReservedValue(_))
            ),
            "hash algo ID 0x{id:02X} should be reserved"
        );
    }
}

// ---------------------------------------------------------------------------
// Header structural rejection tests
// ---------------------------------------------------------------------------

#[test]
fn unsupported_map_version_rejected() {
    // Version 0x02 is not defined; must fail deterministically.
    let bytes = build_raw_v1(
        0x02, // bad version
        0x31,
        0,
        0,
        CDC_MAP_V1_RECORD_SIZE,
        [0u8; 6],
        vec![],
    );
    assert!(
        matches!(parse_cdc_map(&bytes, 100), Err(CdcError::Unsupported(_))),
        "unsupported Map_Version must return Unsupported"
    );
}

#[test]
fn map_version_zero_rejected() {
    let bytes = build_raw_v1(0x00, 0x31, 0, 0, CDC_MAP_V1_RECORD_SIZE, [0u8; 6], vec![]);
    assert!(matches!(
        parse_cdc_map(&bytes, 100),
        Err(CdcError::Unsupported(_))
    ));
}

#[test]
fn nonzero_flags_rejected() {
    let bytes = build_raw_v1(
        CDC_MAP_VERSION_V1,
        0x31,
        0x0001, // non-zero flags
        0,
        CDC_MAP_V1_RECORD_SIZE,
        [0u8; 6],
        vec![],
    );
    assert!(
        matches!(parse_cdc_map(&bytes, 100), Err(CdcError::Malformed(_))),
        "non-zero Flags must be rejected"
    );
}

#[test]
fn nonzero_reserved_bytes_rejected() {
    let mut reserved = [0u8; 6];
    reserved[3] = 0x01; // poison one reserved byte
    let bytes = build_raw_v1(
        CDC_MAP_VERSION_V1,
        0x31,
        0,
        0,
        CDC_MAP_V1_RECORD_SIZE,
        reserved,
        vec![],
    );
    assert!(
        matches!(parse_cdc_map(&bytes, 100), Err(CdcError::Malformed(_))),
        "non-zero Reserved bytes must be rejected"
    );
}

#[test]
fn wrong_record_size_rejected() {
    // Record_Size = 50 (old incorrect size) must fail.
    let bytes = build_raw_v1(CDC_MAP_VERSION_V1, 0x31, 0, 0, 50, [0u8; 6], vec![]);
    assert!(
        matches!(parse_cdc_map(&bytes, 100), Err(CdcError::Malformed(_))),
        "Record_Size ≠ 48 must be rejected"
    );
}

#[test]
fn tlv_length_mismatch_rejected() {
    // Build a valid header claiming 1 record but supply 0 bytes of record data.
    let bytes = build_raw_v1(
        CDC_MAP_VERSION_V1,
        0x31,
        0,
        1, // claims 1 record
        CDC_MAP_V1_RECORD_SIZE,
        [0u8; 6],
        vec![], // 0 bytes of records — mismatch
    );
    assert!(
        matches!(parse_cdc_map(&bytes, 100), Err(CdcError::Malformed(_))),
        "TLV Length mismatch must be rejected"
    );
}

#[test]
fn tlv_length_too_short_rejected() {
    // Only 15 bytes — can't even fit the 16-byte header.
    let bytes = vec![0u8; 15];
    assert!(matches!(
        parse_cdc_map(&bytes, 100),
        Err(CdcError::Malformed(_))
    ));
}

#[test]
fn record_count_exceeds_limit_rejected() {
    let map = CdcMap {
        hash_algorithm_id: 0x31,
        records: (0u8..5)
            .map(|i| CdcMapRecord {
                hash: [i; 32],
                partition_id: 0,
                absolute_offset: 0,
                compressed_size: 64,
            })
            .collect(),
    };
    let bytes = write_cdc_map(&map).expect("write");
    assert!(matches!(
        parse_cdc_map(&bytes, 4),
        Err(CdcError::LimitExceeded(_))
    ));
}

// ---------------------------------------------------------------------------
// Overflow tests
// ---------------------------------------------------------------------------

#[test]
fn record_count_times_record_size_overflow_fails() {
    // Craft a header with Record_Count = u32::MAX.  The multiply
    // u32::MAX × 48 overflows usize on both 32-bit and 64-bit targets if we
    // saturate it, and the TLV length check should catch it first via the
    // checked multiplication returning an error OR via TLV length mismatch.
    // We can't actually supply u32::MAX × 48 bytes, so the length check
    // (bytes.len() != expected) fires after the overflow check.
    // Either Overflow or Malformed is acceptable; both indicate rejection.
    let bytes = build_raw_v1(
        CDC_MAP_VERSION_V1,
        0x31,
        0,
        u32::MAX, // would require ~206 GiB of records
        CDC_MAP_V1_RECORD_SIZE,
        [0u8; 6],
        vec![], // no actual record data
    );
    let result = parse_cdc_map(&bytes, usize::MAX);
    assert!(
        matches!(
            result,
            Err(CdcError::Overflow(_)) | Err(CdcError::Malformed(_))
        ),
        "u32::MAX record count must be rejected (overflow or length mismatch)"
    );
}

#[test]
fn absolute_offset_plus_compressed_size_overflow_in_verify() {
    // A record with absolute_offset = u64::MAX and compressed_size = 1 must
    // produce an Overflow error from verify_cdc_map_record_hash.
    let record = CdcMapRecord {
        hash: [0u8; 32],
        partition_id: 0,
        absolute_offset: u64::MAX,
        compressed_size: 1,
    };
    let archive = vec![0u8; 16]; // small archive — overflow occurs before bounds check
    assert!(matches!(
        verify_cdc_map_record_hash(&record, 0x31, &archive),
        Err(CdcError::Overflow(_))
    ));
}

// ---------------------------------------------------------------------------
// Hash verification tests
// ---------------------------------------------------------------------------

/// Compute BLAKE3 hash for a byte slice.
fn blake3_of(data: &[u8]) -> [u8; 32] {
    let h = blake3::hash(data);
    *h.as_bytes()
}

/// Compute SHA-256 hash for a byte slice.
fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[test]
fn blake3_hash_verification_succeeds_for_valid_range() {
    // Archive: 128 zero bytes.  Chunk lives at [32, 64).
    let archive = vec![0u8; 128];
    let chunk_bytes = &archive[32..64];
    let expected_hash = blake3_of(chunk_bytes);

    let record = CdcMapRecord {
        hash: expected_hash,
        partition_id: 0,
        absolute_offset: 32,
        compressed_size: 32,
    };

    let ok = verify_cdc_map_record_hash(&record, 0x31, &archive).expect("verify should not error");
    assert!(ok, "BLAKE3 hash verification must succeed for correct hash");
}

#[test]
fn blake3_hash_verification_fails_for_corrupted_bytes() {
    let mut archive = vec![0u8; 128];
    let expected_hash = blake3_of(&archive[32..64]);

    // Corrupt the archive after computing the hash.
    archive[40] = 0xFF;

    let record = CdcMapRecord {
        hash: expected_hash,
        partition_id: 0,
        absolute_offset: 32,
        compressed_size: 32,
    };

    let ok = verify_cdc_map_record_hash(&record, 0x31, &archive).expect("verify should not error");
    assert!(
        !ok,
        "BLAKE3 hash verification must fail for corrupted bytes"
    );
}

#[test]
fn sha256_hash_verification_succeeds_for_valid_range() {
    let archive = vec![0xABu8; 64];
    let expected_hash = sha256_of(&archive[0..32]);

    let record = CdcMapRecord {
        hash: expected_hash,
        partition_id: 0,
        absolute_offset: 0,
        compressed_size: 32,
    };

    let ok = verify_cdc_map_record_hash(&record, 0x30, &archive)
        .expect("sha256 verify should not error");
    assert!(
        ok,
        "SHA-256 hash verification must succeed for correct hash"
    );
}

#[test]
fn sha256_hash_verification_fails_for_corrupted_bytes() {
    let archive = vec![0x00u8; 64];
    let expected_hash = sha256_of(&archive[0..32]);

    // Corrupt one byte.
    let mut corrupt_archive = archive.clone();
    corrupt_archive[10] = 0xFF;

    let record = CdcMapRecord {
        hash: expected_hash,
        partition_id: 0,
        absolute_offset: 0,
        compressed_size: 32,
    };

    let ok = verify_cdc_map_record_hash(&record, 0x30, &corrupt_archive)
        .expect("sha256 verify should not error");
    assert!(
        !ok,
        "SHA-256 hash verification must fail for corrupted bytes"
    );
}

#[test]
fn verify_returns_bounds_error_when_range_exceeds_archive() {
    let archive = vec![0u8; 32];
    let record = CdcMapRecord {
        hash: [0u8; 32],
        partition_id: 0,
        absolute_offset: 20,
        compressed_size: 20, // [20, 40) exceeds 32 bytes
    };
    assert!(matches!(
        verify_cdc_map_record_hash(&record, 0x31, &archive),
        Err(CdcError::Bounds(_))
    ));
}

#[test]
fn verify_unsupported_hash_algo_returns_unsupported() {
    let archive = vec![0u8; 64];
    let record = CdcMapRecord {
        hash: [0u8; 32],
        partition_id: 0,
        absolute_offset: 0,
        compressed_size: 32,
    };
    // SHA3-256 is assigned but unsupported.
    assert!(matches!(
        verify_cdc_map_record_hash(&record, 0x32, &archive),
        Err(CdcError::Unsupported(_))
    ));
}

#[test]
fn verify_reserved_hash_algo_returns_reserved_value() {
    let archive = vec![0u8; 64];
    let record = CdcMapRecord {
        hash: [0u8; 32],
        partition_id: 0,
        absolute_offset: 0,
        compressed_size: 32,
    };
    assert!(matches!(
        verify_cdc_map_record_hash(&record, 0x00, &archive),
        Err(CdcError::ReservedValue(_))
    ));
}

// ---------------------------------------------------------------------------
// Structural validation without hash verification
// ---------------------------------------------------------------------------

#[test]
fn structural_validation_does_not_require_hash_verification() {
    // Parse a CDC_MAP without supplying archive bytes.  Structural validation
    // (header checks, length checks, field checks) must succeed independently.
    let records: Vec<CdcMapRecord> = (0u8..3)
        .map(|i| CdcMapRecord {
            hash: [i; 32], // placeholder hashes — not verified here
            partition_id: u32::from(i),
            absolute_offset: u64::from(i) * 1000,
            compressed_size: 500,
        })
        .collect();
    let map = CdcMap {
        hash_algorithm_id: 0x31,
        records: records.clone(),
    };
    let bytes = write_cdc_map(&map).expect("write");

    // Structural parse must succeed even though we do not verify hashes.
    let parsed = parse_cdc_map(&bytes, 100).expect("structural parse must succeed");
    assert_eq!(parsed.records.len(), 3);

    // Structural validation via the convenience wrapper must also succeed.
    validate_cdc_map_bytes(&bytes, 100).expect("structural validate_cdc_map_bytes must succeed");
}

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

#[test]
fn header_size_constant_is_16() {
    assert_eq!(CDC_MAP_HEADER_SIZE, 16);
}

#[test]
fn record_size_constant_is_48() {
    assert_eq!(CDC_MAP_RECORD_LEN, 48);
    assert_eq!(CDC_MAP_V1_RECORD_SIZE, 48);
}

#[test]
fn map_version_constant_is_1() {
    assert_eq!(CDC_MAP_VERSION_V1, 0x01);
}

#[test]
fn written_bytes_have_correct_layout() {
    // Verify the exact on-wire layout of a single-record BLAKE3 CDC_MAP.
    let record = CdcMapRecord {
        hash: [0x11; 32],
        partition_id: 0x0000_00AB,
        absolute_offset: 0x0000_0000_0000_CAFE,
        compressed_size: 0x0000_0400,
    };
    let map = CdcMap {
        hash_algorithm_id: 0x31,
        records: vec![record],
    };
    let bytes = write_cdc_map(&map).expect("write");

    // Header
    assert_eq!(bytes[0], 0x01, "Map_Version must be 0x01");
    assert_eq!(bytes[1], 0x31, "Hash_Algorithm_ID must be 0x31 (BLAKE3)");
    assert_eq!(&bytes[2..4], &[0x00, 0x00], "Flags must be 0");
    assert_eq!(
        &bytes[4..8],
        &[0x01, 0x00, 0x00, 0x00],
        "Record_Count LE = 1"
    );
    assert_eq!(&bytes[8..10], &[0x30, 0x00], "Record_Size LE = 48 = 0x30");
    assert_eq!(&bytes[10..16], &[0u8; 6], "Reserved must be 0");

    // Record
    assert_eq!(&bytes[16..48], &[0x11u8; 32], "Hash = [0x11; 32]");
    assert_eq!(&bytes[48..52], &[0xAB, 0x00, 0x00, 0x00], "Partition_ID LE");
    assert_eq!(
        &bytes[52..60],
        &[0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "Absolute_Offset LE"
    );
    assert_eq!(
        &bytes[60..64],
        &[0x00, 0x04, 0x00, 0x00],
        "Compressed_Size LE"
    );

    assert_eq!(bytes.len(), 64, "total size = 16 + 48 = 64");
}
