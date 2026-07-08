/// CDC interaction tests: CDC metadata with STORE, compressed, encrypted, sparse,
/// fragmented entries.  Also verifies that resource limits are enforced for CDC.
use std::io::Cursor;

use sar_core::{
    ArchiveReader, GlobalFlags, ResourceLimits, SarError,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
    tlv::Tlv,
};

/// Build a minimal CDC-aware archive with a single STORE entry using the given
/// `cdc_algo_id`.  `extra_tlvs` are appended to `LocalFileHeader::fec_value` workaround?
/// Actually: the LocalFileHeader doesn't have a generic tlvs field.  TLV content
/// in LFH is embedded via sparse_map / fec_value bytes; CDC_MAP TLVs are in the
/// Central Dictionary.  For simplicity these tests focus on the LFH cdc_algo_id
/// field and verify archive-level CDC parsing.
fn build_cdc_archive(cdc_algo_id: u8, payload: &[u8]) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::CDC_SUPPORT;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    let mut lfh = LocalFileHeader::minimal_store(b"test.bin".to_vec(), payload.len() as u64);
    lfh.cdc_algo_id = Some(cdc_algo_id);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(payload);
    bytes
}

// ---------------------------------------------------------------------------
// Basic CDC parsing — LITERAL_MODE (0x00)
// ---------------------------------------------------------------------------

#[test]
fn cdc_literal_mode_entry_parses() {
    let bytes = build_cdc_archive(0x00, b"hello world");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");
    assert_eq!(entry.metadata.cdc_algo_id, Some(0x00));
    assert_eq!(entry.payload, b"hello world");
}

// ---------------------------------------------------------------------------
// Basic CDC parsing — FASTCDC (0x02)
// ---------------------------------------------------------------------------

#[test]
fn cdc_fastcdc_entry_parses() {
    let payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let bytes = build_cdc_archive(0x02, &payload);
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");
    assert_eq!(entry.metadata.cdc_algo_id, Some(0x02));
    assert_eq!(entry.payload, payload);
}

// ---------------------------------------------------------------------------
// Reserved algorithm IDs fail closed
// ---------------------------------------------------------------------------

#[test]
fn cdc_reserved_algo_id_fails_closed() {
    // 0x04–0xEF are reserved
    let bytes = build_cdc_archive(0x10, b"data");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader.next_entry().expect_err("must fail");
    assert!(
        matches!(err, SarError::Unsupported(_) | SarError::ReservedValue(_)),
        "expected Unsupported or ReservedValue for reserved CDC algo 0x10, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// RABIN (0x01) is optional — current implementation fails closed
// ---------------------------------------------------------------------------

#[test]
fn cdc_rabin_algo_id_reports_unsupported() {
    let bytes = build_cdc_archive(0x01, b"data");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader
        .next_entry()
        .expect_err("must fail for unsupported algo");
    assert!(
        matches!(err, SarError::Unsupported(_)),
        "expected Unsupported for Rabin (0x01), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Custom algorithm IDs (0xF0–0xFF) fail closed
// ---------------------------------------------------------------------------

#[test]
fn cdc_custom_algo_id_fails_closed() {
    let bytes = build_cdc_archive(0xF5, b"data");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader.next_entry().expect_err("must fail");
    assert!(
        matches!(err, SarError::Unsupported(_)),
        "expected Unsupported for custom CDC algo 0xF5, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// CDC without CDC_SUPPORT flag — cdc_algo_id should be None
// ---------------------------------------------------------------------------

#[test]
fn entry_without_cdc_support_flag_has_no_cdc_algo_id() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let lfh = LocalFileHeader::minimal_store(b"plain.bin".to_vec(), 5);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"hello");

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");
    assert_eq!(entry.metadata.cdc_algo_id, None);
}

// ---------------------------------------------------------------------------
// Verify: CDC support flag tracked in VerificationReport
// ---------------------------------------------------------------------------

#[test]
fn verification_report_tracks_cdc_support() {
    let bytes = build_cdc_archive(0x00, b"hello");
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader.verify().expect("verify");
    assert!(report.cdc_support, "cdc_support should be true");
    assert_eq!(report.cdc_entry_count, 1, "one CDC entry expected");
}

#[test]
fn verification_report_no_cdc_when_flag_absent() {
    let flags = GlobalFlags::NO_INDEX;
    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let lfh = LocalFileHeader::minimal_store(b"plain.bin".to_vec(), 3);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"abc");

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let report = reader.verify().expect("verify");
    assert!(
        !report.cdc_support,
        "cdc_support should be false when flag absent"
    );
    assert_eq!(report.cdc_entry_count, 0);
}

// ---------------------------------------------------------------------------
// CDC resource limits: validate_recipe_payload
// ---------------------------------------------------------------------------

#[test]
fn cdc_chunk_count_resource_limit_enforced() {
    let limit = ResourceLimits {
        max_cdc_chunk_count: 2,
        ..Default::default()
    };

    // Each chunk hash is 32 bytes; 3 hashes exceeds limit of 2
    let recipe_payload = vec![0u8; 32 * 3];
    let err =
        sar_core::cdc::validate_recipe_payload(&recipe_payload, &limit).expect_err("must fail");
    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded when chunk count exceeds max_cdc_chunk_count, got {err:?}"
    );
}

#[test]
fn cdc_metadata_bytes_resource_limit_enforced() {
    // max_cdc_metadata_bytes less than one 32-byte hash
    let limit = ResourceLimits {
        max_cdc_chunk_count: 1_000_000,
        max_cdc_metadata_bytes: 31,
        ..Default::default()
    };
    let recipe_payload = vec![0u8; 32];
    let err =
        sar_core::cdc::validate_recipe_payload(&recipe_payload, &limit).expect_err("must fail");
    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded for metadata bytes, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// CDC_MAP TLV parse_entry_cdc_map: malformed payload rejected
// ---------------------------------------------------------------------------

#[test]
fn cdc_map_tlv_invalid_length_rejected() {
    // Fewer than 16 bytes — cannot contain the v1 header.
    let bad_value = vec![0u8; 10];
    let tlvs = vec![Tlv {
        type_id: 0x40,
        value: bad_value,
    }];
    let err = sar_core::cdc::parse_entry_cdc_map(&tlvs, &ResourceLimits::default())
        .expect_err("must fail for payload shorter than the 16-byte v1 header");
    assert!(
        matches!(err, SarError::Malformed(_)),
        "expected Malformed for truncated CDC_MAP payload, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// CDC_MAP round-trip: write then parse preserves record
// ---------------------------------------------------------------------------

#[test]
fn cdc_map_round_trip() {
    use sar_cdc::{CdcMap, CdcMapRecord};

    let map = CdcMap {
        hash_algorithm_id: 0x31, // BLAKE3
        records: vec![CdcMapRecord {
            hash: [0xABu8; 32],
            partition_id: 7,
            absolute_offset: 1024,
            compressed_size: 512,
        }],
    };

    let limits = ResourceLimits::default();
    let tlv = sar_core::cdc::make_cdc_map_tlv(&map, &limits).expect("make tlv");
    assert_eq!(tlv.type_id, 0x40);

    let tlvs = vec![tlv];
    let parsed = sar_core::cdc::parse_entry_cdc_map(&tlvs, &limits)
        .expect("parse")
        .expect("Some");
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].hash, [0xABu8; 32]);
    assert_eq!(parsed.records[0].partition_id, 7);
    assert_eq!(parsed.records[0].absolute_offset, 1024);
    assert_eq!(parsed.records[0].compressed_size, 512);
}

// ---------------------------------------------------------------------------
// CDC with compressed entry does not affect decompression
// ---------------------------------------------------------------------------

#[test]
fn cdc_with_compressed_entry_decompresses_correctly() {
    use sar_compression::{COMP_ALGO_DEFLATE, CompressionOptions, encode_stream};

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED | GlobalFlags::CDC_SUPPORT;
    let payload = b"hello compressed cdc payload".repeat(10);

    let mut compressed = Vec::new();
    encode_stream(
        COMP_ALGO_DEFLATE,
        &mut payload.as_slice(),
        &mut compressed,
        CompressionOptions { level: Some(6) },
    )
    .expect("compress");

    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"cdc_comp.bin".to_vec(), payload.len() as u64);
    lfh.cdc_algo_id = Some(0x00); // LITERAL
    lfh.comp_algo_id = Some(COMP_ALGO_DEFLATE);
    lfh.uncompressed_size = payload.len() as u64;
    lfh.payload_size = compressed.len() as u64;
    // Set IS_COMPRESSED entry mode bit so the reader decompresses this entry
    lfh.entry_mode = sar_core::EntryMode::from_bits(sar_core::EntryMode::COMPRESSED);
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(&compressed);

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");
    assert_eq!(entry.metadata.cdc_algo_id, Some(0x00));
    assert_eq!(entry.payload, payload.to_vec());
}

// ---------------------------------------------------------------------------
// CDC + SPARSE: CDC_SUPPORT flag does not break sparse entries
// ---------------------------------------------------------------------------

#[test]
fn cdc_support_with_sparse_entry_works() {
    use sar_core::sparse::{SparseExtent, write_sparse_map};

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::CDC_SUPPORT | GlobalFlags::SPARSE_FILES;

    let extents = vec![SparseExtent {
        offset: 0,
        length: 4,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false);

    let mut bytes = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"sparse_cdc.bin".to_vec(), 4u64);
    lfh.cdc_algo_id = Some(0x00); // LITERAL
    lfh.sparse_map = sparse_map_bytes;
    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    bytes.extend_from_slice(&lfh_bytes);
    bytes.extend_from_slice(b"AAAA");

    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    reader.read_global_header().expect("header");
    let entry = reader.next_entry().expect("entry").expect("some");
    assert_eq!(entry.metadata.cdc_algo_id, Some(0x00));
    assert!(
        entry.metadata.sparse_extents.is_some(),
        "sparse extents missing when CDC_SUPPORT active"
    );
}

// ---------------------------------------------------------------------------
// Recipe payload: non-multiple-of-32 is invalid
// ---------------------------------------------------------------------------

#[test]
fn recipe_payload_not_multiple_of_32_rejected() {
    let bad_payload = vec![0u8; 33]; // 33 bytes is not a multiple of 32
    let err = sar_core::cdc::validate_recipe_payload(&bad_payload, &ResourceLimits::default())
        .expect_err("must fail");
    assert!(
        matches!(err, SarError::InvalidLength(_)),
        "expected InvalidLength for non-multiple-of-32 recipe, got {err:?}"
    );
}

#[test]
fn recipe_payload_empty_is_valid_zero_chunks() {
    // An empty recipe payload (no chunks) is valid (file with no content)
    let count = sar_core::cdc::validate_recipe_payload(&[], &ResourceLimits::default())
        .expect("empty recipe should be valid");
    assert_eq!(count, 0);
}
