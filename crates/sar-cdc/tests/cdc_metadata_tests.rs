//! CDC metadata parse/write tests (CDC_MAP round-trips, validation, error cases).

use sar_cdc::{
    algo::{CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL},
    map::{parse_cdc_map, write_cdc_map},
    types::{CDC_MAP_RECORD_LEN, CdcChunk, CdcMap, CdcMapRecord, CdcMetadata},
    validate::{CdcError, validate_cdc_algo_id, validate_cdc_map_bytes, validate_cdc_metadata},
};

fn make_record(seed: u8) -> CdcMapRecord {
    CdcMapRecord {
        hash: [seed; 32],
        partition_id: u16::from(seed),
        absolute_offset: u64::from(seed) * 1024,
        compressed_size: 512,
    }
}

// ---------------------------------------------------------------------------
// validate_cdc_algo_id
// ---------------------------------------------------------------------------

#[test]
fn literal_mode_algo_id_accepted() {
    assert!(validate_cdc_algo_id(CDC_ALGO_LITERAL).is_ok());
}

#[test]
fn fastcdc_algo_id_accepted() {
    assert!(validate_cdc_algo_id(CDC_ALGO_FASTCDC).is_ok());
}

#[test]
fn rabin_algo_id_unsupported() {
    assert!(matches!(
        validate_cdc_algo_id(0x01),
        Err(CdcError::Unsupported(_))
    ));
}

#[test]
fn buzhash_algo_id_unsupported() {
    assert!(matches!(
        validate_cdc_algo_id(0x03),
        Err(CdcError::Unsupported(_))
    ));
}

#[test]
fn reserved_algo_id_rejected() {
    for id in 0x04u8..=0xEF {
        assert!(
            matches!(validate_cdc_algo_id(id), Err(CdcError::ReservedValue(_))),
            "id 0x{id:02X} should be reserved"
        );
    }
}

#[test]
fn custom_range_algo_id_unsupported() {
    for id in 0xF0u8..=0xFF {
        assert!(
            matches!(validate_cdc_algo_id(id), Err(CdcError::Unsupported(_))),
            "id 0x{id:02X} should be unsupported (CUSTOM)"
        );
    }
}

// ---------------------------------------------------------------------------
// validate_cdc_map_bytes
// ---------------------------------------------------------------------------

#[test]
fn valid_map_bytes_accepted() {
    let bytes = vec![0u8; CDC_MAP_RECORD_LEN * 3];
    assert!(validate_cdc_map_bytes(&bytes, 100).is_ok());
}

#[test]
fn empty_map_bytes_accepted() {
    assert!(validate_cdc_map_bytes(&[], 100).is_ok());
}

#[test]
fn non_multiple_length_rejected() {
    let bytes = vec![0u8; CDC_MAP_RECORD_LEN - 1];
    assert!(matches!(
        validate_cdc_map_bytes(&bytes, 100),
        Err(CdcError::Malformed(_))
    ));
}

#[test]
fn record_count_exceeds_limit_rejected() {
    let bytes = vec![0u8; CDC_MAP_RECORD_LEN * 5];
    assert!(matches!(
        validate_cdc_map_bytes(&bytes, 4),
        Err(CdcError::LimitExceeded(_))
    ));
}

// ---------------------------------------------------------------------------
// parse_cdc_map / write_cdc_map round-trip
// ---------------------------------------------------------------------------

#[test]
fn round_trip_empty_map() {
    let map = CdcMap { records: vec![] };
    let bytes = write_cdc_map(&map).expect("write");
    assert!(bytes.is_empty());
    let parsed = parse_cdc_map(&bytes, 100).expect("parse");
    assert_eq!(parsed, map);
}

#[test]
fn round_trip_single_record() {
    let map = CdcMap {
        records: vec![make_record(1)],
    };
    let bytes = write_cdc_map(&map).expect("write");
    assert_eq!(bytes.len(), CDC_MAP_RECORD_LEN);
    let parsed = parse_cdc_map(&bytes, 100).expect("parse");
    assert_eq!(parsed, map);
}

#[test]
fn round_trip_multiple_records() {
    let map = CdcMap {
        records: (0u8..10).map(make_record).collect(),
    };
    let bytes = write_cdc_map(&map).expect("write");
    assert_eq!(bytes.len(), CDC_MAP_RECORD_LEN * 10);
    let parsed = parse_cdc_map(&bytes, 100).expect("parse");
    assert_eq!(parsed, map);
}

#[test]
fn record_fields_preserved() {
    let record = CdcMapRecord {
        hash: [0xAB; 32],
        partition_id: 0x1234,
        absolute_offset: 0x0102_0304_0506_0708,
        compressed_size: 0x8877_6655_4433_2211,
    };
    let map = CdcMap {
        records: vec![record.clone()],
    };
    let bytes = write_cdc_map(&map).expect("write");
    let parsed = parse_cdc_map(&bytes, 1).expect("parse");
    assert_eq!(parsed.records[0], record);
}

#[test]
fn malformed_bytes_rejected_by_parse() {
    // 49 bytes — not a multiple of 50.
    let bytes = vec![0u8; 49];
    assert!(matches!(
        parse_cdc_map(&bytes, 100),
        Err(CdcError::Malformed(_))
    ));
}

#[test]
fn parse_limit_exceeded_rejected() {
    let bytes = vec![0u8; CDC_MAP_RECORD_LEN * 3];
    assert!(matches!(
        parse_cdc_map(&bytes, 2),
        Err(CdcError::LimitExceeded(_))
    ));
}

// ---------------------------------------------------------------------------
// validate_cdc_metadata
// ---------------------------------------------------------------------------

fn make_chunks(sizes: &[u64]) -> Vec<CdcChunk> {
    let mut offset = 0u64;
    sizes
        .iter()
        .map(|&len| {
            let c = CdcChunk {
                offset,
                length: len,
                hash: None,
            };
            offset += len;
            c
        })
        .collect()
}

#[test]
fn valid_metadata_accepted() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: make_chunks(&[1024, 2048, 512]),
    };
    let logical = 1024 + 2048 + 512;
    assert!(validate_cdc_metadata(&meta, logical, 1000).is_ok());
}

#[test]
fn zero_length_chunk_rejected() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: vec![CdcChunk {
            offset: 0,
            length: 0,
            hash: None,
        }],
    };
    assert!(matches!(
        validate_cdc_metadata(&meta, 0, 1000),
        Err(CdcError::InvalidLength(_))
    ));
}

#[test]
fn gap_between_chunks_rejected() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: vec![
            CdcChunk {
                offset: 0,
                length: 500,
                hash: None,
            },
            CdcChunk {
                offset: 600,
                length: 500,
                hash: None,
            }, // gap at 500–600
        ],
    };
    assert!(matches!(
        validate_cdc_metadata(&meta, 1100, 1000),
        Err(CdcError::Bounds(_))
    ));
}

#[test]
fn overlapping_chunks_rejected() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: vec![
            CdcChunk {
                offset: 0,
                length: 500,
                hash: None,
            },
            CdcChunk {
                offset: 400,
                length: 500,
                hash: None,
            }, // overlap
        ],
    };
    assert!(matches!(
        validate_cdc_metadata(&meta, 900, 1000),
        Err(CdcError::Bounds(_))
    ));
}

#[test]
fn chunk_beyond_logical_size_rejected() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: vec![CdcChunk {
            offset: 0,
            length: 2000,
            hash: None,
        }],
    };
    // logical_size = 1000, but chunk extends to 2000
    assert!(matches!(
        validate_cdc_metadata(&meta, 1000, 1000),
        Err(CdcError::Bounds(_))
    ));
}

#[test]
fn partial_coverage_rejected_when_logical_size_known() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: make_chunks(&[500]),
    };
    // logical_size = 1000, chunks only cover 500
    assert!(matches!(
        validate_cdc_metadata(&meta, 1000, 1000),
        Err(CdcError::Bounds(_))
    ));
}

#[test]
fn chunk_count_limit_exceeded() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: make_chunks(&[100, 200, 300]),
    };
    assert!(matches!(
        validate_cdc_metadata(&meta, 600, 2),
        Err(CdcError::LimitExceeded(_))
    ));
}

#[test]
fn zero_logical_size_skips_coverage_check() {
    // When logical_size == 0, coverage / bounds checks are skipped.
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_FASTCDC,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: make_chunks(&[512, 512]),
    };
    assert!(validate_cdc_metadata(&meta, 0, 1000).is_ok());
}

#[test]
fn empty_chunk_list_accepted_for_zero_size() {
    let meta = CdcMetadata {
        algorithm_id: CDC_ALGO_LITERAL,
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
        chunks: vec![],
    };
    assert!(validate_cdc_metadata(&meta, 0, 1000).is_ok());
}
