//! Tests for sparse-file map parsing, writing, validation, and reconstruction.

use sar_core::{
    error::SarError,
    sparse::{
        SparseExtent, apply_sparse_reconstruction, parse_sparse_map, validate_sparse_extents,
        write_sparse_map,
    },
};

// ---------------------------------------------------------------------------
// Parse / write roundtrip
// ---------------------------------------------------------------------------

#[test]
fn parse_write_sparse_map_32bit() {
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 1024,
        },
        SparseExtent {
            offset: 4096,
            length: 2048,
        },
    ];
    let bytes = write_sparse_map(&extents, false);
    assert_eq!(bytes.len(), 16); // 2 × 8 bytes
    let parsed = parse_sparse_map(&bytes, false).expect("parse 32-bit");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].offset, 0);
    assert_eq!(parsed[0].length, 1024);
    assert_eq!(parsed[1].offset, 4096);
    assert_eq!(parsed[1].length, 2048);
}

#[test]
fn parse_write_sparse_map_64bit() {
    let extents = vec![
        SparseExtent {
            offset: 0xFFFF_FFFF_0000_0000,
            length: 0x0000_0000_FFFF_FFFF,
        },
        SparseExtent {
            offset: u64::MAX - 1,
            length: 1,
        },
    ];
    let bytes = write_sparse_map(&extents, true);
    assert_eq!(bytes.len(), 32); // 2 × 16 bytes
    let parsed = parse_sparse_map(&bytes, true).expect("parse 64-bit");
    assert_eq!(parsed[0].offset, 0xFFFF_FFFF_0000_0000);
    assert_eq!(parsed[0].length, 0x0000_0000_FFFF_FFFF);
    assert_eq!(parsed[1].offset, u64::MAX - 1);
    assert_eq!(parsed[1].length, 1);
}

// ---------------------------------------------------------------------------
// Reconstruction
// ---------------------------------------------------------------------------

#[test]
fn reconstruct_sparse_holes_as_zeroes() {
    // Logical file: [D D D D | 0 0 0 0 | E E E E]  (12 bytes)
    // Two extents: [0,4) = "DATA", [8,4) = "EXTS"
    let payload = b"DATAEXTS";
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 4,
        },
        SparseExtent {
            offset: 8,
            length: 4,
        },
    ];
    let out = apply_sparse_reconstruction(payload, &extents, 12).expect("reconstruct");
    assert_eq!(out.len(), 12);
    assert_eq!(&out[0..4], b"DATA");
    assert_eq!(&out[4..8], &[0u8; 4]); // hole
    assert_eq!(&out[8..12], b"EXTS");
}

#[test]
fn extract_sparse_file_safely() {
    // Single extent covering the full logical size — degenerate (non-sparse) case.
    let payload = b"hello world!";
    let extents = vec![SparseExtent {
        offset: 0,
        length: 12,
    }];
    let out = apply_sparse_reconstruction(payload, &extents, 12).expect("reconstruct");
    assert_eq!(&out[..], b"hello world!");
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

#[test]
fn reject_overlapping_extents() {
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 16,
        },
        SparseExtent {
            offset: 8,
            length: 8,
        }, // overlaps
    ];
    let err = validate_sparse_extents(&extents, 64).expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

#[test]
fn reject_extent_beyond_logical_size() {
    let extents = vec![SparseExtent {
        offset: 4,
        length: 8,
    }];
    let err = validate_sparse_extents(&extents, 10).expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

#[test]
fn sparse_invalid_map_error_code() {
    // verify the error maps to SAR_ERR_INVALID_MAP
    use sar_core::error::SarStatus;
    let extents = vec![SparseExtent {
        offset: 0,
        length: 100,
    }];
    let err = validate_sparse_extents(&extents, 50).expect_err("should fail");
    assert_eq!(err.status(), SarStatus::ErrInvalidMap);
}

#[test]
fn parse_sparse_map_alignment_error() {
    // 5 bytes is not a multiple of 8
    let bad = [0u8; 5];
    let err = parse_sparse_map(&bad, false).expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidLength(_)),
        "expected InvalidLength, got {err:?}"
    );
}

#[test]
fn reconstruction_reports_invalid_map_for_out_of_bounds() {
    // Extent end > logical_size in apply_sparse_reconstruction
    let payload = vec![0u8; 8];
    let extents = vec![SparseExtent {
        offset: 0,
        length: 8,
    }];
    let err = apply_sparse_reconstruction(&payload, &extents, 4).expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}
