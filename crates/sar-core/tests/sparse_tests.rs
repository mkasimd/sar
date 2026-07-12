// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Tests for sparse-file map parsing, writing, validation, and reconstruction.

use sar_core::{
    error::SarError,
    sparse::{SparseExtent, parse_sparse_map, write_sparse_map},
};
use sar_sparse::{SparseError, apply_sparse_reconstruction, validate_sparse_extents};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

fn sparse_unlimited() -> sar_sparse::SparseLimits {
    sar_core::ResourceLimits::unlimited().sparse_limits()
}

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
    let bytes = write_sparse_map(&extents, false).expect("write 32-bit sparse map ok");
    assert_eq!(bytes.len(), 16); // 2 × 8 bytes
    let parsed = parse_sparse_map(&bytes, false, &unlimited_limits()).expect("parse 32-bit");
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
    let bytes = write_sparse_map(&extents, true).expect("write 64-bit sparse map ok");
    assert_eq!(bytes.len(), 32); // 2 × 16 bytes
    let parsed = parse_sparse_map(&bytes, true, &unlimited_limits()).expect("parse 64-bit");
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
    let out = apply_sparse_reconstruction(payload, &extents, 12, &sparse_unlimited())
        .expect("reconstruct");
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
    let out = apply_sparse_reconstruction(payload, &extents, 12, &sparse_unlimited())
        .expect("reconstruct");
    assert_eq!(&out[..], b"hello world!");
}

/// Trailing hole: final size is Uncompressed Size (10), last extent ends at 5.
/// Bytes [5..10) must be 0x00.
///
/// ```text
/// Uncompressed Size: 10
/// Sparse Map:  offset=2, length=3
/// Stored Payload: ABC
/// Expected: 00 00 41 42 43 00 00 00 00 00
/// ```
#[test]
fn reconstruct_trailing_hole_uses_logical_size() {
    let payload = b"ABC";
    let extents = vec![SparseExtent {
        offset: 2,
        length: 3,
    }];
    let out = apply_sparse_reconstruction(payload, &extents, 10, &sparse_unlimited())
        .expect("reconstruct");
    assert_eq!(out.len(), 10);
    assert_eq!(&out[0..2], &[0u8; 2]); // leading hole
    assert_eq!(&out[2..5], b"ABC"); // data
    assert_eq!(&out[5..10], &[0u8; 5]); // trailing hole
}

/// Leading + middle + trailing hole.
///
/// ```text
/// Uncompressed Size: 12
/// Sparse Map:  offset=2, length=3 | offset=8, length=2
/// Stored Payload: ABCDE
/// Expected: 00 00 A B C 00 00 00 D E 00 00
/// ```
#[test]
fn reconstruct_leading_middle_trailing_holes() {
    let payload = b"ABCDE";
    let extents = vec![
        SparseExtent {
            offset: 2,
            length: 3,
        },
        SparseExtent {
            offset: 8,
            length: 2,
        },
    ];
    let out = apply_sparse_reconstruction(payload, &extents, 12, &sparse_unlimited())
        .expect("reconstruct");
    assert_eq!(out.len(), 12);
    assert_eq!(&out[0..2], &[0u8; 2]); // leading hole
    assert_eq!(&out[2..5], b"ABC");
    assert_eq!(&out[5..8], &[0u8; 3]); // middle hole
    assert_eq!(&out[8..10], b"DE");
    assert_eq!(&out[10..12], &[0u8; 2]); // trailing hole
}

/// Payload longer than sum of extent lengths must fail.
#[test]
fn reconstruct_rejects_excess_payload() {
    // extents consume 3 bytes, payload is 5 bytes
    let payload = b"ABCDE";
    let extents = vec![SparseExtent {
        offset: 0,
        length: 3,
    }];
    let err = apply_sparse_reconstruction(payload, &extents, 10, &sparse_unlimited())
        .expect_err("should fail with excess payload");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap for excess payload, got {err:?}"
    );
}

/// Payload shorter than sum of extent lengths must fail.
#[test]
fn reconstruct_rejects_short_payload() {
    // extents claim 8 bytes but payload is only 4
    let payload = b"ABCD";
    let extents = vec![SparseExtent {
        offset: 0,
        length: 8,
    }];
    let err = apply_sparse_reconstruction(payload, &extents, 10, &sparse_unlimited())
        .expect_err("should fail with short payload");
    assert!(
        matches!(err, SparseError::Truncated(_)),
        "expected Truncated, got {err:?}"
    );
}

/// descriptor offset + length > Uncompressed Size must fail.
///
/// ```text
/// Uncompressed Size: 10
/// Sparse Map:  offset=8, length=3  (end=11 > 10)
/// Expected: SAR_ERR_INVALID_MAP
/// ```
#[test]
fn reconstruct_rejects_extent_beyond_logical_size_in_apply() {
    let payload = b"ABC";
    let extents = vec![SparseExtent {
        offset: 8,
        length: 3,
    }];
    let err = apply_sparse_reconstruction(payload, &extents, 10, &sparse_unlimited())
        .expect_err("should fail with extent beyond logical size");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

/// Zero-length sparse extents are rejected (fail closed).
#[test]
fn zero_length_extent_is_rejected() {
    let payload = b"ABC";
    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 0,
        }, // zero-length: must be rejected
        SparseExtent {
            offset: 2,
            length: 3,
        },
    ];
    let err = apply_sparse_reconstruction(payload, &extents, 10, &sparse_unlimited())
        .expect_err("zero-length extent must be rejected");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap for zero-length extent, got {err:?}"
    );
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
    let err = validate_sparse_extents(&extents, 64, &sparse_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

#[test]
fn reject_extent_beyond_logical_size() {
    let extents = vec![SparseExtent {
        offset: 4,
        length: 8,
    }];
    let err = validate_sparse_extents(&extents, 10, &sparse_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

#[test]
fn sparse_invalid_map_error_code() {
    // verify the error is the InvalidMap variant (maps to SAR_ERR_INVALID_MAP)
    let extents = vec![SparseExtent {
        offset: 0,
        length: 100,
    }];
    let err = validate_sparse_extents(&extents, 50, &sparse_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

#[test]
fn parse_sparse_map_alignment_error() {
    // 5 bytes is not a multiple of 8
    let bad = [0u8; 5];
    let err = parse_sparse_map(&bad, false, &unlimited_limits()).expect_err("should fail");
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
    let err = apply_sparse_reconstruction(&payload, &extents, 4, &sparse_unlimited())
        .expect_err("should fail");
    assert!(
        matches!(err, SparseError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// write_sparse_map 32-bit truncation prevention tests
// ---------------------------------------------------------------------------

/// 32-bit write accepts values that fit in u32.
#[test]
fn write_sparse_map_32bit_accepts_fitting_values() {
    let extents = vec![SparseExtent {
        offset: u64::from(u32::MAX) - 1,
        length: 1,
    }];
    let bytes = write_sparse_map(&extents, false).expect("32-bit write ok");
    assert_eq!(bytes.len(), 8);
    let parsed = parse_sparse_map(&bytes, false, &unlimited_limits()).expect("parse ok");
    assert_eq!(parsed[0].offset, u64::from(u32::MAX) - 1);
    assert_eq!(parsed[0].length, 1);
}

/// 32-bit write rejects offset exceeding u32::MAX.
#[test]
fn write_sparse_map_32bit_rejects_offset_overflow() {
    let extents = vec![SparseExtent {
        offset: u64::from(u32::MAX) + 1,
        length: 1,
    }];
    let err = write_sparse_map(&extents, false).expect_err("should fail");
    assert!(
        matches!(err, SarError::Overflow(_)),
        "expected Overflow for large offset, got {err:?}"
    );
}

/// 32-bit write rejects length exceeding u32::MAX.
#[test]
fn write_sparse_map_32bit_rejects_length_overflow() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: u64::from(u32::MAX) + 1,
    }];
    let err = write_sparse_map(&extents, false).expect_err("should fail");
    assert!(
        matches!(err, SarError::Overflow(_)),
        "expected Overflow for large length, got {err:?}"
    );
}

/// 64-bit write preserves large u64 values without truncation.
#[test]
fn write_sparse_map_64bit_preserves_large_values() {
    let large_offset = 0xFFFF_FFFF_1234_5678u64;
    let large_length = 0x0000_0001_0000_0001u64;
    let extents = vec![SparseExtent {
        offset: large_offset,
        length: large_length,
    }];
    let bytes = write_sparse_map(&extents, true).expect("64-bit write ok");
    assert_eq!(bytes.len(), 16);
    let parsed = parse_sparse_map(&bytes, true, &unlimited_limits()).expect("parse ok");
    assert_eq!(
        parsed[0].offset, large_offset,
        "offset must not be truncated"
    );
    assert_eq!(
        parsed[0].length, large_length,
        "length must not be truncated"
    );
}

// ---------------------------------------------------------------------------
// Error conversion bridge tests (SparseError -> SarError)
// ---------------------------------------------------------------------------

/// SparseError::InvalidMap converts to SarError::InvalidMap.
#[test]
fn sparse_error_invalid_map_converts_to_sar_invalid_map() {
    let se = sar_sparse::SparseError::InvalidMap("test");
    let sar: SarError = se.into();
    assert!(matches!(sar, SarError::InvalidMap(_)));
}

/// SparseError::Overflow converts to SarError::Overflow.
#[test]
fn sparse_error_overflow_converts_to_sar_overflow() {
    let se = sar_sparse::SparseError::Overflow("test");
    let sar: SarError = se.into();
    assert!(matches!(sar, SarError::Overflow(_)));
}

/// SparseError::Truncated converts to SarError::Truncated.
#[test]
fn sparse_error_truncated_converts_to_sar_truncated() {
    let se = sar_sparse::SparseError::Truncated("test");
    let sar: SarError = se.into();
    assert!(matches!(sar, SarError::Truncated(_)));
}

/// SparseError::LimitExceeded converts to SarError::LimitExceeded.
#[test]
fn sparse_error_limit_converts_to_sar_limit() {
    let se = sar_sparse::SparseError::LimitExceeded("test");
    let sar: SarError = se.into();
    assert!(matches!(sar, SarError::LimitExceeded(_)));
}
