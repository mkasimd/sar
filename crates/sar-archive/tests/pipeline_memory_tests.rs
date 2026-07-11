#![allow(unused_imports)]
//! Stage 3: Pipeline memory accounting and expansion-bomb protection tests.
//!
//! Verifies that in-memory reconstruction and transformation pipelines enforce
//! configured [`ResourceLimits`] before allocating buffers, protecting against:
//!
//! - sparse expansion bombs (tiny payload + huge `Uncompressed Size`)
//! - decompression expansion bombs
//! - fragment-group span bombs
//! - fragmented sparse expansion bombs
//! - FEC / recovery working-set overflows
//!
//! Runtime memory budget is not implemented by design; configured
//! `ResourceLimits` are the deterministic protection mechanism.

use std::io::Cursor;

use sar_archive::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, EntryInput,
};
use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD, CompressionOptions};
use sar_core::{
    GlobalFlags, ResourceLimits, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
    sparse::{SparseExtent, write_sparse_map},
};
use sar_fragmentation::{
    FragmentDescriptor, FragmentEntry, FragmentError, FragmentLimits, reconstruct_fragments,
};
use sar_sparse::{SparseError, SparseLimits, apply_sparse_reconstruction, validate_sparse_extents};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unlimited() -> ResourceLimits {
    ResourceLimits::unlimited()
}

fn s(limits: &ResourceLimits) -> SparseLimits {
    limits.sparse_limits()
}

fn f(limits: &ResourceLimits) -> FragmentLimits {
    limits.fragment_limits()
}

/// Build a minimal no-index archive header.
fn header_bytes(flags: GlobalFlags) -> Vec<u8> {
    write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header")
}

// ---------------------------------------------------------------------------
// §1  REQUIRED: Sparse expansion-bomb reject test
//
// Attack shape:
//   max_decoded_entry_size = 1024
//   Uncompressed Size      = 1025
//   Sparse Map             : offset=1024, length=1
//   Stored Payload         : one byte
//
// Expected:
//   - LimitExceeded (SAR_ERR_LIMIT_EXCEEDED)
//   - rejected BEFORE allocating a 1025-byte buffer
//   - NOT SAR_ERR_INVALID_MAP (the map is structurally valid)
//   - no panic, no hang, no OOM
// ---------------------------------------------------------------------------

#[test]
fn sparse_expansion_bomb_reject() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 1024,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 1024,
        length: 1,
    }];
    let payload = &[0x42u8]; // one byte

    let err = apply_sparse_reconstruction(payload, &extents, 1025, &s(&limits))
        .expect_err("must reject expansion bomb");

    assert!(
        matches!(err, SparseError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
    // Confirm it is NOT InvalidMap; the sparse map is structurally valid
    assert!(
        !matches!(err, SparseError::InvalidMap(_)),
        "must not be InvalidMap — the map is structurally valid but over the limit"
    );
}

// ---------------------------------------------------------------------------
// §2  REQUIRED: Sparse bounded success counterpart
//
// Config:
//   max_decoded_entry_size = 1024
//   Uncompressed Size      = 1024
//   Sparse Map             : offset=1023, length=1
//   Stored Payload         : one byte (0x42)
//
// Expected:
//   - reconstruction succeeds
//   - final output length == Uncompressed Size (1024)
//   - bytes [0..1023] == 0x00
//   - byte [1023] == 0x42
// ---------------------------------------------------------------------------

#[test]
fn sparse_expansion_bomb_bounded_success() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 1024,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 1023,
        length: 1,
    }];
    let payload = &[0x42u8];

    let output = apply_sparse_reconstruction(payload, &extents, 1024, &s(&limits))
        .expect("reconstruction must succeed when within limit");

    assert_eq!(
        output.len(),
        1024,
        "output length must equal Uncompressed Size"
    );
    assert_eq!(
        &output[..1023],
        &[0u8; 1023],
        "all bytes before the final extent must be 0x00"
    );
    assert_eq!(
        output[1023], 0x42,
        "final byte must equal the stored payload byte"
    );
}

// ---------------------------------------------------------------------------
// §3  General memory-bound tests
// ---------------------------------------------------------------------------

/// Allocation above `max_decoded_entry_size` fails before allocation.
#[test]
fn max_decoded_entry_size_rejects_oversized_logical_output() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 512,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 0,
        length: 8,
    }];
    let err =
        apply_sparse_reconstruction(&[0u8; 8], &extents, 1024, &s(&limits)).expect_err("must fail");
    assert!(matches!(err, SparseError::LimitExceeded(_)), "{err:?}");
}

/// Allocation above `max_in_memory_buffer` fails before allocation.
#[test]
fn max_in_memory_buffer_rejects_oversized_buffer() {
    let limits = ResourceLimits {
        max_in_memory_buffer: 512,
        max_decoded_entry_size: u64::MAX,
        max_total_pipeline_memory: u64::MAX,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 0,
        length: 8,
    }];
    // logical_size=1024 > max_in_memory_buffer=512
    let err =
        apply_sparse_reconstruction(&[0u8; 8], &extents, 1024, &s(&limits)).expect_err("must fail");
    assert!(matches!(err, SparseError::LimitExceeded(_)), "{err:?}");
}

/// Cumulative pipeline memory above `max_total_pipeline_memory` fails before allocation.
#[test]
fn max_total_pipeline_memory_rejects_oversized_cumulative() {
    let limits = ResourceLimits {
        max_total_pipeline_memory: 512,
        max_decoded_entry_size: u64::MAX,
        max_in_memory_buffer: u64::MAX,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 0,
        length: 8,
    }];
    // logical_size=1024 > max_total_pipeline_memory=512
    let err =
        apply_sparse_reconstruction(&[0u8; 8], &extents, 1024, &s(&limits)).expect_err("must fail");
    assert!(matches!(err, SparseError::LimitExceeded(_)), "{err:?}");
}

/// Checked arithmetic catches overflow in offset + length.
/// (This is a belt-and-suspenders guard on top of the arithmetic-overflow tests
/// in resource_limit_tests.rs.)
#[test]
fn offset_plus_length_overflow_is_caught() {
    let extents = vec![SparseExtent {
        offset: u64::MAX,
        length: 1,
    }];
    let err = validate_sparse_extents(&extents, u64::MAX, &s(&unlimited())).expect_err("must fail");
    assert!(matches!(err, SparseError::Overflow(_)), "{err:?}");
}

/// Error is deterministic — the same input produces the same error variant, no panic.
#[test]
fn limit_exceeded_error_is_deterministic() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 100,
        ..unlimited()
    };
    for _ in 0..10 {
        let extents = vec![SparseExtent {
            offset: 0,
            length: 1,
        }];
        let err =
            apply_sparse_reconstruction(&[1u8], &extents, 200, &s(&limits)).expect_err("must fail");
        assert!(matches!(err, SparseError::LimitExceeded(_)));
    }
}

// ---------------------------------------------------------------------------
// §4  Sparse tests
// ---------------------------------------------------------------------------

/// Sparse trailing hole within limit succeeds.
#[test]
fn sparse_trailing_hole_within_limit_succeeds() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 1024,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 0,
        length: 5,
    }];
    let payload = b"HELLO";
    // logical_size=10 has a trailing hole [5..10)
    let out = apply_sparse_reconstruction(payload, &extents, 10, &s(&limits))
        .expect("within limit must succeed");
    assert_eq!(out.len(), 10);
    assert_eq!(&out[0..5], b"HELLO");
    assert_eq!(&out[5..10], &[0u8; 5], "trailing hole must be zero");
}

/// Sparse trailing hole above limit fails with resource-limit error.
#[test]
fn sparse_trailing_hole_above_limit_fails() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 9,
        ..unlimited()
    };
    let extents = vec![SparseExtent {
        offset: 0,
        length: 5,
    }];
    let payload = b"HELLO";
    // logical_size=10 > max_decoded_entry_size=9
    let err =
        apply_sparse_reconstruction(payload, &extents, 10, &s(&limits)).expect_err("must fail");
    assert!(
        matches!(err, SparseError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
}

/// Huge sparse hole does not allocate a huge zero buffer — rejected before allocation.
#[test]
fn huge_sparse_hole_does_not_allocate_huge_buffer() {
    let limits = ResourceLimits {
        max_decoded_entry_size: 1024,
        ..unlimited()
    };
    // Logical size is several gigabytes — should be rejected immediately.
    let huge_logical_size: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
    let extents = vec![SparseExtent {
        offset: 0,
        length: 1,
    }];
    let err = apply_sparse_reconstruction(&[0u8], &extents, huge_logical_size, &s(&limits))
        .expect_err("must reject before allocating 4 GiB");
    assert!(
        matches!(
            err,
            SparseError::LimitExceeded(_) | SparseError::Overflow(_)
        ),
        "expected LimitExceeded or Overflow, got {err:?}"
    );
}

/// Payload length mismatch with declared extents returns map/format error, not a limit error.
#[test]
fn payload_length_mismatch_returns_map_or_format_error() {
    let extents = vec![SparseExtent {
        offset: 0,
        length: 10,
    }];
    // payload is only 5 bytes but extents claim 10
    let err = apply_sparse_reconstruction(&[0u8; 5], &extents, 10, &s(&unlimited()))
        .expect_err("must fail");
    assert!(
        matches!(err, SparseError::Truncated(_)),
        "expected Truncated, got {err:?}"
    );
}

/// Excessive sparse map byte size at parse stage fails before reconstruction.
#[test]
fn excessive_sparse_map_size_fails_at_parse_stage() {
    use sar_core::sparse::parse_sparse_map;

    let limits = ResourceLimits {
        max_sparse_map_bytes: 8,
        ..unlimited()
    };
    // 3 extents × 8 bytes = 24 bytes — exceeds limit of 8
    let large_map = vec![0u8; 24];
    let err = parse_sparse_map(&large_map, false, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// §5  Fragmentation tests
// ---------------------------------------------------------------------------

/// Fragment descriptor end overflow is caught.
#[test]
fn fragment_descriptor_end_overflow_fails() {
    use sar_fragmentation::validate_fragment_group;
    let fragments = vec![FragmentEntry {
        fragment_index: 0,
        is_last_fragment: true,
        is_loss_tolerant: false,
        descriptor: FragmentDescriptor {
            absolute_offset: u64::MAX,
            fragment_size: 1,
        },
        payload: vec![1],
    }];
    let err = validate_fragment_group(&fragments, u64::MAX, &f(&unlimited()))
        .expect_err("must fail with overflow");
    assert!(matches!(err, FragmentError::Overflow(_)), "{err:?}");
}

/// Huge fragment group span fails before allocation.
#[test]
fn huge_fragment_group_span_fails_before_allocation() {
    let limits = ResourceLimits {
        max_fragment_group_span: 1024,
        ..unlimited()
    };
    let fragments = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 1,
            },
            payload: vec![1],
        },
        FragmentEntry {
            fragment_index: 1,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 2048,
                fragment_size: 1,
            },
            payload: vec![2],
        },
    ];
    // assembled_size = 2049 > max_fragment_group_span = 1024
    let err = reconstruct_fragments(fragments, 2049, &f(&limits)).expect_err("must fail");
    assert!(matches!(err, FragmentError::LimitExceeded(_)), "{err:?}");
}

/// Loss-tolerant huge gap fails due to resource limit.
/// (Existing test in resource_limit_tests.rs; verified here at the unit level.)
#[test]
fn loss_tolerant_huge_gap_fails_resource_limit() {
    let limits = ResourceLimits {
        max_loss_tolerant_gap: 8,
        ..unlimited()
    };
    let fragments = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 1,
            },
            payload: vec![0xAA],
        },
        FragmentEntry {
            fragment_index: 2,
            is_last_fragment: true,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 100,
                fragment_size: 1,
            },
            payload: vec![0xBB],
        },
    ];
    let err = reconstruct_fragments(fragments, 101, &f(&limits)).expect_err("must fail");
    assert!(matches!(err, FragmentError::LimitExceeded(_)), "{err:?}");
}

/// Fragmented sparse expansion bomb fails safely via `read_all_logical_files`.
///
/// Attack shape:
///   max_decoded_entry_size = 512
///   Fragment 0: Uncompressed Size = 1024 (huge logical sparse size)
///   Sparse Map: offset=1023, length=1
///   Payload: one byte
///
/// Expected: LimitExceeded before any 1024-byte allocation.
#[test]
fn fragmented_sparse_expansion_bomb_fails_safely() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let extents = [SparseExtent {
        offset: 1023,
        length: 1,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    let mut archive = header_bytes(flags);

    // Fragment 0: declares logical_size=1024 via uncompressed_size, carries sparse map
    let mut lfh0 = LocalFileHeader::minimal_store(b"bomb.bin".to_vec(), 1);
    lfh0.uncompressed_size = 1024; // huge logical size
    lfh0.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6)); // IS_FRAGMENT | LAST_FRAGMENT
    lfh0.fragment_id = Some(77);
    lfh0.fragment_index = Some(0);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 1,
    });
    lfh0.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh0).expect("lfh0"));
    archive.extend_from_slice(&[0x42u8]);

    let mut reader = sar_archive::ArchiveReader::with_options(
        Cursor::new(archive),
        sar_archive::ArchiveReaderOptions {
            limits: ResourceLimits {
                max_decoded_entry_size: 512,
                ..unlimited()
            },
            delta_base: None,
        },
    )
    .expect("reader");

    let err = reader
        .read_all_logical_files(false)
        .expect_err("must reject fragmented sparse expansion bomb");
    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
}

/// Excessive fragment count fails deterministically.
#[test]
fn excessive_fragment_count_fails_deterministically() {
    let limits = ResourceLimits {
        max_fragment_count: 2,
        ..unlimited()
    };
    let fragments: Vec<FragmentEntry> = (0u32..3)
        .map(|i| FragmentEntry {
            fragment_index: i,
            is_last_fragment: i == 2,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: u64::from(i),
                fragment_size: 1,
            },
            payload: vec![i as u8],
        })
        .collect();
    let err = reconstruct_fragments(fragments, 3, &f(&limits)).expect_err("must fail");
    assert!(matches!(err, FragmentError::LimitExceeded(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// §6  Compression tests
// ---------------------------------------------------------------------------

/// Decompression output above configured `max_decoded_entry_size` fails
/// before completing the decompression.
#[test]
fn decompression_output_above_limit_fails() {
    use sar_compression::{DecompressionOptions, decode_stream};

    // Create compressible payload: 4096 bytes of repeated data
    let original: Vec<u8> = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(128);
    assert_eq!(original.len(), 4096);

    let mut compressed = Vec::new();
    sar_compression::encode_stream(
        COMP_ALGO_DEFLATE,
        &mut original.as_slice(),
        &mut compressed,
        CompressionOptions { level: Some(6) },
    )
    .expect("encode");

    // Limit output to 1024 bytes; original decompresses to 4096
    let opts = DecompressionOptions {
        max_output_size: 1024,
    };
    let mut out = Vec::new();
    let err = decode_stream(
        COMP_ALGO_DEFLATE,
        &mut compressed.as_slice(),
        &mut out,
        opts,
    )
    .expect_err("must fail with limit exceeded");
    assert!(
        matches!(err, sar_compression::CompressionError::LimitExceeded),
        "expected CompressionError::LimitExceeded, got {err:?}"
    );
}

/// Archive reader respects `max_decoded_entry_size` as a decompression bound.
#[test]
fn archive_reader_decompression_respects_entry_limit() {
    let mut out = Vec::new();
    {
        let mut writer = sar_archive::ArchiveWriter::new_with_compression(
            &mut out,
            sar_archive::ArchiveWriterOptions {
                no_index: true,
                encryption: None,
                fec: None,
                sparse: false,
                ..Default::default()
            },
            sar_archive::CompressionSettings {
                algo_id: COMP_ALGO_DEFLATE,
                level: Some(6),
            },
        )
        .expect("writer");
        // 8 KiB of compressible data
        writer
            .add_entry(sar_archive::EntryInput::file(
                "big.bin",
                b"AAAA".repeat(2048),
            ))
            .expect("entry");
        writer.finish().expect("finish");
    }

    let mut reader = sar_archive::ArchiveReader::with_options(
        Cursor::new(out),
        sar_archive::ArchiveReaderOptions {
            limits: ResourceLimits {
                max_decoded_entry_size: 1024,
                ..unlimited()
            },
            delta_base: None,
        },
    )
    .expect("reader");
    reader.read_global_header().expect("header");

    let err = reader.next_entry().expect_err("must fail");
    assert!(
        matches!(
            err,
            SarError::LimitExceeded(_) | SarError::DecompressionFailed(_)
        ),
        "expected LimitExceeded or DecompressionFailed, got {err:?}"
    );
}

/// Compressed bomb: decompressor does not grow buffer past configured limit.
/// Uses zstd which can achieve very high compression ratios.
#[test]
fn compressed_bomb_returns_resource_limit_error() {
    // 16 KiB of zeros → compresses to very few bytes with zstd
    let original: Vec<u8> = vec![0u8; 16 * 1024];

    let mut compressed = Vec::new();
    sar_compression::encode_stream(
        COMP_ALGO_ZSTD,
        &mut original.as_slice(),
        &mut compressed,
        CompressionOptions { level: Some(9) },
    )
    .expect("encode");

    // Limit to 4 KiB — well below the 16 KiB decompressed size
    use sar_compression::{DecompressionOptions, decode_stream};
    let opts = DecompressionOptions {
        max_output_size: 4 * 1024,
    };
    let mut out = Vec::new();
    let err = decode_stream(COMP_ALGO_ZSTD, &mut compressed.as_slice(), &mut out, opts)
        .expect_err("must fail");
    assert!(
        matches!(err, sar_compression::CompressionError::LimitExceeded),
        "expected LimitExceeded, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §7  FEC / recovery working-set tests
// ---------------------------------------------------------------------------

/// Excessive repair working set is rejected before executing recovery.
/// (Integration test; complements the unit-level test in resource_limit_tests.rs.)
#[test]
fn repair_working_set_above_limit_fails_before_execution() {
    // Build a minimal archive with a global EC TLV
    let flags = GlobalFlags::HAS_GLOBAL_EC;
    let archive = build_archive_with_global_ec(flags);

    let plan = sar_core::plan_archive_repair(
        &archive,
        sar_core::ErasureInput {
            entries: Vec::new(),
            archive_ranges: Vec::new(),
        },
        &unlimited(),
    )
    .expect("plan");

    let limits = ResourceLimits {
        max_repair_working_set: 1,
        ..unlimited()
    };
    let err = sar_core::repair_archive(&archive, &plan, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

/// Archive repair failure does not produce a partial output.
#[test]
fn failed_repair_does_not_produce_partial_output() {
    let flags = GlobalFlags::HAS_GLOBAL_EC;
    let archive = build_archive_with_global_ec(flags);

    // Build a repair plan that specifies erasures outside the protected range
    // (this makes plan_archive_repair fail deterministically).
    let err = sar_core::plan_archive_repair(
        &archive,
        sar_core::ErasureInput {
            entries: Vec::new(),
            archive_ranges: vec![sar_core::ErasureRange {
                offset: 0,
                length: 8,
            }],
        },
        &unlimited(),
    )
    .expect_err("must fail: erasure is outside protected range");

    // Verify we got a well-typed error, not a partial archive bytes
    assert!(
        matches!(err, SarError::RecoveryUnavailable(_)),
        "expected RecoveryUnavailable for out-of-range erasure, got {err:?}"
    );
}

/// Excessive FEC value byte size fails at parse time (not at repair time).
#[test]
fn excessive_fec_value_bytes_fails_at_parse_stage() {
    use sar_core::fec::validate_recovery_tlv;

    // XOR TLV: 14 bytes is a minimal valid value; we test that limiting to 4
    // bytes causes rejection before parse proceeds.
    let limits = ResourceLimits {
        max_fec_value_bytes: 4,
        ..unlimited()
    };
    let dummy_value = vec![0u8; 14];
    let err = validate_recovery_tlv(0x14, &dummy_value, &limits).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// §8  End-to-end expansion bomb via sar_archive::ArchiveReader
// ---------------------------------------------------------------------------

/// End-to-end: `read_all_logical_files` rejects sparse expansion bomb
/// via the high-level archive reader path.
#[test]
fn read_all_logical_files_rejects_sparse_expansion_bomb() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let extents = [SparseExtent {
        offset: 1024,
        length: 1,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    let mut archive = header_bytes(flags);

    // Entry with uncompressed_size=1025 and one stored byte
    let mut lfh = LocalFileHeader::minimal_store(b"bomb.bin".to_vec(), 1);
    lfh.uncompressed_size = 1025;
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(&[0x00u8]);

    let mut reader = sar_archive::ArchiveReader::with_options(
        Cursor::new(archive),
        sar_archive::ArchiveReaderOptions {
            limits: ResourceLimits {
                max_decoded_entry_size: 1024,
                ..unlimited()
            },
            delta_base: None,
        },
    )
    .expect("reader");

    let err = reader
        .read_all_logical_files(false)
        .expect_err("must reject expansion bomb");

    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
}

/// End-to-end: `read_all_logical_files` succeeds for the bounded counterpart.
#[test]
fn read_all_logical_files_sparse_bounded_success() {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let extents = [SparseExtent {
        offset: 1023,
        length: 1,
    }];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    let mut archive = header_bytes(flags);

    let mut lfh = LocalFileHeader::minimal_store(b"ok.bin".to_vec(), 1);
    lfh.uncompressed_size = 1024;
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(&[0x42u8]);

    let mut reader = sar_archive::ArchiveReader::with_options(
        Cursor::new(archive),
        sar_archive::ArchiveReaderOptions {
            limits: ResourceLimits {
                max_decoded_entry_size: 1024,
                ..unlimited()
            },
            delta_base: None,
        },
    )
    .expect("reader");

    let files = reader
        .read_all_logical_files(false)
        .expect("bounded case must succeed");

    assert_eq!(files.len(), 1);
    let data = &files[0].data;
    assert_eq!(
        data.len(),
        1024,
        "output length must equal Uncompressed Size"
    );
    assert_eq!(&data[..1023], &[0u8; 1023], "leading zeros");
    assert_eq!(data[1023], 0x42, "final byte is the stored byte");
}

// ---------------------------------------------------------------------------
// Helpers for FEC archive construction
// ---------------------------------------------------------------------------

fn build_xor_tlv_value(protected_len: u64) -> Vec<u8> {
    let stripe_size = 1u8;
    let block_size_index = 0x04u8; // 4 KiB blocks
    let block_size = 4096u64;
    let stripe_count = protected_len.div_ceil(block_size);
    let mut value = vec![stripe_size, block_size_index];
    value.extend_from_slice(&protected_len.to_le_bytes());
    value.extend_from_slice(&(u32::try_from(stripe_count).expect("stripe count")).to_le_bytes());
    value.extend(vec![
        0u8;
        usize::try_from(stripe_count * block_size)
            .expect("parity len")
    ]);
    value
}

fn build_archive_with_global_ec(flags: GlobalFlags) -> Vec<u8> {
    use sar_core::{
        format::{CentralDictionary, write_central_dictionary, write_global_header},
        tlv::Tlv,
    };

    let ec_flags = flags | GlobalFlags::OPT_PRESENT;
    let header = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: ec_flags.bits().to_le_bytes().to_vec(),
        flags: ec_flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let cd_offset = u64::try_from(header.len()).expect("cd offset");
    let recovery_tlv = Tlv {
        type_id: 0x14,
        value: build_xor_tlv_value(cd_offset - 8),
    };
    let cd = CentralDictionary {
        version: 1,
        file_count: 0,
        partition_info: None,
        global_crc32: None,
        metadata: vec![recovery_tlv],
        offsets: Vec::new(),
    };
    let mut archive = header;
    archive.extend_from_slice(&write_central_dictionary(&cd, ec_flags).expect("cd"));
    archive.extend_from_slice(&u64::to_le_bytes(cd_offset));
    archive
}
