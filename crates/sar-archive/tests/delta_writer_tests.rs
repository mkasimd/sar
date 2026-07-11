//! Writer/reader round-trip tests for VCDIFF and SAR BSDIFF v1 delta entries.
//!
//! Tests verify:
//! * Writer emits a VCDIFF delta entry with `HAS_DELTA` + `Patch Algo ID = 0x01`.
//! * Reader applies VCDIFF using explicit `ArchiveReaderOptions::delta_base`
//!   and reconstructs the exact logical target bytes.
//! * Writer emits a SAR BSDIFF v1 delta entry with `Patch Algo ID = 0x02`.
//! * Reader applies BSDIFF and reconstructs the exact logical target bytes.
//! * Missing base bytes for VCDIFF/BSDIFF return `SAR_ERR_BASE_MISSING`.
//! * All-zero `Delta Base Hash` for VCDIFF/BSDIFF returns `SAR_ERR_BASE_MISSING`.
//! * No-delta entries emitted alongside delta entries use STORE_PATCH defaults.

use std::io::Cursor;

use sar_archive::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, DeltaWriteOptions,
    EntryInput,
};
use sar_core::SarError;
use sar_delta::{PatchAlgoId, PATCH_ALGO_BSDIFF, PATCH_ALGO_STORE_PATCH, PATCH_ALGO_VCDIFF};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const NON_ZERO_HASH: [u8; 32] = {
    let mut h = [0u8; 32];
    h[0] = 0xBD;
    h[31] = 0xAA;
    h
};

fn make_target(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xFF) as u8).collect()
}

fn make_base(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i + 3) & 0xFF) as u8).collect()
}

/// Write a single VCDIFF delta entry and return the raw archive bytes.
fn write_vcdiff_archive(base: Vec<u8>, target: Vec<u8>) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            with_delta: true,
            ..Default::default()
        },
    )
    .expect("create writer");

    let mut entry = EntryInput::file("vcdiff_target.bin", target);
    entry.delta = Some(DeltaWriteOptions {
        algorithm: PatchAlgoId::Vcdiff,
        base,
        delta_base_hash: NON_ZERO_HASH,
    });
    writer.add_entry(entry).expect("add entry");
    writer.finish().expect("finish");
    buf
}

/// Write a single BSDIFF delta entry and return the raw archive bytes.
fn write_bsdiff_archive(base: Vec<u8>, target: Vec<u8>) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            with_delta: true,
            ..Default::default()
        },
    )
    .expect("create writer");

    let mut entry = EntryInput::file("bsdiff_target.bin", target);
    entry.delta = Some(DeltaWriteOptions {
        algorithm: PatchAlgoId::Bsdiff,
        base,
        delta_base_hash: NON_ZERO_HASH,
    });
    writer.add_entry(entry).expect("add entry");
    writer.finish().expect("finish");
    buf
}

/// Read the first entry payload from an archive with an optional delta base.
fn read_first_entry(archive: &[u8], delta_base: Option<Vec<u8>>) -> Result<Vec<u8>, SarError> {
    let cursor = Cursor::new(archive);
    let opts = ArchiveReaderOptions {
        delta_base,
        ..Default::default()
    };
    let mut reader = ArchiveReader::with_options(cursor, opts)?;
    reader.read_global_header()?;
    let entry = reader.next_entry()?.expect("entry expected");
    Ok(entry.payload.clone())
}

// ---------------------------------------------------------------------------
// VCDIFF write + read round-trips
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_writer_reader_round_trip_small() {
    let base = make_base(32);
    let target = make_target(64);

    let archive = write_vcdiff_archive(base.clone(), target.clone());
    let reconstructed = read_first_entry(&archive, Some(base)).expect("read");

    assert_eq!(reconstructed, target, "reconstructed bytes must equal target");
}

#[test]
fn vcdiff_writer_reader_round_trip_empty_base() {
    let base: Vec<u8> = vec![];
    let target: Vec<u8> = b"VCDIFF target with empty base".to_vec();

    let archive = write_vcdiff_archive(base.clone(), target.clone());
    let reconstructed = read_first_entry(&archive, Some(base)).expect("read");

    assert_eq!(reconstructed, target);
}

#[test]
fn vcdiff_writer_emits_vcdiff_algo_id() {
    use sar_core::format::{parse_global_header, parse_lfh};
    use sar_core::GlobalFlags;

    let base = make_base(16);
    let target = make_target(32);
    let archive = write_vcdiff_archive(base, target);

    // Parse the global header manually.
    let limits = sar_core::ResourceLimits::default();
    let (_gh, after_gh) = parse_global_header(&archive, &limits).expect("global header");
    let gh_flags = GlobalFlags::from_bits_truncate(
        u32::from_le_bytes(archive[4..8].try_into().unwrap()) as u32,
    );

    assert!(
        gh_flags.contains(GlobalFlags::HAS_DELTA),
        "global header must have HAS_DELTA set"
    );

    let flags = gh_flags;
    let (lfh, _) = parse_lfh(&archive[after_gh..], &flags, &limits).expect("parse LFH");
    assert_eq!(
        lfh.patch_algo_id,
        Some(PATCH_ALGO_VCDIFF),
        "LFH patch_algo_id must be VCDIFF (0x01)"
    );
}

#[test]
fn vcdiff_missing_base_returns_base_missing() {
    let base = make_base(32);
    let target = make_target(64);
    let archive = write_vcdiff_archive(base, target);

    let result = read_first_entry(&archive, None);
    assert!(
        matches!(result, Err(SarError::BaseMissing(_))),
        "expected BaseMissing for missing delta_base, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// BSDIFF write + read round-trips
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_writer_reader_round_trip_small() {
    let base = make_base(32);
    let target = make_target(64);

    let archive = write_bsdiff_archive(base.clone(), target.clone());
    let reconstructed = read_first_entry(&archive, Some(base)).expect("read");

    assert_eq!(reconstructed, target, "reconstructed bytes must equal target");
}

#[test]
fn bsdiff_writer_reader_round_trip_empty_base() {
    let base: Vec<u8> = vec![];
    let target: Vec<u8> = b"BSDIFF target with empty base".to_vec();

    let archive = write_bsdiff_archive(base.clone(), target.clone());
    let reconstructed = read_first_entry(&archive, Some(base)).expect("read");

    assert_eq!(reconstructed, target);
}

#[test]
fn bsdiff_writer_emits_bsdiff_algo_id() {
    use sar_core::format::{parse_global_header, parse_lfh};
    use sar_core::GlobalFlags;

    let base = make_base(16);
    let target = make_target(32);
    let archive = write_bsdiff_archive(base.clone(), target);

    let limits = sar_core::ResourceLimits::default();
    let (_gh, after_gh) = parse_global_header(&archive, &limits).expect("global header");
    let gh_flags = GlobalFlags::from_bits_truncate(
        u32::from_le_bytes(archive[4..8].try_into().unwrap()) as u32,
    );

    assert!(
        gh_flags.contains(GlobalFlags::HAS_DELTA),
        "global header must have HAS_DELTA set"
    );

    let (lfh, _) =
        parse_lfh(&archive[after_gh..], &gh_flags, &limits).expect("parse LFH");
    assert_eq!(
        lfh.patch_algo_id,
        Some(PATCH_ALGO_BSDIFF),
        "LFH patch_algo_id must be BSDIFF (0x02)"
    );
}

#[test]
fn bsdiff_missing_base_returns_base_missing() {
    let base = make_base(32);
    let target = make_target(64);
    let archive = write_bsdiff_archive(base, target);

    let result = read_first_entry(&archive, None);
    assert!(
        matches!(result, Err(SarError::BaseMissing(_))),
        "expected BaseMissing for missing delta_base, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// Zero-hash rejection
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_zero_delta_base_hash_rejected_by_writer() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            with_delta: true,
            ..Default::default()
        },
    )
    .expect("create writer");

    let mut entry = EntryInput::file("file.bin", b"target".to_vec());
    entry.delta = Some(DeltaWriteOptions {
        algorithm: PatchAlgoId::Vcdiff,
        base: b"base".to_vec(),
        delta_base_hash: [0u8; 32], // all-zero hash
    });
    let result = writer.add_entry(entry);
    assert!(
        matches!(result, Err(SarError::BaseMissing(_))),
        "expected BaseMissing for zero delta_base_hash on VCDIFF, got {:?}",
        result
    );
}

#[test]
fn bsdiff_zero_delta_base_hash_rejected_by_writer() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            with_delta: true,
            ..Default::default()
        },
    )
    .expect("create writer");

    let mut entry = EntryInput::file("file.bin", b"target".to_vec());
    entry.delta = Some(DeltaWriteOptions {
        algorithm: PatchAlgoId::Bsdiff,
        base: b"base".to_vec(),
        delta_base_hash: [0u8; 32], // all-zero hash
    });
    let result = writer.add_entry(entry);
    assert!(
        matches!(result, Err(SarError::BaseMissing(_))),
        "expected BaseMissing for zero delta_base_hash on BSDIFF, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// with_delta=false rejects delta entries
// ---------------------------------------------------------------------------

#[test]
fn delta_entry_without_has_delta_flag_fails() {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            with_delta: false, // HAS_DELTA not set
            ..Default::default()
        },
    )
    .expect("create writer");

    let mut entry = EntryInput::file("file.bin", b"target".to_vec());
    entry.delta = Some(DeltaWriteOptions {
        algorithm: PatchAlgoId::Vcdiff,
        base: b"base".to_vec(),
        delta_base_hash: NON_ZERO_HASH,
    });
    let result = writer.add_entry(entry);
    assert!(
        matches!(result, Err(SarError::FlagConflict(_))),
        "expected FlagConflict when with_delta=false, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// HAS_DELTA active, no per-entry delta → STORE_PATCH defaults
// ---------------------------------------------------------------------------

#[test]
fn has_delta_active_entry_without_delta_uses_store_patch() {
    let target = b"plain target data".to_vec();
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            with_delta: true,
            ..Default::default()
        },
    )
    .expect("create writer");

    // No delta options on this entry → STORE_PATCH should be emitted.
    writer
        .add_entry(EntryInput::file("plain.bin", target.clone()))
        .expect("add entry");
    writer.finish().expect("finish");

    // Reader should reconstruct with STORE_PATCH (no base required).
    let reconstructed = read_first_entry(&buf, None).expect("read");
    assert_eq!(reconstructed, target);

    // Verify algo ID is STORE_PATCH.
    use sar_core::format::{parse_global_header, parse_lfh};
    let limits = sar_core::ResourceLimits::default();
    let (_gh, after_gh) = parse_global_header(&buf, &limits).expect("global header");
    let flags = sar_core::GlobalFlags::from_bits_truncate(
        u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u32,
    );
    let (lfh, _) = parse_lfh(&buf[after_gh..], &flags, &limits).expect("LFH");
    assert_eq!(lfh.patch_algo_id, Some(PATCH_ALGO_STORE_PATCH));
    assert_eq!(lfh.delta_base_hash, Some([0u8; 32]));
}
