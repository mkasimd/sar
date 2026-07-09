//! Integration tests for `BSDIFF` (`0x02`) through the full archive reader pipeline.

use std::io::Cursor;

use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_ZSTD, CompressionOptions, encode_stream};
use sar_core::{
    ArchiveReader, ArchiveReaderOptions, GlobalFlags, ResourceLimits, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
};

fn encode_bsdiff_int(v: i64) -> [u8; 8] {
    let magnitude = v.unsigned_abs();
    let sign_bit: u8 = if v < 0 { 0x80 } else { 0x00 };
    let mut bytes = magnitude.to_le_bytes();
    bytes[7] = (bytes[7] & 0x7F) | sign_bit;
    bytes
}

fn triples_to_control(triples: &[(i64, i64, i64)]) -> Vec<u8> {
    let mut ctrl = Vec::new();
    for &(d, e, s) in triples {
        ctrl.extend_from_slice(&encode_bsdiff_int(d));
        ctrl.extend_from_slice(&encode_bsdiff_int(e));
        ctrl.extend_from_slice(&encode_bsdiff_int(s));
    }
    ctrl
}

fn build_patch(triples: &[(i64, i64, i64)], diff: &[u8], extra: &[u8], new_size: i64) -> Vec<u8> {
    let ctrl = triples_to_control(triples);
    let mut patch = Vec::new();
    patch.extend_from_slice(b"SARBSD01");
    patch.extend_from_slice(&encode_bsdiff_int(i64::try_from(ctrl.len()).expect("ctrl")));
    patch.extend_from_slice(&encode_bsdiff_int(i64::try_from(diff.len()).expect("diff")));
    patch.extend_from_slice(&encode_bsdiff_int(new_size));
    patch.extend_from_slice(&ctrl);
    patch.extend_from_slice(diff);
    patch.extend_from_slice(extra);
    patch
}

const NON_ZERO_HASH: [u8; 32] = {
    let mut h = [0u8; 32];
    h[0] = 0xBD;
    h[31] = 0xAA;
    h
};

fn build_bsdiff_archive(
    patch_payload: &[u8],
    declared_uncompressed_size: u64,
    delta_base_hash: [u8; 32],
    compression: Option<u8>,
) -> Vec<u8> {
    let mut flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;

    let payload = if let Some(comp_algo) = compression {
        flags |= GlobalFlags::COMPRESSED;
        let mut compressed = Vec::new();
        encode_stream(
            comp_algo,
            &mut Cursor::new(patch_payload),
            &mut compressed,
            CompressionOptions { level: Some(6) },
        )
        .expect("compress patch");
        compressed
    } else {
        patch_payload.to_vec()
    };

    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("write global header");

    let mut lfh = LocalFileHeader::minimal_store(b"file.bin".to_vec(), declared_uncompressed_size);
    lfh.patch_algo_id = Some(0x02);
    lfh.delta_base_hash = Some(delta_base_hash);
    lfh.payload_size = u64::try_from(payload.len()).expect("payload len");
    if let Some(comp_algo) = compression {
        lfh.entry_mode = EntryMode::from_bits(EntryMode::COMPRESSED);
        lfh.comp_algo_id = Some(comp_algo);
    }

    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(&payload);
    archive
}

fn read_entry_with_opts(
    archive: Vec<u8>,
    opts: ArchiveReaderOptions,
) -> Result<sar_core::EntryReader, SarError> {
    let mut reader = ArchiveReader::with_options(Cursor::new(archive), opts)?;
    reader.read_global_header()?;
    reader.next_entry()?.ok_or(SarError::NotFound("no entry"))
}

fn opts_with_base(base: Vec<u8>) -> ArchiveReaderOptions {
    ArchiveReaderOptions {
        limits: ResourceLimits::unlimited(),
        delta_base: Some(base),
    }
}

fn opts_no_base() -> ArchiveReaderOptions {
    ArchiveReaderOptions {
        limits: ResourceLimits::unlimited(),
        delta_base: None,
    }
}

#[test]
fn bsdiff_store_pipeline_reconstructs_target() {
    let base = b"hello";
    let target = b"Hello world";
    let diff: Vec<u8> = base
        .iter()
        .zip(target.iter())
        .map(|(b, t)| t.wrapping_sub(*b))
        .collect();
    let patch = build_patch(&[(5, 6, 0)], &diff, &target[5..], target.len() as i64);
    let archive = build_bsdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH, None);
    let entry = read_entry_with_opts(archive, opts_with_base(base.to_vec())).expect("decode");
    assert_eq!(entry.payload, target);
}

#[test]
fn bsdiff_deflate_pipeline_reconstructs_target() {
    let base = b"base-bytes-for-deflate";
    let target = b"SAR BSDIFF + DEFLATE".repeat(8);
    let diff: Vec<u8> = (0..target.len())
        .map(|i| {
            let base_byte = if i < base.len() { base[i] } else { 0 };
            target[i].wrapping_sub(base_byte)
        })
        .collect();
    let patch = build_patch(
        &[(target.len() as i64, 0, 0)],
        &diff,
        b"",
        target.len() as i64,
    );
    let archive = build_bsdiff_archive(
        &patch,
        target.len() as u64,
        NON_ZERO_HASH,
        Some(COMP_ALGO_DEFLATE),
    );
    let entry = read_entry_with_opts(archive, opts_with_base(base.to_vec())).expect("decode");
    assert_eq!(entry.payload, target);
}

#[test]
fn bsdiff_zstd_pipeline_reconstructs_target() {
    let base = b"base-bytes-for-zstd";
    let target = b"SAR BSDIFF + ZSTD".repeat(8);
    let diff: Vec<u8> = (0..target.len())
        .map(|i| {
            let base_byte = if i < base.len() { base[i] } else { 0 };
            target[i].wrapping_sub(base_byte)
        })
        .collect();
    let patch = build_patch(
        &[(target.len() as i64, 0, 0)],
        &diff,
        b"",
        target.len() as i64,
    );
    let archive = build_bsdiff_archive(
        &patch,
        target.len() as u64,
        NON_ZERO_HASH,
        Some(COMP_ALGO_ZSTD),
    );
    let entry = read_entry_with_opts(archive, opts_with_base(base.to_vec())).expect("decode");
    assert_eq!(entry.payload, target);
}

#[test]
fn bsdiff_all_zero_delta_base_hash_returns_base_missing() {
    let patch = build_patch(&[(1, 0, 0)], &[0], b"", 1);
    let archive = build_bsdiff_archive(&patch, 1, [0u8; 32], None);
    let err = read_entry_with_opts(archive, opts_no_base()).expect_err("must fail");
    assert!(matches!(err, SarError::BaseMissing(_)));
}

#[test]
fn bsdiff_missing_base_returns_base_missing() {
    let patch = build_patch(&[(1, 0, 0)], &[0], b"", 1);
    let archive = build_bsdiff_archive(&patch, 1, NON_ZERO_HASH, None);
    let err = read_entry_with_opts(archive, opts_no_base()).expect_err("must fail");
    assert!(matches!(err, SarError::BaseMissing(_)));
}

#[test]
fn bsdiff40_magic_in_payload_is_rejected() {
    let mut patch = build_patch(&[(0, 0, 0)], b"", b"", 0);
    patch[0..8].copy_from_slice(b"BSDIFF40");
    let archive = build_bsdiff_archive(&patch, 0, NON_ZERO_HASH, None);
    let err = read_entry_with_opts(archive, opts_with_base(Vec::new())).expect_err("must fail");
    assert!(matches!(err, SarError::PatchFailed(_)));
}

#[test]
fn bsdiff_target_above_resource_limit_returns_limit_exceeded() {
    let base = b"base content";
    let target = b"target content";
    let diff: Vec<u8> = (0..target.len())
        .map(|i| target[i].wrapping_sub(base.get(i).copied().unwrap_or(0)))
        .collect();
    let patch = build_patch(
        &[(target.len() as i64, 0, 0)],
        &diff,
        b"",
        target.len() as i64,
    );
    let archive = build_bsdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH, None);
    let opts = ArchiveReaderOptions {
        limits: ResourceLimits {
            max_decoded_entry_size: (target.len() as u64) - 1,
            ..ResourceLimits::unlimited()
        },
        delta_base: Some(base.to_vec()),
    };
    let err = read_entry_with_opts(archive, opts).expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

#[test]
fn bsdiff_loss_tolerant_does_not_suppress_patch_failed() {
    let corrupt_patch = b"NOT_SARBSD01_GARBAGE_DATA_XXXXX";
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA | GlobalFlags::FILE_FRAGMENTATION;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(
        b"lt.bin".to_vec(),
        u64::try_from(corrupt_patch.len()).expect("len"),
    );
    lfh.entry_mode = EntryMode::from_bits(
        EntryMode::FRAGMENT | EntryMode::LAST_FRAGMENT | EntryMode::LOSS_TOLERANT,
    );
    lfh.fragment_id = Some(200);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: u32::try_from(corrupt_patch.len()).expect("len"),
    });
    lfh.patch_algo_id = Some(0x02);
    lfh.delta_base_hash = Some(NON_ZERO_HASH);
    lfh.payload_size = u64::try_from(corrupt_patch.len()).expect("len");

    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(corrupt_patch);

    let opts = ArchiveReaderOptions {
        limits: ResourceLimits::unlimited(),
        delta_base: Some(b"base".to_vec()),
    };
    let mut reader = ArchiveReader::with_options(Cursor::new(archive), opts).expect("reader");
    reader.read_global_header().expect("global header");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("must not suppress");
    assert!(matches!(err, SarError::PatchFailed(_)));
}
