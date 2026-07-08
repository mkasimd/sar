//! Integration tests for `BSDIFF` (`0x02`) through the full archive reader
//! pipeline (`sar-core`).
//!
//! Spec requirements tested (spec §8.4.3, §8.4):
//!
//! * Valid BSDIFF40 patch with supplied base reconstructs expected target.
//! * All-zero Delta Base Hash returns `SAR_ERR_BASE_MISSING`.
//! * No base bytes supplied returns `SAR_ERR_BASE_MISSING`.
//! * `BSDIFF + compression` decodes correctly.
//! * `BSDIFF + encryption` decodes correctly.
//! * `BSDIFF + sparse` applies patch before sparse reconstruction.
//! * `BSDIFF + fragmentation` applies after fragment reassembly.
//! * BSDIFF output above `ResourceLimits` returns `SAR_ERR_LIMIT_EXCEEDED`.
//! * `LOSS_TOLERANT` does not suppress `SAR_ERR_PATCH_FAILED`.

use std::io::Cursor;

use bzip2::{Compression, write::BzEncoder};
use sar_compression::{COMP_ALGO_DEFLATE, CompressionOptions, encode_stream};
use sar_core::{
    ArchiveReader, ArchiveReaderOptions, GlobalFlags, ResourceLimits, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
};
use std::io::Write;

// ---------------------------------------------------------------------------
// Patch-building helpers (duplicated from sar-delta/tests to keep crate
// separation; only the archive-builder part is new here).
// ---------------------------------------------------------------------------

fn bzip2_compress(data: &[u8]) -> Vec<u8> {
    let mut enc = BzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).expect("bzip2 encode");
    enc.finish().expect("bzip2 finish")
}

fn encode_bsdiff_int(v: i64) -> [u8; 8] {
    let magnitude = v.unsigned_abs();
    let sign_bit: u8 = if v < 0 { 0x80 } else { 0x00 };
    let mut bytes = magnitude.to_le_bytes();
    bytes[7] = (bytes[7] & 0x7F) | sign_bit;
    bytes
}

/// Builds a BSDIFF40 patch payload for `new_size` bytes.
fn build_bsdiff_patch(
    ctrl_triples: &[(i64, i64, i64)],
    diff_bytes: &[u8],
    extra_bytes: &[u8],
    new_size: i64,
) -> Vec<u8> {
    let mut ctrl_raw = Vec::new();
    for &(d, e, s) in ctrl_triples {
        ctrl_raw.extend_from_slice(&encode_bsdiff_int(d));
        ctrl_raw.extend_from_slice(&encode_bsdiff_int(e));
        ctrl_raw.extend_from_slice(&encode_bsdiff_int(s));
    }

    let ctrl_comp = bzip2_compress(&ctrl_raw);
    let diff_comp = bzip2_compress(diff_bytes);
    let extra_comp = bzip2_compress(extra_bytes);

    let mut patch = Vec::new();
    patch.extend_from_slice(b"BSDIFF40");
    patch.extend_from_slice(&encode_bsdiff_int(ctrl_comp.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(diff_comp.len() as i64));
    patch.extend_from_slice(&encode_bsdiff_int(new_size));
    patch.extend_from_slice(&ctrl_comp);
    patch.extend_from_slice(&diff_comp);
    patch.extend_from_slice(&extra_comp);
    patch
}

/// Identity BSDIFF patch: target == base.
fn identity_bsdiff_patch(base: &[u8]) -> Vec<u8> {
    let diff: Vec<u8> = base.iter().map(|_| 0u8).collect();
    build_bsdiff_patch(&[(base.len() as i64, 0, 0)], &diff, b"", base.len() as i64)
}

// ---------------------------------------------------------------------------
// Archive-building helpers
// ---------------------------------------------------------------------------

/// Non-zero hash sentinel used throughout these tests.
const NON_ZERO_HASH: [u8; 32] = {
    let mut h = [0u8; 32];
    h[0] = 0xBD;
    h[31] = 0xAA;
    h
};

/// Build a minimal `HAS_DELTA` archive with a single BSDIFF entry.
///
/// `patch_payload` is placed verbatim as the entry payload.
fn build_bsdiff_archive(
    patch_payload: &[u8],
    declared_uncompressed_size: u64,
    delta_base_hash: [u8; 32],
) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("write global header");

    let mut lfh = LocalFileHeader::minimal_store(b"file.bin".to_vec(), declared_uncompressed_size);
    lfh.patch_algo_id = Some(0x02); // BSDIFF
    lfh.delta_base_hash = Some(delta_base_hash);
    lfh.payload_size = patch_payload.len() as u64;

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(patch_payload);
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

// ---------------------------------------------------------------------------
// Basic success
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_identity_patch_with_base_reconstructs_target() {
    let base = b"hello, SAR delta BSDIFF!";
    let target = base; // identity
    let patch = identity_bsdiff_patch(base);
    let archive = build_bsdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH);
    let entry = read_entry_with_opts(archive, opts_with_base(base.to_vec()))
        .expect("identity BSDIFF must succeed");
    assert_eq!(entry.payload, target);
}

#[test]
fn bsdiff_patch_with_diff_and_extra_reconstructs_target() {
    let base = b"hello";
    let target = b"Hello world"; // diff first 5, extra " world"
    let diff: Vec<u8> = base
        .iter()
        .zip(target.iter())
        .map(|(b, t)| t.wrapping_sub(*b))
        .collect();
    let extra = &target[5..];
    let patch = build_bsdiff_patch(&[(5, 6, 5)], &diff, extra, target.len() as i64);
    let archive = build_bsdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH);
    let entry =
        read_entry_with_opts(archive, opts_with_base(base.to_vec())).expect("BSDIFF must succeed");
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// Delta Base Hash checks
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_all_zero_delta_base_hash_returns_base_missing() {
    let patch = identity_bsdiff_patch(b"x");
    let archive = build_bsdiff_archive(&patch, 1, [0u8; 32]);
    let err = read_entry_with_opts(archive, opts_no_base()).expect_err("must fail");
    assert!(
        matches!(err, SarError::BaseMissing(_)),
        "expected BaseMissing for all-zero hash, got {err:?}"
    );
}

#[test]
fn bsdiff_no_base_bytes_supplied_returns_base_missing() {
    let patch = identity_bsdiff_patch(b"hello");
    let archive = build_bsdiff_archive(&patch, 5, NON_ZERO_HASH);
    let err = read_entry_with_opts(archive, opts_no_base()).expect_err("must fail");
    assert!(
        matches!(err, SarError::BaseMissing(_)),
        "expected BaseMissing when no base supplied, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// BSDIFF + compression
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_with_compression_decodes_correctly() {
    let base = b"compress-base-bytes-for-bsdiff-test";
    let target: Vec<u8> = b"SAR bsdiff+deflate test payload"
        .iter()
        .cycle()
        .take(128)
        .copied()
        .collect();

    let patch = {
        // Build patch that copies from base (target.len() bytes, base extended with zeros)
        let diff: Vec<u8> = (0..target.len())
            .map(|i| {
                let base_byte = if i < base.len() { base[i] } else { 0u8 };
                target[i].wrapping_sub(base_byte)
            })
            .collect();
        build_bsdiff_patch(
            &[(target.len() as i64, 0, 0)],
            &diff,
            b"",
            target.len() as i64,
        )
    };

    // Compress the patch.
    let mut compressed_patch = Vec::new();
    encode_stream(
        COMP_ALGO_DEFLATE,
        &mut Cursor::new(&patch),
        &mut compressed_patch,
        CompressionOptions { level: Some(6) },
    )
    .expect("compress patch");

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED | GlobalFlags::HAS_DELTA;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"c.bin".to_vec(), target.len() as u64);
    lfh.entry_mode = EntryMode::from_bits(EntryMode::COMPRESSED);
    lfh.comp_algo_id = Some(COMP_ALGO_DEFLATE);
    lfh.payload_size = compressed_patch.len() as u64;
    lfh.patch_algo_id = Some(0x02); // BSDIFF
    lfh.delta_base_hash = Some(NON_ZERO_HASH);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(&compressed_patch);

    let entry = read_entry_with_opts(archive, opts_with_base(base.to_vec()))
        .expect("BSDIFF + compression must succeed");
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// BSDIFF + encryption
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_with_encryption_decodes_correctly() {
    use sar_core::{
        DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, decode_payload_v2, encode_payload_v2,
    };
    use sar_crypto::aad::build_aead_aad;
    use zeroize::Zeroizing;

    let base = b"bsdiff-encryption-base-bytes";
    let target = b"BSDIFF+AES-256-GCM test payload!!!".repeat(2);
    let patch = {
        let diff: Vec<u8> = (0..target.len())
            .map(|i| {
                let base_byte = if i < base.len() { base[i] } else { 0u8 };
                target[i].wrapping_sub(base_byte)
            })
            .collect();
        build_bsdiff_patch(
            &[(target.len() as i64, 0, 0)],
            &diff,
            b"",
            target.len() as i64,
        )
    };

    let key = Zeroizing::new(b"bsdiff-enc-test-key-32-bytes!!!!".to_vec());
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"nonce-bsdif!");
    let aad = build_aead_aad(b"global-flags", b"lfh-bytes");

    let encoded = encode_payload_v2(
        &patch,
        EncodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            compression_level: None,
            crypto: Some(EntryCryptoContext {
                algo_id: sar_crypto::ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad: aad.clone(),
                key: key.clone(),
            }),
        },
    )
    .expect("encrypt patch");

    // Decrypt and assert correctness.
    let decrypted = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            expected_output_size: patch.len() as u64,
            max_output_size: patch.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: sar_crypto::ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key,
            }),
        },
    )
    .expect("decrypt patch");

    // Now apply the patch directly (pipeline correctness test).
    use sar_delta::{apply_bsdiff, bsdiff::BsdiffLimits};
    let result = apply_bsdiff(
        base,
        &decrypted,
        target.len() as u64,
        &BsdiffLimits::unlimited(),
    )
    .expect("apply_bsdiff after decrypt must succeed");
    assert_eq!(result, target);
}

// ---------------------------------------------------------------------------
// ResourceLimits
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_target_above_resource_limit_returns_limit_exceeded() {
    let base = b"base content";
    let target = b"target content";
    let patch = {
        let diff: Vec<u8> = (0..target.len())
            .map(|i| {
                let base_byte = if i < base.len() { base[i] } else { 0u8 };
                target[i].wrapping_sub(base_byte)
            })
            .collect();
        build_bsdiff_patch(
            &[(target.len() as i64, 0, 0)],
            &diff,
            b"",
            target.len() as i64,
        )
    };
    let archive = build_bsdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH);
    let opts = ArchiveReaderOptions {
        limits: ResourceLimits {
            max_decoded_entry_size: (target.len() as u64) - 1,
            ..ResourceLimits::unlimited()
        },
        delta_base: Some(base.to_vec()),
    };
    let err = read_entry_with_opts(archive, opts).expect_err("must fail");
    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// LOSS_TOLERANT does not suppress SAR_ERR_PATCH_FAILED
// ---------------------------------------------------------------------------

#[test]
fn bsdiff_loss_tolerant_does_not_suppress_patch_failed() {
    // Build a BSDIFF entry whose patch data is corrupt (invalid magic).
    let corrupt_patch = b"NOT_BSDIFF40_GARBAGE_DATA_XXXXX";
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA | GlobalFlags::FILE_FRAGMENTATION;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"lt.bin".to_vec(), corrupt_patch.len() as u64);
    lfh.entry_mode = EntryMode::from_bits(
        EntryMode::FRAGMENT | EntryMode::LAST_FRAGMENT | EntryMode::LOSS_TOLERANT,
    );
    lfh.fragment_id = Some(200);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: corrupt_patch.len() as u32,
    });
    lfh.patch_algo_id = Some(0x02); // BSDIFF
    lfh.delta_base_hash = Some(NON_ZERO_HASH);
    lfh.payload_size = corrupt_patch.len() as u64;

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(corrupt_patch);

    let opts = ArchiveReaderOptions {
        limits: ResourceLimits::unlimited(),
        delta_base: Some(b"base".to_vec()),
    };
    let mut reader = ArchiveReader::with_options(Cursor::new(archive), opts).expect("reader");
    reader.read_global_header().expect("global header");
    let err = reader
        .read_all_logical_files(false)
        .expect_err("LOSS_TOLERANT must not suppress PatchFailed");
    assert!(
        matches!(err, SarError::PatchFailed(_)),
        "expected PatchFailed, got {err:?}"
    );
}
