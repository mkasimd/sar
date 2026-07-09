//! Integration tests for `VCDIFF` (`0x01`) through the full archive reader
//! pipeline (`sar-core`).
//!
//! Spec requirements tested (spec §8.4.2, RFC 3284):
//!
//! * Valid VCDIFF patch with supplied base reconstructs expected target.
//! * All-zero Delta Base Hash returns `SAR_ERR_BASE_MISSING`.
//! * No base bytes supplied returns `SAR_ERR_BASE_MISSING`.
//! * `VCDIFF + compression` decodes correctly.
//! * `VCDIFF + encryption` decodes correctly.
//! * VCDIFF output above `ResourceLimits` returns `SAR_ERR_LIMIT_EXCEEDED`.
//! * `LOSS_TOLERANT` does not suppress `SAR_ERR_PATCH_FAILED`.

use std::io::Cursor;

use sar_compression::{COMP_ALGO_DEFLATE, CompressionOptions, encode_stream};
use sar_core::{
    ArchiveReader, ArchiveReaderOptions, GlobalFlags, ResourceLimits, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
};

// ---------------------------------------------------------------------------
// VCDIFF patch-building helpers
// ---------------------------------------------------------------------------

fn encode_varint(mut v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let mut buf = Vec::new();
    while v > 0 {
        buf.push((v & 0x7F) as u8);
        v >>= 7;
    }
    buf.reverse();
    let last = buf.len() - 1;
    for b in &mut buf[..last] {
        *b |= 0x80;
    }
    buf
}

/// Builds a VCDIFF window that emits `add_data` using an ADD instruction.
fn vcdiff_add_window(add_data: &[u8]) -> Vec<u8> {
    let mut inst = Vec::new();
    inst.push(0x01u8); // ADD code, size follows
    inst.extend_from_slice(&encode_varint(add_data.len() as u64));

    let twl = encode_varint(add_data.len() as u64);
    let mut delta_body = Vec::new();
    delta_body.extend_from_slice(&twl);
    delta_body.push(0x00u8); // delta_indicator
    delta_body.extend_from_slice(&encode_varint(add_data.len() as u64)); // len_add_run
    delta_body.extend_from_slice(&encode_varint(inst.len() as u64));
    delta_body.extend_from_slice(&encode_varint(0u64)); // len_addr
    delta_body.extend_from_slice(add_data);
    delta_body.extend_from_slice(&inst);

    let del = encode_varint(delta_body.len() as u64);
    let mut win = Vec::new();
    win.push(0x00u8); // win_indicator
    win.extend_from_slice(&del);
    win.extend_from_slice(&delta_body);
    win
}

/// Builds a full VCDIFF patch wrapping a single window.
fn vcdiff_patch(window_bytes: &[u8]) -> Vec<u8> {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00");
    patch.push(0x00u8); // hdr_indicator
    patch.extend_from_slice(window_bytes);
    patch
}

// ---------------------------------------------------------------------------
// Archive-building helpers
// ---------------------------------------------------------------------------

/// Non-zero hash sentinel.
const NON_ZERO_HASH: [u8; 32] = {
    let mut h = [0u8; 32];
    h[0] = 0xCC;
    h[31] = 0xDD;
    h
};

/// Builds a minimal `HAS_DELTA` archive with a single VCDIFF entry.
fn build_vcdiff_archive(
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
    lfh.patch_algo_id = Some(0x01); // VCDIFF
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
// Basic success (ADD-only, no base required for VCD_SOURCE)
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_add_only_patch_reconstructs_target() {
    let target = b"VCDIFF integration test target!";
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    // Use a non-zero hash but supply the base bytes (base is not used in ADD-only).
    let archive = build_vcdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH);
    let entry = read_entry_with_opts(archive, opts_with_base(b"any base".to_vec()))
        .expect("ADD-only VCDIFF must succeed");
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// Delta Base Hash checks
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_all_zero_delta_base_hash_returns_base_missing() {
    let window = vcdiff_add_window(b"x");
    let patch = vcdiff_patch(&window);
    let archive = build_vcdiff_archive(&patch, 1, [0u8; 32]);
    let err = read_entry_with_opts(archive, opts_no_base()).expect_err("must fail");
    assert!(
        matches!(err, SarError::BaseMissing(_)),
        "expected BaseMissing, got {err:?}"
    );
}

#[test]
fn vcdiff_no_base_bytes_supplied_returns_base_missing() {
    let window = vcdiff_add_window(b"hello");
    let patch = vcdiff_patch(&window);
    let archive = build_vcdiff_archive(&patch, 5, NON_ZERO_HASH);
    let err = read_entry_with_opts(archive, opts_no_base()).expect_err("must fail");
    assert!(
        matches!(err, SarError::BaseMissing(_)),
        "expected BaseMissing, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// VCDIFF + compression
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_with_compression_decodes_correctly() {
    let target: Vec<u8> = b"SAR vcdiff+deflate test payload!!!"
        .iter()
        .cycle()
        .take(256)
        .copied()
        .collect();

    let window = vcdiff_add_window(&target);
    let patch = vcdiff_patch(&window);

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
    lfh.patch_algo_id = Some(0x01); // VCDIFF
    lfh.delta_base_hash = Some(NON_ZERO_HASH);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(&compressed_patch);

    let entry = read_entry_with_opts(archive, opts_with_base(b"base".to_vec()))
        .expect("VCDIFF + compression must succeed");
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// VCDIFF + encryption
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_with_encryption_decodes_correctly() {
    use sar_core::{
        DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, decode_payload_v2, encode_payload_v2,
    };
    use sar_crypto::aad::build_aead_aad;
    use zeroize::Zeroizing;

    let target = b"VCDIFF+AES-256-GCM integration test payload!";
    let window = vcdiff_add_window(target);
    let patch_bytes = vcdiff_patch(&window);

    let key = Zeroizing::new(b"vcdiff-enc-test-key-32-bytes!!!!".to_vec());
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"nonce-vciff!");
    let aad = build_aead_aad(b"global-flags", b"lfh-bytes");

    let encoded = encode_payload_v2(
        &patch_bytes,
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

    let decrypted = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            expected_output_size: patch_bytes.len() as u64,
            max_output_size: patch_bytes.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: sar_crypto::ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key,
            }),
        },
    )
    .expect("decrypt patch");

    use sar_delta::{apply_vcdiff, vcdiff::VcdiffLimits};
    let result = apply_vcdiff(
        b"base",
        &decrypted,
        target.len() as u64,
        &VcdiffLimits::unlimited(),
    )
    .expect("apply_vcdiff after decrypt must succeed");
    assert_eq!(result, target);
}

// ---------------------------------------------------------------------------
// ResourceLimits
// ---------------------------------------------------------------------------

#[test]
fn vcdiff_target_above_resource_limit_returns_limit_exceeded() {
    let target = b"some vcdiff output content";
    let window = vcdiff_add_window(target);
    let patch = vcdiff_patch(&window);
    let archive = build_vcdiff_archive(&patch, target.len() as u64, NON_ZERO_HASH);
    let opts = ArchiveReaderOptions {
        limits: ResourceLimits {
            max_decoded_entry_size: (target.len() as u64) - 1,
            ..ResourceLimits::unlimited()
        },
        delta_base: Some(b"base".to_vec()),
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
fn vcdiff_loss_tolerant_does_not_suppress_patch_failed() {
    // Corrupt patch data (wrong magic).
    let corrupt_patch = b"NOT_VCDIFF_GARBAGE_HERE_XXXXXXXXX";
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
    lfh.fragment_id = Some(201);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: corrupt_patch.len() as u32,
    });
    lfh.patch_algo_id = Some(0x01); // VCDIFF
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
        "expected PatchFailed (not suppressed by LOSS_TOLERANT), got {err:?}"
    );
}

#[test]
fn vcdiff_secondary_compressor_returns_unsupported() {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00");
    patch.push(0x01u8); // VCD_DECOMPRESS
    patch.push(0x01u8); // unsupported compressor id
    patch.extend_from_slice(&vcdiff_add_window(b"x"));

    let archive = build_vcdiff_archive(&patch, 1, NON_ZERO_HASH);
    let err = read_entry_with_opts(archive, opts_with_base(b"base".to_vec())).expect_err("must fail");
    assert!(matches!(err, SarError::Unsupported(_)));
}
