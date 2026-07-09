//! Integration tests for `STORE_PATCH` (`0x00`) through the full archive
//! reader pipeline (`sar-core`).
//!
//! Spec requirements tested (spec §8.4, §6.1):
//!
//! * STORE_PATCH payload equal to full target succeeds.
//! * Output length exactly equals LFH `Uncompressed Size`.
//! * Payload shorter than LFH `Uncompressed Size` returns `SAR_ERR_PATCH_FAILED`.
//! * Payload longer than LFH `Uncompressed Size` returns `SAR_ERR_PATCH_FAILED`.
//! * All-zero `Delta Base Hash` is accepted for STORE_PATCH.
//! * Nonzero `Delta Base Hash` is preserved for STORE_PATCH (base lookup not required).
//! * `STORE_PATCH + compression` decodes correctly.
//! * `STORE_PATCH + encryption` decodes correctly.
//! * `STORE_PATCH + sparse` applies patch before sparse reconstruction.
//! * `STORE_PATCH + fragmentation` applies after fragment reassembly.
//! * STORE_PATCH output above `ResourceLimits` returns `SAR_ERR_LIMIT_EXCEEDED`.
//! * `LOSS_TOLERANT` does not suppress `SAR_ERR_PATCH_FAILED`.
//! * `VCDIFF`, `BSDIFF`, `ZSTD_PATCH`, and custom algorithms return unsupported.

use std::io::Cursor;

use sar_compression::{COMP_ALGO_DEFLATE, CompressionOptions, encode_stream};
use sar_core::{
    ArchiveReader, ArchiveReaderOptions, GlobalFlags, ResourceLimits, SarError,
    flags::EntryMode,
    format::{
        GlobalHeader, LfhFragmentDescriptor, LocalFileHeader, write_global_header, write_lfh,
    },
    sparse::{SparseExtent, write_sparse_map},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `HAS_DELTA` archive with a single STORE_PATCH entry whose
/// payload bytes are `payload` and whose LFH `Uncompressed Size` is
/// `declared_uncompressed_size`.
///
/// The archive uses the STORE compression algorithm and no encryption.
fn build_store_patch_archive(
    payload: &[u8],
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
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh.delta_base_hash = Some(delta_base_hash);
    lfh.payload_size = payload.len() as u64;

    let lfh_bytes = write_lfh(&flags, &lfh).expect("write lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(payload);
    archive
}

fn read_entry(archive: Vec<u8>) -> Result<sar_core::EntryReader, SarError> {
    let mut reader = ArchiveReader::new(Cursor::new(archive))?;
    reader.read_global_header()?;
    reader.next_entry()?.ok_or(SarError::NotFound("no entry"))
}

fn read_entry_with_opts(
    archive: Vec<u8>,
    opts: ArchiveReaderOptions,
) -> Result<sar_core::EntryReader, SarError> {
    let mut reader = ArchiveReader::with_options(Cursor::new(archive), opts)?;
    reader.read_global_header()?;
    reader.next_entry()?.ok_or(SarError::NotFound("no entry"))
}

// ---------------------------------------------------------------------------
// Basic STORE_PATCH success
// ---------------------------------------------------------------------------

#[test]
fn store_patch_payload_equal_to_full_target_succeeds() {
    let target = b"hello, SAR delta!";
    let archive = build_store_patch_archive(target, target.len() as u64, [0u8; 32]);
    let entry = read_entry(archive).expect("must succeed");
    assert_eq!(entry.payload, target);
}

#[test]
fn store_patch_output_length_exactly_equals_uncompressed_size() {
    let target = b"exact length check payload";
    let archive = build_store_patch_archive(target, target.len() as u64, [0u8; 32]);
    let entry = read_entry(archive).expect("must succeed");
    assert_eq!(entry.payload.len() as u64, entry.metadata.uncompressed_size);
}

// ---------------------------------------------------------------------------
// Length mismatch → SAR_ERR_PATCH_FAILED
// ---------------------------------------------------------------------------

#[test]
fn store_patch_payload_shorter_than_uncompressed_size_returns_patch_failed() {
    let payload = b"short";
    // Declare a larger uncompressed size than the actual payload.
    let declared = (payload.len() as u64) + 10;
    let archive = build_store_patch_archive(payload, declared, [0u8; 32]);
    let err = read_entry(archive).expect_err("must fail");
    assert!(
        matches!(err, SarError::PatchFailed(_)),
        "expected PatchFailed, got {err:?}"
    );
}

#[test]
fn store_patch_payload_longer_than_uncompressed_size_returns_patch_failed() {
    let payload = b"longer than declared";
    // Declare a smaller uncompressed size than the actual payload.
    let declared = (payload.len() as u64) - 3;
    let archive = build_store_patch_archive(payload, declared, [0u8; 32]);
    let err = read_entry(archive).expect_err("must fail");
    assert!(
        matches!(err, SarError::PatchFailed(_)),
        "expected PatchFailed, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Delta Base Hash handling
// ---------------------------------------------------------------------------

#[test]
fn store_patch_all_zero_delta_base_hash_accepted() {
    let target = b"all-zero base hash";
    let archive = build_store_patch_archive(target, target.len() as u64, [0u8; 32]);
    let entry = read_entry(archive).expect("all-zero Delta Base Hash must be accepted");
    assert_eq!(entry.metadata.delta_base_hash, Some([0u8; 32]));
    assert_eq!(entry.payload, target);
}

#[test]
fn store_patch_nonzero_delta_base_hash_preserved_no_base_lookup() {
    let target = b"nonzero base hash entry";
    let hash: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[31] = 0xAD;
        h
    };
    let archive = build_store_patch_archive(target, target.len() as u64, hash);
    let entry =
        read_entry(archive).expect("nonzero Delta Base Hash must not require a base lookup");
    // Hash is preserved verbatim in metadata.
    assert_eq!(entry.metadata.delta_base_hash, Some(hash));
    // Payload decoded correctly without accessing any base object.
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// STORE_PATCH + compression
// ---------------------------------------------------------------------------

#[test]
fn store_patch_with_compression_decodes_correctly() {
    let target: Vec<u8> = b"SAR store-patch + deflate compression test payload"
        .iter()
        .cycle()
        .take(256)
        .copied()
        .collect();

    // Compress the target with DEFLATE.
    let mut compressed = Vec::new();
    encode_stream(
        COMP_ALGO_DEFLATE,
        &mut Cursor::new(&target),
        &mut compressed,
        CompressionOptions { level: Some(6) },
    )
    .expect("compress");

    // Build archive: global COMPRESSED + HAS_DELTA, entry IS_COMPRESSED.
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED | GlobalFlags::HAS_DELTA;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"comp.bin".to_vec(), target.len() as u64);
    lfh.entry_mode = EntryMode::from_bits(EntryMode::COMPRESSED);
    lfh.comp_algo_id = Some(COMP_ALGO_DEFLATE);
    lfh.payload_size = compressed.len() as u64;
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh.delta_base_hash = Some([0u8; 32]);

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(&compressed);

    let entry = read_entry(archive).expect("STORE_PATCH + compression must succeed");
    assert_eq!(entry.payload, target);
}

// ---------------------------------------------------------------------------
// STORE_PATCH + encryption
// ---------------------------------------------------------------------------

/// Verifies that STORE_PATCH works correctly in the full decode pipeline when
/// the entry is encrypted (AEAD decrypt → decompress → STORE_PATCH identity).
///
/// Rather than building a full archive with a key provider (which depends on
/// password-based KMS setup), this test exercises the same transformation
/// order by running the encrypt/decrypt pipeline functions directly and then
/// confirming that `apply_store_patch` succeeds on the decrypted output.
#[test]
fn store_patch_with_encryption_decodes_correctly() {
    use sar_core::{
        DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, decode_payload_v2, encode_payload_v2,
    };
    use sar_crypto::aad::build_aead_aad;
    use zeroize::Zeroizing;

    let target = b"STORE_PATCH + AES-256-GCM test payload".repeat(4);

    let key = Zeroizing::new(b"storpatch-enc-test-key-32bytes!x".to_vec());
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(b"nonce-store!");
    let aad = build_aead_aad(b"global-flags", b"lfh-bytes");

    // Encode: encrypt (no compression).
    let encoded = encode_payload_v2(
        &target,
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
    .expect("encrypt");

    // Decode: decrypt (same transformation order as archive reader).
    let decoded = decode_payload_v2(
        &encoded,
        DecodingPlanV2 {
            is_compressed: false,
            comp_algo_id: 0,
            expected_output_size: target.len() as u64,
            max_output_size: target.len() as u64,
            crypto: Some(EntryCryptoContext {
                algo_id: sar_crypto::ENCR_AES256_GCM,
                iv_nonce: nonce,
                aad,
                key,
            }),
        },
    )
    .expect("decrypt");

    // STORE_PATCH: the decrypted payload IS the target.
    let result = sar_core::apply_store_patch(&decoded, target.len() as u64)
        .expect("STORE_PATCH must succeed on decrypted payload");
    assert_eq!(result, target.as_slice());
}

// ---------------------------------------------------------------------------
// STORE_PATCH + sparse
// ---------------------------------------------------------------------------

#[test]
fn store_patch_with_sparse_applies_patch_before_sparse_reconstruction() {
    // Two sparse data segments: [0..5] = "hello", [10..15] = "world".
    // Logical file: "hello\0\0\0\0\0world" (16 bytes).
    let data_a = b"hello";
    let data_b = b"world";
    let logical_size: u64 = 16;

    let extents = vec![
        SparseExtent {
            offset: 0,
            length: 5,
        },
        SparseExtent {
            offset: 10,
            length: 5,
        },
    ];

    // Gathered payload: data_a ++ data_b (10 bytes).
    let mut gathered = Vec::new();
    gathered.extend_from_slice(data_a);
    gathered.extend_from_slice(data_b);

    let sparse_map = write_sparse_map(&extents, false);

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA | GlobalFlags::SPARSE_FILES;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"sparse.bin".to_vec(), logical_size);
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh.delta_base_hash = Some([0u8; 32]);
    lfh.payload_size = gathered.len() as u64;
    lfh.sparse_map = sparse_map;

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(&gathered);

    // `next_entry` applies STORE_PATCH (returns gathered payload as-is for sparse).
    // `read_all_logical_files` then applies sparse reconstruction.
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("global header");
    let files = reader
        .read_all_logical_files(false)
        .expect("STORE_PATCH + sparse must succeed");

    assert_eq!(files.len(), 1);
    let file = &files[0];
    assert_eq!(file.data.len() as u64, logical_size);

    // Verify data segments at correct offsets.
    assert_eq!(&file.data[0..5], data_a, "first extent");
    assert_eq!(&file.data[5..10], &[0u8; 5], "sparse hole");
    assert_eq!(&file.data[10..15], data_b, "second extent");
    assert_eq!(&file.data[15..16], &[0u8; 1], "trailing hole");
}

// ---------------------------------------------------------------------------
// STORE_PATCH + fragmentation
// ---------------------------------------------------------------------------

#[test]
fn store_patch_with_fragmentation_applies_after_fragment_reassembly() {
    // Two fragments whose payloads when assembled produce the full STORE_PATCH target.
    let frag0_data = b"fragment-zero-";
    let frag1_data = b"fragment-one.";
    let full_target: Vec<u8> = frag0_data
        .iter()
        .chain(frag1_data.iter())
        .copied()
        .collect();
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA | GlobalFlags::FILE_FRAGMENTATION;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let fragment_id: u32 = 7;

    // Fragment 0
    let mode0 = EntryMode::from_bits(EntryMode::FRAGMENT);
    let mut lfh0 = LocalFileHeader::minimal_store(b"frag.bin".to_vec(), frag0_data.len() as u64);
    lfh0.entry_mode = mode0;
    lfh0.fragment_id = Some(fragment_id);
    lfh0.fragment_index = Some(0);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: frag0_data.len() as u32,
    });
    lfh0.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh0.delta_base_hash = Some([0u8; 32]);
    lfh0.payload_size = frag0_data.len() as u64;

    let lfh0_bytes = write_lfh(&flags, &lfh0).expect("lfh0");
    archive.extend_from_slice(&lfh0_bytes);
    archive.extend_from_slice(frag0_data);

    // Fragment 1 (last)
    let mode1 = EntryMode::from_bits(EntryMode::FRAGMENT | EntryMode::LAST_FRAGMENT);
    let mut lfh1 = LocalFileHeader::minimal_store(b"frag.bin".to_vec(), frag1_data.len() as u64);
    lfh1.entry_mode = mode1;
    lfh1.fragment_id = Some(fragment_id);
    lfh1.fragment_index = Some(1);
    lfh1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: frag0_data.len() as u64,
        fragment_size: frag1_data.len() as u32,
    });
    lfh1.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh1.delta_base_hash = Some([0u8; 32]);
    lfh1.payload_size = frag1_data.len() as u64;

    let lfh1_bytes = write_lfh(&flags, &lfh1).expect("lfh1");
    archive.extend_from_slice(&lfh1_bytes);
    archive.extend_from_slice(frag1_data);

    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    reader.read_global_header().expect("global header");
    let files = reader
        .read_all_logical_files(false)
        .expect("STORE_PATCH + fragmentation must succeed");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].data, full_target);
}

// ---------------------------------------------------------------------------
// ResourceLimits
// ---------------------------------------------------------------------------

#[test]
fn store_patch_output_above_resource_limits_returns_limit_exceeded() {
    let target = b"some payload content";
    // Set a limit that is smaller than the target payload.
    let archive = build_store_patch_archive(target, target.len() as u64, [0u8; 32]);
    let opts = ArchiveReaderOptions {
        limits: ResourceLimits {
            max_decoded_entry_size: (target.len() as u64) - 1,
            ..ResourceLimits::unlimited()
        },
        delta_base: None,
    };
    let err = read_entry_with_opts(archive, opts).expect_err("must fail with limit exceeded");
    assert!(
        matches!(err, SarError::LimitExceeded(_)),
        "expected LimitExceeded, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// LOSS_TOLERANT does not suppress SAR_ERR_PATCH_FAILED
// ---------------------------------------------------------------------------

#[test]
fn loss_tolerant_does_not_suppress_patch_failed() {
    // Build a fragment entry with LOSS_TOLERANT + IS_FRAGMENT mode bits.
    // LOSS_TOLERANT requires IS_FRAGMENT and FILE_FRAGMENTATION global flag.
    let payload = b"mismatch";
    // Declare a larger uncompressed size so STORE_PATCH fails.
    let declared_uncompressed = (payload.len() as u64) + 5;

    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA | GlobalFlags::FILE_FRAGMENTATION;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"lt.bin".to_vec(), declared_uncompressed);
    // IS_FRAGMENT | LAST_FRAGMENT | LOSS_TOLERANT
    lfh.entry_mode = EntryMode::from_bits(
        EntryMode::FRAGMENT | EntryMode::LAST_FRAGMENT | EntryMode::LOSS_TOLERANT,
    );
    lfh.fragment_id = Some(99);
    lfh.fragment_index = Some(0);
    lfh.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: payload.len() as u32,
    });
    lfh.patch_algo_id = Some(0x00); // STORE_PATCH
    lfh.delta_base_hash = Some([0u8; 32]);
    lfh.payload_size = payload.len() as u64;

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(payload);

    // LOSS_TOLERANT must NOT suppress PatchFailed.
    let err = read_entry(archive).expect_err("must fail");
    assert!(
        matches!(err, SarError::PatchFailed(_)),
        "expected PatchFailed (not suppressed by LOSS_TOLERANT), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Unsupported algorithms return SAR_ERR_UNSUPPORTED
// ---------------------------------------------------------------------------

fn build_archive_with_algo(patch_algo_id: u8) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let payload = b"irrelevant payload";
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let mut lfh = LocalFileHeader::minimal_store(b"x.bin".to_vec(), payload.len() as u64);
    lfh.patch_algo_id = Some(patch_algo_id);
    lfh.delta_base_hash = Some([0u8; 32]);
    lfh.payload_size = payload.len() as u64;

    let lfh_bytes = write_lfh(&flags, &lfh).expect("lfh");
    archive.extend_from_slice(&lfh_bytes);
    archive.extend_from_slice(payload);
    archive
}

#[test]
fn vcdiff_all_zero_hash_returns_base_missing() {
    // VCDIFF with all-zero Delta Base Hash returns SAR_ERR_BASE_MISSING (now implemented).
    let archive = build_archive_with_algo(0x01); // VCDIFF, all-zero hash, no base supplied
    let err = read_entry(archive).expect_err("VCDIFF with all-zero hash must return BaseMissing");
    assert!(
        matches!(err, SarError::BaseMissing(_)),
        "expected BaseMissing for VCDIFF+all-zero-hash, got {err:?}"
    );
}

#[test]
fn bsdiff_all_zero_hash_returns_base_missing() {
    // BSDIFF with all-zero Delta Base Hash returns SAR_ERR_BASE_MISSING (now implemented).
    let archive = build_archive_with_algo(0x02); // BSDIFF, all-zero hash, no base supplied
    let err = read_entry(archive).expect_err("BSDIFF with all-zero hash must return BaseMissing");
    assert!(
        matches!(err, SarError::BaseMissing(_)),
        "expected BaseMissing for BSDIFF+all-zero-hash, got {err:?}"
    );
}

#[test]
fn zstd_patch_returns_unsupported() {
    let archive = build_archive_with_algo(0x03); // ZSTD_PATCH
    let err = read_entry(archive).expect_err("ZSTD_PATCH must return Unsupported");
    assert!(
        matches!(err, SarError::Unsupported(_)),
        "expected Unsupported for ZSTD_PATCH, got {err:?}"
    );
}

#[test]
fn custom_algo_returns_unsupported() {
    let archive = build_archive_with_algo(0xF5); // custom range
    let err = read_entry(archive).expect_err("custom algo must return Unsupported");
    assert!(
        matches!(err, SarError::Unsupported(_)),
        "expected Unsupported for custom algo 0xF5, got {err:?}"
    );
}

#[test]
fn reserved_algo_returns_reserved_value() {
    let archive = build_archive_with_algo(0x80); // reserved range
    let err = read_entry(archive).expect_err("reserved algo must return ReservedValue");
    assert!(
        matches!(err, SarError::ReservedValue(_)),
        "expected ReservedValue for reserved algo 0x80, got {err:?}"
    );
}
