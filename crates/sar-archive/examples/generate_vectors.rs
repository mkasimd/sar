//! Vector generator for `test-vectors/`.
//!
//! Generates binary `.sar` fixture files for conformance testing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example generate_vectors -p sar-archive
//! ```
//!
//! The generator writes fixtures to `test-vectors/` relative to the workspace
//! root. It is **idempotent**: running it again overwrites existing fixtures
//! with identical bytes (generation is deterministic).
//!
//! # Generated fixtures
//!
//! See `test-vectors/README.md` for the full vector inventory.
//!
//! # Determinism
//!
//! All fixtures use fixed salts, iteration counts, and payloads so that the
//! output is bit-for-bit reproducible across builds on the same platform. The
//! AEAD nonces are derived from a fixed seed rather than `getrandom` to ensure
//! reproducibility.
//!
//! Crypto fixtures use test-only passwords and keys. **Do not use for real
//! data.**

#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::path::{Path, PathBuf};

use sar_archive::{
    ArchiveRecoverySettings, ArchiveWriter, ArchiveWriterOptions, CompressionSettings,
    DeltaWriteOptions, EncryptionSettings, EntryInput, FecSettings,
};
use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD};
use sar_core::{
    CDC_ALGO_LITERAL, EntryKind, GlobalFlags, SparseExtent,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256,
    SecretBytes, SecretString, error::SarCryptoError, kms::types::Pbkdf2Params,
    provider::KeyProvider,
};
use sar_delta::{PATCH_ALGO_STORE_PATCH, PatchAlgoId};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR};

// ---------------------------------------------------------------------------
// Test password / key material (TEST-ONLY — do not use for real data)
// ---------------------------------------------------------------------------

const TEST_PASSWORD_AES: &str = "sar-test-password-aes";
const TEST_PASSWORD_XCHACHA: &str = "sar-test-password-xchacha";
const DELTA_VECTOR_PAYLOAD_LEN: usize = 64;
const ZERO_DELTA_BASE_HASH: [u8; 32] = [0u8; 32];
const PROMOTED_DELTA_BASE_HASH_WORD_0: u64 = 0x_bdaa_cafe_dead_beef_u64;
const PROMOTED_DELTA_BASE_HASH_WORD_1: u64 = 0x_1234_5678_9abc_def0_u64;

/// Fixed 32-byte salt for all PBKDF2 derivations in test vectors.
/// This is TEST-ONLY material.
const TEST_SALT_AES: [u8; 32] = [
    0x73, 0x61, 0x72, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x65, 0x73, 0x2d, 0x73, 0x61, 0x6c,
    0x74, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

const TEST_SALT_XCHACHA: [u8; 32] = [
    0x73, 0x61, 0x72, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x78, 0x63, 0x68, 0x61, 0x63, 0x68, 0x61,
    0x2d, 0x73, 0x61, 0x6c, 0x74, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// ---------------------------------------------------------------------------
// Key provider for test vectors
// ---------------------------------------------------------------------------

struct StaticPasswordProvider {
    password: SecretString,
}

impl KeyProvider for StaticPasswordProvider {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(self.password.clone()))
    }

    fn unwrap_key(
        &self,
        _ctx: &KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }

    fn external_key(&self, _ctx: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helper: write bytes to a file under the vectors root
// ---------------------------------------------------------------------------

fn vectors_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    // crates/sar-archive → workspace root
    let workspace = Path::new(&manifest_dir)
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace.join("test-vectors")
}

fn write_fixture(relative_path: &str, bytes: &[u8]) {
    let root = vectors_root();
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create dir");
    }
    std::fs::write(&path, bytes).expect("write fixture");
    println!("wrote {}", path.display());
}

fn skip_deferred_vector(relative_path: &str, reason: &str) {
    println!(
        "skipped {} ({reason})",
        vectors_root().join(relative_path).display()
    );
}

fn make_promoted_delta_base_hash() -> [u8; 32] {
    let mut base_hash = ZERO_DELTA_BASE_HASH;
    let first_word_end = std::mem::size_of::<u64>();
    let second_word_end = first_word_end + std::mem::size_of::<u64>();
    base_hash[..first_word_end].copy_from_slice(&PROMOTED_DELTA_BASE_HASH_WORD_0.to_le_bytes());
    base_hash[first_word_end..second_word_end]
        .copy_from_slice(&PROMOTED_DELTA_BASE_HASH_WORD_1.to_le_bytes());
    base_hash
}

// ---------------------------------------------------------------------------
// Generator helpers
// ---------------------------------------------------------------------------

fn make_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xFF) as u8).collect()
}

fn write_store_archive(no_index: bool, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index,
            ..Default::default()
        },
    )
    .unwrap();
    for (name, payload) in entries {
        writer
            .add_entry(EntryInput::file(*name, payload.to_vec()))
            .unwrap();
    }
    writer.finish().unwrap();
    buf
}

fn write_compressed_archive(algo_id: u8, no_index: bool, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression(
        &mut buf,
        ArchiveWriterOptions {
            no_index,
            ..Default::default()
        },
        CompressionSettings {
            algo_id,
            level: None,
        },
    )
    .unwrap();
    for (name, payload) in entries {
        writer
            .add_entry(EntryInput::file(*name, payload.to_vec()))
            .unwrap();
    }
    writer.finish().unwrap();
    buf
}

fn write_encrypted_archive(algo_id: u8, salt: &[u8], password: &str, payload: &[u8]) -> Vec<u8> {
    let kms_params = KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: salt.to_vec(),
        iterations: 100_000,
        derived_key_length: 32,
    });
    let opts = ArchiveWriterOptions {
        no_index: false,
        encryption: Some(EncryptionSettings {
            algo_id,
            kms_params,
        }),
        ..Default::default()
    };
    let key_provider: Box<dyn KeyProvider> = Box::new(StaticPasswordProvider {
        password: SecretString::new(password.to_string()),
    });
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut buf),
        opts,
        CompressionSettings::store(),
        Some(key_provider),
    )
    .unwrap();
    writer
        .add_entry(EntryInput::file("secret.bin", payload.to_vec()))
        .unwrap();
    writer.finish().unwrap();
    buf
}

fn write_fec_archive(fec: FecSettings, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: false,
            fec: Some(fec),
            ..Default::default()
        },
    )
    .unwrap();
    writer
        .add_entry(EntryInput::file("data.bin", payload.to_vec()))
        .unwrap();
    writer.finish().unwrap();
    buf
}

fn write_archive_recovery_archive(recovery: ArchiveRecoverySettings, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: false,
            archive_recovery: Some(recovery),
            ..Default::default()
        },
    )
    .unwrap();
    writer
        .add_entry(EntryInput::file("data.bin", payload.to_vec()))
        .unwrap();
    writer.finish().unwrap();
    buf
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    // -----------------------------------------------------------------------
    // Valid: minimal
    // -----------------------------------------------------------------------

    let minimal_no_index = write_store_archive(true, &[("hello.txt", b"Hello, SAR!")]);
    write_fixture(
        "valid/minimal/store-no-index/minimal_store_no_index.sar",
        &minimal_no_index,
    );

    let minimal_indexed = write_store_archive(false, &[("hello.txt", b"Hello, SAR!")]);
    write_fixture(
        "valid/indexed/store-indexed/indexed_store.sar",
        &minimal_indexed,
    );

    let no_index_two = write_store_archive(
        true,
        &[
            ("first.txt", b"first entry payload"),
            ("second.txt", b"second entry payload"),
        ],
    );
    write_fixture(
        "valid/no-index/two-entries/no_index_two_entries.sar",
        &no_index_two,
    );

    // -----------------------------------------------------------------------
    // Valid: 32-bit and 64-bit LFH size layout
    // -----------------------------------------------------------------------

    let size_32bit = write_store_archive(false, &[("file.bin", &make_payload(128))]);
    write_fixture("valid/minimal/size-32bit/lfh_32bit_size.sar", &size_32bit);

    // Force64 writes 64-bit size fields.
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                lfh_size_field_policy: sar_archive::LfhSizeFieldPolicy::Force64,
                ..Default::default()
            },
        )
        .unwrap();
        writer
            .add_entry(EntryInput::file("file.bin", make_payload(128)))
            .unwrap();
        writer.finish().unwrap();
        write_fixture("valid/minimal/size-64bit/lfh_64bit_size.sar", &buf);
    }

    // -----------------------------------------------------------------------
    // Valid: compression
    // -----------------------------------------------------------------------

    let payload = b"The quick brown fox jumps over the lazy dog. ".repeat(64);
    let store_bytes = write_compressed_archive(COMP_ALGO_STORE, false, &[("doc.txt", &payload)]);
    write_fixture("valid/compression/store/store_entry.sar", &store_bytes);

    let deflate_bytes =
        write_compressed_archive(COMP_ALGO_DEFLATE, false, &[("doc.txt", &payload)]);
    write_fixture(
        "valid/compression/deflate/deflate_entry.sar",
        &deflate_bytes,
    );

    let zstd_bytes = write_compressed_archive(COMP_ALGO_ZSTD, false, &[("doc.txt", &payload)]);
    write_fixture("valid/compression/zstd/zstd_entry.sar", &zstd_bytes);

    // -----------------------------------------------------------------------
    // Valid: crypto
    // -----------------------------------------------------------------------

    let crypto_payload = make_payload(256);

    let aes_bytes = write_encrypted_archive(
        ENCR_AES256_GCM,
        &TEST_SALT_AES,
        TEST_PASSWORD_AES,
        &crypto_payload,
    );
    write_fixture("valid/crypto/aes256-gcm/aes256_gcm_entry.sar", &aes_bytes);

    let xchacha_bytes = write_encrypted_archive(
        ENCR_XCHACHA20_POLY,
        &TEST_SALT_XCHACHA,
        TEST_PASSWORD_XCHACHA,
        &crypto_payload,
    );
    write_fixture(
        "valid/crypto/xchacha20-poly1305/xchacha20_poly1305_entry.sar",
        &xchacha_bytes,
    );

    // -----------------------------------------------------------------------
    // Invalid: bad AEAD tag — derived from AES-GCM vector by flipping tag
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Invalid: bad AEAD tag — NO_INDEX encrypted archive with corrupted AEAD tag
    // -----------------------------------------------------------------------

    {
        // Use a NO_INDEX encrypted archive so the file ends with the AEAD
        // authentication tag (ciphertext || 16-byte tag). Corrupting the last
        // 16 bytes then triggers SAR_ERR_AUTH_FAILED on decryption.
        let kms_params = KmsParams::Pbkdf2(Pbkdf2Params {
            prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
            salt: TEST_SALT_AES.to_vec(),
            iterations: 100_000,
            derived_key_length: 32,
        });
        let opts = ArchiveWriterOptions {
            no_index: true, // NO_INDEX so file ends with payload (AEAD tag)
            encryption: Some(EncryptionSettings {
                algo_id: ENCR_AES256_GCM,
                kms_params,
            }),
            ..Default::default()
        };
        let key_provider: Box<dyn KeyProvider> = Box::new(StaticPasswordProvider {
            password: SecretString::new(TEST_PASSWORD_AES.to_string()),
        });
        let mut aes_no_index = Vec::new();
        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut aes_no_index),
            opts,
            CompressionSettings::store(),
            Some(key_provider),
        )
        .unwrap();
        writer
            .add_entry(EntryInput::file("secret.bin", crypto_payload.to_vec()))
            .unwrap();
        writer.finish().unwrap();

        let mut bad_tag = aes_no_index;
        if bad_tag.len() >= 16 {
            let len = bad_tag.len();
            // In a NO_INDEX AES-256-GCM archive the file layout is:
            //   global_header | LFH | ciphertext (plaintext_len bytes) | AEAD tag (16 bytes)
            // Because there is no Central Dictionary or Footer (NO_INDEX), the last
            // 16 bytes of the file are always the AES-GCM authentication tag.
            // Flipping them causes AEAD decryption to return an authentication error.
            for b in bad_tag[len - 16..].iter_mut() {
                *b ^= 0xFF;
            }
        }
        write_fixture("invalid/crypto/bad-aead-tag/bad_aead_tag.sar", &bad_tag);
    }

    // -----------------------------------------------------------------------
    // Valid: FEC
    // -----------------------------------------------------------------------

    let fec_payload = make_payload(512);
    let xor_bytes = write_fec_archive(FecSettings::default_xor(), &fec_payload);
    write_fixture("valid/fec/xor/xor_fec_entry.sar", &xor_bytes);

    let rs_bytes = write_fec_archive(FecSettings::default_rs(), &fec_payload);
    write_fixture("valid/fec/rs/rs_fec_entry.sar", &rs_bytes);

    let archive_recovery_xor_bytes = write_archive_recovery_archive(
        ArchiveRecoverySettings {
            algo_id: FEC_ALGO_XOR,
            config0: 1,
            config1: 0,
            symbol_size: 0,
        },
        &make_payload(1024),
    );
    write_fixture(
        "valid/recovery/archive-xor/recovery_tlv_archive_xor.sar",
        &archive_recovery_xor_bytes,
    );

    let archive_recovery_rs_bytes = write_archive_recovery_archive(
        ArchiveRecoverySettings {
            algo_id: FEC_ALGO_REED_SOLOMON,
            config0: 4,
            config1: 2,
            symbol_size: 256,
        },
        &make_payload(1024),
    );
    write_fixture(
        "valid/recovery/archive-rs/recovery_tlv_archive_rs.sar",
        &archive_recovery_rs_bytes,
    );

    // -----------------------------------------------------------------------
    // Valid: fragmentation — valid contiguous two-fragment group
    // -----------------------------------------------------------------------

    // Fragmentation vectors remain deferred in this corrective pass. Do not
    // emit placeholder STORE archives that overclaim fragment metadata.
    skip_deferred_vector(
        "valid/fragmentation/valid-reassembly/fragmented_two_parts.sar",
        "real fragment-group fixtures require the streaming writer path",
    );
    skip_deferred_vector(
        "valid/fragmentation/loss-tolerant-gap/fragmented_loss_tolerant_gap.sar",
        "real LOSS_TOLERANT fragment-gap fixtures require fragment metadata and degraded reassembly behavior",
    );

    // -----------------------------------------------------------------------
    // Valid: sparse
    // -----------------------------------------------------------------------

    {
        // Sparse file with two extents: [0..32) and [64..96), logical size 128.
        let extents = vec![
            SparseExtent {
                offset: 0,
                length: 32,
            },
            SparseExtent {
                offset: 64,
                length: 32,
            },
        ];
        let gathered = make_payload(64); // 32 + 32 bytes of data

        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                sparse: true,
                ..Default::default()
            },
        )
        .unwrap();

        writer
            .write_sparse_entry(
                "sparse.bin",
                &gathered,
                sar_archive::SparseWriteOptions {
                    logical_size: 128,
                    extents,
                },
            )
            .unwrap();
        writer.finish().unwrap();
        write_fixture("valid/sparse/simple/sparse_simple.sar", &buf);
    }

    // Sparse + delta ordering remains reference-only in this corrective pass.
    // Do not emit a STORE fallback that lacks combined sparse + patch metadata.
    skip_deferred_vector(
        "valid/sparse/with-delta/sparse_with_store_patch.sar",
        "real sparse-plus-delta fixtures require combined patch and sparse metadata on one logical entry",
    );

    // -----------------------------------------------------------------------
    // Valid: CDC
    // -----------------------------------------------------------------------

    // CDC requires the CDC_SUPPORT global flag and CDC algo ID in LFH.
    // Use the streaming writer / raw format helper since ArchiveWriter does
    // not yet expose CDC directly. Write a minimal CDC Literal Mode archive
    // using the raw write_lfh path.
    {
        let payload = make_payload(DELTA_VECTOR_PAYLOAD_LEN);

        // GlobalFlags with CDC_SUPPORT
        let flags = GlobalFlags::NO_INDEX | GlobalFlags::CDC_SUPPORT;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut archive = write_global_header(&gh).unwrap();

        // Minimal LFH with the CDC literal-mode algorithm ID.
        let mut lfh = sar_core::format::LocalFileHeader::minimal_store(
            b"cdc_literal.bin".to_vec(),
            payload.len() as u64,
        );
        lfh.cdc_algo_id = Some(CDC_ALGO_LITERAL);

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(&payload);

        write_fixture("valid/cdc/literal-mode/cdc_literal_entry.sar", &archive);
    }

    // FASTCDC CDC_MAP remains deferred in this corrective pass. Do not reuse the
    // literal-mode archive as a placeholder.
    skip_deferred_vector(
        "valid/cdc/fastcdc-metadata/cdc_fastcdc_map.sar",
        "real FASTCDC CDC_MAP fixtures require explicit CDC metadata rather than literal-mode fallback bytes",
    );

    // -----------------------------------------------------------------------
    // Valid: delta — STORE_PATCH
    // -----------------------------------------------------------------------

    {
        let target = make_payload(DELTA_VECTOR_PAYLOAD_LEN);

        let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut archive = write_global_header(&gh).unwrap();

        let mut lfh =
            LocalFileHeader::minimal_store(b"store_patch.bin".to_vec(), target.len() as u64);
        lfh.patch_algo_id = Some(PATCH_ALGO_STORE_PATCH);
        lfh.delta_base_hash = Some(ZERO_DELTA_BASE_HASH);

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(&target);

        write_fixture("valid/delta/store-patch/store_patch_entry.sar", &archive);
    }

    // -----------------------------------------------------------------------
    // Valid: delta — VCDIFF
    // -----------------------------------------------------------------------

    {
        let base = make_payload(DELTA_VECTOR_PAYLOAD_LEN);
        let target: Vec<u8> = make_payload(DELTA_VECTOR_PAYLOAD_LEN)
            .into_iter()
            .map(|b| b.wrapping_add(1))
            .collect();

        // Delta base hash: non-zero opaque identity (SHA-256 of the base bytes
        // used by the reader to locate the base object; treated as opaque here).
        let base_hash = make_promoted_delta_base_hash();

        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: true,
                with_delta: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("vcdiff_target.bin", target);
        entry.delta = Some(DeltaWriteOptions {
            algorithm: PatchAlgoId::Vcdiff,
            base: base.clone(),
            delta_base_hash: base_hash,
        });
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();

        write_fixture("valid/delta/vcdiff/vcdiff_patch_entry.sar", &buf);
        write_fixture("valid/delta/vcdiff/base_file.bin", &base);
    }

    // -----------------------------------------------------------------------
    // Valid: delta — BSDIFF
    // -----------------------------------------------------------------------

    {
        let base = make_payload(DELTA_VECTOR_PAYLOAD_LEN);
        let target: Vec<u8> = make_payload(DELTA_VECTOR_PAYLOAD_LEN)
            .into_iter()
            .map(|b| b.wrapping_add(1))
            .collect();

        let base_hash = make_promoted_delta_base_hash();

        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: true,
                with_delta: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("bsdiff_target.bin", target);
        entry.delta = Some(DeltaWriteOptions {
            algorithm: PatchAlgoId::Bsdiff,
            base: base.clone(),
            delta_base_hash: base_hash,
        });
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();

        write_fixture("valid/delta/bsdiff/bsdiff_patch_entry.sar", &buf);
        write_fixture("valid/delta/bsdiff/base_file.bin", &base);
    }

    // -----------------------------------------------------------------------
    // Valid: filesystem metadata
    // -----------------------------------------------------------------------

    // Permissions
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_permissions: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("protected.txt", b"content".to_vec());
        entry.permissions = Some(0o644);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/permissions/permissions_entry.sar",
            &buf,
        );
    }

    // Owner (UID=1000, GID=1000)
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_uid_gid: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("owned.txt", b"content".to_vec());
        entry.uid_gid = Some((1000u32) | (1000u32 << 16));
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture("valid/filesystem-metadata/owner/owner_entry.sar", &buf);
    }

    // Timestamps (fixed deterministic values: Unix epoch + 1_700_000_000)
    {
        const FIXED_TIME: u64 = 1_700_000_000;
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_timestamps: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("timestamped.txt", b"content".to_vec());
        entry.timestamps = Some([FIXED_TIME, FIXED_TIME, FIXED_TIME]);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/timestamps/timestamps_entry.sar",
            &buf,
        );
    }

    // Symlink entry
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_symlinks: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("link_name", b"target_file.txt".to_vec());
        entry.kind = Some(EntryKind::Symlink);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture("valid/filesystem-metadata/symlink/symlink_entry.sar", &buf);
    }

    // Directory entry
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("subdir/", b"".to_vec());
        entry.kind = Some(EntryKind::Directory);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/directory/directory_entry.sar",
            &buf,
        );
    }

    // Combined: permissions + owner + timestamps
    {
        const FIXED_TIME: u64 = 1_700_000_000;
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_permissions: true,
                with_uid_gid: true,
                with_timestamps: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("full_meta.txt", b"content".to_vec());
        entry.permissions = Some(0o644);
        entry.uid_gid = Some((1000u32) | (1000u32 << 16));
        entry.timestamps = Some([FIXED_TIME, FIXED_TIME, FIXED_TIME]);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/combined/combined_meta_entry.sar",
            &buf,
        );
    }

    // Field presence: HAS_PATH set but zero-length path (PresentInactive)
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_path: true,
                ..Default::default()
            },
        )
        .unwrap();
        // path = None → PresentInactive (HAS_PATH set, zero-length path field)
        let entry = EntryInput::file("no_path_set.txt", b"content".to_vec());
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/field-presence-inactive/field_presence_inactive.sar",
            &buf,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: structure — truncated Global Header
    // -----------------------------------------------------------------------

    // Valid SAR magic + truncated before version field.
    let truncated_gh: Vec<u8> = b"SAR!".to_vec(); // magic only, no version/flags
    write_fixture(
        "invalid/structure/truncated-gh/truncated_global_header.sar",
        &truncated_gh,
    );

    // Truncated LFH: valid global header + partial LFH (missing name/payload).
    {
        let flags = GlobalFlags::NO_INDEX;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut truncated_lfh = write_global_header(&gh).unwrap();
        // LFH Header Size = 17 (marker), then truncate.
        truncated_lfh.extend_from_slice(&17u32.to_le_bytes());
        // Stop here: the LFH is incomplete.
        write_fixture(
            "invalid/structure/truncated-lfh/truncated_lfh.sar",
            &truncated_lfh,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: wrong magic bytes
    // -----------------------------------------------------------------------

    {
        let valid = write_store_archive(true, &[("x.txt", b"x")]);
        let mut bad_magic = valid.clone();
        bad_magic[0] = 0x00;
        bad_magic[1] = 0x00;
        bad_magic[2] = 0x00;
        bad_magic[3] = 0x00;
        write_fixture(
            "invalid/structure/invalid-magic/invalid_magic.sar",
            &bad_magic,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: unknown global flags
    // -----------------------------------------------------------------------

    {
        // Set the upper 16 bits of the flags to all-ones (reserved).
        let mut bad_flags = write_store_archive(true, &[("x.txt", b"x")]);
        // Flags are at offset: magic(4) + version(1) + padding(1) + flags_size(2) = offset 8.
        // flags_size is typically 4 bytes; flags are at bytes 8..12.
        // Set bytes 10 and 11 (upper 16 bits of 32-bit flags) to 0xFF.
        if bad_flags.len() > 12 {
            bad_flags[10] = 0xFF;
            bad_flags[11] = 0xFF;
        }
        write_fixture(
            "invalid/flags/unknown-global-flag/unknown_global_flag.sar",
            &bad_flags,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: unsupported compression algorithm
    // -----------------------------------------------------------------------

    {
        // Build a valid NO_INDEX archive then set an unsupported compression algo byte.
        // COMPRESSED flag must be set; entry mode IS_COMPRESSED must also be set;
        // compression algo ID set to 0xFE (custom/unsupported range).

        let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut archive = write_global_header(&gh).unwrap();

        let payload = b"compressed payload";
        let mut lfh =
            LocalFileHeader::minimal_store(b"compressed.bin".to_vec(), payload.len() as u64);
        // Set IS_COMPRESSED entry mode bit so the reader uses the compression path.
        lfh.entry_mode = sar_core::flags::EntryMode::from_bits(
            lfh.entry_mode.bits() | sar_core::flags::EntryMode::COMPRESSED,
        );
        lfh.comp_algo_id = Some(0xFE); // unsupported custom range

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(payload);

        write_fixture(
            "invalid/algorithms/unsupported-compression/unsupported_compression.sar",
            &archive,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: unsupported encryption algorithm
    // -----------------------------------------------------------------------

    {
        // Build a valid NO_INDEX encrypted archive structure with a KMS using
        // the correct minimum iterations, but set an unsupported encr_algo_id
        // in the LFH. The global header parses OK; the entry is rejected at
        // the encr_algo_id validation step with SAR_ERR_UNSUPPORTED.
        let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: Some(sar_core::format::KmsData {
                mode_id: 0x01, // PBKDF2
                payload: {
                    // Minimal KMS payload: PRF=1, salt_len=16, salt(16), iterations(4), dklen(2)
                    let mut p = vec![0x01u8, 0x10]; // PRF ID + salt_len
                    p.extend_from_slice(&[0xAAu8; 16]); // salt
                    p.extend_from_slice(&100_000u32.to_le_bytes()); // iterations >= 100,000
                    p.extend_from_slice(&32u16.to_le_bytes()); // dklen
                    p
                },
            }),
        };
        let mut archive = write_global_header(&gh).unwrap();

        let payload = b"encrypted payload";
        let mut lfh =
            LocalFileHeader::minimal_store(b"encrypted.bin".to_vec(), payload.len() as u64);
        // Set IS_ENCRYPTED entry mode so reader enters the encryption path.
        lfh.entry_mode = sar_core::flags::EntryMode::from_bits(
            lfh.entry_mode.bits() | sar_core::flags::EntryMode::ENCRYPTED,
        );
        lfh.encr_algo_id = Some(0xFE); // unsupported custom encryption algorithm

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(payload);

        write_fixture(
            "invalid/algorithms/unsupported-crypto/unsupported_crypto.sar",
            &archive,
        );
    }

    println!("\nGeneration complete.");
    println!("Run targeted M12a conformance tests to validate.");
}
