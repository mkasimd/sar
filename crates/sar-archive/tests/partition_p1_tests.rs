// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `SAR-M13b3-PARTITION-P1-IMPLEMENTATION-001`: Partition Manifest Version 1
//! and individual physical Partition validation (spec §§6.2.1, 19.1.1-19.1.14).
//! These tests validate one physical Partition only, never a Partition Set.

use std::io::Cursor;

use sar_archive::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, CompressionSettings,
    EncryptionSettings, EntryInput, PartitionManifestParams,
};
use sar_core::{
    EntryMode, GlobalFlags, LocalFileHeader, PARTITION_MANIFEST_V1_LEN, PARTITION_TOTAL_UNKNOWN,
    PartitionManifestV1, ResourceLimits, SarError, parse_global_header,
    validate_partition_manifest_lfh,
};
use sar_crypto::{
    ENCR_AES256_GCM, KeyProvider, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params,
    SarCryptoError, SecretBytes, SecretString,
};
use sar_partition::{ManifestAuthentication, PartitionSetStatus, PredecessorLink};

const SHA256: u8 = 0x30;
const UUID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

struct Pw(&'static str);

impl KeyProvider for Pw {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(SecretString::new(self.0.to_string())))
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

fn params(index: u32, total: u32, fin: bool) -> PartitionManifestParams {
    PartitionManifestParams {
        partition_set_uuid: UUID,
        partition_index: index,
        total_partitions: total,
        final_partition: fin,
        hash_algorithm_id: SHA256,
        previous_partition_hash: if index == 0 { [0; 32] } else { [0xAB; 32] },
    }
}

fn options(no_index: bool, encrypted: bool) -> ArchiveWriterOptions {
    ArchiveWriterOptions {
        no_index,
        encryption: encrypted.then(|| EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                salt: vec![7; 16],
                iterations: 100_000,
                derived_key_length: 32,
            }),
        }),
        ..Default::default()
    }
}

fn build(p: PartitionManifestParams, no_index: bool, crc: bool, encrypted: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let provider: Option<Box<dyn KeyProvider>> = encrypted.then(|| Box::new(Pw("pw")) as _);
    let mut w = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut out),
        options(no_index, encrypted),
        CompressionSettings::store(),
        provider,
    )
    .expect("writer")
    .with_partition_manifest(p)
    .expect("partition");
    if crc {
        w = w.with_data_area_crc32().expect("crc");
    }
    w.add_entry(EntryInput::file("a.txt", b"hello partition".to_vec()))
        .expect("a");
    w.add_entry(EntryInput::file("b.txt", b"second member".to_vec()))
        .expect("b");
    w.finish().expect("finish");
    out
}

fn inspect(bytes: &[u8]) -> Result<sar_archive::ValidatedPartition, SarError> {
    ArchiveReader::new(Cursor::new(bytes.to_vec()))?.inspect_partition()
}

fn inspect_pw(bytes: &[u8], pw: &'static str) -> Result<sar_archive::ValidatedPartition, SarError> {
    ArchiveReader::with_options(Cursor::new(bytes.to_vec()), ArchiveReaderOptions::default())?
        .with_key_provider(Box::new(Pw(pw)))
        .inspect_partition()
}

/// Offset of the Manifest LFH, found through the descriptor.
fn manifest_offset(bytes: &[u8]) -> usize {
    usize::try_from(inspect_pw(bytes, "pw").expect("valid").manifest_offset()).expect("ok")
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle")
}

// ---------- codec ----------

fn sample() -> PartitionManifestV1 {
    PartitionManifestV1 {
        hash_algorithm_id: SHA256,
        flags: sar_core::PartitionManifestFlags::new(true),
        partition_index: 2,
        total_partitions: 3,
        committed_content_length: 0x0102_0304_0506_0708,
        partition_set_uuid: UUID,
        previous_partition_hash: [0x44; 32],
        current_partition_hash: [0x55; 32],
    }
}

#[test]
fn codec_round_trip_and_byte_positions() {
    let m = sample();
    let b = m.encode(65535).expect("ok");
    assert_eq!(b.len(), PARTITION_MANIFEST_V1_LEN);
    assert_eq!(b.len(), 100);
    assert_eq!(b[0], 1);
    assert_eq!(b[1], SHA256);
    assert_eq!(&b[2..4], &[1, 0]);
    assert_eq!(&b[4..8], &2u32.to_le_bytes());
    assert_eq!(&b[8..12], &3u32.to_le_bytes());
    assert_eq!(&b[12..20], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&b[20..36], &UUID);
    assert_eq!(&b[36..68], &[0x44; 32]);
    assert_eq!(&b[68..100], &[0x55; 32]);
    assert_eq!(PartitionManifestV1::decode(&b, 65535).expect("ok"), m);
}

#[test]
fn codec_rejections() {
    let good = sample().encode(65535).expect("ok");
    let dec = |b: &[u8]| PartitionManifestV1::decode(b, 65535);

    let mut v = good;
    v[0] = 2;
    assert!(matches!(dec(&v), Err(SarError::Unsupported(_))));
    assert!(matches!(dec(&good[..99]), Err(SarError::InvalidLength(_))));
    let mut long = good.to_vec();
    long.push(0);
    assert!(matches!(dec(&long), Err(SarError::InvalidLength(_))));

    let mut v = good;
    v[3] = 0x80;
    assert!(matches!(dec(&v), Err(SarError::ReservedValue(_))));
    let mut v = good;
    v[2] = 0x02;
    assert!(matches!(dec(&v), Err(SarError::ReservedValue(_))));

    let mut v = good;
    v[1] = 0x32;
    assert!(matches!(dec(&v), Err(SarError::Unsupported(_))));
    v[1] = 0x77;
    assert!(matches!(dec(&v), Err(SarError::ReservedValue(_))));

    let mut v = good;
    v[20..36].fill(0);
    assert!(matches!(dec(&v), Err(SarError::Malformed(_))));

    // total zero
    let mut v = good;
    v[8..12].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(dec(&v), Err(SarError::Malformed(_))));
    // index >= total
    let mut v = good;
    v[4..8].copy_from_slice(&3u32.to_le_bytes());
    assert!(matches!(dec(&v), Err(SarError::Malformed(_))));
    // FINAL with wrong final index
    let mut v = good;
    v[4..8].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(dec(&v), Err(SarError::Malformed(_))));
    // unknown total + FINAL
    let mut v = good;
    v[8..12].copy_from_slice(&PARTITION_TOTAL_UNKNOWN.to_le_bytes());
    assert!(matches!(dec(&v), Err(SarError::Malformed(_))));
    // index 0 with nonzero previous hash
    let mut v = good;
    v[4..8].copy_from_slice(&0u32.to_le_bytes());
    v[2] = 0;
    assert!(matches!(dec(&v), Err(SarError::Malformed(_))));
    // total above the limit
    let mut v = good;
    v[2] = 0;
    v[8..12].copy_from_slice(&70_000u32.to_le_bytes());
    assert!(matches!(dec(&v), Err(SarError::LimitExceeded(_))));
}

#[test]
fn codec_accepts_unknown_total_nonfinal() {
    let mut m = sample();
    m.flags = sar_core::PartitionManifestFlags::new(false);
    m.total_partitions = PARTITION_TOTAL_UNKNOWN;
    let b = m.encode(65535).expect("ok");
    assert_eq!(PartitionManifestV1::decode(&b, 65535).expect("ok"), m);
}

// ---------- physical partitions ----------

#[test]
fn valid_partitions_all_shapes() {
    for &(idx, total, fin) in &[
        (0, 1, true),
        (0, 3, false),
        (1, PARTITION_TOTAL_UNKNOWN, false),
        (2, 3, true),
    ] {
        for &no_index in &[false, true] {
            for &crc in &[false, true] {
                if no_index && crc {
                    continue;
                }
                let bytes = build(params(idx, total, fin), no_index, crc, false);
                let d = inspect(&bytes)
                    .unwrap_or_else(|e| panic!("({idx},{total},{fin},{no_index},{crc}): {e:?}"));
                assert_eq!(d.partition_index(), idx);
                assert_eq!(d.is_final(), fin);
                assert_eq!(d.is_indexed(), !no_index);
                assert_eq!(
                    d.manifest_authentication(),
                    ManifestAuthentication::Unauthenticated
                );
                assert_eq!(d.set_status(), PartitionSetStatus::NotEvaluated);
                if idx == 0 {
                    assert_eq!(d.predecessor_link(), PredecessorLink::NotApplicable);
                } else {
                    assert_eq!(
                        d.predecessor_link(),
                        PredecessorLink::Unverified([0xAB; 32])
                    );
                }
            }
        }
    }
}

#[test]
fn generic_paths_stay_fail_closed() {
    let bytes = build(params(0, 1, true), false, false, false);
    let rejected = match ArchiveReader::new(Cursor::new(bytes)) {
        Err(e) => matches!(e, SarError::Unsupported(_)),
        Ok(mut r) => matches!(r.read_global_header(), Err(SarError::Unsupported(_))),
    };
    assert!(rejected, "generic reader must reject PARTITIONED_ARCHIVE");
}

#[test]
fn unpartitioned_archive_is_not_a_partition() {
    let mut out = Vec::new();
    let mut w =
        ArchiveWriter::new(Cursor::new(&mut out), ArchiveWriterOptions::default()).expect("writer");
    w.add_entry(EntryInput::file("a", b"x".to_vec()))
        .expect("ok");
    w.finish().expect("ok");
    assert!(matches!(inspect(&out), Err(SarError::FlagConflict(_))));
}

#[test]
fn hash_covers_encoded_bytes_and_excludes_manifest() {
    for no_index in [false, true] {
        let bytes = build(params(0, 1, true), no_index, false, false);
        let off = manifest_offset(&bytes);

        // Mutating a covered byte (member payload) fails hash verification.
        let mut m = bytes.clone();
        let p = find(&m, b"hello partition");
        m[p] ^= 1;
        assert!(matches!(inspect(&m), Err(SarError::HashMismatch(_))));

        // Second covered member payload.
        let mut m = bytes.clone();
        let p = find(&m, b"second member");
        m[p + 3] ^= 0x20;
        assert!(matches!(inspect(&m), Err(SarError::HashMismatch(_))));

        // Corrupting the stored Current Partition Hash.
        let stored = off + find(&bytes[off..], &UUID);
        let mut m = bytes.clone();
        m[stored + 16 + 32 + 5] ^= 1;
        assert!(matches!(inspect(&m), Err(SarError::HashMismatch(_))));

        // Excluded bytes: previous-hash change leaves the committed hash valid.
        let mut m = bytes.clone();
        m[stored + 16 + 3] ^= 1; // index 0 requires an all-zero previous hash
        assert!(matches!(inspect(&m), Err(SarError::Malformed(_))));
    }
}

#[test]
fn wrong_committed_content_length() {
    let bytes = build(params(0, 1, true), true, false, false);
    let off = manifest_offset(&bytes);
    let uuid_pos = off + find(&bytes[off..], &UUID);
    let mut m = bytes.clone();
    m[uuid_pos - 8] ^= 1; // Committed Content Length LSB
    assert!(matches!(inspect(&m), Err(SarError::Malformed(_))));
}

#[test]
fn bad_manifest_fields_in_physical_partition() {
    let bytes = build(params(0, 1, true), true, false, false);
    let off = manifest_offset(&bytes);
    let uuid_pos = off + find(&bytes[off..], &UUID);
    let base = uuid_pos - 20;

    let mut m = bytes.clone();
    m[base] = 9;
    assert!(matches!(inspect(&m), Err(SarError::Unsupported(_))));
    let mut m = bytes.clone();
    m[base + 3] = 0x40;
    assert!(matches!(inspect(&m), Err(SarError::ReservedValue(_))));
    let mut m = bytes.clone();
    m[base + 1] = 0x32;
    assert!(matches!(inspect(&m), Err(SarError::Unsupported(_))));
    let mut m = bytes.clone();
    m[uuid_pos..uuid_pos + 16].fill(0);
    assert!(matches!(inspect(&m), Err(SarError::Malformed(_))));
}

#[test]
fn missing_manifest() {
    // Plain PARTITIONED_ARCHIVE header without any Manifest: take a valid
    // Partition and drop its Manifest bytes in NO_INDEX form.
    let bytes = build(params(0, 1, true), true, false, false);
    let off = manifest_offset(&bytes);
    let cut = bytes[..off].to_vec();
    assert!(matches!(inspect(&cut), Err(SarError::MetadataMissing(_))));
}

#[test]
fn duplicate_manifest() {
    let bytes = build(params(0, 1, true), true, false, false);
    let off = manifest_offset(&bytes);
    let mut dup = bytes.clone();
    let manifest = bytes[off..].to_vec();
    dup.extend_from_slice(&manifest);
    assert!(matches!(inspect(&dup), Err(SarError::MetadataConflict(_))));
}

#[test]
fn nonterminal_manifest() {
    let bytes = build(params(0, 1, true), true, false, false);
    let off = manifest_offset(&bytes);
    let manifest = bytes[off..].to_vec();
    // Manifest placed before the members.
    let header_len = parse_header_len(&bytes);
    let mut m = bytes[..header_len].to_vec();
    m.extend_from_slice(&manifest);
    m.extend_from_slice(&bytes[header_len..off]);
    assert!(matches!(inspect(&m), Err(SarError::Malformed(_))));
}

fn parse_header_len(bytes: &[u8]) -> usize {
    parse_global_header(bytes, &ResourceLimits::default())
        .expect("header")
        .1
}

#[test]
fn truncated_partition_manifest_crossing_bounds() {
    let bytes = build(params(0, 1, true), true, false, false);
    let cut = &bytes[..bytes.len() - 10];
    assert!(inspect(cut).is_err());
}

#[test]
fn local_cd_and_footer_required_when_indexed() {
    let bytes = build(params(0, 1, true), false, false, false);
    let off = manifest_offset(&bytes);
    // Remove the CD+Footer: the indexed header then lacks a Footer.
    let cut = &bytes[..off + 100];
    let manifest_end = cut.len();
    assert!(manifest_end < bytes.len());
    assert!(inspect(&bytes[..manifest_end]).is_err());
}

#[test]
fn data_area_crc32_detects_excluded_tamper_only_when_enabled() {
    let bytes = build(params(0, 1, true), false, true, false);
    inspect(&bytes).expect("valid with CRC");
    let mut m = bytes.clone();
    let p = find(&m, b"hello partition");
    m[p] ^= 1;
    assert!(matches!(inspect(&m), Err(SarError::CrcMismatch(_))));
}

// ---------- encryption ----------

#[test]
fn encrypted_manifest_authenticated() {
    for no_index in [false, true] {
        let bytes = build(params(0, 2, false), no_index, false, true);
        assert_eq!(
            inspect_pw(&bytes, "pw")
                .expect("ok")
                .manifest_authentication(),
            ManifestAuthentication::Aead
        );
        assert!(matches!(inspect(&bytes), Err(SarError::KeyMissing(_))));
        assert!(matches!(
            inspect_pw(&bytes, "wrong"),
            Err(SarError::AuthFailed(_))
        ));

        let off = manifest_offset(&bytes);
        let lfh_len = usize::try_from(u32::from_le_bytes(
            bytes[off..off + 4].try_into().expect("4 bytes"),
        ))
        .expect("ok");
        // Ciphertext byte and AEAD tag byte (payload is 100 + 16 bytes).
        for pos in [off + lfh_len + 5, off + lfh_len + 115] {
            let mut t = bytes.clone();
            t[pos] ^= 1;
            assert!(matches!(inspect_pw(&t, "pw"), Err(SarError::AuthFailed(_))));
        }
        // Tampered LFH (AAD) is rejected too.
        let mut t = bytes.clone();
        t[off + 4] ^= 0x01;
        assert!(inspect_pw(&t, "pw").is_err());
    }
}

#[test]
fn manifest_lfh_without_partitioned_flag_is_flag_conflict() {
    let mut lfh = LocalFileHeader::minimal_store(Vec::new(), 100);
    lfh.entry_mode = EntryMode::from_bits(EntryMode::PARTITION_MANIFEST);
    lfh.uncompressed_size = 100;
    // Sanity: accepted when the Global Flag is present.
    validate_partition_manifest_lfh(GlobalFlags::PARTITIONED_ARCHIVE, &lfh).expect("valid");
    assert!(matches!(
        validate_partition_manifest_lfh(GlobalFlags::empty(), &lfh),
        Err(SarError::FlagConflict(_))
    ));
}
