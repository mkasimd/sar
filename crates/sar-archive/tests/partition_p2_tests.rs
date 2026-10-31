// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `SAR-M13b3-PARTITION-P2-IMPLEMENTATION-001`: Partition Set assembly and
//! validation over physically inspected Partitions (spec §§19.1.3-19.1.14).
//! Members are built in memory; no test depends on file names or discovery.

use std::io::Cursor;

use sar_archive::{
    ArchiveReader, ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EncryptionSettings,
    EntryInput, PartitionManifestParams, ValidatedPartition, ValidatedPartitionSet,
};
use sar_core::{PARTITION_TOTAL_UNKNOWN, SarError};
use sar_crypto::{
    ENCR_AES256_GCM, KeyProvider, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params,
    SarCryptoError, SecretBytes, SecretString,
};
use sar_partition::{LinkStatus, PartitionSetLimits, PartitionSetMode, SetBoundary};

const SHA256: u8 = 0x30;
const UUID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

struct Pw;

impl KeyProvider for Pw {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(SecretString::new("pw".to_string())))
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

#[derive(Clone, Copy)]
struct Kms {
    prf: u8,
    salt: u8,
    iterations: u32,
}

const KMS_A: Kms = Kms {
    prf: PBKDF2_PRF_HMAC_SHA256,
    salt: 7,
    iterations: 100_000,
};

struct Member {
    index: u32,
    total: u32,
    fin: bool,
    prev: [u8; 32],
    uuid: [u8; 16],
    kms: Option<Kms>,
    tag: &'static str,
    crc: bool,
}

impl Member {
    fn new(index: u32, total: u32, fin: bool, prev: [u8; 32]) -> Self {
        Self {
            index,
            total,
            fin,
            prev,
            uuid: UUID,
            kms: None,
            tag: "x",
            crc: false,
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let enc = self.kms.map(|k| EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: k.prf,
                salt: vec![k.salt; 16],
                iterations: k.iterations,
                derived_key_length: 32,
            }),
        });
        let provider: Option<Box<dyn KeyProvider>> = self.kms.map(|_| Box::new(Pw) as _);
        let mut w = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut out),
            ArchiveWriterOptions {
                no_index: false,
                encryption: enc,
                ..Default::default()
            },
            CompressionSettings::store(),
            provider,
        )
        .expect("writer")
        .with_partition_manifest(PartitionManifestParams {
            partition_set_uuid: self.uuid,
            partition_index: self.index,
            total_partitions: self.total,
            final_partition: self.fin,
            hash_algorithm_id: SHA256,
            previous_partition_hash: self.prev,
        })
        .expect("partition");
        if self.crc {
            w = w.with_data_area_crc32().expect("crc");
        }
        w.add_entry(EntryInput::file("a.txt", self.tag.as_bytes().to_vec()))
            .expect("a");
        w.finish().expect("finish");
        out
    }
}

fn inspect(bytes: &[u8]) -> Result<ValidatedPartition, SarError> {
    ArchiveReader::new(Cursor::new(bytes.to_vec()))?
        .with_key_provider(Box::new(Pw))
        .inspect_partition()
}

/// Builds `n` linked plaintext members with the given declared total.
fn chain(n: u32, total: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..n {
        let fin = total != PARTITION_TOTAL_UNKNOWN && i + 1 == total;
        let bytes = Member::new(i, total, fin, prev).build();
        prev = inspect(&bytes)
            .expect("valid")
            .manifest()
            .current_partition_hash;
        out.push(bytes);
    }
    out
}

fn parts(members: &[&[u8]]) -> Vec<ValidatedPartition> {
    members.iter().map(|b| inspect(b).expect("valid")).collect()
}

fn validate(p: &[ValidatedPartition]) -> Result<ValidatedPartitionSet, SarError> {
    ValidatedPartitionSet::validate(
        p,
        &PartitionSetLimits::default(),
        PartitionSetMode::default(),
    )
}

fn validate_incomplete(p: &[ValidatedPartition]) -> Result<ValidatedPartitionSet, SarError> {
    ValidatedPartitionSet::validate(
        p,
        &PartitionSetLimits::default(),
        PartitionSetMode::AllowIncomplete,
    )
}

// ---------- membership ----------

#[test]
fn one_partition_complete_set() {
    let c = chain(1, 1);
    let set = validate(&parts(&[&c[0]])).expect("complete");
    assert!(set.is_complete());
    assert_eq!(set.assessment().boundary(), SetBoundary::Known(1));
    assert_eq!(set.members()[0].link(), LinkStatus::NotApplicable);
    assert!(!set.manifests_aead_authenticated());
}

#[test]
fn ordered_and_out_of_order_inputs_agree() {
    let c = chain(3, 3);
    let ordered = validate(&parts(&[&c[0], &c[1], &c[2]])).expect("ordered");
    let shuffled = validate(&parts(&[&c[2], &c[0], &c[1]])).expect("shuffled");
    assert!(ordered.is_complete() && shuffled.is_complete());
    let idx: Vec<u32> = shuffled
        .members()
        .iter()
        .map(|m| m.partition_index())
        .collect();
    assert_eq!(idx, [0, 1, 2]);
    assert_eq!(shuffled.members()[1].link(), LinkStatus::Verified);
    assert_eq!(shuffled.members()[2].link(), LinkStatus::Verified);
    assert!(shuffled.members().iter().all(|m| m.input_position() < 3));
}

#[test]
fn mismatching_uuid_is_partition_mismatch() {
    let c = chain(2, 2);
    let mut other = Member::new(1, 2, true, [0; 32]);
    other.uuid = [9; 16];
    let o = other.build();
    let err = validate(&parts(&[&c[0], &o])).expect_err("uuid");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

#[test]
fn missing_first_middle_and_final_members() {
    let c = chain(3, 3);
    for (present, missing) in [([1usize, 2], 0u32), ([0, 2], 1), ([0, 1], 2)] {
        let p = parts(&[&c[present[0]], &c[present[1]]]);
        let err = validate(&p).expect_err("missing");
        assert!(matches!(err, SarError::PartitionMissing(_)), "{err:?}");
        let inc = validate_incomplete(&p).expect("incomplete");
        assert!(!inc.is_complete());
        let r = inc.assessment().missing_ranges();
        assert_eq!((r[0].first, r[0].last), (missing, missing));
    }
}

#[test]
fn missing_predecessor_leaves_link_unverified_when_incomplete() {
    let c = chain(3, 3);
    let inc = validate_incomplete(&parts(&[&c[0], &c[2]])).expect("incomplete");
    assert_eq!(inc.members()[1].link(), LinkStatus::PredecessorUnavailable);
}

// ---------- totals and finality ----------

#[test]
fn unknown_total_without_finality_is_never_complete() {
    let c = chain(2, PARTITION_TOTAL_UNKNOWN);
    let p = parts(&[&c[0], &c[1]]);
    let err = validate(&p).expect_err("no boundary");
    assert!(matches!(err, SarError::PartitionMissing(_)), "{err:?}");
    let inc = validate_incomplete(&p).expect("prefix");
    assert!(!inc.is_complete());
    assert_eq!(inc.assessment().boundary(), SetBoundary::Unknown);
}

#[test]
fn unknown_to_known_transition_completes() {
    let a = Member::new(0, PARTITION_TOTAL_UNKNOWN, false, [0; 32]).build();
    let ha = inspect(&a).expect("a").manifest().current_partition_hash;
    let b = Member::new(1, 2, true, ha).build();
    let set = validate(&parts(&[&a, &b])).expect("complete");
    assert!(set.is_complete());
    assert_eq!(set.assessment().boundary(), SetBoundary::Known(2));
}

#[test]
fn conflicting_known_totals() {
    let a = Member::new(0, 3, false, [0; 32]).build();
    let ha = inspect(&a).expect("a").manifest().current_partition_hash;
    let b = Member::new(1, 2, true, ha).build();
    let err = validate(&parts(&[&a, &b])).expect_err("totals");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

#[test]
fn index_beyond_established_total() {
    let a = Member::new(0, 2, false, [0; 32]).build();
    let ha = inspect(&a).expect("a").manifest().current_partition_hash;
    let b = Member::new(2, PARTITION_TOTAL_UNKNOWN, false, ha).build();
    let err = validate(&parts(&[&a, &b])).expect_err("outside");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

// ---------- hash linkage ----------

#[test]
fn incorrect_predecessor_hash_with_valid_current_hashes() {
    let a = Member::new(0, 2, false, [0; 32]).build();
    let b = Member::new(1, 2, true, [0xEE; 32]).build();
    let p = parts(&[&a, &b]);
    let err = validate(&p).expect_err("link");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

// ---------- replicas ----------

#[test]
fn equivalent_duplicates_are_deduplicated() {
    let c = chain(2, 2);
    let set = validate(&parts(&[&c[1], &c[0], &c[0], &c[1]])).expect("complete");
    assert!(set.is_complete());
    assert_eq!(set.assessment().duplicates_discarded(), 2);
    assert_eq!(set.members().len(), 2);
    assert_eq!(set.members()[0].replica_count(), 2);
    assert_eq!(set.members()[0].input_position(), 1);
}

#[test]
fn conflicting_duplicates_are_rejected() {
    let mut m = Member::new(0, 1, true, [0; 32]);
    let a = m.build();
    m.tag = "different content";
    let b = m.build();
    let err = validate(&parts(&[&a, &b])).expect_err("conflict");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

#[test]
fn failed_candidates_never_conflict_and_are_counted() {
    let c = chain(1, 1);
    let mut broken = c[0].clone();
    broken.truncate(broken.len() - 5);
    let results = vec![inspect(&broken), inspect(&c[0])];
    let set = ValidatedPartitionSet::from_inspection_results(
        results,
        &PartitionSetLimits::default(),
        PartitionSetMode::RequireComplete,
    )
    .expect("complete");
    assert_eq!(set.rejected_candidates(), 1);
    assert!(set.is_complete());
}

// ---------- header and KMS ----------

fn encrypted_member(kms: Kms, index: u32, total: u32, fin: bool, prev: [u8; 32]) -> Vec<u8> {
    let mut m = Member::new(index, total, fin, prev);
    m.kms = Some(kms);
    m.build()
}

#[test]
fn encrypted_set_with_differing_salts_is_consistent_and_authenticated() {
    let a = encrypted_member(KMS_A, 0, 2, false, [0; 32]);
    let ha = inspect(&a).expect("a").manifest().current_partition_hash;
    let b = encrypted_member(Kms { salt: 9, ..KMS_A }, 1, 2, true, ha);
    let set = validate(&parts(&[&b, &a])).expect("complete");
    assert!(set.is_complete());
    assert!(set.manifests_aead_authenticated());
}

#[test]
fn encrypted_versus_plaintext_set_mismatch() {
    let a = Member::new(0, 2, false, [0; 32]).build();
    let ha = inspect(&a).expect("a").manifest().current_partition_hash;
    let b = encrypted_member(KMS_A, 1, 2, true, ha);
    let err = validate(&parts(&[&a, &b])).expect_err("mixed");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

#[test]
fn global_flag_difference_is_rejected() {
    let a = Member::new(0, 2, false, [0; 32]).build();
    let ha = inspect(&a).expect("a").manifest().current_partition_hash;
    let mut b = Member::new(1, 2, true, ha);
    b.crc = true;
    let b = b.build();
    let err = validate(&parts(&[&a, &b])).expect_err("flags");
    assert!(matches!(err, SarError::PartitionMismatch(_)), "{err:?}");
}

// ---------- limits and trust ----------

#[test]
fn candidate_duplicate_and_aggregate_limits() {
    let c = chain(2, 2);
    let p = parts(&[&c[0], &c[1], &c[1]]);
    let mode = PartitionSetMode::default();
    let e = ValidatedPartitionSet::validate(
        &p,
        &PartitionSetLimits::default().with_max_candidates(2),
        mode,
    )
    .expect_err("candidates");
    assert!(matches!(e, SarError::LimitExceeded(_)), "{e:?}");
    let e = ValidatedPartitionSet::validate(
        &p,
        &PartitionSetLimits::default().with_max_duplicate_candidates(0),
        mode,
    )
    .expect_err("duplicates");
    assert!(matches!(e, SarError::LimitExceeded(_)), "{e:?}");
    let e = ValidatedPartitionSet::validate(
        &p,
        &PartitionSetLimits::default().with_max_aggregate_encoded_bytes(10),
        mode,
    )
    .expect_err("aggregate");
    assert!(matches!(e, SarError::LimitExceeded(_)), "{e:?}");
    let e = ValidatedPartitionSet::validate(
        &p,
        &PartitionSetLimits::default().with_max_relationship_steps(1),
        mode,
    )
    .expect_err("steps");
    assert!(matches!(e, SarError::LimitExceeded(_)), "{e:?}");
}

#[test]
fn claimed_total_above_limit_is_rejected_without_allocation_by_total() {
    let bytes = Member::new(0, 60_000, false, [0; 32]).build();
    let p = parts(&[&bytes]);
    let e = ValidatedPartitionSet::validate(
        &p,
        &PartitionSetLimits::default().with_max_partitions(100),
        PartitionSetMode::AllowIncomplete,
    )
    .expect_err("limit");
    assert!(matches!(e, SarError::LimitExceeded(_)), "{e:?}");
    // A huge claimed total is reported as one missing range, not enumerated.
    let inc = validate_incomplete(&p).expect("incomplete");
    assert_eq!(inc.assessment().missing_ranges().len(), 1);
    assert!(!inc.is_complete());
}
