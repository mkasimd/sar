// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `SAR-M13b3-PARTITION-P3-IMPLEMENTATION-001`: multi-Partition writer.
//! Every generated member is re-inspected with the P1 validator and the whole
//! Set is assessed by the P2 validator; writer summaries are only compared
//! against that independent result.

use std::io::{self, Cursor, Write};

use sar_archive::{
    ArchiveReader, ArchiveWriterOptions, CompressionSettings, EncryptionSettings, EntryInput,
    PartitionMemberSummary, PartitionSetWriter, PartitionSetWriterLimits,
    PartitionSetWriterOptions, ValidatedPartition, ValidatedPartitionSet,
};
use sar_core::{PARTITION_TOTAL_UNKNOWN, SarError};
use sar_crypto::hash::new_hasher;
use sar_crypto::{ENCR_AES256_GCM, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params};
use sar_partition::{LinkStatus, PartitionSetLimits, PartitionSetMode, SetBoundary};

const UUID: [u8; 16] = [0x42; 16];

fn opts() -> PartitionSetWriterOptions {
    PartitionSetWriterOptions {
        partition_set_uuid: Some(UUID),
        ..Default::default()
    }
}

fn inspect(bytes: &[u8]) -> Result<ValidatedPartition, SarError> {
    ArchiveReader::new(Cursor::new(bytes.to_vec()))?.inspect_partition()
}

fn validate(bytes: &[&Vec<u8>]) -> Result<ValidatedPartitionSet, SarError> {
    let parts: Vec<ValidatedPartition> = bytes.iter().map(|b| inspect(b).expect("valid")).collect();
    ValidatedPartitionSet::validate(
        &parts,
        &PartitionSetLimits::default(),
        PartitionSetMode::default(),
    )
}

/// Writes one member per entry group; the last is finalized as final.
fn build(
    options: PartitionSetWriterOptions,
    groups: &[&[(&str, &str)]],
) -> (Vec<Vec<u8>>, Vec<PartitionMemberSummary>) {
    let mut set = PartitionSetWriter::new(options).expect("set");
    let mut members = Vec::new();
    let mut sums = Vec::new();
    for (i, group) in groups.iter().enumerate() {
        let mut buf = Vec::new();
        {
            let mut p = set.begin_partition(&mut buf, None).expect("begin");
            for (name, data) in *group {
                p.add_entry(EntryInput::file(*name, data.as_bytes().to_vec()))
                    .expect("entry");
            }
            let s = if i + 1 == groups.len() {
                p.finish_final()
            } else {
                p.finish()
            };
            sums.push(s.expect("finish"));
        }
        members.push(buf);
    }
    let done = set.finish_set().expect("set complete");
    assert_eq!(
        done.total_partitions,
        u32::try_from(groups.len()).expect("ok")
    );
    assert_eq!(
        done.aggregate_bytes,
        members.iter().map(|m| m.len() as u64).sum::<u64>()
    );
    (members, sums)
}

/// Asserts the independent P1/P2 view agrees with the writer's claims.
fn assert_conforms(members: &[Vec<u8>], sums: &[PartitionMemberSummary], total_known: bool) {
    let n = members.len();
    let mut prev = [0u8; 32];
    for (i, (bytes, sum)) in members.iter().zip(sums).enumerate() {
        let v = inspect(bytes).expect("P1 accepts member");
        let m = v.manifest();
        assert_eq!(m.partition_set_uuid, UUID);
        assert_eq!(m.partition_index as usize, i);
        assert_eq!(m.partition_index, sum.partition_index);
        assert_eq!(v.is_final(), i + 1 == n);
        assert_eq!(
            m.total_partitions,
            if i + 1 == n || total_known {
                u32::try_from(n).expect("ok")
            } else {
                PARTITION_TOTAL_UNKNOWN
            }
        );
        assert_eq!(m.previous_partition_hash, prev);
        assert_eq!(m.previous_partition_hash, sum.previous_partition_hash);
        assert_eq!(m.committed_content_length, v.manifest_offset());
        assert_eq!(sum.committed_content_length, v.manifest_offset());
        assert_eq!(v.partition_len(), bytes.len() as u64);
        // Current hash covers exactly the physical prefix before the Manifest LFH.
        let mut h = new_hasher(0x30).expect("ok");
        h.update(&bytes[..usize::try_from(v.manifest_offset()).expect("ok")]);
        assert_eq!(h.finalize().as_slice(), m.current_partition_hash);
        assert_eq!(m.current_partition_hash, sum.current_partition_hash);
        prev = m.current_partition_hash;
        if v.is_indexed() {
            let cd_off = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().expect("ok"));
            assert!(cd_off > v.manifest_offset() && cd_off < bytes.len() as u64);
        }
    }
    let refs: Vec<&Vec<u8>> = members.iter().rev().collect();
    let set = validate(&refs).expect("P2 accepts the Set in any order");
    assert!(set.is_complete());
    assert_eq!(
        set.assessment().boundary(),
        SetBoundary::Known(u32::try_from(n).expect("ok"))
    );
    for (i, m) in set.members().iter().enumerate() {
        assert_eq!(m.partition_index() as usize, i);
        if i > 0 {
            assert_eq!(m.link(), LinkStatus::Verified);
        }
    }
}

#[test]
fn single_partition_set() {
    let (m, s) = build(opts(), &[&[("a", "alpha")]]);
    assert_eq!(s[0].total_partitions, 1);
    assert!(s[0].is_final && s[0].indexed);
    assert_eq!(s[0].previous_partition_hash, [0; 32]);
    assert_conforms(&m, &s, false);
}

#[test]
fn unknown_total_three_partitions() {
    let (m, s) = build(
        opts(),
        &[&[("a", "1")], &[("b", "2"), ("c", "3")], &[("d", "4")]],
    );
    assert_eq!(s[0].total_partitions, PARTITION_TOTAL_UNKNOWN);
    assert_eq!(s[1].total_partitions, PARTITION_TOTAL_UNKNOWN);
    assert_eq!(s[2].total_partitions, 3);
    assert_eq!(s[1].entry_count, 2);
    assert_conforms(&m, &s, false);
}

#[test]
fn known_total_two_and_four_partitions() {
    for n in [2u32, 4] {
        let mut o = opts();
        o.known_total = Some(n);
        let groups: Vec<&[(&str, &str)]> = (0..n).map(|_| &[("f", "x")][..]).collect();
        let (m, s) = build(o, &groups);
        assert!(s.iter().all(|x| x.total_partitions == n));
        assert_conforms(&m, &s, true);
    }
}

#[test]
fn empty_member_and_payload_preserved() {
    let (m, s) = build(opts(), &[&[], &[("big", "payload-bytes")]]);
    assert_eq!(s[0].entry_count, 0);
    assert_conforms(&m, &s, false);
    let hay = &m[1];
    assert!(hay.windows(13).any(|w| w == b"payload-bytes"));
    assert!(!m[0].windows(13).any(|w| w == b"payload-bytes"));
}

#[test]
fn no_index_members() {
    let mut o = opts();
    o.archive.no_index = true;
    let (m, s) = build(o, &[&[("a", "1")], &[("b", "2")]]);
    assert!(s.iter().all(|x| !x.indexed));
    for (b, x) in m.iter().zip(&s) {
        let v = inspect(b).expect("ok");
        assert!(!v.is_indexed());
        // The Manifest is the final structure: nothing follows it.
        assert_eq!(v.partition_len(), x.partition_len);
    }
    assert_conforms(&m, &s, false);
}

#[test]
fn data_area_crc32_indexed_members() {
    let mut o = opts();
    o.data_area_crc32 = true;
    let (m, s) = build(o, &[&[("a", "1")], &[("b", "2")]]);
    assert_conforms(&m, &s, false);
    // Corrupting a payload byte covered by the Data Area CRC32 is detected.
    let mut bad = m[0].clone();
    let pos = bad.windows(1).position(|w| w == b"1").expect("ok");
    bad[pos] = b'9';
    assert!(inspect(&bad).is_err());
}

#[test]
fn empty_area_is_not_indexed() {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("ok");
    p.add_entry(EntryInput::file("a", b"x".to_vec()))
        .expect("ok");
    p.add_entry(EntryInput::file("", Vec::new())).expect("ok");
    let sum = p.finish_final().expect("ok");
    assert_eq!(sum.entry_count, 2);
    let v = inspect(&buf).expect("valid");
    assert!(v.is_final());
}

// ---------- configuration ----------

#[test]
fn rejects_bad_configuration() {
    let mut o = opts();
    o.partition_set_uuid = Some([0; 16]);
    assert!(matches!(
        PartitionSetWriter::new(o),
        Err(SarError::Malformed(_))
    ));

    let mut o = opts();
    o.data_area_crc32 = true;
    o.archive.no_index = true;
    assert!(matches!(
        PartitionSetWriter::new(o),
        Err(SarError::FlagConflict(_))
    ));

    let mut o = opts();
    o.archive = ArchiveWriterOptions {
        encryption: Some(EncryptionSettings {
            algo_id: ENCR_AES256_GCM,
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                salt: vec![1; 16],
                iterations: 100_000,
                derived_key_length: 32,
            }),
        }),
        ..Default::default()
    };
    assert!(matches!(
        PartitionSetWriter::new(o),
        Err(SarError::Unsupported(_))
    ));

    let mut o = opts();
    o.known_total = Some(0);
    assert!(matches!(
        PartitionSetWriter::new(o),
        Err(SarError::Malformed(_))
    ));
    let mut o = opts();
    o.hash_algorithm_id = 0x32;
    assert!(PartitionSetWriter::new(o).is_err());
}

#[test]
fn random_uuid_is_nonzero_and_shared() {
    let mut o = opts();
    o.partition_set_uuid = None;
    let mut set = PartitionSetWriter::new(o).expect("ok");
    let uuid = set.partition_set_uuid();
    assert_ne!(uuid, [0; 16]);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish()
        .expect("ok");
    set.begin_partition(&mut b, None)
        .expect("ok")
        .finish_final()
        .expect("ok");
    for bytes in [&a, &b] {
        assert_eq!(
            inspect(bytes).expect("ok").manifest().partition_set_uuid,
            uuid
        );
    }
}

// ---------- state machine ----------

#[test]
fn declared_total_enforced() {
    let mut o = opts();
    o.known_total = Some(2);
    let mut set = PartitionSetWriter::new(o.clone()).expect("ok");
    let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish()
        .expect("ok");
    set.begin_partition(&mut b, None)
        .expect("ok")
        .finish_final()
        .expect("ok");
    assert!(matches!(
        set.begin_partition(&mut c, None),
        Err(SarError::Malformed(_))
    ));
    set.finish_set().expect("ok");

    // Declared total exceeded before the final member is written.
    let mut set = PartitionSetWriter::new(o.clone()).expect("ok");
    let mut a = Vec::new();
    let r = set
        .begin_partition(&mut a, None)
        .expect("ok")
        .finish_final();
    assert!(matches!(r, Err(SarError::PartitionMismatch(_))));
    assert!(set.finish_set().is_err());

    // Last declared member cannot be nonfinal.
    let mut set = PartitionSetWriter::new(o).expect("ok");
    let (mut a, mut b) = (Vec::new(), Vec::new());
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish()
        .expect("ok");
    let r = set.begin_partition(&mut b, None).expect("ok").finish();
    assert!(matches!(r, Err(SarError::PartitionMismatch(_))));
    assert!(set.finish_set().is_err());
}

#[test]
fn premature_completion_and_use_after_final() {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish()
        .expect("ok");
    assert!(matches!(
        set.finish_set(),
        Err(SarError::PartitionMissing(_))
    ));

    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish_final()
        .expect("ok");
    let mut b = Vec::new();
    assert!(set.begin_partition(&mut b, None).is_err());
    assert!(b.is_empty());
    set.finish_set().expect("ok");
}

#[test]
fn dropped_member_fails_the_set() {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    {
        let mut p = set.begin_partition(&mut a, None).expect("ok");
        p.add_entry(EntryInput::file("a", b"x".to_vec()))
            .expect("ok");
    }
    let mut b = Vec::new();
    assert!(set.begin_partition(&mut b, None).is_err());
    assert!(set.finish_set().is_err());
    // The abandoned member is not a valid Partition.
    assert!(inspect(&a).is_err());
}

#[test]
fn nonfinal_members_alone_are_incomplete() {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let (mut a, mut b) = (Vec::new(), Vec::new());
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish()
        .expect("ok");
    set.begin_partition(&mut b, None)
        .expect("ok")
        .finish()
        .expect("ok");
    drop(set);
    let err = validate(&[&a, &b]).err();
    assert!(err.is_some(), "no final member: not a complete Set");
}

// ---------- capacity and limits ----------

fn one_entry_member_len() -> u64 {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    let mut p = set.begin_partition(&mut a, None).expect("ok");
    p.add_entry(EntryInput::file("a", vec![7u8; 100]))
        .expect("ok");
    p.finish_final().expect("ok").partition_len
}

#[test]
fn capacity_is_exact_upper_bound() {
    let exact = one_entry_member_len();
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    let mut p = set.begin_partition(&mut a, Some(exact)).expect("ok");
    p.add_entry(EntryInput::file("a", vec![7u8; 100]))
        .expect("ok");
    assert_eq!(p.finish_final().expect("ok").partition_len, exact);

    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    let mut p = set.begin_partition(&mut a, Some(exact - 1)).expect("ok");
    let r = p.add_entry(EntryInput::file("a", vec![7u8; 100]));
    assert!(matches!(r, Err(SarError::LimitExceeded(_))));
    // Refusal published nothing; the member is still a valid empty Partition.
    let sum = p.finish_final().expect("ok");
    assert_eq!(sum.entry_count, 0);
    assert!(sum.partition_len < exact);
    assert_eq!(a.len() as u64, sum.partition_len);
    inspect(&a).expect("valid after refusal");
}

#[test]
fn refused_entry_moves_to_next_partition_without_splitting() {
    let exact = one_entry_member_len();
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let mut p = set.begin_partition(&mut a, Some(exact)).expect("ok");
    p.add_entry(EntryInput::file("a", vec![7u8; 100]))
        .expect("ok");
    assert!(p.add_entry(EntryInput::file("b", vec![8u8; 100])).is_err());
    p.finish().expect("ok");
    let mut p = set.begin_partition(&mut b, Some(exact)).expect("ok");
    p.add_entry(EntryInput::file("b", vec![8u8; 100]))
        .expect("ok");
    let s = p.finish_final().expect("ok");
    set.finish_set().expect("ok");
    assert!(a.windows(100).all(|w| w != [8u8; 100]));
    assert!(b.windows(100).any(|w| w == [8u8; 100]));
    assert_eq!(s.partition_index, 1);
    let v = validate(&[&a, &b]).expect("ok");
    assert!(v.is_complete());
}

#[test]
fn capacity_too_small_for_closing_structures() {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    let r = set.begin_partition(&mut a, Some(16)).map(|_| ());
    assert!(matches!(r, Err(SarError::LimitExceeded(_))));
    assert!(a.is_empty());
    // Writer remains usable after a pre-output refusal.
    let mut b = Vec::new();
    set.begin_partition(&mut b, None)
        .expect("ok")
        .finish_final()
        .expect("ok");
}

#[test]
fn aggregate_partition_count_and_entry_limits() {
    let exact = one_entry_member_len();
    let mut o = opts();
    o.limits.max_aggregate_bytes = exact + 10;
    let mut set = PartitionSetWriter::new(o).expect("ok");
    let mut a = Vec::new();
    let mut p = set.begin_partition(&mut a, None).expect("ok");
    assert!(p.add_entry(EntryInput::file("a", vec![7u8; 100])).is_ok());
    p.finish().expect("ok");
    let mut b = Vec::new();
    assert!(matches!(
        set.begin_partition(&mut b, None).and_then(|mut p| p
            .add_entry(EntryInput::file("b", vec![7u8; 100]))
            .map(|_| ())),
        Err(SarError::LimitExceeded(_))
    ));

    let mut o = opts();
    o.limits.max_partitions = 2;
    let mut set = PartitionSetWriter::new(o).expect("ok");
    for _ in 0..2 {
        let mut x = Vec::new();
        set.begin_partition(&mut x, None)
            .expect("ok")
            .finish()
            .expect("ok");
    }
    let mut x = Vec::new();
    assert!(matches!(
        set.begin_partition(&mut x, None),
        Err(SarError::LimitExceeded(_))
    ));

    let mut o = opts();
    o.limits = PartitionSetWriterLimits {
        max_entries_per_partition: 1,
        ..o.limits
    };
    let mut set = PartitionSetWriter::new(o).expect("ok");
    let mut x = Vec::new();
    let mut p = set.begin_partition(&mut x, None).expect("ok");
    p.add_entry(EntryInput::file("a", b"1".to_vec()))
        .expect("ok");
    assert!(matches!(
        p.add_entry(EntryInput::file("b", b"2".to_vec())),
        Err(SarError::LimitExceeded(_))
    ));

    let mut o = opts();
    o.limits.max_entry_bytes = 50;
    let mut set = PartitionSetWriter::new(o).expect("ok");
    let mut x = Vec::new();
    let mut p = set.begin_partition(&mut x, None).expect("ok");
    assert!(matches!(
        p.add_entry(EntryInput::file("a", vec![0; 200])),
        Err(SarError::LimitExceeded(_))
    ));
}

#[test]
fn declared_total_above_limit_rejected() {
    let mut o = opts();
    o.known_total = Some(10);
    o.limits.max_partitions = 5;
    assert!(matches!(
        PartitionSetWriter::new(o),
        Err(SarError::LimitExceeded(_))
    ));
}

// ---------- sink failures ----------

struct FailAfter {
    limit: usize,
    written: usize,
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() > self.limit {
            return Err(io::Error::other("sink failure"));
        }
        self.written += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reference layout of a single-entry member: (manifest_offset, len).
fn layout() -> (usize, usize) {
    let (m, s) = build(opts(), &[&[("a", "alpha")]]);
    (
        usize::try_from(s[0].committed_content_length).expect("ok"),
        m[0].len(),
    )
}

fn fail_at(limit: usize) -> (PartitionSetWriter, Result<PartitionMemberSummary, SarError>) {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let r = {
        let sink = FailAfter { limit, written: 0 };
        match set.begin_partition(sink, None) {
            Err(e) => Err(e),
            Ok(mut p) => p
                .add_entry(EntryInput::file("a", b"alpha".to_vec()))
                .and_then(|_| p.finish_final()),
        }
    };
    (set, r)
}

#[test]
fn sink_failures_never_complete_the_set() {
    let (manifest_off, len) = layout();
    for limit in [
        4,                // Global Header
        manifest_off - 1, // Entry
        manifest_off + 1, // terminal Manifest
        len - 9,          // local CD
        len - 1,          // Footer
    ] {
        let (mut set, r) = fail_at(limit);
        assert!(matches!(r, Err(SarError::Io(_))), "limit {limit}: {r:?}");
        let mut next = Vec::new();
        assert!(set.begin_partition(&mut next, None).is_err());
        assert!(set.finish_set().is_err(), "limit {limit}");
    }
    // A sink with exactly enough room succeeds.
    let (set, r) = fail_at(len);
    r.expect("exact sink");
    set.finish_set().expect("ok");
}

#[test]
fn failure_after_nonfinal_member_keeps_it_valid_but_incomplete() {
    let mut set = PartitionSetWriter::new(opts()).expect("ok");
    let mut a = Vec::new();
    set.begin_partition(&mut a, None)
        .expect("ok")
        .finish()
        .expect("ok");
    let r = set
        .begin_partition(
            FailAfter {
                limit: 4,
                written: 0,
            },
            None,
        )
        .map(|_| ());
    assert!(r.is_err());
    assert!(set.finish_set().is_err());
    inspect(&a).expect("published member stays locally valid");
    let incomplete = ValidatedPartitionSet::validate(
        &[inspect(&a).expect("ok")],
        &PartitionSetLimits::default(),
        PartitionSetMode::default(),
    );
    assert!(incomplete.is_err());
}

#[test]
fn compression_settings_are_reused() {
    let mut o = opts();
    o.compression = CompressionSettings {
        algo_id: 0x01,
        level: None,
    };
    let (m, s) = build(o, &[&[("a", &"z".repeat(500))], &[("b", "y")]]);
    assert_conforms(&m, &s, false);
}

#[test]
fn capacity_accounting_is_exact_for_every_member_layout() {
    let configs = [(false, false), (false, true), (true, false)];
    for (no_index, crc) in configs {
        let mut o = opts();
        o.archive.no_index = no_index;
        o.data_area_crc32 = crc;
        let mut set = PartitionSetWriter::new(o.clone()).expect("ok");
        let mut a = Vec::new();
        let mut p = set.begin_partition(&mut a, None).expect("ok");
        p.add_entry(EntryInput::file("a", vec![1u8; 33]))
            .expect("ok");
        let exact = p.finish_final().expect("ok").partition_len;

        for (cap, fits) in [(exact, true), (exact - 1, false)] {
            let mut set = PartitionSetWriter::new(o.clone()).expect("ok");
            let mut b = Vec::new();
            let mut p = set.begin_partition(&mut b, Some(cap)).expect("ok");
            assert_eq!(
                p.add_entry(EntryInput::file("a", vec![1u8; 33])).is_ok(),
                fits,
                "no_index={no_index} crc={crc} cap={cap}"
            );
            let sum = p.finish_final().expect("ok");
            assert!(sum.partition_len <= cap);
            inspect(&b).expect("valid");
        }
    }
}

// ---------- correction: Empty Area capacity accounting ----------

fn empty_area_member(options: &PartitionSetWriterOptions, capacity: Option<u64>) -> Vec<u8> {
    let mut set = PartitionSetWriter::new(options.clone()).expect("set");
    let mut buf = Vec::new();
    {
        let mut p = set.begin_partition(&mut buf, capacity).expect("begin");
        for name in ["a", "", "b", "", ""] {
            p.add_entry(EntryInput::file(
                name,
                if name.is_empty() {
                    vec![]
                } else {
                    vec![5u8; 20]
                },
            ))
            .expect("entry");
        }
        p.finish_final().expect("finish");
    }
    buf
}

#[test]
fn capacity_is_exact_with_empty_areas() {
    for crc in [false, true] {
        let mut o = opts();
        o.data_area_crc32 = crc;
        let reference = empty_area_member(&o, None);
        let exact = reference.len() as u64;
        let v = inspect(&reference).expect("P1 accepts");
        assert!(v.is_indexed());
        // Footer points at a CD holding 3 offsets (a, b, Manifest), not 6.
        let cd_off = usize::try_from(u64::from_le_bytes(
            reference[reference.len() - 8..].try_into().expect("footer"),
        ))
        .expect("offset");
        let width = 4;
        let crc_len = if crc { 4 } else { 0 };
        let cd_len = reference.len() - 8 - cd_off;
        let padded_fixed = 8 + 4 + crc_len; // version+reserved, size field, optional CRC
        assert!(
            (3 * width..3 * width + 8).contains(&(cd_len - padded_fixed)),
            "crc={crc} cd_len={cd_len}: offsets exclude Empty Areas"
        );

        assert_eq!(empty_area_member(&o, Some(exact)), reference, "crc={crc}");

        let mut set = PartitionSetWriter::new(o.clone()).expect("set");
        let mut buf = Vec::new();
        let mut p = set
            .begin_partition(&mut buf, Some(exact - 1))
            .expect("begin");
        let mut refused = 0;
        for name in ["a", "", "b", "", ""] {
            let data = if name.is_empty() {
                vec![]
            } else {
                vec![5u8; 20]
            };
            if matches!(
                p.add_entry(EntryInput::file(name, data)),
                Err(SarError::LimitExceeded(_))
            ) {
                refused += 1;
            }
        }
        assert!(refused >= 1, "one byte less must refuse an admission");
        p.finish_final().expect("finish");
        inspect(&buf).expect("valid after refusal");
    }
}

// ---------- correction: staging limit ----------

#[test]
fn staging_limit_applies_before_encoding_and_before_publication() {
    let mut o = opts();
    o.limits.max_entry_bytes = 1000;
    let mut set = PartitionSetWriter::new(o.clone()).expect("set");
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    let before = p
        .add_entry(EntryInput::file("ok", vec![1u8; 100]))
        .expect("ok");
    // Oversized input is refused before encoding.
    assert!(matches!(
        p.add_entry(EntryInput::file("big", vec![1u8; 5000])),
        Err(SarError::LimitExceeded(_))
    ));
    // Member state is intact: the next Entry lands right after the first.
    let after = p
        .add_entry(EntryInput::file("ok2", vec![2u8; 100]))
        .expect("ok2");
    assert_eq!(after.lfh_offset, before.lfh_offset + before.total_bytes);
    let sum = p.finish_final().expect("finish");
    assert_eq!(sum.entry_count, 2);
    inspect(&buf).expect("valid");
    assert!(!buf.windows(1000).any(|w| w.iter().all(|b| *b == 1)));
}

#[test]
fn compressed_entry_uses_encoded_size_for_publication_budget() {
    let mut o = opts();
    o.compression = CompressionSettings {
        algo_id: 0x01,
        level: None,
    };
    o.limits.max_entry_bytes = 1000;
    let mut set = PartitionSetWriter::new(o.clone()).expect("set");
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    // 900 compressible input bytes encode to far fewer bytes: accepted.
    p.add_entry(EntryInput::file("z", vec![b'z'; 900]))
        .expect("compressible");
    // 1001 incompressible-or-not input bytes exceed the input bound outright.
    assert!(matches!(
        p.add_entry(EntryInput::file("z2", vec![b'z'; 1001])),
        Err(SarError::LimitExceeded(_))
    ));
    // Incompressible input within the input bound whose encoded form (plus
    // LFH) exceeds the budget is refused before publication.
    let mut x = 0x9E37_79B9_7F4A_7C15_u64;
    let noise: Vec<u8> = (0..990)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[3]
        })
        .collect();
    let r = p.add_entry(EntryInput::file("n".repeat(100), noise));
    assert!(matches!(r, Err(SarError::LimitExceeded(_))), "{r:?}");
    let sum = p.finish_final().expect("finish");
    assert_eq!(sum.entry_count, 1);
    inspect(&buf).expect("valid");
}
