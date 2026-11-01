// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! `SAR-M13b3-PARTITION-P4-IMPLEMENTATION-001`: cross-Partition fragmentation.
//! Every generated member is independently inspected (P1), every Set is
//! validated (P2) and only then handed to the P4 fragment reader.  Malformed
//! cases use byte-exact hand-built members with a correct Manifest, so P1/P2
//! pass and only the P4 structure check can reject them.

use std::cell::RefCell;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;

use sar_archive::{
    ArchiveReader, ArchiveWriterOptions, CompressionSettings, EntryInput, FragmentGroupSpec,
    FragmentWriterLimits, PartitionLogicalEntry, PartitionSetFragmentLimits,
    PartitionSetFragmentOptions, PartitionSetFragmentReader, PartitionSetSummary,
    PartitionSetWriter, PartitionSetWriterLimits, PartitionSetWriterOptions, ValidatedPartition,
    ValidatedPartitionSet,
};
use sar_core::flags::EntryMode;
use sar_core::format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh};
use sar_core::{
    GlobalFlags, PARTITION_TOTAL_UNKNOWN, PartitionManifestFlags, PartitionManifestV1, SarError,
};
use sar_crypto::hash::new_hasher;
use sar_partition::{PartitionSetLimits, PartitionSetMode};

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

/// Independent P1 + P2 check of a generated Set.
fn assert_p1_p2(members: &[Vec<u8>]) {
    let parts: Vec<ValidatedPartition> = members.iter().map(|m| inspect(m).expect("P1")).collect();
    let set = ValidatedPartitionSet::validate(
        &parts,
        &PartitionSetLimits::default(),
        PartitionSetMode::default(),
    )
    .expect("P2");
    assert!(set.is_complete());
}

fn reader(members: &[Vec<u8>]) -> Result<PartitionSetFragmentReader<Cursor<Vec<u8>>>, SarError> {
    reader_with(members, PartitionSetFragmentOptions::default())
}

fn reader_with(
    members: &[Vec<u8>],
    o: PartitionSetFragmentOptions,
) -> Result<PartitionSetFragmentReader<Cursor<Vec<u8>>>, SarError> {
    PartitionSetFragmentReader::open(members.iter().cloned().map(Cursor::new).collect(), o)
}

fn reassemble(members: &[Vec<u8>]) -> Result<Vec<PartitionLogicalEntry>, SarError> {
    let mut out = Vec::new();
    reader(members)?.reassemble(|e| {
        out.push(e);
        Ok(())
    })?;
    Ok(out)
}

// ---------- writer-driven sets ----------

#[derive(Clone)]
enum Op {
    Entry(&'static str, Vec<u8>),
    Begin(u32, &'static str),
    Frag(u32, Vec<u8>, bool),
}

fn build(o: PartitionSetWriterOptions, plan: &[Vec<Op>]) -> Vec<Vec<u8>> {
    let crc = o.archive.with_per_file_crc;
    let mut set = open_set(o);
    let mut members = Vec::new();
    for (i, ops) in plan.iter().enumerate() {
        let mut buf = Vec::new();
        {
            let mut p = set.begin_partition(&mut buf, None).expect("begin");
            for op in ops {
                match op {
                    Op::Entry(n, d) => {
                        let mut input = EntryInput::file(*n, d.clone());
                        input.file_crc32 = crc.then(|| crc32fast::hash(d));
                        p.add_entry(input).expect("entry");
                    }
                    Op::Begin(id, name) => p
                        .begin_fragment_group(FragmentGroupSpec {
                            fragment_id: *id,
                            name: (*name).to_string(),
                            ..Default::default()
                        })
                        .expect("group"),
                    Op::Frag(id, d, last) => {
                        p.add_fragment(*id, d.clone(), *last).expect("fragment");
                    }
                }
            }
            if i + 1 == plan.len() {
                p.finish_final().expect("final");
            } else {
                p.finish().expect("finish");
            }
        }
        members.push(buf);
    }
    set.finish_set().expect("set done");
    members
}

fn two_partition_plan() -> Vec<Vec<Op>> {
    vec![
        vec![
            Op::Entry("a", b"AAA".to_vec()),
            Op::Begin(7, "big"),
            Op::Frag(7, b"hello ".to_vec(), false),
        ],
        vec![
            Op::Frag(7, b"world".to_vec(), true),
            Op::Entry("z", b"ZZZ".to_vec()),
        ],
    ]
}

#[test]
fn fragment_spans_two_partitions() {
    let members = build(opts(), &two_partition_plan());
    assert_p1_p2(&members);
    let mut r = reader(&members).expect("open");
    let report = r.validate_fragment_groups().expect("structure");
    assert!(!report.reconstructed);
    assert_eq!(report.logical_entries, 3);
    assert_eq!(report.groups.len(), 1);
    let g = &report.groups[0];
    assert_eq!((g.fragment_id, g.fragments), (7, 2));
    assert_eq!((g.first_partition, g.last_partition), (0, 1));
    assert_eq!(g.logical_bytes, 11);

    let out = reassemble(&members).expect("reassemble");
    let names: Vec<_> = out.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        ["a", "big", "z"],
        "canonical order at Fragment Index 0"
    );
    assert_eq!(out[1].data, b"hello world");
    assert_eq!(out[1].fragment_id, Some(7));
    assert_eq!(out[1].fragment_count, 2);
    assert_eq!(out[0].fragment_id, None);
}

#[test]
fn fragment_spans_three_partitions_with_gap_partition_and_interleaving() {
    let plan = vec![
        vec![
            Op::Begin(1, "one"),
            Op::Begin(2, "two"),
            Op::Frag(1, b"1a".to_vec(), false),
            Op::Frag(2, b"2a".to_vec(), false),
        ],
        // A Partition holding only an unrelated Entry and a different group.
        vec![
            Op::Entry("plain", b"P".to_vec()),
            Op::Frag(2, b"2b".to_vec(), false),
        ],
        vec![
            Op::Frag(1, b"1b".to_vec(), false),
            Op::Entry("between", b"B".to_vec()),
            Op::Frag(1, b"1c".to_vec(), true),
            Op::Frag(2, b"2c".to_vec(), true),
        ],
    ];
    let members = build(opts(), &plan);
    assert_p1_p2(&members);
    let out = reassemble(&members).expect("reassemble");
    let got: Vec<_> = out
        .iter()
        .map(|e| (e.name.clone(), e.data.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("one".into(), b"1a1b1c".to_vec()),
            ("two".into(), b"2a2b2c".to_vec()),
            ("plain".into(), b"P".to_vec()),
            ("between".into(), b"B".to_vec()),
        ]
    );
    let report = reader(&members)
        .expect("open")
        .validate_fragment_groups()
        .expect("structure");
    assert_eq!(report.groups[0].fragments, 3);
    assert_eq!(report.groups[1].fragments, 3);
    assert_eq!(report.groups[0].last_partition, 2);
}

#[test]
fn layout_variants_index_crc_totals_and_integrity_fields() {
    for (no_index, data_crc, known) in [
        (false, false, true),
        (false, true, true),
        (true, false, true),
        (false, false, false),
    ] {
        for integrity in [false, true] {
            let mut o = opts();
            o.archive.no_index = no_index;
            o.data_area_crc32 = data_crc;
            o.known_total = known.then_some(2);
            o.archive.with_per_file_crc = integrity;
            o.archive.with_content_hash = integrity;
            let members = build(o, &two_partition_plan());
            assert_p1_p2(&members);
            let out = reassemble(&members).expect("reassemble");
            assert_eq!(out[1].data, b"hello world");
            assert_eq!(
                inspect(&members[0]).expect("p").known_total().is_some(),
                known
            );
        }
    }
    assert_ne!(PARTITION_TOTAL_UNKNOWN, 2);
}

#[test]
fn fragment_local_compression_is_decoded_per_fragment() {
    let mut o = opts();
    o.compression = CompressionSettings {
        algo_id: 0x01,
        level: None,
    };
    let a = "x".repeat(400).into_bytes();
    let b = "y".repeat(300).into_bytes();
    let plan = vec![
        vec![Op::Begin(3, "c"), Op::Frag(3, a.clone(), false)],
        vec![Op::Frag(3, b.clone(), true)],
    ];
    let members = build(o, &plan);
    assert_p1_p2(&members);
    let out = reassemble(&members).expect("reassemble");
    assert_eq!(out[0].data, [a, b].concat());
}

#[test]
fn empty_contribution_is_valid() {
    let plan = vec![
        vec![Op::Begin(3, "e"), Op::Frag(3, b"ab".to_vec(), false)],
        vec![
            Op::Frag(3, Vec::new(), false),
            Op::Frag(3, Vec::new(), true),
        ],
    ];
    let members = build(opts(), &plan);
    assert_p1_p2(&members);
    assert_eq!(reassemble(&members).expect("ok")[0].data, b"ab");
}

#[test]
fn fragment_id_namespace_is_per_partition_set() {
    let one = build(opts(), &two_partition_plan());
    let mut o = opts();
    o.partition_set_uuid = Some([0x43; 16]);
    let two = build(o, &two_partition_plan());
    assert_eq!(reassemble(&one).expect("one")[1].data, b"hello world");
    assert_eq!(reassemble(&two).expect("two")[1].data, b"hello world");
    // Mixing members of two Sets is a P2 failure before any fragment logic.
    let mixed = vec![one[0].clone(), two[1].clone()];
    assert!(reader(&mixed).is_err());
}

#[test]
fn fragment_id_is_not_reset_per_partition() {
    let plan = vec![
        vec![Op::Begin(5, "f"), Op::Frag(5, b"a".to_vec(), false)],
        vec![Op::Frag(5, b"b".to_vec(), true)],
    ];
    let members = build(opts(), &plan);
    // A fresh LFH walk of one member alone shows an incomplete group.
    let single = vec![members[0].clone()];
    let err = reader(&single).expect_err("incomplete set");
    assert!(matches!(err, SarError::PartitionMissing(_)));
}

// ---------- writer state machine ----------

fn open_set(o: PartitionSetWriterOptions) -> PartitionSetWriter {
    open_set_with(o, FragmentWriterLimits::default())
}

fn open_set_with(o: PartitionSetWriterOptions, l: FragmentWriterLimits) -> PartitionSetWriter {
    PartitionSetWriter::new(o)
        .expect("set")
        .with_fragmentation(l)
        .expect("fragmentation")
}

fn spec(id: u32, name: &str) -> FragmentGroupSpec {
    FragmentGroupSpec {
        fragment_id: id,
        name: name.to_string(),
        ..Default::default()
    }
}

#[test]
fn writer_requires_fragmentation_option() {
    let mut set = PartitionSetWriter::new(opts()).expect("set");
    assert!(set.begin_fragment_group(spec(1, "x")).is_err());
}

#[test]
fn writer_rejects_open_group_at_final_member() {
    let mut set = open_set(opts());
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    p.begin_fragment_group(spec(1, "x")).expect("group");
    p.add_fragment(1, b"a".to_vec(), false).expect("frag");
    assert!(matches!(p.finish_final(), Err(SarError::FragmentGap(_))));
    assert!(set.finish_set().is_err());
}

#[test]
fn writer_rejects_open_group_at_set_completion() {
    let mut set = open_set(opts());
    let mut a = Vec::new();
    {
        let mut p = set.begin_partition(&mut a, None).expect("begin");
        p.begin_fragment_group(spec(1, "x")).expect("group");
        p.add_fragment(1, b"a".to_vec(), false).expect("frag");
        p.finish().expect("non-final member may leave a group open");
    }
    // The Set cannot be completed without a final member.
    assert!(set.finish_set().is_err());
}

#[test]
fn writer_group_misuse_is_refused_before_publication() {
    let mut set = open_set(opts());
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    assert!(
        p.add_fragment(9, b"a".to_vec(), false).is_err(),
        "unknown group"
    );
    p.begin_fragment_group(spec(1, "x")).expect("group");
    assert!(
        matches!(
            p.begin_fragment_group(spec(1, "y")),
            Err(SarError::MetadataConflict(_))
        ),
        "Fragment ID reuse"
    );
    p.add_fragment(1, b"a".to_vec(), true).expect("terminal");
    assert!(
        p.add_fragment(1, b"b".to_vec(), false).is_err(),
        "fragment after LAST_FRAGMENT"
    );
    assert!(
        p.add_fragment(1, b"b".to_vec(), true).is_err(),
        "duplicate terminal"
    );
    assert!(
        p.begin_fragment_group(spec(1, "again")).is_err(),
        "closed ID is not reusable"
    );
    p.finish_final().expect("member still usable");
    let summary = set.finish_set_with_fragments().expect("set");
    assert_eq!(summary.summary.total_partitions, 1);
    assert_eq!(summary.fragment_groups, 1);
    assert_eq!(summary.fragments, 1);
}

#[test]
fn writer_oversized_fragment_is_refused_and_member_stays_usable() {
    let mut set = open_set(opts());
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, Some(400)).expect("begin");
    p.begin_fragment_group(spec(1, "x")).expect("group");
    assert!(matches!(
        p.add_fragment(1, vec![0u8; 4096], false),
        Err(SarError::LimitExceeded(_))
    ));
    p.add_fragment(1, b"ok".to_vec(), true).expect("retry fits");
    p.finish_final().expect("final");
    set.finish_set().expect("set");
    assert_p1_p2(&[buf.clone()]);
    assert_eq!(reassemble(&[buf]).expect("ok")[0].data, b"ok");
}

#[test]
fn writer_fragment_limits_are_enforced() {
    let mut set = open_set_with(
        opts(),
        FragmentWriterLimits {
            max_fragments_per_group: 1,
            ..Default::default()
        },
    );
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    p.begin_fragment_group(spec(1, "x")).expect("group");
    p.add_fragment(1, b"a".to_vec(), false).expect("first");
    assert!(p.add_fragment(1, b"b".to_vec(), true).is_err());

    let mut set = open_set_with(
        opts(),
        FragmentWriterLimits {
            max_open_fragment_groups: 1,
            ..Default::default()
        },
    );
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    p.begin_fragment_group(spec(1, "x")).expect("one");
    assert!(p.begin_fragment_group(spec(2, "y")).is_err());
}

struct FailAfter(usize);

impl io::Write for FailAfter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.0 < b.len() {
            return Err(io::Error::other("sink failure"));
        }
        self.0 -= b.len();
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn sink_failure_during_fragment_never_completes_set() {
    let mut set = open_set(opts());
    {
        let mut sink = FailAfter(200);
        let mut p = set.begin_partition(&mut sink, None).expect("begin");
        p.begin_fragment_group(spec(1, "x")).expect("group");
        let mut failed = false;
        for _ in 0..8 {
            if p.add_fragment(1, vec![1u8; 64], false).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
    }
    assert!(set.finish_set().is_err());
}

// ---------- hand-built malformed members ----------

#[derive(Clone)]
struct Frag {
    id: u32,
    index: u32,
    last: bool,
    name: &'static str,
    data: &'static [u8],
    mode_extra: u16,
    crc: u32,
    hash: [u8; 32],
}

fn frag(id: u32, index: u32, last: bool, name: &'static str, data: &'static [u8]) -> Frag {
    Frag {
        id,
        index,
        last,
        name,
        data,
        mode_extra: 0,
        crc: 0,
        hash: [0; 32],
    }
}

const FRAG: u16 = 1 << 5;
const LAST: u16 = 1 << 6;

fn term(id: u32, index: u32, name: &'static str, data: &'static [u8], whole: &[u8]) -> Frag {
    let mut f = frag(id, index, true, name, data);
    f.crc = crc32fast::hash(whole);
    f
}

fn raw_member(index: u32, total: u32, fin: bool, prev: [u8; 32], frags: &[Frag]) -> Vec<u8> {
    let flags = GlobalFlags::PARTITIONED_ARCHIVE
        | GlobalFlags::FILE_FRAGMENTATION
        | GlobalFlags::NO_INDEX
        | GlobalFlags::PER_FILE_CRC;
    let mut out = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    for f in frags {
        let mut lfh =
            LocalFileHeader::minimal_store(f.name.as_bytes().to_vec(), f.data.len() as u64);
        let mut bits = FRAG | f.mode_extra;
        if f.last {
            bits |= LAST;
        }
        lfh.entry_mode = EntryMode::from_bits(bits);
        lfh.fragment_id = Some(f.id);
        lfh.fragment_index = Some(f.index);
        lfh.file_crc32 = Some(f.crc);
        let _ = f.hash;
        out.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        out.extend_from_slice(f.data);
    }
    let committed = out.len() as u64;
    let mut hasher = new_hasher(0x30).expect("hasher");
    hasher.update(&out);
    let digest = hasher.finalize();
    let manifest = PartitionManifestV1 {
        hash_algorithm_id: 0x30,
        flags: PartitionManifestFlags::new(fin),
        partition_index: index,
        total_partitions: total,
        committed_content_length: committed,
        partition_set_uuid: UUID,
        previous_partition_hash: prev,
        current_partition_hash: <[u8; 32]>::try_from(digest.as_slice()).expect("32"),
    };
    let payload = manifest.encode(1 << 20).expect("encode");
    let mut m = LocalFileHeader::minimal_store(Vec::new(), payload.len() as u64);
    m.entry_mode = EntryMode::from_bits(EntryMode::PARTITION_MANIFEST);
    m.uncompressed_size = payload.len() as u64;
    out.extend_from_slice(&write_lfh(&flags, &m).expect("manifest lfh"));
    out.extend_from_slice(&payload);
    out
}

fn raw_set(parts: &[Vec<Frag>]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut prev = [0u8; 32];
    for (i, frags) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let m = raw_member(
            u32::try_from(i).expect("i"),
            u32::try_from(parts.len()).expect("n"),
            last,
            prev,
            frags,
        );
        prev = inspect(&m).expect("P1").manifest().current_partition_hash;
        out.push(m);
    }
    out
}

fn structure(parts: &[Vec<Frag>]) -> Result<(), SarError> {
    let members = raw_set(parts);
    assert_p1_p2(&members);
    reader(&members)?.validate_fragment_groups().map(|_| ())
}

#[test]
fn raw_valid_set_baseline() {
    let parts = vec![
        vec![frag(1, 0, false, "f", b"ab")],
        vec![term(1, 1, "", b"cd", b"abcd")],
    ];
    structure(&parts).expect("valid");
    let out = reassemble(&raw_set(&parts)).expect("reassemble");
    assert_eq!(out[0].data, b"abcd");
}

#[test]
fn duplicate_index_is_metadata_conflict() {
    let r = structure(&[
        vec![frag(1, 0, false, "f", b"a")],
        vec![frag(1, 0, false, "f", b"b"), frag(1, 1, true, "", b"c")],
    ]);
    assert!(matches!(
        r,
        Err(SarError::MetadataConflict(_)) | Err(SarError::Malformed(_))
    ));
    let r = structure(&[
        vec![frag(1, 0, false, "f", b"a"), frag(1, 1, false, "", b"b")],
        vec![frag(1, 1, true, "", b"c")],
    ]);
    assert!(matches!(r, Err(SarError::MetadataConflict(_))));
}

#[test]
fn missing_index_and_missing_index_zero_and_missing_terminal() {
    let gap = structure(&[
        vec![frag(1, 0, false, "f", b"a")],
        vec![frag(1, 2, true, "", b"c")],
    ]);
    assert!(matches!(gap, Err(SarError::FragmentGap(_))), "{gap:?}");

    let no_zero = structure(&[
        vec![frag(1, 1, false, "", b"a")],
        vec![frag(1, 2, true, "", b"c")],
    ]);
    assert!(
        matches!(no_zero, Err(SarError::FragmentGap(_))),
        "{no_zero:?}"
    );

    let open = structure(&[
        vec![frag(1, 0, false, "f", b"a")],
        vec![frag(1, 1, false, "", b"b")],
    ]);
    assert!(matches!(open, Err(SarError::FragmentGap(_))), "{open:?}");
}

#[test]
fn nonfinal_partition_end_does_not_conclude_group() {
    // Group open at end of member 0, terminated in member 1: valid.
    structure(&[
        vec![frag(1, 0, false, "f", b"a")],
        vec![frag(1, 1, true, "", b"b")],
    ])
    .expect("valid");
    // Same prefix with no terminal anywhere: incomplete, never "complete".
    let r = structure(&[
        vec![frag(1, 0, false, "f", b"a")],
        vec![frag(2, 0, true, "g", b"b")],
    ]);
    assert!(matches!(r, Err(SarError::FragmentGap(_))));
}

#[test]
fn terminal_marker_violations() {
    let multi = structure(&[
        vec![frag(1, 0, true, "f", b"a")],
        vec![frag(1, 1, true, "", b"b")],
    ]);
    assert!(
        matches!(multi, Err(SarError::MetadataConflict(_))),
        "{multi:?}"
    );

    let after = structure(&[
        vec![frag(1, 0, false, "f", b"a"), frag(1, 2, true, "", b"c")],
        vec![frag(1, 3, false, "", b"d")],
    ]);
    assert!(
        matches!(after, Err(SarError::MetadataConflict(_))),
        "{after:?}"
    );
}

#[test]
fn decreasing_index_in_physical_order_is_malformed() {
    let r = structure(&[
        vec![frag(1, 0, false, "f", b"a"), frag(1, 2, false, "", b"c")],
        vec![frag(1, 1, true, "", b"b")],
    ]);
    assert!(matches!(r, Err(SarError::Malformed(_))), "{r:?}");
}

#[test]
fn class_g_conflict_and_name_conflict() {
    let mut b = frag(1, 1, true, "", b"b");
    b.mode_extra = 1 << 4; // HIDDEN_ATTR differs
    let r = structure(&[vec![frag(1, 0, false, "f", b"a")], vec![b]]);
    assert!(matches!(r, Err(SarError::MetadataConflict(_))), "{r:?}");

    let r = structure(&[
        vec![frag(1, 0, false, "f", b"a")],
        vec![frag(1, 1, true, "other", b"b")],
    ]);
    assert!(matches!(r, Err(SarError::MetadataConflict(_))), "{r:?}");
}

#[test]
fn nonterminal_crc_must_be_zero() {
    let mut a = frag(1, 0, false, "f", b"a");
    a.crc = 5;
    let r = structure(&[vec![a], vec![frag(1, 1, true, "", b"b")]]);
    assert!(matches!(r, Err(SarError::MetadataConflict(_))), "{r:?}");
}

#[test]
fn terminal_crc_is_checked_on_reassembly_only() {
    let mut last = frag(1, 1, true, "", b"cd");
    last.crc = 0x1234_5678;
    let members = raw_set(&[vec![frag(1, 0, false, "f", b"ab")], vec![last]]);
    assert_p1_p2(&members);
    reader(&members)
        .expect("open")
        .validate_fragment_groups()
        .expect("structure alone does not claim content integrity");
    let r = reassemble(&members);
    assert!(matches!(r, Err(SarError::CrcMismatch(_))), "{r:?}");

    let mut good = frag(1, 1, true, "", b"cd");
    good.crc = crc32fast::hash(b"abcd");
    let members = raw_set(&[vec![frag(1, 0, false, "f", b"ab")], vec![good]]);
    assert_eq!(reassemble(&members).expect("ok")[0].data, b"abcd");
}

#[test]
fn unsupported_group_wide_stages_are_refused_by_the_writer() {
    for tweak in [
        (|o: &mut PartitionSetWriterOptions| o.archive.with_delta = true)
            as fn(&mut PartitionSetWriterOptions),
        |o| o.archive.sparse = true,
    ] {
        let mut o = opts();
        tweak(&mut o);
        let mut set = open_set(o);
        assert!(matches!(
            set.begin_fragment_group(spec(1, "x")),
            Err(SarError::Unsupported(_))
        ));
    }
}

#[test]
fn incomplete_set_is_rejected_for_reassembly() {
    let members = build(opts(), &two_partition_plan());
    let r = reader(&members[..1]);
    assert!(matches!(r, Err(SarError::PartitionMissing(_))));
    let r = reader(&members[1..]);
    assert!(r.is_err());
}

#[test]
fn replica_or_duplicate_sources_are_rejected() {
    let members = build(opts(), &two_partition_plan());
    let dup = vec![members[0].clone(), members[0].clone(), members[1].clone()];
    assert!(reader(&dup).is_err());
}

#[test]
fn input_order_does_not_matter() {
    let members = build(opts(), &two_partition_plan());
    let rev = vec![members[1].clone(), members[0].clone()];
    let out = reassemble(&rev).expect("reassemble");
    assert_eq!(out[1].data, b"hello world");
}

#[test]
fn fragment_limits_are_enforced() {
    let members = build(opts(), &two_partition_plan());
    for limits in [
        PartitionSetFragmentLimits {
            max_fragments_total: 1,
            ..Default::default()
        },
        PartitionSetFragmentLimits {
            max_fragments_per_group: 1,
            ..Default::default()
        },
        PartitionSetFragmentLimits {
            max_fragment_groups: 0,
            ..Default::default()
        },
        PartitionSetFragmentLimits {
            max_total_fragment_bytes: 3,
            ..Default::default()
        },
    ] {
        let o = PartitionSetFragmentOptions {
            fragments: limits,
            ..Default::default()
        };
        let r = reader_with(&members, o)
            .expect("open")
            .validate_fragment_groups();
        assert!(matches!(r, Err(SarError::LimitExceeded(_))), "{r:?}");
    }
    let o = PartitionSetFragmentOptions {
        fragments: PartitionSetFragmentLimits {
            max_group_logical_bytes: 4,
            ..Default::default()
        },
        ..Default::default()
    };
    let r = reader_with(&members, o)
        .expect("open")
        .validate_fragment_groups();
    assert!(matches!(r, Err(SarError::LimitExceeded(_))), "{r:?}");
}

// ---------- source stability ----------

#[derive(Clone)]
struct Shared(Rc<RefCell<Vec<u8>>>, u64);

impl Shared {
    fn new(rc: &Rc<RefCell<Vec<u8>>>) -> Self {
        Self(rc.clone(), 0)
    }
}

impl Read for Shared {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.0.borrow();
        let start = usize::try_from(self.1)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        self.1 += n as u64;
        Ok(n)
    }
}

impl Seek for Shared {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.0.borrow().len() as i64;
        let new = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(d) => len + d,
            SeekFrom::Current(d) => self.1 as i64 + d,
        };
        if new < 0 {
            return Err(io::Error::other("negative seek"));
        }
        self.1 = new as u64;
        Ok(self.1)
    }
}

#[test]
fn modified_source_after_open_is_rejected() {
    let members = build(opts(), &two_partition_plan());
    let shared: Vec<Rc<RefCell<Vec<u8>>>> = members
        .iter()
        .map(|m| Rc::new(RefCell::new(m.clone())))
        .collect();
    let mut r = PartitionSetFragmentReader::open(
        shared.iter().map(Shared::new).collect(),
        PartitionSetFragmentOptions::default(),
    )
    .expect("open");
    r.validate_fragment_groups().expect("fresh");

    // Flip a payload byte of the second member after P1/P2 validation.
    {
        let mut b = shared[1].borrow_mut();
        let pos = b
            .windows(5)
            .position(|w| w == b"world")
            .expect("payload present");
        b[pos] ^= 1;
    }
    let mut sunk = 0;
    let res = r.reassemble(|_| {
        sunk += 1;
        Ok(())
    });
    assert!(
        matches!(
            res,
            Err(SarError::HashMismatch(_) | SarError::PartitionMismatch(_))
        ),
        "{res:?}"
    );
    assert_eq!(sunk, 0, "no output from a stale source");
}

#[test]
fn unkeyed_hashes_do_not_imply_authenticity() {
    // A forged-but-self-consistent member (valid hash chain, different
    // content) passes P1/P2 and P4 structure checks: only the final integrity
    // values of the logical Entry can differ, which is not authentication.
    let a = raw_set(&[
        vec![frag(1, 0, false, "f", b"ab")],
        vec![frag(1, 1, true, "", b"cd")],
    ]);
    let b = raw_set(&[
        vec![frag(1, 0, false, "f", b"XY")],
        vec![frag(1, 1, true, "", b"cd")],
    ]);
    for set in [&a, &b] {
        assert_p1_p2(set);
        reader(set)
            .expect("open")
            .validate_fragment_groups()
            .expect("structure");
    }
}

#[test]
fn sink_error_propagates_and_report_not_reconstructed() {
    let members = build(opts(), &two_partition_plan());
    let r = reader(&members)
        .expect("open")
        .reassemble(|_| Err(SarError::Internal("sink")));
    assert!(r.is_err());
    let ok = reader(&members)
        .expect("open")
        .reassemble(|_| Ok(()))
        .expect("ok");
    assert!(ok.reconstructed);
}

#[test]
fn encrypted_members_are_unsupported() {
    use sar_archive::EncryptionSettings;
    use sar_crypto::{ENCR_AES256_GCM, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params};
    let mut o = opts();
    o.archive.encryption = Some(EncryptionSettings {
        algo_id: ENCR_AES256_GCM,
        kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
            prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
            salt: vec![7; 16],
            iterations: 100_000,
            derived_key_length: 32,
        }),
    });
    // The P3 writer requires plaintext members unless a key provider path is
    // used; either refusal is fail-closed.
    assert!(PartitionSetWriter::new(o).is_err());
}

// ---------- P3 public API source compatibility ----------

#[test]
fn pre_p4_struct_layouts_still_compile_as_exhaustive_literals() {
    let limits = PartitionSetWriterLimits {
        max_partitions: 8,
        max_partition_bytes: 1 << 20,
        max_aggregate_bytes: 1 << 24,
        max_entries_per_partition: 64,
        max_entry_bytes: 1 << 16,
    };
    let options = PartitionSetWriterOptions {
        partition_set_uuid: Some(UUID),
        known_total: None,
        hash_algorithm_id: 0x30,
        data_area_crc32: false,
        archive: ArchiveWriterOptions::default(),
        compression: CompressionSettings::store(),
        limits,
    };
    let summary = PartitionSetSummary {
        partition_set_uuid: UUID,
        total_partitions: 1,
        aggregate_bytes: 0,
    };
    assert_eq!(summary.total_partitions, 1);

    // Plain P3 use: fragmentation stays disabled and the Set finishes unchanged.
    let mut set = PartitionSetWriter::new(options).expect("set");
    assert!(set.begin_fragment_group(spec(1, "x")).is_err());
    let mut buf = Vec::new();
    let mut p = set.begin_partition(&mut buf, None).expect("begin");
    assert!(p.begin_fragment_group(spec(1, "x")).is_err());
    p.add_entry(EntryInput::file("a", b"data".to_vec()))
        .expect("entry");
    p.finish_final().expect("final");
    let done = set.finish_set().expect("set");
    assert_eq!(done.total_partitions, 1);
    assert_p1_p2(&[buf.clone()]);
    assert!(!has_fragmentation_flag(&buf));
}

#[test]
fn fragmentation_must_be_enabled_before_the_first_member() {
    let mut set = PartitionSetWriter::new(opts()).expect("set");
    let mut buf = Vec::new();
    set.begin_partition(&mut buf, None)
        .expect("begin")
        .finish_final()
        .expect("final");
    assert!(
        set.with_fragmentation(FragmentWriterLimits::default())
            .is_err()
    );
}

#[test]
fn fragmenting_members_carry_the_flag_and_reassemble_with_integrity() {
    let members = build(opts(), &two_partition_plan());
    for m in &members {
        assert!(has_fragmentation_flag(m));
    }
    assert_p1_p2(&members);
    assert_eq!(reassemble(&members).expect("ok")[1].data, b"hello world");
}

fn has_fragmentation_flag(member: &[u8]) -> bool {
    let (header, _) =
        sar_core::format::parse_global_header(member, &sar_core::ResourceLimits::default())
            .expect("global header");
    header.flags.contains(GlobalFlags::FILE_FRAGMENTATION)
}
