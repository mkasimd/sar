// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! WP-4 fragment-group validation through the real archive reader
//! (`SAR-M13b-WP4-FRAGMENT-GROUP-IMPLEMENTATION-001`).

use std::io::Cursor;

use sar_archive::ArchiveReader;
use sar_core::{
    GlobalFlags, SarError,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};

const FRAG: u16 = 1 << 5;
const LAST: u16 = 1 << 6;
const LOSS: u16 = 1 << 7;

#[derive(Clone)]
struct Frag {
    id: u32,
    index: u32,
    last: bool,
    name: &'static str,
    path: &'static str,
    data: &'static [u8],
    mode_extra: u16,
    crc: u32,
    hash: [u8; 32],
    stream_id: u16,
    uid_gid: u32,
    timestamps: [u64; 3],
    permissions: u16,
    sparse_map: Vec<u8>,
}

fn frag(id: u32, index: u32, last: bool, name: &'static str, data: &'static [u8]) -> Frag {
    Frag {
        id,
        index,
        last,
        name,
        path: "",
        data,
        mode_extra: 0,
        crc: 0,
        hash: [0; 32],
        stream_id: 0,
        uid_gid: 0,
        timestamps: [0; 3],
        permissions: 0,
        sparse_map: Vec::new(),
    }
}

fn build_with(flags: GlobalFlags, frags: &[Frag]) -> Vec<u8> {
    let flags = flags | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut out = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("global header");
    for f in frags {
        let mut lfh =
            LocalFileHeader::minimal_store(f.name.as_bytes().to_vec(), f.data.len() as u64);
        lfh.path = f.path.as_bytes().to_vec();
        lfh.uncompressed_size = f.data.len() as u64;
        let mut bits = FRAG | f.mode_extra;
        if f.last {
            bits |= LAST;
        }
        lfh.entry_mode = EntryMode::from_bits(bits);
        lfh.fragment_id = Some(f.id);
        lfh.fragment_index = Some(f.index);
        lfh.stream_id = f.stream_id;
        lfh.file_crc32 = Some(f.crc);
        lfh.content_hash = Some(f.hash);
        lfh.uid_gid = Some(f.uid_gid);
        lfh.timestamps = Some(f.timestamps);
        lfh.permissions = Some(f.permissions);
        lfh.sparse_map = f.sparse_map.clone();
        out.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        out.extend_from_slice(f.data);
    }
    out
}

fn build(frags: &[Frag]) -> Vec<u8> {
    build_with(GlobalFlags::empty(), frags)
}

fn read(archive: Vec<u8>, lossy: bool) -> Result<Vec<sar_archive::LogicalFile>, SarError> {
    ArchiveReader::new(Cursor::new(archive))
        .expect("reader")
        .read_all_logical_files(lossy)
}

fn pair() -> (Frag, Frag) {
    (
        frag(1, 0, false, "f.bin", b"AAAA"),
        frag(1, 1, true, "", b"BBBB"),
    )
}

// --- Physical order ---------------------------------------------------------

#[test]
fn interleaved_groups_in_increasing_order_are_valid_and_ordered_by_index0() {
    let archive = build(&[
        frag(1, 0, false, "a.bin", b"A0"),
        frag(2, 0, false, "b.bin", b"B0"),
        frag(1, 1, true, "", b"A1"),
        frag(2, 1, true, "", b"B1"),
    ]);
    let files = read(archive, false).expect("valid");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, "a.bin");
    assert_eq!(files[0].data, b"A0A1");
    assert_eq!(files[1].name, "b.bin");
    assert_eq!(files[1].data, b"B0B1");
}

#[test]
fn group_is_positioned_at_index0_relative_to_plain_entries() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let header = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    let mut archive = header.clone();
    let plain = |name: &str, data: &[u8]| {
        let mut l = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), data.len() as u64);
        l.uncompressed_size = data.len() as u64;
        let mut out = write_lfh(&flags, &l).expect("lfh");
        out.extend_from_slice(data);
        out
    };
    archive.extend_from_slice(&plain("first.bin", b"1"));
    let group = build(&[
        frag(9, 0, false, "g.bin", b"G0"),
        frag(9, 1, true, "", b"G1"),
    ]);
    archive.extend_from_slice(&group[header.len()..]);
    archive.extend_from_slice(&plain("last.bin", b"3"));
    let files = read(archive, false).expect("valid");
    let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["first.bin", "g.bin", "last.bin"]);
}

#[test]
fn out_of_order_physical_index_is_malformed() {
    let archive = build(&[
        frag(1, 0, false, "f.bin", b"A"),
        frag(1, 2, true, "", b"C"),
        frag(1, 1, false, "", b"B"),
    ]);
    assert!(matches!(read(archive, false), Err(SarError::Malformed(_))));
}

#[test]
fn duplicate_index_is_metadata_conflict() {
    let archive = build(&[
        frag(1, 0, false, "f.bin", b"A"),
        frag(1, 0, false, "f.bin", b"A"),
        frag(1, 1, true, "", b"B"),
    ]);
    assert!(matches!(
        read(archive, false),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn empty_index0_name_is_malformed() {
    let archive = build(&[frag(1, 0, false, "", b"A"), frag(1, 1, true, "", b"B")]);
    assert!(matches!(read(archive, false), Err(SarError::Malformed(_))));
}

// --- Name / Path authority --------------------------------------------------

#[test]
fn later_fragment_may_omit_or_repeat_name_and_path() {
    let mut a = frag(1, 0, false, "f.bin", b"A");
    a.path = "dir";
    let mut b = frag(1, 1, false, "f.bin", b"B");
    b.path = "dir";
    let c = frag(1, 2, true, "", b"C");
    let files = read(build_with(GlobalFlags::HAS_PATH, &[a, b, c]), false).expect("valid");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].data, b"ABC");
}

#[test]
fn later_fragment_name_mismatch_is_metadata_conflict() {
    let (a, mut b) = pair();
    b.name = "other.bin";
    assert!(matches!(
        read(build(&[a, b]), false),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn later_fragment_path_mismatch_is_metadata_conflict() {
    let (mut a, mut b) = pair();
    a.path = "dir";
    b.path = "other";
    assert!(matches!(
        read(build_with(GlobalFlags::HAS_PATH, &[a, b]), false),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn nonzero_index_first_seen_does_not_establish_name() {
    // Index 1 appears first physically (Index 0 later) -> order violation or gap, never success.
    let archive = build(&[
        frag(1, 1, true, "x.bin", b"B"),
        frag(1, 0, false, "f.bin", b"A"),
    ]);
    assert!(read(archive, false).is_err());
}

// --- Class G invariants -----------------------------------------------------

fn conflict(mutate: impl FnOnce(&mut Frag), flags: GlobalFlags, lossy_group: bool) {
    let (mut a, mut b) = pair();
    if lossy_group {
        a.mode_extra |= LOSS;
        b.mode_extra |= LOSS;
    }
    mutate(&mut b);
    let archive = build_with(flags, &[a, b]);
    let err = read(archive, lossy_group).expect_err("conflict");
    assert!(matches!(err, SarError::MetadataConflict(_)), "got {err:?}");
}

#[test]
fn class_g_mode_bits_must_agree() {
    conflict(|f| f.mode_extra |= 1 << 4, GlobalFlags::empty(), false); // HIDDEN_ATTR
    conflict(|f| f.mode_extra |= 1 << 14, GlobalFlags::empty(), false); // ATOMIC_WRITE
    conflict(|f| f.mode_extra |= 1 << 15, GlobalFlags::empty(), false); // FORCE_SYNC
    // OP_CODE and encryption/compression are rejected earlier by the entry decoder
    // (Unsupported by default), so they are covered by the collector invariant only.
}

#[test]
fn loss_tolerant_mismatch_is_conflict_not_gap() {
    conflict(|f| f.mode_extra &= !LOSS, GlobalFlags::empty(), true);
    let (a, mut b) = pair();
    b.mode_extra |= LOSS;
    assert!(matches!(
        read(build(&[a, b]), true),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn class_g_stream_id_and_ext_metadata_must_agree() {
    conflict(|f| f.stream_id = 7, GlobalFlags::empty(), false);
    conflict(|f| f.uid_gid = 9, GlobalFlags::EXT_UID_GID, false);
    conflict(|f| f.timestamps = [1, 2, 3], GlobalFlags::EXT_TIME, false);
    conflict(|f| f.permissions = 0o644, GlobalFlags::HAS_PERMS, false);
}

#[test]
fn conflicts_remain_fatal_under_loss_tolerant() {
    conflict(|f| f.permissions = 0o644, GlobalFlags::HAS_PERMS, true);
    conflict(|f| f.mode_extra |= 1 << 4, GlobalFlags::empty(), true);
}

// --- Completion-authoritative integrity -------------------------------------

#[test]
fn terminal_crc_is_authoritative() {
    let (a, mut b) = pair();
    b.crc = crc32fast::hash(b"AAAABBBB");
    let files = read(build_with(GlobalFlags::PER_FILE_CRC, &[a, b]), false).expect("valid");
    assert_eq!(files[0].data, b"AAAABBBB");
}

#[test]
fn wrong_terminal_crc_is_crc_mismatch_even_if_index0_has_correct_value() {
    let (mut a, mut b) = pair();
    a.crc = 0; // neutral
    b.crc = crc32fast::hash(b"AAAABBBB") ^ 1;
    assert!(matches!(
        read(build_with(GlobalFlags::PER_FILE_CRC, &[a, b]), false),
        Err(SarError::CrcMismatch(_))
    ));
}

#[test]
fn nonzero_nonterminal_crc_is_metadata_conflict() {
    let (mut a, mut b) = pair();
    a.crc = crc32fast::hash(b"AAAABBBB");
    b.crc = a.crc;
    assert!(matches!(
        read(build_with(GlobalFlags::PER_FILE_CRC, &[a, b]), false),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn nonzero_nonterminal_content_hash_is_metadata_conflict() {
    let (mut a, b) = pair();
    a.hash = [1; 32];
    assert!(matches!(
        read(build_with(GlobalFlags::DEDUPLICATION, &[a, b]), false),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn zero_terminal_integrity_values_are_valid() {
    let (a, mut b) = pair();
    // Zero terminal CRC is authoritative; payload CRC is not zero, so this is a mismatch.
    b.crc = 0;
    assert!(matches!(
        read(
            build_with(GlobalFlags::PER_FILE_CRC, &[a.clone(), b.clone()]),
            false
        ),
        Err(SarError::CrcMismatch(_))
    ));
    // Zero Content Hash on all fragments is structurally valid.
    let files = read(build_with(GlobalFlags::DEDUPLICATION, &[a, b]), false).expect("valid");
    assert_eq!(files[0].data, b"AAAABBBB");
}

#[test]
fn degraded_output_is_not_crc_verified() {
    let (mut a, mut b) = pair();
    a.mode_extra |= LOSS;
    b.mode_extra |= LOSS;
    b.index = 2; // missing index 1
    b.crc = 0xDEAD_BEEF;
    let files = read(build_with(GlobalFlags::PER_FILE_CRC, &[a, b]), true).expect("degraded");
    assert!(files[0].is_degraded);
    assert_eq!(files[0].data, b"AAAA");
}

// --- Gaps and later-fragment Sparse Map -------------------------------------

#[test]
fn gaps_without_loss_tolerant_are_fragment_gap() {
    let (_, b) = pair();
    // Missing Index 0.
    assert!(read(build(std::slice::from_ref(&b)), false).is_err());
    // Interior gap.
    let mut c = b.clone();
    c.index = 2;
    assert!(matches!(
        read(build(&[frag(1, 0, false, "f.bin", b"A"), c]), false),
        Err(SarError::FragmentGap(_))
    ));
    // Missing terminal.
    assert!(matches!(
        read(build(&[frag(1, 0, false, "f.bin", b"A")]), false),
        Err(SarError::FragmentGap(_))
    ));
}

#[test]
fn later_fragment_sparse_map_is_metadata_conflict_even_if_malformed() {
    for map in [vec![0xFF; 3], vec![1, 0, 0, 0]] {
        let (a, mut b) = pair();
        b.sparse_map = map;
        let flags = GlobalFlags::SPARSE_FILES;
        assert!(matches!(
            read(build_with(flags, &[a, b]), false),
            Err(SarError::MetadataConflict(_))
        ));
    }
}

// --- Streaming iteration and retention budget -------------------------------

fn with_plain_entries(group_first: &'static [u8], plain: &[(&str, usize)]) -> Vec<u8> {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let header = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header");
    let mut archive = header.clone();
    let g0 = build(&[frag(9, 0, false, "g.bin", group_first)]);
    archive.extend_from_slice(&g0[header.len()..]);
    for (name, len) in plain {
        let mut l = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), *len as u64);
        l.uncompressed_size = *len as u64;
        archive.extend_from_slice(&write_lfh(&flags, &l).expect("lfh"));
        archive.extend_from_slice(&vec![1u8; *len]);
    }
    archive
}

#[test]
fn next_logical_entry_yields_canonical_order_then_ends() {
    let mut archive = with_plain_entries(b"G0", &[("c.bin", 3)]);
    let header_len = build(&[]).len();
    let tail = build(&[frag(9, 1, true, "", b"G1")]);
    archive.extend_from_slice(&tail[header_len..]);
    let mut reader = ArchiveReader::new(Cursor::new(archive)).expect("reader");
    let mut names = Vec::new();
    while let Some(item) = reader.next_logical_entry().expect("item") {
        names.push(match item {
            sar_archive::fragment_group::CollectedEntry::Entry(e) => e.metadata.name.clone(),
            sar_archive::fragment_group::CollectedEntry::Group(g) => g.name.clone(),
        });
    }
    assert_eq!(names, ["g.bin", "c.bin"]);
    assert!(reader.next_logical_entry().expect("ended").is_none());
}

#[test]
fn entries_blocked_by_incomplete_group_beyond_budget_fail_closed() {
    let archive = with_plain_entries(&[0u8; 1000], &[("a", 1000), ("b", 1000), ("c", 1000)]);
    let limits = sar_core::ResourceLimits {
        max_total_pipeline_memory: 2_500,
        ..sar_core::ResourceLimits::default()
    };
    let mut reader = ArchiveReader::with_options(
        Cursor::new(archive),
        sar_archive::ArchiveReaderOptions {
            limits,
            delta_base: None,
        },
    )
    .expect("reader");
    assert!(matches!(
        reader.read_all_logical_files(true),
        Err(SarError::LimitExceeded(_))
    ));
}
