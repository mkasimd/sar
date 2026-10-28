// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Collector-level tests: streaming release, bounded retention, terminal
//! Content Hash authority, and Class G active-versus-inert semantics.
//!
//! Entries are decoded from real archives through the production reader.
//! Class G cases that the production decoder rejects earlier (non-zero
//! `OP_CODE`, algorithm IDs that need global flags) mutate the decoded LFH
//! after decoding so the collector layer is exercised in isolation.

use std::io::Cursor;

use sar_core::{
    GlobalFlags, SarError,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};

use super::{CollectedEntry, FragmentGroupCollector};
use crate::archive::{ArchiveReader, EntryReader};

const FRAG: u16 = 1 << 5;
const LAST: u16 = 1 << 6;

enum Spec {
    Plain(&'static str, usize),
    Frag {
        id: u32,
        index: u32,
        last: bool,
        name: &'static str,
        len: usize,
        hash: [u8; 32],
    },
}

fn frag(id: u32, index: u32, last: bool, name: &'static str, len: usize) -> Spec {
    Spec::Frag {
        id,
        index,
        last,
        name,
        len,
        hash: [0; 32],
    }
}

fn decode(flags: GlobalFlags, specs: &[Spec]) -> Vec<EntryReader> {
    let flags = flags | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut out = write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("global header");
    for spec in specs {
        let (name, len, bits, id, index, hash) = match spec {
            Spec::Plain(name, len) => (*name, *len, 0, None, None, [0; 32]),
            Spec::Frag {
                id,
                index,
                last,
                name,
                len,
                hash,
            } => (
                *name,
                *len,
                FRAG | if *last { LAST } else { 0 },
                Some(*id),
                Some(*index),
                *hash,
            ),
        };
        let mut lfh = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), len as u64);
        lfh.entry_mode = EntryMode::from_bits(bits);
        lfh.fragment_id = id;
        lfh.fragment_index = index;
        lfh.file_crc32 = Some(0);
        lfh.hash_algo_id = Some(0x31);
        lfh.content_hash = Some(hash);
        lfh.uid_gid = Some(0);
        lfh.timestamps = Some([0; 3]);
        lfh.permissions = Some(0);
        out.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
        out.extend_from_slice(&vec![0xAB; len]);
    }
    let mut reader = ArchiveReader::new(Cursor::new(out)).expect("reader");
    reader.read_global_header().expect("global header");
    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry().expect("entry") {
        entries.push(entry);
    }
    entries
}

fn drain(collector: &mut FragmentGroupCollector) -> Vec<CollectedEntry> {
    let mut out = Vec::new();
    while let Some(item) = collector.next_ready().expect("next_ready") {
        out.push(item);
    }
    out
}

fn label(item: &CollectedEntry) -> String {
    match item {
        CollectedEntry::Entry(e) => e.metadata.name.clone(),
        CollectedEntry::Group(g) => g.name.clone(),
    }
}

fn push_all(entries: Vec<EntryReader>) -> Result<(), SarError> {
    let mut collector = FragmentGroupCollector::new(sar_core::ResourceLimits::default());
    for entry in entries {
        collector.push(entry)?;
    }
    Ok(())
}

// --- Streaming release and bounded retention --------------------------------

#[test]
fn ordinary_entries_are_released_immediately_with_bounded_retention() {
    let specs: Vec<Spec> = (0..200).map(|_| Spec::Plain("p.bin", 1024)).collect();
    let mut collector = FragmentGroupCollector::new(sar_core::ResourceLimits::default());
    let mut emitted = 0;
    for entry in decode(GlobalFlags::empty(), &specs) {
        collector.push(entry).expect("push");
        let items = drain(&mut collector);
        assert_eq!(items.len(), 1, "released before the next push");
        assert_eq!(collector.retained_bytes(), 0);
        emitted += 1;
    }
    assert_eq!(emitted, 200);
    // Retention never exceeds one Entry although the archive carries 200 KiB.
    assert_eq!(collector.peak_retained_bytes(), 1024);
}

#[test]
fn incomplete_group_blocks_later_entries_then_releases_in_canonical_order() {
    let entries = decode(
        GlobalFlags::empty(),
        &[
            Spec::Plain("A", 10),
            frag(7, 0, false, "B", 100),
            Spec::Plain("C", 20),
            frag(7, 1, true, "", 100),
            Spec::Plain("D", 30),
        ],
    );
    let mut it = entries.into_iter();
    let mut collector = FragmentGroupCollector::new(sar_core::ResourceLimits::default());

    collector.push(it.next().expect("A")).expect("A");
    assert_eq!(label(&drain(&mut collector)[0]), "A");
    assert_eq!(collector.retained_bytes(), 0);

    collector.push(it.next().expect("B0")).expect("B0");
    assert!(drain(&mut collector).is_empty());
    assert_eq!(collector.retained_bytes(), 100);

    collector.push(it.next().expect("C")).expect("C");
    assert!(drain(&mut collector).is_empty(), "C must not precede B");
    assert_eq!(collector.retained_bytes(), 120);

    collector.push(it.next().expect("B1")).expect("B1");
    let released = drain(&mut collector);
    let labels: Vec<_> = released.iter().map(label).collect();
    assert_eq!(labels, ["B", "C"]);
    assert_eq!(collector.retained_bytes(), 0, "consumed payloads released");

    collector.push(it.next().expect("D")).expect("D");
    assert_eq!(label(&drain(&mut collector)[0]), "D");
    assert_eq!(collector.retained_bytes(), 0);
}

#[test]
fn retention_beyond_budget_behind_incomplete_group_fails_closed() {
    let limits = sar_core::ResourceLimits {
        max_total_pipeline_memory: 2_500,
        ..sar_core::ResourceLimits::default()
    };
    let mut collector = FragmentGroupCollector::new(limits);
    let mut specs = vec![frag(1, 0, false, "G", 1_000)];
    specs.extend((0..10).map(|_| Spec::Plain("p", 1_000)));
    let mut result = Ok(());
    let mut pushed = 0;
    for entry in decode(GlobalFlags::empty(), &specs) {
        result = collector.push(entry);
        if result.is_err() {
            break;
        }
        pushed += 1;
        assert!(drain(&mut collector).is_empty());
    }
    assert!(matches!(result, Err(SarError::LimitExceeded(_))));
    assert_eq!(pushed, 2, "group fragment plus one blocked Entry fit");
    assert!(collector.retained_bytes() <= 2_500);
}

#[test]
fn fragment_after_released_complete_group_is_metadata_conflict() {
    let mut entries = decode(
        GlobalFlags::empty(),
        &[
            frag(1, 0, false, "G", 4),
            frag(1, 1, true, "", 4),
            frag(1, 2, true, "", 4),
        ],
    )
    .into_iter();
    let mut collector = FragmentGroupCollector::new(sar_core::ResourceLimits::default());
    collector.push(entries.next().expect("0")).expect("0");
    collector.push(entries.next().expect("1")).expect("1");
    assert_eq!(drain(&mut collector).len(), 1);
    assert!(matches!(
        collector.push(entries.next().expect("2")),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn incomplete_group_is_released_after_input_finished() {
    let entries = decode(
        GlobalFlags::empty(),
        &[frag(1, 0, false, "G", 4), Spec::Plain("P", 4)],
    );
    let mut collector = FragmentGroupCollector::new(sar_core::ResourceLimits::default());
    for entry in entries {
        collector.push(entry).expect("push");
        assert!(drain(&mut collector).is_empty());
    }
    collector.finish_input();
    let labels: Vec<_> = drain(&mut collector).iter().map(label).collect();
    assert_eq!(labels, ["G", "P"]);
    assert_eq!(collector.retained_bytes(), 0);
}

// --- Terminal Content Hash authority ----------------------------------------

fn hash_group(first: [u8; 32], last: [u8; 32]) -> Vec<EntryReader> {
    decode(
        GlobalFlags::DEDUPLICATION,
        &[
            Spec::Frag {
                id: 1,
                index: 0,
                last: false,
                name: "f",
                len: 4,
                hash: first,
            },
            Spec::Frag {
                id: 1,
                index: 1,
                last: true,
                name: "",
                len: 4,
                hash: last,
            },
        ],
    )
}

fn terminal_hash(entries: Vec<EntryReader>) -> Option<[u8; 32]> {
    let mut collector = FragmentGroupCollector::new(sar_core::ResourceLimits::default());
    for entry in entries {
        collector.push(entry).expect("push");
    }
    match drain(&mut collector).pop().expect("group") {
        CollectedEntry::Group(group) => group.terminal_content_hash,
        CollectedEntry::Entry(_) => panic!("expected group"),
    }
}

#[test]
fn terminal_nonzero_content_hash_is_retained() {
    assert_eq!(terminal_hash(hash_group([0; 32], [7; 32])), Some([7; 32]));
}

#[test]
fn terminal_all_zero_content_hash_is_retained_as_authoritative() {
    assert_eq!(terminal_hash(hash_group([0; 32], [0; 32])), Some([0; 32]));
}

#[test]
fn non_terminal_nonzero_content_hash_is_metadata_conflict() {
    assert!(matches!(
        push_all(hash_group([9; 32], [7; 32])),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn matching_hash_algo_ids_are_accepted() {
    let mut entries = hash_group([0; 32], [7; 32]);
    for entry in &mut entries {
        entry.header.hash_algo_id = Some(0x30);
    }
    assert!(push_all(entries).is_ok());
}

#[test]
fn conflicting_hash_algo_ids_are_metadata_conflict() {
    let mut entries = hash_group([0; 32], [7; 32]);
    entries[1].header.hash_algo_id = Some(0x30);
    assert!(matches!(
        push_all(entries),
        Err(SarError::MetadataConflict(_))
    ));
}

// --- Class G active versus inert fields -------------------------------------

fn pair() -> Vec<EntryReader> {
    decode(
        GlobalFlags::empty(),
        &[frag(1, 0, false, "f", 4), frag(1, 1, true, "", 4)],
    )
}

fn with_second(mutate: impl FnOnce(&mut LocalFileHeader)) -> Result<(), SarError> {
    let mut entries = pair();
    mutate(&mut entries[1].header);
    push_all(entries)
}

fn with_both(
    first: impl FnOnce(&mut LocalFileHeader),
    second: impl FnOnce(&mut LocalFileHeader),
) -> Result<(), SarError> {
    let mut entries = pair();
    first(&mut entries[0].header);
    second(&mut entries[1].header);
    push_all(entries)
}

fn set_bits(header: &mut LocalFileHeader, extra: u16) {
    header.entry_mode = EntryMode::from_bits(header.entry_mode.bits() | extra);
}

#[test]
fn matching_active_compression_algorithms_are_accepted() {
    let set = |h: &mut LocalFileHeader| {
        set_bits(h, EntryMode::COMPRESSED);
        h.comp_algo_id = Some(1);
    };
    assert!(with_both(set, set).is_ok());
}

#[test]
fn conflicting_active_compression_algorithms_are_metadata_conflict() {
    let result = with_both(
        |h| {
            set_bits(h, EntryMode::COMPRESSED);
            h.comp_algo_id = Some(1);
        },
        |h| {
            set_bits(h, EntryMode::COMPRESSED);
            h.comp_algo_id = Some(2);
        },
    );
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
}

#[test]
fn inert_compression_algorithm_difference_is_accepted() {
    // IS_COMPRESSED is clear on both fragments, so the field is inactive.
    let result = with_both(|h| h.comp_algo_id = Some(1), |h| h.comp_algo_id = Some(2));
    assert!(result.is_ok());
}

#[test]
fn matching_active_encryption_algorithms_are_accepted() {
    let set = |h: &mut LocalFileHeader| {
        set_bits(h, EntryMode::ENCRYPTED);
        h.encr_algo_id = Some(1);
    };
    assert!(with_both(set, set).is_ok());
}

#[test]
fn conflicting_active_encryption_algorithms_are_metadata_conflict() {
    let result = with_both(
        |h| {
            set_bits(h, EntryMode::ENCRYPTED);
            h.encr_algo_id = Some(1);
        },
        |h| {
            set_bits(h, EntryMode::ENCRYPTED);
            h.encr_algo_id = Some(2);
        },
    );
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
}

#[test]
fn inert_encryption_algorithm_difference_is_accepted() {
    let result = with_both(|h| h.encr_algo_id = Some(1), |h| h.encr_algo_id = Some(2));
    assert!(result.is_ok());
}

#[test]
fn active_versus_inert_mode_bit_difference_is_metadata_conflict() {
    let result = with_second(|h| set_bits(h, EntryMode::COMPRESSED));
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
    let result = with_second(|h| set_bits(h, EntryMode::ENCRYPTED));
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
}

#[test]
fn patch_and_cdc_algorithm_ids_must_agree() {
    let result = with_both(|h| h.patch_algo_id = Some(0), |h| h.patch_algo_id = Some(1));
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
    let result = with_both(|h| h.cdc_algo_id = Some(0), |h| h.cdc_algo_id = Some(1));
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
    let same = |h: &mut LocalFileHeader| {
        h.patch_algo_id = Some(0);
        h.cdc_algo_id = Some(0);
    };
    assert!(with_both(same, same).is_ok());
}

#[test]
fn delta_base_hash_must_agree() {
    let result = with_both(
        |h| h.delta_base_hash = Some([1; 32]),
        |h| h.delta_base_hash = Some([2; 32]),
    );
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
    let same = |h: &mut LocalFileHeader| h.delta_base_hash = Some([1; 32]);
    assert!(with_both(same, same).is_ok());
}

#[test]
fn op_code_must_agree_across_the_group() {
    // The production decoder rejects a non-zero OP_CODE earlier, so the
    // mismatch is only reachable by mutating the decoded LFH.
    let result = with_second(|h| set_bits(h, 0x0100));
    assert!(matches!(result, Err(SarError::MetadataConflict(_))));
    let same = |h: &mut LocalFileHeader| set_bits(h, 0x0100);
    assert!(with_both(same, same).is_ok());
}
