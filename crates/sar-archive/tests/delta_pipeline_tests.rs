// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Canonical delta/CDC transformation pipeline (spec §6.1.2, §8.4, §13.1, §20.3).
//!
//! Fragment-local stages yield decoded contributions whose lengths equal each
//! LFH `Uncompressed Size`; contributions are concatenated in Fragment Index
//! order; the patch is applied exactly once to the complete representation;
//! CDC resolution (unsupported unless literal) follows the patch.

use std::io::Cursor;

use sar_archive::{ArchiveReader, ArchiveReaderOptions, StreamArchiveParser, StreamEvent};
use sar_core::{
    GlobalFlags, ResourceLimits, SarError,
    flags::EntryMode,
    format::{GlobalHeader, LocalFileHeader, write_global_header, write_lfh},
};
use sar_delta::{apply_vcdiff, bsdiff::BsdiffLimits, generate_bsdiff_patch, vcdiff::VcdiffLimits};

const HASH: [u8; 32] = [0xA5; 32];
const PATCH_STORE: u8 = 0x00;
const PATCH_VCDIFF: u8 = 0x01;
const PATCH_BSDIFF: u8 = 0x02;

fn varint(mut v: u64) -> Vec<u8> {
    let mut buf = vec![(v & 0x7F) as u8];
    v >>= 7;
    while v > 0 {
        buf.push((v & 0x7F) as u8 | 0x80);
        v >>= 7;
    }
    buf.reverse();
    buf
}

/// VCDIFF patch that emits `target` through one ADD instruction.
fn vcdiff_add_patch(target: &[u8]) -> Vec<u8> {
    let mut inst = vec![0x01u8];
    inst.extend(varint(target.len() as u64));
    let mut body = varint(target.len() as u64);
    body.push(0x00);
    body.extend(varint(target.len() as u64));
    body.extend(varint(inst.len() as u64));
    body.extend(varint(0));
    body.extend_from_slice(target);
    body.extend_from_slice(&inst);
    let mut patch = b"\xD6\xC3\xC4\x00\x00\x00".to_vec();
    patch.extend(varint(body.len() as u64));
    patch.extend(body);
    patch
}

struct Frag<'a> {
    index: u32,
    last: bool,
    payload: &'a [u8],
}

struct Spec {
    patch_algo: Option<u8>,
    base_hash: [u8; 32],
    cdc: Option<u8>,
}

fn delta(patch_algo: u8) -> Spec {
    Spec {
        patch_algo: Some(patch_algo),
        base_hash: HASH,
        cdc: None,
    }
}

fn flags(spec: &Spec, fragmented: bool) -> GlobalFlags {
    let mut f = GlobalFlags::NO_INDEX;
    if spec.patch_algo.is_some() {
        f |= GlobalFlags::HAS_DELTA;
    }
    if spec.cdc.is_some() {
        f |= GlobalFlags::CDC_SUPPORT;
    }
    if fragmented {
        f |= GlobalFlags::FILE_FRAGMENTATION;
    }
    f
}

fn lfh_for(spec: &Spec, name: &[u8], size: usize) -> LocalFileHeader {
    let mut lfh = LocalFileHeader::minimal_store(name.to_vec(), size as u64);
    lfh.patch_algo_id = spec.patch_algo;
    if spec.patch_algo.is_some() {
        lfh.delta_base_hash = Some(spec.base_hash);
    }
    lfh.cdc_algo_id = spec.cdc;
    lfh
}

fn header(flags: GlobalFlags) -> Vec<u8> {
    write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("header")
}

fn unfragmented(spec: &Spec, payload: &[u8]) -> Vec<u8> {
    let f = flags(spec, false);
    let mut out = header(f);
    out.extend(write_lfh(&f, &lfh_for(spec, b"f.bin", payload.len())).expect("lfh"));
    out.extend_from_slice(payload);
    out
}

fn fragmented(spec: &Spec, loss_tolerant: bool, frags: &[Frag]) -> Vec<u8> {
    let f = flags(spec, true);
    let mut out = header(f);
    for frag in frags {
        let mut mode = EntryMode::FRAGMENT;
        if frag.last {
            mode |= EntryMode::LAST_FRAGMENT;
        }
        if loss_tolerant {
            mode |= EntryMode::LOSS_TOLERANT;
        }
        let mut lfh = lfh_for(spec, b"f.bin", frag.payload.len());
        lfh.entry_mode = EntryMode::from_bits(mode);
        lfh.fragment_id = Some(7);
        lfh.fragment_index = Some(frag.index);
        out.extend(write_lfh(&f, &lfh).expect("lfh"));
        out.extend_from_slice(frag.payload);
    }
    out
}

fn options(base: Option<&[u8]>) -> ArchiveReaderOptions {
    ArchiveReaderOptions {
        limits: ResourceLimits::unlimited(),
        delta_base: base.map(<[u8]>::to_vec),
    }
}

fn read_all(
    archive: Vec<u8>,
    opts: ArchiveReaderOptions,
    lossy: bool,
) -> Result<Vec<u8>, SarError> {
    let mut reader = ArchiveReader::with_options(Cursor::new(archive), opts)?;
    let mut files = reader.read_all_logical_files(lossy)?;
    Ok(files.remove(0).data)
}

fn two(payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (a, b) = payload.split_at(payload.len() / 2);
    (a.to_vec(), b.to_vec())
}

fn split_frags<'a>(a: &'a [u8], b: &'a [u8]) -> [Frag<'a>; 2] {
    [
        Frag {
            index: 0,
            last: false,
            payload: a,
        },
        Frag {
            index: 1,
            last: true,
            payload: b,
        },
    ]
}

fn target() -> Vec<u8> {
    (0..200u32).map(|i| (i % 251) as u8).collect()
}

#[test]
fn unfragmented_vcdiff_lfh_size_is_patch_size_not_output_size() {
    let t = target();
    let patch = vcdiff_add_patch(&t);
    assert_ne!(patch.len(), t.len());
    let archive = unfragmented(&delta(PATCH_VCDIFF), &patch);
    let mut reader =
        ArchiveReader::with_options(Cursor::new(archive), options(Some(b"base"))).expect("reader");
    reader.read_global_header().expect("hdr");
    let entry = reader.next_entry().expect("entry").expect("some");
    assert_eq!(entry.metadata.uncompressed_size, patch.len() as u64);
    assert_eq!(entry.payload, t);
}

#[test]
fn unfragmented_bsdiff_lfh_size_is_patch_size_not_output_size() {
    let base = b"the quick brown fox".repeat(4);
    let t = b"the quick brown cat jumps".repeat(3);
    let patch = generate_bsdiff_patch(&base, &t, &BsdiffLimits::unlimited()).expect("gen");
    assert_ne!(patch.len(), t.len());
    let archive = unfragmented(&delta(PATCH_BSDIFF), &patch);
    assert_eq!(
        read_all(archive, options(Some(&base)), false).expect("ok"),
        t
    );
}

#[test]
fn fragmented_vcdiff_is_applied_once_after_reassembly() {
    let t = target();
    let patch = vcdiff_add_patch(&t);
    let (a, b) = two(&patch);
    // Neither half is a valid VCDIFF stream, so per-fragment application would fail.
    assert!(apply_vcdiff(b"base", &a, &VcdiffLimits::unlimited()).is_err());
    let archive = fragmented(&delta(PATCH_VCDIFF), false, &split_frags(&a, &b));
    for lossy in [false, true] {
        assert_eq!(
            read_all(archive.clone(), options(Some(b"base")), lossy).expect("ok"),
            t
        );
    }
}

#[test]
fn fragmented_bsdiff_three_fragments_applied_once() {
    let base = b"0123456789abcdef".repeat(8);
    let mut t = base.clone();
    t[10] ^= 0xFF;
    t.extend_from_slice(b"tail");
    let patch = generate_bsdiff_patch(&base, &t, &BsdiffLimits::unlimited()).expect("gen");
    let n = patch.len() / 3;
    let frags = [
        Frag {
            index: 0,
            last: false,
            payload: &patch[..n],
        },
        Frag {
            index: 1,
            last: false,
            payload: &patch[n..2 * n],
        },
        Frag {
            index: 2,
            last: true,
            payload: &patch[2 * n..],
        },
    ];
    let archive = fragmented(&delta(PATCH_BSDIFF), false, &frags);
    assert_eq!(
        read_all(archive, options(Some(&base)), false).expect("ok"),
        t
    );
}

#[test]
fn fragmented_store_patch_concatenates_contributions() {
    let t = target();
    let (a, b) = two(&t);
    let mut spec = delta(PATCH_STORE);
    spec.base_hash = [0u8; 32];
    let archive = fragmented(&spec, false, &split_frags(&a, &b));
    assert_eq!(read_all(archive, options(None), false).expect("ok"), t);
}

#[test]
fn incomplete_delta_group_is_fragment_gap_even_when_loss_tolerant() {
    let patch = vcdiff_add_patch(&target());
    let (a, b) = two(&patch);
    for (algo, lossy_flag) in [
        (PATCH_VCDIFF, false),
        (PATCH_VCDIFF, true),
        (PATCH_STORE, true),
    ] {
        let mut spec = delta(algo);
        if algo == PATCH_STORE {
            spec.base_hash = [0u8; 32];
        }
        // Fragment Index 1 is missing; index 2 is terminal.
        let frags = [
            Frag {
                index: 0,
                last: false,
                payload: &a,
            },
            Frag {
                index: 2,
                last: true,
                payload: &b,
            },
        ];
        let archive = fragmented(&spec, lossy_flag, &frags);
        for allow in [false, true] {
            let err = read_all(archive.clone(), options(Some(b"base")), allow).expect_err("gap");
            assert!(matches!(err, SarError::FragmentGap(_)), "{err:?}");
        }
    }
}

#[test]
fn missing_base_and_zero_hash_are_base_missing() {
    let patch = vcdiff_add_patch(&target());
    let (a, b) = two(&patch);
    for archive in [
        unfragmented(&delta(PATCH_VCDIFF), &patch),
        fragmented(&delta(PATCH_VCDIFF), false, &split_frags(&a, &b)),
    ] {
        let err = read_all(archive, options(None), false).expect_err("no base");
        assert!(matches!(err, SarError::BaseMissing(_)), "{err:?}");
    }
    let mut zero = delta(PATCH_VCDIFF);
    zero.base_hash = [0u8; 32];
    let err = read_all(unfragmented(&zero, &patch), options(Some(b"base")), false)
        .expect_err("zero hash");
    assert!(matches!(err, SarError::BaseMissing(_)), "{err:?}");
}

#[test]
fn malformed_patch_fails_even_when_loss_tolerant() {
    let patch = vcdiff_add_patch(&target());
    let truncated = &patch[..patch.len() - 5];
    let (a, b) = two(truncated);
    let archive = fragmented(&delta(PATCH_VCDIFF), true, &split_frags(&a, &b));
    let err = read_all(archive, options(Some(b"base")), true).expect_err("bad patch");
    assert!(matches!(err, SarError::PatchFailed(_)), "{err:?}");
}

#[test]
fn patch_output_bound_is_enforced_before_release() {
    let t = target();
    let patch = vcdiff_add_patch(&t);
    let (a, b) = two(&patch);
    let archive = fragmented(&delta(PATCH_VCDIFF), false, &split_frags(&a, &b));
    let tight = ArchiveReaderOptions {
        limits: ResourceLimits {
            max_decoded_entry_size: t.len() as u64 - 1,
            ..ResourceLimits::unlimited()
        },
        delta_base: Some(b"base".to_vec()),
    };
    let err = read_all(archive.clone(), tight, false).expect_err("limit");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");

    // Patch input plus patch output must fit max_total_pipeline_memory.
    let budget = ArchiveReaderOptions {
        limits: ResourceLimits {
            max_total_pipeline_memory: patch.len() as u64 + t.len() as u64 - 1,
            ..ResourceLimits::unlimited()
        },
        delta_base: Some(b"base".to_vec()),
    };
    let err = read_all(archive, budget, false).expect_err("budget");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

#[test]
fn non_literal_cdc_without_catalog_is_unresolvable_unfragmented_and_fragmented() {
    let spec = Spec {
        patch_algo: None,
        base_hash: [0u8; 32],
        cdc: Some(0x02),
    };
    let err =
        read_all(unfragmented(&spec, b"recipe-bytes"), options(None), false).expect_err("cdc");
    // No catalog and no resolver: the Recipe is unresolvable, not unsupported.
    assert!(matches!(err, SarError::RecipeUnresolvable(_)), "{err:?}");

    let frags = split_frags(b"recipe", b"-bytes");
    let archive = fragmented(&spec, false, &frags);
    let err = read_all(archive, options(None), false).expect_err("cdc frag");
    assert!(matches!(err, SarError::RecipeUnresolvable(_)), "{err:?}");

    // An incomplete recipe is a gap before it is ever interpreted.
    let gap = [
        Frag {
            index: 0,
            last: false,
            payload: b"recipe",
        },
        Frag {
            index: 2,
            last: true,
            payload: b"-bytes",
        },
    ];
    for lossy in [false, true] {
        let err =
            read_all(fragmented(&spec, lossy, &gap), options(None), true).expect_err("cdc gap");
        assert!(matches!(err, SarError::FragmentGap(_)), "{err:?}");
    }
}

#[test]
fn literal_cdc_after_patch_is_supported() {
    let mut spec = delta(PATCH_STORE);
    spec.base_hash = [0u8; 32];
    spec.cdc = Some(0x00);
    let t = target();
    assert_eq!(
        read_all(unfragmented(&spec, &t), options(None), false).expect("ok"),
        t
    );
}

#[test]
fn delta_patch_then_non_literal_cdc_is_unresolvable_without_catalog() {
    let mut spec = delta(PATCH_STORE);
    spec.base_hash = [0u8; 32];
    spec.cdc = Some(0x02);
    let err = read_all(unfragmented(&spec, b"abc"), options(None), false).expect_err("cdc");
    assert!(matches!(err, SarError::RecipeUnresolvable(_)), "{err:?}");
}

fn stream_first_entry(archive: &[u8], opts: ArchiveReaderOptions) -> Result<Vec<u8>, SarError> {
    let mut parser = StreamArchiveParser::with_options(opts);
    parser.push_bytes(archive)?;
    parser.finalize_input();
    loop {
        match parser.step()? {
            sar_archive::StreamStep::Ready(StreamEvent::Entry(entry)) => return Ok(entry.payload),
            sar_archive::StreamStep::Complete => return Err(SarError::NotFound("entry")),
            _ => {}
        }
    }
}

#[test]
fn stream_parser_matches_archive_reader() {
    let t = target();
    let patch = vcdiff_add_patch(&t);
    let archive = unfragmented(&delta(PATCH_VCDIFF), &patch);
    assert_eq!(
        stream_first_entry(&archive, options(Some(b"base"))).expect("ok"),
        t
    );
    let err = stream_first_entry(&archive, options(None)).expect_err("no base");
    assert!(matches!(err, SarError::BaseMissing(_)), "{err:?}");

    let spec = Spec {
        patch_algo: None,
        base_hash: [0u8; 32],
        cdc: Some(0x02),
    };
    let err = stream_first_entry(&unfragmented(&spec, b"recipe"), options(None)).expect_err("cdc");
    assert!(matches!(err, SarError::Unsupported(_)), "{err:?}");
}

#[test]
fn sparse_reconstruction_follows_patch_application() {
    use sar_core::sparse::{SparseExtent, SparseMap, write_sparse_map};

    let map = write_sparse_map(
        &SparseMap {
            logical_size: 12,
            extents: vec![SparseExtent {
                offset: 4,
                length: 4,
            }],
        },
        false,
    )
    .expect("map");
    let mut spec = delta(PATCH_STORE);
    spec.base_hash = [0u8; 32];
    let mut f = flags(&spec, false);
    f |= GlobalFlags::SPARSE_FILES;
    let mut out = header(f);
    let mut lfh = lfh_for(&spec, b"s.bin", 4);
    lfh.sparse_map = map;
    out.extend(write_lfh(&f, &lfh).expect("lfh"));
    out.extend_from_slice(b"AAAA");

    let mut expected = vec![0u8; 12];
    expected[4..8].copy_from_slice(b"AAAA");
    assert_eq!(read_all(out, options(None), false).expect("ok"), expected);
}
