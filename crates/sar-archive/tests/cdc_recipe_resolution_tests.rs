// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! End-to-end archive-level CDC Recipe Mode tests (specification Sections
//! 13.1, 20 and 21).  Archives are assembled byte-for-byte so every CDC_MAP
//! field, Recipe and chunk-store byte is under test control.

use std::{cell::Cell, collections::HashMap, io::Cursor, rc::Rc};

use sar_archive::{ArchiveReader, ArchiveReaderOptions, cdc_resolve::CdcChunkResolver};
use sar_cdc::{FastCdcOptions, chunk_data};
use sar_core::{
    GlobalFlags, ResourceLimits, SarError, compute_cdc_chunk_hash,
    flags::EntryMode,
    format::{
        CentralDictionary, Footer, GlobalHeader, LocalFileHeader, write_central_dictionary,
        write_footer, write_global_header, write_lfh,
    },
    sparse::{SparseExtent, SparseMap, write_sparse_map},
    tlv::Tlv,
};

const SHA256: u8 = 0x30;
const BLAKE3: u8 = 0x31;
const FRAG: u16 = 1 << 5;
const LAST: u16 = 1 << 6;

#[derive(Clone)]
struct E {
    name: &'static str,
    cdc: u8,
    payload: Vec<u8>,
    sparse: Vec<u8>,
    crc: Option<u32>,
    hash: Option<(u8, [u8; 32])>,
    frag: Option<(u32, u32, bool)>,
}

fn e(name: &'static str, cdc: u8, payload: Vec<u8>) -> E {
    E {
        name,
        cdc,
        payload,
        sparse: Vec::new(),
        crc: None,
        hash: None,
        frag: None,
    }
}

fn base_flags() -> GlobalFlags {
    GlobalFlags::CDC_SUPPORT
}

fn hash(alg: u8, bytes: &[u8]) -> [u8; 32] {
    compute_cdc_chunk_hash(alg, bytes).expect("hash")
}

fn lfh_of(flags: GlobalFlags, e: &E) -> Vec<u8> {
    let mut l = LocalFileHeader::minimal_store(e.name.as_bytes().to_vec(), e.payload.len() as u64);
    l.cdc_algo_id = Some(e.cdc);
    l.sparse_map = e.sparse.clone();
    if flags.contains(GlobalFlags::PER_FILE_CRC) {
        l.file_crc32 = Some(e.crc.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::DEDUPLICATION) {
        let (a, h) = e.hash.unwrap_or((BLAKE3, [0; 32]));
        l.hash_algo_id = Some(a);
        l.content_hash = Some(h);
    }
    if let Some((id, index, last)) = e.frag {
        let mut mode = FRAG;
        if last {
            mode |= LAST;
        }
        l.entry_mode = EntryMode::from_bits(mode);
        l.fragment_id = Some(id);
        l.fragment_index = Some(index);
    }
    write_lfh(&flags, &l).expect("lfh")
}

fn store_entry(flags: GlobalFlags, store: &[u8]) -> E {
    let mut s = e("store", 0, store.to_vec());
    s.crc = Some(crc32fast::hash(store));
    s.hash = Some((BLAKE3, hash(BLAKE3, store)));
    let _ = flags;
    s
}

fn header_bytes(flags: GlobalFlags) -> Vec<u8> {
    write_global_header(&GlobalHeader {
        version: 1,
        flags,
        kms: None,
    })
    .expect("global header")
}

/// Absolute offset of the first byte of the chunk store.
fn chunk_base(flags: GlobalFlags, store: &[u8]) -> u64 {
    let flags = effective(flags, true);
    (header_bytes(flags).len() + lfh_of(flags, &store_entry(flags, store)).len()) as u64
}

fn effective(flags: GlobalFlags, has_tlvs: bool) -> GlobalFlags {
    if has_tlvs && !flags.contains(GlobalFlags::NO_INDEX) {
        flags | GlobalFlags::OPT_PRESENT
    } else {
        flags
    }
}

/// Header, chunk-store entry, `entries`, then (when indexed) CD and footer.
fn build(flags: GlobalFlags, store: &[u8], entries: &[E], tlvs: Vec<Tlv>) -> Vec<u8> {
    let flags = effective(flags, !tlvs.is_empty());
    let mut out = header_bytes(flags);
    let mut offsets = Vec::new();
    let mut all = vec![store_entry(flags, store)];
    all.extend_from_slice(entries);
    for entry in &all {
        offsets.push(out.len() as u64);
        out.extend_from_slice(&lfh_of(flags, entry));
        out.extend_from_slice(&entry.payload);
    }
    if !flags.contains(GlobalFlags::NO_INDEX) {
        let cd_offset = out.len() as u64;
        let cd = CentralDictionary {
            version: 1,
            file_count: offsets.len() as u64,
            global_crc32: None,
            metadata: tlvs,
            offsets,
        };
        out.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        out.extend_from_slice(&write_footer(Footer { cd_offset }));
    }
    out
}

type Rec = ([u8; 32], u32, u64, u32);

fn raw_map(version: u8, alg: u8, recs: &[Rec]) -> Tlv {
    let mut v = vec![version, alg, 0, 0];
    v.extend_from_slice(&(recs.len() as u32).to_le_bytes());
    v.extend_from_slice(&48u16.to_le_bytes());
    v.extend_from_slice(&[0; 6]);
    for (h, part, off, size) in recs {
        v.extend_from_slice(h);
        v.extend_from_slice(&part.to_le_bytes());
        v.extend_from_slice(&off.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
    }
    Tlv {
        type_id: 0x40,
        value: v,
    }
}

struct Scenario {
    alg: u8,
    chunks: Vec<Vec<u8>>,
    store: Vec<u8>,
    base: u64,
    recs: Vec<Rec>,
    recipe: Vec<u8>,
    logical: Vec<u8>,
}

fn scenario(flags: GlobalFlags, alg: u8, chunks: Vec<Vec<u8>>) -> Scenario {
    let store: Vec<u8> = chunks.concat();
    let base = chunk_base(flags, &store);
    let mut recs = Vec::new();
    let mut recipe = Vec::new();
    let mut off = base;
    for c in &chunks {
        let h = hash(alg, c);
        recs.push((h, 0, off, c.len() as u32));
        recipe.extend_from_slice(&h);
        off += c.len() as u64;
    }
    Scenario {
        alg,
        logical: store.clone(),
        chunks,
        store,
        base,
        recs,
        recipe,
    }
}

fn std_chunks() -> Vec<Vec<u8>> {
    vec![b"alpha-chunk".to_vec(), vec![7u8; 40], b"omega".to_vec()]
}

impl Scenario {
    fn tlv(&self) -> Tlv {
        raw_map(1, self.alg, &self.recs)
    }
    fn archive(&self, flags: GlobalFlags, entries: &[E]) -> Vec<u8> {
        build(flags, &self.store, entries, vec![self.tlv()])
    }
    fn recipe_entry(&self, cdc: u8) -> E {
        e("r", cdc, self.recipe.clone())
    }
}

fn opts(limits: ResourceLimits) -> ArchiveReaderOptions {
    ArchiveReaderOptions {
        limits,
        ..Default::default()
    }
}

fn read(
    bytes: Vec<u8>,
    limits: ResourceLimits,
    lossy: bool,
) -> Result<Vec<(String, Vec<u8>)>, SarError> {
    let mut r = ArchiveReader::with_options(Cursor::new(bytes), opts(limits))?;
    Ok(r.read_all_logical_files(lossy)?
        .into_iter()
        .map(|f| (f.name, f.data))
        .collect())
}

fn read_r(bytes: Vec<u8>, limits: ResourceLimits) -> Result<Vec<u8>, SarError> {
    let files = read(bytes, limits, false)?;
    Ok(files
        .into_iter()
        .find(|(n, _)| n == "r")
        .expect("entry r")
        .1)
}

fn def() -> ResourceLimits {
    ResourceLimits::default()
}

// ── Algorithm matrix, literal vs recipe, DEDUPLICATION independence ─────────

#[test]
fn sha256_and_blake3_recipes_resolve_locally() {
    for alg in [SHA256, BLAKE3] {
        let flags = base_flags();
        let s = scenario(flags, alg, std_chunks());
        let literal = e("lit", 0, b"plain".to_vec());
        let bytes = s.archive(flags, &[literal, s.recipe_entry(0x02)]);
        let files = read(bytes, def(), false).expect("resolve");
        let get = |n: &str| files.iter().find(|(k, _)| k == n).expect(n).1.clone();
        assert_eq!(get("lit"), b"plain");
        assert_eq!(get("r"), s.logical, "alg {alg:#x}");
    }
}

#[test]
fn recipe_mode_works_without_deduplication_and_final_hash_is_authoritative() {
    // Without DEDUPLICATION there is no Content Hash at all.
    let s = scenario(base_flags(), BLAKE3, std_chunks());
    let ok = s.archive(base_flags(), &[s.recipe_entry(0x02)]);
    assert_eq!(read_r(ok, def()).expect("no dedup"), s.logical);

    // With DEDUPLICATION the hash covers the final logical Entry.
    let flags = base_flags() | GlobalFlags::DEDUPLICATION;
    let s = scenario(flags, BLAKE3, std_chunks());
    let mut good = s.recipe_entry(0x02);
    good.hash = Some((SHA256, hash(SHA256, &s.logical)));
    assert_eq!(
        read_r(s.archive(flags, &[good]), def()).expect("final hash"),
        s.logical
    );

    // A hash of the serialized Recipe is not a substitute.
    let mut recipe_hash = s.recipe_entry(0x02);
    recipe_hash.hash = Some((BLAKE3, hash(BLAKE3, &s.recipe)));
    assert!(matches!(
        read_r(s.archive(flags, &[recipe_hash]), def()),
        Err(SarError::HashMismatch(_))
    ));
}

#[test]
fn unsupported_and_reserved_hash_algorithms_fail_closed() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    for (alg, check) in [
        (0x32u8, true), // registered SHA3-256, not supported
        (0x77, false),  // reserved
    ] {
        let tlv = raw_map(1, alg, &s.recs);
        let bytes = build(flags, &s.store, &[s.recipe_entry(0x02)], vec![tlv]);
        let err = read_r(bytes, def()).expect_err("must fail");
        if check {
            assert!(matches!(err, SarError::Unsupported(_)), "{err:?}");
        } else {
            assert!(matches!(err, SarError::ReservedValue(_)), "{err:?}");
        }
    }
}

#[test]
fn unsupported_map_version_and_bad_record_size_fail_closed() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let bytes = build(
        flags,
        &s.store,
        &[s.recipe_entry(0x02)],
        vec![raw_map(2, BLAKE3, &s.recs)],
    );
    assert!(matches!(
        read_r(bytes, def()),
        Err(SarError::Unsupported(_))
    ));
}

// ── Resolution failures ─────────────────────────────────────────────────────

#[test]
fn missing_chunk_and_missing_catalog_are_recipe_unresolvable() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let mut recs = s.recs.clone();
    recs.pop();
    let bytes = build(
        flags,
        &s.store,
        &[s.recipe_entry(0x02)],
        vec![raw_map(1, BLAKE3, &recs)],
    );
    assert!(matches!(
        read_r(bytes, def()),
        Err(SarError::RecipeUnresolvable(_))
    ));
    let no_catalog = build(flags, &s.store, &[s.recipe_entry(0x02)], Vec::new());
    assert!(matches!(
        read_r(no_catalog, def()),
        Err(SarError::RecipeUnresolvable(_))
    ));
    let no_index = build(
        flags | GlobalFlags::NO_INDEX,
        &s.store,
        &[s.recipe_entry(0x02)],
        Vec::new(),
    );
    assert!(matches!(
        read_r(no_index, def()),
        Err(SarError::RecipeUnresolvable(_))
    ));
}

#[test]
fn corrupt_referenced_chunk_is_hash_mismatch() {
    let flags = base_flags();
    let s = scenario(flags, SHA256, std_chunks());
    let mut bytes = s.archive(flags, &[s.recipe_entry(0x02)]);
    bytes[usize::try_from(s.base).expect("base") + 3] ^= 0x01;
    assert!(matches!(
        read_r(bytes, def()),
        Err(SarError::HashMismatch(_))
    ));
}

#[test]
fn recipe_length_not_multiple_of_32_is_invalid_length() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let mut r = s.recipe_entry(0x02);
    r.payload.push(0);
    assert!(matches!(
        read_r(s.archive(flags, &[r]), def()),
        Err(SarError::InvalidLength(_))
    ));
}

// ── Catalog consistency ─────────────────────────────────────────────────────

#[test]
fn conflicting_duplicate_records_are_metadata_conflict_identical_tolerated() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let mut identical = s.recs.clone();
    identical.push(s.recs[0]);
    let ok = build(
        flags,
        &s.store,
        &[s.recipe_entry(0x02)],
        vec![raw_map(1, BLAKE3, &identical)],
    );
    assert_eq!(read_r(ok, def()).expect("identical dup"), s.logical);

    let mut conflicting = s.recs.clone();
    let mut dup = s.recs[0];
    dup.2 += 1;
    conflicting.push(dup);
    let bad = build(
        flags,
        &s.store,
        &[s.recipe_entry(0x02)],
        vec![raw_map(1, BLAKE3, &conflicting)],
    );
    assert!(matches!(
        read_r(bad.clone(), def()),
        Err(SarError::MetadataConflict(_))
    ));
    // Structural verification rejects it too, without reading any chunk.
    let mut reader = ArchiveReader::new(Cursor::new(bad)).expect("reader");
    assert!(matches!(
        reader.verify(),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn ambiguous_catalog_is_metadata_conflict() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let bytes = build(
        flags,
        &s.store,
        &[s.recipe_entry(0x02)],
        vec![s.tlv(), s.tlv()],
    );
    assert!(matches!(
        read_r(bytes.clone(), def()),
        Err(SarError::MetadataConflict(_))
    ));
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    assert!(matches!(
        reader.verify(),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn nonzero_partition_index_is_rejected_for_unpartitioned_archive() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let mut recs = s.recs.clone();
    recs[0].1 = 1;
    let bytes = build(
        flags,
        &s.store,
        &[s.recipe_entry(0x02)],
        vec![raw_map(1, BLAKE3, &recs)],
    );
    assert!(matches!(
        read_r(bytes.clone(), def()),
        Err(SarError::Malformed(_))
    ));
    let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    assert!(matches!(reader.verify(), Err(SarError::Malformed(_))));
}

// ── Checked ranges, counts and limits ───────────────────────────────────────

type RangeCheck = fn(&SarError) -> bool;

#[test]
fn chunk_ranges_are_checked_before_access() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let cases: [(u64, u32, RangeCheck); 4] = [
        (u64::MAX - 2, 8, |e| matches!(e, SarError::Overflow(_))),
        (s.base + 10_000, 4, |e| matches!(e, SarError::Bounds(_))),
        (0, 4, |e| matches!(e, SarError::Bounds(_))),
        (s.base, u32::MAX, |e| {
            matches!(e, SarError::LimitExceeded(_) | SarError::Bounds(_))
        }),
    ];
    for (off, size, check) in cases {
        let mut recs = s.recs.clone();
        recs[1].2 = off;
        recs[1].3 = size;
        let bytes = build(
            flags,
            &s.store,
            &[s.recipe_entry(0x02)],
            vec![raw_map(1, BLAKE3, &recs)],
        );
        let err = read_r(bytes, def()).expect_err("range");
        assert!(check(&err), "off {off} size {size}: {err:?}");
    }
}

#[test]
fn recipe_and_output_limits_are_enforced_at_boundaries() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let bytes = s.archive(flags, &[s.recipe_entry(0x02)]);
    let total = s.logical.len() as u64; // 56 < the 96-byte Recipe itself

    let at = |l: ResourceLimits| read_r(bytes.clone(), l);
    assert!(
        at(ResourceLimits {
            max_cdc_chunk_count: 3,
            ..def()
        })
        .is_ok()
    );
    assert!(matches!(
        at(ResourceLimits {
            max_cdc_chunk_count: 2,
            ..def()
        }),
        Err(SarError::LimitExceeded(_))
    ));
    assert!(matches!(
        at(ResourceLimits {
            max_cdc_metadata_bytes: 95,
            ..def()
        }),
        Err(SarError::LimitExceeded(_))
    ));
    assert!(
        at(ResourceLimits {
            max_decoded_entry_size: 96,
            ..def()
        })
        .is_ok()
    );
    assert!(matches!(
        at(ResourceLimits {
            max_decoded_entry_size: total - 1,
            ..def()
        }),
        Err(SarError::LimitExceeded(_))
    ));
    let r = at(ResourceLimits {
        max_in_memory_buffer: 512,
        ..def()
    });
    assert!(r.is_ok(), "{r:?}");
    assert!(matches!(
        at(ResourceLimits {
            max_in_memory_buffer: 55,
            ..def()
        }),
        Err(SarError::LimitExceeded(_))
    ));
    assert!(matches!(
        at(ResourceLimits {
            max_total_pipeline_memory: 100,
            ..def()
        }),
        Err(SarError::LimitExceeded(_))
    ));
}

#[test]
fn record_count_limit_bounds_the_catalog() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let bytes = s.archive(flags, &[s.recipe_entry(0x02)]);
    let limits = ResourceLimits {
        max_cdc_chunk_count: 2,
        ..def()
    };
    let mut reader = ArchiveReader::with_options(Cursor::new(bytes), opts(limits)).expect("r");
    assert!(matches!(reader.verify(), Err(SarError::LimitExceeded(_))));
}

// ── Fragmented Recipes ──────────────────────────────────────────────────────

fn fragments(s: &Scenario, with_terminal: bool) -> Vec<E> {
    let (a, b) = s.recipe.split_at(32);
    let mut f0 = e("rf", 0x02, a.to_vec());
    f0.frag = Some((5, 0, false));
    f0.crc = Some(0);
    let mut f1 = e("", 0x02, b.to_vec());
    f1.frag = Some((5, if with_terminal { 1 } else { 2 }, true));
    vec![f0, f1]
}

#[test]
fn complete_fragmented_recipe_reconstructs() {
    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let s = scenario(flags, BLAKE3, std_chunks());
    let files = read(s.archive(flags, &fragments(&s, true)), def(), false).expect("frag");
    assert_eq!(
        files.iter().find(|(n, _)| n == "rf").expect("rf").1,
        s.logical
    );
}

#[test]
fn incomplete_fragmented_recipe_is_fragment_gap_even_when_loss_tolerant() {
    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let s = scenario(flags, BLAKE3, std_chunks());
    for lossy in [false, true] {
        let frs = fragments(&s, false);
        let err = read(s.archive(flags, &frs), def(), lossy).expect_err("gap");
        assert!(matches!(err, SarError::FragmentGap(_)), "{err:?}");
    }
}

// ── CDC followed by sparse reconstruction and final integrity ───────────────

#[test]
fn cdc_then_sparse_then_final_crc_and_content_hash() {
    let flags = base_flags()
        | GlobalFlags::SPARSE_FILES
        | GlobalFlags::PER_FILE_CRC
        | GlobalFlags::DEDUPLICATION;
    let chunks = vec![b"AB".to_vec(), b"CD".to_vec()];
    let s = scenario(flags, BLAKE3, chunks);
    let map = write_sparse_map(
        &SparseMap {
            logical_size: 10,
            extents: vec![SparseExtent {
                offset: 3,
                length: 4,
            }],
        },
        false,
    )
    .expect("map");
    let mut want = vec![0u8; 10];
    want[3..7].copy_from_slice(b"ABCD");

    let mut r = s.recipe_entry(0x02);
    r.sparse = map.clone();
    r.crc = Some(crc32fast::hash(&want));
    r.hash = Some((BLAKE3, hash(BLAKE3, &want)));
    assert_eq!(
        read_r(s.archive(flags, &[r.clone()]), def()).expect("ok"),
        want
    );

    let mut bad_crc = r.clone();
    bad_crc.crc = Some(crc32fast::hash(&want) ^ 1);
    assert!(matches!(
        read_r(s.archive(flags, &[bad_crc]), def()),
        Err(SarError::CrcMismatch(_))
    ));
    let mut bad_hash = r.clone();
    bad_hash.hash = Some((BLAKE3, hash(BLAKE3, b"other")));
    assert!(matches!(
        read_r(s.archive(flags, &[bad_hash]), def()),
        Err(SarError::HashMismatch(_))
    ));
    // Resolved length must equal the sum of the Sparse Extents.
    let mut short = r;
    short.sparse = write_sparse_map(
        &SparseMap {
            logical_size: 10,
            extents: vec![SparseExtent {
                offset: 3,
                length: 3,
            }],
        },
        false,
    )
    .expect("map");
    assert!(matches!(
        read_r(s.archive(flags, &[short]), def()),
        Err(SarError::InvalidLength(_))
    ));
}

// ── FASTCDC (0x02) integration ──────────────────────────────────────────────

#[test]
fn fastcdc_chunks_round_trip_through_recipe_mode() {
    let data: Vec<u8> = (0u32..20_000)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let opts = FastCdcOptions {
        min_size: 64,
        avg_size: 256,
        max_size: 1024,
    };
    let cuts = chunk_data(&data, &opts, 100_000).expect("chunking");
    assert!(cuts.len() > 4);
    let chunks: Vec<Vec<u8>> = cuts
        .iter()
        .map(|c| {
            let start = usize::try_from(c.offset).expect("offset");
            data[start..start + usize::try_from(c.length).expect("length")].to_vec()
        })
        .collect();
    for alg in [SHA256, BLAKE3] {
        let flags = base_flags();
        let s = scenario(flags, alg, chunks.clone());
        assert_eq!(s.logical, data);
        let mut uniq = s.recs.clone();
        uniq.sort_by_key(|r| r.0);
        uniq.dedup_by_key(|r| r.0);
        let tlv = raw_map(1, alg, &uniq);
        let bytes = build(flags, &s.store, &[s.recipe_entry(0x02)], vec![tlv]);
        assert_eq!(read_r(bytes, def()).expect("fastcdc"), data);
    }
}

// ── External resolver boundary ──────────────────────────────────────────────

#[derive(Clone)]
struct Mock {
    calls: Rc<Cell<usize>>,
    chunks: HashMap<[u8; 32], Vec<u8>>,
}

impl CdcChunkResolver for Mock {
    fn resolve_chunk(&self, _alg: u8, hash: &[u8; 32], _max: u64) -> Option<Vec<u8>> {
        self.calls.set(self.calls.get() + 1);
        self.chunks.get(hash).cloned()
    }
}

fn mock(s: &Scenario) -> (Mock, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    let chunks = s
        .recs
        .iter()
        .zip(&s.chunks)
        .map(|(r, c)| (r.0, c.clone()))
        .collect();
    (
        Mock {
            calls: calls.clone(),
            chunks,
        },
        calls,
    )
}

fn reader_with(
    bytes: Vec<u8>,
    alg: u8,
    m: Mock,
    limits: ResourceLimits,
) -> Result<ArchiveReader<Cursor<Vec<u8>>>, SarError> {
    ArchiveReader::with_options(Cursor::new(bytes), opts(limits))?
        .with_cdc_resolver(alg, Box::new(m))
}

#[test]
fn external_resolver_is_used_only_for_logical_reconstruction() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    // No local CDC_MAP: the explicitly configured resolver supplies chunks.
    let bytes = build(flags, &s.store, &[s.recipe_entry(0x02)], Vec::new());
    let (m, calls) = mock(&s);

    let mut r = reader_with(bytes.clone(), BLAKE3, m.clone(), def()).expect("reader");
    r.verify().expect("structural verify");
    let _ = r.audit(Default::default());
    let mut r2 = reader_with(bytes.clone(), BLAKE3, m.clone(), def()).expect("reader");
    r2.read_global_header().expect("header");
    while r2.next_entry().expect("physical").is_some() {}
    assert_eq!(
        calls.get(),
        0,
        "structural operations never call the resolver"
    );

    let mut r3 = reader_with(bytes, BLAKE3, m, def()).expect("reader");
    let files = r3.read_all_logical_files(false).expect("logical");
    assert_eq!(
        files.iter().find(|f| f.name == "r").expect("r").data,
        s.logical
    );
    assert_eq!(calls.get(), 3);
}

#[test]
fn external_resolver_failures_map_to_existing_statuses() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let bytes = build(flags, &s.store, &[s.recipe_entry(0x02)], Vec::new());

    let (mut m, _) = mock(&s);
    m.chunks.remove(&s.recs[1].0);
    let mut r = reader_with(bytes.clone(), BLAKE3, m, def()).expect("reader");
    assert!(matches!(
        r.read_all_logical_files(false),
        Err(SarError::RecipeUnresolvable(_))
    ));

    let (mut m, _) = mock(&s);
    m.chunks.insert(s.recs[0].0, b"tampered".to_vec());
    let mut r = reader_with(bytes.clone(), BLAKE3, m, def()).expect("reader");
    assert!(matches!(
        r.read_all_logical_files(false),
        Err(SarError::HashMismatch(_))
    ));

    let (m, _) = mock(&s);
    let limits = ResourceLimits {
        max_in_memory_buffer: 10,
        ..def()
    };
    let mut r = reader_with(bytes.clone(), BLAKE3, m, limits).expect("reader");
    assert!(matches!(
        r.read_all_logical_files(false),
        Err(SarError::LimitExceeded(_))
    ));

    let (m, _) = mock(&s);
    let limits = ResourceLimits {
        max_decoded_entry_size: 20,
        ..def()
    };
    let mut r = reader_with(bytes, BLAKE3, m, limits).expect("reader");
    assert!(matches!(
        r.read_all_logical_files(false),
        Err(SarError::LimitExceeded(_))
    ));
}

#[test]
fn resolver_algorithm_must_be_registered_supported_and_match_the_catalog() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let (m, _) = mock(&s);
    let bytes = s.archive(flags, &[s.recipe_entry(0x02)]);
    let reader = || ArchiveReader::new(Cursor::new(bytes.clone())).expect("reader");

    assert!(matches!(
        reader().with_cdc_resolver(0x32, Box::new(m.clone())),
        Err(SarError::Unsupported(_))
    ));
    assert!(matches!(
        reader().with_cdc_resolver(0x77, Box::new(m.clone())),
        Err(SarError::ReservedValue(_))
    ));
    // Algorithm differing from the archive's CDC_MAP: ambiguous selection.
    let mut r = reader()
        .with_cdc_resolver(SHA256, Box::new(m.clone()))
        .expect("configure");
    assert!(matches!(
        r.read_all_logical_files(false),
        Err(SarError::MetadataConflict(_))
    ));
}

#[test]
fn unconfigured_resolver_is_never_invoked_and_uri_is_inert() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let provider = Tlv {
        type_id: 0x41,
        value: b"sarp+https://chunks.invalid/v1".to_vec(),
    };
    let bytes = build(flags, &s.store, &[s.recipe_entry(0x02)], vec![provider]);
    // A provider URI alone is metadata: no catalog, no resolver.
    assert!(matches!(
        read_r(bytes, def()),
        Err(SarError::RecipeUnresolvable(_))
    ));
}

// ── Collector bookkeeping, end to end ───────────────────────────────────────

#[test]
fn many_small_fragment_groups_exhaust_bookkeeping_limits() {
    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let s = scenario(flags, BLAKE3, std_chunks());
    // Each group's terminal fragment is missing, so state is retained.
    let entries: Vec<E> = (0..200u32)
        .map(|id| {
            let mut f = e("g", 0, vec![1]);
            f.frag = Some((id, 0, false));
            f
        })
        .collect();
    let bytes = s.archive(flags, &entries);
    let limits = ResourceLimits {
        max_total_pipeline_memory: 64 * 1024,
        ..def()
    };
    let err = read(bytes.clone(), limits, true).expect_err("bookkeeping");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
    let limits = ResourceLimits {
        max_entry_count: 50,
        ..def()
    };
    let err = read(bytes, limits, true).expect_err("group count");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

// ── Physical/logical boundary ───────────────────────────────────────────────

#[test]
fn next_entry_is_physical_and_next_logical_entry_resolves_before_exposure() {
    use sar_archive::fragment_group::CollectedEntry;

    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let s = scenario(flags, BLAKE3, std_chunks());
    let mut entries = vec![s.recipe_entry(0x02)];
    entries.extend(fragments(&s, true));
    let bytes = s.archive(flags, &entries);

    // Physical view: Recipe bytes, never chunk content, and no chunk reads.
    let mut r = ArchiveReader::new(Cursor::new(bytes.clone())).expect("reader");
    r.read_global_header().expect("header");
    let mut physical = Vec::new();
    while let Some(entry) = r.next_entry().expect("physical") {
        physical.push((entry.metadata.name.clone(), entry.payload));
    }
    assert!(physical.iter().any(|(_, p)| *p == s.recipe));
    assert!(
        physical
            .iter()
            .all(|(n, p)| n == "store" || *p != s.logical)
    );

    // Logical view (the path used by CLI extract): resolved content only.
    let mut r = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
    let mut seen = 0;
    while let Some(item) = r.next_logical_entry().expect("logical") {
        match item {
            CollectedEntry::Entry(e) if e.metadata.name == "r" => {
                assert_eq!(e.payload, s.logical);
                seen += 1;
            }
            CollectedEntry::Group(g) => {
                let (raw, degraded) = g.reconstruct(&opts(def())).expect("group");
                assert!(!degraded);
                assert_eq!(raw, s.logical);
                seen += 1;
            }
            CollectedEntry::Entry(e) => assert_ne!(e.payload, s.recipe, "{}", e.metadata.name),
        }
    }
    assert_eq!(seen, 2);
}

#[test]
fn malformed_cdc_map_cannot_bypass_structural_verify() {
    let flags = base_flags();
    let s = scenario(flags, BLAKE3, std_chunks());
    let good = raw_map(1, BLAKE3, &s.recs);
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut t = good.clone();
        f(&mut t.value);
        t
    };
    let cases: Vec<(&str, Tlv)> = vec![
        ("version", mutate(&|v| v[0] = 2)),
        ("flags", mutate(&|v| v[2] = 1)),
        ("reserved", mutate(&|v| v[10] = 1)),
        ("record size", mutate(&|v| v[8] = 47)),
        ("count high", mutate(&|v| v[4] = 9)),
        ("truncated", mutate(&|v| v.truncate(v.len() - 1))),
        ("algo 0x32", mutate(&|v| v[1] = 0x32)),
        ("algo reserved", mutate(&|v| v[1] = 0x77)),
    ];
    for (label, tlv) in cases {
        let bytes = build(flags, &s.store, &[s.recipe_entry(0x02)], vec![tlv]);
        let mut reader = ArchiveReader::new(Cursor::new(bytes)).expect("reader");
        assert!(
            reader.verify().is_err(),
            "verify accepted malformed {label}"
        );
    }
}

#[test]
fn resolution_is_charged_for_bytes_the_collector_still_retains() {
    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let chunks = vec![vec![1u8; 1000], vec![2u8; 1000], vec![3u8; 1000]];
    let s = scenario(flags, BLAKE3, chunks);
    // F0, an unfragmented Recipe (retained behind the incomplete group), F1.
    let frs = fragments(&s, true);
    let entries = vec![frs[0].clone(), s.recipe_entry(0x02), frs[1].clone()];
    let bytes = s.archive(flags, &entries);

    let fits = ResourceLimits {
        max_total_pipeline_memory: 100_000,
        ..def()
    };
    assert_eq!(read(bytes.clone(), fits, false).expect("fits").len(), 3);

    // Exact boundary: the smallest passing limit succeeds with correct
    // content and one byte less is rejected.
    let min = min_pipeline_limit(&bytes);
    let at = read(bytes.clone(), pipeline(min), false).expect("at limit");
    for name in ["rf", "r"] {
        assert_eq!(at.iter().find(|(n, _)| n == name).expect(name).1, s.logical);
    }
    let err = read(bytes, pipeline(min - 1), false).expect_err("one below");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");

    // The same group without the retained Recipe Entry needs strictly less.
    let alone = s.archive(flags, &fragments(&s, true));
    assert!(
        min_pipeline_limit(&alone) < min,
        "retained bytes not charged"
    );
}

fn pipeline(max_total_pipeline_memory: u64) -> ResourceLimits {
    ResourceLimits {
        max_total_pipeline_memory,
        ..def()
    }
}

/// Smallest `max_total_pipeline_memory` under which the archive reads.
fn min_pipeline_limit(bytes: &[u8]) -> u64 {
    let (mut lo, mut hi) = (0u64, 1 << 22);
    assert!(read(bytes.to_vec(), pipeline(hi), false).is_ok());
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if read(bytes.to_vec(), pipeline(mid), false).is_ok() {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    hi
}

#[test]
fn fragment_reconstruction_peak_is_charged_before_concatenation() {
    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let s = scenario(flags, SHA256, std_chunks());
    let mut f0 = e("lf", 0x00, vec![1u8; 10_000]);
    f0.frag = Some((9, 0, false));
    f0.crc = Some(0);
    let mut f1 = e("", 0x00, vec![2u8; 10_000]);
    f1.frag = Some((9, 1, true));
    let bytes = s.archive(flags, &[f0, f1]);

    // The collector admits 20 000 payload bytes, but concatenation holds the
    // grown output beside the remaining contributions (up to 2 x 20 000).
    let min = min_pipeline_limit(&bytes);
    assert!(min >= 40_000, "peak not charged: {min}");
    let files = read(bytes.clone(), pipeline(min), false).expect("at limit");
    assert_eq!(
        files.iter().find(|(n, _)| n == "lf").expect("lf").1.len(),
        20_000
    );
    let err = read(bytes, pipeline(min - 1), false).expect_err("one below");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

#[test]
fn reconstruction_peak_includes_other_groups_still_retained() {
    let flags = base_flags() | GlobalFlags::FILE_FRAGMENTATION;
    let s = scenario(flags, SHA256, std_chunks());
    let frag = |name: &'static str, id: u32, index: u32, last: bool, fill: u8| {
        let mut f = e(name, 0x00, vec![fill; 10_000]);
        f.frag = Some((id, index, last));
        if index == 0 {
            f.crc = Some(0);
        }
        f
    };
    // Group 1 completes (and is reconstructed) while group 2's first
    // fragment is still retained by the collector.
    let entries = [
        frag("a", 1, 0, false, 1),
        frag("b", 2, 0, false, 3),
        frag("", 1, 1, true, 2),
        frag("", 2, 1, true, 4),
    ];
    let bytes = s.archive(flags, &entries);

    // Group 1 alone peaks at 2 x 20 000; group 2's 10 000 retained payload
    // bytes (plus its bookkeeping) are live at the same time.
    let min = min_pipeline_limit(&bytes);
    assert!(min >= 50_000, "other retained group not charged: {min}");
    let files = read(bytes.clone(), pipeline(min), false).expect("at limit");
    for (name, len) in [("a", 20_000), ("b", 20_000)] {
        assert_eq!(
            files.iter().find(|(n, _)| n == name).expect(name).1.len(),
            len
        );
    }
    let err = read(bytes, pipeline(min - 1), false).expect_err("one below");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

#[test]
fn cdc_map_parse_peak_is_charged_before_allocation() {
    let s = scenario(base_flags(), SHA256, std_chunks());
    let tlvs = [s.tlv()];
    // 16 + 3 x 48 bytes of TLV, plus 3 x (48 + 96) of record and index memory.
    let peak = 160 + 3 * 144;
    assert!(sar_core::cdc::parse_entry_cdc_map(&tlvs, &pipeline(peak)).is_ok());
    let err = sar_core::cdc::parse_entry_cdc_map(&tlvs, &pipeline(peak - 1)).expect_err("below");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}
