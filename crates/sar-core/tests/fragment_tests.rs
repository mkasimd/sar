// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Tests for fragment-group metadata parsing and reassembly.

use sar_core::{
    EntryMode, GlobalFlags,
    format::{LocalFileHeader, parse_lfh, write_lfh},
};
use sar_fragmentation::{
    FragmentEntry, FragmentError, reconstruct_fragments, validate_fragment_group,
};

fn unlimited_limits() -> sar_core::ResourceLimits {
    sar_core::ResourceLimits::unlimited()
}

fn frag_unlimited() -> sar_fragmentation::FragmentLimits {
    sar_core::ResourceLimits::unlimited().fragment_limits()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn make_frag_lfh(
    _flags: &GlobalFlags,
    fragment_id: u32,
    fragment_index: u32,
    is_last: bool,
    is_loss_tolerant: bool,
    payload_size: u64,
) -> LocalFileHeader {
    let mut mode = 1u16 << 5; // IS_FRAGMENT
    if is_last {
        mode |= 1 << 6;
    }
    if is_loss_tolerant {
        mode |= 1 << 7;
    }
    LocalFileHeader {
        header_size: 0,
        entry_mode: EntryMode::from_bits(mode),
        stream_id: 0,
        sequence_no: 0,
        uncompressed_size: payload_size,
        payload_size,
        comp_algo_id: None,
        patch_algo_id: None,
        encr_algo_id: None,
        cdc_algo_id: None,
        fec_algo_id: None,
        fragment_id: Some(fragment_id),
        fragment_index: Some(fragment_index),
        iv_nonce: None,
        delta_base_hash: None,
        file_crc32: None,
        hash_algo_id: None,
        content_hash: None,
        uid_gid: None,
        timestamps: None,
        permissions: None,
        name: b"file.bin".to_vec(),
        path: Vec::new(),
        sparse_map: Vec::new(),
        fec_value: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Roundtrip
// ---------------------------------------------------------------------------

#[test]
fn parse_write_fragment_metadata() {
    let flags = GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let lfh = make_frag_lfh(&flags, 0xAB, 2, false, false, 512);
    let bytes = write_lfh(&flags, &lfh).expect("write LFH");
    let (parsed, _) = parse_lfh(&bytes, &flags, &unlimited_limits()).expect("parse LFH");

    assert_eq!(parsed.fragment_id, Some(0xAB));
    assert_eq!(parsed.fragment_index, Some(2));
    // Contribution length is the LFH Uncompressed Size; no separate field.
    assert_eq!(parsed.uncompressed_size, 512);
    assert!(parsed.entry_mode.is_fragment());
    assert!(!parsed.entry_mode.is_last_fragment());
    assert!(!parsed.entry_mode.is_loss_tolerant());
}

// ---------------------------------------------------------------------------
// Reconstruction (canonical Fragment Index ordering)
//
// Replaces the obsolete absolute-offset tests: `reject_overlapping_fragments`
// and `reject_invalid_fragment_bounds` (descriptor offsets no longer exist on
// the wire; retired) and the zero-filling `loss_tolerant_gap_*` test
// (replaced by longest-contiguous-prefix semantics).
// ---------------------------------------------------------------------------

fn frag(index: u32, last: bool, lt: bool, data: &[u8]) -> FragmentEntry {
    FragmentEntry {
        fragment_index: index,
        is_last_fragment: last,
        is_loss_tolerant: lt,
        uncompressed_size: data.len() as u64,
        payload: data.to_vec(),
    }
}

#[test]
fn reconstruct_complete_fragment_set() {
    let frags = vec![
        frag(0, false, false, b"AAAAAAAA"),
        frag(1, true, false, b"BBBBBBBB"),
    ];
    let (data, degraded) = reconstruct_fragments(frags, &frag_unlimited()).expect("reconstruct");
    assert!(!degraded);
    assert_eq!(data, b"AAAAAAAABBBBBBBB");
}

#[test]
fn accept_out_of_order_fragments() {
    let frags = vec![
        frag(1, true, false, b"DDDD"),
        frag(0, false, false, b"CCCC"),
    ];
    let (data, degraded) = reconstruct_fragments(frags, &frag_unlimited()).expect("reconstruct");
    assert!(!degraded);
    assert_eq!(data, b"CCCCDDDD");
}

#[test]
fn reject_missing_fragments_no_loss_tolerant() {
    let frags = vec![
        frag(0, false, false, b"AAAA"),
        frag(2, true, false, b"CCCC"),
    ];
    let err = reconstruct_fragments(frags, &frag_unlimited()).expect_err("should fail");
    assert!(
        matches!(err, FragmentError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn loss_tolerant_gap_emits_contiguous_prefix_only() {
    let frags = vec![frag(0, false, true, b"AAAA"), frag(2, true, true, b"CCCC")];
    let (data, degraded) = reconstruct_fragments(frags, &frag_unlimited()).expect("reconstruct");
    assert!(degraded, "expected degraded=true");
    // No synthetic zeros and no concatenation across the gap.
    assert_eq!(data, b"AAAA");
}

#[test]
fn validate_rejects_duplicate_index() {
    let frags = vec![frag(0, false, false, b"A"), frag(0, true, false, b"B")];
    let err = validate_fragment_group(&frags, &frag_unlimited()).expect_err("should fail");
    assert!(matches!(err, FragmentError::DuplicateIndex(_)));
}
