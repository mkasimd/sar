//! Tests for fragment-group metadata parsing and reassembly.

use sar_core::{
    EntryMode, GlobalFlags,
    error::SarError,
    format::{LfhFragmentDescriptor, LocalFileHeader, parse_lfh, write_lfh},
    fragment::{FragmentDescriptor, FragmentEntry, reconstruct_fragments, validate_fragment_group},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn make_frag_lfh(
    _flags: &GlobalFlags,
    fragment_id: u32,
    fragment_index: u32,
    abs_offset: u64,
    frag_size: u32,
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
        entry_mode: EntryMode(mode),
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
        fragment_descriptor: Some(LfhFragmentDescriptor {
            absolute_offset: abs_offset,
            fragment_size: frag_size,
        }),
        iv_nonce: None,
        delta_base_hash: None,
        file_crc32: None,
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
    let lfh = make_frag_lfh(&flags, 0xAB, 2, 1024, 512, false, false, 512);
    let bytes = write_lfh(&flags, &lfh).expect("write LFH");
    let (parsed, _) = parse_lfh(&bytes, &flags).expect("parse LFH");

    assert_eq!(parsed.fragment_id, Some(0xAB));
    assert_eq!(parsed.fragment_index, Some(2));
    assert_eq!(
        parsed.fragment_descriptor,
        Some(LfhFragmentDescriptor {
            absolute_offset: 1024,
            fragment_size: 512,
        })
    );
    assert!(parsed.entry_mode.is_fragment());
    assert!(!parsed.entry_mode.is_last_fragment());
    assert!(!parsed.entry_mode.is_loss_tolerant());
}

// ---------------------------------------------------------------------------
// Reconstruction
// ---------------------------------------------------------------------------

#[test]
fn reconstruct_complete_fragment_set() {
    // Two 8-byte fragments covering a 16-byte logical file.
    let frags = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 8,
            },
            payload: b"AAAAAAAA".to_vec(),
        },
        FragmentEntry {
            fragment_index: 1,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 8,
                fragment_size: 8,
            },
            payload: b"BBBBBBBB".to_vec(),
        },
    ];
    let (data, degraded) = reconstruct_fragments(frags, 16).expect("reconstruct");
    assert!(!degraded);
    assert_eq!(&data[..8], b"AAAAAAAA");
    assert_eq!(&data[8..], b"BBBBBBBB");
}

#[test]
fn accept_out_of_order_fragments() {
    // Provide fragments out of index order; reconstruct must sort them.
    let frags = vec![
        FragmentEntry {
            fragment_index: 1,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 4,
                fragment_size: 4,
            },
            payload: b"DDDD".to_vec(),
        },
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 4,
            },
            payload: b"CCCC".to_vec(),
        },
    ];
    let (data, degraded) = reconstruct_fragments(frags, 8).expect("reconstruct");
    assert!(!degraded);
    assert_eq!(&data[..4], b"CCCC");
    assert_eq!(&data[4..], b"DDDD");
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

#[test]
fn reject_overlapping_fragments() {
    // Fragment 0 covers [0, 8) and fragment 1 covers [4, 12) — they overlap.
    let frags = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 8,
            },
            payload: vec![0u8; 8],
        },
        FragmentEntry {
            fragment_index: 1,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 4,
                fragment_size: 8,
            },
            payload: vec![0u8; 8],
        },
    ];
    let err = validate_fragment_group(&frags, 12).expect_err("should fail");
    assert!(
        matches!(err, SarError::InvalidMap(_)),
        "expected InvalidMap, got {err:?}"
    );
}

#[test]
fn reject_invalid_fragment_bounds() {
    // Fragment descriptor extends past logical_size.
    let frags = vec![FragmentEntry {
        fragment_index: 0,
        is_last_fragment: true,
        is_loss_tolerant: false,
        descriptor: FragmentDescriptor {
            absolute_offset: 0,
            fragment_size: 100,
        },
        payload: vec![0u8; 100],
    }];
    let err = validate_fragment_group(&frags, 50).expect_err("should fail");
    assert!(
        matches!(err, SarError::Bounds(_)),
        "expected Bounds, got {err:?}"
    );
}

#[test]
fn reject_missing_fragments_no_loss_tolerant() {
    // Index gap: 0, 2 — index 1 is missing and LOSS_TOLERANT is not set.
    let frags = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 4,
            },
            payload: vec![0u8; 4],
        },
        FragmentEntry {
            fragment_index: 2,
            is_last_fragment: true,
            is_loss_tolerant: false,
            descriptor: FragmentDescriptor {
                absolute_offset: 8,
                fragment_size: 4,
            },
            payload: vec![0u8; 4],
        },
    ];
    let err = reconstruct_fragments(frags, 12).expect_err("should fail");
    assert!(
        matches!(err, SarError::FragmentGap(_)),
        "expected FragmentGap, got {err:?}"
    );
}

#[test]
fn loss_tolerant_gap_returns_warn_incomplete() {
    // Index gap but LOSS_TOLERANT is set — reconstruct should succeed with
    // is_degraded = true.
    let frags = vec![
        FragmentEntry {
            fragment_index: 0,
            is_last_fragment: false,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 0,
                fragment_size: 4,
            },
            payload: b"AAAA".to_vec(),
        },
        // Index 1 is missing
        FragmentEntry {
            fragment_index: 2,
            is_last_fragment: true,
            is_loss_tolerant: true,
            descriptor: FragmentDescriptor {
                absolute_offset: 8,
                fragment_size: 4,
            },
            payload: b"CCCC".to_vec(),
        },
    ];
    let (data, degraded) = reconstruct_fragments(frags, 12).expect("reconstruct");
    assert!(degraded, "expected degraded=true");
    // Bytes [0..4] = AAAA, [4..8] = zeros (missing fragment), [8..12] = CCCC
    assert_eq!(&data[..4], b"AAAA");
    assert_eq!(&data[4..8], &[0u8; 4]);
    assert_eq!(&data[8..12], b"CCCC");
}
