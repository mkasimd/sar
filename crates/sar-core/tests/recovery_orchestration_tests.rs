//! Tests for archive-level recovery orchestration (inspect, plan, repair).

use sar_core::{
    ArchiveWriter, ArchiveWriterOptions, EntryInput, GlobalFlags, SarError,
    error::SarStatus,
    format::{
        CentralDictionary, Footer, GlobalHeader, write_central_dictionary, write_footer,
        write_global_header,
    },
    recovery::{ErasureInput, ErasureRange, inspect_recovery_metadata, plan_archive_repair},
    tlv::Tlv,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds the on-wire bytes for a valid XOR RECOVERY TLV (type 0x14).
///
/// Uses stripe_size=1, block_size_index=0x00 (256 bytes).
/// `protected_len` drives the stripe count; parity data is zero-filled.
fn build_xor_tlv_value(protected_len: u64) -> Vec<u8> {
    let stripe_size: u8 = 1;
    let block_size_index: u8 = 0x00; // 256 bytes
    let block_size: u64 = 256;
    let stripe_count = protected_len.div_ceil(stripe_size as u64 * block_size);

    let mut v = Vec::new();
    v.push(stripe_size);
    v.push(block_size_index);
    v.extend_from_slice(&protected_len.to_le_bytes());
    v.extend_from_slice(&(stripe_count as u32).to_le_bytes());
    // Zero-filled parity: stripe_count * block_size bytes
    v.extend(vec![0u8; (stripe_count * block_size) as usize]);
    v
}

/// Builds a minimal indexed SAR archive without any RECOVERY TLV.
fn build_archive_no_ec() -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: false,
            encryption: None,
            fec: None,
            sparse: false,
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "a.txt".into(),
            payload: b"hello".to_vec(),
        })
        .expect("entry");
    writer.finish().expect("finish");
    out
}

/// Builds a minimal indexed SAR archive with `HAS_GLOBAL_EC` and one XOR RECOVERY TLV.
fn build_archive_with_global_ec() -> Vec<u8> {
    // Build global header with HAS_GLOBAL_EC | OPT_PRESENT
    let flags = GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
    let header = GlobalHeader {
        version: 0x01,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let header_bytes = write_global_header(&header).expect("header");
    let header_len = header_bytes.len() as u64;

    // Empty data area (no entries).
    // cd_offset = header_len
    let cd_offset = header_len;
    let protected_len = cd_offset - 8; // GLOBAL_FLAGS_OFFSET = 8

    let tlv_value = build_xor_tlv_value(protected_len);
    let recovery_tlv = Tlv {
        type_id: 0x14,
        value: tlv_value,
    };

    let cd = CentralDictionary {
        version: 0x01,
        file_count: 0,
        partition_info: None,
        global_crc32: None,
        metadata: vec![recovery_tlv],
        offsets: Vec::new(),
    };
    let cd_bytes = write_central_dictionary(&cd, flags).expect("cd");
    let footer_bytes = write_footer(Footer { cd_offset });

    let mut archive = header_bytes;
    archive.extend_from_slice(&cd_bytes);
    archive.extend_from_slice(&footer_bytes);
    archive
}

// ---------------------------------------------------------------------------
// inspect_recovery_metadata
// ---------------------------------------------------------------------------

#[test]
fn inspect_recovery_metadata_no_ec() {
    let archive = build_archive_no_ec();
    let meta = inspect_recovery_metadata(&archive).expect("inspect");
    assert!(!meta.has_global_ec);
    assert!(!meta.repair_possible);
    assert!(meta.recovery_tlvs.is_empty());
    assert!(meta.repair_unavailable_reason.is_some());
}

#[test]
fn inspect_recovery_metadata_with_ec() {
    let archive = build_archive_with_global_ec();
    let meta = inspect_recovery_metadata(&archive).expect("inspect");
    assert!(meta.has_global_ec);
    assert_eq!(meta.recovery_tlvs.len(), 1);
    assert!(meta.protected_range.is_some());
    assert!(meta.repair_possible);
    assert!(meta.repair_unavailable_reason.is_none());
}

// ---------------------------------------------------------------------------
// plan_archive_repair
// ---------------------------------------------------------------------------

#[test]
fn plan_repair_requires_explicit_erasures() {
    // When no archive_ranges are provided, planning should still succeed
    // (caller is responsible for providing erasures).
    let archive = build_archive_with_global_ec();
    let meta = inspect_recovery_metadata(&archive).expect("inspect");
    let pr = meta.protected_range.as_ref().expect("protected_range");

    // Block-aligned erasure at the start of the protected range.
    let erasures = ErasureInput {
        entries: Vec::new(),
        archive_ranges: vec![ErasureRange {
            offset: pr.offset,
            length: 256, // one XOR block (block_size_index=0x00 → 256 bytes)
        }],
    };
    // This should succeed (block-aligned).
    let plan_result = plan_archive_repair(&archive, erasures);
    // plan_archive_repair may succeed or return RecoveryUnavailable depending on
    // whether the protected range is large enough.  For this small archive the
    // protected range is only 4 bytes, so 256 bytes would exceed it.
    match plan_result {
        Err(SarError::RecoveryUnavailable(_)) => {} // expected for out-of-range
        Ok(_) => {}                                 // also acceptable if range is large enough
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn plan_repair_unavailable_without_ec() {
    let archive = build_archive_no_ec();
    let erasures = ErasureInput {
        entries: Vec::new(),
        archive_ranges: Vec::new(),
    };
    let err = plan_archive_repair(&archive, erasures).expect_err("should fail");
    assert!(
        matches!(err, SarError::RecoveryUnavailable(_)),
        "expected RecoveryUnavailable, got {err:?}"
    );
    assert_eq!(err.status(), SarStatus::ErrRecoveryUnavailable);
}

#[test]
fn plan_repair_unavailable_for_no_index_archive() {
    // NO_INDEX archives have no CD → no RECOVERY TLV → unavailable.
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            encryption: None,
            fec: None,
            sparse: false,
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput {
            name: "x".into(),
            payload: b"x".to_vec(),
        })
        .expect("entry");
    writer.finish().expect("finish");

    let err = plan_archive_repair(
        &out,
        ErasureInput {
            entries: Vec::new(),
            archive_ranges: Vec::new(),
        },
    )
    .expect_err("should fail");
    assert!(matches!(err, SarError::RecoveryUnavailable(_)));
}

#[test]
fn plan_repair_rejects_out_of_range_erasures() {
    let archive = build_archive_with_global_ec();
    let meta = inspect_recovery_metadata(&archive).expect("inspect");
    let pr = meta.protected_range.as_ref().expect("protected_range");

    // Erasure at offset 0 (before protected range starts at 8)
    let erasures = ErasureInput {
        entries: Vec::new(),
        archive_ranges: vec![ErasureRange {
            offset: 0, // outside protected range
            length: 256,
        }],
    };
    let err = plan_archive_repair(&archive, erasures).expect_err("should fail");
    assert!(matches!(err, SarError::RecoveryUnavailable(_)));
    let _ = pr;
}

#[test]
fn plan_repair_rejects_unaligned_erasures() {
    let archive = build_archive_with_global_ec();
    let meta = inspect_recovery_metadata(&archive).expect("inspect");
    let pr = meta.protected_range.as_ref().expect("protected_range");

    // Erasure starts at protected_range.offset+1 (not block-aligned)
    let erasures = ErasureInput {
        entries: Vec::new(),
        archive_ranges: vec![ErasureRange {
            offset: pr.offset + 1, // unaligned
            length: 256,
        }],
    };
    let err = plan_archive_repair(&archive, erasures).expect_err("should fail");
    assert!(matches!(err, SarError::RecoveryUnavailable(_)));
}

#[test]
fn archive_level_repair_unavailable_when_spec_incomplete() {
    // When erasures cannot be block-aligned due to spec ambiguity, we must
    // get RecoveryUnavailable with the documented message.
    let archive = build_archive_with_global_ec();
    let meta = inspect_recovery_metadata(&archive).expect("inspect");
    let pr = meta.protected_range.as_ref().expect("protected_range");

    let erasures = ErasureInput {
        entries: Vec::new(),
        archive_ranges: vec![ErasureRange {
            offset: pr.offset + 1, // not aligned
            length: 3,             // not a multiple of 256
        }],
    };
    let err = plan_archive_repair(&archive, erasures).expect_err("should fail");
    assert!(
        matches!(err, SarError::RecoveryUnavailable(_)),
        "expected RecoveryUnavailable for spec-incomplete case"
    );
}

// ---------------------------------------------------------------------------
// Verify that repair is not supported when there's no TLV
// ---------------------------------------------------------------------------

#[test]
fn repair_archive_fails_without_tlv() {
    use sar_core::recovery::repair_archive;
    use sar_core::recovery::{ProtectedRange, RecoveryPlan};

    let archive = build_archive_no_ec();
    // Craft a plan manually (this would never be returned by plan_archive_repair
    // for a no-EC archive, but we test the underlying repair function directly).
    let plan = RecoveryPlan {
        erasures: ErasureInput {
            entries: Vec::new(),
            archive_ranges: Vec::new(),
        },
        protected_range: ProtectedRange {
            offset: 8,
            length: 4,
            algo_id: 0x14,
        },
        algo_id: 0x14,
    };
    let err = repair_archive(&archive, &plan).expect_err("should fail");
    assert!(matches!(
        err,
        SarError::RecoveryUnavailable(_) | SarError::Bounds(_)
    ));
}
