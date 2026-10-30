// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Resource-safety and correctness tests for archive-level repair (WP-7B,
//! `M13-RECOVERY-001`).
//!
//! The archives built here carry real XOR / Reed-Solomon parity over the
//! protected range, so successful repairs are checked byte-for-byte against the
//! pristine archive.  Working-set boundaries are pinned against the documented
//! peak-memory model in `repair_archive`.

use sar_archive::recovery::{
    ErasureInput, ErasureRange, ProtectedRange, RecoveryPlan, inspect_recovery_metadata,
    plan_archive_repair, repair_archive,
};
use sar_core::{
    GlobalFlags, ResourceLimits, SarError,
    format::{
        CentralDictionary, Footer, GlobalHeader, write_central_dictionary, write_footer,
        write_global_header,
    },
    tlv::Tlv,
};
use sar_fec::{FecCodec, FecOptions, RsCodec, XorCodec};

const PROT_OFFSET: u64 = 8;

#[derive(Clone, Copy)]
enum Codec {
    Xor { stripe: u8, index: u8 },
    Rs { k: u8, parity: u8, symbol: u32 },
}

struct Fixture {
    archive: Vec<u8>,
    tlv_len: u64,
    cd_len: u64,
    block: u64,
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + i / 251) % 251).expect("test setup"))
        .collect()
}

fn header_bytes() -> Vec<u8> {
    write_global_header(&GlobalHeader {
        version: 0x01,
        flags: GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT,
        kms: None,
    })
    .expect("header")
}

fn wrap_archive(protected_len: usize, type_id: u8, tlv_value: &[u8]) -> (Vec<u8>, u64) {
    let flags = GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
    let mut archive = header_bytes();
    let data_len = protected_len + 8 - archive.len();
    archive.extend_from_slice(&pattern(data_len));
    let cd_offset = archive.len() as u64;
    let cd = CentralDictionary {
        version: 0x01,
        file_count: 0,
        global_crc32: None,
        metadata: vec![Tlv {
            type_id,
            value: tlv_value.to_vec(),
        }],
        offsets: Vec::new(),
    };
    let cd_bytes = write_central_dictionary(&cd, flags).expect("cd");
    let cd_len = cd_bytes.len() as u64;
    archive.extend_from_slice(&cd_bytes);
    archive.extend_from_slice(&write_footer(Footer { cd_offset }));
    (archive, cd_len)
}

/// Builds an archive whose protected range is exactly `protected_len` bytes and
/// whose RECOVERY TLV holds genuine parity for it.
fn build(codec: Codec, protected_len: usize) -> Fixture {
    let header_len = header_bytes().len();
    assert!(protected_len + 8 >= header_len);
    let (type_id, value, block) = {
        // Parity is computed over the final protected bytes, which do not
        // depend on the CD, so build once without a TLV to extract them.
        let (probe, _) = wrap_archive(protected_len, 0x14, &[0, 0]);
        let protected = &probe[8..8 + protected_len];
        match codec {
            Codec::Xor { stripe, index } => {
                let c = XorCodec::new(stripe, index).expect("xor");
                let v = c.encode_recovery(protected, FecOptions).expect("encode");
                (0x14, v.data, 256u64 << index)
            }
            Codec::Rs { k, parity, symbol } => {
                let c = RsCodec::new(k, parity, symbol).expect("rs");
                let v = c.encode_recovery(protected, FecOptions).expect("encode");
                (0x11, v.data, u64::from(symbol))
            }
        }
    };
    let (archive, cd_len) = wrap_archive(protected_len, type_id, &value);
    Fixture {
        archive,
        tlv_len: value.len() as u64,
        cd_len,
        block,
    }
}

fn range(rel_offset: u64, length: u64) -> ErasureRange {
    ErasureRange {
        offset: PROT_OFFSET + rel_offset,
        length,
    }
}

/// Overwrites the erased ranges with garbage.  The first 32 bytes (Global
/// Flags and header) stay intact so the archive remains parseable; those bytes
/// are still part of the erased range and are recovered by the codec.
fn corrupt(archive: &[u8], ranges: &[ErasureRange]) -> Vec<u8> {
    let mut bad = archive.to_vec();
    for r in ranges {
        let start = usize::try_from(r.offset).expect("test setup").max(32);
        let end = usize::try_from(r.offset + r.length).expect("test setup");
        if start < end {
            bad[start..end].fill(0xEE);
        }
    }
    bad
}

fn plan_for(bad: &[u8], ranges: Vec<ErasureRange>) -> RecoveryPlan {
    plan_archive_repair(
        bad,
        ErasureInput {
            entries: Vec::new(),
            archive_ranges: ranges,
        },
        &ResourceLimits::unlimited(),
    )
    .expect("plan")
}

fn limit(bytes: u64) -> ResourceLimits {
    ResourceLimits {
        max_repair_working_set: bytes,
        ..ResourceLimits::unlimited()
    }
}

fn manual_plan(offset: u64, length: u64, algo_id: u8, ranges: Vec<ErasureRange>) -> RecoveryPlan {
    RecoveryPlan {
        erasures: ErasureInput {
            entries: Vec::new(),
            archive_ranges: ranges,
        },
        protected_range: ProtectedRange {
            offset,
            length,
            algo_id,
        },
        algo_id,
    }
}

/// Independent RS codec scratch model: symbol buffers, GF matrices live during
/// inversion (4 t^2, `t <= min(k, parity)`), Vandermonde (`parity * k`) and
/// per-group index vectors / row headers.
fn rs_scratch(k: u64, parity: u64, symbol: u64) -> u64 {
    let t = k.min(parity);
    (1 + 2 * parity) * symbol + 4 * t * t + parity * k + 16 * k + 64 * t
}

/// Documented peak-memory model of `repair_archive`.
struct Model {
    archive: u64,
    cd_len: u64,
    tlv: u64,
    ranges_all: u64,
    ranges_nonempty: u64,
    unique_blocks: u64,
    padded: u64,
    scratch: u64,
}

impl Model {
    fn peak(&self) -> u64 {
        let a = self.archive;
        let merge = 16 * self.ranges_nonempty;
        let index = 8 * self.unique_blocks;
        let report = 16 * self.ranges_all;
        let mut peak = (a + 2 * self.cd_len)
            .max(a + self.tlv + merge)
            .max(a + self.tlv + merge + index);
        if self.unique_blocks == 0 {
            peak = peak.max(2 * a + report);
        } else {
            peak = peak
                .max(a + self.tlv + index + self.padded + self.scratch)
                .max(2 * a + self.padded + report);
        }
        peak
    }
}

/// Asserts the exact success/failure boundary at `expected` and returns the
/// repaired archive from the passing run.
fn assert_boundary(bad: &[u8], plan: &RecoveryPlan, expected: u64) -> Vec<u8> {
    let err = repair_archive(bad, plan, &limit(expected - 1)).expect_err("below boundary");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
    let (repaired, report) = repair_archive(bad, plan, &limit(expected)).expect("at boundary");
    assert!(report.success);
    repaired
}

// ---------------------------------------------------------------------------
// Correct recovery + exact working-set boundaries
// ---------------------------------------------------------------------------

#[test]
fn xor_repair_recovers_bytes_and_pins_working_set_boundary() {
    let fx = build(
        Codec::Xor {
            stripe: 4,
            index: 0,
        },
        256 * 16,
    );
    let ranges = vec![range(256, 256), range(256 * 6, 256), range(256 * 13, 256)];
    let bad = corrupt(&fx.archive, &ranges);
    assert_ne!(bad, fx.archive);
    let plan = plan_for(&bad, ranges);

    let model = Model {
        archive: fx.archive.len() as u64,
        cd_len: fx.cd_len,
        tlv: fx.tlv_len,
        ranges_all: 3,
        ranges_nonempty: 3,
        unique_blocks: 3,
        padded: 256 * 16,
        scratch: 2 * 256 + 8 * 4,
    };
    let repaired = assert_boundary(&bad, &plan, model.peak());
    assert_eq!(repaired, fx.archive);
}

#[test]
fn rs_repair_recovers_bytes_and_pins_working_set_boundary() {
    let fx = build(
        Codec::Rs {
            k: 4,
            parity: 2,
            symbol: 512,
        },
        512 * 12,
    );
    let ranges = vec![range(0, 1024), range(512 * 5, 512), range(512 * 9, 1024)];
    let bad = corrupt(&fx.archive, &ranges);
    let plan = plan_for(&bad, ranges);

    let model = Model {
        archive: fx.archive.len() as u64,
        cd_len: fx.cd_len,
        tlv: fx.tlv_len,
        ranges_all: 3,
        ranges_nonempty: 3,
        unique_blocks: 5,
        padded: 512 * 12,
        scratch: rs_scratch(4, 2, 512),
    };
    assert_eq!(model.unique_blocks, 5);
    let repaired = assert_boundary(&bad, &plan, model.peak());
    assert_eq!(repaired, fx.archive);
}

/// XOR with a 255-block stripe and 64 KiB blocks makes the codec allocate a
/// ~16 MiB padded buffer for a ~192 KiB protected range.  The previous
/// `A + 2P + TLV` formula accounted well under 1 MiB for this configuration.
#[test]
fn previously_undercounted_codec_padding_is_now_enforced() {
    let prot = 3 * 65_536;
    let fx = build(
        Codec::Xor {
            stripe: 255,
            index: 0x08,
        },
        prot,
    );
    let ranges = vec![range(65_536, 65_536)];
    let bad = corrupt(&fx.archive, &ranges);
    let plan = plan_for(&bad, ranges);

    let old_formula = fx.archive.len() as u64 + 2 * prot as u64 + fx.tlv_len;
    let model = Model {
        archive: fx.archive.len() as u64,
        cd_len: fx.cd_len,
        tlv: fx.tlv_len,
        ranges_all: 1,
        ranges_nonempty: 1,
        unique_blocks: 1,
        padded: 255 * 65_536,
        scratch: 2 * 65_536 + 8 * 255,
    };
    assert!(
        old_formula < 1024 * 1024,
        "old accounting stayed under 1 MiB"
    );
    assert!(model.peak() > 16 * 1024 * 1024);

    let err = repair_archive(&bad, &plan, &limit(1024 * 1024)).expect_err("rejected");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");

    let repaired = assert_boundary(&bad, &plan, model.peak());
    assert_eq!(repaired, fx.archive);
}

/// Acceptance coverage for M13-RECOVERY-001: with erasures the
/// repaired-output peak holds the input archive (X), the recovered protected
/// range (P) and the repaired archive (X), so no limit below `2X + P` may be
/// accepted even when the former `X + 2P + T` estimate would have passed.
#[test]
fn repaired_output_peak_is_not_undercounted_below_two_archives_plus_protected_range() {
    let cases = [
        (
            build(
                Codec::Xor {
                    stripe: 4,
                    index: 0,
                },
                256 * 16,
            ),
            vec![range(256, 256), range(256 * 6, 256)],
        ),
        (
            build(
                Codec::Rs {
                    k: 4,
                    parity: 2,
                    symbol: 512,
                },
                512 * 12,
            ),
            vec![range(0, 1024), range(512 * 9, 512)],
        ),
    ];
    for (fx, ranges) in cases {
        let bad = corrupt(&fx.archive, &ranges);
        let plan = plan_for(&bad, ranges);
        let x = fx.archive.len() as u64;
        let p = prot_len(&fx);
        let old_estimate = x + 2 * p + fx.tlv_len;
        let minimum_peak = 2 * x + p;
        assert!(old_estimate < minimum_peak, "old estimate undercounts");
        for rejected in [old_estimate, minimum_peak - 1] {
            let err = repair_archive(&bad, &plan, &limit(rejected)).expect_err("undercounted");
            assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
        }
        let (repaired, report) =
            repair_archive(&bad, &plan, &ResourceLimits::unlimited()).expect("unbounded repair");
        assert!(report.success);
        assert_eq!(repaired, fx.archive);
    }
}

#[test]
fn repair_without_erasures_copies_archive_and_pins_boundary() {
    let fx = build(
        Codec::Xor {
            stripe: 4,
            index: 0,
        },
        256 * 8,
    );
    let plan = plan_for(&fx.archive, Vec::new());
    let model = Model {
        archive: fx.archive.len() as u64,
        cd_len: fx.cd_len,
        tlv: fx.tlv_len,
        ranges_all: 0,
        ranges_nonempty: 0,
        unique_blocks: 0,
        padded: 0,
        scratch: 0,
    };
    let repaired = assert_boundary(&fx.archive, &plan, model.peak());
    assert_eq!(repaired, fx.archive);
}

#[test]
fn overlapping_and_duplicate_ranges_are_merged_before_expansion() {
    // Stripe size 1: parity equals data, so even a fully erased range recovers.
    let fx = build(
        Codec::Xor {
            stripe: 1,
            index: 0,
        },
        256 * 64,
    );
    let mut ranges: Vec<ErasureRange> = (0..2000).map(|_| range(0, 256 * 64)).collect();
    ranges.push(range(256 * 10, 256 * 5));
    ranges.push(range(256 * 3, 0));
    let bad = corrupt(&fx.archive, &ranges);
    let plan = plan_for(&bad, ranges);

    let model = Model {
        archive: fx.archive.len() as u64,
        cd_len: fx.cd_len,
        tlv: fx.tlv_len,
        ranges_all: 2002,
        ranges_nonempty: 2001,
        unique_blocks: 64,
        padded: 256 * 64,
        scratch: 2 * 256 + 8,
    };
    let repaired = assert_boundary(&bad, &plan, model.peak());
    assert_eq!(repaired, fx.archive);
}

// ---------------------------------------------------------------------------
// Erasure-count and capacity limits
// ---------------------------------------------------------------------------

#[test]
fn excessive_erasure_count_is_ec_failed_before_index_allocation() {
    let fx = build(
        Codec::Rs {
            k: 4,
            parity: 2,
            symbol: 512,
        },
        512 * 12,
    );
    // 12 erased symbols > 3 groups * 2 parity symbols.
    let ranges = vec![range(0, 512 * 12)];
    let bad = corrupt(&fx.archive, &ranges);
    let plan = plan_for(&bad, ranges);

    let err = repair_archive(&bad, &plan, &ResourceLimits::unlimited()).expect_err("fail");
    assert!(matches!(err, SarError::EcFailed(_)), "{err:?}");

    // Fails on capacity even when the limit only covers the merge stage.
    let a = fx.archive.len() as u64;
    let tight = (a + 2 * fx.cd_len).max(a + fx.tlv_len + 16);
    let err = repair_archive(&bad, &plan, &limit(tight)).expect_err("fail");
    assert!(matches!(err, SarError::EcFailed(_)), "{err:?}");
}

#[test]
fn too_many_erasures_in_one_group_or_stripe_is_ec_failed() {
    let rs = build(
        Codec::Rs {
            k: 4,
            parity: 2,
            symbol: 512,
        },
        512 * 12,
    );
    let ranges = vec![range(0, 512 * 3)];
    let bad = corrupt(&rs.archive, &ranges);
    let plan = plan_for(&bad, ranges);
    let err = repair_archive(&bad, &plan, &ResourceLimits::unlimited()).expect_err("fail");
    assert!(matches!(err, SarError::EcFailed(_)), "{err:?}");

    let xor = build(
        Codec::Xor {
            stripe: 4,
            index: 0,
        },
        256 * 16,
    );
    let ranges = vec![range(0, 512)];
    let bad = corrupt(&xor.archive, &ranges);
    let plan = plan_for(&bad, ranges);
    let err = repair_archive(&bad, &plan, &ResourceLimits::unlimited()).expect_err("fail");
    assert!(matches!(err, SarError::EcFailed(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// Caller-constructed plans
// ---------------------------------------------------------------------------

fn xor_fixture() -> Fixture {
    build(
        Codec::Xor {
            stripe: 4,
            index: 0,
        },
        256 * 16,
    )
}

fn prot_len(fx: &Fixture) -> u64 {
    fx.archive.len() as u64 - 8 - fx.cd_len - 8
}

fn repair_err(fx: &Fixture, plan: &RecoveryPlan) -> SarError {
    repair_archive(&fx.archive, plan, &ResourceLimits::unlimited()).expect_err("must reject")
}

#[test]
fn plan_with_overflowing_protected_range_is_rejected() {
    let fx = xor_fixture();
    let err = repair_err(&fx, &manual_plan(u64::MAX, 2, 0x14, Vec::new()));
    assert!(
        matches!(err, SarError::Bounds(_) | SarError::Overflow(_)),
        "{err:?}"
    );
    let err = repair_err(&fx, &manual_plan(PROT_OFFSET, u64::MAX, 0x14, Vec::new()));
    assert!(
        matches!(err, SarError::Bounds(_) | SarError::Overflow(_)),
        "{err:?}"
    );
}

#[test]
fn plan_protected_range_must_match_archive() {
    let fx = xor_fixture();
    let p = prot_len(&fx);
    for (offset, length) in [
        (0, p + 8),
        (PROT_OFFSET, p + 1),
        (PROT_OFFSET, p - 1),
        (9, p - 1),
    ] {
        let err = repair_err(&fx, &manual_plan(offset, length, 0x14, Vec::new()));
        assert!(
            matches!(err, SarError::Bounds(_)),
            "{offset}/{length}: {err:?}"
        );
    }
}

#[test]
fn erasure_before_protected_range_is_rejected_without_panic() {
    let fx = xor_fixture();
    let p = prot_len(&fx);
    for offset in [0, 4, 7] {
        let plan = manual_plan(
            PROT_OFFSET,
            p,
            0x14,
            vec![ErasureRange {
                offset,
                length: 256,
            }],
        );
        let err = repair_err(&fx, &plan);
        assert!(matches!(err, SarError::RecoveryUnavailable(_)), "{err:?}");
    }
}

#[test]
fn erasure_range_overflow_and_oversize_are_rejected() {
    let fx = xor_fixture();
    let p = prot_len(&fx);
    let cases = [
        (
            ErasureRange {
                offset: u64::MAX - 100,
                length: 256,
            },
            true,
        ),
        (
            ErasureRange {
                offset: PROT_OFFSET,
                length: u64::MAX,
            },
            true,
        ),
        (range(0, p + 256), false),
        (range(p, 256), false),
        (range(0, 1 << 60), false),
    ];
    for (er, overflow) in cases {
        let err = repair_err(&fx, &manual_plan(PROT_OFFSET, p, 0x14, vec![er]));
        if overflow {
            assert!(matches!(err, SarError::Overflow(_)), "{err:?}");
        } else {
            assert!(matches!(err, SarError::RecoveryUnavailable(_)), "{err:?}");
        }
    }
}

#[test]
fn unaligned_erasures_are_rejected_by_repair() {
    let fx = xor_fixture();
    let p = prot_len(&fx);
    for er in [range(1, 256), range(0, 255), range(0, 257)] {
        let err = repair_err(&fx, &manual_plan(PROT_OFFSET, p, 0x14, vec![er]));
        assert!(matches!(err, SarError::RecoveryUnavailable(_)), "{err:?}");
    }
}

#[test]
fn inconsistent_plan_algorithm_ids_are_rejected() {
    let fx = xor_fixture();
    let p = prot_len(&fx);
    let mut plan = manual_plan(PROT_OFFSET, p, 0x14, Vec::new());
    plan.protected_range.algo_id = 0x11;
    assert!(matches!(repair_err(&fx, &plan), SarError::Malformed(_)));

    let plan = manual_plan(PROT_OFFSET, p, 0x11, Vec::new());
    assert!(matches!(
        repair_err(&fx, &plan),
        SarError::RecoveryUnavailable(_)
    ));
}

#[test]
fn tlv_protected_length_must_match_plan() {
    // TLV claims a protected length one block longer than the real range.
    let header_len = header_bytes().len();
    let real_len = 256 * 8;
    assert!(real_len + 8 > header_len);
    let c = XorCodec::new(4, 0).expect("test setup");
    let longer = pattern(real_len + 256);
    let value = c
        .encode_recovery(&longer, FecOptions)
        .expect("test setup")
        .data;
    let (archive, cd_len) = wrap_archive(real_len, 0x14, &value);
    let fx = Fixture {
        archive,
        tlv_len: value.len() as u64,
        cd_len,
        block: 256,
    };
    let plan = manual_plan(PROT_OFFSET, prot_len(&fx), 0x14, vec![range(0, fx.block)]);
    assert!(matches!(repair_err(&fx, &plan), SarError::InvalidLength(_)));
}

#[test]
fn zero_or_reserved_block_sizes_are_rejected_without_panic() {
    // RS symbol size 0 and XOR reserved block-size index.
    let mut rs_value = vec![4u8, 2];
    rs_value.extend_from_slice(&0u32.to_le_bytes());
    rs_value.extend_from_slice(&1024u64.to_le_bytes());
    rs_value.extend_from_slice(&1u32.to_le_bytes());
    let mut xor_value = vec![4u8, 0x09];
    xor_value.extend_from_slice(&1024u64.to_le_bytes());
    xor_value.extend_from_slice(&1u32.to_le_bytes());
    xor_value.extend_from_slice(&[0u8; 256]);

    for (type_id, value) in [(0x11u8, rs_value), (0x14u8, xor_value)] {
        let (archive, _) = wrap_archive(1024, type_id, &value);
        assert!(inspect_recovery_metadata(&archive, &ResourceLimits::unlimited()).is_err());
        let err = plan_archive_repair(
            &archive,
            ErasureInput {
                entries: Vec::new(),
                archive_ranges: vec![range(0, 256)],
            },
            &ResourceLimits::unlimited(),
        )
        .expect_err("plan must fail");
        assert!(
            matches!(
                err,
                SarError::Malformed(_) | SarError::ReservedValue(_) | SarError::InvalidLength(_)
            ),
            "{err:?}"
        );
        let plan = manual_plan(PROT_OFFSET, 1024, type_id, vec![range(0, 256)]);
        assert!(repair_archive(&archive, &plan, &ResourceLimits::unlimited()).is_err());
    }
}

#[test]
fn plan_archive_repair_rejects_overflow_and_pre_range_erasures() {
    let fx = xor_fixture();
    for er in [
        ErasureRange {
            offset: u64::MAX,
            length: 2,
        },
        ErasureRange {
            offset: 0,
            length: 256,
        },
    ] {
        let err = plan_archive_repair(
            &fx.archive,
            ErasureInput {
                entries: Vec::new(),
                archive_ranges: vec![er],
            },
            &ResourceLimits::unlimited(),
        )
        .expect_err("reject");
        assert!(
            matches!(
                err,
                SarError::Overflow(_) | SarError::RecoveryUnavailable(_)
            ),
            "{err:?}"
        );
    }
}

#[test]
fn stage_one_limit_rejects_before_central_dictionary_parse() {
    let fx = xor_fixture();
    let plan = plan_for(&fx.archive, Vec::new());
    let stage1 = fx.archive.len() as u64 + 2 * fx.cd_len;
    let err = repair_archive(&fx.archive, &plan, &limit(stage1 - 1)).expect_err("reject");
    assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
}

/// Largest RS configuration the codec accepts (k = 255, 32 parity symbols):
/// the matrix terms of the scratch model are at their maximum and are pinned
/// at the exact limit boundary, with a full group of 32 erasures recovered.
#[test]
fn rs_maximum_configuration_scratch_boundary_is_exact() {
    let symbol = 16u64;
    let fx = build(
        Codec::Rs {
            k: 255,
            parity: 32,
            symbol: 16,
        },
        255 * 16 * 2,
    );
    assert_eq!(fx.block, symbol);
    let ranges = vec![
        range(2 * symbol, 32 * symbol),
        range(255 * symbol + 5 * symbol, symbol),
    ];
    let bad = corrupt(&fx.archive, &ranges);
    let plan = plan_for(&bad, ranges);

    let scratch = rs_scratch(255, 32, symbol);
    assert_eq!(
        scratch,
        65 * 16 + 4 * 32 * 32 + 32 * 255 + 16 * 255 + 64 * 32
    );
    let model = Model {
        archive: fx.archive.len() as u64,
        cd_len: fx.cd_len,
        tlv: fx.tlv_len,
        ranges_all: 2,
        ranges_nonempty: 2,
        unique_blocks: 33,
        padded: 255 * 16 * 2,
        scratch,
    };
    let repaired = assert_boundary(&bad, &plan, model.peak());
    assert_eq!(repaired, fx.archive);
}
