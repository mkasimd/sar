// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! WP-7B: archive-level recovery fuzz target.
//!
//! Exercises `inspect_recovery_metadata`, `plan_archive_repair` and
//! `repair_archive` with caller-controlled archive bytes, recovery metadata,
//! erasure ranges, resource limits and tampered `RecoveryPlan` values.
//!
//! Two input modes share one header byte (`data[0] & 1`):
//!
//! * Structured (bit 0 clear): the target *builds* a valid archive with real
//!   XOR or Reed-Solomon parity from bounded parameters, corrupts the requested
//!   erased ranges, and plans/repairs it.  Because the parity is genuine, any
//!   successful repair is asserted to reproduce the pristine archive
//!   byte-for-byte.  This reaches real planning and repair instead of failing
//!   in header parsing.
//! * Raw (bit 0 set): header-described erasure ranges are applied to arbitrary
//!   archive bytes (the rest of the input), so mutated seeds exercise malformed
//!   Central Dictionaries, TLVs and ranges.
//!
//! Layouts (all multi-byte integers little-endian; missing bytes read as 0):
//!
//! ```text
//! structured: mode, codec, a, b, c, protected_len:u16, limit_sel, limit:u32,
//!             tamper, n_ranges, n_ranges * (start_block, n_blocks, jitter, fill)
//! raw:        mode, tamper, n_ranges, limit_sel, limit:u32,
//!             n_ranges * (offset:u64, length:u64), archive bytes...
//! ```
//!
//! Input size, working-set limit and every allocation are bounded: the working
//! set is capped at 64 MiB and enforced by `repair_archive` before allocation.

#![no_main]

use libfuzzer_sys::fuzz_target;
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

const MAX_INPUT: usize = 64 * 1024;
const MAX_WORKING_SET: u64 = 64 * 1024 * 1024;
const FLAGS_OFFSET: u64 = 8;
/// Bytes at the start of the archive that stay intact so the header parses.
const KEEP_INTACT: usize = 32;

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    fn u64(&mut self) -> u64 {
        u64::from(self.u32()) | (u64::from(self.u32()) << 32)
    }
}

fn limits(selector: u8, value: u32, working_set: Option<u64>) -> ResourceLimits {
    let working_set = working_set.unwrap_or(match selector % 4 {
        0 => u64::from(value).min(MAX_WORKING_SET),
        2 => u64::from(value) % (1024 * 1024),
        _ => MAX_WORKING_SET,
    });
    ResourceLimits {
        max_archive_size: 1024 * 1024,
        max_recovery_protected_range: 1024 * 1024,
        max_cd_bytes: 64 * 1024,
        max_repair_working_set: working_set,
        ..ResourceLimits::default()
    }
}

fn tamper_plan(plan: &mut RecoveryPlan, tamper: u8) {
    match tamper % 8 {
        1 => plan.protected_range.offset = plan.protected_range.offset.wrapping_add(1),
        2 => plan.protected_range.offset = 0,
        3 => plan.protected_range.length = plan.protected_range.length.wrapping_add(1),
        4 => plan.protected_range.length = plan.protected_range.length.saturating_sub(1),
        5 => plan.protected_range.length = u64::MAX,
        6 => plan.protected_range.offset = u64::MAX,
        7 => plan.algo_id ^= 0x05,
        _ => {}
    }
}

/// Runs inspect, plan and repair (planned and manually constructed plans).
/// Returns repaired archives for each successful repair.
fn exercise(
    archive: &[u8],
    ranges: &[ErasureRange],
    tamper: u8,
    selector: u8,
    value: u32,
) -> Vec<Vec<u8>> {
    let lim = limits(selector, value, None);
    let meta = inspect_recovery_metadata(archive, &lim);
    let erasures = ErasureInput {
        entries: Vec::new(),
        archive_ranges: ranges.to_vec(),
    };

    let mut plans: Vec<(RecoveryPlan, bool)> = Vec::new();
    if let Ok(plan) = plan_archive_repair(archive, erasures.clone(), &lim) {
        plans.push((plan, false));
    }
    if let Ok(meta) = &meta {
        if let Some(pr) = &meta.protected_range {
            let mut plan = RecoveryPlan {
                erasures,
                protected_range: ProtectedRange {
                    offset: pr.offset,
                    length: pr.length,
                    algo_id: pr.algo_id,
                },
                algo_id: pr.algo_id,
            };
            tamper_plan(&mut plan, tamper);
            plans.push((plan, tamper % 8 != 0));
        }
    }

    let mut repaired_all = Vec::new();
    for (plan, tampered) in &plans {
        let result = repair_archive(archive, plan, &lim);
        if let Ok((repaired, report)) = result {
            assert!(!*tampered, "tampered plan must be rejected");
            assert_eq!(repaired.len(), archive.len());
            assert!(report.success);
            // Monotonic in the working-set limit.
            let wide = limits(1, 0, Some(MAX_WORKING_SET));
            let (again, _) = repair_archive(archive, plan, &wide).expect("wider limit succeeds");
            assert_eq!(again, repaired);
            repaired_all.push(repaired);
        } else if let Err(SarError::LimitExceeded(_)) = result {
            // Expected when the selected limit is small.
        }
    }
    repaired_all
}

fn build_structured(r: &mut Reader<'_>) -> Option<(Vec<u8>, u64, ErasureInputSpec)> {
    let codec = r.u8();
    let a = r.u8();
    let b = r.u8();
    let c = r.u8();
    let protected_len = 64 + usize::from(r.u16() % 16_384);

    let flags = GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
    let mut archive = write_global_header(&GlobalHeader {
        version: 0x01,
        flags,
        kms: None,
    })
    .ok()?;
    let data_len = (protected_len + 8).checked_sub(archive.len())?;
    archive.extend((0..data_len).map(|i| u8::try_from((i * 31 + i / 251) % 251).unwrap_or(0)));
    let cd_offset = u64::try_from(archive.len()).ok()?;
    let protected = archive[8..].to_vec();

    let (type_id, value, block) = if codec & 1 == 0 {
        let index = b % 4;
        let c = XorCodec::new(1 + a % 16, index).ok()?;
        let v = c.encode_recovery(&protected, FecOptions).ok()?;
        (0x14u8, v.data, 256u64 << index)
    } else {
        let symbol = [64u32, 128, 256, 512][usize::from(c % 4)];
        let c = RsCodec::new(1 + a % 8, 1 + b % 4, symbol).ok()?;
        let v = c.encode_recovery(&protected, FecOptions).ok()?;
        (0x11u8, v.data, u64::from(symbol))
    };

    let cd = CentralDictionary {
        version: 0x01,
        file_count: 0,
        global_crc32: None,
        metadata: vec![Tlv { type_id, value }],
        offsets: Vec::new(),
    };
    let cd_bytes = write_central_dictionary(&cd, flags).ok()?;
    let pristine_len = archive.len();
    archive.extend_from_slice(&cd_bytes);
    archive.extend_from_slice(&write_footer(Footer { cd_offset }));
    Some((
        archive,
        block,
        ErasureInputSpec {
            protected_len: u64::try_from(pristine_len - 8).ok()?,
        },
    ))
}

struct ErasureInputSpec {
    protected_len: u64,
}

fn structured(data: &[u8]) {
    let mut r = Reader(&data[1..]);
    let Some((pristine, block, spec)) = build_structured(&mut r) else {
        return;
    };
    let selector = r.u8();
    let value = r.u32();
    let tamper = r.u8();
    let count = usize::from(r.u8() % 7);
    let blocks = (spec.protected_len / block).max(1);
    let protected_end = usize::try_from(FLAGS_OFFSET + spec.protected_len).unwrap_or(usize::MAX);

    let mut ranges = Vec::new();
    let mut bad = pristine.clone();
    for _ in 0..count {
        let start = u64::from(r.u8()) % blocks;
        let n = 1 + u64::from(r.u8()) % 4;
        let jitter = r.u8();
        let fill = r.u8();
        let mut offset = FLAGS_OFFSET + start * block;
        let mut length = n * block;
        match jitter % 8 {
            0 => offset += 1,
            1 => offset = u64::from(jitter / 8) % FLAGS_OFFSET,
            2 => length += block,
            3 => length = 0,
            _ => {}
        }
        let from = usize::try_from(offset).unwrap_or(usize::MAX).max(KEEP_INTACT);
        let to = usize::try_from(offset + length)
            .unwrap_or(usize::MAX)
            .min(protected_end);
        if from < to {
            bad[from..to].fill(fill);
        }
        ranges.push(ErasureRange { offset, length });
    }

    for repaired in exercise(&bad, &ranges, tamper, selector, value) {
        assert_eq!(repaired, pristine, "successful repair must restore bytes");
    }
}

fn raw(data: &[u8]) {
    let mut r = Reader(&data[1..]);
    let tamper = r.u8();
    let count = usize::from(r.u8() % 9);
    let selector = r.u8();
    let value = r.u32();
    let ranges: Vec<ErasureRange> = (0..count)
        .map(|_| ErasureRange {
            offset: r.u64(),
            length: r.u64(),
        })
        .collect();
    let archive = r.0;
    let _ = exercise(archive, &ranges, tamper, selector, value);
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }
    if data[0] & 1 == 0 {
        structured(data);
    } else {
        raw(data);
    }
});
