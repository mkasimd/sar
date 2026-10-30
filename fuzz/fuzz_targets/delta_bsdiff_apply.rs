// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! WP-7: bounded `apply_bsdiff` execution fuzz target.
//!
//! Input layout: `u16` little-endian base length, base bytes, then the patch.
//! Executes real SARBSD01 patch application under small limits; the output must
//! never exceed the configured target bound.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_delta::{apply_bsdiff, bsdiff::BsdiffLimits};

const MAX_OUTPUT: u64 = 64 * 1024;

fn limits() -> BsdiffLimits {
    BsdiffLimits {
        max_patch_size: 64 * 1024,
        max_control_bytes: 8 * 1024,
        max_diff_bytes: 64 * 1024,
        max_extra_bytes: 64 * 1024,
        max_control_triples: 256,
        max_target_size: MAX_OUTPUT,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((len_bytes, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let base_len = usize::from(u16::from_le_bytes(*len_bytes)).min(rest.len());
    let (base, patch) = rest.split_at(base_len);
    if let Ok(out) = apply_bsdiff(base, patch, &limits()) {
        assert!(out.len() as u64 <= MAX_OUTPUT);
    }
});
