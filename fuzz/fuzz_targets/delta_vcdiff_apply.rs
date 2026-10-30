// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! WP-7: bounded `apply_vcdiff` execution fuzz target.
//!
//! Input layout: `u16` little-endian base length, base bytes, then the patch.
//! Executes real VCDIFF window/instruction application under small limits; the
//! output must never exceed the configured output bound.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_delta::{apply_vcdiff, vcdiff::VcdiffLimits};

const MAX_OUTPUT: u64 = 64 * 1024;

fn limits() -> VcdiffLimits {
    VcdiffLimits {
        max_patch_size: 64 * 1024,
        max_window_count: 64,
        max_instruction_count: 4096,
        max_output_size: MAX_OUTPUT,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((len_bytes, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let base_len = usize::from(u16::from_le_bytes(*len_bytes)).min(rest.len());
    let (base, patch) = rest.split_at(base_len);
    if let Ok(out) = apply_vcdiff(base, patch, &limits()) {
        assert!(out.len() as u64 <= MAX_OUTPUT);
    }
});
