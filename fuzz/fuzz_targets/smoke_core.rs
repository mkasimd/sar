// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{format::parse_global_header, limits::ResourceLimits};

fuzz_target!(|data: &[u8]| {
    let mut limits = ResourceLimits::unlimited();
    limits.max_archive_size = 4096;
    limits.max_path_bytes = 1024;
    limits.max_tlv_bytes = 1024;
    limits.max_tlv_count = 16;

    let _ = parse_global_header(data, &limits);
});
