// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{format::parse_global_header, limits::ResourceLimits};

fn parser_limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 4096,
        max_global_flags_bytes: 256,
        max_kms_payload_bytes: 512,
        max_tlv_bytes: 512,
        max_tlv_count: 16,
        ..ResourceLimits::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = parser_limits();
    let _ = parse_global_header(data, &limits);
});
