// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{limits::ResourceLimits, tlv::parse_tlvs};

fn parser_limits() -> ResourceLimits {
    ResourceLimits {
        max_tlv_bytes: 512,
        max_tlv_count: 16,
        max_fec_value_bytes: 512,
        max_cdc_metadata_bytes: 512,
        ..ResourceLimits::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = parser_limits();
    let _ = parse_tlvs(data, &limits);
});
