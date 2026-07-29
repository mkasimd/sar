// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{limits::ResourceLimits, tlv::parse_tlvs};

/// PR4-focused resource limits: wider than the basic `parse_tlv` target to
/// exercise FEC/recovery TLVs, CDC map TLVs, delta metadata TLVs, and
/// data-hash / metadata edge cases, but still bounded.
fn parser_limits() -> ResourceLimits {
    ResourceLimits {
        max_tlv_bytes: 16 * 1024,
        max_tlv_count: 128,
        max_fec_value_bytes: 16 * 1024,
        max_cdc_metadata_bytes: 16 * 1024,
        ..ResourceLimits::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = parser_limits();
    let _ = parse_tlvs(data, &limits);
});
