// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{
    flags::GlobalFlags,
    format::{parse_central_dictionary, parse_footer},
    limits::ResourceLimits,
};

fn parser_limits() -> ResourceLimits {
    ResourceLimits {
        max_cd_bytes: 4096,
        max_entry_count: 128,
        max_tlv_bytes: 512,
        max_tlv_count: 16,
        max_fec_value_bytes: 512,
        ..ResourceLimits::default()
    }
}

fn cd_flags(selector: u8) -> GlobalFlags {
    let mut flags = GlobalFlags::empty();

    if selector & 0x01 != 0 {
        flags |= GlobalFlags::SIZE_64BIT;
    }
    if selector & 0x02 != 0 {
        flags |= GlobalFlags::OPT_PRESENT;
    }
    if selector & 0x04 != 0 {
        flags |= GlobalFlags::HAS_GLOBAL_CRC32;
    }
    if selector & 0x08 != 0 {
        flags |= GlobalFlags::PARTITIONED_ARCHIVE;
    }

    flags
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_footer(data);

    if data.is_empty() {
        return;
    }

    let flags = cd_flags(data[0]);
    let limits = parser_limits();
    let _ = parse_central_dictionary(&data[1..], flags, &limits);
});
