// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{flags::GlobalFlags, format::parse_lfh, limits::ResourceLimits};

fn parser_limits() -> ResourceLimits {
    ResourceLimits {
        max_lfh_header_bytes: 512,
        max_path_bytes: 256,
        max_sparse_map_bytes: 512,
        max_fec_value_bytes: 512,
        max_decoded_entry_size: 4096,
        max_in_memory_buffer: 4096,
        max_total_pipeline_memory: 8192,
        ..ResourceLimits::default()
    }
}

fn lfh_flags(selector: u8) -> GlobalFlags {
    let mut flags = GlobalFlags::empty();

    if selector & 0x01 != 0 {
        flags |= GlobalFlags::SIZE_64BIT;
    }
    if selector & 0x02 != 0 {
        flags |= GlobalFlags::HAS_PATH;
    }
    if selector & 0x04 != 0 {
        flags |= GlobalFlags::SPARSE_FILES;
    }
    if selector & 0x08 != 0 {
        flags |= GlobalFlags::SELECTIVE_FEC;
    }
    if selector & 0x10 != 0 {
        flags |= GlobalFlags::HAS_PERMS;
    }
    if selector & 0x20 != 0 {
        flags |= GlobalFlags::EXT_UID_GID;
    }
    if selector & 0x40 != 0 {
        flags |= GlobalFlags::EXT_TIME;
    }
    if selector & 0x80 != 0 {
        flags |= GlobalFlags::FILE_FRAGMENTATION;
    }

    flags
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let flags = lfh_flags(data[0]);
    let limits = parser_limits();
    let _ = parse_lfh(&data[1..], &flags, &limits);
});
