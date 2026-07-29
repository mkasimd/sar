// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_core::{flags::GlobalFlags, format::parse_lfh, limits::ResourceLimits};

/// PR4-focused resource limits: wider than the basic `parse_lfh` target to
/// exercise fragmentation, FEC, CDC, and filesystem metadata edge cases, but
/// still bounded to keep fuzz iterations fast.
fn parser_limits() -> ResourceLimits {
    ResourceLimits {
        max_lfh_header_bytes: 4 * 1024,
        max_path_bytes: 1024,
        max_sparse_map_bytes: 4 * 1024,
        max_sparse_descriptors: 256,
        max_fec_value_bytes: 4 * 1024,
        max_fragment_count: 256,
        max_fragment_group_span: 256 * 1024,
        max_loss_tolerant_gap: 256 * 1024,
        max_decoded_entry_size: 64 * 1024,
        max_in_memory_buffer: 64 * 1024,
        max_total_pipeline_memory: 128 * 1024,
        ..ResourceLimits::default()
    }
}

/// Map the first two input bytes to a PR4-relevant combination of GlobalFlags.
///
/// Byte 0 selects flags relevant to fragmentation, FEC/recovery, sparse, path,
/// permissions, UID/GID, and timestamps (same mapping as `parse_lfh` for
/// continuity with existing seeds).
///
/// Byte 1 selects additional flags relevant to PR4: CDC, delta, symlinks,
/// per-file CRC, deduplication, and compressed/delta LFH fields.
fn lfh_flags(sel0: u8, sel1: u8) -> GlobalFlags {
    let mut flags = GlobalFlags::empty();

    // Byte 0: fragmentation and core metadata flags
    if sel0 & 0x01 != 0 {
        flags |= GlobalFlags::SIZE_64BIT;
    }
    if sel0 & 0x02 != 0 {
        flags |= GlobalFlags::HAS_PATH;
    }
    if sel0 & 0x04 != 0 {
        flags |= GlobalFlags::SPARSE_FILES;
    }
    if sel0 & 0x08 != 0 {
        flags |= GlobalFlags::SELECTIVE_FEC;
    }
    if sel0 & 0x10 != 0 {
        flags |= GlobalFlags::HAS_PERMS;
    }
    if sel0 & 0x20 != 0 {
        flags |= GlobalFlags::EXT_UID_GID;
    }
    if sel0 & 0x40 != 0 {
        flags |= GlobalFlags::EXT_TIME;
    }
    if sel0 & 0x80 != 0 {
        flags |= GlobalFlags::FILE_FRAGMENTATION;
    }

    // Byte 1: additional PR4 metadata flags
    if sel1 & 0x01 != 0 {
        flags |= GlobalFlags::CDC_SUPPORT;
    }
    if sel1 & 0x02 != 0 {
        flags |= GlobalFlags::HAS_DELTA;
    }
    if sel1 & 0x04 != 0 {
        flags |= GlobalFlags::HAS_SYMLINKS;
    }
    if sel1 & 0x08 != 0 {
        flags |= GlobalFlags::PER_FILE_CRC;
    }
    if sel1 & 0x10 != 0 {
        flags |= GlobalFlags::DEDUPLICATION;
    }
    if sel1 & 0x20 != 0 {
        flags |= GlobalFlags::COMPRESSED;
    }

    flags
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let flags = lfh_flags(data[0], data[1]);
    let limits = parser_limits();
    let _ = parse_lfh(&data[2..], &flags, &limits);
});
