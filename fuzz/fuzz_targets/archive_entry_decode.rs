// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.3: Archive ordinary entry decoding fuzz target.
//!
//! Exercises `ArchiveReader` global header parsing and bounded ordinary entry
//! walking. Stops after at most 16 entries or on any error. Does not perform
//! filesystem extraction. Does not require key providers or external delta
//! bases. Does not execute stream/session semantics.
//!
//! Note: `next_entry` always decodes payload bytes. Resource limits enforce
//! maximum decoded sizes before allocation.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use sar_archive::{ArchiveReader, ArchiveReaderOptions};
use sar_core::limits::ResourceLimits;

fn fuzz_limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 64 * 1024,
        max_entry_count: 16,
        max_lfh_header_bytes: 4 * 1024,
        max_path_bytes: 1024,
        max_global_flags_bytes: 256,
        max_kms_payload_bytes: 512,
        max_tlv_bytes: 4 * 1024,
        max_tlv_count: 32,
        max_cd_bytes: 16 * 1024,
        max_decoded_entry_size: 64 * 1024,
        max_in_memory_buffer: 64 * 1024,
        max_total_pipeline_memory: 128 * 1024,
        max_sparse_map_bytes: 4 * 1024,
        max_sparse_descriptors: 64,
        max_fragment_count: 64,
        max_fec_value_bytes: 4 * 1024,
        max_recovery_protected_range: 64 * 1024,
        max_repair_working_set: 64 * 1024,
        max_cdc_chunk_count: 1024,
        max_cdc_metadata_bytes: 64 * 1024,
        ..ResourceLimits::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let options = ArchiveReaderOptions {
        limits: fuzz_limits(),
        ..ArchiveReaderOptions::default()
    };

    let cursor = Cursor::new(data);
    let Ok(mut reader) = ArchiveReader::with_options(cursor, options) else {
        return;
    };

    if reader.read_global_header().is_err() {
        return;
    }

    for _ in 0..16 {
        match reader.next_entry() {
            Ok(Some(_entry)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
});
