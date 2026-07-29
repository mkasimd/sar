// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use sar_archive::{ArchiveReader, ArchiveReaderOptions};
use sar_core::limits::ResourceLimits;

fn fuzz_limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 64 * 1024,
        max_entry_count: 32,
        max_lfh_header_bytes: 4 * 1024,
        max_path_bytes: 1024,
        max_global_flags_bytes: 256,
        max_kms_payload_bytes: 512,
        max_tlv_bytes: 4 * 1024,
        max_tlv_count: 64,
        max_cd_bytes: 16 * 1024,
        max_decoded_entry_size: 64 * 1024,
        max_in_memory_buffer: 64 * 1024,
        max_total_pipeline_memory: 128 * 1024,
        max_sparse_map_bytes: 4 * 1024,
        max_sparse_descriptors: 64,
        max_fragment_count: 64,
        max_fragment_group_span: 64 * 1024,
        max_fragment_gap_bytes: 64 * 1024,
        max_fec_value_bytes: 4 * 1024,
        max_recovery_protected_range: 64 * 1024,
        max_repair_working_set: 64 * 1024,
        max_cdc_chunk_count: 1024,
        max_cdc_metadata_bytes: 64 * 1024,
        ..ResourceLimits::default()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    for allow_lossy in [false, true] {
        let options = ArchiveReaderOptions {
            limits: fuzz_limits(),
            ..ArchiveReaderOptions::default()
        };
        let cursor = Cursor::new(data);
        let Ok(mut reader) = ArchiveReader::with_options(cursor, options) else {
            continue;
        };
        let _ = reader.read_all_logical_files(allow_lossy);
    }
});
