// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.3: Archive audit entry walking fuzz target.
//!
//! Exercises `ArchiveReader::audit` with metadata-only payload policy and
//! control-entry rejection. Does not decode encrypted payloads or require key
//! providers. Does not execute control entries. Does not perform filesystem
//! extraction. Does not execute stream/session semantics.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use sar_archive::{
    ArchiveAuditOptions, ArchiveReader, ArchiveReaderOptions, ControlEntryPolicy,
    PayloadAuditPolicy,
};
use sar_core::limits::ResourceLimits;

fn fuzz_limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 1024 * 1024,
        max_entry_count: 64,
        max_lfh_header_bytes: 64 * 1024,
        max_path_bytes: 4096,
        max_global_flags_bytes: 4096,
        max_kms_payload_bytes: 16 * 1024,
        max_tlv_bytes: 64 * 1024,
        max_tlv_count: 256,
        max_cd_bytes: 256 * 1024,
        max_decoded_entry_size: 1024 * 1024,
        max_in_memory_buffer: 1024 * 1024,
        max_total_pipeline_memory: 2 * 1024 * 1024,
        max_sparse_map_bytes: 64 * 1024,
        max_sparse_descriptors: 1024,
        max_fragment_count: 1024,
        max_fec_value_bytes: 64 * 1024,
        max_recovery_protected_range: 1024 * 1024,
        max_repair_working_set: 1024 * 1024,
        max_cdc_chunk_count: 16 * 1024,
        max_cdc_metadata_bytes: 1024 * 1024,
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

    let audit_options = ArchiveAuditOptions {
        control_entry_policy: ControlEntryPolicy::Reject,
        payload_policy: PayloadAuditPolicy::MetadataOnly,
        include_inert_payload_bytes: false,
    };

    let _ = reader.audit(audit_options);
});
