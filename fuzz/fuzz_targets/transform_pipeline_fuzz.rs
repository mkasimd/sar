// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.5 PR2: Transform pipeline read/decode fuzz target.
//!
//! Exercises `ArchiveReader` entry decoding with arbitrary input bytes that
//! may declare any compression algorithm ID.  The fuzzer mutates from
//! hand-curated seeds containing valid STORE, DEFLATE, and ZSTD archives to
//! cover:
//!
//! - decompressor initialization per entry
//! - resource-limit enforcement before decompression expansion
//! - decompressor state isolation between consecutive entries
//! - reserved or unsupported compression algorithm IDs
//! - truncated or malformed compressed payloads
//!
//! ## Corpus categories covered
//!
//! - `fuzz/seeds/transform_pipeline/`
//!
//! ## Bounds enforced before use
//!
//! - Archive size: 256 KiB
//! - Entry count: 128
//! - Decoded entry size: 256 KiB
//! - Total pipeline memory: 512 KiB
//!
//! ## What this target does NOT cover
//!
//! - Encryption (no key provider)
//! - Delta patch algorithms requiring a base object
//! - Filesystem extraction
//! - Stream / session semantics

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use sar_archive::{ArchiveReader, ArchiveReaderOptions};
use sar_core::limits::ResourceLimits;

fn fuzz_limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 256 * 1024,
        max_entry_count: 128,
        max_lfh_header_bytes: 8 * 1024,
        max_path_bytes: 2048,
        max_global_flags_bytes: 512,
        max_kms_payload_bytes: 1024,
        max_tlv_bytes: 8 * 1024,
        max_tlv_count: 64,
        max_cd_bytes: 64 * 1024,
        max_decoded_entry_size: 256 * 1024,
        max_in_memory_buffer: 256 * 1024,
        max_total_pipeline_memory: 512 * 1024,
        max_sparse_map_bytes: 8 * 1024,
        max_sparse_descriptors: 128,
        max_fragment_count: 128,
        max_fec_value_bytes: 8 * 1024,
        max_recovery_protected_range: 256 * 1024,
        max_repair_working_set: 256 * 1024,
        max_cdc_chunk_count: 4 * 1024,
        max_cdc_metadata_bytes: 256 * 1024,
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

    // Walk entries to exercise per-entry decompressor initialization.
    // Stopping at 128 entries prevents unbounded iteration.
    for _ in 0..128 {
        match reader.next_entry() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
});
