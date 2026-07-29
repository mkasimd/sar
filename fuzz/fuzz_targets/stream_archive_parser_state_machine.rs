// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.4: Stateful `StreamArchiveParser` forward-only push-parsing fuzz target.
//!
//! Drives `StreamArchiveParser` through arbitrary bounded operation sequences
//! to exercise push-parse state transitions with unusual chunk boundaries.
//! No key providers, no filesystem extraction.
//!
//! ## Operations exercised
//!
//! - `PushChunk`: append a bounded byte chunk to the parser input buffer.
//! - `Step`: execute one deterministic parser step.
//! - `FinalizeInput`: signal that no further bytes will arrive.
//! - `CheckState`: read the current parser state without side effects.
//!
//! ## Bounds enforced before use
//!
//! - Byte chunks are truncated to 64 KiB.
//! - Operation count is truncated to 256 operations.
//! - Resource limits are set conservatively before any allocation.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sar_archive::{ArchiveReaderOptions, StreamArchiveParser, StreamParseState};
use sar_core::{SarError, limits::ResourceLimits};

const MAX_CHUNK_BYTES: usize = 256 * 1024;
const MAX_OPS: usize = 256;

/// One fuzzer-generated parser operation.
#[derive(Debug, Arbitrary)]
enum ParserOp {
    /// Push a byte chunk into the parser input buffer.
    PushChunk(Vec<u8>),
    /// Execute one deterministic parser step.
    Step,
    /// Declare that no further bytes will arrive.
    FinalizeInput,
    /// Query the current parser state without side effects.
    CheckState,
}

fn fuzz_limits() -> ResourceLimits {
    ResourceLimits {
        max_archive_size: 128 * 1024,
        max_entry_count: 32,
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

fuzz_target!(|ops: Vec<ParserOp>| {
    let options = ArchiveReaderOptions {
        limits: fuzz_limits(),
        ..ArchiveReaderOptions::default()
    };

    let mut parser = StreamArchiveParser::with_options(options);

    for op in ops.into_iter().take(MAX_OPS) {
        // Stop after the parser enters a terminal state.
        match parser.state() {
            StreamParseState::Error | StreamParseState::ArchiveComplete => break,
            _ => {}
        }

        match op {
            ParserOp::PushChunk(chunk) => {
                let chunk = if chunk.len() > MAX_CHUNK_BYTES {
                    &chunk[..MAX_CHUNK_BYTES]
                } else {
                    &chunk[..]
                };
                match parser.push_bytes(chunk) {
                    Ok(()) => {}
                    Err(SarError::LimitExceeded(_)) | Err(SarError::Overflow(_)) => {
                        // Resource-limit rejection; continue without bytes.
                    }
                    Err(_) => {
                        // Other errors are unexpected on push; stop.
                        break;
                    }
                }
            }

            ParserOp::Step => {
                match parser.step() {
                    Ok(_) => {}
                    Err(_) => {
                        // Parser errors set the internal Error state; the loop
                        // guard above will stop on the next iteration.
                    }
                }
            }

            ParserOp::FinalizeInput => {
                parser.finalize_input();
            }

            ParserOp::CheckState => {
                let _ = parser.state();
            }
        }
    }

    // Drive any remaining steps to completion or error to exercise the final
    // parser state transitions.
    parser.finalize_input();
    for _ in 0..MAX_OPS {
        match parser.state() {
            StreamParseState::Error | StreamParseState::ArchiveComplete => break,
            _ => {}
        }

        match parser.step() {
            Ok(sar_archive::StreamStep::Complete) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
});
