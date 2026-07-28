// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.4: Stateful `ArchiveWriter` operation-sequence fuzz target.
//!
//! Drives `ArchiveWriter<Vec<u8>>` through arbitrary bounded operation
//! sequences to exercise lifecycle state transitions.  No filesystem
//! extraction, no key providers, no encryption.
//!
//! ## Operations exercised
//!
//! - `AddEntry`: add a regular-file entry with bounded name and payload.
//! - `AddSparseEntry`: add a sparse entry with bounded extents and payload
//!   (requires `sparse = true` in writer options).
//! - `CheckState`: call `stream_state()` and discard the result.
//! - `Finish`: call `finish()`, consuming the writer.
//!
//! ## Bounds enforced before use
//!
//! - Entry names are truncated to 256 bytes.
//! - Entry payloads are truncated to 64 KiB.
//! - Sparse extent lists are truncated to 32 extents.
//! - Operation count is truncated to 256 operations.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput, SparseWriteOptions};
use sar_core::SarError;
use sar_sparse::SparseExtent;

const MAX_NAME_BYTES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_EXTENTS: usize = 32;
const MAX_OPS: usize = 256;

/// One fuzzer-generated operation for the archive writer.
#[derive(Debug, Arbitrary)]
enum WriterOp {
    /// Add a regular-file entry.
    AddEntry {
        name: Vec<u8>,
        payload: Vec<u8>,
    },
    /// Add a sparse entry.  The writer must have `sparse = true`; operations
    /// that fail with a validation error are simply ignored.
    AddSparseEntry {
        name: Vec<u8>,
        payload: Vec<u8>,
        extents: Vec<(u64, u64)>,
        logical_size: u64,
    },
    /// Query current stream-write state without side effects.
    CheckState,
    /// Finalize and consume the writer.
    Finish,
}

fn truncate_bytes(v: Vec<u8>, max: usize) -> Vec<u8> {
    if v.len() > max { v[..max].to_vec() } else { v }
}

fn name_from_bytes(v: Vec<u8>) -> String {
    String::from_utf8_lossy(&truncate_bytes(v, MAX_NAME_BYTES)).into_owned()
}

/// Build a valid set of non-overlapping extents whose total data length equals
/// `payload.len()`.  Returns `None` when the constraints cannot be satisfied
/// with the given inputs (overflow, extents that go past logical_size, etc.).
fn build_extents(
    raw_extents: Vec<(u64, u64)>,
    payload: &[u8],
    logical_size: u64,
) -> Option<Vec<SparseExtent>> {
    let total_payload = u64::try_from(payload.len()).ok()?;
    if total_payload == 0 {
        // No data extents; logical_size must be >= 0 (always true).
        return Some(Vec::new());
    }

    // Limit extent count.
    let raw_extents: Vec<_> = raw_extents.into_iter().take(MAX_EXTENTS).collect();
    if raw_extents.is_empty() {
        // Build a single covering extent: offset=0, length=total_payload.
        if total_payload > logical_size {
            return None;
        }
        return Some(vec![SparseExtent {
            offset: 0,
            length: total_payload,
        }]);
    }

    // Distribute payload bytes across extents by normalizing lengths.
    // Strategy: scale raw lengths proportionally so they sum to total_payload.
    let raw_len_sum: u64 = raw_extents
        .iter()
        .fold(0u64, |acc, (_, l)| acc.saturating_add(*l));

    if raw_len_sum == 0 {
        // All zero-length extents; fall back to single covering extent.
        if total_payload > logical_size {
            return None;
        }
        return Some(vec![SparseExtent {
            offset: 0,
            length: total_payload,
        }]);
    }

    // Build proportional lengths that sum exactly to total_payload.
    let mut lengths: Vec<u64> = raw_extents
        .iter()
        .map(|(_, l)| {
            // proportion = l / raw_len_sum * total_payload
            let num = (*l).saturating_mul(total_payload);
            num / raw_len_sum
        })
        .collect();

    // Fix rounding: ensure the sum equals total_payload.
    let sum: u64 = lengths.iter().sum();
    if sum < total_payload {
        *lengths.last_mut()? += total_payload - sum;
    } else if sum > total_payload {
        let excess = sum - total_payload;
        let last = lengths.last_mut()?;
        *last = last.saturating_sub(excess);
    }

    // Remove zero-length extents.
    let nonzero_count = lengths.iter().filter(|&&l| l > 0).count();
    if nonzero_count == 0 {
        if total_payload > logical_size {
            return None;
        }
        return Some(vec![SparseExtent {
            offset: 0,
            length: total_payload,
        }]);
    }

    // Build non-overlapping extents with monotonically increasing offsets.
    let mut extents = Vec::new();
    let mut cursor: u64 = 0;
    for ((raw_offset, _), length) in raw_extents.iter().zip(lengths.iter()) {
        if *length == 0 {
            continue;
        }
        // Place extent at max(cursor, raw_offset % logical_size) to stay
        // within logical_size and avoid overlaps.
        let placement = if logical_size > 0 {
            let capped = raw_offset % logical_size;
            cursor.max(capped)
        } else {
            cursor
        };
        let end = placement.checked_add(*length)?;
        if end > logical_size {
            break;
        }
        extents.push(SparseExtent {
            offset: placement,
            length: *length,
        });
        cursor = end;
    }

    // Verify the built extents' total data matches total_payload.
    let built_sum: u64 = extents.iter().map(|e| e.length).sum();
    if built_sum != total_payload {
        // Cannot satisfy; fall back to a single covering extent.
        if total_payload > logical_size {
            return None;
        }
        return Some(vec![SparseExtent {
            offset: 0,
            length: total_payload,
        }]);
    }

    Some(extents)
}

fuzz_target!(|ops: Vec<WriterOp>| {
    // Use sparse=true and no_index=false so both entry types and CD/footer are
    // exercised.  No encryption, no key providers.
    let options = ArchiveWriterOptions {
        sparse: true,
        no_index: false,
        ..ArchiveWriterOptions::default()
    };

    let buf: Vec<u8> = Vec::new();
    let Ok(writer) = ArchiveWriter::new(buf, options) else {
        return;
    };

    let mut writer: Option<ArchiveWriter<Vec<u8>>> = Some(writer);
    let mut finished = false;

    for op in ops.into_iter().take(MAX_OPS) {
        let Some(w) = writer.as_mut() else {
            break;
        };

        match op {
            WriterOp::AddEntry { name, payload } => {
                let name = name_from_bytes(name);
                let payload = truncate_bytes(payload, MAX_PAYLOAD_BYTES);
                let entry = EntryInput::file(name, payload);
                match w.add_entry(entry) {
                    Ok(_) => {}
                    Err(SarError::Io(_)) => {
                        // I/O on Vec<u8> should not fail, but treat as terminal.
                        writer = None;
                        finished = true;
                        break;
                    }
                    Err(_) => {
                        // Validation or state errors are expected; continue.
                    }
                }
            }

            WriterOp::AddSparseEntry {
                name,
                payload,
                extents,
                logical_size,
            } => {
                let name = name_from_bytes(name);
                let payload = truncate_bytes(payload, MAX_PAYLOAD_BYTES);
                // Build a coherent extent list for the given payload size.
                // If we cannot build one, skip the operation.
                let Some(built_extents) = build_extents(extents, &payload, logical_size) else {
                    continue;
                };
                let sparse = SparseWriteOptions {
                    logical_size,
                    extents: built_extents,
                };
                match w.write_sparse_entry(&name, &payload, sparse) {
                    Ok(_) => {}
                    Err(SarError::Io(_)) => {
                        writer = None;
                        finished = true;
                        break;
                    }
                    Err(_) => {
                        // Validation errors (e.g. logical_size < extent end)
                        // are expected and non-terminal.
                    }
                }
            }

            WriterOp::CheckState => {
                let _ = w.stream_state();
            }

            WriterOp::Finish => {
                // finish() consumes self; take the writer out of the Option.
                if let Some(w) = writer.take() {
                    let _ = w.finish();
                }
                finished = true;
                break;
            }
        }
    }

    // If finish was never called, call it now to exercise the finalization path.
    if !finished {
        if let Some(w) = writer.take() {
            let _ = w.finish();
        }
    }
});
