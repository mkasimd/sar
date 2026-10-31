// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Archive-level CDC Recipe resolution (specification Sections 13.1, 20, 21).
//!
//! A Recipe is an ordered list of 32-byte chunk hashes.  Resolution selects
//! exactly one catalog (the local `CDC_MAP`, or an explicitly configured
//! external resolver), establishes its registered hash algorithm before the
//! Recipe is interpreted, then concatenates hash-verified chunks in Recipe
//! order.  Nothing here performs network access or dereferences
//! `CDC_EXT_PROVIDER` URIs.

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use sar_core::{
    SarError, cdc::CDC_RECIPE_HASH_LEN, compute_cdc_chunk_hash, limits::ResourceLimits, tlv::Tlv,
};

/// Application-supplied source of CDC chunk bytes.
///
/// Installed explicitly with [`crate::archive::ArchiveReader::with_cdc_resolver`].
/// The reader never calls it during parsing, listing, `next_entry` or
/// structural verification; only logical-content reconstruction
/// ([`crate::archive::ArchiveReader::next_logical_entry`] and
/// [`crate::archive::ArchiveReader::read_all_logical_files`]) may.
///
/// The `CDC_EXT_PROVIDER` URI of an archive is inert metadata and is never
/// passed to the resolver; applications decide which provider to trust.
///
/// # Contract
///
/// * `hash_algorithm_id` is the registered SAR hash algorithm configured for
///   the resolver; `hash` is the Recipe element.
/// * Return `None` when the chunk is missing, unavailable or the caller is not
///   authorized; the reader reports `SAR_ERR_RECIPE_UNRESOLVABLE`.
/// * `max_len` is the largest chunk the reader will accept.  A longer chunk is
///   rejected with `SAR_ERR_LIMIT_EXCEEDED`.  Implementations should not
///   produce more than `max_len` bytes.
/// * The returned `Vec` is owned by the reader.  Its bytes are hash-verified
///   with `hash_algorithm_id` before use; a mismatch is
///   `SAR_ERR_HASH_MISMATCH`.
pub trait CdcChunkResolver {
    /// Returns the bytes of the chunk identified by `hash`, or `None`.
    fn resolve_chunk(
        &self,
        hash_algorithm_id: u8,
        hash: &[u8; 32],
        max_len: u64,
    ) -> Option<Vec<u8>>;
}

/// Explicit external-resolution configuration.
pub(crate) struct ExternalCdc {
    pub(crate) algo_id: u8,
    pub(crate) resolver: Box<dyn CdcChunkResolver>,
}

/// Accounted bytes per catalog record (hash, location, map bookkeeping).
const CATALOG_RECORD_BOOKKEEPING: u64 = 96;

/// The unambiguously selected local `CDC_MAP`, indexed by chunk hash.
pub(crate) struct LocalCatalog {
    pub(crate) algo_id: u8,
    records: HashMap<[u8; 32], (u64, u32)>,
    bookkeeping: u64,
}

impl LocalCatalog {
    /// Selects the single `CDC_MAP` in `tlvs`.
    ///
    /// `Ok(None)` means no catalog is present.  More than one `CDC_MAP` is
    /// `SAR_ERR_METADATA_CONFLICT`; a non-zero `Partition_Index` is rejected
    /// because this reader handles unpartitioned archives only.  Bookkeeping
    /// is charged to `max_total_pipeline_memory` before the index is built.
    pub(crate) fn select(tlvs: &[Tlv], limits: &ResourceLimits) -> Result<Option<Self>, SarError> {
        let Some(map) = sar_core::cdc::parse_entry_cdc_map(tlvs, limits)? else {
            return Ok(None);
        };
        check_unpartitioned(&map)?;
        let count = u64::try_from(map.records.len())
            .map_err(|_| SarError::Overflow("CDC_MAP record count"))?;
        let bookkeeping = count
            .checked_mul(CATALOG_RECORD_BOOKKEEPING)
            .ok_or(SarError::Overflow("CDC_MAP catalog bookkeeping"))?;
        limits.check_total_pipeline_memory(bookkeeping)?;
        let mut records = HashMap::new();
        records
            .try_reserve(map.records.len())
            .map_err(|_| SarError::LimitExceeded("CDC_MAP catalog allocation failed"))?;
        for r in &map.records {
            records.insert(r.hash, (r.absolute_offset, r.compressed_size));
        }
        Ok(Some(Self {
            algo_id: map.hash_algorithm_id,
            records,
            bookkeeping,
        }))
    }
}

/// Structural check: `Partition_Index` is zero for every record of an
/// unpartitioned archive (Section 21.1).
pub(crate) fn check_unpartitioned(map: &sar_core::CdcMap) -> Result<(), SarError> {
    if map.records.iter().any(|r| r.partition_id != 0) {
        return Err(SarError::Malformed(
            "CDC_MAP Partition_Index must be zero for an unpartitioned archive",
        ));
    }
    Ok(())
}

/// Where chunk bytes come from for one resolution.
pub(crate) enum ChunkSource<'a, R> {
    /// Local `CDC_MAP`, reading from the archive data area `[header_len, data_end)`.
    Local {
        reader: &'a mut R,
        catalog: &'a LocalCatalog,
        header_len: u64,
        data_end: u64,
    },
    /// Explicitly configured external resolver.
    External(&'a ExternalCdc),
    /// No catalog or resolver is available.
    Unavailable,
}

fn verified(algo_id: u8, expected: &[u8; 32], bytes: &[u8]) -> Result<(), SarError> {
    if &compute_cdc_chunk_hash(algo_id, bytes)? != expected {
        return Err(SarError::HashMismatch(
            "CDC chunk does not match its Recipe hash",
        ));
    }
    Ok(())
}

fn to_u64(n: usize, what: &'static str) -> Result<u64, SarError> {
    u64::try_from(n).map_err(|_| SarError::Overflow(what))
}

/// Resolves `recipe` to the concatenated, hash-verified logical bytes.
///
/// Limits are enforced before allocation: Recipe hash count and metadata
/// bytes, per-chunk size (`max_in_memory_buffer`), total output
/// (`max_decoded_entry_size`) and simultaneously held bytes
/// (`max_total_pipeline_memory`: Recipe, catalog bookkeeping, output and
/// `held_elsewhere`, the bytes the fragment-group collector still retains).
pub(crate) fn resolve_recipe<R: Read + Seek>(
    source: ChunkSource<'_, R>,
    limits: &ResourceLimits,
    recipe: &[u8],
    held_elsewhere: u64,
) -> Result<Vec<u8>, SarError> {
    let algo_id = match &source {
        ChunkSource::Local { catalog, .. } => catalog.algo_id,
        ChunkSource::External(ext) => ext.algo_id,
        ChunkSource::Unavailable => {
            return Err(SarError::RecipeUnresolvable(
                "no CDC catalog or external resolver available for Recipe",
            ));
        }
    };
    // The algorithm is established (and must be supported) before any Recipe
    // element is interpreted.
    compute_cdc_chunk_hash(algo_id, &[])?;
    sar_core::validate_recipe_payload(recipe, limits)?;
    let recipe_len = to_u64(recipe.len(), "recipe length")?;
    let (hashes, _) = recipe.as_chunks::<CDC_RECIPE_HASH_LEN>();

    match source {
        ChunkSource::Local {
            reader,
            catalog,
            header_len,
            data_end,
        } => {
            // Pass 1: locate and bounds-check every range, and sum the output.
            let mut total: u64 = 0;
            let mut ranges = Vec::new();
            ranges
                .try_reserve(hashes.len())
                .map_err(|_| SarError::LimitExceeded("CDC range list allocation failed"))?;
            for h in hashes {
                let &(offset, size) = catalog.records.get(h).ok_or(
                    SarError::RecipeUnresolvable("Recipe hash not present in CDC_MAP"),
                )?;
                let size64 = u64::from(size);
                limits.check_in_memory_buffer(size64)?;
                let end = offset.checked_add(size64).ok_or(SarError::Overflow(
                    "CDC_MAP Member_Offset + Compressed_Size",
                ))?;
                if offset < header_len || end > data_end {
                    return Err(SarError::Bounds(
                        "CDC_MAP chunk range lies outside the archive data area",
                    ));
                }
                total = total
                    .checked_add(size64)
                    .ok_or(SarError::Overflow("CDC reconstructed length"))?;
                limits.check_decoded_entry_size(total)?;
                ranges.push((offset, size64));
            }
            let held = total
                .checked_add(recipe_len)
                .and_then(|n| n.checked_add(held_elsewhere))
                .and_then(|n| n.checked_add(catalog.bookkeeping))
                .and_then(|n| {
                    n.checked_add(
                        to_u64(ranges.capacity(), "range list")
                            .ok()?
                            .checked_mul(16)?,
                    )
                })
                .ok_or(SarError::Overflow("CDC resolution memory"))?;
            limits.check_total_pipeline_memory(held)?;
            let mut out = Vec::new();
            out.try_reserve_exact(
                usize::try_from(total).map_err(|_| SarError::Overflow("CDC output length"))?,
            )
            .map_err(|_| SarError::LimitExceeded("CDC output allocation failed"))?;
            // Pass 2: read and verify each chunk before accepting it.
            for (h, &(offset, size)) in hashes.iter().zip(&ranges) {
                let start = out.len();
                let len =
                    usize::try_from(size).map_err(|_| SarError::Overflow("CDC chunk length"))?;
                out.resize(start + len, 0);
                reader.seek(SeekFrom::Start(offset))?;
                reader.read_exact(&mut out[start..]).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        SarError::Truncated("CDC chunk bytes")
                    } else {
                        SarError::Io(e)
                    }
                })?;
                if let Err(e) = verified(algo_id, h, &out[start..]) {
                    out.truncate(start);
                    return Err(e);
                }
            }
            Ok(out)
        }
        ChunkSource::External(ext) => {
            let mut out: Vec<u8> = Vec::new();
            for h in hashes {
                let room = limits
                    .max_decoded_entry_size
                    .saturating_sub(to_u64(out.len(), "CDC output length")?);
                let max_len = room.min(limits.max_in_memory_buffer);
                let chunk = ext.resolver.resolve_chunk(ext.algo_id, h, max_len).ok_or(
                    SarError::RecipeUnresolvable("external resolver could not supply chunk"),
                )?;
                let chunk_len = to_u64(chunk.len(), "CDC chunk length")?;
                if chunk_len > max_len {
                    return Err(SarError::LimitExceeded(
                        "resolved CDC chunk exceeds the permitted size",
                    ));
                }
                let new_total = to_u64(out.len(), "CDC output length")?
                    .checked_add(chunk_len)
                    .ok_or(SarError::Overflow("CDC reconstructed length"))?;
                limits.check_decoded_entry_size(new_total)?;
                let held = new_total
                    .checked_add(recipe_len)
                    .and_then(|n| n.checked_add(chunk_len))
                    .and_then(|n| n.checked_add(held_elsewhere))
                    .ok_or(SarError::Overflow("CDC resolution memory"))?;
                limits.check_total_pipeline_memory(held)?;
                verified(ext.algo_id, h, &chunk)?;
                out.try_reserve(chunk.len())
                    .map_err(|_| SarError::LimitExceeded("CDC output allocation failed"))?;
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        }
        ChunkSource::Unavailable => Err(SarError::Internal("unreachable CDC source")),
    }
}
