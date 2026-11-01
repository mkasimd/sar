// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Archival fragment-group collection and cross-fragment consistency checks
//! (specification Section 6.1.3).
//!
//! The collector sits between physical LFH validation and group-wide
//! reconstruction.  It enforces canonical physical Fragment Index order,
//! Class G group invariants, Fragment Index 0 Name/Path authority, neutral
//! completion-authoritative integrity fields, and returns logical Entries in
//! canonical order (a fragment group is positioned at its Fragment Index 0
//! LFH).  Reconstruction itself is delegated to `sar-fragmentation`.
//!
//! Stateful Streaming arrival-order semantics and Partition Set fragment
//! scope are not handled here.

use std::collections::{HashMap, HashSet, VecDeque};

use sar_core::{
    error::SarError, flags::EntryMode, format::LocalFileHeader, limits::ResourceLimits,
    metadata::EntrySparseMetadata,
};
use sar_fragmentation::{FragmentEntry, reconstruct_fragments};

use sar_cdc::CDC_ALGO_LITERAL;
use sar_sparse::{check_gathered_length, validate_sparse_extents};

use crate::archive::{
    ArchiveReaderOptions, EntryMetadata, EntryReader, apply_patch_stage, require_literal_cdc,
};

/// Entry Mode bits that are Class G (group invariant) for fragmented LFHs:
/// `IS_ENCRYPTED`, `IS_COMPRESSED`, `HIDDEN_ATTR`, `IS_FRAGMENT`,
/// `LOSS_TOLERANT`, `OP_CODE`, `ATOMIC_WRITE`, and `FORCE_SYNC`.
const GROUP_INVARIANT_MODE_MASK: u16 = EntryMode::ENCRYPTED
    | EntryMode::COMPRESSED
    | EntryMode::HIDDEN_ATTR
    | EntryMode::FRAGMENT
    | EntryMode::LOSS_TOLERANT
    | 0x0F00
    | EntryMode::ATOMIC_WRITE
    | EntryMode::FORCE_SYNC;

/// Rejects a Sparse Map on a fragment with Fragment Index greater than zero.
///
/// This is a role prohibition checked on the raw Sparse Map bytes, before the
/// Sparse Map content is interpreted (Sections 6.1.3 and 19.6).
pub(crate) fn check_later_fragment_sparse_map(lfh: &LocalFileHeader) -> Result<(), SarError> {
    if lfh.entry_mode.is_fragment()
        && lfh.fragment_index.is_some_and(|index| index != 0)
        && !lfh.sparse_map.is_empty()
    {
        return Err(SarError::MetadataConflict(
            "Sparse Map present on a fragment with Fragment Index greater than zero",
        ));
    }
    Ok(())
}

/// Returns true when two fragment LFHs of one group disagree on a Class G field.
fn group_invariant_mismatch(a: &LocalFileHeader, b: &LocalFileHeader) -> Option<&'static str> {
    if (a.entry_mode.bits() ^ b.entry_mode.bits()) & GROUP_INVARIANT_MODE_MASK != 0 {
        return Some("group-invariant Entry Mode bits differ across fragment group");
    }
    if a.stream_id != b.stream_id {
        return Some("Stream ID differs across fragment group");
    }
    // Class G/N: algorithm IDs are compared only while the corresponding
    // Entry Mode bit makes them semantically active.
    if a.entry_mode.is_compressed() && a.comp_algo_id != b.comp_algo_id {
        return Some("Comp Algo ID differs across fragment group");
    }
    if a.entry_mode.is_encrypted() && a.encr_algo_id != b.encr_algo_id {
        return Some("Encr Algo ID differs across fragment group");
    }
    if a.patch_algo_id != b.patch_algo_id {
        return Some("Patch Algo ID differs across fragment group");
    }
    if a.cdc_algo_id != b.cdc_algo_id {
        return Some("CDC Algo ID differs across fragment group");
    }
    if a.delta_base_hash != b.delta_base_hash {
        return Some("Delta Base Hash differs across fragment group");
    }
    if a.hash_algo_id != b.hash_algo_id {
        return Some("Hash Algo ID differs across fragment group");
    }
    if a.uid_gid != b.uid_gid {
        return Some("UID/GID differs across fragment group");
    }
    if a.timestamps != b.timestamps {
        return Some("Timestamps differ across fragment group");
    }
    if a.permissions != b.permissions {
        return Some("Permissions differ across fragment group");
    }
    None
}

/// One logical item in canonical Entry order.
#[derive(Debug)]
pub enum CollectedEntry {
    /// An ordinary (non-fragmented) Entry.
    Entry(Box<EntryReader>),
    /// A fragment group, positioned at its Fragment Index 0 LFH.
    Group(Box<FragmentGroup>),
}

/// A validated fragment group awaiting reconstruction.
#[derive(Debug)]
pub struct FragmentGroup {
    /// Fragment ID shared by all fragments of the group.
    pub fragment_id: u32,
    /// Authoritative logical Entry name from Fragment Index 0, or empty when
    /// Fragment Index 0 is absent.
    pub name: String,
    /// Metadata of the Fragment Index 0 LFH when present.
    pub index0: Option<EntryMetadata>,
    /// Authoritative File CRC32 from the `LAST_FRAGMENT` LFH, when that LFH is
    /// present and `PER_FILE_CRC` is active.
    pub terminal_crc32: Option<u32>,
    /// Authoritative Content Hash from the `LAST_FRAGMENT` LFH, when that LFH
    /// is present and carries the field.  An all-zero terminal value is still
    /// authoritative.  Verified by the logical-file readers after complete
    /// reassembly.
    pub terminal_content_hash: Option<[u8; 32]>,
    /// LFH Hash Algo ID of the terminal fragment (group-invariant, Class G).
    pub terminal_hash_algo_id: Option<u8>,
    entries: Vec<EntryReader>,
    /// Logical bytes after the group-wide patch and CDC stages, set by
    /// [`Self::resolve_recipe`] for a Recipe-Mode group.
    resolved: Option<Vec<u8>>,
    /// Bytes the collector still held (other groups, metadata, tombstones)
    /// when this group was emitted; charged with the reconstruction peak.
    held_elsewhere: u64,
}

impl FragmentGroup {
    /// True when the group is Recipe Mode and still awaits CDC resolution.
    pub(crate) fn needs_cdc(&self) -> bool {
        self.resolved.is_none()
            && self
                .entries
                .first()
                .and_then(|e| e.metadata.cdc_algo_id)
                .is_some_and(|id| id != CDC_ALGO_LITERAL)
    }

    /// Runs the group-wide stages up to and including CDC resolution
    /// (Section 13.1 steps 4-6) for a Recipe-Mode group: fragment reassembly,
    /// the group-wide patch, then `resolve` on the Recipe bytes.
    ///
    /// The group must be complete; an incomplete one is
    /// [`SarError::FragmentGap`] even under `LOSS_TOLERANT`.  The result is
    /// returned by [`Self::reconstruct`], which does not repeat these stages.
    pub(crate) fn resolve_recipe(
        &mut self,
        options: &ArchiveReaderOptions,
        resolve: impl FnOnce(&[u8]) -> Result<Vec<u8>, SarError>,
    ) -> Result<(), SarError> {
        if !self.is_complete() {
            return Err(SarError::FragmentGap(
                "a group-wide stage requires a complete fragment group",
            ));
        }
        self.check_reconstruction_peak(&options.limits)?;
        let patch = self.patch();
        let fragments = std::mem::take(&mut self.entries)
            .into_iter()
            .map(|e| FragmentEntry {
                fragment_index: e.metadata.fragment_index.unwrap_or(0),
                is_last_fragment: e.metadata.is_last_fragment,
                is_loss_tolerant: e.metadata.is_loss_tolerant,
                uncompressed_size: e.metadata.uncompressed_size,
                payload: e.payload,
            })
            .collect();
        let (mut bytes, degraded) =
            reconstruct_fragments(fragments, &options.limits.fragment_limits())?;
        if degraded {
            return Err(SarError::FragmentGap(
                "a group-wide stage requires a complete fragment group",
            ));
        }
        if let Some((algo_id, base_hash)) = patch {
            bytes = apply_patch_stage(options, algo_id, base_hash, bytes)?;
        }
        self.resolved = Some(resolve(&bytes)?);
        Ok(())
    }

    /// Concatenation grows the first contribution to the full group length
    /// while the other contributions are still held, so the live peak is up to
    /// twice the retained payload bytes; enforce that before allocating.
    fn check_reconstruction_peak(&self, limits: &ResourceLimits) -> Result<(), SarError> {
        let mut total: u64 = 0;
        for e in &self.entries {
            let len = u64::try_from(e.payload.len())
                .map_err(|_| SarError::Overflow("fragment payload length"))?;
            total = total
                .checked_add(len)
                .ok_or(SarError::Overflow("fragment length sum overflow"))?;
        }
        let peak = total
            .checked_mul(2)
            .and_then(|n| n.checked_add(self.held_elsewhere))
            .ok_or(SarError::Overflow("fragment reconstruction memory"))?;
        limits.check_total_pipeline_memory(peak)
    }

    /// Number of fragments held by the group.
    pub(crate) fn fragment_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when Fragment Indices `0..=LAST_FRAGMENT` are all present.
    pub(crate) fn is_complete(&self) -> bool {
        self.resolved.is_some()
            || self
                .entries
                .iter()
                .find(|e| e.metadata.is_last_fragment)
                .is_some_and(|t| {
                    t.metadata
                        .fragment_index
                        .is_some_and(|i| u64::from(i) + 1 == self.entries.len() as u64)
                })
    }

    /// Patch Algo ID and Delta Base Hash of the group (Class G), when the
    /// group carries a patch.
    fn patch(&self) -> Option<(u8, [u8; 32])> {
        let m = &self.entries.first()?.metadata;
        Some((m.patch_algo_id?, m.delta_base_hash.unwrap_or([0u8; 32])))
    }

    /// Validates the Sparse Map retained from Fragment Index 0 against the group
    /// before any contribution is concatenated.
    ///
    /// Returns `Ok(None)` for a non-sparse group.  For a sparse group the
    /// checks run in this order:
    ///
    /// 1. The group must be complete (Fragment Index 0 through `LAST_FRAGMENT`).
    ///    An incomplete sparse group is [`SarError::FragmentGap`] even when
    ///    `LOSS_TOLERANT` is set (specification Section 19.4.5).
    /// 2. The Sparse Logical Size must not exceed `max_decoded_entry_size`.
    /// 3. Without a group-wide patch: a non-literal CDC Algo ID (an unresolved
    ///    Hash Recipe) fails closed with [`SarError::Unsupported`], and the
    ///    checked sum of contribution lengths (the gathered length) must equal
    ///    the checked sum of Sparse Extent lengths ([`SarError::InvalidLength`]).
    ///    With a group-wide patch the gathered data is the patch output, so
    ///    both checks run in [`Self::reconstruct`] after the patch and CDC
    ///    stages.
    ///
    /// # Errors
    ///
    /// As described above, plus [`SarError::InvalidMap`] and
    /// [`SarError::Overflow`] from extent validation.
    pub fn validate_sparse(
        &self,
        limits: &ResourceLimits,
    ) -> Result<Option<&EntrySparseMetadata>, SarError> {
        let Some(sparse) = self.index0.as_ref().and_then(|m| m.sparse.as_ref()) else {
            return Ok(None);
        };
        if !self.is_complete() {
            return Err(SarError::FragmentGap(
                "sparse reconstruction requires a complete fragment group",
            ));
        }
        limits.check_decoded_entry_size(sparse.logical_size)?;
        let extent_total = validate_sparse_extents(
            &sparse.extents,
            sparse.logical_size,
            &limits.sparse_limits(),
        )?;
        if let Some(resolved) = &self.resolved {
            let len =
                u64::try_from(resolved.len()).map_err(|_| SarError::Overflow("gathered length"))?;
            check_gathered_length(len, extent_total)?;
        } else if self.patch().is_none() {
            require_literal_cdc(self.entries.first().and_then(|e| e.metadata.cdc_algo_id))?;
            check_gathered_length(self.contribution_total()?, extent_total)?;
        }
        Ok(Some(sparse))
    }

    pub(crate) fn contribution_total(&self) -> Result<u64, SarError> {
        let mut gathered: u64 = 0;
        for entry in &self.entries {
            gathered = gathered
                .checked_add(entry.metadata.uncompressed_size)
                .ok_or(SarError::Overflow("fragment contribution length sum"))?;
        }
        Ok(gathered)
    }

    /// Reconstructs the group's logical byte sequence.
    ///
    /// Fragment-local stages have already completed for every contribution.
    /// Then, in order: ascending Fragment Index concatenation; the group-wide
    /// patch, applied **once** to the complete Fragment Reassembly Sequence
    /// (see [`crate::apply_patch_stage`] semantics: output length comes from
    /// the patch construction, bounded before allocation); CDC resolution,
    /// which [`crate::archive::ArchiveReader::next_logical_entry`] performs
    /// before releasing a Recipe-Mode group (an unresolved Recipe group fails
    /// closed with [`SarError::Unsupported`] here); and the sparse gathered-length check.  Sparse scattering and
    /// final integrity verification are performed by the caller.
    ///
    /// Returns `(bytes, is_degraded)`.  A group requiring a group-wide stage
    /// (patch, non-literal CDC or sparse reconstruction) must be complete: an
    /// incomplete one is [`SarError::FragmentGap`] even under `LOSS_TOLERANT`,
    /// and no patch is applied to a partial representation.  Any other
    /// incomplete group fails with [`SarError::FragmentGap`] unless every
    /// fragment sets `LOSS_TOLERANT`, in which case only the longest
    /// contiguous prefix from Fragment Index 0 is returned (`is_degraded`).
    ///
    /// # Errors
    ///
    /// Any error from [`sar_fragmentation::reconstruct_fragments`], and
    /// `PATCH_FAILED`, `BASE_MISSING`, `LIMIT_EXCEEDED` or `UNSUPPORTED` from
    /// the group-wide stages.
    pub fn reconstruct(self, options: &ArchiveReaderOptions) -> Result<(Vec<u8>, bool), SarError> {
        let limits = &options.limits;
        if let Some(bytes) = self.resolved {
            if let Some(sparse) = self.index0.as_ref().and_then(|m| m.sparse.as_ref()) {
                let extent_total = validate_sparse_extents(
                    &sparse.extents,
                    sparse.logical_size,
                    &limits.sparse_limits(),
                )?;
                let gathered = u64::try_from(bytes.len())
                    .map_err(|_| SarError::Overflow("gathered length"))?;
                check_gathered_length(gathered, extent_total)?;
            }
            return Ok((bytes, false));
        }
        let patch = self.patch();
        let cdc_algo_id = self.entries.first().and_then(|e| e.metadata.cdc_algo_id);
        let sparse_total = match self.index0.as_ref().and_then(|m| m.sparse.as_ref()) {
            Some(sparse) => Some(validate_sparse_extents(
                &sparse.extents,
                sparse.logical_size,
                &limits.sparse_limits(),
            )?),
            None => None,
        };
        let needs_group_stage = patch.is_some()
            || cdc_algo_id.is_some_and(|id| id != CDC_ALGO_LITERAL)
            || sparse_total.is_some();
        if needs_group_stage && !self.is_complete() {
            return Err(SarError::FragmentGap(
                "a group-wide stage requires a complete fragment group",
            ));
        }
        self.check_reconstruction_peak(limits)?;
        let fragments = self
            .entries
            .into_iter()
            .map(|e| FragmentEntry {
                fragment_index: e.metadata.fragment_index.unwrap_or(0),
                is_last_fragment: e.metadata.is_last_fragment,
                is_loss_tolerant: e.metadata.is_loss_tolerant,
                uncompressed_size: e.metadata.uncompressed_size,
                payload: e.payload,
            })
            .collect();
        let (mut bytes, degraded) = reconstruct_fragments(fragments, &limits.fragment_limits())?;
        if degraded {
            return Ok((bytes, true));
        }
        if let Some((algo_id, base_hash)) = patch {
            bytes = apply_patch_stage(options, algo_id, base_hash, bytes)?;
        }
        require_literal_cdc(cdc_algo_id)?;
        if let Some(extent_total) = sparse_total {
            let gathered =
                u64::try_from(bytes.len()).map_err(|_| SarError::Overflow("gathered length"))?;
            check_gathered_length(gathered, extent_total)?;
        }
        Ok((bytes, false))
    }
}

struct GroupState {
    fragment_id: u32,
    seen: HashSet<u32>,
    max_index: u32,
    name: Option<Vec<u8>>,
    path: Option<Vec<u8>>,
    index0: Option<EntryMetadata>,
    terminal_crc32: Option<u32>,
    terminal_content_hash: Option<[u8; 32]>,
    terminal_hash_algo_id: Option<u8>,
    entries: Vec<EntryReader>,
    /// Decoded payload bytes currently retained in `entries`.
    retained: u64,
    /// Per-Entry metadata bookkeeping bytes retained for this group.
    aux: u64,
    /// True once Fragment Indices `0..=LAST_FRAGMENT` are all present.  The
    /// state is kept (without payloads) after emission so that a later
    /// fragment of the same group is still rejected.
    complete: bool,
    /// A `LAST_FRAGMENT` LFH has been seen; nothing may follow it.
    terminal_seen: bool,
}

enum Slot {
    Entry(Box<EntryReader>),
    Group(u32),
}

/// Checked accounting of decoded payload bytes owned by the collector.
///
/// Bounded by `max_total_pipeline_memory`, whose documented semantics are the
/// cumulative bytes held in memory across pipeline stages.
struct Retention {
    limits: ResourceLimits,
    current: u64,
    /// Bytes of fixed-size per-group state kept for the life of the
    /// collector (see [`GROUP_TOMBSTONE_BYTES`]); never released.
    permanent: u64,
    /// Transient per-Entry metadata bytes, released on emission.
    aux: u64,
    #[cfg(test)]
    peak: u64,
}

impl Retention {
    fn add(&mut self, bytes: u64, enforce: bool) -> Result<(), SarError> {
        let next = self
            .current
            .checked_add(bytes)
            .ok_or(SarError::Overflow("collector retained byte count"))?;
        if enforce {
            self.limits
                .check_total_pipeline_memory(self.held_with(next)?)?;
        }
        self.current = next;
        #[cfg(test)]
        {
            self.peak = self.peak.max(next);
        }
        Ok(())
    }

    /// Total bytes held for a payload count of `payload`, plus bookkeeping.
    fn held_with(&self, payload: u64) -> Result<u64, SarError> {
        payload
            .checked_add(self.permanent)
            .and_then(|n| n.checked_add(self.aux))
            .ok_or(SarError::Overflow("collector retained byte count"))
    }

    fn add_permanent(&mut self, bytes: u64) -> Result<(), SarError> {
        let next = self
            .permanent
            .checked_add(bytes)
            .ok_or(SarError::Overflow("collector bookkeeping byte count"))?;
        let held = self
            .held_with(self.current)?
            .checked_add(bytes)
            .ok_or(SarError::Overflow("collector bookkeeping byte count"))?;
        self.limits.check_total_pipeline_memory(held)?;
        self.permanent = next;
        Ok(())
    }

    fn add_aux(&mut self, bytes: u64) -> Result<(), SarError> {
        let held = self
            .held_with(self.current)?
            .checked_add(bytes)
            .ok_or(SarError::Overflow("collector bookkeeping byte count"))?;
        self.limits.check_total_pipeline_memory(held)?;
        self.aux = self.aux.saturating_add(bytes);
        Ok(())
    }

    fn release_aux(&mut self, bytes: u64) -> Result<(), SarError> {
        self.aux = self
            .aux
            .checked_sub(bytes)
            .ok_or(SarError::Internal("collector bookkeeping underflow"))?;
        Ok(())
    }

    fn release(&mut self, bytes: u64) -> Result<(), SarError> {
        self.current = self
            .current
            .checked_sub(bytes)
            .ok_or(SarError::Internal("collector retained byte underflow"))?;
        Ok(())
    }
}

/// Accounted bytes of per-Entry metadata retained beside the payload: the
/// parsed LFH, its metadata copy and the group's Index-0 copies.
const ENTRY_BOOKKEEPING_BYTES: u64 = 1024;

/// Accounted bytes of the fixed-size state kept for every Fragment ID seen,
/// so a later fragment of an already-emitted group is still rejected.  The
/// number of such states is bounded by `max_entry_count`.
const GROUP_TOMBSTONE_BYTES: u64 = 128;

fn payload_bytes(entry: &EntryReader) -> Result<u64, SarError> {
    u64::try_from(entry.payload.len()).map_err(|_| SarError::Overflow("payload length"))
}

/// Metadata bytes retained beside an Entry's payload (not counted in
/// [`Retention::current`], which is payload only).
fn entry_bookkeeping(entry: &EntryReader) -> Result<u64, SarError> {
    let variable = entry
        .header
        .name
        .len()
        .checked_add(entry.header.path.len())
        .and_then(|n| n.checked_add(entry.header.sparse_map.len()))
        .and_then(|n| n.checked_mul(3))
        .ok_or(SarError::Overflow("entry metadata length"))?;
    u64::try_from(variable)
        .ok()
        .and_then(|v| v.checked_add(ENTRY_BOOKKEEPING_BYTES))
        .ok_or(SarError::Overflow("entry metadata length"))
}

/// Streaming collector yielding logical Entries in canonical order while
/// validating fragment-group consistency.
///
/// Entries are queued in canonical order (a fragment group is positioned at
/// its Fragment Index 0 LFH).  The queue head is released as soon as it is an
/// ordinary Entry or a complete group; only Entries behind an incomplete
/// group stay retained.  Callers must drain [`Self::next_ready`] after every
/// [`Self::push`].
pub(crate) struct FragmentGroupCollector {
    limits: ResourceLimits,
    queue: VecDeque<Slot>,
    groups: HashMap<u32, GroupState>,
    retention: Retention,
    input_finished: bool,
}

impl FragmentGroupCollector {
    /// Creates an empty collector for one Physical Archive Member.
    pub(crate) fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            queue: VecDeque::new(),
            groups: HashMap::new(),
            retention: Retention {
                limits,
                current: 0,
                permanent: 0,
                aux: 0,
                #[cfg(test)]
                peak: 0,
            },
            input_finished: false,
        }
    }

    /// Payload and per-Entry bookkeeping bytes currently retained.
    #[cfg(test)]
    pub(crate) fn retained_bytes(&self) -> u64 {
        self.retention.current
    }

    /// Everything the collector holds (payloads, per-Entry metadata and
    /// per-group state), so later stages can charge it against
    /// `max_total_pipeline_memory` together with their own buffers.
    pub(crate) fn held_bytes(&self) -> Result<u64, SarError> {
        self.retention.held_with(self.retention.current)
    }

    /// Highest retained decoded payload byte count observed.
    #[cfg(test)]
    pub(crate) fn peak_retained_bytes(&self) -> u64 {
        self.retention.peak
    }

    /// Returns true once [`Self::finish_input`] has been called.
    pub(crate) fn is_input_finished(&self) -> bool {
        self.input_finished
    }

    /// Declares that no further Entries will be pushed; remaining incomplete
    /// groups become emittable (their degraded/gap handling is the
    /// consumer's reconstruction step).
    pub(crate) fn finish_input(&mut self) {
        self.input_finished = true;
    }

    /// Adds the next Entry in canonical physical order.
    ///
    /// Empty Areas are ignored.
    ///
    /// # Errors
    ///
    /// * [`SarError::Malformed`] for a missing Fragment ID/Index, a fragmented
    ///   Index 0 with an empty Name, or Fragment Indices out of strictly
    ///   increasing physical order.
    /// * [`SarError::MetadataConflict`] for a duplicate Fragment Index, Class G
    ///   mismatch, later-fragment Name/Path/Sparse Map conflict, a fragment
    ///   following the terminal fragment, or a non-zero integrity field on a
    ///   non-terminal fragment.
    /// * [`SarError::LimitExceeded`] when the fragment count limit or the
    ///   retained decoded-byte budget (`max_total_pipeline_memory`) is
    ///   exceeded.
    pub(crate) fn push(&mut self, entry: EntryReader) -> Result<(), SarError> {
        if self.input_finished {
            return Err(SarError::Internal("Entry pushed after end of input"));
        }
        let bytes = payload_bytes(&entry)?;
        let meta = &entry.metadata;
        if !meta.is_fragment {
            if meta.name.is_empty() {
                return Ok(());
            }
            // With an empty queue the Entry is immediately emittable and is
            // not retained behind anything; otherwise it is blocked by an
            // incomplete earlier group and counts against the budget.
            let blocked = !self.queue.is_empty();
            self.retention.add(bytes, blocked)?;
            self.retention.add_aux(entry_bookkeeping(&entry)?)?;
            self.queue.push_back(Slot::Entry(Box::new(entry)));
            return Ok(());
        }

        let fid = meta.fragment_id.ok_or(SarError::Malformed(
            "IS_FRAGMENT set but Fragment ID is absent",
        ))?;
        let index = meta.fragment_index.ok_or(SarError::Malformed(
            "IS_FRAGMENT set but Fragment Index is absent",
        ))?;
        if index == 0 && entry.header.name.is_empty() {
            return Err(SarError::Malformed(
                "fragment with Fragment Index 0 requires a non-empty Name",
            ));
        }
        if index != 0 && !entry.header.sparse_map.is_empty() {
            return Err(SarError::MetadataConflict(
                "Sparse Map present on a fragment with Fragment Index greater than zero",
            ));
        }
        if !meta.is_last_fragment {
            if entry.header.file_crc32.is_some_and(|crc| crc != 0) {
                return Err(SarError::MetadataConflict(
                    "non-terminal fragment carries a non-zero File CRC32",
                ));
            }
            if entry.header.content_hash.is_some_and(|h| h != [0u8; 32]) {
                return Err(SarError::MetadataConflict(
                    "non-terminal fragment carries a non-zero Content Hash",
                ));
            }
        }

        if !self.groups.contains_key(&fid) {
            self.limits.check_entry_count(
                self.groups
                    .len()
                    .checked_add(1)
                    .ok_or(SarError::Overflow("fragment group count"))?,
            )?;
            self.retention.add_permanent(GROUP_TOMBSTONE_BYTES)?;
            self.queue.push_back(Slot::Group(fid));
            self.groups.insert(
                fid,
                GroupState {
                    fragment_id: fid,
                    seen: HashSet::new(),
                    max_index: 0,
                    name: None,
                    path: None,
                    index0: None,
                    terminal_crc32: None,
                    terminal_content_hash: None,
                    terminal_hash_algo_id: None,
                    entries: Vec::new(),
                    retained: 0,
                    aux: 0,
                    complete: false,
                    terminal_seen: false,
                },
            );
        }
        let group = self
            .groups
            .get_mut(&fid)
            .ok_or(SarError::Internal("fragment group state missing"))?;

        self.limits.check_fragment_count(
            group
                .entries
                .len()
                .checked_add(1)
                .ok_or(SarError::Overflow("fragment count"))?,
        )?;

        if group.seen.contains(&index) {
            return Err(SarError::MetadataConflict(
                "duplicate Fragment Index in fragment group",
            ));
        }
        if !group.seen.is_empty() && index < group.max_index {
            return Err(SarError::Malformed(
                "Fragment Indices are not in strictly increasing physical order",
            ));
        }

        if let Some(first) = group.entries.first()
            && let Some(reason) = group_invariant_mismatch(&first.header, &entry.header)
        {
            return Err(SarError::MetadataConflict(reason));
        }

        if index == 0 {
            group.name = Some(entry.header.name.clone());
            group.path = Some(entry.header.path.clone());
            group.index0 = Some(entry.metadata.clone());
        } else {
            if let Some(name) = &group.name
                && !entry.header.name.is_empty()
                && &entry.header.name != name
            {
                return Err(SarError::MetadataConflict(
                    "later fragment Name differs from Fragment Index 0",
                ));
            }
            if let Some(path) = &group.path
                && !entry.header.path.is_empty()
                && &entry.header.path != path
            {
                return Err(SarError::MetadataConflict(
                    "later fragment Path differs from Fragment Index 0",
                ));
            }
        }
        if group.terminal_seen {
            return Err(SarError::MetadataConflict(
                "fragment follows the LAST_FRAGMENT of its fragment group",
            ));
        }

        // Fragment contributions are always retained until the group is
        // emitted, so they are always checked against the budget.
        self.retention.add(bytes, true)?;
        let aux = entry_bookkeeping(&entry)?;
        self.retention.add_aux(aux)?;
        group.aux = group
            .aux
            .checked_add(aux)
            .ok_or(SarError::Overflow("fragment group bookkeeping"))?;
        group.retained = group
            .retained
            .checked_add(bytes)
            .ok_or(SarError::Overflow("fragment group retained byte count"))?;

        if entry.metadata.is_last_fragment {
            group.terminal_seen = true;
            // The terminal LFH carries the authoritative CRC32 and Content
            // Hash; an all-zero terminal value is still authoritative.
            group.terminal_crc32 = entry.header.file_crc32;
            group.terminal_content_hash = entry.header.content_hash;
            group.terminal_hash_algo_id = entry.header.hash_algo_id;
        }
        group.seen.insert(index);
        group.max_index = group.max_index.max(index);
        let is_last = entry.metadata.is_last_fragment;
        group.entries.push(entry);
        if is_last {
            // Indices are unique and strictly increasing, so `len == last + 1`
            // means exactly `0..=last` is present.
            let expected = u64::from(index)
                .checked_add(1)
                .ok_or(SarError::Overflow("fragment count"))?;
            let present = u64::try_from(group.entries.len())
                .map_err(|_| SarError::Overflow("fragment count"))?;
            group.complete = present == expected;
        }
        Ok(())
    }

    /// Returns the next logical Entry in canonical order when it can be
    /// emitted without violating that order, releasing its retained bytes.
    ///
    /// The queue head is emittable when it is an ordinary Entry, a complete
    /// group, or any group after [`Self::finish_input`].
    ///
    /// # Errors
    ///
    /// [`SarError::Malformed`] for a non-UTF-8 Index-0 Name and
    /// [`SarError::Internal`] for inconsistent collector state.
    pub(crate) fn next_ready(&mut self) -> Result<Option<CollectedEntry>, SarError> {
        let ready = match self.queue.front() {
            None => return Ok(None),
            Some(Slot::Entry(_)) => true,
            Some(Slot::Group(fid)) => {
                self.input_finished || self.groups.get(fid).is_some_and(|g| g.complete)
            }
        };
        if !ready {
            return Ok(None);
        }
        let slot = self
            .queue
            .pop_front()
            .ok_or(SarError::Internal("fragment collector queue empty"))?;
        match slot {
            Slot::Entry(entry) => {
                self.retention.release(payload_bytes(&entry)?)?;
                self.retention.release_aux(entry_bookkeeping(&entry)?)?;
                Ok(Some(CollectedEntry::Entry(entry)))
            }
            Slot::Group(fid) => {
                let state = self
                    .groups
                    .get_mut(&fid)
                    .ok_or(SarError::Internal("fragment group state vanished"))?;
                self.retention
                    .release(std::mem::take(&mut state.retained))?;
                self.retention.release_aux(std::mem::take(&mut state.aux))?;
                let held_elsewhere = self.retention.held_with(self.retention.current)?;
                // Keep only the fixed-size tombstone (`complete`, id).
                state.seen = HashSet::new();
                state.path = None;
                let name = state
                    .name
                    .take()
                    .map(String::from_utf8)
                    .transpose()
                    .map_err(|_| SarError::Malformed("LFH Name String is not valid UTF-8"))?
                    .unwrap_or_default();
                Ok(Some(CollectedEntry::Group(Box::new(FragmentGroup {
                    fragment_id: state.fragment_id,
                    name,
                    index0: state.index0.take(),
                    terminal_crc32: state.terminal_crc32,
                    terminal_content_hash: state.terminal_content_hash,
                    terminal_hash_algo_id: state.terminal_hash_algo_id,
                    entries: std::mem::take(&mut state.entries),
                    resolved: None,
                    held_elsewhere,
                }))))
            }
        }
    }
}

#[cfg(test)]
mod tests;
