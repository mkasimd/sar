//! Cross-Partition fragment-group validation and bounded logical reassembly
//! (M13b.3 P4; specification §§6.1.3, 19.1.6, 19.1.8, 19.4, 19.5).
//!
//! # Scope and trust boundary
//!
//! [`PartitionSetFragmentReader::open`] takes the actual member sources, runs
//! the P1 physical inspection on each, and the P2 Partition Set validation on
//! the results.  The sources are then owned by the reader, so a fragment
//! payload is never consumed from a file that was not inspected by this
//! reader.  P1/P2 results are metadata-only and do not pin bytes: every walk
//! (structure validation and reassembly) re-runs the full P1 inspection of
//! every member first and fails with `SAR_ERR_PARTITION_MISMATCH` when the
//! fresh result differs from the one recorded at `open`.  Reassembly also
//! re-inspects after the last member was read.  This detects content changes
//! between inspections; it is **not** an atomic snapshot of the filesystem.
//!
//! Fragment grouping reuses the single [`FragmentGroupCollector`], fed with
//! the Entries of all members in canonical order (ascending Partition Index,
//! then physical LFH order).  One collector per reader gives the Fragment ID
//! scope of the complete Partition Set; separate readers share nothing.
//! The end of a member never concludes a group: groups are concluded by a
//! `LAST_FRAGMENT` LFH or, for the incomplete case, only after the exact end
//! of the complete Set.
//!
//! The Partition hashes are unkeyed and prove no authenticity.  Neither
//! [`PartitionSetFragmentReader::validate_fragment_groups`] nor reassembly
//! authenticates the Partition Set.
//!
//! # Supported reassembly profile
//!
//! Plaintext fragments with fragment-local compression decoded per fragment,
//! literal (non-CDC) data, no group-wide patch and no sparse reconstruction.
//! Anything else is `SAR_ERR_UNSUPPORTED` at reassembly (structure validation
//! still applies).  Incomplete Sets and degraded (`LOSS_TOLERANT`) output are
//! rejected.  Memory is bounded by `ResourceLimits` and
//! [`PartitionSetFragmentLimits`]; Entries are handed to a caller sink one at
//! a time and no temporary file is created.

use std::collections::HashMap;
use std::io::{Read, Seek};

use sar_core::SarError;
use sar_core::flags::{EntryMode, GlobalFlags};
use sar_partition::{PartitionSetLimits, PartitionSetMode};

use super::{
    ArchiveReader, ArchiveReaderOptions, EntryMetadata, ValidatedPartition, ValidatedPartitionSet,
};
use crate::fragment_group::{CollectedEntry, FragmentGroup, FragmentGroupCollector};

/// Limits applied by the P4 fragment walk.  Every limit is checked before
/// the corresponding allocation or expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionSetFragmentLimits {
    /// Maximum distinct Fragment IDs in the Set.
    pub max_fragment_groups: u32,
    /// Maximum fragments in the whole Set (also bounds validation work).
    pub max_fragments_total: u64,
    /// Maximum fragments in one group.
    pub max_fragments_per_group: u32,
    /// Maximum aggregate encoded payload bytes of all fragments.
    pub max_total_fragment_bytes: u64,
    /// Maximum Fragment Reassembly Sequence length of one group.
    pub max_group_logical_bytes: u64,
}

impl Default for PartitionSetFragmentLimits {
    fn default() -> Self {
        Self {
            max_fragment_groups: 1 << 16,
            max_fragments_total: 1 << 24,
            max_fragments_per_group: 1 << 20,
            max_total_fragment_bytes: 1 << 38,
            max_group_logical_bytes: 1 << 36,
        }
    }
}

/// Options for [`PartitionSetFragmentReader`].
#[derive(Debug, Clone, Default)]
pub struct PartitionSetFragmentOptions {
    /// Per-member reader options and `ResourceLimits`.
    pub archive: ArchiveReaderOptions,
    /// P2 Set validation limits.
    pub set: PartitionSetLimits,
    /// P4 fragment limits.
    pub fragments: PartitionSetFragmentLimits,
}

/// Structure of one validated fragment group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentGroupStructure {
    /// Fragment ID, scoped to the Partition Set.
    pub fragment_id: u32,
    /// Logical Entry name from Fragment Index 0.
    pub name: String,
    /// Number of fragments (`0..N-1`).
    pub fragments: u32,
    /// Partition Index holding the first (Index 0) fragment.
    pub first_partition: u32,
    /// Partition Index holding the `LAST_FRAGMENT` fragment.
    pub last_partition: u32,
    /// Sum of the declared contribution lengths.
    pub logical_bytes: u64,
}

/// Outcome of a P4 walk.  Distinct from [`ValidatedPartitionSet`]: it says
/// something about fragment-group structure (and, after reassembly, about
/// reconstructed content), never about Partition Set authenticity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionSetFragmentReport {
    /// Partition Set UUID.
    pub partition_set_uuid: [u8; 16],
    /// Partitions walked.
    pub partitions: u32,
    /// Logical Entries (ordinary Entries plus fragment groups).
    pub logical_entries: u64,
    /// Fragment groups, in canonical order of their Fragment Index 0.
    pub groups: Vec<FragmentGroupStructure>,
    /// True only when every logical Entry was fully reconstructed and its
    /// final CRC32 / Content Hash checked (reassembly), false after
    /// structure-only validation.
    pub reconstructed: bool,
}

/// A fully reconstructed logical Entry.
#[derive(Debug, Clone)]
pub struct PartitionLogicalEntry {
    /// Full logical Entry name.
    pub name: String,
    /// Fragment ID when the Entry was fragmented.
    pub fragment_id: Option<u32>,
    /// Number of fragments (1 for an ordinary Entry).
    pub fragment_count: u32,
    /// Metadata of the ordinary Entry or of Fragment Index 0.
    pub metadata: EntryMetadata,
    /// Complete logical bytes.
    pub data: Vec<u8>,
}

/// Owns inspected member sources of one complete Partition Set.
pub struct PartitionSetFragmentReader<R: Read + Seek> {
    readers: Vec<ArchiveReader<R>>,
    inspected: Vec<ValidatedPartition>,
    uuid: [u8; 16],
    per_file_crc: bool,
    options: PartitionSetFragmentOptions,
}

impl<R: Read + Seek> std::fmt::Debug for PartitionSetFragmentReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionSetFragmentReader")
            .field("partitions", &self.readers.len())
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> PartitionSetFragmentReader<R> {
    /// Inspects every source (P1), validates the Set (P2) and takes ownership
    /// of the sources ordered by Partition Index.
    ///
    /// # Errors
    ///
    /// Any P1 or P2 error; [`SarError::PartitionMissing`] for an incomplete
    /// Set (degraded processing is not supported);
    /// [`SarError::PartitionMismatch`] for replicas or mixed Sets;
    /// [`SarError::Unsupported`] for encrypted or KMS-protected members.
    pub fn open(sources: Vec<R>, options: PartitionSetFragmentOptions) -> Result<Self, SarError> {
        let mut readers = Vec::new();
        let mut parts = Vec::new();
        for source in sources {
            let mut reader = ArchiveReader::with_options(source, options.archive.clone())?;
            let part = reader.inspect_partition_in_place(options.set.max_partitions)?;
            if reader
                .global_header
                .as_ref()
                .is_some_and(|h| h.flags.contains(GlobalFlags::ENCRYPTED))
            {
                return Err(SarError::Unsupported(
                    "encrypted Partition reassembly requires per-Partition KMS orchestration",
                ));
            }
            parts.push(part);
            readers.push(reader);
        }
        let set =
            ValidatedPartitionSet::validate(&parts, &options.set, PartitionSetMode::default())?;
        if !set.is_complete() {
            return Err(SarError::PartitionMissing(
                "fragment processing requires a complete Partition Set",
            ));
        }
        if set.members().len() != parts.len()
            || set.members().iter().any(|m| m.replica_count() != 1)
        {
            return Err(SarError::PartitionMismatch(
                "exactly one source per Partition Index is required",
            ));
        }
        let uuid = parts
            .first()
            .ok_or(SarError::PartitionMissing("no Partition supplied"))?
            .manifest()
            .partition_set_uuid;
        let mut slots: Vec<Option<ArchiveReader<R>>> = readers.into_iter().map(Some).collect();
        let mut ordered_readers = Vec::with_capacity(slots.len());
        let mut ordered_parts = Vec::with_capacity(slots.len());
        for member in set.members() {
            let pos = member.input_position();
            let reader = slots
                .get_mut(pos)
                .and_then(Option::take)
                .ok_or(SarError::Internal("Partition input position invalid"))?;
            ordered_readers.push(reader);
            ordered_parts.push(
                parts
                    .get(pos)
                    .cloned()
                    .ok_or(SarError::Internal("Partition input position invalid"))?,
            );
        }
        let per_file_crc = ordered_readers
            .first()
            .and_then(|r| r.global_header.as_ref())
            .is_some_and(|h| h.flags.contains(GlobalFlags::PER_FILE_CRC));
        Ok(Self {
            readers: ordered_readers,
            inspected: ordered_parts,
            uuid,
            per_file_crc,
            options,
        })
    }

    /// Partition Set UUID shared by all members.
    #[must_use]
    pub const fn partition_set_uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// The P1 results the Set was validated from, in Partition Index order.
    #[must_use]
    pub fn partitions(&self) -> &[ValidatedPartition] {
        &self.inspected
    }

    fn reinspect(&mut self) -> Result<(), SarError> {
        let max = self.options.set.max_partitions;
        for (reader, expected) in self.readers.iter_mut().zip(&self.inspected) {
            let now = reader.inspect_partition_in_place(max)?;
            if now != *expected {
                return Err(SarError::PartitionMismatch(
                    "Partition source changed since validation",
                ));
            }
        }
        Ok(())
    }

    /// Walks all Entries in canonical order through one set-scoped collector.
    fn walk(
        &mut self,
        keep_payloads: bool,
        mut visit: impl FnMut(CollectedEntry) -> Result<(), SarError>,
    ) -> Result<HashMap<u32, (u32, u32)>, SarError> {
        self.reinspect()?;
        let limits = self.options.fragments;
        let mut collector = FragmentGroupCollector::new(self.options.archive.limits);
        let mut spans: HashMap<u32, (u32, u32)> = HashMap::new();
        let mut counts: HashMap<u32, u32> = HashMap::new();
        let mut total: u64 = 0;
        let mut encoded: u64 = 0;
        for (reader, part) in self.readers.iter_mut().zip(&self.inspected) {
            let pidx = part.partition_index();
            while let Some(mut entry) = reader.next_entry()? {
                if entry.metadata.is_fragment {
                    total = total
                        .checked_add(1)
                        .ok_or(SarError::Overflow("fragment count"))?;
                    if total > limits.max_fragments_total {
                        return Err(SarError::LimitExceeded("Partition Set fragment count"));
                    }
                    encoded = encoded
                        .checked_add(entry.metadata.payload_size)
                        .ok_or(SarError::Overflow("aggregate fragment bytes"))?;
                    if encoded > limits.max_total_fragment_bytes {
                        return Err(SarError::LimitExceeded("aggregate fragment bytes"));
                    }
                    if u64::try_from(entry.payload.len()).ok()
                        != Some(entry.metadata.uncompressed_size)
                    {
                        return Err(SarError::InvalidLength(
                            "fragment contribution length differs from Uncompressed Size",
                        ));
                    }
                    if let Some(fid) = entry.metadata.fragment_id {
                        if !counts.contains_key(&fid)
                            && counts.len() >= limits.max_fragment_groups as usize
                        {
                            return Err(SarError::LimitExceeded("fragment group count"));
                        }
                        let n = counts.entry(fid).or_insert(0);
                        *n = n
                            .checked_add(1)
                            .ok_or(SarError::Overflow("fragments per group"))?;
                        if *n > limits.max_fragments_per_group {
                            return Err(SarError::LimitExceeded("fragments per group"));
                        }
                        spans.entry(fid).or_insert((pidx, pidx)).1 = pidx;
                    }
                }
                if !keep_payloads {
                    entry.payload = Vec::new();
                }
                collector.push(entry)?;
                while let Some(item) = collector.next_ready()? {
                    visit(item)?;
                }
            }
        }
        // The complete Set boundary is known (P2); only now may open groups
        // be concluded as incomplete.
        collector.finish_input();
        while let Some(item) = collector.next_ready()? {
            visit(item)?;
        }
        Ok(spans)
    }

    fn check_group_shape(
        group: &FragmentGroup,
        limits: &PartitionSetFragmentLimits,
    ) -> Result<u64, SarError> {
        if !group.is_complete() {
            return Err(SarError::FragmentGap(
                "fragment group is incomplete at the Partition Set boundary",
            ));
        }
        let logical = group.contribution_total()?;
        if logical > limits.max_group_logical_bytes {
            return Err(SarError::LimitExceeded("fragment group logical bytes"));
        }
        Ok(logical)
    }

    /// Validates fragment-group structure over the complete Set: membership,
    /// canonical ordering, Class G / Index-0 / completion field consistency
    /// and completion of every group.  No logical content is reconstructed
    /// and no final integrity value is checked.
    ///
    /// # Errors
    ///
    /// The collector's normative errors (`SAR_ERR_METADATA_CONFLICT`,
    /// `SAR_ERR_MALFORMED`, `SAR_ERR_FRAGMENT_GAP`, ...), limit errors, and
    /// [`SarError::PartitionMismatch`] when a source changed.
    pub fn validate_fragment_groups(&mut self) -> Result<PartitionSetFragmentReport, SarError> {
        let limits = self.options.fragments;
        let mut groups = Vec::new();
        let mut logical_entries: u64 = 0;
        let spans = self.walk(false, |item| {
            logical_entries = logical_entries
                .checked_add(1)
                .ok_or(SarError::Overflow("logical entry count"))?;
            if let CollectedEntry::Group(g) = item {
                let logical_bytes = Self::check_group_shape(&g, &limits)?;
                groups.push(FragmentGroupStructure {
                    fragment_id: g.fragment_id,
                    name: g.name.clone(),
                    fragments: u32::try_from(g.fragment_count())
                        .map_err(|_| SarError::Overflow("fragment count"))?,
                    first_partition: 0,
                    last_partition: 0,
                    logical_bytes,
                });
            }
            Ok(())
        })?;
        for g in &mut groups {
            let (first, last) = spans.get(&g.fragment_id).copied().unwrap_or((0, 0));
            g.first_partition = first;
            g.last_partition = last;
        }
        self.reinspect()?;
        self.report(logical_entries, groups, false)
    }

    fn report(
        &self,
        logical_entries: u64,
        groups: Vec<FragmentGroupStructure>,
        reconstructed: bool,
    ) -> Result<PartitionSetFragmentReport, SarError> {
        Ok(PartitionSetFragmentReport {
            partition_set_uuid: self.uuid,
            partitions: u32::try_from(self.readers.len())
                .map_err(|_| SarError::Overflow("partition count"))?,
            logical_entries,
            groups,
            reconstructed,
        })
    }

    fn require_supported(meta: &EntryMetadata) -> Result<(), SarError> {
        if meta.entry_mode_raw & EntryMode::ENCRYPTED != 0 {
            return Err(SarError::Unsupported(
                "encrypted fragment reassembly is not supported",
            ));
        }
        if meta.patch_algo_id.is_some() {
            return Err(SarError::Unsupported(
                "group-wide patch reassembly is not supported",
            ));
        }
        if meta.sparse.is_some() || meta.sparse_extents.is_some() {
            return Err(SarError::Unsupported(
                "sparse reconstruction across Partitions is not supported",
            ));
        }
        crate::archive::require_literal_cdc(meta.cdc_algo_id)
    }

    /// Strict reassembly of every logical Entry of the complete Set.
    ///
    /// Structure validation runs first, so no Entry is delivered when any
    /// group is incomplete or inconsistent.  Entries are then delivered to
    /// `sink` in canonical order (a fragmented Entry at its Fragment Index 0
    /// position) after fragment-local decoding, `Contribution[0] || ... ||
    /// Contribution[N-1]` concatenation, and final CRC32 / Content Hash
    /// verification against the `LAST_FRAGMENT` values.  Sink output must be
    /// treated as provisional until this method returns `Ok`: a source change
    /// detected by the final re-inspection fails the call after delivery.
    ///
    /// # Errors
    ///
    /// As [`Self::validate_fragment_groups`]; [`SarError::Unsupported`] for
    /// encryption, patch, non-literal CDC or sparse Entries;
    /// [`SarError::CrcMismatch`] / [`SarError::HashMismatch`] for final
    /// integrity failures; any sink error.
    pub fn reassemble(
        &mut self,
        mut sink: impl FnMut(PartitionLogicalEntry) -> Result<(), SarError>,
    ) -> Result<PartitionSetFragmentReport, SarError> {
        let mut report = self.validate_fragment_groups()?;
        let archive = self.options.archive.clone();
        let per_file_crc = self.per_file_crc;
        let limits = self.options.fragments;
        self.walk(true, |item| match item {
            CollectedEntry::Entry(entry) => {
                Self::require_supported(&entry.metadata)?;
                if per_file_crc
                    && let Some(crc) = entry.metadata.file_crc32
                    && crc32fast::hash(&entry.payload) != crc
                {
                    return Err(SarError::CrcMismatch(
                        "file CRC32 mismatch on reconstructed logical file",
                    ));
                }
                crate::content_hash::verify_logical(
                    entry.metadata.hash_algo_id,
                    entry.metadata.content_hash,
                    &entry.payload,
                )?;
                sink(PartitionLogicalEntry {
                    name: entry.metadata.name.clone(),
                    fragment_id: None,
                    fragment_count: 1,
                    metadata: entry.metadata,
                    data: entry.payload,
                })
            }
            CollectedEntry::Group(group) => {
                Self::check_group_shape(&group, &limits)?;
                let index0 = group.index0.clone().ok_or(SarError::FragmentGap(
                    "Fragment Index 0 is missing from the group",
                ))?;
                Self::require_supported(&index0)?;
                let fragment_id = group.fragment_id;
                let name = group.name.clone();
                let fragment_count = u32::try_from(group.fragment_count())
                    .map_err(|_| SarError::Overflow("fragment count"))?;
                let (crc, hash, algo) = (
                    group.terminal_crc32,
                    group.terminal_content_hash,
                    group.terminal_hash_algo_id,
                );
                let (data, degraded) = group.reconstruct(&archive)?;
                if degraded {
                    return Err(SarError::FragmentGap(
                        "degraded fragment output is not supported",
                    ));
                }
                if per_file_crc
                    && let Some(expected) = crc
                    && crc32fast::hash(&data) != expected
                {
                    return Err(SarError::CrcMismatch(
                        "file CRC32 mismatch on reconstructed fragment-group logical file",
                    ));
                }
                crate::content_hash::verify_logical(algo, hash, &data)?;
                sink(PartitionLogicalEntry {
                    name,
                    fragment_id: Some(fragment_id),
                    fragment_count,
                    metadata: index0,
                    data,
                })
            }
        })?;
        self.reinspect()?;
        report.reconstructed = true;
        Ok(report)
    }
}
