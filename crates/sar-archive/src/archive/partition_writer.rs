// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Multi-Partition Set writer (M13b.3 P3).
//!
//! [`PartitionSetWriter`] produces the physical members of one Partition Set,
//! each into its own caller-supplied sink starting at byte zero.  Every member
//! is built by [`ArchiveWriter::with_partition_manifest`], so the Manifest
//! codec, LFH encoder, CRC32, Central Dictionary and Footer are the P1 code
//! paths; this module only sequences members, chains hashes and enforces
//! resource limits.
//!
//! # Contract
//!
//! * Each application Entry lives wholly inside one Partition; Entries are
//!   never split across members (a fragmented logical Entry is a group of
//!   *separate* fragment Entries, each wholly inside one member; see the
//!   fragment-group section below).  An Entry that does not fit is refused
//!   *before* any of its bytes are published ([`SarError::LimitExceeded`]) and
//!   the member stays usable; the caller may finish it and begin the next one.
//! * Admission is exact for size: the encoded Entry (LFH plus payload) plus the
//!   exact length of the mandatory closing structures (Manifest LFH and
//!   payload, Central Dictionary sized by the indexed LFH count - Empty Areas
//!   are not indexed - alignment padding, Footer) is compared with the
//!   Partition capacity before any byte is published.  Capacity is an upper
//!   bound; nothing is padded.
//! * Staging memory: `max_entry_bytes` is enforced on the input payload (and
//!   delta base) before any transformation, on the wire payload before it is
//!   copied and encoded, on the encoded payload plus FEC value before the FEC
//!   value is allocated, and on the final LFH plus payload before
//!   publication.  It is *not* a hard cap on transient allocations: the
//!   compressor's output buffer (bounded by the codec's worst-case expansion
//!   of an input that already passed the limit) and delta patch generation
//!   (bounded by the patch generator's own default limits) allocate before the
//!   encoded size is known.  Peak transient memory per Entry is therefore a
//!   small constant multiple of `max_entry_bytes`, never the whole Partition.
//! * Completion is explicit.  Any sink failure, abandoned member or refused
//!   finalization moves the writer to a failed state; a dropped writer never
//!   claims a complete Set.  Previously published members are not rolled back
//!   and, without the final member, do not form a complete Set.
//! * The writer never re-reads a sink.  Its summaries are writer claims; use
//!   [`ArchiveReader::inspect_partition`] and [`ValidatedPartitionSet`] for
//!   independent validation.
//! * Plaintext only: `ENCRYPTED` configurations are rejected with
//!   [`SarError::Unsupported`] (per-Partition KMS is outside P3).
//!
//! # Fragment groups (M13b.3 P4)
//!
//! With [`PartitionSetWriter::with_fragmentation`] every member carries
//! `FILE_FRAGMENTATION`.  A fragmented logical Entry is declared once with
//! [`PartitionSetWriter::begin_fragment_group`] (the Fragment ID scope is the
//! whole Set) and then written fragment by fragment with
//! [`PartitionWriter::add_fragment`] into caller-selected members.  Fragment
//! Indices are assigned `0, 1, 2, ...` in call order, which is the canonical
//! physical order; the terminal call sets `LAST_FRAGMENT`.  Class G fields come
//! from the [`FragmentGroupSpec`] and are identical in every fragment; Name,
//! Path and (when `PER_FILE_CRC` / `DEDUPLICATION` are active) the final File
//! CRC32 and Content Hash are carried only by the authoritative fragments
//! (Index 0 and `LAST_FRAGMENT`); nonterminal integrity fields are zero.  The
//! final CRC32 and Content Hash are computed incrementally over the logical
//! (pre-compression) contributions unless the spec supplies them.  Each
//! contribution is compressed independently with the configured
//! [`CompressionSettings`].
//!
//! * Every fragment is a whole LFH plus payload inside one member and goes
//!   through the same admission checks as any Entry, so an oversized fragment
//!   is refused before publication and the member stays usable.
//! * A member may be finalized while groups stay open.  The final member and
//!   [`PartitionSetWriter::finish_set`] refuse (with
//!   [`SarError::FragmentGap`]) while any group has not received its
//!   terminal fragment; nothing is padded or invented.
//! * Fragment group state is bounded by the `max_fragment*` limits.

use super::*;

use std::collections::HashMap;

use partition::PartitionAdmission;
use sar_core::flags::EntryMode;
use sar_core::format::LocalFileHeader;
use sar_core::partition_manifest::validate_manifest_hash_algorithm_id;
use sar_core::{PARTITION_MAX_SUPPORTED_COUNT, PARTITION_TOTAL_UNKNOWN};
use sar_crypto::hash::Hasher;

/// Resource limits of a [`PartitionSetWriter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionSetWriterLimits {
    /// Maximum number of Partitions (at most 65535).
    pub max_partitions: u32,
    /// Maximum size of one physical Partition in bytes.
    pub max_partition_bytes: u64,
    /// Maximum sum of all Partition sizes in bytes.
    pub max_aggregate_bytes: u64,
    /// Maximum physical Entries per Partition.  The indexed offset array is
    /// bounded by this count times the offset width.
    pub max_entries_per_partition: u64,
    /// Maximum size of one Entry staged in memory, checked at each stage of
    /// encoding (see the module documentation for the exact guarantee).
    pub max_entry_bytes: u64,
}

impl Default for PartitionSetWriterLimits {
    fn default() -> Self {
        Self {
            max_partitions: PARTITION_MAX_SUPPORTED_COUNT,
            max_partition_bytes: 1 << 30,
            max_aggregate_bytes: 1 << 36,
            max_entries_per_partition: 1 << 20,
            max_entry_bytes: 1 << 28,
        }
    }
}

/// Fragment-writing limits, supplied through
/// [`PartitionSetWriter::with_fragmentation`] (kept apart from
/// [`PartitionSetWriterLimits`] so that struct keeps its P3 layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentWriterLimits {
    /// Maximum number of fragment groups declared in one Set (open or closed;
    /// a Fragment ID is never reused within a Set).
    pub max_fragment_groups: u32,
    /// Maximum number of fragment groups waiting for their terminal fragment.
    pub max_open_fragment_groups: u32,
    /// Maximum number of fragments in one group.
    pub max_fragments_per_group: u32,
    /// Maximum number of fragments written in one Set.
    pub max_fragments_total: u64,
    /// Maximum logical (reassembled) bytes of one group.
    pub max_group_logical_bytes: u64,
    /// Maximum logical bytes of all fragment groups of one Set.
    pub max_total_fragment_bytes: u64,
}

impl Default for FragmentWriterLimits {
    fn default() -> Self {
        Self {
            max_fragment_groups: 1 << 16,
            max_open_fragment_groups: 1 << 10,
            max_fragments_per_group: 1 << 20,
            max_fragments_total: 1 << 24,
            max_group_logical_bytes: 1 << 36,
            max_total_fragment_bytes: 1 << 38,
        }
    }
}

/// Set-wide configuration shared by every member.
#[derive(Debug, Clone)]
pub struct PartitionSetWriterOptions {
    /// Partition Set UUID; `None` generates a random nonzero UUID.
    pub partition_set_uuid: Option<[u8; 16]>,
    /// Declared Total Partitions, or `None` when unknown until the final member.
    pub known_total: Option<u32>,
    /// Manifest hash algorithm (`0x30` SHA256 or `0x31` BLAKE3-256).
    pub hash_algorithm_id: u8,
    /// Enables `HAS_DATA_AREA_CRC32` on every member (indexed members only).
    pub data_area_crc32: bool,
    /// Per-member writer options.  `encryption` and `archive_recovery` must be
    /// `None`; `no_index` applies to every member
    /// (the default of this type is indexed).
    pub archive: ArchiveWriterOptions,
    /// Compression applied to Entries.
    pub compression: CompressionSettings,
    /// Resource limits.
    pub limits: PartitionSetWriterLimits,
}

impl Default for PartitionSetWriterOptions {
    fn default() -> Self {
        Self {
            partition_set_uuid: None,
            known_total: None,
            hash_algorithm_id: 0x30,
            data_area_crc32: false,
            archive: ArchiveWriterOptions {
                no_index: false,
                ..ArchiveWriterOptions::default()
            },
            compression: CompressionSettings::store(),
            limits: PartitionSetWriterLimits::default(),
        }
    }
}

/// Writer-side facts about one finished member (not a validation result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMemberSummary {
    /// Partition Index written to the Manifest.
    pub partition_index: u32,
    /// Whether `FINAL_PARTITION` was set.
    pub is_final: bool,
    /// Total Partitions written to the Manifest (`0xFFFFFFFF` if unknown).
    pub total_partitions: u32,
    /// Application Entries (including Empty Areas), excluding the Manifest.
    pub entry_count: u64,
    /// Whether the member carries a local Central Dictionary and Footer.
    pub indexed: bool,
    /// Total member size in bytes.
    pub partition_len: u64,
    /// Committed Content Length (offset of the Manifest LFH).
    pub committed_content_length: u64,
    /// Previous Partition Hash written to the Manifest.
    pub previous_partition_hash: [u8; 32],
    /// Current Partition Hash written to the Manifest.
    pub current_partition_hash: [u8; 32],
}

/// Writer-side facts about a completed Set (not a validation result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionSetSummary {
    /// Partition Set UUID shared by all members.
    pub partition_set_uuid: [u8; 16],
    /// Exact number of members written.
    pub total_partitions: u32,
    /// Sum of all member sizes in bytes.
    pub aggregate_bytes: u64,
}

/// Writer-side result of a fragmenting Set: the ordinary summary plus fragment
/// statistics.  Like [`PartitionSetSummary`] it is not a validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentedPartitionSetSummary {
    /// The ordinary Set summary.
    pub summary: PartitionSetSummary,
    /// Number of completed fragment groups (logical fragmented Entries).
    pub fragment_groups: u32,
    /// Number of fragment LFHs written across all members.
    pub fragments: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetState {
    Idle,
    MemberOpen,
    Complete,
    Failed,
}

/// Declaration of one fragmented logical Entry (spec Sections 6.1.3, 19.1.6).
///
/// Everything here is group-invariant (Class G) or Index-0-authoritative:
/// the writer repeats the Class G values in every fragment LFH and emits Name
/// and Path only in Fragment Index 0.
#[derive(Debug, Clone, Default)]
pub struct FragmentGroupSpec {
    /// Fragment ID, unique within the Partition Set.
    pub fragment_id: u32,
    /// Logical Entry Name (required, written by Fragment Index 0 only).
    pub name: String,
    /// Directory path (Index 0 only); requires `with_path`.
    pub path: Option<String>,
    /// Permissions; present exactly when `with_permissions` is enabled.
    pub permissions: Option<u16>,
    /// Packed UID/GID; present exactly when `with_uid_gid` is enabled.
    pub uid_gid: Option<u32>,
    /// Timestamps; present exactly when `with_timestamps` is enabled.
    pub timestamps: Option<[u64; 3]>,
    /// Sets `HIDDEN_ATTR` on every fragment.
    pub is_hidden: bool,
    /// Sets `LOSS_TOLERANT` on every fragment.
    pub loss_tolerant: bool,
    /// Stream ID of every fragment.
    pub stream_id: Option<u16>,
    /// Hash Algo ID of the Content Hash (default BLAKE3-256); used only with
    /// `with_content_hash`.
    pub hash_algo_id: Option<u8>,
    /// Explicit final File CRC32 (written verbatim by `LAST_FRAGMENT`);
    /// computed over the logical contributions when `None`.
    pub file_crc32: Option<u32>,
    /// Explicit final Content Hash (written verbatim by `LAST_FRAGMENT`);
    /// computed over the logical contributions when `None`.
    pub content_hash: Option<[u8; 32]>,
}

/// Fragment-specific LFH fields applied on top of an ordinary Entry LFH.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FragmentLfhParams {
    pub(crate) id: u32,
    pub(crate) index: u32,
    pub(crate) last: bool,
    pub(crate) loss_tolerant: bool,
}

impl FragmentLfhParams {
    pub(crate) fn apply(self, lfh: &mut LocalFileHeader) -> Result<(), SarError> {
        let mut bits = lfh.entry_mode.bits() | EntryMode::FRAGMENT;
        if self.last {
            bits |= EntryMode::LAST_FRAGMENT;
        }
        if self.loss_tolerant {
            bits |= EntryMode::LOSS_TOLERANT;
        }
        lfh.entry_mode = EntryMode::from_bits(bits);
        lfh.fragment_id = Some(self.id);
        lfh.fragment_index = Some(self.index);
        Ok(())
    }
}

/// Validated, not yet committed description of the next fragment.
struct FragmentPlan {
    index: u32,
    terminal: bool,
    loss_tolerant: bool,
    contribution_len: u64,
    contribution_crc32: u32,
    crc32: u32,
    content_hash: Option<[u8; 32]>,
}

/// Final integrity values already derived for a terminal fragment whose
/// publication was refused; a retry must present the same contribution.
struct PendingTerminal {
    contribution_len: u64,
    contribution_crc32: u32,
    crc32: u32,
    content_hash: Option<[u8; 32]>,
}

enum GroupState {
    Open(Box<OpenGroup>),
    /// Terminal fragment published; the ID stays reserved.
    Closed,
}

struct OpenGroup {
    spec: FragmentGroupSpec,
    next_index: u32,
    logical_bytes: u64,
    crc: crc32fast::Hasher,
    hasher: Option<Box<dyn Hasher>>,
    pending_terminal: Option<PendingTerminal>,
}

/// Sequential writer for the members of one Partition Set.
pub struct PartitionSetWriter {
    options: PartitionSetWriterOptions,
    fragment_limits: Option<FragmentWriterLimits>,
    uuid: [u8; 16],
    state: SetState,
    next_index: u32,
    previous_hash: [u8; 32],
    aggregate_bytes: u64,
    groups: HashMap<u32, GroupState>,
    open_groups: u32,
    closed_groups: u32,
    fragments: u64,
    fragment_bytes: u64,
}

impl PartitionSetWriter {
    /// Initializes a Set.
    ///
    /// # Errors
    ///
    /// [`SarError::Malformed`] for a zero UUID or zero total,
    /// [`SarError::Unsupported`] for encryption, archive recovery or an
    /// unsupported hash algorithm, [`SarError::FlagConflict`] for
    /// `no_index` with `data_area_crc32`, and [`SarError::LimitExceeded`] for
    /// limits or a declared total above the supported maximum.
    pub fn new(options: PartitionSetWriterOptions) -> Result<Self, SarError> {
        if options.archive.encryption.is_some() {
            return Err(SarError::Unsupported(
                "encrypted Partition Set writing is not supported",
            ));
        }
        if options.archive.archive_recovery.is_some() {
            return Err(SarError::Unsupported(
                "archive recovery is not supported for Partition Set writing",
            ));
        }
        if options.data_area_crc32 && options.archive.no_index {
            return Err(SarError::FlagConflict(
                "HAS_DATA_AREA_CRC32 requires an indexed Partition (NO_INDEX is set)",
            ));
        }
        validate_manifest_hash_algorithm_id(options.hash_algorithm_id)?;
        let limits = options.limits;
        if limits.max_partitions == 0 || limits.max_partitions > PARTITION_MAX_SUPPORTED_COUNT {
            return Err(SarError::LimitExceeded(
                "max_partitions is outside the supported range",
            ));
        }
        if let Some(total) = options.known_total {
            if total == 0 || total == PARTITION_TOTAL_UNKNOWN {
                return Err(SarError::Malformed(
                    "declared Total Partitions must be between 1 and 0xFFFFFFFE",
                ));
            }
            if total > limits.max_partitions {
                return Err(SarError::LimitExceeded(
                    "declared Total Partitions exceeds the configured limit",
                ));
            }
        }
        let uuid = match options.partition_set_uuid {
            Some(uuid) => uuid,
            None => {
                let mut uuid = [0u8; 16];
                getrandom::fill(&mut uuid)
                    .map_err(|_| SarError::Internal("random Partition Set UUID unavailable"))?;
                uuid
            }
        };
        if uuid == [0u8; 16] {
            return Err(SarError::Malformed("Partition Set UUID must be nonzero"));
        }
        Ok(Self {
            options,
            fragment_limits: None,
            uuid,
            state: SetState::Idle,
            next_index: 0,
            previous_hash: [0u8; 32],
            aggregate_bytes: 0,
            groups: HashMap::new(),
            open_groups: 0,
            closed_groups: 0,
            fragments: 0,
            fragment_bytes: 0,
        })
    }

    /// Enables fragment writing with explicit limits.  Must be called before
    /// the first member is opened so that `FILE_FRAGMENTATION` is set
    /// consistently on every Partition Global Header.
    ///
    /// # Errors
    ///
    /// [`SarError::Malformed`] once a member was started, and
    /// [`SarError::LimitExceeded`] for a zero group or fragment limit.
    pub fn with_fragmentation(mut self, limits: FragmentWriterLimits) -> Result<Self, SarError> {
        if self.state != SetState::Idle || self.next_index != 0 {
            return Err(SarError::Malformed(
                "fragmentation must be enabled before the first member",
            ));
        }
        if limits.max_fragments_per_group == 0 || limits.max_open_fragment_groups == 0 {
            return Err(SarError::LimitExceeded(
                "fragment limits must allow at least one group and fragment",
            ));
        }
        self.fragment_limits = Some(limits);
        Ok(self)
    }

    /// Declares one fragment group.  Call between members (or through
    /// [`PartitionWriter::begin_fragment_group`] on an open member).  The
    /// Fragment ID must be new in this Set; the group stays open until its
    /// terminal fragment is written.
    ///
    /// # Errors
    ///
    /// [`SarError::FlagConflict`] without
    /// [`PartitionSetWriter::with_fragmentation`] or when a spec field does
    /// not match the enabled metadata flags, [`SarError::Malformed`] for an
    /// empty or oversized Name or Path, [`SarError::MetadataConflict`] for a
    /// reused Fragment ID, [`SarError::LimitExceeded`] for the group limits,
    /// and [`SarError::Malformed`] when the writer is complete or failed.
    /// Every refusal leaves the writer usable.
    pub fn begin_fragment_group(&mut self, spec: FragmentGroupSpec) -> Result<(), SarError> {
        match self.state {
            SetState::Idle | SetState::MemberOpen => {}
            SetState::Complete => {
                return Err(SarError::Malformed("Partition Set is already complete"));
            }
            SetState::Failed => {
                return Err(SarError::Malformed("Partition Set writer has failed"));
            }
        }
        let archive = &self.options.archive;
        let Some(limits) = self.fragment_limits else {
            return Err(SarError::FlagConflict(
                "fragment groups require PartitionSetWriter::with_fragmentation",
            ));
        };
        if spec.name.is_empty() {
            return Err(SarError::Malformed(
                "a fragment group requires a non-empty Name",
            ));
        }
        if spec.name.len() > usize::from(u16::MAX)
            || spec
                .path
                .as_ref()
                .is_some_and(|p| p.len() > usize::from(u16::MAX))
        {
            return Err(SarError::Malformed("fragment Name or Path is too long"));
        }
        if spec.path.is_some() && !archive.with_path {
            return Err(SarError::FlagConflict("path requires with_path"));
        }
        if spec.permissions.is_some() != archive.with_permissions
            || spec.uid_gid.is_some() != archive.with_uid_gid
            || spec.timestamps.is_some() != archive.with_timestamps
        {
            return Err(SarError::FlagConflict(
                "fragment group metadata must match the enabled metadata flags",
            ));
        }
        if spec.file_crc32.is_some() && !archive.with_per_file_crc {
            return Err(SarError::FlagConflict(
                "file_crc32 requires with_per_file_crc",
            ));
        }
        if spec.content_hash.is_some() && !archive.with_content_hash {
            return Err(SarError::FlagConflict(
                "content_hash requires with_content_hash",
            ));
        }
        if archive.with_delta || archive.sparse {
            return Err(SarError::Unsupported(
                "fragment groups with delta or sparse writers are outside the P4 profile",
            ));
        }
        let hasher = if archive.with_content_hash {
            let algo = spec
                .hash_algo_id
                .unwrap_or(sar_crypto::algorithm::HASH_BLAKE3);
            sar_core::validate_lfh_hash_algo_id(algo)?;
            Some(sar_crypto::hash::new_hasher(algo).map_err(SarError::from)?)
        } else {
            None
        };
        if self.groups.contains_key(&spec.fragment_id) {
            return Err(SarError::MetadataConflict(
                "Fragment ID already used in this Partition Set",
            ));
        }
        let declared = u32::try_from(self.groups.len())
            .map_err(|_| SarError::Overflow("fragment group count"))?;
        if declared >= limits.max_fragment_groups {
            return Err(SarError::LimitExceeded(
                "fragment group count exceeds the configured limit",
            ));
        }
        if self.open_groups >= limits.max_open_fragment_groups {
            return Err(SarError::LimitExceeded(
                "open fragment group count exceeds the configured limit",
            ));
        }
        self.open_groups = self
            .open_groups
            .checked_add(1)
            .ok_or(SarError::Overflow("open fragment group count"))?;
        self.groups.insert(
            spec.fragment_id,
            GroupState::Open(Box::new(OpenGroup {
                spec,
                next_index: 0,
                logical_bytes: 0,
                crc: crc32fast::Hasher::new(),
                hasher,
                pending_terminal: None,
            })),
        );
        Ok(())
    }

    /// Validates one fragment against the group and limits without changing
    /// any state, and derives the final integrity values for a terminal one.
    fn plan_fragment(
        &self,
        fragment_id: u32,
        contribution: &[u8],
        is_last: bool,
    ) -> Result<FragmentPlan, SarError> {
        let group = match self.groups.get(&fragment_id) {
            Some(GroupState::Open(group)) => group,
            Some(GroupState::Closed) => {
                return Err(SarError::MetadataConflict(
                    "fragment follows the LAST_FRAGMENT of its group",
                ));
            }
            None => return Err(SarError::Malformed("unknown fragment group")),
        };
        let limits = self
            .fragment_limits
            .ok_or(SarError::Malformed("fragmentation is not enabled"))?;
        let count = group
            .next_index
            .checked_add(1)
            .ok_or(SarError::Overflow("fragment count"))?;
        if count > limits.max_fragments_per_group {
            return Err(SarError::LimitExceeded(
                "fragments per group exceed the configured limit",
            ));
        }
        if self.fragments >= limits.max_fragments_total {
            return Err(SarError::LimitExceeded(
                "total fragment count exceeds the configured limit",
            ));
        }
        let len = u64::try_from(contribution.len())
            .map_err(|_| SarError::Overflow("contribution length"))?;
        let logical = group
            .logical_bytes
            .checked_add(len)
            .ok_or(SarError::Overflow("group logical length"))?;
        if logical > limits.max_group_logical_bytes {
            return Err(SarError::LimitExceeded(
                "group logical size exceeds the configured limit",
            ));
        }
        let total = self
            .fragment_bytes
            .checked_add(len)
            .ok_or(SarError::Overflow("total fragment bytes"))?;
        if total > limits.max_total_fragment_bytes {
            return Err(SarError::LimitExceeded(
                "total fragment bytes exceed the configured limit",
            ));
        }
        let contribution_crc32 = crc32fast::hash(contribution);
        let (crc32, content_hash) = if is_last {
            match &group.pending_terminal {
                Some(p)
                    if p.contribution_len == len && p.contribution_crc32 == contribution_crc32 =>
                {
                    (p.crc32, p.content_hash)
                }
                Some(_) => {
                    return Err(SarError::MetadataConflict(
                        "a retried terminal fragment must repeat its contribution",
                    ));
                }
                None => {
                    let mut crc = group.crc.clone();
                    crc.update(contribution);
                    (crc.finalize(), None)
                }
            }
        } else {
            (0, None)
        };
        Ok(FragmentPlan {
            index: group.next_index,
            terminal: is_last,
            loss_tolerant: group.spec.loss_tolerant,
            contribution_len: len,
            contribution_crc32,
            crc32,
            content_hash,
        })
    }

    fn fragment_input(
        &mut self,
        fragment_id: u32,
        contribution: Vec<u8>,
        plan: &mut FragmentPlan,
    ) -> Result<EntryInput, SarError> {
        let archive = &self.options.archive;
        let (with_crc, with_hash) = (archive.with_per_file_crc, archive.with_content_hash);
        let is_last_plan = plan.terminal;
        let Some(GroupState::Open(group)) = self.groups.get_mut(&fragment_id) else {
            return Err(SarError::Internal("fragment group state missing"));
        };
        let spec = &group.spec;
        let first = plan.index == 0;
        let mut content_hash = None;
        if with_hash {
            content_hash = Some(if is_last_plan {
                match (spec.content_hash, plan.content_hash) {
                    (Some(explicit), _) => explicit,
                    (None, Some(pending)) => pending,
                    (None, None) => {
                        let mut hasher = group
                            .hasher
                            .take()
                            .ok_or(SarError::Internal("fragment hasher missing"))?;
                        hasher.update(&contribution);
                        let digest = hasher.finalize();
                        let digest = <[u8; 32]>::try_from(digest.as_slice())
                            .map_err(|_| SarError::Internal("content hash is not 32 bytes"))?;
                        plan.content_hash = Some(digest);
                        digest
                    }
                }
            } else {
                [0u8; 32]
            });
        }
        let file_crc32 = with_crc.then(|| {
            if is_last_plan {
                spec.file_crc32.unwrap_or(plan.crc32)
            } else {
                0
            }
        });
        Ok(EntryInput {
            name: if first {
                spec.name.clone()
            } else {
                String::new()
            },
            payload: contribution,
            kind: Some(sar_core::metadata::EntryKind::RegularFile),
            path: if first { spec.path.clone() } else { None },
            permissions: spec.permissions,
            uid_gid: spec.uid_gid,
            timestamps: spec.timestamps,
            is_hidden: spec.is_hidden,
            stream_id: spec.stream_id,
            file_crc32,
            hash_algo_id: with_hash.then(|| {
                spec.hash_algo_id
                    .unwrap_or(sar_crypto::algorithm::HASH_BLAKE3)
            }),
            content_hash,
            ..EntryInput::default()
        })
    }

    fn commit_fragment(
        &mut self,
        fragment_id: u32,
        plan: FragmentPlan,
        is_last: bool,
        retained: Option<Vec<u8>>,
    ) -> Result<(), SarError> {
        self.fragments = self
            .fragments
            .checked_add(1)
            .ok_or(SarError::Overflow("fragment count"))?;
        self.fragment_bytes = self
            .fragment_bytes
            .checked_add(plan.contribution_len)
            .ok_or(SarError::Overflow("total fragment bytes"))?;
        let Some(GroupState::Open(group)) = self.groups.get_mut(&fragment_id) else {
            return Err(SarError::Internal("fragment group state missing"));
        };
        if let Some(bytes) = retained {
            group.crc.update(&bytes);
            if let Some(hasher) = group.hasher.as_mut() {
                hasher.update(&bytes);
            }
        }
        group.next_index = plan.index + 1;
        group.logical_bytes = group
            .logical_bytes
            .checked_add(plan.contribution_len)
            .ok_or(SarError::Overflow("group logical length"))?;
        if is_last {
            self.groups.insert(fragment_id, GroupState::Closed);
            self.open_groups = self.open_groups.saturating_sub(1);
            self.closed_groups = self
                .closed_groups
                .checked_add(1)
                .ok_or(SarError::Overflow("fragment group count"))?;
        }
        Ok(())
    }

    /// Records what a refused terminal publication already consumed so a
    /// retry with the same contribution still carries correct values.
    fn remember_terminal(&mut self, fragment_id: u32, plan: &FragmentPlan) {
        if !plan.terminal {
            return;
        }
        if let Some(GroupState::Open(group)) = self.groups.get_mut(&fragment_id) {
            group.pending_terminal = Some(PendingTerminal {
                contribution_len: plan.contribution_len,
                contribution_crc32: plan.contribution_crc32,
                crc32: plan.crc32,
                content_hash: plan.content_hash,
            });
        }
    }

    /// The Partition Set UUID used by every member.
    #[must_use]
    pub const fn partition_set_uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Index the next member will receive.
    #[must_use]
    pub const fn next_partition_index(&self) -> u32 {
        self.next_index
    }

    /// Starts the next physical Partition in `sink`, which receives the
    /// member from byte zero.  `capacity` is an optional upper bound for this
    /// member, further capped by the configured limits and the remaining
    /// aggregate budget.  The Global Header is written immediately.
    ///
    /// # Errors
    ///
    /// [`SarError::Malformed`] if the Set is complete, failed or has an open
    /// member, [`SarError::PartitionMismatch`] beyond a declared total,
    /// [`SarError::LimitExceeded`] for the Partition count, aggregate size or a
    /// capacity too small for the mandatory structures.  Refusals before any
    /// output leave the writer usable.
    pub fn begin_partition<W: Write>(
        &mut self,
        sink: W,
        capacity: Option<u64>,
    ) -> Result<PartitionWriter<'_, W>, SarError> {
        match self.state {
            SetState::Idle => {}
            SetState::MemberOpen => {
                return Err(SarError::Malformed("a Partition is already open"));
            }
            SetState::Complete => {
                return Err(SarError::Malformed("Partition Set is already complete"));
            }
            SetState::Failed => {
                return Err(SarError::Malformed("Partition Set writer has failed"));
            }
        }
        let index = self.next_index;
        if let Some(total) = self.options.known_total
            && index >= total
        {
            return Err(SarError::PartitionMismatch(
                "Partition count would exceed the declared Total Partitions",
            ));
        }
        let limits = self.options.limits;
        if index >= limits.max_partitions {
            return Err(SarError::LimitExceeded(
                "Partition count exceeds the configured limit",
            ));
        }
        let remaining = limits
            .max_aggregate_bytes
            .checked_sub(self.aggregate_bytes)
            .filter(|r| *r > 0)
            .ok_or(SarError::LimitExceeded(
                "aggregate encoded size limit exhausted",
            ))?;
        let max_partition_bytes = capacity
            .unwrap_or(u64::MAX)
            .min(limits.max_partition_bytes)
            .min(remaining);

        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            sink,
            self.options.archive.clone(),
            self.options.compression,
            None,
        )?
        .with_partition_manifest(PartitionManifestParams {
            partition_set_uuid: self.uuid,
            partition_index: index,
            total_partitions: PARTITION_TOTAL_UNKNOWN,
            final_partition: false,
            hash_algorithm_id: self.options.hash_algorithm_id,
            previous_partition_hash: self.previous_hash,
        })?;
        if self.options.data_area_crc32 {
            writer = writer.with_data_area_crc32()?;
        }
        if self.fragment_limits.is_some() {
            writer = writer.with_file_fragmentation()?;
        }
        writer.set_partition_admission(PartitionAdmission {
            max_partition_bytes,
            max_entries: limits.max_entries_per_partition,
            max_entry_bytes: limits.max_entry_bytes,
        })?;
        if let Err(err) = writer.begin_partition_output() {
            if !writer.take_admission_rejection() {
                self.state = SetState::Failed;
            }
            return Err(err);
        }
        self.state = SetState::MemberOpen;
        Ok(PartitionWriter {
            set: self,
            writer: Some(writer),
            index,
        })
    }

    /// Completes the Set.  Succeeds only after the final Partition was
    /// finalized successfully.
    ///
    /// # Errors
    ///
    /// [`SarError::PartitionMissing`] when the final Partition has not been
    /// written, [`SarError::FragmentGap`] when a fragment group never received
    /// its terminal fragment, [`SarError::Malformed`] when the writer has
    /// failed.
    pub fn finish_set(self) -> Result<PartitionSetSummary, SarError> {
        self.finish_set_with_fragments().map(|r| r.summary)
    }

    /// Completes the Set like [`Self::finish_set`] and also reports fragment
    /// statistics.  Writer-side facts only, not a validation result.
    ///
    /// # Errors
    ///
    /// Same as [`Self::finish_set`].
    pub fn finish_set_with_fragments(self) -> Result<FragmentedPartitionSetSummary, SarError> {
        match self.state {
            SetState::Complete if self.open_groups != 0 => Err(SarError::FragmentGap(
                "a fragment group has no terminal fragment",
            )),
            SetState::Complete => Ok(FragmentedPartitionSetSummary {
                summary: PartitionSetSummary {
                    partition_set_uuid: self.uuid,
                    total_partitions: self.next_index,
                    aggregate_bytes: self.aggregate_bytes,
                },
                fragment_groups: self.closed_groups,
                fragments: self.fragments,
            }),
            SetState::Failed => Err(SarError::Malformed("Partition Set writer has failed")),
            SetState::Idle | SetState::MemberOpen => Err(SarError::PartitionMissing(
                "the final Partition has not been written",
            )),
        }
    }
}

/// One open physical Partition.  Finalizing consumes it; dropping it without
/// finalizing marks the Set writer as failed.
pub struct PartitionWriter<'a, W: Write> {
    set: &'a mut PartitionSetWriter,
    writer: Option<ArchiveWriter<W>>,
    index: u32,
}

impl<W: Write> PartitionWriter<'_, W> {
    /// Partition Index of this member.
    #[must_use]
    pub const fn partition_index(&self) -> u32 {
        self.index
    }

    /// Writes one complete Entry into this Partition.
    ///
    /// A refusal caused by the Partition capacity or limits happens before any
    /// byte is published and leaves the member usable.  Any other error may
    /// have produced partial output, so the member and the Set writer fail.
    ///
    /// # Errors
    ///
    /// [`SarError::LimitExceeded`] for admission refusals, otherwise any
    /// [`ArchiveWriter::add_entry`] error.
    pub fn add_entry(&mut self, entry: EntryInput) -> Result<EntryWritten, SarError> {
        let writer = self
            .writer
            .as_mut()
            .ok_or(SarError::Malformed("Partition writer is no longer usable"))?;
        match writer.add_entry(entry) {
            Ok(written) => Ok(written),
            Err(err) => {
                if !writer.take_admission_rejection() {
                    self.writer = None;
                    self.set.state = SetState::Failed;
                }
                Err(err)
            }
        }
    }

    /// Declares a fragment group; see
    /// [`PartitionSetWriter::begin_fragment_group`].
    ///
    /// # Errors
    ///
    /// As for [`PartitionSetWriter::begin_fragment_group`].
    pub fn begin_fragment_group(&mut self, spec: FragmentGroupSpec) -> Result<(), SarError> {
        if self.writer.is_none() {
            return Err(SarError::Malformed("Partition writer is no longer usable"));
        }
        self.set.begin_fragment_group(spec)
    }

    /// Writes the next fragment of group `fragment_id` into this Partition.
    ///
    /// The fragment receives the group's next Fragment Index (`0` first), so
    /// calls define the canonical physical order.  `contribution` is the
    /// logical contribution (it may be empty); it is compressed independently
    /// of every other fragment.  `is_last` sets `LAST_FRAGMENT` and carries
    /// the final File CRC32 and Content Hash, after which the group is closed.
    ///
    /// A refusal before any byte is published (unknown or closed group, group
    /// limits, [`SarError::LimitExceeded`] admission) leaves the member and
    /// the group unchanged.  Any other error may have produced partial
    /// output, so the member and the Set writer fail.
    ///
    /// # Errors
    ///
    /// [`SarError::Malformed`] for an unknown group,
    /// [`SarError::MetadataConflict`] for a fragment after `LAST_FRAGMENT`,
    /// [`SarError::LimitExceeded`] / [`SarError::Overflow`] for limits, and
    /// any [`ArchiveWriter::add_entry`] error.
    pub fn add_fragment(
        &mut self,
        fragment_id: u32,
        contribution: Vec<u8>,
        is_last: bool,
    ) -> Result<EntryWritten, SarError> {
        if self.writer.is_none() {
            return Err(SarError::Malformed("Partition writer is no longer usable"));
        }
        let mut plan = self
            .set
            .plan_fragment(fragment_id, &contribution, is_last)?;
        // Running digests advance only after publication, so a refused
        // nonterminal fragment can be retried; this copy is bounded by the
        // staging limit like the writer's own payload copy.
        let archive = &self.set.options.archive;
        let retained = (!is_last && (archive.with_per_file_crc || archive.with_content_hash))
            .then(|| contribution.clone());
        let input = self
            .set
            .fragment_input(fragment_id, contribution, &mut plan)?;
        let params = FragmentLfhParams {
            id: fragment_id,
            index: plan.index,
            last: is_last,
            loss_tolerant: plan.loss_tolerant,
        };
        let writer = self
            .writer
            .as_mut()
            .ok_or(SarError::Malformed("Partition writer is no longer usable"))?;
        match writer.add_entry_with_fragment(input, Some(params)) {
            Ok(written) => {
                self.set
                    .commit_fragment(fragment_id, plan, is_last, retained)?;
                Ok(written)
            }
            Err(err) => {
                if writer.take_admission_rejection() {
                    self.set.remember_terminal(fragment_id, &plan);
                } else {
                    self.writer = None;
                    self.set.state = SetState::Failed;
                }
                Err(err)
            }
        }
    }

    /// Finalizes this member as a nonfinal Partition.
    ///
    /// # Errors
    ///
    /// [`SarError::PartitionMismatch`] if the declared total requires this to
    /// be the final member, plus any I/O or structural error; every error
    /// fails the Set writer.
    pub fn finish(self) -> Result<PartitionMemberSummary, SarError> {
        self.finish_member(false)
    }

    /// Finalizes this member as the final Partition, fixing the Set total at
    /// `index + 1`.
    ///
    /// # Errors
    ///
    /// [`SarError::PartitionMismatch`] if a declared total differs from
    /// `index + 1`, plus any I/O or structural error; every error fails the
    /// Set writer.
    pub fn finish_final(self) -> Result<PartitionMemberSummary, SarError> {
        self.finish_member(true)
    }

    fn finish_member(mut self, is_final: bool) -> Result<PartitionMemberSummary, SarError> {
        let writer = self
            .writer
            .take()
            .ok_or(SarError::Malformed("Partition writer is no longer usable"))?;
        self.set.state = SetState::Failed;
        if is_final && self.set.open_groups != 0 {
            return Err(SarError::FragmentGap(
                "the final Partition cannot be written while a fragment group is open",
            ));
        }
        let index = self.index;
        let count = index
            .checked_add(1)
            .ok_or(SarError::Overflow("Partition count"))?;
        let total = match (self.set.options.known_total, is_final) {
            (Some(total), true) if total != count => {
                return Err(SarError::PartitionMismatch(
                    "final Partition does not match the declared Total Partitions",
                ));
            }
            (Some(total), false) if count >= total => {
                return Err(SarError::PartitionMismatch(
                    "the last declared Partition must be finalized as final",
                ));
            }
            (Some(total), _) => total,
            (None, true) => count,
            (None, false) => PARTITION_TOTAL_UNKNOWN,
        };
        let mut writer = writer;
        writer.set_partition_finality(is_final, total)?;
        let (summary, commitment) = writer.finish_with_commitment()?;
        let commitment = commitment.ok_or(SarError::Internal("missing Partition commitment"))?;
        let entry_count = summary
            .entry_count
            .checked_sub(1)
            .ok_or(SarError::Internal("Partition Manifest not counted"))?;
        let aggregate = self
            .set
            .aggregate_bytes
            .checked_add(summary.archive_size)
            .ok_or(SarError::Overflow("aggregate encoded size"))?;
        if aggregate > self.set.options.limits.max_aggregate_bytes {
            return Err(SarError::LimitExceeded(
                "aggregate encoded size limit exceeded",
            ));
        }
        let member = PartitionMemberSummary {
            partition_index: index,
            is_final,
            total_partitions: total,
            entry_count,
            indexed: summary.indexed,
            partition_len: summary.archive_size,
            committed_content_length: commitment.manifest_offset,
            previous_partition_hash: self.set.previous_hash,
            current_partition_hash: commitment.current_hash,
        };
        self.set.previous_hash = commitment.current_hash;
        self.set.next_index = count;
        self.set.aggregate_bytes = aggregate;
        self.set.state = if is_final {
            SetState::Complete
        } else {
            SetState::Idle
        };
        Ok(member)
    }
}

impl<W: Write> Drop for PartitionWriter<'_, W> {
    fn drop(&mut self) {
        if self.writer.is_some() {
            self.set.state = SetState::Failed;
        }
    }
}
