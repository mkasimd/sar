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
//!   never split across members.  An Entry that does not fit is refused
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

use super::*;

use partition::PartitionAdmission;
use sar_core::partition_manifest::validate_manifest_hash_algorithm_id;
use sar_core::{PARTITION_MAX_SUPPORTED_COUNT, PARTITION_TOTAL_UNKNOWN};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetState {
    Idle,
    MemberOpen,
    Complete,
    Failed,
}

/// Sequential writer for the members of one Partition Set.
pub struct PartitionSetWriter {
    options: PartitionSetWriterOptions,
    uuid: [u8; 16],
    state: SetState,
    next_index: u32,
    previous_hash: [u8; 32],
    aggregate_bytes: u64,
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
            uuid,
            state: SetState::Idle,
            next_index: 0,
            previous_hash: [0u8; 32],
            aggregate_bytes: 0,
        })
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
    /// written, [`SarError::Malformed`] when the writer has failed.
    pub fn finish_set(self) -> Result<PartitionSetSummary, SarError> {
        match self.state {
            SetState::Complete => Ok(PartitionSetSummary {
                partition_set_uuid: self.uuid,
                total_partitions: self.next_index,
                aggregate_bytes: self.aggregate_bytes,
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
