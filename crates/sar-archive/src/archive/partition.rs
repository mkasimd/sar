// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Physical Partition construction and local validation (M13b.3 P1).
//!
//! This module is the only place that bypasses the generic unpartitioned
//! processing gate, and only through two explicit entry points:
//! [`ArchiveWriter::with_partition_manifest`] and
//! [`ArchiveReader::inspect_partition`].  Neither exposes the Partition as a
//! logical archive and neither evaluates a Partition Set.

use super::*;

use sar_core::partition_manifest::{
    PARTITION_MANIFEST_V1_LEN, PARTITION_MAX_SUPPORTED_COUNT, PartitionManifestFlags,
    PartitionManifestV1, validate_manifest_hash_algorithm_id, validate_partition_manifest_lfh,
};
use sar_crypto::aead::aead_decrypt;
use sar_crypto::algorithm::AEAD_TAG_SIZE;
use sar_crypto::hash::{Hasher, ct_eq, new_hasher};
use sar_partition::{ManifestAuthentication, PartitionSetStatus, PredecessorLink};

/// Largest Manifest payload read into memory.  Version 1 needs 116 bytes at
/// most; the margin only bounds the allocation made before the Manifest
/// Version is known.
const MANIFEST_PAYLOAD_READ_LIMIT: u64 = 4096;
const HASH_CHUNK: usize = 64 * 1024;

/// Result of [`ArchiveReader::inspect_partition`]: one physical Partition
/// whose local structure and content commitment were verified.
///
/// Fields are private and the only constructor is the inspection routine, so a
/// value of this type cannot be forged by callers: it always reflects a
/// completed physical inspection, and
/// [`Self::manifest_authentication`] reports what that inspection actually
/// established.  It is **not** a Partition Set: the predecessor link is
/// unverified and the set status is
/// [`PartitionSetStatus::NotEvaluated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPartition {
    manifest: PartitionManifestV1,
    manifest_offset: u64,
    partition_len: u64,
    indexed: bool,
    authentication: ManifestAuthentication,
}

impl ValidatedPartition {
    /// The decoded Manifest.
    #[must_use]
    pub const fn manifest(&self) -> &PartitionManifestV1 {
        &self.manifest
    }

    /// Zero-based Partition Index.
    #[must_use]
    pub const fn partition_index(&self) -> u32 {
        self.manifest.partition_index
    }

    /// Known total, or `None` for the unknown sentinel.
    #[must_use]
    pub const fn known_total(&self) -> Option<u32> {
        if self.manifest.total_partitions == sar_core::PARTITION_TOTAL_UNKNOWN {
            None
        } else {
            Some(self.manifest.total_partitions)
        }
    }

    /// True when this Partition declares `FINAL_PARTITION`.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.manifest.flags.is_final()
    }

    /// Physical offset of the Manifest LFH (equals the committed length).
    #[must_use]
    pub const fn manifest_offset(&self) -> u64 {
        self.manifest_offset
    }

    /// Physical length of the Partition in bytes.
    #[must_use]
    pub const fn partition_len(&self) -> u64 {
        self.partition_len
    }

    /// True when the Partition carries a local Central Dictionary and Footer.
    #[must_use]
    pub const fn is_indexed(&self) -> bool {
        self.indexed
    }

    /// Manifest authentication outcome.
    #[must_use]
    pub const fn manifest_authentication(&self) -> ManifestAuthentication {
        self.authentication
    }

    /// Declared predecessor relationship (never verified here).
    #[must_use]
    pub const fn predecessor_link(&self) -> PredecessorLink {
        if self.manifest.partition_index == 0 {
            PredecessorLink::NotApplicable
        } else {
            PredecessorLink::Unverified(self.manifest.previous_partition_hash)
        }
    }

    /// Always [`PartitionSetStatus::NotEvaluated`].
    #[must_use]
    pub const fn set_status(&self) -> PartitionSetStatus {
        PartitionSetStatus::NotEvaluated
    }
}

/// Identity and ordering fields of the Partition Manifest written by
/// [`ArchiveWriter::finish`] for one Partition.
///
/// `Committed Content Length` and `Current Partition Hash` are computed by the
/// writer and cannot be supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionManifestParams {
    /// Opaque, nonzero Partition Set UUID.
    pub partition_set_uuid: [u8; 16],
    /// Zero-based Partition Index.
    pub partition_index: u32,
    /// Known total, or `0xFFFFFFFF` when not yet known.
    pub total_partitions: u32,
    /// Sets `FINAL_PARTITION`.
    pub final_partition: bool,
    /// DATA_HASH algorithm ID (`0x30` SHA256 or `0x31` BLAKE3-256).
    pub hash_algorithm_id: u8,
    /// Declared `Previous Partition Hash`; all zero for Partition Index zero.
    pub previous_partition_hash: [u8; 32],
}

pub(super) struct PartitionWriterState {
    params: PartitionManifestParams,
    hasher: Option<Box<dyn Hasher>>,
}

impl PartitionWriterState {
    /// Feeds encoded Partition bytes that precede the Manifest LFH.
    pub(super) fn commit(&mut self, bytes: &[u8]) {
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
    }
}

impl<W: Write> ArchiveWriter<W> {
    /// Turns this writer into a single physical Partition writer.
    ///
    /// Sets `PARTITIONED_ARCHIVE`; [`Self::finish`] then appends the terminal
    /// Partition Manifest Entry (committing the exact encoded bytes written so
    /// far) before the local Central Dictionary and Footer.  Must be called
    /// before the Global Header is emitted.  The writer produces one Partition
    /// only; it does not assemble or validate a Partition Set.
    ///
    /// # Errors
    ///
    /// Manifest field errors ([`SarError::Malformed`], [`SarError::Unsupported`],
    /// [`SarError::ReservedValue`], [`SarError::LimitExceeded`]),
    /// [`SarError::Malformed`] when the Global Header was already emitted, and
    /// [`SarError::FlagConflict`] for an invalid flag combination.
    pub fn with_partition_manifest(
        mut self,
        params: PartitionManifestParams,
    ) -> Result<Self, SarError> {
        if self.finished || self.header_written || self.partition.is_some() {
            return Err(SarError::Malformed(
                "Partition Manifest must be configured once, before the Global Header",
            ));
        }
        // Field validation with placeholder digests; the real values are
        // computed in `finish`.
        manifest_from_params(&params, 0, [0u8; 32])?
            .validate_fields(PARTITION_MAX_SUPPORTED_COUNT)?;
        let flags = self.flags | GlobalFlags::PARTITIONED_ARCHIVE;
        validate_global_flags(flags)?;
        self.flags = flags;
        self.partition = Some(PartitionWriterState {
            params,
            hasher: Some(new_hasher(params.hash_algorithm_id).map_err(SarError::from)?),
        });
        Ok(self)
    }

    /// Writes the terminal Partition Manifest Entry.
    pub(super) fn write_partition_manifest(&mut self) -> Result<(), SarError> {
        let state = self
            .partition
            .as_mut()
            .ok_or(SarError::Internal("Partition Manifest state missing"))?;
        let params = state.params;
        let digest = state
            .hasher
            .take()
            .ok_or(SarError::Malformed("Partition Manifest already written"))?
            .finalize();
        let current_hash = <[u8; 32]>::try_from(digest.as_slice())
            .map_err(|_| SarError::Internal("Partition hash is not 32 bytes"))?;
        let committed = self.position;
        let plain = manifest_from_params(&params, committed, current_hash)?
            .encode(PARTITION_MAX_SUPPORTED_COUNT)?;

        let manifest_len = u64::try_from(PARTITION_MANIFEST_V1_LEN)
            .map_err(|_| SarError::Overflow("Manifest length"))?;
        let is_encrypted = self.flags.contains(GlobalFlags::ENCRYPTED);
        let mut mode = EntryMode::PARTITION_MANIFEST;
        let mut payload_len = manifest_len;
        if is_encrypted {
            mode |= EntryMode::ENCRYPTED;
            payload_len = payload_len
                .checked_add(16)
                .ok_or(SarError::Overflow("encrypted Manifest length"))?;
        }
        let mut lfh = LocalFileHeader::minimal_store(Vec::new(), payload_len);
        lfh.entry_mode = EntryMode::from_bits(mode);
        lfh.uncompressed_size = manifest_len;
        if self.flags.contains(GlobalFlags::DEDUPLICATION) {
            lfh.hash_algo_id = Some(params.hash_algorithm_id);
        }

        let payload = if is_encrypted {
            let algo_id = self
                .encr_algo_id
                .ok_or(SarError::Internal("missing writer encryption algorithm"))?;
            let nonce = reserve_unique_nonce(&mut self.used_nonces, |field| {
                generate_nonce(algo_id, field)
            })?;
            lfh.encr_algo_id = Some(algo_id);
            lfh.iv_nonce = Some(nonce);
            let aad_lfh = lfh_bytes_for_aad(self.flags, &lfh_to_bytes(&lfh, self.flags)?, 0, 0)?;
            let aad = build_aead_aad(&self.global_header_bytes, &aad_lfh);
            let key = self.derive_writer_entry_key(algo_id, &nonce)?;
            encode_payload_v2(
                &plain,
                EncodingPlanV2 {
                    is_compressed: false,
                    comp_algo_id: COMP_ALGO_STORE,
                    compression_level: None,
                    crypto: Some(EntryCryptoContext {
                        algo_id,
                        iv_nonce: nonce,
                        aad,
                        key,
                    }),
                },
            )?
        } else {
            plain.to_vec()
        };
        let lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
        self.write_entry(lfh, lfh_bytes, payload)?;
        Ok(())
    }
}

fn manifest_from_params(
    params: &PartitionManifestParams,
    committed: u64,
    current: [u8; 32],
) -> Result<PartitionManifestV1, SarError> {
    validate_manifest_hash_algorithm_id(params.hash_algorithm_id)?;
    Ok(PartitionManifestV1 {
        hash_algorithm_id: params.hash_algorithm_id,
        flags: PartitionManifestFlags::new(params.final_partition),
        partition_index: params.partition_index,
        total_partitions: params.total_partitions,
        committed_content_length: committed,
        partition_set_uuid: params.partition_set_uuid,
        previous_partition_hash: params.previous_partition_hash,
        current_partition_hash: current,
    })
}

/// Location of the terminal Manifest found by the physical walk.
struct ManifestSite {
    offset: u64,
    lfh: LocalFileHeader,
    lfh_bytes: Vec<u8>,
    payload_start: u64,
}

impl<R: Read + Seek> ArchiveReader<R> {
    /// Validates this source as exactly one physical Partition.
    ///
    /// Consumes the reader so the Partition cannot afterwards be processed as
    /// a logical archive; generic reader paths still reject
    /// `PARTITIONED_ARCHIVE`.  Equivalent to
    /// [`Self::inspect_partition_with_max_partitions`] with 65535.
    ///
    /// # Errors
    ///
    /// See [`Self::inspect_partition_with_max_partitions`].
    pub fn inspect_partition(self) -> Result<ValidatedPartition, SarError> {
        self.inspect_partition_with_max_partitions(PARTITION_MAX_SUPPORTED_COUNT)
    }

    /// Validates this source as exactly one physical Partition (spec
    /// §§6.2.1, 7, 19.1.1–19.1.5, 19.1.7, 19.1.12–19.1.14).
    ///
    /// Checks, in order: Global Header, local Footer/CD presence per
    /// `NO_INDEX`, the sequential LFH walk (exactly one terminal Manifest,
    /// bounded by the Data Area), Manifest LFH restrictions, CD offsets and the
    /// Data Area CRC32, Manifest payload (AEAD-authenticated when `ENCRYPTED`;
    /// a key provider is then required), `Committed Content Length`, and
    /// finally the Current Partition Hash over the encoded bytes
    /// `[0, Committed Content Length)`, streamed through a fixed buffer.
    ///
    /// Ordinary Entry payloads are neither decoded nor authenticated, and
    /// `DATA_HASH`/`SIGNATURE` metadata is not evaluated.  Nothing here
    /// verifies the predecessor link or any Partition Set property; a plaintext
    /// Manifest is reported as unauthenticated.
    ///
    /// # Errors
    ///
    /// Per spec §19.1.14: [`SarError::MetadataMissing`],
    /// [`SarError::MetadataConflict`], [`SarError::FlagConflict`],
    /// [`SarError::Malformed`], [`SarError::InvalidLength`],
    /// [`SarError::Unsupported`], [`SarError::ReservedValue`],
    /// [`SarError::LimitExceeded`], [`SarError::HashMismatch`], plus
    /// [`SarError::CrcMismatch`], [`SarError::Truncated`],
    /// [`SarError::KeyMissing`] and [`SarError::AuthFailed`] for the
    /// corresponding structural, key and AEAD failures.
    pub fn inspect_partition_with_max_partitions(
        mut self,
        max_partitions: u32,
    ) -> Result<ValidatedPartition, SarError> {
        let header = self.read_global_header_inner(true)?;
        if !header.flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) {
            return Err(SarError::FlagConflict(
                "Partition inspection requires PARTITIONED_ARCHIVE",
            ));
        }

        let (site, physical) = self.walk_partition(&header)?;

        if let Some(cd) = &self.cd {
            check_cd_index_against_lfhs(cd, &physical)?;
            if cd.offsets.last() != Some(&site.offset) {
                return Err(SarError::Malformed(
                    "the final indexed LFH must be the Partition Manifest Entry",
                ));
            }
        }
        if self.cd.is_some() {
            self.verify_data_area_crc32()?;
        }

        let (plain, authentication) = self.read_manifest_payload(&header, &site)?;
        let manifest = PartitionManifestV1::decode(&plain, max_partitions)?;
        let manifest_len = u64::try_from(PARTITION_MANIFEST_V1_LEN)
            .map_err(|_| SarError::Overflow("Manifest length"))?;
        let expected_payload = match authentication {
            ManifestAuthentication::Aead => manifest_len
                .checked_add(16)
                .ok_or(SarError::Overflow("encrypted Manifest length"))?,
            ManifestAuthentication::Unauthenticated => manifest_len,
        };
        if site.lfh.uncompressed_size != manifest_len || site.lfh.payload_size != expected_payload {
            return Err(SarError::InvalidLength(
                "Partition Manifest Uncompressed Size or Payload Size is not valid for Version 1",
            ));
        }
        if manifest.committed_content_length != site.offset {
            return Err(SarError::Malformed(
                "Committed Content Length differs from the Manifest LFH offset",
            ));
        }

        let computed = self.hash_committed_range(manifest.hash_algorithm_id, site.offset)?;
        if !ct_eq(&computed, &manifest.current_partition_hash) {
            return Err(SarError::HashMismatch(
                "Current Partition Hash does not match the committed content",
            ));
        }

        Ok(ValidatedPartition {
            manifest,
            manifest_offset: site.offset,
            partition_len: self.file_len,
            indexed: self.cd.is_some(),
            authentication,
        })
    }

    /// Sequentially walks the Data Area, locating the single terminal Manifest.
    ///
    /// Returns the Manifest site and `(offset, indexed)` for every LFH.
    fn walk_partition(
        &mut self,
        header: &GlobalHeader,
    ) -> Result<(ManifestSite, Vec<(u64, bool)>), SarError> {
        let mut offset = self.header_len;
        let mut physical: Vec<(u64, bool)> = Vec::new();
        let mut site: Option<ManifestSite> = None;

        while offset < self.data_end {
            self.reader.seek(SeekFrom::Start(offset))?;
            let mut size_bytes = [0u8; 4];
            read_required(&mut self.reader, &mut size_bytes, "LFH header size")?;
            let header_size = usize::try_from(u32::from_le_bytes(size_bytes))
                .map_err(|_| SarError::Overflow("LFH header size"))?;
            let parsed = self.read_lfh_at(header, offset, size_bytes, header_size);

            if site.is_some() {
                return match parsed {
                    Ok((lfh, _)) if lfh.entry_mode.is_partition_manifest() => {
                        Err(SarError::MetadataConflict(
                            "more than one Partition Manifest Entry in one Partition",
                        ))
                    }
                    _ => Err(SarError::Malformed(
                        "no LFH may follow the Partition Manifest Entry",
                    )),
                };
            }
            let (lfh, lfh_bytes) = parsed?;

            let payload_start = offset
                .checked_add(u64::from(lfh.header_size))
                .ok_or(SarError::Overflow("payload start"))?;
            let payload_end = payload_start
                .checked_add(lfh.payload_size)
                .ok_or(SarError::Overflow("payload end"))?;
            if payload_end > self.data_end {
                return Err(SarError::Truncated(
                    "LFH payload exceeds the Partition Data Area",
                ));
            }
            self.options
                .limits
                .check_entry_count(physical.len().saturating_add(1))?;
            physical.push((offset, !is_empty_area(&lfh)));

            if lfh.entry_mode.is_partition_manifest() {
                validate_partition_manifest_lfh(header.flags, &lfh)?;
                site = Some(ManifestSite {
                    offset,
                    lfh,
                    lfh_bytes,
                    payload_start,
                });
            } else if lfh.entry_mode.is_session_control() || lfh.entry_mode.op_code() != 0 {
                return Err(SarError::Unsupported(
                    "archive parsing rejects SESSION_CONTROL entries and nonzero OP_CODE values by default",
                ));
            }
            offset = payload_end;
        }

        let site = site.ok_or(SarError::MetadataMissing(
            "Partition does not contain a Partition Manifest Entry",
        ))?;
        Ok((site, physical))
    }

    /// Reads and parses one LFH, bounding it by the Data Area.
    fn read_lfh_at(
        &mut self,
        header: &GlobalHeader,
        offset: u64,
        size_bytes: [u8; 4],
        header_size: usize,
    ) -> Result<(LocalFileHeader, Vec<u8>), SarError> {
        self.options.limits.check_lfh_header_bytes(header_size)?;
        if header_size < 4 {
            return Err(SarError::InvalidLength(
                "LFH Header Size smaller than fixed prefix",
            ));
        }
        let header_end = offset
            .checked_add(
                u64::try_from(header_size).map_err(|_| SarError::Overflow("LFH header size"))?,
            )
            .ok_or(SarError::Overflow("LFH header end"))?;
        if header_end > self.data_end {
            return Err(SarError::Truncated("LFH exceeds the Partition Data Area"));
        }
        let mut lfh_bytes = vec![0u8; header_size];
        lfh_bytes[..4].copy_from_slice(&size_bytes);
        if header_size > 4 {
            read_required(&mut self.reader, &mut lfh_bytes[4..], "LFH")?;
        }
        let (lfh, _) = parse_lfh(&lfh_bytes, &header.flags, &self.options.limits)?;
        Ok((lfh, lfh_bytes))
    }

    /// Returns the decoded Manifest payload, AEAD-authenticated when required.
    fn read_manifest_payload(
        &mut self,
        header: &GlobalHeader,
        site: &ManifestSite,
    ) -> Result<(Vec<u8>, ManifestAuthentication), SarError> {
        if site.lfh.payload_size > MANIFEST_PAYLOAD_READ_LIMIT {
            return Err(SarError::LimitExceeded(
                "Partition Manifest payload exceeds the read limit",
            ));
        }
        self.options
            .limits
            .check_allocation_bytes(site.lfh.payload_size)?;
        let payload_len = usize::try_from(site.lfh.payload_size)
            .map_err(|_| SarError::Overflow("Manifest payload length"))?;
        self.reader.seek(SeekFrom::Start(site.payload_start))?;
        let mut payload = vec![0u8; payload_len];
        read_required(&mut self.reader, &mut payload, "Partition Manifest payload")?;

        if !site.lfh.entry_mode.is_encrypted() {
            return Ok((payload, ManifestAuthentication::Unauthenticated));
        }

        let algo_id = site.lfh.encr_algo_id.ok_or(SarError::Malformed(
            "encrypted Partition Manifest is missing Encr Algo ID",
        ))?;
        if payload.len() < AEAD_TAG_SIZE {
            return Err(SarError::InvalidLength(
                "encrypted Partition Manifest is shorter than its AEAD tag",
            ));
        }
        let provider = self.key_provider.as_deref().ok_or(SarError::KeyMissing(
            "no key provider configured for encrypted Partition Manifest",
        ))?;
        let context = build_kms_context(header)?;
        let iv_nonce = site.lfh.iv_nonce.ok_or(SarError::Malformed(
            "encrypted Partition Manifest is missing IV/nonce field",
        ))?;
        let key = {
            let mut scope = self
                .master_secret
                .lock()
                .map_err(|_| SarError::Internal("master secret scope poisoned"))?;
            let master = scope
                .get_or_resolve(provider, &context, &self.options.limits.kdf_limits())
                .map_err(SarError::from)?;
            derive_entry_key(master, algo_id, &iv_nonce).map_err(SarError::from)?
        };
        let aad_lfh = lfh_bytes_for_aad(
            header.flags,
            &site.lfh_bytes,
            site.lfh.fec_algo_id.unwrap_or(0),
            site.lfh.fec_value.len(),
        )?;
        let aad = build_aead_aad(&self.global_header_bytes, &aad_lfh);
        let plain =
            aead_decrypt(algo_id, &key, &iv_nonce, &aad, &payload).map_err(SarError::from)?;
        Ok((plain, ManifestAuthentication::Aead))
    }

    /// Hashes the encoded physical bytes `[0, committed)` with a fixed buffer.
    fn hash_committed_range(&mut self, algo_id: u8, committed: u64) -> Result<Vec<u8>, SarError> {
        let mut hasher = new_hasher(algo_id).map_err(SarError::from)?;
        self.reader.seek(SeekFrom::Start(0))?;
        let mut remaining = committed;
        let mut buf = vec![0u8; HASH_CHUNK];
        while remaining > 0 {
            let chunk =
                usize::try_from(remaining).map_or(HASH_CHUNK, |value| value.min(HASH_CHUNK));
            read_required(
                &mut self.reader,
                &mut buf[..chunk],
                "committed Partition content",
            )?;
            hasher.update(&buf[..chunk]);
            remaining -= u64::try_from(chunk).map_err(|_| SarError::Overflow("hash chunk"))?;
        }
        Ok(hasher.finalize())
    }
}
