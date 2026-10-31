// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Partition Manifest Version 1 (spec §§6.2.1, 19.1.1–19.1.4, 19.1.14).
//!
//! Pure, side-effect-free codec and field validation for the 100-byte decoded
//! Manifest payload and the structural LFH restrictions of a Partition Manifest
//! Entry.  Nothing here validates a Partition Set: predecessor links, set-wide
//! consistency and completeness belong to later layers.

use sar_crypto::algorithm::{HASH_BLAKE3, HASH_SHA3_256, HASH_SHA256};

use crate::error::SarError;
use crate::flags::{EntryMode, GlobalFlags, validate_entry_mode_against_global};
use crate::format::LocalFileHeader;

/// The only Manifest Version defined by SAR version 1.0.
pub const PARTITION_MANIFEST_VERSION_1: u8 = 1;
/// Exact decoded size of a Manifest Version 1 payload.
pub const PARTITION_MANIFEST_V1_LEN: usize = 100;
/// `Total Partitions` sentinel for a not-yet-known count.
pub const PARTITION_TOTAL_UNKNOWN: u32 = 0xFFFF_FFFF;
/// Length of a Manifest digest (all registered DATA_HASH algorithms used here).
pub const PARTITION_HASH_LEN: usize = 32;
/// Length of the opaque Partition Set UUID.
pub const PARTITION_SET_UUID_LEN: usize = 16;
/// Smallest Partition count every partition-capable implementation must
/// support (spec §19.1.3); used as the default configured limit.
pub const PARTITION_MAX_SUPPORTED_COUNT: u32 = 65_535;

const OFF_VERSION: usize = 0;
const OFF_HASH_ALGO: usize = 1;
const OFF_FLAGS: usize = 2;
const OFF_INDEX: usize = 4;
const OFF_TOTAL: usize = 8;
const OFF_COMMITTED: usize = 12;
const OFF_UUID: usize = 20;
const OFF_PREV_HASH: usize = 36;
const OFF_CURRENT_HASH: usize = 68;

/// Manifest Flags (Manifest Version 1): bit 0 is `FINAL_PARTITION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PartitionManifestFlags(u16);

impl PartitionManifestFlags {
    /// Bit 0: this Partition is the final Partition of the set.
    pub const FINAL_PARTITION: u16 = 1;

    /// Builds the flag field from the `FINAL_PARTITION` state.
    #[must_use]
    pub const fn new(final_partition: bool) -> Self {
        Self(if final_partition {
            Self::FINAL_PARTITION
        } else {
            0
        })
    }

    /// Decodes wire bits, rejecting every reserved bit.
    ///
    /// # Errors
    ///
    /// [`SarError::ReservedValue`] when any of bits 1 through 15 is set.
    pub fn from_wire(bits: u16) -> Result<Self, SarError> {
        if bits & !Self::FINAL_PARTITION != 0 {
            return Err(SarError::ReservedValue(
                "reserved Partition Manifest Flags bit is set",
            ));
        }
        Ok(Self(bits))
    }

    /// Raw wire bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// True when `FINAL_PARTITION` is set.
    #[must_use]
    pub const fn is_final(self) -> bool {
        self.0 & Self::FINAL_PARTITION != 0
    }
}

/// Decoded Partition Manifest Version 1 payload.
///
/// The Partition Set UUID is opaque bytes; no UUID byte order is assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionManifestV1 {
    /// SAR DATA_HASH algorithm identifier of both digests.
    pub hash_algorithm_id: u8,
    /// Manifest Flags.
    pub flags: PartitionManifestFlags,
    /// Zero-based Partition Index.
    pub partition_index: u32,
    /// Known total (`1..=0xFFFFFFFE`) or [`PARTITION_TOTAL_UNKNOWN`].
    pub total_partitions: u32,
    /// Physical offset of the Manifest LFH from byte zero of the Partition.
    pub committed_content_length: u64,
    /// Opaque, nonzero Partition Set identity.
    pub partition_set_uuid: [u8; PARTITION_SET_UUID_LEN],
    /// Declared predecessor digest; all zero for Partition Index zero.
    pub previous_partition_hash: [u8; PARTITION_HASH_LEN],
    /// Digest of `Partition[0 .. Committed Content Length)`.
    pub current_partition_hash: [u8; PARTITION_HASH_LEN],
}

/// Validates a Manifest Hash Algorithm ID.
///
/// # Errors
///
/// [`SarError::Unsupported`] for the registered but unimplemented SHA3-256,
/// [`SarError::ReservedValue`] for any unregistered identifier.
pub fn validate_manifest_hash_algorithm_id(id: u8) -> Result<(), SarError> {
    match id {
        HASH_SHA256 | HASH_BLAKE3 => Ok(()),
        HASH_SHA3_256 => Err(SarError::Unsupported(
            "SHA3_256 Partition Manifest hash is not implemented",
        )),
        _ => Err(SarError::ReservedValue(
            "unregistered Partition Manifest Hash Algorithm ID",
        )),
    }
}

impl PartitionManifestV1 {
    /// Decodes and locally validates a Manifest Version 1 payload.
    ///
    /// `max_partitions` is the configured Partition count limit (spec §19.1.13).
    ///
    /// # Errors
    ///
    /// * [`SarError::InvalidLength`] for an empty payload or a Version 1 payload
    ///   that is not exactly 100 bytes.
    /// * [`SarError::Unsupported`] for any other Manifest Version.
    /// * [`SarError::ReservedValue`] for a reserved flag bit or an unregistered
    ///   Hash Algorithm ID; [`SarError::Unsupported`] for SHA3_256.
    /// * [`SarError::Malformed`], [`SarError::LimitExceeded`] per
    ///   [`Self::validate_fields`].
    pub fn decode(bytes: &[u8], max_partitions: u32) -> Result<Self, SarError> {
        let Some(&version) = bytes.get(OFF_VERSION) else {
            return Err(SarError::InvalidLength(
                "Partition Manifest payload is empty",
            ));
        };
        if version != PARTITION_MANIFEST_VERSION_1 {
            return Err(SarError::Unsupported(
                "unsupported Partition Manifest Version",
            ));
        }
        if bytes.len() != PARTITION_MANIFEST_V1_LEN {
            return Err(SarError::InvalidLength(
                "Partition Manifest Version 1 payload must be exactly 100 bytes",
            ));
        }
        let flags =
            PartitionManifestFlags::from_wire(u16::from_le_bytes(array(bytes, OFF_FLAGS)?))?;
        let manifest = Self {
            hash_algorithm_id: bytes[OFF_HASH_ALGO],
            flags,
            partition_index: u32::from_le_bytes(array(bytes, OFF_INDEX)?),
            total_partitions: u32::from_le_bytes(array(bytes, OFF_TOTAL)?),
            committed_content_length: u64::from_le_bytes(array(bytes, OFF_COMMITTED)?),
            partition_set_uuid: array(bytes, OFF_UUID)?,
            previous_partition_hash: array(bytes, OFF_PREV_HASH)?,
            current_partition_hash: array(bytes, OFF_CURRENT_HASH)?,
        };
        manifest.validate_fields(max_partitions)?;
        Ok(manifest)
    }

    /// Validates, then encodes the exact 100-byte Version 1 payload.
    ///
    /// # Errors
    ///
    /// Every error of [`Self::validate_fields`].
    pub fn encode(&self, max_partitions: u32) -> Result<[u8; PARTITION_MANIFEST_V1_LEN], SarError> {
        self.validate_fields(max_partitions)?;
        let mut out = [0u8; PARTITION_MANIFEST_V1_LEN];
        out[OFF_VERSION] = PARTITION_MANIFEST_VERSION_1;
        out[OFF_HASH_ALGO] = self.hash_algorithm_id;
        out[OFF_FLAGS..OFF_INDEX].copy_from_slice(&self.flags.bits().to_le_bytes());
        out[OFF_INDEX..OFF_TOTAL].copy_from_slice(&self.partition_index.to_le_bytes());
        out[OFF_TOTAL..OFF_COMMITTED].copy_from_slice(&self.total_partitions.to_le_bytes());
        out[OFF_COMMITTED..OFF_UUID].copy_from_slice(&self.committed_content_length.to_le_bytes());
        out[OFF_UUID..OFF_PREV_HASH].copy_from_slice(&self.partition_set_uuid);
        out[OFF_PREV_HASH..OFF_CURRENT_HASH].copy_from_slice(&self.previous_partition_hash);
        out[OFF_CURRENT_HASH..].copy_from_slice(&self.current_partition_hash);
        Ok(out)
    }

    /// Validates the Manifest's own fields (spec §§19.1.3, 19.1.4, 19.1.14).
    ///
    /// Purely local: the predecessor digest is not compared with any other
    /// Partition, and the Current Partition Hash is not recomputed.
    ///
    /// # Errors
    ///
    /// * [`SarError::Unsupported`] / [`SarError::ReservedValue`] for the Hash
    ///   Algorithm ID.
    /// * [`SarError::Malformed`] for an all-zero UUID, zero Total Partitions,
    ///   an index outside a known total, inconsistent `FINAL_PARTITION`, an
    ///   unknown total combined with `FINAL_PARTITION`, or a nonzero
    ///   `Previous Partition Hash` at Partition Index zero.
    /// * [`SarError::LimitExceeded`] when a valid count or index exceeds
    ///   `max_partitions`.
    pub fn validate_fields(&self, max_partitions: u32) -> Result<(), SarError> {
        validate_manifest_hash_algorithm_id(self.hash_algorithm_id)?;
        if self.partition_set_uuid == [0u8; PARTITION_SET_UUID_LEN] {
            return Err(SarError::Malformed("Partition Set UUID must be nonzero"));
        }
        let is_final = self.flags.is_final();
        match self.total_partitions {
            0 => return Err(SarError::Malformed("Total Partitions must not be zero")),
            PARTITION_TOTAL_UNKNOWN => {
                if is_final {
                    return Err(SarError::Malformed(
                        "FINAL_PARTITION requires a known Total Partitions",
                    ));
                }
            }
            total => {
                if self.partition_index >= total {
                    return Err(SarError::Malformed(
                        "Partition Index must be less than Total Partitions",
                    ));
                }
                let last = total
                    .checked_sub(1)
                    .ok_or(SarError::Overflow("Total Partitions underflow"))?;
                if is_final != (self.partition_index == last) {
                    return Err(SarError::Malformed(
                        "FINAL_PARTITION is inconsistent with Partition Index and Total Partitions",
                    ));
                }
            }
        }
        if self.partition_index == 0 && self.previous_partition_hash != [0u8; PARTITION_HASH_LEN] {
            return Err(SarError::Malformed(
                "Partition Index 0 requires an all-zero Previous Partition Hash",
            ));
        }
        if self.total_partitions != PARTITION_TOTAL_UNKNOWN
            && self.total_partitions > max_partitions
        {
            return Err(SarError::LimitExceeded(
                "Total Partitions exceeds the configured limit",
            ));
        }
        if self.partition_index >= max_partitions {
            return Err(SarError::LimitExceeded(
                "Partition Index exceeds the configured Partition limit",
            ));
        }
        Ok(())
    }
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SarError> {
    let end = offset
        .checked_add(N)
        .ok_or(SarError::Overflow("Partition Manifest field offset"))?;
    bytes
        .get(offset..end)
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(SarError::InvalidLength(
            "Partition Manifest field is truncated",
        ))
}

/// Validates the structural LFH restrictions of a Partition Manifest Entry
/// (spec §6.2.1) against the Global Flags.
///
/// Payload and size relationships (`Uncompressed Size`, `Payload Size`) depend
/// on the decoded Manifest Version and are checked by the caller.
///
/// # Errors
///
/// * [`SarError::Malformed`] when the LFH is not a Partition Manifest Entry or
///   a field violates §6.2.1 (nonzero ID, size, metadata, name, path).
/// * [`SarError::FlagConflict`] for Entry Mode/Global Flag conflicts, including
///   an unencrypted Manifest in an `ENCRYPTED` Partition.
pub fn validate_partition_manifest_lfh(
    global_flags: GlobalFlags,
    lfh: &LocalFileHeader,
) -> Result<(), SarError> {
    if !lfh.entry_mode.is_partition_manifest() {
        return Err(SarError::Malformed("LFH is not a Partition Manifest Entry"));
    }
    validate_entry_mode_against_global(global_flags, lfh.entry_mode)?;
    if global_flags.contains(GlobalFlags::ENCRYPTED) && !lfh.entry_mode.is_encrypted() {
        return Err(SarError::FlagConflict(
            "Partition Manifest in an ENCRYPTED Partition requires IS_ENCRYPTED",
        ));
    }
    if lfh.entry_mode.bits() & EntryMode::ENCRYPTED != 0 {
        let algo = lfh.encr_algo_id.ok_or(SarError::Malformed(
            "encrypted Partition Manifest is missing Encr Algo ID",
        ))?;
        sar_crypto::validate_entry_encr_algo_id(algo).map_err(SarError::from)?;
    }
    let zero = |value: Option<u8>| value.is_none_or(|v| v == 0);
    if lfh.stream_id != 0 || lfh.sequence_no != 0 {
        return Err(SarError::Malformed(
            "Partition Manifest requires zero Stream ID and Sequence No",
        ));
    }
    if !zero(lfh.comp_algo_id)
        || !zero(lfh.patch_algo_id)
        || !zero(lfh.cdc_algo_id)
        || !zero(lfh.fec_algo_id)
    {
        return Err(SarError::Malformed(
            "Partition Manifest requires zero Comp, Patch, CDC and FEC Algo IDs",
        ));
    }
    if lfh.delta_base_hash.is_some_and(|h| h != [0u8; 32]) {
        return Err(SarError::Malformed(
            "Partition Manifest requires an all-zero Delta Base Hash",
        ));
    }
    if !lfh.fec_value.is_empty() || !lfh.sparse_map.is_empty() {
        return Err(SarError::Malformed(
            "Partition Manifest forbids FEC Value and Sparse Map",
        ));
    }
    if lfh.file_crc32.is_some_and(|v| v != 0)
        || lfh.content_hash.is_some_and(|h| h != [0u8; 32])
        || lfh.uid_gid.is_some_and(|v| v != 0)
        || lfh.timestamps.is_some_and(|t| t != [0u64; 3])
        || lfh.permissions.is_some_and(|v| v != 0)
    {
        return Err(SarError::Malformed(
            "Partition Manifest requires zero CRC32, Content Hash, UID/GID, timestamps and permissions",
        ));
    }
    if !lfh.name.is_empty() || !lfh.path.is_empty() {
        return Err(SarError::Malformed(
            "Partition Manifest requires empty Name and Path",
        ));
    }
    Ok(())
}
