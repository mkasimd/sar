// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

use sar_compression::COMP_ALGO_STORE;
use sar_crypto::aad::build_aead_aad;
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, KMS_TLS_EXPORTER, KeyProvider, KmsContext, KmsParams,
    MasterSecretScope, SecretBytes,
    aead::generate_nonce,
    derive_entry_key,
    kms::tls_exporter::parse_tls_exporter_kms_payload,
    kms::types::{parse_kms_payload, serialize_kms_payload},
    provider::resolve_master_secret,
    validate_entry_encr_algo_id,
};
use sar_delta::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH, PATCH_ALGO_VCDIFF,
    PATCH_ALGO_ZSTD_PATCH, PatchAlgoId, apply_bsdiff, apply_vcdiff, bsdiff::BsdiffLimits,
    generate_bsdiff_patch, generate_store_patch, generate_vcdiff_patch, vcdiff::VcdiffLimits,
};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR, FecOptions, types::FecCodec};
use sar_sparse::{
    SparseExtent, SparseMap, apply_sparse_reconstruction, check_gathered_length,
    validate_sparse_extents,
};
use serde::Serialize;

use sar_core::{
    error::SarError,
    flags::{EntryMode, GlobalFlags, validate_global_flags},
    format::{
        CentralDictionary, Footer, GLOBAL_HEADER_FIXED_LEN, GLOBAL_HEADER_FLAGS_OFFSET,
        GlobalHeader, KmsData, LocalFileHeader, SUPPORTED_CD_VERSION, decode_global_flags,
        lfh_bytes_for_aad, lfh_to_bytes, parse_central_dictionary, parse_footer,
        parse_global_header, parse_lfh, parse_partition_central_dictionary,
        require_unpartitioned_processing, validate_global_header_prefix, write_central_dictionary,
        write_footer, write_global_header, write_partition_central_dictionary,
    },
    limits::ResourceLimits,
    tlv::Tlv,
};

mod partition;
mod partition_writer;
pub use partition::{PartitionManifestParams, ValidatedPartition, ValidatedPartitionSet};
pub use partition_writer::{
    PartitionMemberSummary, PartitionSetSummary, PartitionSetWriter, PartitionSetWriterLimits,
    PartitionSetWriterOptions, PartitionWriter,
};

use crate::transform::{
    DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, decode_payload_v2, encode_payload_v2,
};

const ZERO_DELTA_BASE_HASH: [u8; 32] = [0u8; 32];

/// Metadata summary for profile/verification checks.
#[derive(Debug, Clone)]
pub struct ArchiveMetadata {
    /// Parsed global header.
    pub global_header: GlobalHeader,
    /// Central dictionary when present.
    pub central_dictionary: Option<CentralDictionary>,
}

/// Single entry metadata.
#[derive(Debug, Clone, Serialize)]
pub struct EntryMetadata {
    /// Absolute LFH offset.
    pub lfh_offset: u64,
    /// Name bytes interpreted as UTF-8.
    pub name: String,
    /// Optional path bytes interpreted as UTF-8.
    pub path: Option<String>,
    /// Decoded symlink target for symlink entries.
    ///
    /// This is `Some(target)` only when `entry_kind == EntryKind::Symlink`.
    /// The target is decoded strictly from the entry payload bytes (no lossy
    /// conversion). Invalid UTF-8 payload for symlink entries is rejected by
    /// the reader.
    pub symlink_target: Option<String>,
    /// Encoded payload size.
    pub payload_size: u64,
    /// LFH `Uncompressed Size`: the decoded size of this physical Entry's
    /// stored representation (spec Section 6.1.2).  For a fragment it is the
    /// decoded contribution; for a delta Entry it is the decoded patch
    /// representation size, **not** the patched output length, so it is not
    /// the length of [`EntryReader::payload`] after patch application.
    pub uncompressed_size: u64,
    /// Effective compression algorithm ID used for decoding.
    pub compression_algo_id: u8,
    /// Effective compression algorithm name.
    pub compression_algorithm: &'static str,
    /// True when entry mode actively applied compression.
    pub is_compressed: bool,
    /// FEC metadata summary (omits parity blob).  `None` when Selective FEC
    /// is disabled or this entry has `FEC Algo ID == 0x00`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<sar_core::fec::FecSummary>,
    /// Fragment ID shared by all fragments of one logical file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_id: Option<u32>,
    /// Zero-based fragment sequence index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_index: Option<u32>,
    /// True when the `IS_FRAGMENT` entry mode bit is set.
    pub is_fragment: bool,
    /// True when the `LAST_FRAGMENT` entry mode bit is set.
    pub is_last_fragment: bool,
    /// True when the `LOSS_TOLERANT` entry mode bit is set.
    pub is_loss_tolerant: bool,
    /// Parsed sparse extents.  `None` when `SPARSE_FILES` is not enabled or
    /// the Sparse Map Size is zero (absent map).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse_extents: Option<Vec<SparseExtent>>,
    /// Per-file CRC32.  `None` when `PER_FILE_CRC` global flag is not set
    /// or the field contains zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_crc32: Option<u32>,
    /// LFH Hash Algo ID selecting the Content Hash algorithm.  `None` when the
    /// `DEDUPLICATION` global flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algo_id: Option<u8>,
    /// Content hash (32 bytes).  `None` when `DEDUPLICATION` global flag is
    /// not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<[u8; 32]>,
    /// CDC algorithm ID from the LFH.  `None` when `CDC_SUPPORT` global flag
    /// is not set.  `0x00` = Literal Mode (payload is literal data).
    /// Values > 0 = Recipe Mode (payload is an ordered list of chunk hashes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdc_algo_id: Option<u8>,
    /// Patch algorithm ID from the LFH.  `None` when `HAS_DELTA` global flag
    /// is not set.  Present as a validated registry byte when `HAS_DELTA` is
    /// set.
    ///
    /// `STORE_PATCH` (`0x00`), `VCDIFF` (`0x01`) and `BSDIFF` (`0x02`) are
    /// applied once to the complete decoded patch representation; `ZSTD_PATCH`
    /// (`0x03`) is not implemented and returns `SAR_ERR_UNSUPPORTED`.  For a
    /// delta Entry, [`EntryMetadata::uncompressed_size`] is the decoded patch
    /// representation (or fragment contribution) size, not the patched length.
    ///
    /// See `docs/SPEC_QUESTIONS.md` for remaining spec gaps (Delta Base Hash
    /// algorithm and base object resolution model).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_algo_id: Option<u8>,
    /// Delta base hash (32 bytes, opaque).  `None` when `HAS_DELTA` global
    /// flag is not set.  The hash algorithm is **not specified** by the spec
    /// and is treated as opaque bytes.  For `STORE_PATCH`, all-zero bytes mean
    /// "no base required".  Serialised as a hex string.
    ///
    /// Base object resolution is **not implemented** in this milestone.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_hash_hex_opt"
    )]
    pub delta_base_hash: Option<[u8; 32]>,

    // -----------------------------------------------------------------------
    // M11a expanded metadata
    // -----------------------------------------------------------------------
    /// Semantic entry kind derived from Entry Mode bits 0/1 and name state.
    pub entry_kind: sar_core::metadata::EntryKind,
    /// Raw Entry Mode bits from the LFH.
    pub entry_mode_raw: u16,
    /// Stream ID from the LFH.
    pub stream_id: u16,
    /// Sequence number from the LFH.
    pub sequence_no: u16,
    /// True when the `HIDDEN_ATTR` entry mode bit is set.
    pub is_hidden: bool,
    /// POSIX permissions.  `None` when the `HAS_PERMS` global flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<sar_core::metadata::EntryPermissionMetadata>,
    /// UID/GID.  `None` when the `EXT_UID_GID` global flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<sar_core::metadata::EntryOwnerMetadata>,
    /// Timestamps (mtime/atime/ctime).  `None` when the `EXT_TIME` global flag
    /// is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<sar_core::metadata::EntryTimestampMetadata>,

    // -----------------------------------------------------------------------
    // M11b filesystem metadata presence model
    // -----------------------------------------------------------------------
    /// Path field presence model (M11b).
    ///
    /// `Absent` when global `HAS_PATH` is not set.
    /// `PresentInactive("")` when `HAS_PATH` is set but path length is zero
    /// (field is physically present in LFH but no path is provided for this entry).
    /// `PresentActive(path)` when `HAS_PATH` is set and a non-empty path is provided.
    ///
    /// Do not collapse `PresentInactive` into `None`; zero-length path is not
    /// the same as an absent path field.
    #[serde(skip)]
    pub path_presence: sar_core::metadata::FieldPresence<String>,
    /// Permissions field presence model (M11b).
    ///
    /// `Absent` when global `HAS_PERMS` is not set.
    /// `PresentActive(value)` when `HAS_PERMS` is set (including when value
    /// is zero/default — a zero mode is not the same as an absent field).
    #[serde(skip)]
    pub permissions_presence:
        sar_core::metadata::FieldPresence<sar_core::metadata::EntryPermissionMetadata>,
    /// UID/GID field presence model (M11b).
    ///
    /// `Absent` when global `EXT_UID_GID` is not set.
    /// `PresentActive(value)` when `EXT_UID_GID` is set (including zero).
    #[serde(skip)]
    pub owner_presence: sar_core::metadata::FieldPresence<sar_core::metadata::EntryOwnerMetadata>,
    /// Timestamps field presence model (M11b).
    ///
    /// `Absent` when global `EXT_TIME` is not set.
    /// `PresentActive(value)` when `EXT_TIME` is set (including all-zero timestamps).
    #[serde(skip)]
    pub timestamps_presence:
        sar_core::metadata::FieldPresence<sar_core::metadata::EntryTimestampMetadata>,

    /// Compression field presence model.
    ///
    /// Distinguishes between the compression field being absent (global
    /// `COMPRESSED` not set), physically present but inactive (`IS_COMPRESSED`
    /// entry-mode bit unset), and present and active.  When `PresentInactive`,
    /// the inner value contains the raw algo_id even though the effective
    /// algorithm is STORE.
    #[serde(skip)]
    pub compression_presence:
        sar_core::metadata::FieldPresence<sar_core::metadata::EntryCompressionMetadata>,
    /// Encryption field presence model.
    ///
    /// Distinguishes between the encryption fields being absent (global
    /// `ENCRYPTED` not set), physically present but inactive (`IS_ENCRYPTED`
    /// entry-mode bit unset), and present and active.
    #[serde(skip)]
    pub encryption_presence:
        sar_core::metadata::FieldPresence<sar_core::metadata::EntryEncryptionMetadata>,
    /// FEC field presence model.
    ///
    /// `Absent` when global `SELECTIVE_FEC` is not set.
    /// `PresentInactive` when `SELECTIVE_FEC` is set but `fec_algo_id == 0`.
    /// `PresentActive` when `SELECTIVE_FEC` is set and `fec_algo_id != 0`.
    #[serde(skip)]
    pub fec_presence: sar_core::metadata::FieldPresence<sar_core::metadata::EntryFecMetadata>,
    /// Fragment field presence model.
    ///
    /// `Absent` when global `FILE_FRAGMENTATION` is not set.
    /// `PresentInactive` when `FILE_FRAGMENTATION` is set but `IS_FRAGMENT`
    /// entry mode is not set.
    /// `PresentActive` when `FILE_FRAGMENTATION` is set and `IS_FRAGMENT` is set.
    #[serde(skip)]
    pub fragment_presence:
        sar_core::metadata::FieldPresence<sar_core::metadata::EntryFragmentMetadata>,
    /// CDC metadata.  `None` when `CDC_SUPPORT` global flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdc: Option<sar_core::metadata::EntryCdcMetadata>,
    /// Delta metadata.  `None` when `HAS_DELTA` global flag is not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<sar_core::metadata::EntryDeltaMetadata>,
    /// Sparse metadata (Sparse Logical Size and extents).  `None` when the
    /// `SPARSE_FILES` global flag is not set or the Sparse Map Size is zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse: Option<sar_core::metadata::EntrySparseMetadata>,
    /// Combined CRC32 and content-hash metadata.  `None` when neither
    /// `PER_FILE_CRC` nor `DEDUPLICATION` global flags are set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<sar_core::metadata::EntryHashMetadata>,
}

/// Serializes an `Option<[u8; 32]>` as an optional lowercase hex string.
fn serialize_hash_hex_opt<S>(value: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            s.serialize_some(&hex)
        }
        None => s.serialize_none(),
    }
}

/// A reconstructed logical file, which may have been assembled from multiple
/// fragment entries or had its sparse holes zero-filled.
///
/// Returned by [`ArchiveReader::read_all_logical_files`].
#[derive(Debug, Clone)]
pub struct LogicalFile {
    /// Entry name (taken from the first or only entry for this logical file).
    pub name: String,
    /// Fragment ID shared by all entries in this group, or `None` for
    /// unfragmented entries.
    pub fragment_id: Option<u32>,
    /// Fully reconstructed payload bytes.
    ///
    /// For fragmented entries, fragment contributions have been concatenated in
    /// ascending Fragment Index order.  For sparse entries, holes are zero-filled.
    pub data: Vec<u8>,
    /// `true` when the payload is incomplete due to missing fragments that were
    /// permitted by `LOSS_TOLERANT` semantics.  Callers **must not** treat this
    /// as a fully verified output.
    pub is_degraded: bool,
}

/// Decoded archive entry returned by [`ArchiveReader::next_entry`].
#[derive(Debug, Clone)]
pub struct EntryReader {
    /// Parsed LFH.
    pub header: LocalFileHeader,
    /// Entry payload bytes.
    pub payload: Vec<u8>,
    /// Entry metadata.
    pub metadata: EntryMetadata,
}

#[derive(Debug)]
struct DecodedArchiveEntryParts {
    payload: Vec<u8>,
    metadata: EntryMetadata,
}

/// Writer input.
///
/// Delta write configuration for a single archive entry.
///
/// When attached to an [`EntryInput`], the archive writer generates a real
/// patch from the supplied base bytes and encodes it as the stored payload.
/// The global `HAS_DELTA` flag must be enabled via
/// [`ArchiveWriterOptions::with_delta`].
///
/// # Constraints
///
/// * `VCDIFF` and `BSDIFF` require a non-zero `delta_base_hash` (all-zero is
///   rejected as missing reconstruction identity).
/// * `STORE_PATCH` accepts an all-zero `delta_base_hash` (no base required).
/// * No automatic base discovery is performed; the caller must supply `base`.
#[derive(Debug, Clone)]
pub struct DeltaWriteOptions {
    /// Patch algorithm to generate.
    pub algorithm: PatchAlgoId,
    /// Base object bytes used by the patch generator.  For `STORE_PATCH` this
    /// is ignored; for `VCDIFF` and `BSDIFF` it is the source bytes.
    pub base: Vec<u8>,
    /// Opaque 32-byte reconstruction identity stored in the LFH
    /// `Delta Base Hash` field.  Must be non-zero for `VCDIFF` and `BSDIFF`.
    pub delta_base_hash: [u8; 32],
}

/// All metadata fields are optional and default to `None`/`false`/`0`.
/// Fields that require a corresponding global flag in
/// [`ArchiveWriterOptions`] are validated fail-closed by
/// [`ArchiveWriter::add_entry`]. If the required flag is not enabled, writing
/// fails with an error.
#[derive(Debug, Clone, Default)]
pub struct EntryInput {
    /// Entry name.
    pub name: String,
    /// Entry payload bytes.
    pub payload: Vec<u8>,
    /// Explicit entry kind.  `None` resolves to `RegularFile` (or
    /// `EmptyArea` when `name` is empty and `is_fragment` is not set).
    pub kind: Option<sar_core::metadata::EntryKind>,
    /// Optional directory path.  Written to the LFH when the writer's
    /// `with_path` option is enabled (`HAS_PATH` global flag).
    pub path: Option<String>,
    /// POSIX permission mode.  Written when `with_permissions` is enabled.
    pub permissions: Option<u16>,
    /// Packed UID/GID (low 16 = UID, high 16 = GID).  Written when
    /// `with_uid_gid` is enabled.
    pub uid_gid: Option<u32>,
    /// Timestamps `[mtime, atime, ctime]` as 64-bit Unix seconds.  Written
    /// when `with_timestamps` is enabled.
    pub timestamps: Option<[u64; 3]>,
    /// If `true`, sets the `HIDDEN_ATTR` entry mode bit.
    pub is_hidden: bool,
    /// Stream ID override.  Defaults to `0` when `None`.
    pub stream_id: Option<u16>,
    /// Sequence number override.  Defaults to `0` when `None`.
    pub sequence_no: Option<u16>,
    /// Per-file CRC32.  Written when `with_per_file_crc` is enabled.
    pub file_crc32: Option<u32>,
    /// LFH Hash Algo ID (`0x30` SHA-256, `0x31` BLAKE3-256, `0x32` SHA3-256)
    /// written with the Content Hash.  Defaults to BLAKE3-256 when `None`.
    pub hash_algo_id: Option<u8>,
    /// Explicit Content Hash (32 bytes), honoured when `with_content_hash` is
    /// enabled.
    ///
    /// * `None`: the writer generates the digest of the final logical Entry
    ///   (sparse holes included) with `hash_algo_id`.
    /// * `Some(value)`: `value` is written verbatim and is **not** checked by
    ///   the writer; a wrong value is detected by the reader as
    ///   `SAR_ERR_HASH_MISMATCH`.  An all-zero value is an ordinary digest,
    ///   not an absent hash.
    pub content_hash: Option<[u8; 32]>,
    /// Delta write options.  When `Some`, the writer generates a real patch
    /// from `delta.base` + `payload` and stores the patch bytes.  The global
    /// [`ArchiveWriterOptions::with_delta`] flag must be enabled.
    pub delta: Option<DeltaWriteOptions>,
}

impl EntryInput {
    /// Constructs a simple regular-file entry with the given name and payload.
    ///
    /// All metadata fields are set to their defaults (`None`/`false`/`0`).
    /// This is the ergonomic constructor for ordinary file entries.
    #[must_use]
    pub fn file(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            payload: payload.into(),
            ..Self::default()
        }
    }
}

/// Result of writing one entry.
#[derive(Debug, Clone)]
pub struct EntryWritten {
    /// Absolute LFH offset.
    pub lfh_offset: u64,
    /// Total bytes written for entry.
    pub total_bytes: u64,
}

/// FEC algorithm settings for archive writing.
///
/// When provided in [`ArchiveWriterOptions`], every entry payload is FEC-encoded
/// and the `SELECTIVE_FEC` global flag is set.
#[derive(Debug, Clone)]
pub struct FecSettings {
    /// FEC algorithm ID (`FEC_ALGO_XOR = 0x14` or `FEC_ALGO_REED_SOLOMON = 0x11`).
    pub algo_id: u8,
    /// Config byte 0: for XOR = stripe size; for RS = `k` (data symbols per group).
    pub config0: u8,
    /// Config byte 1: for XOR = block-size index (0x00–0x08); for RS = parity count (`n-k`).
    pub config1: u8,
    /// Symbol size in bytes.  Used by Reed-Solomon; ignored for XOR.
    pub symbol_size: u32,
}

impl FecSettings {
    /// Constructs default XOR FEC settings: stripe=4, block-size-index=4 (4 KiB blocks).
    #[must_use]
    pub fn default_xor() -> Self {
        Self {
            algo_id: FEC_ALGO_XOR,
            config0: 4,
            config1: 4,
            symbol_size: 0,
        }
    }

    /// Constructs default Reed-Solomon FEC settings: k=4, parity=2, symbol-size=256 B.
    #[must_use]
    pub fn default_rs() -> Self {
        Self {
            algo_id: FEC_ALGO_REED_SOLOMON,
            config0: 4,
            config1: 2,
            symbol_size: 256,
        }
    }
}

/// Archive-level RECOVERY TLV generation settings.
///
/// When provided in [`ArchiveWriterOptions`], the writer generates one
/// archive-level RECOVERY TLV during [`ArchiveWriter::finish`], sets
/// `HAS_GLOBAL_EC`, and protects the byte range from the first Global Flags
/// byte through the final byte immediately before the Central Dictionary.
#[derive(Debug, Clone)]
pub struct ArchiveRecoverySettings {
    /// Recovery algorithm ID (`FEC_ALGO_XOR = 0x14` or `FEC_ALGO_REED_SOLOMON = 0x11`).
    pub algo_id: u8,
    /// Config byte 0: for XOR = stripe size; for RS = `k` (data symbols per group).
    pub config0: u8,
    /// Config byte 1: for XOR = block-size index (0x00–0x08); for RS = parity count (`n-k`).
    pub config1: u8,
    /// Symbol size in bytes. Used by Reed-Solomon; ignored for XOR.
    pub symbol_size: u32,
}

impl ArchiveRecoverySettings {
    /// Constructs default XOR archive-recovery settings.
    #[must_use]
    pub fn default_xor() -> Self {
        Self {
            algo_id: FEC_ALGO_XOR,
            config0: 4,
            config1: 4,
            symbol_size: 0,
        }
    }

    /// Constructs default Reed-Solomon archive-recovery settings.
    #[must_use]
    pub fn default_rs() -> Self {
        Self {
            algo_id: FEC_ALGO_REED_SOLOMON,
            config0: 4,
            config1: 2,
            symbol_size: 256,
        }
    }

    fn as_fec_settings(&self) -> FecSettings {
        FecSettings {
            algo_id: self.algo_id,
            config0: self.config0,
            config1: self.config1,
            symbol_size: self.symbol_size,
        }
    }
}

/// Encryption settings for archive writing.
#[derive(Debug, Clone)]
pub struct EncryptionSettings {
    /// AEAD algorithm ID (`ENCR_AES256_GCM` or `ENCR_XCHACHA20_POLY`).
    pub algo_id: u8,
    /// KMS parameters used to establish the KMS Master Secret and serialize the KMS payload.
    pub kms_params: KmsParams,
}

/// Writer options.
#[derive(Debug, Clone)]
pub struct ArchiveWriterOptions {
    /// If true, omit Central Dictionary and Footer.
    pub no_index: bool,
    /// Optional encryption settings for new entries.
    pub encryption: Option<EncryptionSettings>,
    /// Optional FEC settings.  When set, `SELECTIVE_FEC` is enabled and every
    /// entry payload is FEC-encoded using the specified algorithm.
    pub fec: Option<FecSettings>,
    /// Optional archive-level recovery settings. When set, the writer emits one
    /// Central Dictionary RECOVERY TLV during finalization.
    pub archive_recovery: Option<ArchiveRecoverySettings>,
    /// If `true`, set the global `SPARSE_FILES` flag.  Required before calling
    /// [`ArchiveWriter::write_sparse_entry`].
    pub sparse: bool,
    /// If `true`, set the global `HAS_PATH` flag.  Entries may then supply
    /// `path` in [`EntryInput`] and the writer will include it in the LFH.
    pub with_path: bool,
    /// If `true`, set the global `HAS_PERMS` flag.  Entries may then supply
    /// `permissions` in [`EntryInput`].
    pub with_permissions: bool,
    /// If `true`, set the global `EXT_UID_GID` flag.  Entries may then supply
    /// `uid_gid` in [`EntryInput`].
    pub with_uid_gid: bool,
    /// If `true`, set the global `EXT_TIME` flag.  Entries may then supply
    /// `timestamps` in [`EntryInput`].
    pub with_timestamps: bool,
    /// If `true`, set the global `PER_FILE_CRC` flag.  Entries may then
    /// supply `file_crc32` in [`EntryInput`].
    pub with_per_file_crc: bool,
    /// If `true`, set the global `DEDUPLICATION` flag.  Entries may then
    /// supply `content_hash` in [`EntryInput`].
    pub with_content_hash: bool,
    /// If `true`, set the global `HAS_SYMLINKS` flag.  Required when any
    /// entry has `kind = Some(EntryKind::Symlink)`.
    pub with_symlinks: bool,
    /// If `true`, set the global `HAS_DELTA` flag.  Required when any entry
    /// supplies [`EntryInput::delta`] with `VCDIFF` or `BSDIFF` options.
    /// Entries without a `delta` field emit `STORE_PATCH` with an all-zero
    /// base hash when this flag is active.
    pub with_delta: bool,
    /// LFH size-field encoding policy for `Uncompressed Size` and `Payload Size`.
    pub lfh_size_field_policy: LfhSizeFieldPolicy,
    /// Resource limits applied by the writer.  The KDF work-factor limits
    /// are checked before KMS key derivation; valid parameters above them
    /// return `SAR_ERR_LIMIT_EXCEEDED`.
    pub limits: ResourceLimits,
}

/// LFH size-field encoding policy used by the archive writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfhSizeFieldPolicy {
    /// Default behavior. Uses 32-bit LFH size fields unless a 64-bit field is
    /// required before the global header is emitted.
    Auto,
    /// Require 32-bit LFH size fields. Writing fails closed when any required
    /// size exceeds `u32::MAX`.
    Force32,
    /// Always emit 64-bit LFH size fields and set global `SIZE_64BIT`.
    Force64,
}

/// Archive writer compression settings.
#[derive(Debug, Clone, Copy)]
pub struct CompressionSettings {
    /// Compression algorithm ID.
    pub algo_id: u8,
    /// Optional compression level.
    pub level: Option<u8>,
}

impl CompressionSettings {
    /// STORE/default compression settings.
    #[must_use]
    pub const fn store() -> Self {
        Self {
            algo_id: COMP_ALGO_STORE,
            level: None,
        }
    }
}

impl Default for ArchiveWriterOptions {
    fn default() -> Self {
        Self {
            no_index: true,
            encryption: None,
            fec: None,
            archive_recovery: None,
            sparse: false,
            with_path: false,
            with_permissions: false,
            with_uid_gid: false,
            with_timestamps: false,
            with_per_file_crc: false,
            with_content_hash: false,
            with_symlinks: false,
            with_delta: false,
            lfh_size_field_policy: LfhSizeFieldPolicy::Auto,
            limits: ResourceLimits::default(),
        }
    }
}

/// Options for writing a sparse entry with [`ArchiveWriter::write_sparse_entry`].
///
/// The caller supplies:
/// * `logical_size` — full apparent file size including all sparse holes, stored as
///   the leading Sparse Logical Size of the Sparse Map.  Must be >= the end of
///   every declared extent.
/// * `extents` — ordered, non-overlapping sparse extents describing how
///   `gathered_payload` maps into the logical file.  The sum of all
///   `extent.length` values must equal the length of the `gathered_payload`
///   slice passed to [`ArchiveWriter::write_sparse_entry`].
///
/// The writer validates all constraints before emitting any bytes.
#[derive(Debug, Clone)]
pub struct SparseWriteOptions {
    /// Full logical file size, including all sparse holes.  This is encoded as
    /// the leading Sparse Logical Size of the Sparse Map (the LFH
    /// `Uncompressed Size` is the gathered-data length) and is **required** to
    /// be set explicitly.  The writer will not derive it from the extents.
    pub logical_size: u64,
    /// Ordered, non-overlapping sparse extents that describe the data regions.
    pub extents: Vec<SparseExtent>,
}

/// Reader-side limits.
///
/// Pass a [`ResourceLimits`] value to configure all resource caps uniformly.
/// The [`ArchiveReaderOptions::max_decoded_entry_size`] method provides
/// backward-compatible access to the corresponding limit value.
#[derive(Debug, Clone, Default)]
pub struct ArchiveReaderOptions {
    /// Unified resource limits for parsing and reconstruction.
    pub limits: ResourceLimits,
    /// Explicit base bytes for delta patch algorithms that require them
    /// (`BSDIFF`, `VCDIFF`).
    ///
    /// When `HAS_DELTA` is active and the patch algorithm requires a base
    /// object, the reader uses these bytes as the base.  If `None` and a
    /// base-requiring algorithm is encountered, the reader returns
    /// [`SarError::BaseMissing`].
    ///
    /// Automatic base discovery is **not** implemented.  The caller is
    /// responsible for locating the correct base object and supplying its
    /// bytes here before calling [`ArchiveReader::next_entry`].
    ///
    /// `STORE_PATCH` does not require base bytes and ignores this field.
    pub delta_base: Option<Vec<u8>>,
}

impl ArchiveReaderOptions {
    /// Returns the effective maximum decoded entry size from the embedded
    /// [`ResourceLimits`].
    #[must_use]
    pub fn max_decoded_entry_size(&self) -> u64 {
        self.limits.max_decoded_entry_size
    }
}

/// Final archive summary.
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveSummary {
    /// Total entries written.
    pub entry_count: u64,
    /// Total archive bytes.
    pub archive_size: u64,
    /// Indexed mode flag.
    pub indexed: bool,
}

/// Verification result.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    /// True when all validated invariants pass.
    pub valid: bool,
    /// Number of parsed entries.
    pub entry_count: u64,
    /// Indexed mode flag.
    pub indexed: bool,
    /// Number of CDC entries with a valid algorithm ID.
    pub cdc_entry_count: u64,
    /// True when CDC_SUPPORT is active in the global flags.
    pub cdc_support: bool,
}

/// Policy for handling entries that carry SESSION_CONTROL or nonzero OP_CODE bits.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ControlEntryPolicy {
    /// Reject inert control/opcode entries with `SAR_ERR_UNSUPPORTED`.
    #[default]
    Reject,
    /// Preserve and report inert control/opcode entries as audit records.
    PreserveInert,
}

/// Payload handling policy for archive auditing.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PayloadAuditPolicy {
    /// Parse structure and report payload metadata without decoding payload bytes.
    MetadataOnly,
    /// Decode ordinary archive-entry payloads when key/base providers are available.
    ///
    /// Missing key/base/provider conditions are reported as unavailable and do
    /// not fail the full audit.
    DecodeWhenKeysAvailable,
    /// Require ordinary archive-entry decode. Missing key/base/provider conditions fail.
    #[default]
    RequireDecode,
}

/// Archive audit options.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ArchiveAuditOptions {
    /// Policy for SESSION_CONTROL/nonzero OP_CODE entries.
    pub control_entry_policy: ControlEntryPolicy,
    /// Policy for ordinary archive-entry payload decoding during audit.
    pub payload_policy: PayloadAuditPolicy,
    /// When `true`, include raw payload bytes for inert entries.
    ///
    /// This is opt-in and intended for explicit audit export workflows.
    pub include_inert_payload_bytes: bool,
}

/// Archive mode observed by audit.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveAuditMode {
    /// Indexed archive with CD/Footer.
    Indexed,
    /// Forward-only archive with `NO_INDEX`.
    NoIndex,
}

/// Per-entry audit classification.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveAuditEntryKind {
    /// Ordinary archive entry (`SESSION_CONTROL=0`, `OP_CODE=0`).
    OrdinaryEntry,
    /// Inert nonzero-opcode entry (`SESSION_CONTROL=0`, `OP_CODE!=0`).
    InertOpcodeEntry,
    /// Inert session-control entry (`SESSION_CONTROL=1`).
    InertSessionControl,
}

/// Payload decode result for one audited entry.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveAuditPayloadStatus {
    /// Payload decoding succeeded.
    Decoded,
    /// Payload decoding was intentionally skipped by policy.
    Skipped,
    /// Payload decoding was unavailable (e.g., missing key/base provider).
    Unavailable,
    /// Payload decoding failed with a concrete error.
    Failed,
}

/// Per-entry archive audit report.
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAuditEntryReport {
    /// Absolute LFH offset.
    pub lfh_offset: u64,
    /// Raw `Entry_Mode` bits.
    pub entry_mode_bits: u16,
    /// Raw `OP_CODE` value.
    pub op_code: u8,
    /// Whether `SESSION_CONTROL` bit is set.
    pub session_control: bool,
    /// Entry semantic class in audit mode.
    pub kind: ArchiveAuditEntryKind,
    /// Encoded payload size from LFH.
    pub payload_size: u64,
    /// Logical/uncompressed size from LFH.
    pub uncompressed_size: u64,
    /// Compression algorithm ID when physically present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comp_algo_id: Option<u8>,
    /// Encryption algorithm ID when physically present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encr_algo_id: Option<u8>,
    /// FEC algorithm ID when physically present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec_algo_id: Option<u8>,
    /// Patch algorithm ID when physically present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_algo_id: Option<u8>,
    /// Payload audit status.
    pub payload_status: ArchiveAuditPayloadStatus,
    /// Decoded payload size when decode succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_payload_size: Option<u64>,
    /// Stable SAR status when payload decode is unavailable/failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_error_status: Option<String>,
    /// Human-readable payload decode error summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_error: Option<String>,
    /// Optional raw inert payload bytes when explicitly requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inert_payload_bytes: Option<Vec<u8>>,
}

/// Recovery TLV summary in archive audit reports.
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAuditRecoverySummary {
    /// Number of recovery TLVs (`0x10..=0x1F`) found in CD metadata.
    pub tlv_count: u32,
    /// Sorted type IDs of recovery TLVs found.
    pub tlv_type_ids: Vec<u8>,
}

/// Deterministic machine-readable archive audit report.
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveAuditReport {
    /// Archive indexing mode.
    pub mode: ArchiveAuditMode,
    /// Raw global flag bits from the Global Header.
    pub global_flags: u32,
    /// Number of entries observed in the Data Area.
    pub entry_count_seen: u64,
    /// Per-entry audit reports in stream order.
    pub entries: Vec<ArchiveAuditEntryReport>,
    /// Footer presence (indexed archives only).
    pub footer_present: bool,
    /// Central Dictionary presence.
    pub central_dictionary_present: bool,
    /// For indexed archives, indicates that the Central Dictionary and Footer
    /// were present and structurally parseable during audit. For `NO_INDEX`
    /// archives this is always `true`. This is not a separate cryptographic
    /// or full semantic validity claim.
    pub cd_footer_valid: bool,
    /// Recovery TLV presence/summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<ArchiveAuditRecoverySummary>,
}

/// Streaming archive reader over a seekable source.
pub struct ArchiveReader<R> {
    reader: R,
    options: ArchiveReaderOptions,
    global_header: Option<GlobalHeader>,
    /// Raw encoded Global Header bytes `[0, first LFH)`, retained for AEAD AAD.
    global_header_bytes: Vec<u8>,
    header_len: u64,
    data_end: u64,
    next_offset: u64,
    file_len: u64,
    cd: Option<CentralDictionary>,
    key_provider: Option<Box<dyn KeyProvider>>,
    /// KMS Master Secret for this physical archive; the KDF runs once.
    master_secret: Mutex<MasterSecretScope>,
    logical: LogicalState,
    /// Explicitly configured external CDC chunk resolver (never implicit).
    cdc_external: Option<crate::cdc_resolve::ExternalCdc>,
    /// Lazily selected local `CDC_MAP` catalog; `Some(None)` = none present.
    cdc_catalog: Option<Option<crate::cdc_resolve::LocalCatalog>>,
}

/// Progress of [`ArchiveReader::next_logical_entry`].
enum LogicalState {
    NotStarted,
    Active(Box<crate::fragment_group::FragmentGroupCollector>),
    Done,
}

/// True for an Empty Area LFH (empty name, not a fragment).
///
/// A Partition Manifest Entry is never an Empty Area (spec §6.2.1).
fn is_empty_area(lfh: &LocalFileHeader) -> bool {
    !lfh.entry_mode.is_partition_manifest()
        && sar_core::metadata::EntryKind::from_mode_and_name(lfh.entry_mode, lfh.name.is_empty())
            == sar_core::metadata::EntryKind::EmptyArea
}

/// Checks the CD offset array against the physical LFH walk
/// (`(offset, indexed)` in physical order); spec §7.1.
///
/// Offsets that are not LFH boundaries, or that name an Empty Area, are
/// `Malformed`; an Entry Count that differs from the number of indexed LFHs
/// (a missing or surplus offset) is `InvalidLength`.  Out-of-bounds offsets
/// are rejected earlier by `CentralDictionary::validate_offset_layout`.
fn check_cd_index_against_lfhs(
    cd: &CentralDictionary,
    physical: &[(u64, bool)],
) -> Result<(), SarError> {
    for offset in &cd.offsets {
        match physical.binary_search_by_key(offset, |(o, _)| *o) {
            Err(_) => {
                return Err(SarError::Malformed(
                    "CD offset does not identify an LFH boundary",
                ));
            }
            Ok(idx) if !physical[idx].1 => {
                return Err(SarError::Malformed(
                    "CD offset refers to an Empty Area, which must not be indexed",
                ));
            }
            Ok(_) => {}
        }
    }
    let indexed = physical.iter().filter(|(_, indexed)| *indexed).count();
    if cd.file_count != u64::try_from(indexed).map_err(|_| SarError::Overflow("entry count"))? {
        return Err(SarError::InvalidLength(
            "CD Entry Count does not match indexed LFH count",
        ));
    }
    Ok(())
}

/// Fills a required structural buffer, mapping a short read to `Truncated`.
///
/// Only `UnexpectedEof` is a truncation; every other I/O failure stays `Io`.
fn read_required<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    what: &'static str,
) -> Result<(), SarError> {
    reader.read_exact(buf).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            SarError::Truncated(what)
        } else {
            SarError::Io(err)
        }
    })
}

impl<R: Read + Seek> ArchiveReader<R> {
    /// Creates a new archive reader.
    pub fn new(reader: R) -> Result<Self, SarError> {
        Self::with_options(reader, ArchiveReaderOptions::default())
    }

    /// Creates a new archive reader with configurable limits.
    pub fn with_options(mut reader: R, options: ArchiveReaderOptions) -> Result<Self, SarError> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        options.limits.check_archive_size(file_len)?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            options,
            global_header: None,
            global_header_bytes: Vec::new(),
            header_len: 0,
            data_end: 0,
            next_offset: 0,
            file_len,
            cd: None,
            key_provider: None,
            master_secret: Mutex::new(MasterSecretScope::new()),
            logical: LogicalState::NotStarted,
            cdc_external: None,
            cdc_catalog: None,
        })
    }

    /// Explicitly configures external CDC chunk resolution.
    ///
    /// `hash_algorithm_id` is the registered SAR hash algorithm (SHA-256
    /// `0x30` or BLAKE3-256 `0x31`) of the Recipes the resolver serves; it is
    /// never inferred from hash bytes.  When configured, the resolver is the
    /// selected catalog for logical reconstruction and the local `CDC_MAP`
    /// is not consulted for chunks; a local `CDC_MAP` declaring a different
    /// algorithm is `SAR_ERR_METADATA_CONFLICT`.  The resolver is invoked only
    /// by [`Self::next_logical_entry`] and [`Self::read_all_logical_files`],
    /// never by parsing, listing, [`Self::next_entry`] or [`Self::verify`].
    /// `CDC_EXT_PROVIDER` URIs are never dereferenced.
    ///
    /// # Errors
    ///
    /// [`SarError::Unsupported`] / [`SarError::ReservedValue`] when the
    /// algorithm is not a supported registered hash.
    pub fn with_cdc_resolver(
        mut self,
        hash_algorithm_id: u8,
        resolver: Box<dyn crate::cdc_resolve::CdcChunkResolver>,
    ) -> Result<Self, SarError> {
        sar_core::compute_cdc_chunk_hash(hash_algorithm_id, &[])?;
        self.cdc_external = Some(crate::cdc_resolve::ExternalCdc {
            algo_id: hash_algorithm_id,
            resolver,
        });
        Ok(self)
    }

    /// Selects the local catalog (once) and checks it against any configured
    /// external resolver.
    fn prepare_cdc_catalog(&mut self) -> Result<(), SarError> {
        if self.cdc_catalog.is_none() {
            let catalog = match &self.cd {
                Some(cd) => {
                    crate::cdc_resolve::LocalCatalog::select(&cd.metadata, &self.options.limits)?
                }
                None => None,
            };
            self.cdc_catalog = Some(catalog);
        }
        if let (Some(ext), Some(Some(local))) = (&self.cdc_external, &self.cdc_catalog)
            && ext.algo_id != local.algo_id
        {
            return Err(SarError::MetadataConflict(
                "configured CDC resolver algorithm differs from the CDC_MAP Hash_Algorithm_ID",
            ));
        }
        Ok(())
    }

    /// Completes the CDC stage of one logical item (Section 13.1 step 6).
    fn resolve_cdc_item(
        &mut self,
        item: crate::fragment_group::CollectedEntry,
        held_elsewhere: u64,
    ) -> Result<crate::fragment_group::CollectedEntry, SarError> {
        use crate::cdc_resolve::{ChunkSource, resolve_recipe};
        use crate::fragment_group::CollectedEntry;
        let is_recipe = |id: Option<u8>| id.is_some_and(|i| i != sar_core::cdc::CDC_ALGO_LITERAL);
        match item {
            CollectedEntry::Entry(mut entry) if is_recipe(entry.metadata.cdc_algo_id) => {
                self.prepare_cdc_catalog()?;
                let source = match (&self.cdc_external, &self.cdc_catalog) {
                    (Some(ext), _) => ChunkSource::External(ext),
                    (None, Some(Some(catalog))) => ChunkSource::Local {
                        reader: &mut self.reader,
                        catalog,
                        header_len: self.header_len,
                        data_end: self.data_end,
                    },
                    _ => ChunkSource::Unavailable,
                };
                let resolved =
                    resolve_recipe(source, &self.options.limits, &entry.payload, held_elsewhere)?;
                if let Some(sparse) = &entry.metadata.sparse {
                    let extent_total = validate_sparse_extents(
                        &sparse.extents,
                        sparse.logical_size,
                        &self.options.limits.sparse_limits(),
                    )?;
                    check_gathered_length(
                        u64::try_from(resolved.len())
                            .map_err(|_| SarError::Overflow("gathered length"))?,
                        extent_total,
                    )?;
                }
                entry.payload = resolved;
                Ok(CollectedEntry::Entry(entry))
            }
            CollectedEntry::Group(mut group) if group.needs_cdc() => {
                self.prepare_cdc_catalog()?;
                let source = match (&self.cdc_external, &self.cdc_catalog) {
                    (Some(ext), _) => ChunkSource::External(ext),
                    (None, Some(Some(catalog))) => ChunkSource::Local {
                        reader: &mut self.reader,
                        catalog,
                        header_len: self.header_len,
                        data_end: self.data_end,
                    },
                    _ => ChunkSource::Unavailable,
                };
                let limits = self.options.limits;
                group.resolve_recipe(&self.options, |recipe| {
                    resolve_recipe(source, &limits, recipe, held_elsewhere)
                })?;
                Ok(CollectedEntry::Group(group))
            }
            other => Ok(other),
        }
    }

    /// Attach a key provider used for encrypted entry decoding.
    #[must_use]
    pub fn with_key_provider(mut self, key_provider: Box<dyn KeyProvider>) -> Self {
        self.key_provider = Some(key_provider);
        self.master_secret = Mutex::new(MasterSecretScope::new());
        self
    }

    /// Parses and returns the global header.
    pub fn read_global_header(&mut self) -> Result<GlobalHeader, SarError> {
        self.read_global_header_inner(false)
    }

    /// Shared Global Header / Footer / Central Dictionary parse.
    ///
    /// `allow_partitioned` is set only by the explicit Partition inspection
    /// entry point; every generic path keeps the fail-closed gate.
    fn read_global_header_inner(
        &mut self,
        allow_partitioned: bool,
    ) -> Result<GlobalHeader, SarError> {
        self.reader.seek(SeekFrom::Start(0))?;

        let mut fixed = [0u8; GLOBAL_HEADER_FIXED_LEN];
        read_required(&mut self.reader, &mut fixed[..8], "global header prefix")?;
        validate_global_header_prefix(&fixed[..8])?;
        read_required(&mut self.reader, &mut fixed[8..], "global flags")?;
        let mut flags_bytes = [0u8; 4];
        flags_bytes.copy_from_slice(&fixed[8..]);
        let flags = decode_global_flags(flags_bytes)?;

        let mut header_bytes = Vec::with_capacity(GLOBAL_HEADER_FIXED_LEN + 5);
        header_bytes.extend_from_slice(&fixed);

        if flags.contains(GlobalFlags::ENCRYPTED) {
            let mut kms_prefix = [0u8; 5];
            read_required(&mut self.reader, &mut kms_prefix, "KMS prefix")?;
            header_bytes.extend_from_slice(&kms_prefix);
            let payload_len = usize::try_from(u32::from_le_bytes([
                kms_prefix[1],
                kms_prefix[2],
                kms_prefix[3],
                kms_prefix[4],
            ]))
            .map_err(|_| SarError::Overflow("KMS payload length"))?;
            self.options.limits.check_kms_payload_bytes(payload_len)?;
            let mut payload = vec![0u8; payload_len];
            read_required(&mut self.reader, &mut payload, "KMS payload")?;
            header_bytes.extend_from_slice(&payload);
        }

        let (header, consumed) = parse_global_header(&header_bytes, &self.options.limits)?;
        // A (re)read header starts a new KMS scope.
        self.master_secret = Mutex::new(MasterSecretScope::new());
        if let Some(kms) = &header.kms {
            // Mode 0x04 TLS_EXPORTER payloads are validated structurally here with
            // the canonical parser; exporter acquisition remains a transport concern.
            if kms.mode_id == KMS_TLS_EXPORTER {
                parse_tls_exporter_kms_payload(&kms.payload).map_err(SarError::from)?;
            } else {
                let _ = parse_kms_payload(kms.mode_id, &kms.payload).map_err(SarError::from)?;
            }
        }
        if !allow_partitioned {
            require_unpartitioned_processing(header.flags)?;
        }
        let header_len = u64::try_from(consumed).map_err(|_| SarError::Overflow("header len"))?;

        let (data_end, cd) = if header.flags.contains(GlobalFlags::NO_INDEX) {
            (self.file_len, None)
        } else {
            if self.file_len < 8 {
                return Err(SarError::Truncated("indexed archive missing footer"));
            }
            self.reader.seek(SeekFrom::Start(self.file_len - 8))?;
            let mut footer_bytes = [0u8; 8];
            read_required(&mut self.reader, &mut footer_bytes, "footer")?;
            let Footer { cd_offset } = parse_footer(&footer_bytes)?;

            let indexed_end = self
                .file_len
                .checked_sub(8)
                .ok_or(SarError::Truncated("indexed archive missing footer"))?;
            if cd_offset >= indexed_end {
                return Err(SarError::Bounds("CD offset points outside indexed range"));
            }
            if cd_offset < header_len {
                return Err(SarError::Bounds("CD offset overlaps data/header"));
            }

            let cd_region_len = self
                .file_len
                .checked_sub(8)
                .and_then(|value| value.checked_sub(cd_offset))
                .ok_or(SarError::Overflow("CD region length"))?;
            self.options.limits.check_cd_bytes(cd_region_len)?;
            self.options.limits.check_allocation_bytes(cd_region_len)?;
            let cd_len_usize = self
                .options
                .limits
                .allocation_len(cd_region_len, "CD region length usize")?;

            self.reader.seek(SeekFrom::Start(cd_offset))?;
            let mut cd_bytes = vec![0u8; cd_len_usize];
            read_required(&mut self.reader, &mut cd_bytes, "central dictionary")?;
            let (cd, consumed_cd) = if allow_partitioned {
                parse_partition_central_dictionary(&cd_bytes, header.flags, &self.options.limits)?
            } else {
                parse_central_dictionary(&cd_bytes, header.flags, &self.options.limits)?
            };
            if consumed_cd > cd_bytes.len() {
                return Err(SarError::Truncated("CD parse exceeded available bytes"));
            }
            if cd_bytes[consumed_cd..].iter().any(|byte| *byte != 0) {
                return Err(SarError::Malformed("CD alignment padding must be all zero"));
            }

            // Structural offset checks only; LFH-boundary membership needs a
            // Data Area walk and is performed by verify()/audit().
            cd.validate_offset_layout(header_len, cd_offset, self.file_len)?;

            let has_recovery_tlv = cd
                .metadata
                .iter()
                .any(|tlv| (0x10..=0x1F).contains(&tlv.type_id));
            if has_recovery_tlv && !header.flags.contains(GlobalFlags::HAS_GLOBAL_EC) {
                return Err(SarError::FlagConflict(
                    "RECOVERY TLV metadata requires HAS_GLOBAL_EC global flag",
                ));
            }
            if header.flags.contains(GlobalFlags::HAS_GLOBAL_EC) {
                for tlv in &cd.metadata {
                    if (0x10..=0x1F).contains(&tlv.type_id) {
                        sar_core::fec::validate_recovery_tlv(
                            tlv.type_id,
                            &tlv.value,
                            &self.options.limits,
                        )?;
                    }
                }
            }
            (cd_offset, Some(cd))
        };

        self.global_header_bytes = header_bytes
            .get(..consumed)
            .ok_or(SarError::Internal(
                "global header length exceeds read bytes",
            ))?
            .to_vec();
        self.global_header = Some(header.clone());
        self.header_len = header_len;
        self.data_end = data_end;
        self.next_offset = header_len;
        self.cd = cd;

        Ok(header)
    }

    /// Reads the next physical archive entry sequentially.
    ///
    /// This decodes one physical Entry (including AEAD authentication of an
    /// encrypted Entry).  It does not reassemble fragment groups and does not
    /// verify the LFH Content Hash, which covers the final logical Entry; use
    /// [`Self::read_all_logical_files`] for that verification.  For a
    /// non-literal CDC Entry the returned payload is the serialized Recipe,
    /// not file content: no chunk is read and no resolver is called.
    /// [`Self::next_logical_entry`] resolves Recipes.
    pub fn next_entry(&mut self) -> Result<Option<EntryReader>, SarError> {
        let header = self
            .global_header
            .as_ref()
            .ok_or(SarError::Malformed("call read_global_header first"))?
            .clone();

        if self.next_offset >= self.data_end {
            return Ok(None);
        }

        self.reader.seek(SeekFrom::Start(self.next_offset))?;
        let mut header_size_bytes = [0u8; 4];
        read_required(&mut self.reader, &mut header_size_bytes, "LFH header size")?;
        let header_size = usize::try_from(u32::from_le_bytes(header_size_bytes))
            .map_err(|_| SarError::Overflow("LFH header size"))?;
        self.options.limits.check_lfh_header_bytes(header_size)?;
        if header_size < 4 {
            return Err(SarError::InvalidLength(
                "LFH Header Size smaller than fixed prefix",
            ));
        }

        let mut lfh_bytes = vec![0u8; header_size];
        lfh_bytes[..4].copy_from_slice(&header_size_bytes);
        if header_size > 4 {
            read_required(&mut self.reader, &mut lfh_bytes[4..], "LFH")?;
        }

        let (lfh, _) = parse_lfh(&lfh_bytes, &header.flags, &self.options.limits)?;
        if lfh.entry_mode.is_session_control() || lfh.entry_mode.op_code() != 0 {
            return Err(SarError::Unsupported(
                "archive parsing rejects SESSION_CONTROL entries and nonzero OP_CODE values by default",
            ));
        }
        let payload_start = self
            .next_offset
            .checked_add(u64::from(lfh.header_size))
            .ok_or(SarError::Overflow("payload start"))?;
        let payload_end = payload_start
            .checked_add(lfh.payload_size)
            .ok_or(SarError::Overflow("payload end"))?;
        if payload_end > self.data_end {
            return Err(SarError::Truncated("payload exceeds data area bounds"));
        }

        self.reader.seek(SeekFrom::Start(payload_start))?;
        let payload_len = self
            .options
            .limits
            .allocation_len(lfh.payload_size, "payload length usize")?;
        let mut encoded_payload = vec![0u8; payload_len];
        read_required(&mut self.reader, &mut encoded_payload, "entry payload")?;
        let decoded = self.decode_ordinary_archive_entry_from_parts(
            &header,
            self.next_offset,
            &lfh,
            &lfh_bytes,
            &encoded_payload,
        )?;

        self.next_offset = payload_end;

        Ok(Some(EntryReader {
            header: lfh,
            payload: decoded.payload,
            metadata: decoded.metadata,
        }))
    }

    /// Recomputes the Data Area CRC32 (spec §7.2) over the exact encoded bytes
    /// `[first LFH, CD)` and compares it with the Central Dictionary value.
    ///
    /// No-op when `HAS_DATA_AREA_CRC32` is unset.  The range is streamed
    /// through a fixed buffer; payloads are never decoded.
    fn verify_data_area_crc32(&mut self) -> Result<(), SarError> {
        let Some(expected) = self.cd.as_ref().and_then(|cd| cd.global_crc32) else {
            return Ok(());
        };
        let mut remaining = self
            .data_end
            .checked_sub(self.header_len)
            .ok_or(SarError::Bounds("Data Area end precedes first LFH"))?;
        self.reader.seek(SeekFrom::Start(self.header_len))?;
        let mut hasher = crc32fast::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let chunk = usize::try_from(remaining.min(64 * 1024))
                .map_err(|_| SarError::Overflow("CRC chunk length"))?;
            read_required(&mut self.reader, &mut buf[..chunk], "Data Area")?;
            hasher.update(&buf[..chunk]);
            remaining -= u64::try_from(chunk).map_err(|_| SarError::Overflow("CRC chunk"))?;
        }
        if hasher.finalize() != expected {
            return Err(SarError::CrcMismatch("Data Area CRC32 mismatch"));
        }
        Ok(())
    }

    /// Verifies archive structure and index consistency.
    ///
    /// When `HAS_DATA_AREA_CRC32` is set, the Data Area CRC32 is verified over
    /// the encoded bytes first (`SAR_ERR_CRC_MISMATCH`).  The CD offset array
    /// is then checked against the physical LFH walk: Empty Areas must be
    /// absent, every other LFH present, offsets strictly ascending.
    /// [`Self::next_entry`] and [`Self::read_all_logical_files`] do not verify
    /// the Data Area CRC32.
    ///
    /// Physical Entries are decoded through [`Self::next_entry`], so this does
    /// not verify the final logical Content Hash or reconstruct fragment
    /// groups; those require [`Self::read_all_logical_files`].
    pub fn verify(&mut self) -> Result<VerificationReport, SarError> {
        if self.global_header.is_none() {
            let _ = self.read_global_header()?;
        }

        let global = self
            .global_header
            .as_ref()
            .ok_or(SarError::Malformed("global header missing"))?
            .clone();

        // Raw-byte integrity first: a corrupted Data Area must surface as
        // SAR_ERR_CRC_MISMATCH rather than as a downstream decode error.
        self.verify_data_area_crc32()?;

        self.next_offset = self.header_len;
        let mut physical: Vec<(u64, bool)> = Vec::new();
        let mut cdc_entry_count: u64 = 0;
        while let Some(entry) = self.next_entry()? {
            physical.push((entry.metadata.lfh_offset, !is_empty_area(&entry.header)));
            if entry.metadata.cdc_algo_id.is_some() {
                cdc_entry_count = cdc_entry_count
                    .checked_add(1)
                    .ok_or(SarError::Overflow("CDC entry count"))?;
            }
        }

        let cdc_support = global.flags.contains(GlobalFlags::CDC_SUPPORT);

        if let Some(cd) = &self.cd {
            let has_cdc_metadata = cd
                .metadata
                .iter()
                .any(|tlv| sar_core::cdc::is_cdc_metadata_tlv_type(tlv.type_id));
            if has_cdc_metadata && !cdc_support {
                return Err(SarError::FlagConflict(
                    "CDC metadata requires the CDC_SUPPORT global flag",
                ));
            }

            check_cd_index_against_lfhs(cd, &physical)?;

            if global.flags.contains(GlobalFlags::SIGNED) {
                let has_data_hash = cd
                    .metadata
                    .iter()
                    .any(|tlv| (0x30..=0x3F).contains(&tlv.type_id));
                if !has_data_hash {
                    return Err(SarError::FlagConflict(
                        "SIGNED requires DATA_HASH TLV in metadata",
                    ));
                }
            }

            // Validate any RECOVERY TLVs present in CD metadata.
            if global.flags.contains(GlobalFlags::HAS_GLOBAL_EC) {
                for tlv in &cd.metadata {
                    if (0x10..=0x1F).contains(&tlv.type_id) {
                        sar_core::fec::validate_recovery_tlv(
                            tlv.type_id,
                            &tlv.value,
                            &self.options.limits,
                        )?;
                    }
                }
            }

            // Validate any CDC_MAP TLVs present in CD metadata when
            // CDC_SUPPORT is active.
            if cdc_support {
                for tlv in &cd.metadata {
                    if sar_core::cdc::is_cdc_metadata_tlv_type(tlv.type_id) {
                        sar_core::cdc::validate_cdc_metadata_tlv(tlv, &self.options.limits)?;
                    }
                }
                // Catalog selection must be unambiguous and unpartitioned;
                // chunk bytes are not read or resolved here.
                if let Some(map) =
                    sar_core::cdc::parse_entry_cdc_map(&cd.metadata, &self.options.limits)?
                {
                    crate::cdc_resolve::check_unpartitioned(&map)?;
                }
            }
        }

        Ok(VerificationReport {
            valid: true,
            entry_count: u64::try_from(physical.len())
                .map_err(|_| SarError::Overflow("entry count"))?,
            indexed: self.cd.is_some(),
            cdc_entry_count,
            cdc_support,
        })
    }

    /// Audits archive structure and payload availability with explicit policies.
    ///
    /// Defaults are safe:
    /// - `ControlEntryPolicy::Reject`
    /// - `PayloadAuditPolicy::RequireDecode`
    pub fn audit(&mut self, options: ArchiveAuditOptions) -> Result<ArchiveAuditReport, SarError> {
        if self.global_header.is_none() {
            let _ = self.read_global_header()?;
        }

        let header = self
            .global_header
            .as_ref()
            .ok_or(SarError::Malformed("global header missing"))?
            .clone();
        self.verify_data_area_crc32()?;
        self.next_offset = self.header_len;

        let mut entries = Vec::new();
        let mut physical: Vec<(u64, bool)> = Vec::new();
        while self.next_offset < self.data_end {
            let lfh_offset = self.next_offset;
            self.reader.seek(SeekFrom::Start(lfh_offset))?;

            let mut header_size_bytes = [0u8; 4];
            read_required(&mut self.reader, &mut header_size_bytes, "LFH header size")?;
            let header_size = usize::try_from(u32::from_le_bytes(header_size_bytes))
                .map_err(|_| SarError::Overflow("LFH header size"))?;
            self.options.limits.check_lfh_header_bytes(header_size)?;
            if header_size < 4 {
                return Err(SarError::InvalidLength(
                    "LFH Header Size smaller than fixed prefix",
                ));
            }

            let mut lfh_bytes = vec![0u8; header_size];
            lfh_bytes[..4].copy_from_slice(&header_size_bytes);
            if header_size > 4 {
                read_required(&mut self.reader, &mut lfh_bytes[4..], "LFH")?;
            }
            let (lfh, _) = parse_lfh(&lfh_bytes, &header.flags, &self.options.limits)?;
            physical.push((lfh_offset, !is_empty_area(&lfh)));

            let session_control = lfh.entry_mode.is_session_control();
            let op_code = lfh.entry_mode.op_code();
            let kind = if session_control {
                ArchiveAuditEntryKind::InertSessionControl
            } else if op_code != 0 {
                ArchiveAuditEntryKind::InertOpcodeEntry
            } else {
                ArchiveAuditEntryKind::OrdinaryEntry
            };
            if !matches!(kind, ArchiveAuditEntryKind::OrdinaryEntry)
                && options.control_entry_policy == ControlEntryPolicy::Reject
            {
                return Err(SarError::Unsupported(
                    "archive parsing rejects SESSION_CONTROL entries and nonzero OP_CODE values by default",
                ));
            }

            let payload_start = self
                .next_offset
                .checked_add(u64::from(lfh.header_size))
                .ok_or(SarError::Overflow("payload start"))?;
            let payload_end = payload_start
                .checked_add(lfh.payload_size)
                .ok_or(SarError::Overflow("payload end"))?;
            if payload_end > self.data_end {
                return Err(SarError::Truncated("payload exceeds data area bounds"));
            }

            let mut decoded_payload_size = None;
            let mut payload_error_status = None;
            let mut payload_error = None;
            let mut inert_payload_bytes = None;
            let payload_status;

            match kind {
                ArchiveAuditEntryKind::OrdinaryEntry => match options.payload_policy {
                    PayloadAuditPolicy::MetadataOnly => {
                        payload_status = ArchiveAuditPayloadStatus::Skipped;
                    }
                    PayloadAuditPolicy::DecodeWhenKeysAvailable
                    | PayloadAuditPolicy::RequireDecode => {
                        self.reader.seek(SeekFrom::Start(payload_start))?;
                        let payload_len = self
                            .options
                            .limits
                            .allocation_len(lfh.payload_size, "payload length usize")?;
                        let mut encoded_payload = vec![0u8; payload_len];
                        read_required(&mut self.reader, &mut encoded_payload, "entry payload")?;

                        match self.decode_ordinary_archive_entry_from_parts(
                            &header,
                            lfh_offset,
                            &lfh,
                            &lfh_bytes,
                            &encoded_payload,
                        ) {
                            Ok(decoded) => {
                                payload_status = ArchiveAuditPayloadStatus::Decoded;
                                decoded_payload_size = Some(
                                    u64::try_from(decoded.payload.len())
                                        .map_err(|_| SarError::Overflow("decoded payload size"))?,
                                );
                            }
                            Err(err) => {
                                let is_unavailable = matches!(
                                    err,
                                    SarError::KeyMissing(_) | SarError::BaseMissing(_)
                                );
                                payload_error_status = Some(err.status().name().to_string());
                                payload_error = Some(err.to_string());

                                if options.payload_policy == PayloadAuditPolicy::RequireDecode {
                                    return Err(err);
                                }
                                // Only missing key/base/provider conditions degrade to
                                // Unavailable in best-effort audit mode. All concrete
                                // decode, authentication, metadata, and structural errors
                                // remain Failed per the audit policy.
                                payload_status = if is_unavailable {
                                    ArchiveAuditPayloadStatus::Unavailable
                                } else {
                                    ArchiveAuditPayloadStatus::Failed
                                };
                            }
                        }
                    }
                },
                ArchiveAuditEntryKind::InertOpcodeEntry
                | ArchiveAuditEntryKind::InertSessionControl => {
                    payload_status = ArchiveAuditPayloadStatus::Skipped;
                    if options.include_inert_payload_bytes {
                        self.reader.seek(SeekFrom::Start(payload_start))?;
                        let payload_len = self
                            .options
                            .limits
                            .allocation_len(lfh.payload_size, "payload length usize")?;
                        let mut raw_payload = vec![0u8; payload_len];
                        read_required(&mut self.reader, &mut raw_payload, "entry payload")?;
                        inert_payload_bytes = Some(raw_payload);
                    }
                }
            }

            entries.push(ArchiveAuditEntryReport {
                lfh_offset,
                entry_mode_bits: lfh.entry_mode.bits(),
                op_code,
                session_control,
                kind,
                payload_size: lfh.payload_size,
                uncompressed_size: lfh.uncompressed_size,
                comp_algo_id: lfh.comp_algo_id,
                encr_algo_id: lfh.encr_algo_id,
                fec_algo_id: lfh.fec_algo_id,
                patch_algo_id: lfh.patch_algo_id,
                payload_status,
                decoded_payload_size,
                payload_error_status,
                payload_error,
                inert_payload_bytes,
            });

            self.next_offset = payload_end;
        }

        if let Some(cd) = &self.cd {
            check_cd_index_against_lfhs(cd, &physical)?;
        }

        let mut recovery_type_ids: Vec<u8> = self
            .cd
            .as_ref()
            .into_iter()
            .flat_map(|cd| cd.metadata.iter())
            .filter_map(|tlv| (0x10..=0x1F).contains(&tlv.type_id).then_some(tlv.type_id))
            .collect();
        recovery_type_ids.sort_unstable();
        recovery_type_ids.dedup();
        let recovery = if recovery_type_ids.is_empty() {
            None
        } else {
            Some(ArchiveAuditRecoverySummary {
                tlv_count: u32::try_from(recovery_type_ids.len())
                    .map_err(|_| SarError::Overflow("recovery tlv count"))?,
                tlv_type_ids: recovery_type_ids,
            })
        };

        Ok(ArchiveAuditReport {
            mode: if header.flags.contains(GlobalFlags::NO_INDEX) {
                ArchiveAuditMode::NoIndex
            } else {
                ArchiveAuditMode::Indexed
            },
            global_flags: header.flags.bits(),
            entry_count_seen: u64::try_from(entries.len())
                .map_err(|_| SarError::Overflow("entry count"))?,
            entries,
            footer_present: !header.flags.contains(GlobalFlags::NO_INDEX),
            central_dictionary_present: self.cd.is_some(),
            cd_footer_valid: header.flags.contains(GlobalFlags::NO_INDEX) || self.cd.is_some(),
            recovery,
        })
    }

    /// Returns parsed archive metadata when header has been read.
    pub fn metadata(&self) -> Option<ArchiveMetadata> {
        self.global_header
            .as_ref()
            .map(|global_header| ArchiveMetadata {
                global_header: global_header.clone(),
                central_dictionary: self.cd.clone(),
            })
    }

    /// Decodes and validates one ordinary archive entry using normal archive rules.
    fn decode_ordinary_archive_entry_from_parts(
        &self,
        header: &GlobalHeader,
        lfh_offset: u64,
        lfh: &LocalFileHeader,
        lfh_bytes: &[u8],
        encoded_payload: &[u8],
    ) -> Result<DecodedArchiveEntryParts, SarError> {
        crate::fragment_group::check_later_fragment_sparse_map(lfh)?;
        let is_effectively_compressed =
            header.flags.contains(GlobalFlags::COMPRESSED) && lfh.entry_mode.is_compressed();
        let is_encrypted = lfh.entry_mode.is_encrypted();
        if is_encrypted && !header.flags.contains(GlobalFlags::ENCRYPTED) {
            return Err(SarError::FlagConflict(
                "IS_ENCRYPTED requires global ENCRYPTED",
            ));
        }
        let is_sparse =
            header.flags.contains(GlobalFlags::SPARSE_FILES) && !lfh.sparse_map.is_empty();
        let is_has_delta = header.flags.contains(GlobalFlags::HAS_DELTA);
        let patch_raw_id = lfh.patch_algo_id.unwrap_or(0);

        // LFH `Uncompressed Size` is the fragment-local transform-boundary
        // length: the decoded contribution of a fragment, or the decoded patch
        // representation of an unfragmented delta Entry.  It is never the
        // patch output length or the Sparse Logical Size (spec Sections 6.1.2
        // and 8.4).
        let decode_expected = lfh.uncompressed_size;

        let effective_comp_algo_id = if is_effectively_compressed {
            lfh.comp_algo_id.unwrap_or(COMP_ALGO_STORE)
        } else {
            COMP_ALGO_STORE
        };

        let crypto = if is_encrypted {
            let algo_id = lfh.encr_algo_id.ok_or(SarError::Malformed(
                "encrypted entry missing encryption algorithm ID",
            ))?;
            validate_entry_encr_algo_id(algo_id).map_err(SarError::from)?;
            let provider = self.key_provider.as_deref().ok_or(SarError::KeyMissing(
                "no key provider configured for encrypted archive",
            ))?;
            let context = build_kms_context(header)?;
            let iv_nonce = lfh.iv_nonce.ok_or(SarError::Malformed(
                "encrypted entry missing IV/nonce field",
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
            let fec_algo_id = lfh.fec_algo_id.unwrap_or(0);
            let aad_lfh_bytes =
                lfh_bytes_for_aad(header.flags, lfh_bytes, fec_algo_id, lfh.fec_value.len())?;
            let aad = build_aead_aad(&self.global_header_bytes, &aad_lfh_bytes);
            Some(EntryCryptoContext {
                algo_id,
                iv_nonce,
                aad,
                key,
            })
        } else {
            None
        };

        let decoded = decode_payload_v2(
            encoded_payload,
            DecodingPlanV2 {
                is_compressed: is_effectively_compressed,
                comp_algo_id: effective_comp_algo_id,
                expected_output_size: decode_expected,
                max_output_size: self.options.max_decoded_entry_size(),
                crypto,
            },
        )?;

        if u64::try_from(decoded.len()).map_err(|_| SarError::Overflow("decoded payload len"))?
            != lfh.uncompressed_size
        {
            return Err(SarError::InvalidLength(
                "decoded payload size does not match LFH Uncompressed Size",
            ));
        }
        if !is_effectively_compressed && !is_encrypted && lfh.payload_size != lfh.uncompressed_size
        {
            return Err(SarError::InvalidLength(
                "STORE mode requires Payload Size == Uncompressed Size",
            ));
        }

        // The patch is a group-wide stage.  An unfragmented Entry's single
        // contribution is the complete patch representation; a fragment's
        // contribution is patched once, after reassembly, by the group stage.
        let decoded = if is_has_delta && !lfh.entry_mode.is_fragment() {
            apply_patch_stage(
                &self.options,
                patch_raw_id,
                lfh.delta_base_hash.unwrap_or(ZERO_DELTA_BASE_HASH),
                decoded,
            )?
        } else {
            decoded
        };

        let fec = if header.flags.contains(GlobalFlags::SELECTIVE_FEC) {
            let algo_id = lfh.fec_algo_id.unwrap_or(0);
            sar_core::fec::parse_lfh_fec_value(algo_id, &lfh.fec_value, &self.options.limits)?
        } else {
            None
        };

        let cdc_algo_id_opt: Option<u8> = if header.flags.contains(GlobalFlags::CDC_SUPPORT) {
            let algo_id = lfh.cdc_algo_id.unwrap_or(0);
            sar_core::cdc::validate_cdc_algo_id(algo_id)?;
            Some(algo_id)
        } else {
            None
        };
        let sparse_map: Option<SparseMap> = if is_sparse {
            let is_64bit = header.flags.contains(GlobalFlags::SIZE_64BIT);
            let map = sar_core::sparse::parse_sparse_map(
                &lfh.sparse_map,
                is_64bit,
                &self.options.limits,
            )?;
            let extent_total = validate_sparse_extents(
                &map.extents,
                map.logical_size,
                &self.options.limits.sparse_limits(),
            )?;
            // An unfragmented sparse Entry's decoded payload is the complete
            // gathered data; a fragment is only a contribution, checked when the
            // group is assembled.
            // A Recipe's payload is not the gathered data; the length is
            // checked after CDC resolution.
            let is_recipe = cdc_algo_id_opt.is_some_and(|id| id != sar_core::cdc::CDC_ALGO_LITERAL);
            if !lfh.entry_mode.is_fragment() && !is_recipe {
                check_gathered_length(
                    u64::try_from(decoded.len())
                        .map_err(|_| SarError::Overflow("gathered length"))?,
                    extent_total,
                )?;
            }
            Some(map)
        } else {
            None
        };
        let sparse_extents: Option<Vec<SparseExtent>> =
            sparse_map.as_ref().map(|m| m.extents.clone());

        let name = String::from_utf8(lfh.name.clone())
            .map_err(|_| SarError::Malformed("LFH Name String is not valid UTF-8"))?;

        if lfh.entry_mode.is_directory() && lfh.payload_size != 0 {
            return Err(SarError::Malformed(
                "IS_DIRECTORY entry must have zero Payload Size",
            ));
        }

        let entry_kind =
            sar_core::metadata::EntryKind::from_mode_and_name(lfh.entry_mode, name.is_empty());
        let symlink_target = if matches!(entry_kind, sar_core::metadata::EntryKind::Symlink) {
            Some(
                std::str::from_utf8(&decoded)
                    .map_err(|_| SarError::Malformed("Symlink target payload is not valid UTF-8"))?
                    .to_owned(),
            )
        } else {
            None
        };

        let path = if lfh.path.is_empty() {
            None
        } else {
            Some(
                String::from_utf8(lfh.path.clone())
                    .map_err(|_| SarError::Malformed("LFH Path String is not valid UTF-8"))?,
            )
        };

        let compression_presence: sar_core::metadata::FieldPresence<
            sar_core::metadata::EntryCompressionMetadata,
        > = if header.flags.contains(GlobalFlags::COMPRESSED) {
            let raw_algo_id = lfh.comp_algo_id.unwrap_or(COMP_ALGO_STORE);
            let metadata = sar_core::metadata::EntryCompressionMetadata {
                algo_id: raw_algo_id,
                algorithm_name: compression_algorithm_name(raw_algo_id),
            };
            if is_effectively_compressed {
                sar_core::metadata::FieldPresence::PresentActive(metadata)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(metadata)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let encryption_presence: sar_core::metadata::FieldPresence<
            sar_core::metadata::EntryEncryptionMetadata,
        > = if header.flags.contains(GlobalFlags::ENCRYPTED) {
            let algo_id = lfh.encr_algo_id.unwrap_or(0);
            let iv_nonce = lfh.iv_nonce.unwrap_or([0u8; 24]);
            let metadata = sar_core::metadata::EntryEncryptionMetadata { algo_id, iv_nonce };
            if is_encrypted {
                sar_core::metadata::FieldPresence::PresentActive(metadata)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(metadata)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let fec_presence: sar_core::metadata::FieldPresence<sar_core::metadata::EntryFecMetadata> =
            if header.flags.contains(GlobalFlags::SELECTIVE_FEC) {
                let algo_id = lfh.fec_algo_id.unwrap_or(0);
                let metadata = sar_core::metadata::EntryFecMetadata {
                    algo_id,
                    summary: fec.clone(),
                };
                if algo_id != 0 {
                    sar_core::metadata::FieldPresence::PresentActive(metadata)
                } else {
                    sar_core::metadata::FieldPresence::PresentInactive(metadata)
                }
            } else {
                sar_core::metadata::FieldPresence::Absent
            };

        let fragment_presence: sar_core::metadata::FieldPresence<
            sar_core::metadata::EntryFragmentMetadata,
        > = if header.flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
            let fragment_id = lfh.fragment_id.unwrap_or(0);
            let fragment_index = lfh.fragment_index.unwrap_or(0);
            let metadata = sar_core::metadata::EntryFragmentMetadata {
                fragment_id,
                fragment_index,
                is_last: lfh.entry_mode.is_last_fragment(),
                is_loss_tolerant: lfh.entry_mode.is_loss_tolerant(),
            };
            if lfh.entry_mode.is_fragment() {
                sar_core::metadata::FieldPresence::PresentActive(metadata)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(metadata)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let cdc = cdc_algo_id_opt.map(|algo_id| sar_core::metadata::EntryCdcMetadata { algo_id });

        let delta = if is_has_delta {
            Some(sar_core::metadata::EntryDeltaMetadata {
                patch_algo_id: patch_raw_id,
                base_hash: lfh.delta_base_hash.unwrap_or(ZERO_DELTA_BASE_HASH),
            })
        } else {
            None
        };

        let sparse = sparse_map
            .as_ref()
            .map(|map| sar_core::metadata::EntrySparseMetadata {
                logical_size: map.logical_size,
                extents: map.extents.clone(),
            });

        let has_crc = header.flags.contains(GlobalFlags::PER_FILE_CRC);
        let has_hash = header.flags.contains(GlobalFlags::DEDUPLICATION);
        let hash = if has_crc || has_hash {
            Some(sar_core::metadata::EntryHashMetadata {
                crc32: if has_crc { lfh.file_crc32 } else { None },
                hash_algo_id: if has_hash { lfh.hash_algo_id } else { None },
                content_hash: if has_hash { lfh.content_hash } else { None },
            })
        } else {
            None
        };

        let metadata = EntryMetadata {
            lfh_offset,
            name,
            path: path.clone(),
            symlink_target,
            payload_size: lfh.payload_size,
            uncompressed_size: lfh.uncompressed_size,
            compression_algo_id: effective_comp_algo_id,
            compression_algorithm: compression_algorithm_name(effective_comp_algo_id),
            is_compressed: is_effectively_compressed,
            fec,
            fragment_id: lfh.fragment_id,
            fragment_index: lfh.fragment_index,
            is_fragment: lfh.entry_mode.is_fragment(),
            is_last_fragment: lfh.entry_mode.is_last_fragment(),
            is_loss_tolerant: lfh.entry_mode.is_loss_tolerant(),
            sparse_extents,
            file_crc32: lfh.file_crc32,
            hash_algo_id: lfh.hash_algo_id,
            content_hash: lfh.content_hash,
            cdc_algo_id: cdc_algo_id_opt,
            patch_algo_id: if is_has_delta {
                Some(patch_raw_id)
            } else {
                None
            },
            delta_base_hash: if is_has_delta {
                Some(lfh.delta_base_hash.unwrap_or(ZERO_DELTA_BASE_HASH))
            } else {
                None
            },
            entry_kind,
            entry_mode_raw: lfh.entry_mode.bits(),
            stream_id: lfh.stream_id,
            sequence_no: lfh.sequence_no,
            is_hidden: lfh.entry_mode.is_hidden_attr(),
            permissions: lfh
                .permissions
                .map(|mode| sar_core::metadata::EntryPermissionMetadata { mode }),
            owner: lfh
                .uid_gid
                .map(|uid_gid| sar_core::metadata::EntryOwnerMetadata { uid_gid }),
            timestamps: lfh
                .timestamps
                .map(|ts| sar_core::metadata::EntryTimestampMetadata {
                    mtime: ts[0],
                    atime: ts[1],
                    ctime: ts[2],
                }),
            path_presence: if header.flags.contains(GlobalFlags::HAS_PATH) {
                if let Some(path) = path {
                    sar_core::metadata::FieldPresence::PresentActive(path)
                } else {
                    sar_core::metadata::FieldPresence::PresentInactive(String::new())
                }
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            permissions_presence: if header.flags.contains(GlobalFlags::HAS_PERMS) {
                sar_core::metadata::FieldPresence::PresentActive(
                    sar_core::metadata::EntryPermissionMetadata {
                        mode: lfh.permissions.unwrap_or(0),
                    },
                )
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            owner_presence: if header.flags.contains(GlobalFlags::EXT_UID_GID) {
                sar_core::metadata::FieldPresence::PresentActive(
                    sar_core::metadata::EntryOwnerMetadata {
                        uid_gid: lfh.uid_gid.unwrap_or(0),
                    },
                )
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            timestamps_presence: if header.flags.contains(GlobalFlags::EXT_TIME) {
                let timestamps = lfh.timestamps.unwrap_or([0u64; 3]);
                sar_core::metadata::FieldPresence::PresentActive(
                    sar_core::metadata::EntryTimestampMetadata {
                        mtime: timestamps[0],
                        atime: timestamps[1],
                        ctime: timestamps[2],
                    },
                )
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            compression_presence,
            encryption_presence,
            fec_presence,
            fragment_presence,
            cdc,
            delta,
            sparse,
            hash,
        };

        Ok(DecodedArchiveEntryParts {
            payload: decoded,
            metadata,
        })
    }

    /// Returns the next validated logical Entry in canonical order.
    ///
    /// Ordinary Entries are released as soon as no earlier incomplete
    /// fragment group blocks them, so a consumer can process an archive
    /// incrementally.  A fragment group is positioned at its Fragment Index 0
    /// LFH and is released when complete, or at end of archive when
    /// incomplete (reconstruction then applies the `LOSS_TOLERANT` rules).
    /// Entries behind an incomplete group are retained, bounded by
    /// `max_total_pipeline_memory`.
    ///
    /// Iteration starts at the first Entry and ends with `Ok(None)`; a
    /// failure ends it.  [`Self::read_all_logical_files`] restarts it.
    ///
    /// This iterator does not itself verify the LFH Content Hash of the
    /// released logical Entry; [`Self::read_all_logical_files`] does.
    ///
    /// # Errors
    ///
    /// Fragment-group validation errors (see [`Self::read_all_logical_files`]),
    /// [`SarError::LimitExceeded`] when retention would exceed
    /// `max_total_pipeline_memory`, and any error from [`Self::next_entry`].
    pub fn next_logical_entry(
        &mut self,
    ) -> Result<Option<crate::fragment_group::CollectedEntry>, SarError> {
        let mut collector = match std::mem::replace(&mut self.logical, LogicalState::Done) {
            LogicalState::Done => return Ok(None),
            LogicalState::Active(collector) => collector,
            LogicalState::NotStarted => {
                if self.global_header.is_none() {
                    self.read_global_header()?;
                }
                self.next_offset = self.header_len;
                Box::new(crate::fragment_group::FragmentGroupCollector::new(
                    self.options.limits,
                ))
            }
        };
        loop {
            if let Some(item) = collector.next_ready()? {
                let held = collector.held_bytes()?;
                let item = self.resolve_cdc_item(item, held)?;
                self.logical = LogicalState::Active(collector);
                return Ok(Some(item));
            }
            if collector.is_input_finished() {
                return Ok(None);
            }
            match self.next_entry()? {
                Some(entry) => collector.push(entry)?,
                None => collector.finish_input(),
            }
        }
    }

    /// Reads all entries from the archive and returns fully reconstructed
    /// logical files.
    ///
    /// This high-level helper handles two cases that [`next_entry`] does not
    /// address automatically:
    ///
    /// * **Fragment groups** — entries sharing a `fragment_id` are validated by
    ///   [`Self::next_logical_entry`] (physical Fragment
    ///   Index order, Class G invariants, Index-0 Name/Path authority, neutral
    ///   non-terminal integrity fields) and assembled using
    ///   [`sar_fragmentation::reconstruct_fragments`].  All fragments must
    ///   be present unless `allow_lossy` is `true` **and** the group has
    ///   `LOSS_TOLERANT` set.  Logical files are returned in canonical order; a
    ///   fragment group is positioned at its Fragment Index 0 LFH.
    /// * **Sparse entries** — when global `SPARSE_FILES` is active and an entry
    ///   carries a sparse map, the raw data segments are scattered into a
    ///   zero-filled logical-size buffer via
    ///   [`apply_sparse_reconstruction`].
    ///
    /// # Loss-tolerant behavior
    ///
    /// When `allow_lossy` is `false`, a missing fragment causes
    /// [`SarError::FragmentGap`].  When `allow_lossy` is `true` and the
    /// fragment group has `LOSS_TOLERANT` set, the degraded output is returned
    /// with [`LogicalFile::is_degraded`] set to `true`.
    ///
    /// AEAD authentication failures are **never** suppressed by `allow_lossy`.
    /// Format errors are **never** suppressed by `allow_lossy`.
    ///
    /// # Sparse logical size
    ///
    /// The final apparent size of a sparse entry is the Sparse Logical Size at
    /// the start of the Sparse Map (spec 17.2), never an LFH `Uncompressed Size`.
    /// LFH `Uncompressed Size` is the fragment-local contribution length (or, for
    /// unfragmented entries, the gathered-data length). Fragmented sparse groups
    /// are reconstructed only after the complete group is assembled; the gathered
    /// length must equal the sum of the extent lengths
    /// ([`SarError::InvalidLength`]). An incomplete sparse group always returns
    /// [`SarError::FragmentGap`], even with `allow_lossy` and `LOSS_TOLERANT`.
    ///
    /// Sparse logical sizes are capped to
    /// [`ResourceLimits::max_decoded_entry_size`].
    ///
    /// # Caller contract
    ///
    /// This method resets the internal read cursor to the beginning of the
    /// data area, so it can be called even after previous [`next_entry`] calls.
    ///
    /// # Errors
    ///
    /// * [`SarError::FragmentGap`] — gap in fragment indices without
    ///   `allow_lossy`.
    /// * [`SarError::InvalidMap`] — overlapping or out-of-bounds sparse extents.
    /// * [`SarError::MetadataConflict`] — duplicate Fragment Index, Class G
    ///   mismatch, later-fragment Name/Path/Sparse Map conflict, or non-zero
    ///   non-terminal File CRC32 / Content Hash.
    /// * [`SarError::CrcMismatch`] — terminal File CRC32 does not match.
    /// * [`SarError::Overflow`] — arithmetic overflow or allocation limit
    ///   exceeded.
    /// * [`SarError::Malformed`] — `IS_FRAGMENT` without a `fragment_id`, an
    ///   Index-0 fragment with an empty Name, or fragments out of strictly
    ///   increasing physical Fragment Index order.
    /// * Any error propagated from [`next_entry`].
    ///
    /// # Sparse + fragmentation ordering
    ///
    /// When both `SPARSE_FILES` and `FILE_FRAGMENTATION` are active, this method
    /// follows the spec-mandated order:
    ///
    /// ```text
    /// Fragment Reassembly → Logical Payload → Sparse Reconstruction → Final File
    /// ```
    ///
    /// The Sparse Map **must** appear only in the fragment with `Fragment Index = 0`
    /// and describes the fully reassembled logical payload.  A Sparse Map on any
    /// non-zero fragment index causes [`SarError::MetadataConflict`].
    ///
    /// # CRC32 verification
    ///
    /// When the global `PER_FILE_CRC` flag is set and an entry carries a non-zero
    /// `File CRC32` field (for a fragment group, the `LAST_FRAGMENT` LFH value),
    /// the CRC32 is verified against the **fully reconstructed**
    /// logical file bytes (including sparse holes).  A mismatch returns
    /// [`SarError::CrcMismatch`].  LOSS_TOLERANT semantics do not suppress
    /// CRC32 mismatches on complete (non-degraded) output.
    ///
    /// [`next_entry`]: Self::next_entry
    pub fn read_all_logical_files(
        &mut self,
        allow_lossy: bool,
    ) -> Result<Vec<LogicalFile>, SarError> {
        use crate::fragment_group::CollectedEntry;

        // Ensure global header is read.
        if self.global_header.is_none() {
            self.read_global_header()?;
        }

        let global = self
            .global_header
            .as_ref()
            .ok_or(SarError::Malformed("global header missing after read"))?
            .clone();

        // Restart canonical logical iteration from the data area start so
        // callers may invoke this after prior next_entry calls.
        self.logical = LogicalState::NotStarted;

        let mut result: Vec<LogicalFile> = Vec::new();

        while let Some(item) = self.next_logical_entry()? {
            match item {
                CollectedEntry::Entry(entry) => {
                    let name = entry.metadata.name.clone();
                    let file_crc32 = entry.metadata.file_crc32;
                    let data = Self::apply_sparse_if_needed(
                        &self.options.limits,
                        entry.payload,
                        entry.metadata.sparse.as_ref(),
                    )?;
                    // CRC32 verification over the fully reconstructed logical file
                    // (including sparse holes), per spec §17.5.
                    if global.flags.contains(GlobalFlags::PER_FILE_CRC)
                        && let Some(expected_crc) = file_crc32
                    {
                        let computed = crc32fast::hash(&data);
                        if computed != expected_crc {
                            return Err(SarError::CrcMismatch(
                                "file CRC32 mismatch on reconstructed logical file",
                            ));
                        }
                    }
                    crate::content_hash::verify_logical(
                        entry.metadata.hash_algo_id,
                        entry.metadata.content_hash,
                        &data,
                    )?;
                    result.push(LogicalFile {
                        name,
                        fragment_id: None,
                        data,
                        is_degraded: false,
                    });
                }
                CollectedEntry::Group(group) => {
                    let fid = group.fragment_id;
                    let name = group.name.clone();
                    // Incomplete sparse groups and inconsistent Sparse Maps fail
                    // before any payload is concatenated (spec §19.4.5, §17.5).
                    let sparse_meta = group.validate_sparse(&self.options.limits)?.cloned();
                    // Authoritative File CRC32 is carried by LAST_FRAGMENT.
                    let terminal_crc32 = group.terminal_crc32;
                    let terminal_content_hash = group.terminal_content_hash;
                    let terminal_hash_algo_id = group.terminal_hash_algo_id;

                    let (raw, is_degraded) = group.reconstruct(&self.options)?;

                    // When the caller does not allow lossy and degraded output was
                    // produced by a LOSS_TOLERANT group, surface it as an error.
                    if is_degraded && !allow_lossy {
                        return Err(SarError::FragmentGap(
                            "fragment group has gaps; use allow_lossy to permit degraded output",
                        ));
                    }

                    // Sparse reconstruction follows complete Fragment Reassembly
                    // (spec §13.7.6, §17.6) and uses the Index-0 Sparse Logical Size.
                    let raw = match sparse_meta.as_ref() {
                        Some(meta) => {
                            Self::apply_sparse_if_needed(&self.options.limits, raw, Some(meta))?
                        }
                        None => raw,
                    };

                    // CRC32 verification over the fully reconstructed logical file.
                    // Degraded output is a partial prefix and is never CRC-verified.
                    if !is_degraded
                        && global.flags.contains(GlobalFlags::PER_FILE_CRC)
                        && let Some(expected_crc) = terminal_crc32
                    {
                        let computed = crc32fast::hash(&raw);
                        if computed != expected_crc {
                            return Err(SarError::CrcMismatch(
                                "file CRC32 mismatch on reconstructed fragment-group logical file",
                            ));
                        }
                    }

                    // The terminal Content Hash is authoritative and is checked
                    // only over a complete reconstruction; LOSS_TOLERANT never
                    // masks a mismatch.
                    if !is_degraded {
                        crate::content_hash::verify_logical(
                            terminal_hash_algo_id,
                            terminal_content_hash,
                            &raw,
                        )?;
                    }
                    result.push(LogicalFile {
                        name,
                        fragment_id: Some(fid),
                        data: raw,
                        is_degraded,
                    });
                }
            }
        }

        Ok(result)
    }

    /// Applies sparse reconstruction when `sparse` is `Some`; otherwise returns
    /// `payload` unchanged.
    ///
    /// `payload` is the complete gathered data.  The output has exactly the
    /// Sparse Logical Size declared by the Sparse Map, which is authoritative
    /// (an absent map is the only pass-through case; a present map with no
    /// extents yields an all-hole Entry).
    ///
    /// The Sparse Logical Size is checked against `max_decoded_entry_size`, and
    /// the simultaneously held gathered data, output buffer and extent list
    /// against `max_total_pipeline_memory`, before the output is allocated.
    fn apply_sparse_if_needed(
        limits: &ResourceLimits,
        payload: Vec<u8>,
        sparse: Option<&sar_core::metadata::EntrySparseMetadata>,
    ) -> Result<Vec<u8>, SarError> {
        let Some(sparse) = sparse else {
            return Ok(payload);
        };
        check_sparse_memory(limits, payload.len(), sparse)?;
        Ok(apply_sparse_reconstruction(
            &payload,
            &sparse.extents,
            sparse.logical_size,
            &limits.sparse_limits(),
        )?)
    }
}

/// Maximum attempts to draw a nonce not yet used by this writer.
const NONCE_GENERATION_ATTEMPTS: usize = 3;

/// Draws a nonce and records it in `used`, the writer's nonce-uniqueness scope.
///
/// A writer has exactly one KMS Master Secret and one `Encr Algo ID`, so one
/// set per writer is the Section 8.2.2 scope.  For `AES256_GCM` the reserved
/// trailing bytes are always zero, so comparing the whole 24-byte field is
/// equivalent to comparing the 12-byte active nonce.  Exhausting the attempts
/// aborts the encoding with `SAR_ERR_NONCE_REUSE`.
fn reserve_unique_nonce(
    used: &mut HashSet<[u8; 24]>,
    mut generate: impl FnMut(&mut [u8; 24]) -> Result<(), sar_crypto::SarCryptoError>,
) -> Result<[u8; 24], SarError> {
    let mut nonce = [0u8; 24];
    for _ in 0..NONCE_GENERATION_ATTEMPTS {
        generate(&mut nonce).map_err(SarError::from)?;
        if used.insert(nonce) {
            return Ok(nonce);
        }
    }
    Err(SarError::NonceReuse("failed to generate a unique nonce"))
}

/// Checks the bytes held at once while scattering: gathered data, the output
/// buffer of Sparse Logical Size, and the extent list.
pub(crate) fn check_sparse_memory(
    limits: &ResourceLimits,
    gathered_len: usize,
    sparse: &sar_core::metadata::EntrySparseMetadata,
) -> Result<(), SarError> {
    limits.check_decoded_entry_size(sparse.logical_size)?;
    let gathered =
        u64::try_from(gathered_len).map_err(|_| SarError::Overflow("sparse gathered length"))?;
    let extent_bytes = u64::try_from(sparse.extents.len())
        .ok()
        .and_then(|n| n.checked_mul(std::mem::size_of::<SparseExtent>() as u64))
        .ok_or(SarError::Overflow("sparse extent list bytes"))?;
    let held = gathered
        .checked_add(sparse.logical_size)
        .and_then(|n| n.checked_add(extent_bytes))
        .ok_or(SarError::Overflow("sparse reconstruction memory"))?;
    limits.check_total_pipeline_memory(held)
}

/// Archive writer with compression and optional encryption support.
pub struct ArchiveWriter<W> {
    writer: W,
    flags: GlobalFlags,
    lfh_size_field_policy: LfhSizeFieldPolicy,
    compression: CompressionSettings,
    position: u64,
    /// Total physical entries written, including Empty Areas.
    entry_count: u64,
    /// Offsets of indexed LFHs; Empty Areas are excluded (spec §7.1).
    offsets: Vec<u64>,
    /// Running CRC32 over the encoded Data Area bytes (spec §7.2).
    data_area_crc: Option<crc32fast::Hasher>,
    cd_metadata: Vec<Tlv>,
    finished: bool,
    master_secret: Option<SecretBytes>,
    encr_algo_id: Option<u8>,
    used_nonces: HashSet<[u8; 24]>,
    /// Exact encoded Global Header bytes emitted by this writer (AEAD AAD prefix).
    global_header_bytes: Vec<u8>,
    header_kms: Option<KmsData>,
    header_written: bool,
    fec: Option<FecSettings>,
    archive_recovery: Option<ArchiveRecoveryState>,
    stream_state: StreamWriteState,
    partition: Option<partition::PartitionWriterState>,
}

const RECOVERY_TLV_TYPE_MIN: u8 = 0x10;
const RECOVERY_TLV_TYPE_MAX: u8 = 0x1F;

struct ArchiveRecoveryState {
    settings: ArchiveRecoverySettings,
    global_flags_start_offset: u64,
    protected_range_start: u64,
    protected_range_end: Option<u64>,
    central_dictionary_offset: Option<u64>,
    footer_offset: Option<u64>,
    protected_bytes: Vec<u8>,
}

/// Structural write phases for stream-oriented archive emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamWriteState {
    /// Writer is ready to emit an LFH (global header may be emitted lazily).
    NeedLocalFileHeader,
    /// Writer is currently emitting an LFH+payload sequence.
    NeedPayload,
    /// Writer finished one full entry.
    EntryReady,
    /// Writer is ready to emit CD/footer for indexed output.
    NeedCentralDictionaryOrFooter,
    /// Archive writing has completed.
    ArchiveComplete,
    /// Writer entered a terminal error state.
    Error,
}

/// Generates patch bytes for a delta entry.
///
/// For `VCDIFF` and `BSDIFF`, the patch is generated from `delta_opts.base` +
/// `target` using the bounded deterministic generators in `sar-delta`.
/// For `STORE_PATCH`, the target bytes are returned as-is (the patch payload
/// **is** the target for STORE_PATCH).
///
/// # Errors
///
/// Returns an error for unsupported algorithms or generation failures.
fn generate_entry_patch(
    delta_opts: &DeltaWriteOptions,
    target: &[u8],
) -> Result<Vec<u8>, SarError> {
    match delta_opts.algorithm {
        PatchAlgoId::StorePatch => {
            // STORE_PATCH: the patch payload is the target bytes verbatim.
            // Use generate_store_patch for consistency with the other generation paths.
            let expected_len = u64::try_from(target.len())
                .map_err(|_| SarError::Overflow("STORE_PATCH target length exceeds u64"))?;
            generate_store_patch(target, expected_len).map_err(map_patch_error)
        }
        PatchAlgoId::Vcdiff => {
            let limits = VcdiffLimits::default();
            generate_vcdiff_patch(&delta_opts.base, target, &limits).map_err(map_patch_error)
        }
        PatchAlgoId::Bsdiff => {
            let limits = BsdiffLimits::default();
            generate_bsdiff_patch(&delta_opts.base, target, &limits).map_err(map_patch_error)
        }
        PatchAlgoId::ZstdPatch => Err(SarError::Unsupported(
            "ZSTD_PATCH: patch generation not implemented",
        )),
        PatchAlgoId::Custom(_) => Err(SarError::Unsupported(
            "CUSTOM patch algorithm: generation not supported",
        )),
    }
}

impl<W: Write> ArchiveWriter<W> {
    /// Creates a new archive writer.
    pub fn new(writer: W, options: ArchiveWriterOptions) -> Result<Self, SarError> {
        Self::new_with_compression_key_provider_and_cd_metadata(
            writer,
            options,
            CompressionSettings::store(),
            None,
            Vec::new(),
        )
    }

    /// Creates a new indexed archive writer with Central Dictionary metadata.
    ///
    /// CDC metadata TLVs (`0x40`, `0x41`, `0x4F`) automatically enable
    /// `CDC_SUPPORT` and cause normal writer entry APIs to emit
    /// `LITERAL_MODE (0x00)` in each LFH CDC field.
    pub fn new_with_cd_metadata(
        writer: W,
        options: ArchiveWriterOptions,
        cd_metadata: Vec<Tlv>,
    ) -> Result<Self, SarError> {
        Self::new_with_compression_key_provider_and_cd_metadata(
            writer,
            options,
            CompressionSettings::store(),
            None,
            cd_metadata,
        )
    }

    /// Creates a new archive writer and writes the global header with compression settings.
    pub fn new_with_compression(
        writer: W,
        options: ArchiveWriterOptions,
        compression: CompressionSettings,
    ) -> Result<Self, SarError> {
        Self::new_with_compression_key_provider_and_cd_metadata(
            writer,
            options,
            compression,
            None,
            Vec::new(),
        )
    }

    /// Creates a new archive writer with compression and an optional key provider.
    pub fn new_with_compression_and_key_provider(
        writer: W,
        options: ArchiveWriterOptions,
        compression: CompressionSettings,
        key_provider: Option<Box<dyn KeyProvider>>,
    ) -> Result<Self, SarError> {
        Self::new_with_compression_key_provider_and_cd_metadata(
            writer,
            options,
            compression,
            key_provider,
            Vec::new(),
        )
    }

    fn new_with_compression_key_provider_and_cd_metadata(
        writer: W,
        options: ArchiveWriterOptions,
        compression: CompressionSettings,
        key_provider: Option<Box<dyn KeyProvider>>,
        cd_metadata: Vec<Tlv>,
    ) -> Result<Self, SarError> {
        let ArchiveWriterOptions {
            no_index,
            encryption,
            fec,
            archive_recovery,
            sparse,
            with_path,
            with_permissions,
            with_uid_gid,
            with_timestamps,
            with_per_file_crc,
            with_content_hash,
            with_symlinks,
            with_delta,
            lfh_size_field_policy,
            limits,
        } = options;

        let has_recovery_cd_metadata = cd_metadata
            .iter()
            .any(|tlv| (RECOVERY_TLV_TYPE_MIN..=RECOVERY_TLV_TYPE_MAX).contains(&tlv.type_id));

        if no_index && !cd_metadata.is_empty() {
            return Err(SarError::FlagConflict(
                "Central Dictionary metadata requires indexed archive output",
            ));
        }
        if no_index && archive_recovery.is_some() {
            return Err(SarError::FlagConflict(
                "archive-level recovery requires indexed archive output",
            ));
        }
        if archive_recovery.is_some() && has_recovery_cd_metadata {
            return Err(SarError::FlagConflict(
                "archive-level recovery option conflicts with pre-supplied RECOVERY TLV metadata",
            ));
        }

        let mut flags = GlobalFlags::empty();
        if no_index {
            flags |= GlobalFlags::NO_INDEX;
        }
        if !cd_metadata.is_empty() {
            flags |= GlobalFlags::OPT_PRESENT;
        }
        if archive_recovery.is_some() || has_recovery_cd_metadata {
            flags |= GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
        }
        if cd_metadata
            .iter()
            .any(|tlv| sar_core::cdc::is_cdc_metadata_tlv_type(tlv.type_id))
        {
            flags |= GlobalFlags::CDC_SUPPORT;
        }
        if compression.algo_id != COMP_ALGO_STORE {
            flags |= GlobalFlags::COMPRESSED;
        }
        if fec.is_some() {
            flags |= GlobalFlags::SELECTIVE_FEC;
        }
        if sparse {
            flags |= GlobalFlags::SPARSE_FILES;
        }
        if with_path {
            flags |= GlobalFlags::HAS_PATH;
        }
        if with_permissions {
            flags |= GlobalFlags::HAS_PERMS;
        }
        if with_uid_gid {
            flags |= GlobalFlags::EXT_UID_GID;
        }
        if with_timestamps {
            flags |= GlobalFlags::EXT_TIME;
        }
        if with_per_file_crc {
            flags |= GlobalFlags::PER_FILE_CRC;
        }
        if with_content_hash {
            flags |= GlobalFlags::DEDUPLICATION;
        }
        if with_symlinks {
            flags |= GlobalFlags::HAS_SYMLINKS;
        }
        if with_delta {
            flags |= GlobalFlags::HAS_DELTA;
        }
        if matches!(lfh_size_field_policy, LfhSizeFieldPolicy::Force64) {
            flags |= GlobalFlags::SIZE_64BIT;
        }

        let mut master_secret = None;
        let mut encr_algo_id = None;
        let kms = if let Some(encryption) = &encryption {
            validate_entry_encr_algo_id(encryption.algo_id).map_err(SarError::from)?;
            if !matches!(encryption.algo_id, ENCR_AES256_GCM | ENCR_XCHACHA20_POLY) {
                return Err(SarError::Unsupported(
                    "archive writer supports only AES-256-GCM and XChaCha20-Poly1305",
                ));
            }
            flags |= GlobalFlags::ENCRYPTED;
            let mode_id = kms_mode_id(&encryption.kms_params);
            let context = KmsContext {
                mode_id,
                params: encryption.kms_params.clone(),
            };
            let provider = key_provider
                .as_deref()
                .ok_or(SarError::KeyMissing("encryption requires a key provider"))?;
            master_secret = Some(
                resolve_master_secret(provider, &context, &limits.kdf_limits())
                    .map_err(SarError::from)?,
            );
            encr_algo_id = Some(encryption.algo_id);
            Some(KmsData {
                mode_id,
                payload: serialize_kms_payload(&encryption.kms_params).map_err(SarError::from)?,
            })
        } else {
            None
        };

        for tlv in &cd_metadata {
            if sar_core::cdc::is_cdc_metadata_tlv_type(tlv.type_id) {
                sar_core::cdc::validate_cdc_metadata_tlv(tlv, &limits)?;
            } else if (RECOVERY_TLV_TYPE_MIN..=RECOVERY_TLV_TYPE_MAX).contains(&tlv.type_id) {
                sar_core::fec::validate_recovery_tlv(tlv.type_id, &tlv.value, &limits)?;
            }
        }
        if let Some(recovery) = &archive_recovery {
            validate_writer_fec_settings(&recovery.as_fec_settings())?;
        }

        validate_global_flags(flags)?;

        Ok(Self {
            writer,
            flags,
            lfh_size_field_policy,
            compression,
            position: 0,
            entry_count: 0,
            offsets: Vec::new(),
            data_area_crc: None,
            cd_metadata,
            finished: false,
            master_secret,
            encr_algo_id,
            used_nonces: HashSet::new(),
            global_header_bytes: Vec::new(),
            header_kms: kms,
            header_written: false,
            fec,
            archive_recovery: archive_recovery.map(|settings| ArchiveRecoveryState {
                settings,
                global_flags_start_offset: GLOBAL_HEADER_FLAGS_OFFSET,
                protected_range_start: GLOBAL_HEADER_FLAGS_OFFSET,
                protected_range_end: None,
                central_dictionary_offset: None,
                footer_offset: None,
                protected_bytes: Vec::new(),
            }),
            stream_state: StreamWriteState::NeedLocalFileHeader,
            partition: None,
        })
    }

    /// Enables `HAS_DATA_AREA_CRC32` (Global Flag bit 16, Rust name
    /// `GlobalFlags::HAS_GLOBAL_CRC32`): the CRC32 of the exact encoded Data
    /// Area bytes is computed incrementally while writing and stored in the
    /// Central Dictionary (spec §7.2).
    ///
    /// Must be called before the first entry is added (the Global Header is
    /// emitted lazily and carries the flag).
    ///
    /// # Errors
    ///
    /// [`SarError::FlagConflict`] for a `NO_INDEX` writer;
    /// [`SarError::Malformed`] when the Global Header was already emitted or
    /// the writer is finished.
    pub fn with_data_area_crc32(mut self) -> Result<Self, SarError> {
        if self.finished || self.header_written {
            return Err(SarError::Malformed(
                "Data Area CRC32 must be enabled before the Global Header is emitted",
            ));
        }
        let flags = self.flags | GlobalFlags::HAS_GLOBAL_CRC32;
        validate_global_flags(flags)?;
        self.flags = flags;
        self.data_area_crc = Some(crc32fast::Hasher::new());
        Ok(self)
    }

    /// Returns the current structural writer state.
    #[must_use]
    pub const fn stream_state(&self) -> StreamWriteState {
        self.stream_state
    }

    fn track_archive_recovery_bytes(&mut self, bytes: &[u8]) -> Result<(), SarError> {
        let Some(recovery) = &mut self.archive_recovery else {
            return Ok(());
        };
        let updated_len = recovery
            .protected_bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(SarError::Overflow("archive recovery protected bytes len"))?;
        let updated_len_u64 =
            u64::try_from(updated_len).map_err(|_| SarError::Overflow("archive recovery len"))?;
        let limits = ResourceLimits::default();
        limits.check_in_memory_buffer(updated_len_u64)?;
        limits.check_recovery_protected_range(updated_len_u64)?;
        recovery.protected_bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finalize_archive_recovery_metadata(&mut self) -> Result<(), SarError> {
        let Some(recovery) = &mut self.archive_recovery else {
            return Ok(());
        };
        recovery.protected_range_end = Some(self.position);
        recovery.central_dictionary_offset = Some(self.position);

        let expected_protected_len = self
            .position
            .checked_sub(recovery.protected_range_start)
            .ok_or(SarError::Overflow("archive recovery protected range len"))?;
        let buffered_len = u64::try_from(recovery.protected_bytes.len())
            .map_err(|_| SarError::Overflow("archive recovery buffered len"))?;
        if buffered_len != expected_protected_len {
            return Err(SarError::Internal(
                "archive recovery protected byte tracking length mismatch",
            ));
        }

        let fec_value = compute_fec_value(
            &recovery.settings.as_fec_settings(),
            &recovery.protected_bytes,
        )?;
        self.cd_metadata.push(Tlv {
            type_id: recovery.settings.algo_id,
            value: fec_value,
        });
        Ok(())
    }

    /// Derives the per-Entry key from the writer's KMS Master Secret.
    fn derive_writer_entry_key(
        &self,
        algo_id: u8,
        nonce: &[u8; 24],
    ) -> Result<SecretBytes, SarError> {
        let master = self.master_secret.as_ref().ok_or(SarError::KeyMissing(
            "writer KMS Master Secret is unavailable",
        ))?;
        derive_entry_key(master, algo_id, nonce).map_err(SarError::from)
    }

    fn emit_global_header_if_needed(&mut self) -> Result<(), SarError> {
        if self.header_written {
            return Ok(());
        }
        validate_global_flags(self.flags)?;
        if self.partition.is_none() {
            require_unpartitioned_processing(self.flags)?;
        }
        let header = GlobalHeader {
            version: 0x01,
            flags: self.flags,
            kms: self.header_kms.clone(),
        };
        let bytes = write_global_header(&header)?;
        self.global_header_bytes.clone_from(&bytes);
        if let Some(recovery) = &self.archive_recovery {
            let recovery_start = usize::try_from(recovery.global_flags_start_offset)
                .map_err(|_| SarError::Overflow("global header flags offset usize"))?;
            if recovery_start > bytes.len() {
                return Err(SarError::Bounds(
                    "global header shorter than Global Flags offset",
                ));
            }
            self.track_archive_recovery_bytes(&bytes[recovery_start..])?;
        }
        self.admit_partition_header(
            u64::try_from(bytes.len()).map_err(|_| SarError::Overflow("header len"))?,
        )?;
        self.writer.write_all(&bytes)?;
        if let Some(state) = &mut self.partition {
            state.commit(&bytes);
        }
        self.position = self
            .position
            .checked_add(u64::try_from(bytes.len()).map_err(|_| SarError::Overflow("header len"))?)
            .ok_or(SarError::Overflow("archive position after header"))?;
        self.header_written = true;
        Ok(())
    }

    fn apply_size_policy(
        &mut self,
        uncompressed_size: u64,
        payload_size: u64,
    ) -> Result<(), SarError> {
        let exceeds_u32 =
            uncompressed_size > u64::from(u32::MAX) || payload_size > u64::from(u32::MAX);
        match self.lfh_size_field_policy {
            LfhSizeFieldPolicy::Force64 => {
                self.flags |= GlobalFlags::SIZE_64BIT;
                Ok(())
            }
            LfhSizeFieldPolicy::Force32 => {
                if exceeds_u32 {
                    return Err(SarError::Overflow(
                        "size does not fit 32-bit field under Force32 policy",
                    ));
                }
                self.flags.remove(GlobalFlags::SIZE_64BIT);
                Ok(())
            }
            LfhSizeFieldPolicy::Auto => {
                if exceeds_u32 {
                    if self.header_written && !self.flags.contains(GlobalFlags::SIZE_64BIT) {
                        return Err(SarError::Overflow(
                            "Auto policy cannot promote to 64-bit size fields after header emission",
                        ));
                    }
                    self.flags |= GlobalFlags::SIZE_64BIT;
                } else if !self.header_written {
                    self.flags.remove(GlobalFlags::SIZE_64BIT);
                }
                Ok(())
            }
        }
    }

    /// Adds one archive entry.
    pub fn add_entry(&mut self, entry: EntryInput) -> Result<EntryWritten, SarError> {
        if self.finished {
            self.stream_state = StreamWriteState::Error;
            return Err(SarError::Malformed("archive writer already finished"));
        }

        // Validate metadata vs global flags before encoding anything.
        self.validate_entry_input_metadata(&entry)?;
        self.admit_partition_input(&entry)?;

        // Generate the wire payload: patch bytes for VCDIFF/BSDIFF, target bytes otherwise.
        let wire_payload: Vec<u8> = if let Some(ref delta_opts) = entry.delta {
            generate_entry_patch(delta_opts, &entry.payload)?
        } else {
            entry.payload.clone()
        };
        self.admit_partition_wire(wire_payload.len())?;

        // `uncompressed_size` is the decoded size of the stored representation
        // (spec Sections 6.1.2 and 8.4): the patch length for a delta Entry,
        // never the patch output (target) length.
        let uncompressed_len =
            u64::try_from(wire_payload.len()).map_err(|_| SarError::Overflow("payload len"))?;

        let is_compressed = self.compression.algo_id != COMP_ALGO_STORE;
        let mut encoded_payload = encode_payload_v2(
            &wire_payload,
            EncodingPlanV2 {
                is_compressed,
                comp_algo_id: self.compression.algo_id,
                compression_level: self.compression.level,
                crypto: None,
            },
        )?;
        self.admit_partition_encoded(encoded_payload.len())?;
        let is_encrypted = self.flags.contains(GlobalFlags::ENCRYPTED);
        let is_fec = self.fec.is_some();

        // When FEC is active the payload_size field must account for the FEC algo ID
        // being present; the actual payload bytes are the same size as without FEC
        // (FEC value is stored in the LFH header, not in Payload Data).
        let payload_len = if is_encrypted {
            u64::try_from(encoded_payload.len())
                .map_err(|_| SarError::Overflow("payload len"))?
                .checked_add(16)
                .ok_or(SarError::Overflow("encrypted payload len"))?
        } else {
            u64::try_from(encoded_payload.len()).map_err(|_| SarError::Overflow("payload len"))?
        };
        self.apply_size_policy(uncompressed_len, payload_len)?;
        self.emit_global_header_if_needed()?;
        let mut lfh = LocalFileHeader::minimal_store(entry.name.as_bytes().to_vec(), payload_len);
        lfh.uncompressed_size = uncompressed_len;

        // Apply expanded EntryInput metadata to the LFH.
        self.apply_entry_input_to_lfh(&entry, &mut lfh)?;

        if self.flags.contains(GlobalFlags::CDC_SUPPORT) {
            lfh.cdc_algo_id = Some(sar_core::cdc::CDC_ALGO_LITERAL);
        }
        if self.flags.contains(GlobalFlags::COMPRESSED) {
            lfh.comp_algo_id = Some(self.compression.algo_id);
        }
        if is_compressed {
            lfh.entry_mode = EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::COMPRESSED);
        }

        // Pre-set FEC algo ID so it is included in the AEAD AAD (spec §13.2.1).
        if is_fec {
            let fec_cfg = self
                .fec
                .as_ref()
                .ok_or(SarError::Internal("missing FEC settings"))?;
            lfh.fec_algo_id = Some(fec_cfg.algo_id);
            if is_encrypted {
                let reserved_fec_len = compute_fec_value_len(fec_cfg, encoded_payload.len())?;
                lfh.fec_value = vec![0u8; reserved_fec_len];
            }
        }

        if is_encrypted {
            let algo_id = self
                .encr_algo_id
                .ok_or(SarError::Internal("missing writer encryption algorithm"))?;
            let nonce = reserve_unique_nonce(&mut self.used_nonces, |field| {
                generate_nonce(algo_id, field)
            })?;
            lfh.encr_algo_id = Some(algo_id);
            lfh.iv_nonce = Some(nonce);
            lfh.entry_mode = EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::ENCRYPTED);

            // Reserve the final FEC Value length before AEAD so Header Size in the
            // AAD matches the final on-wire LFH. Per spec §13.2.1, only FEC Size
            // and FEC Value are excluded from the AAD.
            let provisional_lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            let fec_algo_id = lfh.fec_algo_id.unwrap_or(0);
            let aad_lfh_bytes = lfh_bytes_for_aad(
                self.flags,
                &provisional_lfh_bytes,
                fec_algo_id,
                lfh.fec_value.len(),
            )?;
            let aad = build_aead_aad(&self.global_header_bytes, &aad_lfh_bytes);
            let key = self.derive_writer_entry_key(algo_id, &nonce)?;
            encoded_payload = encode_payload_v2(
                &wire_payload,
                EncodingPlanV2 {
                    is_compressed,
                    comp_algo_id: self.compression.algo_id,
                    compression_level: self.compression.level,
                    crypto: Some(EntryCryptoContext {
                        algo_id,
                        iv_nonce: nonce,
                        aad,
                        key,
                    }),
                },
            )?;

            if is_fec {
                // Compute FEC over ciphertext only (exclude the 16-byte AEAD tag).
                let tag_len = 16usize;
                let ciphertext_len =
                    encoded_payload
                        .len()
                        .checked_sub(tag_len)
                        .ok_or(SarError::InvalidLength(
                            "encrypted payload shorter than AEAD tag",
                        ))?;
                let ciphertext = &encoded_payload[..ciphertext_len];
                let fec_value = compute_fec_value(
                    self.fec
                        .as_ref()
                        .ok_or(SarError::Internal("missing FEC settings"))?,
                    ciphertext,
                )?;
                if fec_value.len() != lfh.fec_value.len() {
                    return Err(SarError::InvalidLength(
                        "computed FEC value length changed after AEAD",
                    ));
                }
                lfh.fec_value = fec_value;
            }

            // Re-serialize LFH now that fec_value is populated.
            let final_lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            self.write_entry(lfh, final_lfh_bytes, encoded_payload)
        } else {
            if is_fec {
                // Compute FEC over the full encoded (unencrypted) payload.
                let fec_value = compute_fec_value(
                    self.fec
                        .as_ref()
                        .ok_or(SarError::Internal("missing FEC settings"))?,
                    &encoded_payload,
                )?;
                lfh.fec_value = fec_value;
            }
            let lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            self.write_entry(lfh, lfh_bytes, encoded_payload)
        }
    }

    fn write_entry(
        &mut self,
        lfh: LocalFileHeader,
        lfh_bytes: Vec<u8>,
        encoded_payload: Vec<u8>,
    ) -> Result<EntryWritten, SarError> {
        let lfh_offset = self.position;
        self.admit_partition_entry(
            &lfh,
            u64::try_from(lfh_bytes.len())
                .ok()
                .zip(u64::try_from(encoded_payload.len()).ok())
                .and_then(|(a, b)| a.checked_add(b))
                .ok_or(SarError::Overflow("entry write length"))?,
        )?;
        self.stream_state = StreamWriteState::NeedPayload;
        self.track_archive_recovery_bytes(&lfh_bytes)?;
        self.track_archive_recovery_bytes(&encoded_payload)?;
        self.writer.write_all(&lfh_bytes)?;
        self.writer.write_all(&encoded_payload)?;
        if !lfh.entry_mode.is_partition_manifest()
            && let Some(state) = &mut self.partition
        {
            state.commit(&lfh_bytes);
            state.commit(&encoded_payload);
        }
        if let Some(crc) = &mut self.data_area_crc {
            crc.update(&lfh_bytes);
            crc.update(&encoded_payload);
        }

        let written = u64::try_from(lfh_bytes.len())
            .map_err(|_| SarError::Overflow("lfh bytes len"))?
            .checked_add(
                u64::try_from(encoded_payload.len())
                    .map_err(|_| SarError::Overflow("payload bytes len"))?,
            )
            .ok_or(SarError::Overflow("entry write length"))?;
        self.position = self
            .position
            .checked_add(written)
            .ok_or(SarError::Overflow("archive position"))?;
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .ok_or(SarError::Overflow("entry count"))?;
        if !is_empty_area(&lfh) {
            self.offsets.push(lfh_offset);
        }
        self.stream_state = StreamWriteState::EntryReady;

        Ok(EntryWritten {
            lfh_offset,
            total_bytes: written,
        })
    }

    /// Validates that expanded [`EntryInput`] metadata is consistent with the
    /// writer's currently enabled global flags.  Returns `Err` for any
    /// metadata field that is requested but the corresponding flag is not set.
    fn validate_entry_input_metadata(&self, entry: &EntryInput) -> Result<(), SarError> {
        use sar_core::metadata::EntryKind;

        // Symlink entries require HAS_SYMLINKS.
        if matches!(entry.kind, Some(EntryKind::Symlink))
            && !self.flags.contains(GlobalFlags::HAS_SYMLINKS)
        {
            return Err(SarError::FlagConflict(
                "Symlink entry requires ArchiveWriterOptions::with_symlinks = true",
            ));
        }
        if matches!(entry.kind, Some(EntryKind::Symlink))
            && std::str::from_utf8(&entry.payload).is_err()
        {
            return Err(SarError::Malformed(
                "Symlink entry payload must be valid UTF-8",
            ));
        }

        // Directory entries must have zero payload.
        if matches!(entry.kind, Some(EntryKind::Directory)) && !entry.payload.is_empty() {
            return Err(SarError::Malformed(
                "Directory entry must have zero-length payload",
            ));
        }

        // Path requires HAS_PATH.
        if entry.path.is_some() && !self.flags.contains(GlobalFlags::HAS_PATH) {
            return Err(SarError::FlagConflict(
                "EntryInput::path requires ArchiveWriterOptions::with_path = true",
            ));
        }

        // Path length must fit in a u16 LFH field (max 65535 bytes).
        if matches!(&entry.path, Some(p) if p.len() > usize::from(u16::MAX)) {
            return Err(SarError::Overflow(
                "path length exceeds LFH u16 field capacity",
            ));
        }

        // Name length must fit in a u16 LFH field (max 65535 bytes).
        if entry.name.len() > usize::from(u16::MAX) {
            return Err(SarError::Overflow(
                "name length exceeds LFH u16 field capacity",
            ));
        }

        // Permissions require HAS_PERMS, and HAS_PERMS requires explicit permissions.
        if self.flags.contains(GlobalFlags::HAS_PERMS) {
            if entry.permissions.is_none() {
                return Err(SarError::Malformed(
                    "ArchiveWriterOptions::with_permissions requires EntryInput::permissions",
                ));
            }
        } else if entry.permissions.is_some() {
            return Err(SarError::FlagConflict(
                "EntryInput::permissions requires ArchiveWriterOptions::with_permissions = true",
            ));
        }

        // UID/GID requires EXT_UID_GID, and EXT_UID_GID requires explicit UID/GID metadata.
        if self.flags.contains(GlobalFlags::EXT_UID_GID) {
            if entry.uid_gid.is_none() {
                return Err(SarError::Malformed(
                    "ArchiveWriterOptions::with_uid_gid requires EntryInput::uid_gid",
                ));
            }
        } else if entry.uid_gid.is_some() {
            return Err(SarError::FlagConflict(
                "EntryInput::uid_gid requires ArchiveWriterOptions::with_uid_gid = true",
            ));
        }

        // Timestamps require EXT_TIME, and EXT_TIME requires explicit timestamp metadata.
        if self.flags.contains(GlobalFlags::EXT_TIME) {
            if entry.timestamps.is_none() {
                return Err(SarError::Malformed(
                    "ArchiveWriterOptions::with_timestamps requires EntryInput::timestamps",
                ));
            }
        } else if entry.timestamps.is_some() {
            return Err(SarError::FlagConflict(
                "EntryInput::timestamps requires ArchiveWriterOptions::with_timestamps = true",
            ));
        }

        // CRC32 requires PER_FILE_CRC.
        if entry.file_crc32.is_some() && !self.flags.contains(GlobalFlags::PER_FILE_CRC) {
            return Err(SarError::FlagConflict(
                "EntryInput::file_crc32 requires ArchiveWriterOptions::with_per_file_crc = true",
            ));
        }

        // Content hash requires DEDUPLICATION.
        if entry.content_hash.is_some() && !self.flags.contains(GlobalFlags::DEDUPLICATION) {
            return Err(SarError::FlagConflict(
                "EntryInput::content_hash requires ArchiveWriterOptions::with_content_hash = true",
            ));
        }

        // Delta options require HAS_DELTA global flag.
        if let Some(ref delta_opts) = entry.delta {
            if !self.flags.contains(GlobalFlags::HAS_DELTA) {
                return Err(SarError::FlagConflict(
                    "EntryInput::delta requires ArchiveWriterOptions::with_delta = true",
                ));
            }
            // VCDIFF and BSDIFF require non-zero reconstruction identity.
            let algo = delta_opts.algorithm;
            if matches!(algo, PatchAlgoId::Vcdiff | PatchAlgoId::Bsdiff)
                && delta_opts.delta_base_hash == ZERO_DELTA_BASE_HASH
            {
                return Err(SarError::BaseMissing(
                    "VCDIFF/BSDIFF delta_base_hash must be non-zero (all-zero means missing identity)",
                ));
            }
        }

        Ok(())
    }

    /// Copies expanded [`EntryInput`] metadata fields into the LFH.
    ///
    /// Called after the LFH is constructed and before encoding begins.
    /// Only sets fields whose corresponding global flag is enabled.
    fn apply_entry_input_to_lfh(
        &self,
        entry: &EntryInput,
        lfh: &mut LocalFileHeader,
    ) -> Result<(), SarError> {
        use sar_core::metadata::EntryKind;

        // Stream ID and sequence number.
        lfh.stream_id = entry.stream_id.unwrap_or(0);
        lfh.sequence_no = entry.sequence_no.unwrap_or(0);

        // Entry kind → entry mode bits.
        let effective_kind = entry.kind.unwrap_or(if entry.name.is_empty() {
            EntryKind::EmptyArea
        } else {
            EntryKind::RegularFile
        });
        match effective_kind {
            EntryKind::Directory => {
                lfh.entry_mode =
                    EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::IS_DIRECTORY);
            }
            EntryKind::Symlink => {
                lfh.entry_mode =
                    EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::IS_SYMLINK);
            }
            EntryKind::RegularFile | EntryKind::EmptyArea => {}
        }

        // Hidden attribute.
        if entry.is_hidden {
            lfh.entry_mode = EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::HIDDEN_ATTR);
        }

        // Optional metadata fields (only when the global flag is set).
        if self.flags.contains(GlobalFlags::HAS_PATH)
            && let Some(ref path) = entry.path
        {
            lfh.path = path.as_bytes().to_vec();
        }

        // When a Global Flag forces a field to be physically present in the LFH,
        // the high-level writer requires the caller to provide that metadata explicitly.
        // Explicit zero values remain valid; missing values fail closed.
        if self.flags.contains(GlobalFlags::HAS_PERMS) {
            lfh.permissions = Some(entry.permissions.ok_or(SarError::Malformed(
                "HAS_PERMS requires EntryInput::permissions",
            ))?);
        }

        if self.flags.contains(GlobalFlags::EXT_UID_GID) {
            lfh.uid_gid = Some(entry.uid_gid.ok_or(SarError::Malformed(
                "EXT_UID_GID requires EntryInput::uid_gid",
            ))?);
        }

        if self.flags.contains(GlobalFlags::EXT_TIME) {
            lfh.timestamps = Some(entry.timestamps.ok_or(SarError::Malformed(
                "EXT_TIME requires EntryInput::timestamps",
            ))?);
        }

        if self.flags.contains(GlobalFlags::PER_FILE_CRC) {
            lfh.file_crc32 = entry.file_crc32.or(Some(0));
        }

        if self.flags.contains(GlobalFlags::DEDUPLICATION) {
            let algo_id = entry
                .hash_algo_id
                .unwrap_or(sar_crypto::algorithm::HASH_BLAKE3);
            sar_core::validate_lfh_hash_algo_id(algo_id)?;
            lfh.hash_algo_id = Some(algo_id);
            // The digest covers the final logical Entry.  An explicit
            // `content_hash` is written verbatim; an all-zero value is an
            // ordinary digest value, not "absent".
            lfh.content_hash = Some(match entry.content_hash {
                Some(explicit) => explicit,
                None => crate::content_hash::digest_logical(algo_id, &entry.payload)?,
            });
        }

        // When HAS_DELTA is globally active, every LFH must carry Patch Algo ID
        // and Delta Base Hash (the format uses unwrap_or(default) on read, so these
        // fields are mandatory wire-format fields whenever the global flag is set).
        if self.flags.contains(GlobalFlags::HAS_DELTA) {
            if let Some(ref delta_opts) = entry.delta {
                lfh.patch_algo_id = Some(delta_opts.algorithm.as_u8());
                lfh.delta_base_hash = Some(delta_opts.delta_base_hash);
            } else {
                // No per-entry delta: default to STORE_PATCH with all-zero hash.
                lfh.patch_algo_id = Some(PATCH_ALGO_STORE_PATCH);
                lfh.delta_base_hash = Some(ZERO_DELTA_BASE_HASH);
            }
        }

        Ok(())
    }

    /// Writes a sparse archive entry.
    ///
    /// The writer must have been created with
    /// [`ArchiveWriterOptions::sparse`]` = true`.
    ///
    /// # Arguments
    ///
    /// * `name` — entry name (UTF-8).
    /// * `gathered_payload` — raw data bytes for all non-hole regions, stored
    ///   sequentially in extent order.
    /// * `sparse` — validated-on-call sparse options; see [`SparseWriteOptions`].
    ///
    /// # Validation
    ///
    /// Before writing any bytes, this method verifies:
    ///
    /// * `SPARSE_FILES` global flag is set.
    /// * `sparse.logical_size` is `>= end` of every declared extent.
    /// * No two extents overlap.
    /// * All arithmetic is checked and does not overflow.
    /// * `gathered_payload.len()` equals the sum of `extent.length` values.
    ///
    /// # Errors
    ///
    /// * [`SarError::Malformed`] — `SPARSE_FILES` flag not set.
    /// * [`SarError::InvalidMap`] — overlapping extents, extent beyond
    ///   `logical_size`, or payload length mismatch.
    /// * [`SarError::Overflow`] — arithmetic overflow in extent validation.
    /// * Any I/O error from writing.
    pub fn write_sparse_entry(
        &mut self,
        name: &str,
        gathered_payload: &[u8],
        sparse: SparseWriteOptions,
    ) -> Result<EntryWritten, SarError> {
        if self.finished {
            self.stream_state = StreamWriteState::Error;
            return Err(SarError::Malformed("archive writer already finished"));
        }
        if !self.flags.contains(GlobalFlags::SPARSE_FILES) {
            return Err(SarError::Malformed(
                "write_sparse_entry requires ArchiveWriterOptions::sparse = true",
            ));
        }

        // Validate extents against logical_size (overlap and bounds).
        validate_sparse_extents(
            &sparse.extents,
            sparse.logical_size,
            &ResourceLimits::unlimited().sparse_limits(),
        )?;

        // Validate payload length equals sum of extent lengths.
        let mut total_extent_bytes: u64 = 0;
        for extent in &sparse.extents {
            total_extent_bytes = total_extent_bytes
                .checked_add(extent.length)
                .ok_or(SarError::Overflow("sparse extent length sum overflow"))?;
        }
        let payload_len_u64 = u64::try_from(gathered_payload.len())
            .map_err(|_| SarError::Overflow("gathered payload length overflow"))?;
        if payload_len_u64 != total_extent_bytes {
            return Err(SarError::InvalidLength(
                "gathered_payload length does not equal sum of sparse extent lengths",
            ));
        }

        // Encode the gathered payload (compression / encryption if enabled).
        let is_compressed = self.compression.algo_id != COMP_ALGO_STORE;
        let mut encoded_payload = encode_payload_v2(
            gathered_payload,
            EncodingPlanV2 {
                is_compressed,
                comp_algo_id: self.compression.algo_id,
                compression_level: self.compression.level,
                crypto: None,
            },
        )?;
        let is_encrypted = self.flags.contains(GlobalFlags::ENCRYPTED);
        let is_fec = self.fec.is_some();

        let encoded_len = if is_encrypted {
            u64::try_from(encoded_payload.len())
                .map_err(|_| SarError::Overflow("payload len"))?
                .checked_add(16)
                .ok_or(SarError::Overflow("encrypted payload len"))?
        } else {
            u64::try_from(encoded_payload.len()).map_err(|_| SarError::Overflow("payload len"))?
        };
        self.apply_size_policy(sparse.logical_size, encoded_len)?;
        self.emit_global_header_if_needed()?;

        // Build LFH: Uncompressed Size is the gathered-data length; the Sparse
        // Logical Size is carried only by the leading Sparse Map field.
        let is_64bit = self.flags.contains(GlobalFlags::SIZE_64BIT);
        let sparse_map_bytes = sar_core::sparse::write_sparse_map(
            &SparseMap {
                logical_size: sparse.logical_size,
                extents: sparse.extents.clone(),
            },
            is_64bit,
        )?;

        let mut lfh = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), encoded_len);
        lfh.uncompressed_size = payload_len_u64;
        if self.flags.contains(GlobalFlags::CDC_SUPPORT) {
            lfh.cdc_algo_id = Some(sar_core::cdc::CDC_ALGO_LITERAL);
        }
        lfh.sparse_map = sparse_map_bytes;
        if self.flags.contains(GlobalFlags::DEDUPLICATION) {
            // Digest of the final logical Entry, including holes.
            let algo_id = sar_crypto::algorithm::HASH_BLAKE3;
            lfh.hash_algo_id = Some(algo_id);
            lfh.content_hash = Some(crate::content_hash::digest_sparse_logical(
                algo_id,
                gathered_payload,
                &sparse.extents,
                sparse.logical_size,
            )?);
        }
        if self.flags.contains(GlobalFlags::COMPRESSED) {
            lfh.comp_algo_id = Some(self.compression.algo_id);
        }
        if is_compressed {
            lfh.entry_mode = EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::COMPRESSED);
        }

        if is_fec {
            let fec_cfg = self
                .fec
                .as_ref()
                .ok_or(SarError::Internal("missing FEC settings"))?;
            lfh.fec_algo_id = Some(fec_cfg.algo_id);
            if is_encrypted {
                let reserved_fec_len = compute_fec_value_len(fec_cfg, encoded_payload.len())?;
                lfh.fec_value = vec![0u8; reserved_fec_len];
            }
        }

        if is_encrypted {
            let algo_id = self
                .encr_algo_id
                .ok_or(SarError::Internal("missing writer encryption algorithm"))?;
            let nonce = reserve_unique_nonce(&mut self.used_nonces, |field| {
                generate_nonce(algo_id, field)
            })?;
            lfh.encr_algo_id = Some(algo_id);
            lfh.iv_nonce = Some(nonce);
            lfh.entry_mode = EntryMode::from_bits(lfh.entry_mode.bits() | EntryMode::ENCRYPTED);

            let provisional_lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            let fec_algo_id = lfh.fec_algo_id.unwrap_or(0);
            let aad_lfh_bytes = lfh_bytes_for_aad(
                self.flags,
                &provisional_lfh_bytes,
                fec_algo_id,
                lfh.fec_value.len(),
            )?;
            let aad = build_aead_aad(&self.global_header_bytes, &aad_lfh_bytes);
            let key = self.derive_writer_entry_key(algo_id, &nonce)?;
            encoded_payload = encode_payload_v2(
                gathered_payload,
                EncodingPlanV2 {
                    is_compressed,
                    comp_algo_id: self.compression.algo_id,
                    compression_level: self.compression.level,
                    crypto: Some(EntryCryptoContext {
                        algo_id,
                        iv_nonce: nonce,
                        aad,
                        key,
                    }),
                },
            )?;

            if is_fec {
                let tag_len = 16usize;
                let ciphertext_len =
                    encoded_payload
                        .len()
                        .checked_sub(tag_len)
                        .ok_or(SarError::InvalidLength(
                            "encrypted payload shorter than AEAD tag",
                        ))?;
                let ciphertext = &encoded_payload[..ciphertext_len];
                let fec_value = compute_fec_value(
                    self.fec
                        .as_ref()
                        .ok_or(SarError::Internal("missing FEC settings"))?,
                    ciphertext,
                )?;
                if fec_value.len() != lfh.fec_value.len() {
                    return Err(SarError::InvalidLength(
                        "computed FEC value length changed after AEAD (sparse)",
                    ));
                }
                lfh.fec_value = fec_value;
            }

            let final_lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            self.write_entry(lfh, final_lfh_bytes, encoded_payload)
        } else {
            if is_fec {
                let fec_value = compute_fec_value(
                    self.fec
                        .as_ref()
                        .ok_or(SarError::Internal("missing FEC settings"))?,
                    &encoded_payload,
                )?;
                lfh.fec_value = fec_value;
            }
            let lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            self.write_entry(lfh, lfh_bytes, encoded_payload)
        }
    }

    /// Finalizes archive and optionally writes CD/Footer.
    pub fn finish(self) -> Result<ArchiveSummary, SarError> {
        self.finish_with_commitment().map(|(summary, _)| summary)
    }

    /// [`Self::finish`] that also reports the Partition commitment computed
    /// by the writer (Partition writers only) and flushes the sink.
    pub(crate) fn finish_with_commitment(
        mut self,
    ) -> Result<(ArchiveSummary, Option<partition::PartitionCommitment>), SarError> {
        if self.finished {
            self.stream_state = StreamWriteState::Error;
            return Err(SarError::Malformed("archive writer already finished"));
        }
        self.emit_global_header_if_needed()?;
        let manifest_offset = self.position;
        if self.partition.is_some() {
            self.write_partition_manifest()?;
        }
        self.stream_state = StreamWriteState::NeedCentralDictionaryOrFooter;

        if !self.flags.contains(GlobalFlags::NO_INDEX) {
            self.finalize_archive_recovery_metadata()?;
            let cd_offset = self.position;
            let file_count = u64::try_from(self.offsets.len())
                .map_err(|_| SarError::Overflow("offset count"))?;
            let cd = CentralDictionary {
                version: SUPPORTED_CD_VERSION,
                file_count,
                global_crc32: self.data_area_crc.take().map(|crc| crc.finalize()),
                metadata: self.cd_metadata.clone(),
                offsets: self.offsets.clone(),
            };
            let cd_bytes = if self.partition.is_some() {
                write_partition_central_dictionary(&cd, self.flags)?
            } else {
                write_central_dictionary(&cd, self.flags)?
            };
            self.writer.write_all(&cd_bytes)?;
            self.position = self
                .position
                .checked_add(
                    u64::try_from(cd_bytes.len()).map_err(|_| SarError::Overflow("CD len"))?,
                )
                .ok_or(SarError::Overflow("archive position after CD"))?;

            let pad = (8 - (self.position % 8)) % 8;
            if pad > 0 {
                let pad_len = usize::try_from(pad).map_err(|_| SarError::Overflow("pad len"))?;
                self.writer.write_all(&vec![0u8; pad_len])?;
                self.position = self
                    .position
                    .checked_add(pad)
                    .ok_or(SarError::Overflow("archive position after padding"))?;
            }

            if let Some(recovery) = &mut self.archive_recovery {
                recovery.footer_offset = Some(self.position);
            }
            self.writer.write_all(&write_footer(Footer { cd_offset }))?;
            self.position = self
                .position
                .checked_add(8)
                .ok_or(SarError::Overflow("archive position after footer"))?;
        }

        let commitment = match &self.partition {
            Some(state) => {
                self.writer.flush()?;
                state
                    .current_hash()
                    .map(|current_hash| partition::PartitionCommitment {
                        current_hash,
                        manifest_offset,
                    })
            }
            None => None,
        };
        self.finished = true;
        self.stream_state = StreamWriteState::ArchiveComplete;
        Ok((
            ArchiveSummary {
                entry_count: self.entry_count,
                archive_size: self.position,
                indexed: !self.flags.contains(GlobalFlags::NO_INDEX),
            },
            commitment,
        ))
    }
}

pub(crate) fn compression_algorithm_name(algo_id: u8) -> &'static str {
    match algo_id {
        0x00 => "STORE",
        0x01 => "DEFLATE",
        0x02 => "ZSTD",
        _ => "UNKNOWN",
    }
}

fn kms_mode_id(params: &KmsParams) -> u8 {
    match params {
        KmsParams::Pbkdf2(_) => sar_crypto::KMS_PBKDF2,
        KmsParams::Argon2(_) => sar_crypto::KMS_ARGON2,
        KmsParams::AsymmetricWrap(_) => sar_crypto::KMS_ASYMMETRIC_WRAP,
        KmsParams::TlsExporter(_) => sar_crypto::KMS_TLS_EXPORTER,
    }
}

pub(crate) fn build_kms_context(header: &GlobalHeader) -> Result<KmsContext, SarError> {
    let kms = header
        .kms
        .as_ref()
        .ok_or(SarError::Malformed("encrypted archive is missing KMS data"))?;
    let params = if kms.mode_id == KMS_TLS_EXPORTER {
        // Mode 0x04: parse using the TLS_EXPORTER-specific parser so the
        // transport layer can supply a key provider that wraps the pre-derived
        // TLS exporter material.
        parse_tls_exporter_kms_payload(&kms.payload)
            .map(KmsParams::TlsExporter)
            .map_err(SarError::from)?
    } else {
        parse_kms_payload(kms.mode_id, &kms.payload).map_err(SarError::from)?
    };
    Ok(KmsContext {
        mode_id: kms.mode_id,
        params,
    })
}

fn validate_writer_fec_settings(fec: &FecSettings) -> Result<(), SarError> {
    match fec.algo_id {
        FEC_ALGO_XOR => {
            sar_fec::XorCodec::new(fec.config0, fec.config1).map_err(SarError::from)?;
        }
        FEC_ALGO_REED_SOLOMON => {
            sar_fec::RsCodec::new(fec.config0, fec.config1, fec.symbol_size)
                .map_err(SarError::from)?;
        }
        other => {
            return Err(SarError::Unsupported(
                if (RECOVERY_TLV_TYPE_MIN..=RECOVERY_TLV_TYPE_MAX).contains(&other) {
                    "FEC algorithm is assigned but not supported by archive writer"
                } else {
                    "FEC algorithm ID out of defined range"
                },
            ));
        }
    }
    Ok(())
}

/// Encodes FEC parity for `protected` bytes using the provided [`FecSettings`] and
/// returns the raw FEC value bytes ready for embedding in the `FEC Value` LFH field.
fn compute_fec_value(fec: &FecSettings, protected: &[u8]) -> Result<Vec<u8>, SarError> {
    let fec_value = match fec.algo_id {
        FEC_ALGO_XOR => {
            let codec = sar_fec::XorCodec::new(fec.config0, fec.config1).map_err(SarError::from)?;
            codec
                .encode_recovery(protected, FecOptions)
                .map_err(SarError::from)?
        }
        FEC_ALGO_REED_SOLOMON => {
            let codec = sar_fec::RsCodec::new(fec.config0, fec.config1, fec.symbol_size)
                .map_err(SarError::from)?;
            codec
                .encode_recovery(protected, FecOptions)
                .map_err(SarError::from)?
        }
        other => {
            return Err(SarError::Unsupported(if (0x10..=0x1F).contains(&other) {
                "FEC algorithm is assigned but not supported by archive writer"
            } else {
                "FEC algorithm ID out of defined range"
            }));
        }
    };
    Ok(fec_value.data)
}

fn compute_fec_value_len(fec: &FecSettings, protected_len: usize) -> Result<usize, SarError> {
    const MAX_PARITY_SIZE: u64 = 256 * 1024 * 1024;
    let original_len =
        u64::try_from(protected_len).map_err(|_| SarError::Overflow("protected len"))?;

    match fec.algo_id {
        FEC_ALGO_XOR => {
            sar_fec::XorCodec::new(fec.config0, fec.config1).map_err(SarError::from)?;
            let stripe_size = fec.config0;
            let block_size = match fec.config1 {
                0x00 => 256u64,
                0x01 => 512,
                0x02 => 1_024,
                0x03 => 2_048,
                0x04 => 4_096,
                0x05 => 8_192,
                0x06 => 16_384,
                0x07 => 32_768,
                0x08 => 65_536,
                _ => return Err(SarError::ReservedValue("XOR block size index is reserved")),
            };

            let stripe_bytes = u64::from(stripe_size)
                .checked_mul(block_size)
                .ok_or(SarError::Overflow("XOR effective stripe size overflow"))?;
            let stripe_count = ceil_div_u64(original_len, stripe_bytes)?;
            let parity_len = stripe_count
                .checked_mul(block_size)
                .ok_or(SarError::Overflow("XOR parity length overflow"))?;
            if parity_len > MAX_PARITY_SIZE {
                return Err(SarError::LimitExceeded(
                    "XOR parity exceeds implementation limit",
                ));
            }
            usize::try_from(14u64 + parity_len)
                .map_err(|_| SarError::Overflow("XOR FEC value length exceeds usize"))
        }
        FEC_ALGO_REED_SOLOMON => {
            sar_fec::RsCodec::new(fec.config0, fec.config1, fec.symbol_size)
                .map_err(SarError::from)?;

            let group_bytes = u64::from(fec.config0)
                .checked_mul(u64::from(fec.symbol_size))
                .ok_or(SarError::Overflow("RS group size overflow"))?;
            let group_count = ceil_div_u64(original_len, group_bytes)?;
            let parity_len = group_count
                .checked_mul(u64::from(fec.config1))
                .ok_or(SarError::Overflow("RS parity count × group overflow"))?
                .checked_mul(u64::from(fec.symbol_size))
                .ok_or(SarError::Overflow("RS parity length overflow"))?;
            if parity_len > MAX_PARITY_SIZE {
                return Err(SarError::LimitExceeded(
                    "RS parity exceeds implementation limit",
                ));
            }
            usize::try_from(18u64 + parity_len)
                .map_err(|_| SarError::Overflow("RS FEC value length exceeds usize"))
        }
        other => Err(SarError::Unsupported(if (0x10..=0x1F).contains(&other) {
            "FEC algorithm is assigned but not supported by archive writer"
        } else {
            "FEC algorithm ID out of defined range"
        })),
    }
}

fn ceil_div_u64(a: u64, b: u64) -> Result<u64, SarError> {
    if b == 0 {
        return Err(SarError::Overflow("ceil_div by zero"));
    }
    a.checked_add(b - 1)
        .ok_or(SarError::Overflow("ceil_div overflow"))?
        .checked_div(b)
        .ok_or(SarError::Overflow("ceil_div"))
}

/// Maps a [`sar_delta::PatchError`] to a [`SarError`].
pub(crate) fn map_patch_error(e: sar_delta::PatchError) -> SarError {
    match e {
        sar_delta::PatchError::PatchFailed(m) => SarError::PatchFailed(m),
        sar_delta::PatchError::Unsupported(m) => SarError::Unsupported(m),
        sar_delta::PatchError::ReservedValue(m) => SarError::ReservedValue(m),
        sar_delta::PatchError::BaseMissing(m) => SarError::BaseMissing(m),
        sar_delta::PatchError::LimitExceeded(m) => SarError::LimitExceeded(m),
    }
}

/// Fails closed on a non-literal CDC Algo ID.
///
/// The reader performs no CDC recipe resolution, so a non-literal algorithm
/// means the reconstructed bytes are an unresolved Hash Recipe, which must not
/// be returned as a logical Entry (specification Sections 13.1.3 and 20.3).
pub(crate) fn require_literal_cdc(cdc_algo_id: Option<u8>) -> Result<(), SarError> {
    if cdc_algo_id.is_some_and(|id| id != sar_core::cdc::CDC_ALGO_LITERAL) {
        return Err(SarError::Unsupported(
            "CDC recipe resolution is not implemented; a non-literal CDC Algo ID cannot be reconstructed",
        ));
    }
    Ok(())
}

/// Applies the group-wide patch stage once to a complete patch representation.
///
/// `patch_representation` is the decoded contribution of an unfragmented Entry,
/// or the complete Fragment Reassembly Sequence of a fragment group.  The output
/// length is determined by the patch construction and is never compared with
/// an LFH `Uncompressed Size`.  Patch input and output are bounded by
/// `max_total_pipeline_memory` while both are live, and the output by
/// `max_decoded_entry_size`, before the output is allocated.
pub(crate) fn apply_patch_stage(
    options: &ArchiveReaderOptions,
    patch_algo_id: u8,
    delta_base_hash: [u8; 32],
    patch_representation: Vec<u8>,
) -> Result<Vec<u8>, SarError> {
    let limits = &options.limits;
    let require_base = |zero_hash: &'static str, no_base: &'static str| {
        if delta_base_hash == ZERO_DELTA_BASE_HASH {
            return Err(SarError::BaseMissing(zero_hash));
        }
        options
            .delta_base
            .as_deref()
            .ok_or(SarError::BaseMissing(no_base))
    };
    match patch_algo_id {
        PATCH_ALGO_STORE_PATCH => {
            let len = u64::try_from(patch_representation.len())
                .map_err(|_| SarError::Overflow("patch representation length"))?;
            limits.check_decoded_entry_size(len)?;
            Ok(patch_representation)
        }
        PATCH_ALGO_VCDIFF => {
            validate_delta_pre_dispatch(patch_representation.len(), limits)?;
            let base = require_base(
                "VCDIFF: all-zero Delta Base Hash indicates missing base",
                "VCDIFF: no base bytes supplied in reader options",
            )?;
            let vcdiff_limits =
                vcdiff_limits_from_resource_limits(limits, patch_representation.len())?;
            apply_vcdiff(base, &patch_representation, &vcdiff_limits).map_err(map_patch_error)
        }
        PATCH_ALGO_BSDIFF => {
            validate_delta_pre_dispatch(patch_representation.len(), limits)?;
            let base = require_base(
                "BSDIFF: all-zero Delta Base Hash indicates missing base",
                "BSDIFF: no base bytes supplied in reader options",
            )?;
            let bsdiff_limits =
                bsdiff_limits_from_resource_limits(limits, patch_representation.len())?;
            apply_bsdiff(base, &patch_representation, &bsdiff_limits).map_err(map_patch_error)
        }
        PATCH_ALGO_ZSTD_PATCH => Err(SarError::Unsupported(
            "ZSTD_PATCH: dictionary protocol not specified; not implemented",
        )),
        id if id >= PATCH_ALGO_CUSTOM_MIN => Err(SarError::Unsupported(
            "CUSTOM patch algorithm not supported",
        )),
        _ => Err(SarError::ReservedValue("reserved patch algorithm ID")),
    }
}

/// Returns the output budget for a patch whose representation is
/// `patch_len` bytes: `max_decoded_entry_size`, reduced so that the
/// representation and the output together stay within
/// `max_total_pipeline_memory`.
fn patch_output_budget(limits: &ResourceLimits, patch_len: usize) -> Result<u64, SarError> {
    let patch_len =
        u64::try_from(patch_len).map_err(|_| SarError::Overflow("patch representation length"))?;
    let remaining = limits
        .max_total_pipeline_memory
        .checked_sub(patch_len)
        .ok_or(SarError::LimitExceeded(
            "delta patch representation exceeds max_total_pipeline_memory",
        ))?;
    Ok(limits.max_decoded_entry_size.min(remaining))
}

/// Performs cheap reader-side delta checks before dispatching to a patch decoder.
/// This catches obviously excessive patch payload sizes before
/// VCDIFF/BSDIFF-specific parsing begins.
pub(crate) fn validate_delta_pre_dispatch(
    patch_payload_len: usize,
    limits: &ResourceLimits,
) -> Result<(), SarError> {
    let patch_payload_len = u64::try_from(patch_payload_len)
        .map_err(|_| SarError::Overflow("delta patch payload length exceeds u64"))?;

    if patch_payload_len > limits.max_in_memory_buffer {
        return Err(SarError::LimitExceeded(
            "delta patch payload exceeds max_in_memory_buffer",
        ));
    }

    Ok(())
}

/// Builds a [`BsdiffLimits`] from the unified [`ResourceLimits`].
pub(crate) fn bsdiff_limits_from_resource_limits(
    r: &ResourceLimits,
    patch_len: usize,
) -> Result<BsdiffLimits, SarError> {
    let max_target_size = patch_output_budget(r, patch_len)?;
    Ok(BsdiffLimits {
        max_patch_size: r.max_in_memory_buffer,
        max_control_bytes: r.max_bsdiff_control_bytes,
        max_diff_bytes: r.max_bsdiff_diff_bytes,
        max_extra_bytes: r.max_bsdiff_extra_bytes,
        max_control_triples: r.max_bsdiff_control_triples,
        max_target_size,
    })
}

/// Builds a [`VcdiffLimits`] from the unified [`ResourceLimits`].
pub(crate) fn vcdiff_limits_from_resource_limits(
    r: &ResourceLimits,
    patch_len: usize,
) -> Result<VcdiffLimits, SarError> {
    let budget = patch_output_budget(r, patch_len)?;
    let max_output = if r.max_vcdiff_output_size == 0 {
        budget
    } else {
        r.max_vcdiff_output_size.min(budget)
    };
    Ok(VcdiffLimits {
        max_patch_size: r.max_in_memory_buffer,
        max_window_count: r.max_vcdiff_window_count,
        max_instruction_count: r.max_vcdiff_instruction_count,
        max_output_size: max_output,
    })
}

#[cfg(test)]
mod nonce_reuse_tests {
    use super::*;
    use sar_core::SarStatus;

    #[test]
    fn repeated_nonce_aborts_with_nonce_reuse() {
        let mut used = HashSet::new();
        let fixed = |field: &mut [u8; 24]| {
            field[..12].copy_from_slice(&[0x11; 12]);
            Ok(())
        };
        let first = reserve_unique_nonce(&mut used, fixed).expect("first nonce is fresh");
        assert_eq!(&first[..12], &[0x11; 12]);

        let mut calls = 0;
        let err = reserve_unique_nonce(&mut used, |field| {
            calls += 1;
            field[..12].copy_from_slice(&[0x11; 12]);
            Ok(())
        })
        .expect_err("reuse must abort");
        assert_eq!(err.status(), SarStatus::ErrNonceReuse);
        assert_eq!(calls, NONCE_GENERATION_ATTEMPTS);
        assert_eq!(used.len(), 1, "a rejected nonce is not recorded twice");
    }

    #[test]
    fn collision_is_retried_and_fresh_nonce_succeeds() {
        let mut used = HashSet::new();
        reserve_unique_nonce(&mut used, |field| {
            field[0] = 1;
            Ok(())
        })
        .expect("first");
        let mut sequence = [1u8, 2u8].into_iter();
        let second = reserve_unique_nonce(&mut used, |field| {
            field[0] = sequence.next().expect("sequence");
            Ok(())
        })
        .expect("retry succeeds");
        assert_eq!(second[0], 2);
        assert_eq!(used.len(), 2);
    }
}
