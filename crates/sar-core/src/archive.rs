use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};

use sar_compression::COMP_ALGO_STORE;
use sar_crypto::aad::build_aead_aad;
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, KeyProvider, KmsContext, KmsParams, SecretBytes,
    aead::generate_nonce,
    kms::types::{parse_kms_payload, serialize_kms_payload},
    provider::resolve_cek,
    validate_encr_algo_id,
};
use sar_delta::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH, PATCH_ALGO_VCDIFF,
    PATCH_ALGO_ZSTD_PATCH, apply_store_patch,
};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR, FecOptions, types::FecCodec};
use serde::Serialize;

use crate::{
    error::SarError,
    flags::{EntryMode, GlobalFlags, validate_global_flags},
    format::{
        CentralDictionary, Footer, GlobalHeader, KmsData, LocalFileHeader, SUPPORTED_CD_VERSION,
        global_header_flags_bytes, lfh_bytes_for_aad, lfh_to_bytes, parse_central_dictionary,
        parse_footer, parse_global_header, parse_lfh, write_central_dictionary, write_footer,
        write_global_header,
    },
    limits::ResourceLimits,
    tlv::Tlv,
    transform::{
        DecodingPlanV2, EncodingPlanV2, EntryCryptoContext, decode_payload_v2, encode_payload_v2,
    },
};

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
    /// Name bytes interpreted as UTF-8 lossily.
    pub name: String,
    /// Optional path bytes interpreted as UTF-8 lossily.
    pub path: Option<String>,
    /// Encoded payload size.
    pub payload_size: u64,
    /// Logical uncompressed size.
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
    pub fec: Option<crate::fec::FecSummary>,
    /// Fragment ID shared by all fragments of one logical file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_id: Option<u32>,
    /// Zero-based fragment sequence index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_index: Option<u32>,
    /// Typed fragment descriptor (absolute offset + declared size).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_descriptor: Option<crate::fragment::FragmentDescriptor>,
    /// True when the `IS_FRAGMENT` entry mode bit is set.
    pub is_fragment: bool,
    /// True when the `LAST_FRAGMENT` entry mode bit is set.
    pub is_last_fragment: bool,
    /// True when the `LOSS_TOLERANT` entry mode bit is set.
    pub is_loss_tolerant: bool,
    /// Parsed sparse extents.  `None` when `SPARSE_FILES` is not enabled or
    /// the sparse map is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse_extents: Option<Vec<crate::sparse::SparseExtent>>,
    /// Per-file CRC32.  `None` when `PER_FILE_CRC` global flag is not set
    /// or the field contains zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_crc32: Option<u32>,
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
    /// `STORE_PATCH` (`0x00`) is implemented: the decoded patch payload is the
    /// complete reconstructed target logical byte sequence.
    ///
    /// `VCDIFF` (`0x01`), `BSDIFF` (`0x02`), and `ZSTD_PATCH` (`0x03`) are
    /// assigned but not yet implemented; reading an entry with any of these
    /// algorithms returns `SAR_ERR_UNSUPPORTED`.
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
    /// For fragmented entries, fragments have been assembled at their declared
    /// absolute offsets.  For sparse entries, holes are zero-filled.
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

/// Writer input.
#[derive(Debug, Clone)]
pub struct EntryInput {
    /// Entry name.
    pub name: String,
    /// Entry payload bytes.
    pub payload: Vec<u8>,
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

/// Encryption settings for archive writing.
#[derive(Debug, Clone)]
pub struct EncryptionSettings {
    /// AEAD algorithm ID (`ENCR_AES256_GCM` or `ENCR_XCHACHA20_POLY`).
    pub algo_id: u8,
    /// KMS parameters used to resolve and serialize the CEK.
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
    /// If `true`, set the global `SPARSE_FILES` flag.  Required before calling
    /// [`ArchiveWriter::write_sparse_entry`].
    pub sparse: bool,
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
            sparse: false,
        }
    }
}

/// Options for writing a sparse entry with [`ArchiveWriter::write_sparse_entry`].
///
/// The caller supplies:
/// * `logical_size` — full apparent file size including all sparse holes, stored as
///   LFH `Uncompressed Size`.  Must be >= the end of every declared extent.
/// * `extents` — ordered, non-overlapping sparse extents describing how
///   `gathered_payload` maps into the logical file.  The sum of all
///   `extent.length` values must equal the length of the `gathered_payload`
///   slice passed to [`ArchiveWriter::write_sparse_entry`].
///
/// The writer validates all constraints before emitting any bytes.
#[derive(Debug, Clone)]
pub struct SparseWriteOptions {
    /// Full logical file size, including all sparse holes.  This becomes the
    /// LFH `Uncompressed Size` and is **required** to be set explicitly.
    /// The writer will not derive this value from the extents alone.
    pub logical_size: u64,
    /// Ordered, non-overlapping sparse extents that describe the data regions.
    pub extents: Vec<crate::sparse::SparseExtent>,
}

/// Reader-side limits.
///
/// Pass a [`ResourceLimits`] value to configure all resource caps uniformly.
/// The [`ArchiveReaderOptions::max_decoded_entry_size`] method provides
/// backward-compatible access to the corresponding limit value.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArchiveReaderOptions {
    /// Unified resource limits for parsing and reconstruction.
    pub limits: ResourceLimits,
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

/// Streaming archive reader over a seekable source.
pub struct ArchiveReader<R> {
    reader: R,
    options: ArchiveReaderOptions,
    global_header: Option<GlobalHeader>,
    global_flags_section: Vec<u8>,
    header_len: u64,
    data_end: u64,
    next_offset: u64,
    file_len: u64,
    cd: Option<CentralDictionary>,
    key_provider: Option<Box<dyn KeyProvider>>,
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
            global_flags_section: Vec::new(),
            header_len: 0,
            data_end: 0,
            next_offset: 0,
            file_len,
            cd: None,
            key_provider: None,
        })
    }

    /// Attach a key provider used for encrypted entry decoding.
    #[must_use]
    pub fn with_key_provider(mut self, key_provider: Box<dyn KeyProvider>) -> Self {
        self.key_provider = Some(key_provider);
        self
    }

    /// Parses and returns the global header.
    pub fn read_global_header(&mut self) -> Result<GlobalHeader, SarError> {
        self.reader.seek(SeekFrom::Start(0))?;

        let mut fixed = [0u8; 8];
        self.reader.read_exact(&mut fixed)?;
        let flags_size = usize::from(u16::from_le_bytes([fixed[6], fixed[7]]));
        if flags_size < 4 {
            return Err(SarError::InvalidLength("global flags size must be >= 4"));
        }
        self.options.limits.check_global_flags_bytes(flags_size)?;

        let mut header_bytes = Vec::with_capacity(8 + flags_size + 96 + 5);
        header_bytes.extend_from_slice(&fixed);
        let mut flags_buf = vec![0u8; flags_size];
        self.reader.read_exact(&mut flags_buf)?;
        header_bytes.extend_from_slice(&flags_buf);

        let mut low = [0u8; 4];
        low.copy_from_slice(&flags_buf[..4]);
        let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
        validate_global_flags(flags)?;

        if flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) {
            let mut descriptor = [0u8; 96];
            self.reader.read_exact(&mut descriptor)?;
            header_bytes.extend_from_slice(&descriptor);
        }

        if flags.contains(GlobalFlags::ENCRYPTED) {
            let mut kms_prefix = [0u8; 5];
            self.reader.read_exact(&mut kms_prefix)?;
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
            self.reader.read_exact(&mut payload)?;
            header_bytes.extend_from_slice(&payload);
        }

        let (header, consumed) = parse_global_header(&header_bytes, &self.options.limits)?;
        if let Some(kms) = &header.kms {
            let _ = parse_kms_payload(kms.mode_id, &kms.payload).map_err(SarError::from)?;
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
            self.reader.read_exact(&mut footer_bytes)?;
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
            self.reader.read_exact(&mut cd_bytes)?;
            let (cd, consumed_cd) =
                parse_central_dictionary(&cd_bytes, header.flags, &self.options.limits)?;
            if consumed_cd > cd_bytes.len() {
                return Err(SarError::Truncated("CD parse exceeded available bytes"));
            }
            if cd_bytes[consumed_cd..].iter().any(|byte| *byte != 0) {
                return Err(SarError::InvalidAlignment(
                    "CD alignment padding must be all zero",
                ));
            }
            (cd_offset, Some(cd))
        };

        self.global_flags_section = global_header_flags_bytes(&header);
        self.global_header = Some(header.clone());
        self.header_len = header_len;
        self.data_end = data_end;
        self.next_offset = header_len;
        self.cd = cd;

        Ok(header)
    }

    /// Reads the next archive entry sequentially.
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
        self.reader.read_exact(&mut header_size_bytes)?;
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
            self.reader.read_exact(&mut lfh_bytes[4..])?;
        }

        let (lfh, _) = parse_lfh(&lfh_bytes, &header.flags, &self.options.limits)?;
        let is_effectively_compressed =
            header.flags.contains(GlobalFlags::COMPRESSED) && lfh.entry_mode.is_compressed();
        let is_encrypted = lfh.entry_mode.is_encrypted();

        if is_encrypted && !header.flags.contains(GlobalFlags::ENCRYPTED) {
            return Err(SarError::FlagConflict(
                "IS_ENCRYPTED requires global ENCRYPTED",
            ));
        }

        let effective_comp_algo_id = if is_effectively_compressed {
            lfh.comp_algo_id.unwrap_or(COMP_ALGO_STORE)
        } else {
            COMP_ALGO_STORE
        };

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
        self.reader.read_exact(&mut encoded_payload)?;

        let crypto = if is_encrypted {
            let algo_id = lfh.encr_algo_id.ok_or(SarError::Malformed(
                "encrypted entry missing encryption algorithm ID",
            ))?;
            validate_encr_algo_id(algo_id).map_err(SarError::from)?;
            let provider = self.key_provider.as_deref().ok_or(SarError::KeyMissing(
                "no key provider configured for encrypted archive",
            ))?;
            let context = build_kms_context(&header)?;
            let key = resolve_cek(provider, &context).map_err(SarError::from)?;
            let iv_nonce = lfh.iv_nonce.ok_or(SarError::Malformed(
                "encrypted entry missing IV/nonce field",
            ))?;
            // Per spec §13.2.1: when SELECTIVE_FEC is active and FEC Algo ID is
            // non-zero, FEC Size and FEC Value are excluded from the AAD.
            let fec_algo_id = lfh.fec_algo_id.unwrap_or(0);
            let aad_lfh_bytes =
                lfh_bytes_for_aad(header.flags, &lfh_bytes, fec_algo_id, lfh.fec_value.len())?;
            let aad = build_aead_aad(&self.global_flags_section, &aad_lfh_bytes);
            Some(EntryCryptoContext {
                algo_id,
                iv_nonce,
                aad,
                key,
            })
        } else {
            None
        };

        // For sparse entries, `uncompressed_size` is the final logical file size
        // (including holes), not the decoded payload byte count.  The decoded
        // payload equals the sum of sparse extent lengths, which may be much
        // smaller than the logical size.  Pass a permissive upper bound so the
        // decompressor does not refuse to run.
        let is_sparse =
            header.flags.contains(GlobalFlags::SPARSE_FILES) && !lfh.sparse_map.is_empty();

        // STORE_PATCH resource-limit guard: reject before any allocation when the
        // declared Uncompressed Size exceeds the configured limit.  Non-sparse
        // entries are already protected by the `expected_output_size` path inside
        // `decode_payload_v2`, but sparse entries pass `max_decoded_entry_size` as
        // the upper bound there; an explicit check is required for those too.
        let is_has_delta = header.flags.contains(GlobalFlags::HAS_DELTA);
        let patch_raw_id = lfh.patch_algo_id.unwrap_or(0);
        if is_has_delta && patch_raw_id == PATCH_ALGO_STORE_PATCH {
            self.options
                .limits
                .check_decoded_entry_size(lfh.uncompressed_size)?;
        }

        // STORE_PATCH pre-decode length guard for non-compressed, non-encrypted
        // entries: the decoded patch payload equals the raw encoded payload, so a
        // mismatch between `payload_size` and `Uncompressed Size` is detectable
        // before `decode_payload_v2`.  Return PatchFailed rather than letting the
        // STORE decompressor's output-limit enforcement produce LimitExceeded.
        if is_has_delta
            && patch_raw_id == PATCH_ALGO_STORE_PATCH
            && !is_effectively_compressed
            && !is_encrypted
            && !is_sparse
            && lfh.payload_size != lfh.uncompressed_size
        {
            return Err(SarError::PatchFailed(
                "STORE_PATCH: raw payload length does not match LFH Uncompressed Size",
            ));
        }

        let decode_expected = if is_sparse {
            // We don't want the decompressor to be bounded by logical_size;
            // max_decoded_entry_size is already the correct upper bound.
            self.options.max_decoded_entry_size()
        } else {
            lfh.uncompressed_size
        };

        let decoded = decode_payload_v2(
            &encoded_payload,
            DecodingPlanV2 {
                is_compressed: is_effectively_compressed,
                comp_algo_id: effective_comp_algo_id,
                expected_output_size: decode_expected,
                max_output_size: self.options.max_decoded_entry_size(),
                crypto,
            },
        )?;

        // Apply delta patch when `HAS_DELTA` is active.
        //
        // Transformation order (spec §8.4 / §6.1):
        //   FEC repair (done above)  →  AEAD decrypt (decode_payload_v2)  →
        //   decompress (decode_payload_v2)  →  patch application  →
        //   sparse reconstruction (read_all_logical_files)
        let decoded = if is_has_delta {
            match patch_raw_id {
                PATCH_ALGO_STORE_PATCH => {
                    // STORE_PATCH: the decoded payload IS the complete reconstructed
                    // target logical byte sequence.  No base read.  No instruction
                    // stream.  No external dictionary.
                    //
                    // For non-sparse entries the output length must equal
                    // Uncompressed Size exactly; sparse reconstruction handles the
                    // final logical size for sparse entries.
                    if !is_sparse {
                        apply_store_patch(&decoded, lfh.uncompressed_size).map_err(|e| match e {
                            sar_delta::PatchError::PatchFailed(m) => SarError::PatchFailed(m),
                            sar_delta::PatchError::Unsupported(m) => SarError::Unsupported(m),
                            sar_delta::PatchError::ReservedValue(m) => SarError::ReservedValue(m),
                        })?
                    } else {
                        decoded
                    }
                }
                PATCH_ALGO_VCDIFF | PATCH_ALGO_BSDIFF | PATCH_ALGO_ZSTD_PATCH => {
                    return Err(SarError::Unsupported("patch algorithm not yet implemented"));
                }
                id if id >= PATCH_ALGO_CUSTOM_MIN => {
                    return Err(SarError::Unsupported(
                        "CUSTOM patch algorithm not supported",
                    ));
                }
                _ => {
                    return Err(SarError::ReservedValue("reserved patch algorithm ID"));
                }
            }
        } else {
            decoded
        };

        if !is_sparse {
            if u64::try_from(decoded.len())
                .map_err(|_| SarError::Overflow("decoded payload len"))?
                != lfh.uncompressed_size
            {
                return Err(SarError::InvalidLength(
                    "decoded payload size does not match LFH Uncompressed Size",
                ));
            }
            if !is_effectively_compressed
                && !is_encrypted
                && lfh.payload_size != lfh.uncompressed_size
            {
                return Err(SarError::InvalidLength(
                    "STORE mode requires Payload Size == Uncompressed Size",
                ));
            }
        }

        let fec = if header.flags.contains(GlobalFlags::SELECTIVE_FEC) {
            let algo_id = lfh.fec_algo_id.unwrap_or(0);
            crate::fec::parse_lfh_fec_value(algo_id, &lfh.fec_value, &self.options.limits)?
        } else {
            None
        };

        let metadata = EntryMetadata {
            lfh_offset: self.next_offset,
            name: String::from_utf8_lossy(&lfh.name).into_owned(),
            path: if lfh.path.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&lfh.path).into_owned())
            },
            payload_size: lfh.payload_size,
            uncompressed_size: lfh.uncompressed_size,
            compression_algo_id: effective_comp_algo_id,
            compression_algorithm: compression_algorithm_name(effective_comp_algo_id),
            is_compressed: is_effectively_compressed,
            fec,
            fragment_id: lfh.fragment_id,
            fragment_index: lfh.fragment_index,
            fragment_descriptor: lfh.fragment_descriptor.as_ref().map(|fd| {
                crate::fragment::FragmentDescriptor {
                    absolute_offset: fd.absolute_offset,
                    fragment_size: fd.fragment_size,
                }
            }),
            is_fragment: lfh.entry_mode.is_fragment(),
            is_last_fragment: lfh.entry_mode.is_last_fragment(),
            is_loss_tolerant: lfh.entry_mode.is_loss_tolerant(),
            sparse_extents: if header.flags.contains(GlobalFlags::SPARSE_FILES)
                && !lfh.sparse_map.is_empty()
            {
                let is_64bit = header.flags.contains(GlobalFlags::SIZE_64BIT);
                Some(crate::sparse::parse_sparse_map(
                    &lfh.sparse_map,
                    is_64bit,
                    &self.options.limits,
                )?)
            } else {
                None
            },
            file_crc32: lfh.file_crc32,
            content_hash: lfh.content_hash,
            cdc_algo_id: if header.flags.contains(GlobalFlags::CDC_SUPPORT) {
                // `lfh.cdc_algo_id` is `None` when parsing an archive written by
                // an older implementation that sets `CDC_SUPPORT` but omits the
                // per-entry byte.  Default to `LITERAL_MODE (0x00)` so validation
                // still proceeds — 0x00 is always valid and never triggers a
                // chunking path, making it the safest conservative fallback.
                let algo_id = lfh.cdc_algo_id.unwrap_or(0);
                crate::cdc::validate_cdc_algo_id(algo_id)?;
                Some(algo_id)
            } else {
                None
            },
            // Patch fields: present when HAS_DELTA is globally set.
            // Registry validation and patch application have already been performed
            // above; this block only surfaces the validated ID and opaque hash bytes.
            patch_algo_id: if is_has_delta {
                Some(patch_raw_id)
            } else {
                None
            },
            delta_base_hash: if is_has_delta {
                // Preserved as opaque 32 bytes.  No hash algorithm is assumed.
                // All-zero bytes mean "no base required" for STORE_PATCH; the
                // field is still preserved verbatim for all other algorithms.
                Some(lfh.delta_base_hash.unwrap_or([0u8; 32]))
            } else {
                None
            },
        };

        self.next_offset = payload_end;

        Ok(Some(EntryReader {
            header: lfh,
            payload: decoded,
            metadata,
        }))
    }

    /// Verifies archive structure and index consistency.
    pub fn verify(&mut self) -> Result<VerificationReport, SarError> {
        if self.global_header.is_none() {
            let _ = self.read_global_header()?;
        }

        let global = self
            .global_header
            .as_ref()
            .ok_or(SarError::Malformed("global header missing"))?
            .clone();

        self.next_offset = self.header_len;
        let mut offsets = Vec::new();
        let mut cdc_entry_count: u64 = 0;
        while let Some(entry) = self.next_entry()? {
            offsets.push(entry.metadata.lfh_offset);
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
                .any(|tlv| crate::cdc::is_cdc_metadata_tlv_type(tlv.type_id));
            if has_cdc_metadata && !cdc_support {
                return Err(SarError::FlagConflict(
                    "CDC metadata requires the CDC_SUPPORT global flag",
                ));
            }

            if cd.file_count
                != u64::try_from(offsets.len()).map_err(|_| SarError::Overflow("entry count"))?
            {
                return Err(SarError::InvalidLength("CD file count mismatch"));
            }

            if cd.offsets != offsets {
                return Err(SarError::InvalidMap(
                    "CD offsets do not match Data Area LFH offsets",
                ));
            }

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
                        crate::fec::validate_recovery_tlv(
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
                    if crate::cdc::is_cdc_metadata_tlv_type(tlv.type_id) {
                        crate::cdc::validate_cdc_metadata_tlv(tlv, &self.options.limits)?;
                    }
                }
            }
        }

        Ok(VerificationReport {
            valid: true,
            entry_count: u64::try_from(offsets.len())
                .map_err(|_| SarError::Overflow("entry count"))?,
            indexed: self.cd.is_some(),
            cdc_entry_count,
            cdc_support,
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

    /// Reads all entries from the archive and returns fully reconstructed
    /// logical files.
    ///
    /// This high-level helper handles two cases that [`next_entry`] does not
    /// address automatically:
    ///
    /// * **Fragment groups** — entries sharing a `fragment_id` are assembled
    ///   using [`crate::fragment::reconstruct_fragments`].  All fragments must
    ///   be present unless `allow_lossy` is `true` **and** the group has
    ///   `LOSS_TOLERANT` set.
    /// * **Sparse entries** — when global `SPARSE_FILES` is active and an entry
    ///   carries a sparse map, the raw data segments are scattered into a
    ///   zero-filled logical-size buffer via
    ///   [`crate::sparse::apply_sparse_reconstruction`].
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
    /// # Sparse logical-size derivation
    ///
    /// The logical size for sparse reconstruction is taken from the LFH
    /// `Uncompressed Size` field, which the spec defines as the full logical
    /// file size including trailing holes.  Any gap after the final sparse
    /// extent up to `Uncompressed Size` is reconstructed as `0x00` bytes.
    /// Trailing sparse holes are not a spec gap when `Uncompressed Size` is
    /// available.
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
    /// * [`SarError::InvalidMap`] — overlapping or out-of-bounds sparse extents
    ///   or fragment descriptors.
    /// * [`SarError::Overflow`] — arithmetic overflow or allocation limit
    ///   exceeded.
    /// * [`SarError::Malformed`] — `IS_FRAGMENT` without a `fragment_id`.
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
    /// non-zero fragment index causes [`SarError::InvalidMap`].
    ///
    /// # CRC32 verification
    ///
    /// When the global `PER_FILE_CRC` flag is set and an entry carries a non-zero
    /// `File CRC32` field, the CRC32 is verified against the **fully reconstructed**
    /// logical file bytes (including sparse holes).  A mismatch returns
    /// [`SarError::CrcMismatch`].  LOSS_TOLERANT semantics do not suppress
    /// CRC32 mismatches on complete (non-degraded) output.
    ///
    /// [`next_entry`]: Self::next_entry
    pub fn read_all_logical_files(
        &mut self,
        allow_lossy: bool,
    ) -> Result<Vec<LogicalFile>, SarError> {
        use crate::fragment::{FragmentEntry, reconstruct_fragments};
        use std::collections::HashMap;

        // Ensure global header is read.
        if self.global_header.is_none() {
            self.read_global_header()?;
        }

        let global = self
            .global_header
            .as_ref()
            .ok_or(SarError::Malformed("global header missing after read"))?
            .clone();

        // Reset cursor so callers may invoke this after prior next_entry calls.
        self.next_offset = self.header_len;

        // Collect all decoded entries.
        let mut all_entries: Vec<EntryReader> = Vec::new();
        while let Some(entry) = self.next_entry()? {
            all_entries.push(entry);
        }

        // Preserve insertion order of first-seen fragment IDs.
        let mut frag_order: Vec<u32> = Vec::new();

        /// Accumulator for one logical-file fragment group.
        struct FragGroup {
            /// Name taken from the first-seen fragment entry.
            name: String,
            /// All fragment entries collected so far.
            entries: Vec<EntryReader>,
            /// Sparse extents from fragment index 0.  `None` when this group
            /// has no sparse map.
            sparse_extents: Option<Vec<crate::sparse::SparseExtent>>,
            /// LFH `Uncompressed Size` from fragment index 0 for sparse
            /// reconstruction.  Meaningful only when `sparse_extents.is_some()`.
            sparse_uncompressed_size: u64,
            /// File CRC32 from fragment index 0 for post-assembly verification.
            /// `None` when the entry has no CRC32 field.
            file_crc32: Option<u32>,
        }

        // fragment_id → FragGroup
        let mut frag_groups: HashMap<u32, FragGroup> = HashMap::new();
        let mut result: Vec<LogicalFile> = Vec::new();

        for entry in all_entries {
            // Empty Areas (Name Length == 0, IS_FRAGMENT == 0) must not appear
            // in logical file output.  They do not participate in sparse
            // reconstruction, hashing, delta, or fragmentation.
            if entry.metadata.name.is_empty() && !entry.metadata.is_fragment {
                continue;
            }

            if entry.metadata.is_fragment {
                let fid = entry.metadata.fragment_id.ok_or(SarError::Malformed(
                    "IS_FRAGMENT set but fragment_id is absent",
                ))?;

                // Spec §13.7.6 / §19.6: Sparse Map MUST appear only in the
                // fragment with Fragment Index = 0.  Any other placement is a
                // hard error, even with allow_lossy.
                let has_sparse = entry.metadata.sparse_extents.is_some();
                if has_sparse && entry.metadata.fragment_index != Some(0) {
                    return Err(SarError::InvalidMap(
                        "sparse map present on non-zero fragment index; Sparse Map MUST appear only in fragment with Fragment Index = 0",
                    ));
                }

                let group = frag_groups.entry(fid).or_insert_with(|| {
                    frag_order.push(fid);
                    FragGroup {
                        name: entry.metadata.name.clone(),
                        entries: Vec::new(),
                        sparse_extents: None,
                        sparse_uncompressed_size: 0,
                        file_crc32: None,
                    }
                });
                self.options.limits.check_fragment_count(
                    group
                        .entries
                        .len()
                        .checked_add(1)
                        .ok_or(SarError::Overflow("fragment count"))?,
                )?;

                // Capture sparse map, logical size, and CRC32 from fragment 0.
                if entry.metadata.fragment_index == Some(0) {
                    if has_sparse {
                        group.sparse_extents = entry.metadata.sparse_extents.clone();
                        group.sparse_uncompressed_size = entry.metadata.uncompressed_size;
                    }
                    group.file_crc32 = entry.metadata.file_crc32;
                }

                group.entries.push(entry);
            } else {
                let name = entry.metadata.name.clone();
                let sparse = entry.metadata.sparse_extents.clone();
                let uncompressed_size = entry.metadata.uncompressed_size;
                let file_crc32 = entry.metadata.file_crc32;
                let data = Self::apply_sparse_if_needed(
                    &self.options.limits,
                    entry.payload,
                    &sparse,
                    uncompressed_size,
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
                result.push(LogicalFile {
                    name,
                    fragment_id: None,
                    data,
                    is_degraded: false,
                });
            }
        }

        // Reconstruct each fragment group in first-seen order.
        for fid in frag_order {
            let FragGroup {
                name,
                entries: group_entries,
                sparse_extents: group_sparse_extents,
                sparse_uncompressed_size: group_sparse_uncompressed_size,
                file_crc32: group_file_crc32,
            } = frag_groups.remove(&fid).ok_or(SarError::Malformed(
                "fragment group ID vanished during reconstruction",
            ))?;

            // Compute assembled-payload logical size from FragmentDescriptors:
            // max(descriptor.absolute_offset + descriptor.fragment_size).
            // For sparse+fragment archives this is the intermediate gathered-
            // payload size, not the final logical file size; sparse
            // reconstruction expands it to `group_sparse_uncompressed_size`.
            let mut assembled_size: u64 = 0;
            for e in &group_entries {
                if let Some(desc) = &e.metadata.fragment_descriptor {
                    let end = desc
                        .absolute_offset
                        .checked_add(u64::from(desc.fragment_size))
                        .ok_or(SarError::Overflow("fragment descriptor end overflow"))?;
                    if end > assembled_size {
                        assembled_size = end;
                    }
                }
            }

            // Build FragmentEntry list from decoded payloads.
            let frag_entries: Vec<FragmentEntry> = group_entries
                .into_iter()
                .filter_map(|e| {
                    let desc = e.metadata.fragment_descriptor?;
                    Some(FragmentEntry {
                        fragment_index: e.metadata.fragment_index.unwrap_or(0),
                        is_last_fragment: e.metadata.is_last_fragment,
                        is_loss_tolerant: e.metadata.is_loss_tolerant,
                        descriptor: desc,
                        payload: e.payload,
                    })
                })
                .collect();

            let (raw, is_degraded) =
                reconstruct_fragments(frag_entries, assembled_size, &self.options.limits)?;

            // When the caller does not allow lossy and degraded output was
            // produced by a LOSS_TOLERANT group, surface it as an error.
            if is_degraded && !allow_lossy {
                return Err(SarError::FragmentGap(
                    "fragment group has gaps; use allow_lossy to permit degraded output",
                ));
            }

            // Spec §13.7.6 / §19.6: apply sparse reconstruction over the fully
            // assembled fragment payload.  The sparse map and logical size come
            // from fragment index 0.
            let data = if let Some(ref extents) = group_sparse_extents {
                if group_sparse_uncompressed_size > self.options.max_decoded_entry_size() {
                    return Err(SarError::LimitExceeded(
                        "sparse logical file size exceeds configured limit",
                    ));
                }
                crate::sparse::validate_sparse_extents(
                    extents,
                    group_sparse_uncompressed_size,
                    &self.options.limits,
                )?;
                crate::sparse::apply_sparse_reconstruction(
                    &raw,
                    extents,
                    group_sparse_uncompressed_size,
                    &self.options.limits,
                )?
            } else {
                raw
            };

            // CRC32 verification over the fully reconstructed logical file
            // (after fragment reassembly and sparse reconstruction).
            if global.flags.contains(GlobalFlags::PER_FILE_CRC)
                && let Some(expected_crc) = group_file_crc32
            {
                let computed = crc32fast::hash(&data);
                if computed != expected_crc {
                    return Err(SarError::CrcMismatch(
                        "file CRC32 mismatch on reconstructed fragment-group logical file",
                    ));
                }
            }

            result.push(LogicalFile {
                name,
                fragment_id: Some(fid),
                data,
                is_degraded,
            });
        }

        Ok(result)
    }

    /// Applies sparse reconstruction when `sparse_extents` is `Some` and
    /// non-empty; otherwise returns `payload` unchanged.
    ///
    /// `uncompressed_size` is the LFH `Uncompressed Size` field, which the
    /// spec defines as the full logical file size including trailing holes.
    /// The sparse payload bytes (sum of extent lengths) may be smaller.
    ///
    /// Returns [`SarError::Overflow`] when `uncompressed_size` exceeds
    /// `max_size`, preventing unbounded allocation.
    fn apply_sparse_if_needed(
        limits: &ResourceLimits,
        payload: Vec<u8>,
        sparse_extents: &Option<Vec<crate::sparse::SparseExtent>>,
        uncompressed_size: u64,
    ) -> Result<Vec<u8>, SarError> {
        let Some(extents) = sparse_extents else {
            return Ok(payload);
        };
        if extents.is_empty() {
            return Ok(payload);
        }

        // Use LFH Uncompressed Size as the authoritative logical file size.
        // This correctly handles trailing sparse holes that extend beyond the
        // last extent.
        limits.check_decoded_entry_size(uncompressed_size)?;
        crate::sparse::validate_sparse_extents(extents, uncompressed_size, limits)?;
        crate::sparse::apply_sparse_reconstruction(&payload, extents, uncompressed_size, limits)
    }
}

/// Archive writer with compression and optional encryption support.
pub struct ArchiveWriter<W> {
    writer: W,
    flags: GlobalFlags,
    compression: CompressionSettings,
    position: u64,
    offsets: Vec<u64>,
    cd_metadata: Vec<Tlv>,
    finished: bool,
    cek: Option<SecretBytes>,
    encr_algo_id: Option<u8>,
    used_nonces: HashSet<[u8; 24]>,
    global_flags_section: Vec<u8>,
    fec: Option<FecSettings>,
}

impl<W: Write> ArchiveWriter<W> {
    /// Creates a new archive writer and writes the global header.
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
        mut writer: W,
        options: ArchiveWriterOptions,
        compression: CompressionSettings,
        key_provider: Option<Box<dyn KeyProvider>>,
        cd_metadata: Vec<Tlv>,
    ) -> Result<Self, SarError> {
        if options.no_index && !cd_metadata.is_empty() {
            return Err(SarError::FlagConflict(
                "Central Dictionary metadata requires indexed archive output",
            ));
        }

        let mut flags = GlobalFlags::empty();
        if options.no_index {
            flags |= GlobalFlags::NO_INDEX;
        }
        if !cd_metadata.is_empty() {
            flags |= GlobalFlags::OPT_PRESENT;
        }
        if cd_metadata
            .iter()
            .any(|tlv| crate::cdc::is_cdc_metadata_tlv_type(tlv.type_id))
        {
            flags |= GlobalFlags::CDC_SUPPORT;
        }
        if compression.algo_id != COMP_ALGO_STORE {
            flags |= GlobalFlags::COMPRESSED;
        }
        if options.fec.is_some() {
            flags |= GlobalFlags::SELECTIVE_FEC;
        }
        if options.sparse {
            flags |= GlobalFlags::SPARSE_FILES;
        }

        let mut cek = None;
        let mut encr_algo_id = None;
        let kms = if let Some(encryption) = &options.encryption {
            validate_encr_algo_id(encryption.algo_id).map_err(SarError::from)?;
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
            cek = Some(resolve_cek(provider, &context).map_err(SarError::from)?);
            encr_algo_id = Some(encryption.algo_id);
            Some(KmsData {
                mode_id,
                payload: serialize_kms_payload(&encryption.kms_params),
            })
        } else {
            None
        };

        let limits = ResourceLimits::default();
        for tlv in &cd_metadata {
            if crate::cdc::is_cdc_metadata_tlv_type(tlv.type_id) {
                crate::cdc::validate_cdc_metadata_tlv(tlv, &limits)?;
            }
        }

        validate_global_flags(flags)?;
        let header = GlobalHeader {
            version: 0x01,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms,
        };
        let global_flags_section = global_header_flags_bytes(&header);
        let bytes = write_global_header(&header)?;
        writer.write_all(&bytes)?;

        Ok(Self {
            writer,
            flags,
            compression,
            position: u64::try_from(bytes.len()).map_err(|_| SarError::Overflow("header len"))?,
            offsets: Vec::new(),
            cd_metadata,
            finished: false,
            cek,
            encr_algo_id,
            used_nonces: HashSet::new(),
            global_flags_section,
            fec: options.fec,
        })
    }

    /// Adds one archive entry.
    pub fn add_entry(&mut self, entry: EntryInput) -> Result<EntryWritten, SarError> {
        if self.finished {
            return Err(SarError::Malformed("archive writer already finished"));
        }

        let uncompressed_len =
            u64::try_from(entry.payload.len()).map_err(|_| SarError::Overflow("payload len"))?;
        let is_compressed = self.compression.algo_id != COMP_ALGO_STORE;
        let mut encoded_payload = encode_payload_v2(
            &entry.payload,
            EncodingPlanV2 {
                is_compressed,
                comp_algo_id: self.compression.algo_id,
                compression_level: self.compression.level,
                crypto: None,
            },
        )?;
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
        let mut lfh = LocalFileHeader::minimal_store(entry.name.into_bytes(), payload_len);
        lfh.uncompressed_size = uncompressed_len;
        if self.flags.contains(GlobalFlags::CDC_SUPPORT) {
            lfh.cdc_algo_id = Some(crate::cdc::CDC_ALGO_LITERAL);
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
            let mut nonce = [0u8; 24];
            let mut inserted = false;
            for _ in 0..3 {
                generate_nonce(algo_id, &mut nonce).map_err(SarError::from)?;
                if self.used_nonces.insert(nonce) {
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                return Err(SarError::NonceReuse("failed to generate a unique nonce"));
            }
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
            let aad = build_aead_aad(&self.global_flags_section, &aad_lfh_bytes);
            let key = self
                .cek
                .as_ref()
                .ok_or(SarError::KeyMissing("writer CEK is unavailable"))?;
            encoded_payload = encode_payload_v2(
                &entry.payload,
                EncodingPlanV2 {
                    is_compressed,
                    comp_algo_id: self.compression.algo_id,
                    compression_level: self.compression.level,
                    crypto: Some(EntryCryptoContext {
                        algo_id,
                        iv_nonce: nonce,
                        aad,
                        key: key.clone(),
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
        self.writer.write_all(&lfh_bytes)?;
        self.writer.write_all(&encoded_payload)?;

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
        self.offsets.push(lfh_offset);

        let _ = lfh;
        Ok(EntryWritten {
            lfh_offset,
            total_bytes: written,
        })
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
            return Err(SarError::Malformed("archive writer already finished"));
        }
        if !self.flags.contains(GlobalFlags::SPARSE_FILES) {
            return Err(SarError::Malformed(
                "write_sparse_entry requires ArchiveWriterOptions::sparse = true",
            ));
        }

        // Validate extents against logical_size (overlap and bounds).
        crate::sparse::validate_sparse_extents(
            &sparse.extents,
            sparse.logical_size,
            &ResourceLimits::unlimited(),
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
            return Err(SarError::InvalidMap(
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

        // Build LFH: uncompressed_size = logical_size (full sparse extent including holes).
        let is_64bit = self.flags.contains(GlobalFlags::SIZE_64BIT);
        let sparse_map_bytes = crate::sparse::write_sparse_map(&sparse.extents, is_64bit);

        let mut lfh = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), encoded_len);
        lfh.uncompressed_size = sparse.logical_size;
        if self.flags.contains(GlobalFlags::CDC_SUPPORT) {
            lfh.cdc_algo_id = Some(crate::cdc::CDC_ALGO_LITERAL);
        }
        lfh.sparse_map = sparse_map_bytes;
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
            let mut nonce = [0u8; 24];
            let mut inserted = false;
            for _ in 0..3 {
                generate_nonce(algo_id, &mut nonce).map_err(SarError::from)?;
                if self.used_nonces.insert(nonce) {
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                return Err(SarError::NonceReuse("failed to generate a unique nonce"));
            }
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
            let aad = build_aead_aad(&self.global_flags_section, &aad_lfh_bytes);
            let key = self
                .cek
                .as_ref()
                .ok_or(SarError::KeyMissing("writer CEK is unavailable"))?;
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
                        key: key.clone(),
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
    pub fn finish(mut self) -> Result<ArchiveSummary, SarError> {
        if self.finished {
            return Err(SarError::Malformed("archive writer already finished"));
        }

        if !self.flags.contains(GlobalFlags::NO_INDEX) {
            let cd_offset = self.position;
            let file_count = u64::try_from(self.offsets.len())
                .map_err(|_| SarError::Overflow("offset count"))?;
            let cd = CentralDictionary {
                version: SUPPORTED_CD_VERSION,
                file_count,
                partition_info: None,
                global_crc32: None,
                metadata: self.cd_metadata.clone(),
                offsets: self.offsets.clone(),
            };
            let cd_bytes = write_central_dictionary(&cd, self.flags)?;
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

            self.writer.write_all(&write_footer(Footer { cd_offset }))?;
            self.position = self
                .position
                .checked_add(8)
                .ok_or(SarError::Overflow("archive position after footer"))?;
        }

        self.finished = true;
        Ok(ArchiveSummary {
            entry_count: u64::try_from(self.offsets.len())
                .map_err(|_| SarError::Overflow("entry count"))?,
            archive_size: self.position,
            indexed: !self.flags.contains(GlobalFlags::NO_INDEX),
        })
    }
}

fn compression_algorithm_name(algo_id: u8) -> &'static str {
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
    }
}

fn build_kms_context(header: &GlobalHeader) -> Result<KmsContext, SarError> {
    let kms = header
        .kms
        .as_ref()
        .ok_or(SarError::Malformed("encrypted archive is missing KMS data"))?;
    let params = parse_kms_payload(kms.mode_id, &kms.payload).map_err(SarError::from)?;
    Ok(KmsContext {
        mode_id: kms.mode_id,
        params,
    })
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
