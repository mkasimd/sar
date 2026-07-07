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
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR, FecOptions, types::FecCodec};
use serde::Serialize;

use crate::{
    error::SarError,
    flags::{GlobalFlags, validate_global_flags},
    format::{
        CentralDictionary, Footer, GlobalHeader, KmsData, LocalFileHeader, SUPPORTED_CD_VERSION,
        global_header_flags_bytes, lfh_bytes_for_aad, lfh_to_bytes, parse_central_dictionary,
        parse_footer, parse_global_header, parse_lfh, write_central_dictionary, write_footer,
        write_global_header,
    },
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
}

/// Entry payload reader result.
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
        }
    }
}

/// Reader-side limits.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveReaderOptions {
    /// Maximum allowed uncompressed bytes per decoded entry.
    pub max_decoded_entry_size: u64,
}

impl Default for ArchiveReaderOptions {
    fn default() -> Self {
        Self {
            max_decoded_entry_size: 1024 * 1024 * 1024,
        }
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
            let mut payload = vec![0u8; payload_len];
            self.reader.read_exact(&mut payload)?;
            header_bytes.extend_from_slice(&payload);
        }

        let (header, consumed) = parse_global_header(&header_bytes)?;
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

            if cd_offset >= self.file_len.saturating_sub(8) {
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
            let cd_len_usize = usize::try_from(cd_region_len)
                .map_err(|_| SarError::Overflow("CD region length usize"))?;

            self.reader.seek(SeekFrom::Start(cd_offset))?;
            let mut cd_bytes = vec![0u8; cd_len_usize];
            self.reader.read_exact(&mut cd_bytes)?;
            let (cd, consumed_cd) = parse_central_dictionary(&cd_bytes, header.flags)?;
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

        let (lfh, _) = parse_lfh(&lfh_bytes, &header.flags)?;
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
        let payload_len = usize::try_from(lfh.payload_size)
            .map_err(|_| SarError::Overflow("payload length usize"))?;
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
                lfh_bytes_for_aad(header.flags, &lfh_bytes, fec_algo_id, lfh.fec_value.len());
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

        let decoded = decode_payload_v2(
            &encoded_payload,
            DecodingPlanV2 {
                is_compressed: is_effectively_compressed,
                comp_algo_id: effective_comp_algo_id,
                expected_output_size: lfh.uncompressed_size,
                max_output_size: self.options.max_decoded_entry_size,
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

        let fec = if header.flags.contains(GlobalFlags::SELECTIVE_FEC) {
            let algo_id = lfh.fec_algo_id.unwrap_or(0);
            crate::fec::parse_lfh_fec_value(algo_id, &lfh.fec_value)?
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
                Some(crate::sparse::parse_sparse_map(&lfh.sparse_map, is_64bit)?)
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
        while let Some(entry) = self.next_entry()? {
            offsets.push(entry.metadata.lfh_offset);
        }

        if let Some(cd) = &self.cd {
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
                        crate::fec::validate_recovery_tlv(tlv.type_id, &tlv.value)?;
                    }
                }
            }
        }

        Ok(VerificationReport {
            valid: true,
            entry_count: u64::try_from(offsets.len())
                .map_err(|_| SarError::Overflow("entry count"))?,
            indexed: self.cd.is_some(),
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
    /// The logical size for sparse reconstruction is derived as the maximum of
    /// `extent.offset + extent.length` across all extents for that entry.  If
    /// the file has a trailing sparse hole that is not covered by any extent,
    /// the derived size will be smaller than the true logical size.  This is a
    /// known spec gap; see `docs/SPEC_QUESTIONS.md`.
    ///
    /// Sparse logical sizes are capped to
    /// [`ArchiveReaderOptions::max_decoded_entry_size`].
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

        // Reset cursor so callers may invoke this after prior next_entry calls.
        self.next_offset = self.header_len;

        // Collect all decoded entries.
        let mut all_entries: Vec<EntryReader> = Vec::new();
        while let Some(entry) = self.next_entry()? {
            all_entries.push(entry);
        }

        // Preserve insertion order of first-seen fragment IDs.
        let mut frag_order: Vec<u32> = Vec::new();
        // fragment_id → (first_seen_name, Vec<EntryReader>)
        let mut frag_groups: HashMap<u32, (String, Vec<EntryReader>)> = HashMap::new();
        let mut result: Vec<LogicalFile> = Vec::new();

        for entry in all_entries {
            if entry.metadata.is_fragment {
                let fid = entry.metadata.fragment_id.ok_or(SarError::Malformed(
                    "IS_FRAGMENT set but fragment_id is absent",
                ))?;
                let group = frag_groups.entry(fid).or_insert_with(|| {
                    frag_order.push(fid);
                    (entry.metadata.name.clone(), Vec::new())
                });
                group.1.push(entry);
            } else {
                let name = entry.metadata.name.clone();
                let sparse = entry.metadata.sparse_extents.clone();
                let data = Self::apply_sparse_if_needed(
                    entry.payload,
                    &sparse,
                    self.options.max_decoded_entry_size,
                )?;
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
            let (name, group_entries) = frag_groups
                .remove(&fid)
                .expect("fid must be present in map");

            // Compute logical size = max(descriptor.absolute_offset + descriptor.fragment_size).
            let mut logical_size: u64 = 0;
            for e in &group_entries {
                if let Some(desc) = &e.metadata.fragment_descriptor {
                    let end = desc
                        .absolute_offset
                        .checked_add(u64::from(desc.fragment_size))
                        .ok_or(SarError::Overflow("fragment descriptor end overflow"))?;
                    if end > logical_size {
                        logical_size = end;
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

            let (raw, is_degraded) = reconstruct_fragments(frag_entries, logical_size)?;

            // When the caller does not allow lossy and degraded output was
            // produced by a LOSS_TOLERANT group, surface it as an error.
            if is_degraded && !allow_lossy {
                return Err(SarError::FragmentGap(
                    "fragment group has gaps; use allow_lossy to permit degraded output",
                ));
            }

            result.push(LogicalFile {
                name,
                fragment_id: Some(fid),
                data: raw,
                is_degraded,
            });
        }

        Ok(result)
    }

    /// Applies sparse reconstruction when `sparse_extents` is `Some` and
    /// non-empty; otherwise returns `payload` unchanged.
    ///
    /// The sparse logical size is derived as the maximum of
    /// `extent.offset + extent.length` across all extents.  If that value
    /// exceeds `max_size`, an [`SarError::Overflow`] is returned to prevent
    /// unbounded allocation.
    fn apply_sparse_if_needed(
        payload: Vec<u8>,
        sparse_extents: &Option<Vec<crate::sparse::SparseExtent>>,
        max_size: u64,
    ) -> Result<Vec<u8>, SarError> {
        let Some(extents) = sparse_extents else {
            return Ok(payload);
        };
        if extents.is_empty() {
            return Ok(payload);
        }

        // Compute logical size = max extent end.
        let logical_size = extents
            .iter()
            .filter_map(|e| e.offset.checked_add(e.length))
            .max()
            .unwrap_or(0);

        if logical_size > max_size {
            return Err(SarError::Overflow(
                "sparse logical file size exceeds max_decoded_entry_size limit",
            ));
        }

        crate::sparse::validate_sparse_extents(extents, logical_size)?;
        crate::sparse::apply_sparse_reconstruction(&payload, extents, logical_size)
    }
}

/// Archive writer with compression and optional encryption support.
pub struct ArchiveWriter<W> {
    writer: W,
    flags: GlobalFlags,
    compression: CompressionSettings,
    position: u64,
    offsets: Vec<u64>,
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
        Self::new_with_compression_and_key_provider(
            writer,
            options,
            CompressionSettings::store(),
            None,
        )
    }

    /// Creates a new archive writer and writes the global header with compression settings.
    pub fn new_with_compression(
        writer: W,
        options: ArchiveWriterOptions,
        compression: CompressionSettings,
    ) -> Result<Self, SarError> {
        Self::new_with_compression_and_key_provider(writer, options, compression, None)
    }

    /// Creates a new archive writer with compression and an optional key provider.
    pub fn new_with_compression_and_key_provider(
        mut writer: W,
        options: ArchiveWriterOptions,
        compression: CompressionSettings,
        key_provider: Option<Box<dyn KeyProvider>>,
    ) -> Result<Self, SarError> {
        let mut flags = GlobalFlags::empty();
        if options.no_index {
            flags |= GlobalFlags::NO_INDEX;
        }
        if compression.algo_id != COMP_ALGO_STORE {
            flags |= GlobalFlags::COMPRESSED;
        }
        if options.fec.is_some() {
            flags |= GlobalFlags::SELECTIVE_FEC;
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
        if self.flags.contains(GlobalFlags::COMPRESSED) {
            lfh.comp_algo_id = Some(self.compression.algo_id);
        }
        if is_compressed {
            lfh.entry_mode.0 |= 1 << 3;
        }

        // Pre-set FEC algo ID so it is included in the AEAD AAD (spec §13.2.1).
        if is_fec {
            let fec_cfg = self.fec.as_ref().expect("is_fec checked");
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
            lfh.entry_mode.0 |= 1 << 2;

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
            );
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
                let ciphertext_len = encoded_payload.len().saturating_sub(tag_len);
                let ciphertext = &encoded_payload[..ciphertext_len];
                let fec_value = compute_fec_value(self.fec.as_ref().expect("is_fec"), ciphertext)?;
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
                let fec_value =
                    compute_fec_value(self.fec.as_ref().expect("is_fec"), &encoded_payload)?;
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
                metadata: Vec::<Tlv>::new(),
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
