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
use serde::Serialize;

use crate::{
    error::SarError,
    flags::{GlobalFlags, validate_global_flags},
    format::{
        CentralDictionary, Footer, GlobalHeader, KmsData, LocalFileHeader, SUPPORTED_CD_VERSION,
        global_header_flags_bytes, lfh_to_bytes, parse_central_dictionary, parse_footer,
        parse_global_header, parse_lfh, write_central_dictionary, write_footer,
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
}

/// Entry payload reader result.
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
            let aad = build_aead_aad(&self.global_flags_section, &lfh_bytes);
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

            let lfh_bytes = lfh_to_bytes(&lfh, self.flags)?;
            let aad = build_aead_aad(&self.global_flags_section, &lfh_bytes);
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
            self.write_entry(lfh, lfh_bytes, encoded_payload)
        } else {
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
