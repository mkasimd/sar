use std::io::{Read, Seek, SeekFrom, Write};

use serde::Serialize;

use crate::{
    error::SarError,
    flags::{GlobalFlags, validate_global_flags},
    format::{
        CentralDictionary, Footer, GlobalHeader, LocalFileHeader, SUPPORTED_CD_VERSION,
        parse_central_dictionary, parse_footer, parse_global_header, parse_lfh,
        write_central_dictionary, write_footer, write_global_header, write_lfh,
    },
    tlv::Tlv,
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
    /// Payload size.
    pub payload_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
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

/// Writer options.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveWriterOptions {
    /// If true, omit Central Dictionary and Footer.
    pub no_index: bool,
}

impl Default for ArchiveWriterOptions {
    fn default() -> Self {
        Self { no_index: true }
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
#[derive(Debug)]
pub struct ArchiveReader<R> {
    reader: R,
    global_header: Option<GlobalHeader>,
    header_len: u64,
    data_end: u64,
    next_offset: u64,
    file_len: u64,
    cd: Option<CentralDictionary>,
}

impl<R: Read + Seek> ArchiveReader<R> {
    /// Creates a new archive reader.
    pub fn new(mut reader: R) -> Result<Self, SarError> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            global_header: None,
            header_len: 0,
            data_end: 0,
            next_offset: 0,
            file_len,
            cd: None,
        })
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
                .and_then(|v| v.checked_sub(cd_offset))
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
            .ok_or(SarError::Malformed("call read_global_header first"))?;

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

        if header.flags.contains(GlobalFlags::ENCRYPTED) {
            return Err(SarError::Unsupported(
                "encrypted payload processing is not implemented in Milestones 1–3",
            ));
        }

        if lfh.entry_mode.is_encrypted() {
            return Err(SarError::Unsupported(
                "entry-level encryption processing is not implemented in Milestones 1–3",
            ));
        }

        if lfh.entry_mode.is_compressed() && lfh.comp_algo_id.unwrap_or(0) != 0 {
            return Err(SarError::Unsupported(
                "compression algorithms beyond STORE are not implemented",
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
        let payload_len = usize::try_from(lfh.payload_size)
            .map_err(|_| SarError::Overflow("payload length usize"))?;
        let mut payload = vec![0u8; payload_len];
        self.reader.read_exact(&mut payload)?;

        if lfh.payload_size != lfh.uncompressed_size {
            return Err(SarError::InvalidLength(
                "STORE mode requires Payload Size == Uncompressed Size",
            ));
        }

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
        };

        self.next_offset = payload_end;

        Ok(Some(EntryReader {
            header: lfh,
            payload,
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

/// Archive writer for STORE-only archives.
#[derive(Debug)]
pub struct ArchiveWriter<W> {
    writer: W,
    flags: GlobalFlags,
    position: u64,
    offsets: Vec<u64>,
    finished: bool,
}

impl<W: Write> ArchiveWriter<W> {
    /// Creates a new archive writer and writes the global header.
    pub fn new(mut writer: W, options: ArchiveWriterOptions) -> Result<Self, SarError> {
        let mut flags = GlobalFlags::empty();
        if options.no_index {
            flags |= GlobalFlags::NO_INDEX;
        }
        validate_global_flags(flags)?;

        let header = GlobalHeader {
            version: 0x01,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let bytes = write_global_header(&header)?;
        writer.write_all(&bytes)?;

        Ok(Self {
            writer,
            flags,
            position: u64::try_from(bytes.len()).map_err(|_| SarError::Overflow("header len"))?,
            offsets: Vec::new(),
            finished: false,
        })
    }

    /// Adds a STORE entry.
    pub fn add_entry(&mut self, entry: EntryInput) -> Result<EntryWritten, SarError> {
        if self.finished {
            return Err(SarError::Malformed("archive writer already finished"));
        }

        let payload_len =
            u64::try_from(entry.payload.len()).map_err(|_| SarError::Overflow("payload len"))?;
        let lfh = LocalFileHeader::minimal_store(entry.name.into_bytes(), payload_len);
        let lfh_bytes = write_lfh(&self.flags, &lfh)?;

        let lfh_offset = self.position;
        self.writer.write_all(&lfh_bytes)?;
        self.writer.write_all(&entry.payload)?;

        let written = u64::try_from(lfh_bytes.len())
            .map_err(|_| SarError::Overflow("lfh bytes len"))?
            .checked_add(payload_len)
            .ok_or(SarError::Overflow("entry write length"))?;
        self.position = self
            .position
            .checked_add(written)
            .ok_or(SarError::Overflow("archive position"))?;
        self.offsets.push(lfh_offset);

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
