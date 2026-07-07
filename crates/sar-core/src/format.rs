use crate::{
    error::SarError,
    flags::{EntryMode, GlobalFlags, validate_entry_mode_against_global, validate_global_flags},
    io::{BinaryWriter, ParseCursor},
    tlv::{Tlv, parse_tlvs, write_tlvs},
};

const MAGIC: [u8; 4] = *b"SAR!";
const SUPPORTED_GLOBAL_VERSION: u8 = 0x01;
/// Central Dictionary format version supported in Milestones 1–3.
pub const SUPPORTED_CD_VERSION: u8 = 0x01;

/// Parsed KMS extension data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsData {
    /// KMS mode ID.
    pub mode_id: u8,
    /// Mode-specific payload bytes.
    pub payload: Vec<u8>,
}

/// 96-byte partition descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionDescriptor {
    /// Partition set UUID.
    pub partition_set_uuid: [u8; 16],
    /// Zero-based partition index.
    pub partition_index: u32,
    /// Total partitions.
    pub total_partitions: u32,
    /// Previous partition hash.
    pub previous_partition_hash: [u8; 32],
    /// Partition hash.
    pub partition_hash: [u8; 32],
}

/// Global header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalHeader {
    /// Header version.
    pub version: u8,
    /// Raw global flags bytes.
    pub flags_bytes: Vec<u8>,
    /// Parsed low 32-bit flags.
    pub flags: GlobalFlags,
    /// Optional partition descriptor.
    pub partition_descriptor: Option<PartitionDescriptor>,
    /// Optional KMS extension.
    pub kms: Option<KmsData>,
}

/// Local file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileHeader {
    /// Declared header size from header-start to payload-start.
    pub header_size: u32,
    /// Entry mode bits.
    pub entry_mode: EntryMode,
    /// Stream ID.
    pub stream_id: u16,
    /// Sequence number.
    pub sequence_no: u16,
    /// Uncompressed logical size.
    pub uncompressed_size: u64,
    /// Encoded payload size.
    pub payload_size: u64,
    /// Compression algorithm ID (when global COMPRESSED).
    pub comp_algo_id: Option<u8>,
    /// Patch algorithm ID (when global HAS_DELTA).
    pub patch_algo_id: Option<u8>,
    /// Encryption algorithm ID (when global ENCRYPTED).
    pub encr_algo_id: Option<u8>,
    /// CDC algorithm ID (when global CDC_SUPPORT).
    pub cdc_algo_id: Option<u8>,
    /// FEC algorithm ID (when global SELECTIVE_FEC).
    pub fec_algo_id: Option<u8>,
    /// Fragment ID (when global FILE_FRAGMENTATION).
    pub fragment_id: Option<u32>,
    /// Fragment index (when global FILE_FRAGMENTATION).
    pub fragment_index: Option<u32>,
    /// Fragment descriptor absolute offset and size.
    pub fragment_descriptor: Option<(u64, u32)>,
    /// IV/nonce (when global ENCRYPTED).
    pub iv_nonce: Option<[u8; 24]>,
    /// Delta base hash (when global HAS_DELTA).
    pub delta_base_hash: Option<[u8; 32]>,
    /// File CRC32 (when global PER_FILE_CRC).
    pub file_crc32: Option<u32>,
    /// Content hash (when global DEDUPLICATION).
    pub content_hash: Option<[u8; 32]>,
    /// UID/GID (when global EXT_UID_GID).
    pub uid_gid: Option<u32>,
    /// mtime/atime/ctime (when global EXT_TIME).
    pub timestamps: Option<[u64; 3]>,
    /// POSIX permissions (when global HAS_PERMS).
    pub permissions: Option<u16>,
    /// Name bytes.
    pub name: Vec<u8>,
    /// Path bytes.
    pub path: Vec<u8>,
    /// Sparse map bytes.
    pub sparse_map: Vec<u8>,
    /// FEC value bytes.
    pub fec_value: Vec<u8>,
}

impl LocalFileHeader {
    /// Creates a minimal STORE entry LFH.
    #[must_use]
    pub fn minimal_store(name: Vec<u8>, payload_size: u64) -> Self {
        Self {
            header_size: 0,
            entry_mode: EntryMode(0),
            stream_id: 0,
            sequence_no: 0,
            uncompressed_size: payload_size,
            payload_size,
            comp_algo_id: None,
            patch_algo_id: None,
            encr_algo_id: None,
            cdc_algo_id: None,
            fec_algo_id: None,
            fragment_id: None,
            fragment_index: None,
            fragment_descriptor: None,
            iv_nonce: None,
            delta_base_hash: None,
            file_crc32: None,
            content_hash: None,
            uid_gid: None,
            timestamps: None,
            permissions: None,
            name,
            path: Vec::new(),
            sparse_map: Vec::new(),
            fec_value: Vec::new(),
        }
    }
}

/// Central Dictionary structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CentralDictionary {
    /// Central dictionary version.
    pub version: u8,
    /// File count.
    pub file_count: u64,
    /// Optional partition tuple (partition_id, total_partitions).
    pub partition_info: Option<(u16, u16)>,
    /// Optional global CRC32.
    pub global_crc32: Option<u32>,
    /// Metadata TLVs.
    pub metadata: Vec<Tlv>,
    /// Absolute LFH offsets.
    pub offsets: Vec<u64>,
}

/// Footer structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footer {
    /// Absolute CD offset.
    pub cd_offset: u64,
}

fn size_field_len(flags: GlobalFlags) -> usize {
    if flags.contains(GlobalFlags::SIZE_64BIT) {
        8
    } else {
        4
    }
}

fn read_size(cursor: &mut ParseCursor<'_>, flags: GlobalFlags) -> Result<u64, SarError> {
    if flags.contains(GlobalFlags::SIZE_64BIT) {
        cursor.read_u64_le()
    } else {
        Ok(u64::from(cursor.read_u32_le()?))
    }
}

fn write_size(writer: &mut BinaryWriter, flags: GlobalFlags, value: u64) -> Result<(), SarError> {
    if flags.contains(GlobalFlags::SIZE_64BIT) {
        writer.write_u64_le(value);
    } else {
        let v = u32::try_from(value)
            .map_err(|_| SarError::Overflow("size does not fit 32-bit field"))?;
        writer.write_u32_le(v);
    }
    Ok(())
}

/// Parses the global header from a byte slice.
pub fn parse_global_header(input: &[u8]) -> Result<(GlobalHeader, usize), SarError> {
    let mut cursor = ParseCursor::new(input);
    let magic = cursor.read_bytes(4)?;
    if magic != MAGIC {
        return Err(SarError::InvalidMagic);
    }

    let version = cursor.read_u8()?;
    if version != SUPPORTED_GLOBAL_VERSION {
        return Err(SarError::InvalidVersion(
            "unsupported global header version",
        ));
    }

    if cursor.read_u8()? != 0 {
        return Err(SarError::ReservedValue("global reserved byte must be zero"));
    }

    let flags_size = usize::from(cursor.read_u16_le()?);
    if flags_size < 4 {
        return Err(SarError::InvalidLength("global flags size must be >= 4"));
    }
    let flags_bytes = cursor.read_bytes(flags_size)?.to_vec();

    let mut low = [0u8; 4];
    low.copy_from_slice(&flags_bytes[..4]);
    let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
    validate_global_flags(flags)?;

    let partition_descriptor = if flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) {
        let bytes = cursor.read_bytes(96)?;
        let mut pcur = ParseCursor::new(bytes);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(pcur.read_bytes(16)?);
        let index = pcur.read_u32_le()?;
        let total = pcur.read_u32_le()?;
        let mut prev = [0u8; 32];
        prev.copy_from_slice(pcur.read_bytes(32)?);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(pcur.read_bytes(32)?);
        let reserved = pcur.read_bytes(8)?;
        if reserved.iter().any(|byte| *byte != 0) {
            return Err(SarError::ReservedValue(
                "partition descriptor reserved bytes must be zero",
            ));
        }
        Some(PartitionDescriptor {
            partition_set_uuid: uuid,
            partition_index: index,
            total_partitions: total,
            previous_partition_hash: prev,
            partition_hash: hash,
        })
    } else {
        None
    };

    let kms = if flags.contains(GlobalFlags::ENCRYPTED) {
        let mode_id = cursor.read_u8()?;
        match mode_id {
            0x01..=0x03 => {}
            0xF0..=0xFF => return Err(SarError::Unsupported("custom KMS mode")),
            _ => return Err(SarError::ReservedValue("unknown KMS mode")),
        }
        let payload_len = usize::try_from(cursor.read_u32_le()?)
            .map_err(|_| SarError::Overflow("KMS payload length"))?;
        let payload = cursor.read_bytes(payload_len)?.to_vec();
        Some(KmsData { mode_id, payload })
    } else {
        None
    };

    if !flags.contains(GlobalFlags::ENCRYPTED) && kms.is_some() {
        return Err(SarError::FlagConflict(
            "KMS extension must be omitted when ENCRYPTED is unset",
        ));
    }
    if !flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) && partition_descriptor.is_some() {
        return Err(SarError::FlagConflict(
            "partition descriptor must be omitted when PARTITIONED_ARCHIVE is unset",
        ));
    }

    let header = GlobalHeader {
        version,
        flags_bytes,
        flags,
        partition_descriptor,
        kms,
    };

    Ok((header, cursor.position()))
}

/// Encodes the global header.
pub fn write_global_header(header: &GlobalHeader) -> Result<Vec<u8>, SarError> {
    validate_global_flags(header.flags)?;

    if header.flags.contains(GlobalFlags::ENCRYPTED) && header.kms.is_none() {
        return Err(SarError::FlagConflict("ENCRYPTED requires KMS extension"));
    }
    if !header.flags.contains(GlobalFlags::ENCRYPTED) && header.kms.is_some() {
        return Err(SarError::FlagConflict("KMS extension requires ENCRYPTED"));
    }
    if header.flags.contains(GlobalFlags::PARTITIONED_ARCHIVE)
        && header.partition_descriptor.is_none()
    {
        return Err(SarError::FlagConflict(
            "PARTITIONED_ARCHIVE requires partition descriptor",
        ));
    }
    if !header.flags.contains(GlobalFlags::PARTITIONED_ARCHIVE)
        && header.partition_descriptor.is_some()
    {
        return Err(SarError::FlagConflict(
            "partition descriptor requires PARTITIONED_ARCHIVE",
        ));
    }

    let mut flags_bytes = header.flags_bytes.clone();
    if flags_bytes.len() < 4 {
        return Err(SarError::InvalidLength("global flags bytes must be >= 4"));
    }
    let bits = header.flags.bits().to_le_bytes();
    flags_bytes[..4].copy_from_slice(&bits);

    let mut writer = BinaryWriter::new();
    writer.write_bytes(&MAGIC);
    writer.write_u8(header.version);
    writer.write_u8(0);
    let flags_len_u16 = u16::try_from(flags_bytes.len())
        .map_err(|_| SarError::Overflow("global flags size does not fit u16"))?;
    writer.write_u16_le(flags_len_u16);
    writer.write_bytes(&flags_bytes);

    if let Some(descriptor) = &header.partition_descriptor {
        writer.write_bytes(&descriptor.partition_set_uuid);
        writer.write_u32_le(descriptor.partition_index);
        writer.write_u32_le(descriptor.total_partitions);
        writer.write_bytes(&descriptor.previous_partition_hash);
        writer.write_bytes(&descriptor.partition_hash);
        writer.write_bytes(&[0u8; 8]);
    }

    if let Some(kms) = &header.kms {
        writer.write_u8(kms.mode_id);
        let payload_len_u32 = u32::try_from(kms.payload.len())
            .map_err(|_| SarError::Overflow("KMS payload does not fit u32"))?;
        writer.write_u32_le(payload_len_u32);
        writer.write_bytes(&kms.payload);
    }

    Ok(writer.into_inner())
}

/// Computes expected LFH size from flags and variable-length fields.
pub fn compute_lfh_size(flags: &GlobalFlags, lfh: &LocalFileHeader) -> Result<u64, SarError> {
    let mut size = 0u64;
    let mut add = |v: u64| {
        size = size
            .checked_add(v)
            .ok_or(SarError::Overflow("LFH size computation"))?;
        Ok::<(), SarError>(())
    };

    let size_len = u64::try_from(size_field_len(*flags)).map_err(|_| SarError::Overflow("size"))?;

    add(4)?;
    add(2)?;
    add(2)?;
    add(2)?;
    add(size_len)?;
    add(size_len)?;
    if flags.contains(GlobalFlags::COMPRESSED) {
        add(1)?;
    }
    if flags.contains(GlobalFlags::HAS_DELTA) {
        add(1)?;
    }
    if flags.contains(GlobalFlags::ENCRYPTED) {
        add(1)?;
    }
    if flags.contains(GlobalFlags::CDC_SUPPORT) {
        add(1)?;
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        add(1)?;
    }
    if flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        add(4 + 4 + 12)?;
    }
    if flags.contains(GlobalFlags::ENCRYPTED) {
        add(24)?;
    }
    if flags.contains(GlobalFlags::HAS_DELTA) {
        add(32)?;
    }
    if flags.contains(GlobalFlags::PER_FILE_CRC) {
        add(4)?;
    }
    if flags.contains(GlobalFlags::DEDUPLICATION) {
        add(32)?;
    }
    if flags.contains(GlobalFlags::EXT_UID_GID) {
        add(4)?;
    }
    if flags.contains(GlobalFlags::EXT_TIME) {
        add(24)?;
    }
    if flags.contains(GlobalFlags::HAS_PERMS) {
        add(2)?;
    }

    add(2)?;
    if flags.contains(GlobalFlags::HAS_PATH) {
        add(2)?;
    }
    if flags.contains(GlobalFlags::SPARSE_FILES) {
        add(4)?;
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        add(3)?;
    }

    add(u64::try_from(lfh.name.len()).map_err(|_| SarError::Overflow("name len"))?)?;
    if flags.contains(GlobalFlags::HAS_PATH) {
        add(u64::try_from(lfh.path.len()).map_err(|_| SarError::Overflow("path len"))?)?;
    }
    if flags.contains(GlobalFlags::SPARSE_FILES) {
        add(u64::try_from(lfh.sparse_map.len()).map_err(|_| SarError::Overflow("sparse len"))?)?;
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        add(u64::try_from(lfh.fec_value.len()).map_err(|_| SarError::Overflow("fec len"))?)?;
    }

    Ok(size)
}

/// Parses an LFH from the current archive offset.
pub fn parse_lfh(input: &[u8], flags: &GlobalFlags) -> Result<(LocalFileHeader, usize), SarError> {
    let mut cursor = ParseCursor::new(input);
    let header_size_u32 = cursor.read_u32_le()?;
    let header_size =
        usize::try_from(header_size_u32).map_err(|_| SarError::Overflow("header size"))?;
    if header_size > input.len() {
        return Err(SarError::Truncated("LFH header exceeds available input"));
    }

    let mut hdr_cursor = ParseCursor::new(&input[..header_size]);
    let declared_header_size = hdr_cursor.read_u32_le()?;
    if declared_header_size != header_size_u32 {
        return Err(SarError::InvalidLength("LFH header size mismatch"));
    }

    let entry_mode = EntryMode(hdr_cursor.read_u16_le()?);
    validate_entry_mode_against_global(*flags, entry_mode)?;

    let stream_id = hdr_cursor.read_u16_le()?;
    let sequence_no = hdr_cursor.read_u16_le()?;
    let uncompressed_size = read_size(&mut hdr_cursor, *flags)?;
    let payload_size = read_size(&mut hdr_cursor, *flags)?;

    let comp_algo_id = if flags.contains(GlobalFlags::COMPRESSED) {
        Some(hdr_cursor.read_u8()?)
    } else {
        None
    };
    let patch_algo_id = if flags.contains(GlobalFlags::HAS_DELTA) {
        Some(hdr_cursor.read_u8()?)
    } else {
        None
    };
    let encr_algo_id = if flags.contains(GlobalFlags::ENCRYPTED) {
        Some(hdr_cursor.read_u8()?)
    } else {
        None
    };
    let cdc_algo_id = if flags.contains(GlobalFlags::CDC_SUPPORT) {
        Some(hdr_cursor.read_u8()?)
    } else {
        None
    };
    let fec_algo_id = if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        Some(hdr_cursor.read_u8()?)
    } else {
        None
    };

    let fragment_id = if flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        Some(hdr_cursor.read_u32_le()?)
    } else {
        None
    };
    let fragment_index = if flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        Some(hdr_cursor.read_u32_le()?)
    } else {
        None
    };
    let fragment_descriptor = if flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        Some((hdr_cursor.read_u64_le()?, hdr_cursor.read_u32_le()?))
    } else {
        None
    };

    let iv_nonce = if flags.contains(GlobalFlags::ENCRYPTED) {
        let mut iv = [0u8; 24];
        iv.copy_from_slice(hdr_cursor.read_bytes(24)?);
        Some(iv)
    } else {
        None
    };

    let delta_base_hash = if flags.contains(GlobalFlags::HAS_DELTA) {
        let mut h = [0u8; 32];
        h.copy_from_slice(hdr_cursor.read_bytes(32)?);
        Some(h)
    } else {
        None
    };

    let file_crc32 = if flags.contains(GlobalFlags::PER_FILE_CRC) {
        Some(hdr_cursor.read_u32_le()?)
    } else {
        None
    };

    let content_hash = if flags.contains(GlobalFlags::DEDUPLICATION) {
        let mut h = [0u8; 32];
        h.copy_from_slice(hdr_cursor.read_bytes(32)?);
        Some(h)
    } else {
        None
    };

    let uid_gid = if flags.contains(GlobalFlags::EXT_UID_GID) {
        Some(hdr_cursor.read_u32_le()?)
    } else {
        None
    };

    let timestamps = if flags.contains(GlobalFlags::EXT_TIME) {
        Some([
            hdr_cursor.read_u64_le()?,
            hdr_cursor.read_u64_le()?,
            hdr_cursor.read_u64_le()?,
        ])
    } else {
        None
    };

    let permissions = if flags.contains(GlobalFlags::HAS_PERMS) {
        Some(hdr_cursor.read_u16_le()?)
    } else {
        None
    };

    let name_len = usize::from(hdr_cursor.read_u16_le()?);
    let path_len = if flags.contains(GlobalFlags::HAS_PATH) {
        usize::from(hdr_cursor.read_u16_le()?)
    } else {
        0
    };
    let sparse_len = if flags.contains(GlobalFlags::SPARSE_FILES) {
        usize::try_from(hdr_cursor.read_u32_le()?).map_err(|_| SarError::Overflow("sparse len"))?
    } else {
        0
    };
    let fec_len = if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        usize::try_from(hdr_cursor.read_u24_le()?).map_err(|_| SarError::Overflow("fec len"))?
    } else {
        0
    };

    let name = if name_len > 0 {
        hdr_cursor.read_bytes(name_len)?.to_vec()
    } else {
        Vec::new()
    };
    let path = if flags.contains(GlobalFlags::HAS_PATH) && path_len > 0 {
        hdr_cursor.read_bytes(path_len)?.to_vec()
    } else {
        Vec::new()
    };
    let sparse_map = if flags.contains(GlobalFlags::SPARSE_FILES) && sparse_len > 0 {
        hdr_cursor.read_bytes(sparse_len)?.to_vec()
    } else {
        Vec::new()
    };
    let fec_value = if flags.contains(GlobalFlags::SELECTIVE_FEC) && fec_len > 0 {
        hdr_cursor.read_bytes(fec_len)?.to_vec()
    } else {
        Vec::new()
    };

    if hdr_cursor.position() != header_size {
        return Err(SarError::InvalidLength(
            "computed LFH size does not match Header Size",
        ));
    }

    let lfh = LocalFileHeader {
        header_size: header_size_u32,
        entry_mode,
        stream_id,
        sequence_no,
        uncompressed_size,
        payload_size,
        comp_algo_id,
        patch_algo_id,
        encr_algo_id,
        cdc_algo_id,
        fec_algo_id,
        fragment_id,
        fragment_index,
        fragment_descriptor,
        iv_nonce,
        delta_base_hash,
        file_crc32,
        content_hash,
        uid_gid,
        timestamps,
        permissions,
        name,
        path,
        sparse_map,
        fec_value,
    };

    let computed = compute_lfh_size(flags, &lfh)?;
    if computed != u64::from(header_size_u32) {
        return Err(SarError::InvalidLength("computed LFH size mismatch"));
    }

    Ok((lfh, header_size))
}

/// Encodes LFH bytes.
pub fn write_lfh(flags: &GlobalFlags, lfh: &LocalFileHeader) -> Result<Vec<u8>, SarError> {
    validate_entry_mode_against_global(*flags, lfh.entry_mode)?;
    let computed_size = compute_lfh_size(flags, lfh)?;
    let header_size =
        u32::try_from(computed_size).map_err(|_| SarError::Overflow("LFH header size"))?;

    let name_len_u16 = u16::try_from(lfh.name.len()).map_err(|_| SarError::Overflow("name len"))?;
    let path_len_u16 = u16::try_from(lfh.path.len()).map_err(|_| SarError::Overflow("path len"))?;
    let sparse_len_u32 =
        u32::try_from(lfh.sparse_map.len()).map_err(|_| SarError::Overflow("sparse len"))?;
    let fec_len_u32 =
        u32::try_from(lfh.fec_value.len()).map_err(|_| SarError::Overflow("fec len"))?;

    let mut writer = BinaryWriter::new();
    writer.write_u32_le(header_size);
    writer.write_u16_le(lfh.entry_mode.0);
    writer.write_u16_le(lfh.stream_id);
    writer.write_u16_le(lfh.sequence_no);
    write_size(&mut writer, *flags, lfh.uncompressed_size)?;
    write_size(&mut writer, *flags, lfh.payload_size)?;

    if flags.contains(GlobalFlags::COMPRESSED) {
        writer.write_u8(lfh.comp_algo_id.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::HAS_DELTA) {
        writer.write_u8(lfh.patch_algo_id.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::ENCRYPTED) {
        writer.write_u8(lfh.encr_algo_id.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::CDC_SUPPORT) {
        writer.write_u8(lfh.cdc_algo_id.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        writer.write_u8(lfh.fec_algo_id.unwrap_or(0));
    }

    if flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        writer.write_u32_le(lfh.fragment_id.unwrap_or(0));
        writer.write_u32_le(lfh.fragment_index.unwrap_or(0));
        let (abs, sz) = lfh.fragment_descriptor.unwrap_or((0, 0));
        writer.write_u64_le(abs);
        writer.write_u32_le(sz);
    }
    if flags.contains(GlobalFlags::ENCRYPTED) {
        writer.write_bytes(&lfh.iv_nonce.unwrap_or([0u8; 24]));
    }
    if flags.contains(GlobalFlags::HAS_DELTA) {
        writer.write_bytes(&lfh.delta_base_hash.unwrap_or([0u8; 32]));
    }
    if flags.contains(GlobalFlags::PER_FILE_CRC) {
        writer.write_u32_le(lfh.file_crc32.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::DEDUPLICATION) {
        writer.write_bytes(&lfh.content_hash.unwrap_or([0u8; 32]));
    }
    if flags.contains(GlobalFlags::EXT_UID_GID) {
        writer.write_u32_le(lfh.uid_gid.unwrap_or(0));
    }
    if flags.contains(GlobalFlags::EXT_TIME) {
        let ts = lfh.timestamps.unwrap_or([0u64; 3]);
        writer.write_u64_le(ts[0]);
        writer.write_u64_le(ts[1]);
        writer.write_u64_le(ts[2]);
    }
    if flags.contains(GlobalFlags::HAS_PERMS) {
        writer.write_u16_le(lfh.permissions.unwrap_or(0));
    }

    writer.write_u16_le(name_len_u16);
    if flags.contains(GlobalFlags::HAS_PATH) {
        writer.write_u16_le(path_len_u16);
    }
    if flags.contains(GlobalFlags::SPARSE_FILES) {
        writer.write_u32_le(sparse_len_u32);
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        writer.write_u24_le(fec_len_u32)?;
    }

    writer.write_bytes(&lfh.name);
    if flags.contains(GlobalFlags::HAS_PATH) {
        writer.write_bytes(&lfh.path);
    }
    if flags.contains(GlobalFlags::SPARSE_FILES) {
        writer.write_bytes(&lfh.sparse_map);
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        writer.write_bytes(&lfh.fec_value);
    }

    Ok(writer.into_inner())
}

/// Parses a Central Dictionary.
pub fn parse_central_dictionary(
    input: &[u8],
    flags: GlobalFlags,
) -> Result<(CentralDictionary, usize), SarError> {
    let mut cursor = ParseCursor::new(input);
    let version = cursor.read_u8()?;
    if version != SUPPORTED_CD_VERSION {
        return Err(SarError::InvalidVersion(
            "unsupported central dictionary version",
        ));
    }
    let reserved = cursor.read_bytes(7)?;
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(SarError::ReservedValue("CD reserved bytes must be zero"));
    }

    let file_count = read_size(&mut cursor, flags)?;
    let partition_info = if flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) {
        Some((cursor.read_u16_le()?, cursor.read_u16_le()?))
    } else {
        None
    };
    let global_crc32 = if flags.contains(GlobalFlags::HAS_GLOBAL_CRC32) {
        Some(cursor.read_u32_le()?)
    } else {
        None
    };

    let metadata = if flags.contains(GlobalFlags::OPT_PRESENT) {
        let meta_size = usize::try_from(cursor.read_u32_le()?)
            .map_err(|_| SarError::Overflow("CD metadata size"))?;
        let meta_bytes = cursor.read_bytes(meta_size)?;
        parse_tlvs(meta_bytes)?
    } else {
        Vec::new()
    };

    let file_count_usize = usize::try_from(file_count)
        .map_err(|_| SarError::Overflow("CD file count does not fit usize"))?;
    let mut offsets = Vec::with_capacity(file_count_usize);
    for _ in 0..file_count_usize {
        offsets.push(read_size(&mut cursor, flags)?);
    }

    Ok((
        CentralDictionary {
            version,
            file_count,
            partition_info,
            global_crc32,
            metadata,
            offsets,
        },
        cursor.position(),
    ))
}

/// Encodes a Central Dictionary.
pub fn write_central_dictionary(
    cd: &CentralDictionary,
    flags: GlobalFlags,
) -> Result<Vec<u8>, SarError> {
    let mut writer = BinaryWriter::new();
    writer.write_u8(cd.version);
    writer.write_bytes(&[0u8; 7]);
    write_size(&mut writer, flags, cd.file_count)?;

    if flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) {
        let (partition_id, total) = cd.partition_info.ok_or(SarError::MetadataMissing(
            "partition info required for PARTITIONED_ARCHIVE",
        ))?;
        writer.write_u16_le(partition_id);
        writer.write_u16_le(total);
    }

    if flags.contains(GlobalFlags::HAS_GLOBAL_CRC32) {
        writer.write_u32_le(cd.global_crc32.ok_or(SarError::MetadataMissing(
            "global CRC32 required by HAS_GLOBAL_CRC32",
        ))?);
    }

    if flags.contains(GlobalFlags::OPT_PRESENT) {
        let meta_bytes = write_tlvs(&cd.metadata)?;
        let meta_len = u32::try_from(meta_bytes.len())
            .map_err(|_| SarError::Overflow("metadata size does not fit u32"))?;
        writer.write_u32_le(meta_len);
        writer.write_bytes(&meta_bytes);
    }

    if usize::try_from(cd.file_count).map_err(|_| SarError::Overflow("file count usize"))?
        != cd.offsets.len()
    {
        return Err(SarError::InvalidLength(
            "offset count does not match file count",
        ));
    }

    for offset in &cd.offsets {
        write_size(&mut writer, flags, *offset)?;
    }

    Ok(writer.into_inner())
}

/// Parses footer bytes.
pub fn parse_footer(input: &[u8]) -> Result<Footer, SarError> {
    if input.len() < 8 {
        return Err(SarError::Truncated("footer requires 8 bytes"));
    }
    let mut cursor = ParseCursor::new(&input[..8]);
    Ok(Footer {
        cd_offset: cursor.read_u64_le()?,
    })
}

/// Encodes footer bytes.
pub fn write_footer(footer: Footer) -> [u8; 8] {
    footer.cd_offset.to_le_bytes()
}

/// Returns the raw bytes of the global-header AAD section.
pub fn global_header_flags_bytes(header: &GlobalHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + header.flags_bytes.len());
    out.extend_from_slice(b"SAR!");
    out.push(header.version);
    out.push(0x00);
    let flags_size = header.flags_bytes.len() as u16;
    out.extend_from_slice(&flags_size.to_le_bytes());
    out.extend_from_slice(&header.flags_bytes);
    out
}

/// Serialize a local file header into its on-wire bytes for AAD construction.
pub fn lfh_to_bytes(lfh: &LocalFileHeader, flags: GlobalFlags) -> Result<Vec<u8>, SarError> {
    write_lfh(&flags, lfh)
}

/// Returns the byte offset of the `FEC Size` field (3 bytes) within the serialized LFH,
/// assuming `SELECTIVE_FEC` is active.
///
/// This is the sum of all fixed-size and length-prefix fields that precede `FEC Size`
/// in the LFH field sequence (fields 1–24 in the spec).
pub fn fec_size_field_offset(flags: GlobalFlags) -> usize {
    let size_len = size_field_len(flags);
    let mut off: usize = 4 + 2 + 2 + 2 + size_len + size_len; // fields 1-6
    if flags.contains(GlobalFlags::COMPRESSED) {
        off += 1; // Comp Algo ID
    }
    if flags.contains(GlobalFlags::HAS_DELTA) {
        off += 1; // Patch Algo ID
    }
    if flags.contains(GlobalFlags::ENCRYPTED) {
        off += 1; // Encr Algo ID
    }
    if flags.contains(GlobalFlags::CDC_SUPPORT) {
        off += 1; // CDC Algo ID
    }
    if flags.contains(GlobalFlags::SELECTIVE_FEC) {
        off += 1; // FEC Algo ID (field 11) — included in AAD; only FEC Size/Value are excluded
    }
    if flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        off += 4 + 4 + 12; // Fragment ID + Index + Descriptor
    }
    if flags.contains(GlobalFlags::ENCRYPTED) {
        off += 24; // IV/Nonce
    }
    if flags.contains(GlobalFlags::HAS_DELTA) {
        off += 32; // Delta Base Hash
    }
    if flags.contains(GlobalFlags::PER_FILE_CRC) {
        off += 4; // File CRC32
    }
    if flags.contains(GlobalFlags::DEDUPLICATION) {
        off += 32; // Content Hash
    }
    if flags.contains(GlobalFlags::EXT_UID_GID) {
        off += 4; // UID/GID
    }
    if flags.contains(GlobalFlags::EXT_TIME) {
        off += 24; // Timestamps
    }
    if flags.contains(GlobalFlags::HAS_PERMS) {
        off += 2; // Permissions
    }
    off += 2; // Name Length (field 22)
    if flags.contains(GlobalFlags::HAS_PATH) {
        off += 2; // Path Length (field 23)
    }
    if flags.contains(GlobalFlags::SPARSE_FILES) {
        off += 4; // Sparse Map Size (field 24)
    }
    off // FEC Size starts here (field 25)
}

/// Returns the LFH bytes with the `FEC Size` (3 bytes) and `FEC Value` fields removed,
/// for use in AEAD AAD computation per spec §13.2.1.
///
/// When `SELECTIVE_FEC` is active and `fec_algo_id` is non-zero, the spec requires that
/// `FEC Size` and `FEC Value` be excluded from the AEAD AAD.  If `SELECTIVE_FEC` is not
/// active, or `fec_algo_id` is zero, the full `lfh_bytes` slice is returned unchanged.
///
/// # Panics
///
/// Panics in debug builds if `lfh_bytes` is shorter than expected.
pub fn lfh_bytes_for_aad(
    flags: GlobalFlags,
    lfh_bytes: &[u8],
    fec_algo_id: u8,
    fec_value_len: usize,
) -> Vec<u8> {
    if !flags.contains(GlobalFlags::SELECTIVE_FEC) || fec_algo_id == 0 {
        return lfh_bytes.to_vec();
    }
    let fec_size_off = fec_size_field_offset(flags);
    // FEC Size is 3 bytes; FEC Value is at the very end of the LFH.
    // The bytes between FEC Size end and FEC Value start are Name + Path + Sparse data.
    let before_fec_size = fec_size_off;
    let after_fec_size_end = lfh_bytes.len().saturating_sub(fec_value_len);
    // Exclude the 3-byte FEC Size field: bytes [before_fec_size .. before_fec_size+3]
    // Exclude the FEC Value:             bytes [after_fec_size_end .. ]
    let stripped_len = lfh_bytes.len().saturating_sub(3 + fec_value_len);
    let mut out = Vec::with_capacity(stripped_len);
    if before_fec_size <= lfh_bytes.len() {
        out.extend_from_slice(&lfh_bytes[..before_fec_size]);
    }
    let after_fec_size = before_fec_size + 3;
    if after_fec_size <= after_fec_size_end && after_fec_size_end <= lfh_bytes.len() {
        out.extend_from_slice(&lfh_bytes[after_fec_size..after_fec_size_end]);
    }
    // Patch the Header Size field (first 4 bytes, LE u32) to reflect the stripped size.
    // This ensures writer (provisional LFH, fec_value=[]) and reader (final LFH, fec_value=N bytes)
    // produce identical AAD bytes despite the difference in the on-disk Header Size value.
    // Both normalize to: original_header_size - 3 (FEC Size) - fec_value_len = stripped_len.
    if out.len() >= 4 {
        let patched_size = u32::try_from(stripped_len).unwrap_or(u32::MAX);
        out[..4].copy_from_slice(&patched_size.to_le_bytes());
    }
    out
}
