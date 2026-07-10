use std::io::Write;

use crate::{
    error::SarError,
    format::{flags::GlobalFlags, mode::EntryMode},
    types::{
        algorithms::CompressionAlgorithm,
        input::{
            EntryCompressionMetadata, EntryHashMetadata, EntryInput, EntrySparseMetadata,
            SparseHole,
        },
    },
};

const HEADER_MAGIC: &[u8; 4] = b"SAR1";
const VERSION: u8 = 1;
const END_MAGIC: &[u8; 8] = b"SAREND!!";

#[derive(Debug, Default)]
pub struct ArchiveWriter {
    global_flags: GlobalFlags,
    entries: Vec<(EntryInput, Vec<u8>)>,
}

impl ArchiveWriter {
    pub fn new(global_flags: GlobalFlags) -> Self {
        Self {
            global_flags,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: EntryInput) -> Result<(), SarError> {
        let serialized = serialize_entry(&entry, self.global_flags)?;
        self.entries.push((entry, serialized));
        Ok(())
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SarError> {
        writer.write_all(HEADER_MAGIC)?;
        writer.write_all(&[VERSION])?;
        writer.write_all(&self.global_flags.bits().to_le_bytes())?;
        writer.write_all(&self.entry_count().to_le_bytes())?;

        for (_, serialized) in &self.entries {
            writer.write_all(serialized)?;
        }

        writer.write_all(END_MAGIC)?;
        Ok(())
    }

    pub fn global_flags(&self) -> GlobalFlags {
        self.global_flags
    }

    pub fn entry_count(&self) -> u32 {
        self.entries.len() as u32
    }
}

fn serialize_entry(entry: &EntryInput, global_flags: GlobalFlags) -> Result<Vec<u8>, SarError> {
    validate_required_flags(entry, global_flags)?;
    validate_lengths(entry)?;

    let entry_mode = compute_entry_mode(entry);
    let payload_size = entry.payload.len() as u64;
    let payload_len = serialized_payload_len(entry, global_flags, payload_size);

    let mut bytes = Vec::new();
    write_len_prefixed_string(&mut bytes, &entry.name, true)?;

    if global_flags.contains(GlobalFlags::PATH) {
        write_len_prefixed_string(&mut bytes, entry.path.as_deref().unwrap_or(""), false)?;
    }

    bytes.write_all(&entry_mode.bits().to_le_bytes())?;
    bytes.write_all(&payload_size.to_le_bytes())?;

    if global_flags.contains(GlobalFlags::STREAM_ID) {
        bytes.write_all(&entry.stream_id.unwrap_or_default().to_le_bytes())?;
    }

    if global_flags.contains(GlobalFlags::SEQ_NO) {
        bytes.write_all(&entry.sequence_no.unwrap_or_default().to_le_bytes())?;
    }

    if global_flags.contains(GlobalFlags::PERMISSIONS) {
        let permissions = entry
            .permissions
            .as_ref()
            .map(|value| value.mode)
            .unwrap_or_default();
        bytes.write_all(&permissions.to_le_bytes())?;
    }

    if global_flags.contains(GlobalFlags::OWNER) {
        let owner = entry.owner.as_ref();
        bytes.write_all(
            &owner
                .map(|value| value.uid)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(
            &owner
                .map(|value| value.gid)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
    }

    if global_flags.contains(GlobalFlags::TIMESTAMPS) {
        let timestamps = entry.timestamps;
        let mtime = timestamps.map(|value| value.mtime).unwrap_or_default();
        let atime = timestamps.map(|value| value.atime).unwrap_or_default();
        let ctime = timestamps.map(|value| value.ctime).unwrap_or_default();
        write_timestamp(&mut bytes, mtime)?;
        write_timestamp(&mut bytes, atime)?;
        write_timestamp(&mut bytes, ctime)?;
    }

    if global_flags.contains(GlobalFlags::HIDDEN) {
        bytes.write_all(&[u8::from(entry.hidden.unwrap_or(false))])?;
    }

    if global_flags.contains(GlobalFlags::COMPRESSION) {
        let compression = entry
            .compression
            .as_ref()
            .cloned()
            .unwrap_or(EntryCompressionMetadata {
                algorithm: CompressionAlgorithm::None,
                compressed_size: 0,
            });
        bytes.write_all(&[u8::from(compression.algorithm)])?;
        bytes.write_all(&compression.compressed_size.to_le_bytes())?;
    }

    if global_flags.contains(GlobalFlags::ENCRYPTION) {
        let encryption = entry.encryption.as_ref();
        bytes.write_all(&[u8::from(
            encryption.map(|value| value.algorithm).unwrap_or_default(),
        )])?;
        bytes.write_all(
            &encryption
                .map(|value| value.key_id)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
    }

    if global_flags.contains(GlobalFlags::CDC) {
        let cdc = entry.cdc.as_ref();
        bytes.write_all(&[u8::from(
            cdc.map(|value| value.algorithm).unwrap_or_default(),
        )])?;
        bytes.write_all(
            &cdc.map(|value| value.min_chunk_size)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(
            &cdc.map(|value| value.avg_chunk_size)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(
            &cdc.map(|value| value.max_chunk_size)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
    }

    if global_flags.contains(GlobalFlags::FEC) {
        let fec = entry.fec.as_ref();
        bytes.write_all(&[u8::from(
            fec.map(|value| value.algorithm).unwrap_or_default(),
        )])?;
        bytes.write_all(
            &fec.map(|value| value.block_size)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(&[fec.map(|value| value.data_shards).unwrap_or_default()])?;
        bytes.write_all(&[fec.map(|value| value.parity_shards).unwrap_or_default()])?;
    }

    if global_flags.contains(GlobalFlags::DELTA) {
        let delta = entry.delta.as_ref();
        bytes.write_all(&[u8::from(
            delta.map(|value| value.algorithm).unwrap_or_default(),
        )])?;
        bytes.write_all(
            &delta
                .map(|value| value.base_stream_id)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(
            &delta
                .map(|value| value.base_sequence_no)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
    }

    if global_flags.contains(GlobalFlags::FRAGMENT) {
        let fragment = entry.fragment.as_ref();
        bytes.write_all(
            &fragment
                .map(|value| value.fragment_index)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(
            &fragment
                .map(|value| value.fragment_count)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
        bytes.write_all(
            &fragment
                .map(|value| value.fragment_id)
                .unwrap_or_default()
                .to_le_bytes(),
        )?;
    }

    if global_flags.contains(GlobalFlags::SPARSE) {
        let sparse = entry
            .sparse
            .as_ref()
            .cloned()
            .unwrap_or(EntrySparseMetadata { holes: Vec::new() });
        bytes.write_all(&(sparse.holes.len() as u32).to_le_bytes())?;
        for hole in sparse.holes {
            write_sparse_hole(&mut bytes, hole)?;
        }
    }

    if global_flags.contains(GlobalFlags::CRC32) {
        bytes.write_all(&entry.crc32.unwrap_or_default().to_le_bytes())?;
    }

    if global_flags.contains(GlobalFlags::HASH) {
        let hash = entry
            .content_hash
            .as_ref()
            .cloned()
            .unwrap_or(EntryHashMetadata {
                algorithm: crate::types::algorithms::HashAlgorithm::Sha256,
                hash: Vec::new(),
            });
        bytes.write_all(&[u8::from(hash.algorithm)])?;
        bytes.write_all(&[hash.hash.len() as u8])?;
        bytes.write_all(&hash.hash)?;
    }

    let actual_payload_len = entry.payload.len();
    if actual_payload_len != payload_len {
        return Err(SarError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "payload length {} does not match encoded payload length {}",
                actual_payload_len, payload_len
            ),
        )));
    }
    bytes.write_all(&entry.payload)?;

    Ok(bytes)
}

fn validate_required_flags(entry: &EntryInput, global_flags: GlobalFlags) -> Result<(), SarError> {
    let required = entry.required_global_flags();
    let checks = [
        (GlobalFlags::PATH, "path"),
        (GlobalFlags::STREAM_ID, "stream_id"),
        (GlobalFlags::SEQ_NO, "sequence_no"),
        (GlobalFlags::PERMISSIONS, "permissions"),
        (GlobalFlags::OWNER, "owner"),
        (GlobalFlags::TIMESTAMPS, "timestamps"),
        (GlobalFlags::HIDDEN, "hidden"),
        (GlobalFlags::COMPRESSION, "compression"),
        (GlobalFlags::ENCRYPTION, "encryption"),
        (GlobalFlags::CDC, "cdc"),
        (GlobalFlags::FEC, "fec"),
        (GlobalFlags::DELTA, "delta"),
        (GlobalFlags::FRAGMENT, "fragment"),
        (GlobalFlags::SPARSE, "sparse"),
        (GlobalFlags::CRC32, "crc32"),
        (GlobalFlags::HASH, "content_hash"),
    ];

    for (flag, field) in checks {
        if required.contains(flag) && !global_flags.contains(flag) {
            return Err(SarError::EntryMetadataRequiresFlag {
                field,
                required_flag: flag.bits(),
            });
        }
    }

    Ok(())
}

fn validate_lengths(entry: &EntryInput) -> Result<(), SarError> {
    let name_len = entry.name.len();
    if name_len > u16::MAX as usize {
        return Err(SarError::NameTooLong(name_len));
    }

    if let Some(path) = &entry.path {
        let path_len = path.len();
        if path_len > u16::MAX as usize {
            return Err(SarError::PathTooLong(path_len));
        }
    }

    if let Some(hash) = &entry.content_hash {
        let hash_len = hash.hash.len();
        if hash_len > u8::MAX as usize {
            return Err(SarError::HashTooLong(hash_len));
        }
    }

    if let Some(sparse) = &entry.sparse {
        if sparse.holes.len() > u32::MAX as usize {
            return Err(SarError::SparseTooManyHoles(sparse.holes.len()));
        }
    }

    Ok(())
}

fn compute_entry_mode(entry: &EntryInput) -> EntryMode {
    let mut mode = EntryMode::from_bits(entry.kind.to_mode_bits());

    if entry.path.is_some() {
        mode.insert(EntryMode::PATH_ACTIVE);
    }
    if entry.stream_id.is_some() {
        mode.insert(EntryMode::STREAM_ID_ACTIVE);
    }
    if entry.sequence_no.is_some() {
        mode.insert(EntryMode::SEQ_NO_ACTIVE);
    }
    if entry.permissions.is_some() {
        mode.insert(EntryMode::PERMISSIONS_ACTIVE);
    }
    if entry.owner.is_some() {
        mode.insert(EntryMode::OWNER_ACTIVE);
    }
    if entry.timestamps.is_some() {
        mode.insert(EntryMode::TIMESTAMPS_ACTIVE);
    }
    if entry.hidden.is_some() {
        mode.insert(EntryMode::HIDDEN_ACTIVE);
    }
    if entry.compression.is_some() {
        mode.insert(EntryMode::COMPRESSION_ACTIVE);
    }
    if entry.encryption.is_some() {
        mode.insert(EntryMode::ENCRYPTION_ACTIVE);
    }
    if entry.cdc.is_some() {
        mode.insert(EntryMode::CDC_ACTIVE);
    }
    if entry.fec.is_some() {
        mode.insert(EntryMode::FEC_ACTIVE);
    }
    if entry.delta.is_some() {
        mode.insert(EntryMode::DELTA_ACTIVE);
    }
    if entry.fragment.is_some() {
        mode.insert(EntryMode::FRAGMENT_ACTIVE);
    }
    if entry.sparse.is_some() {
        mode.insert(EntryMode::SPARSE_ACTIVE);
    }
    if entry.crc32.is_some() {
        mode.insert(EntryMode::CRC32_ACTIVE);
    }
    if entry.content_hash.is_some() {
        mode.insert(EntryMode::HASH_ACTIVE);
    }

    mode
}

fn serialized_payload_len(
    entry: &EntryInput,
    global_flags: GlobalFlags,
    payload_size: u64,
) -> usize {
    if global_flags.contains(GlobalFlags::COMPRESSION) {
        if let Some(compression) = &entry.compression {
            if compression.algorithm != CompressionAlgorithm::None {
                return compression.compressed_size as usize;
            }
        }
    }

    payload_size as usize
}

fn write_len_prefixed_string(
    output: &mut Vec<u8>,
    value: &str,
    is_name: bool,
) -> Result<(), SarError> {
    let len = value.len();
    if len > u16::MAX as usize {
        return Err(if is_name {
            SarError::NameTooLong(len)
        } else {
            SarError::PathTooLong(len)
        });
    }
    output.write_all(&(len as u16).to_le_bytes())?;
    output.write_all(value.as_bytes())?;
    Ok(())
}

fn write_timestamp(
    output: &mut Vec<u8>,
    timestamp: crate::types::timestamp::EntryTimestamp,
) -> Result<(), SarError> {
    output.write_all(&timestamp.secs.to_le_bytes())?;
    output.write_all(&timestamp.nsecs.to_le_bytes())?;
    Ok(())
}

fn write_sparse_hole(output: &mut Vec<u8>, hole: SparseHole) -> Result<(), SarError> {
    output.write_all(&hole.offset.to_le_bytes())?;
    output.write_all(&hole.length.to_le_bytes())?;
    Ok(())
}
