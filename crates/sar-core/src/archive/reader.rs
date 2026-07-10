use std::io::Read;

use crate::{
    error::SarError,
    format::{flags::GlobalFlags, mode::EntryMode},
    types::{
        algorithms::{
            CdcAlgorithm, CompressionAlgorithm, DeltaAlgorithm, EncryptionAlgorithm, FecAlgorithm,
            HashAlgorithm,
        },
        input::{
            EntryCdcMetadata, EntryCompressionMetadata, EntryDeltaMetadata,
            EntryEncryptionMetadata, EntryFecMetadata, EntryFragmentMetadata, EntryHashMetadata,
            EntryOwnerMetadata, EntryPermissionMetadata, EntrySparseMetadata, SparseHole,
        },
        kind::EntryKind,
        metadata::EntryMetadata,
        presence::FieldPresence,
        timestamp::{EntryTimestamp, EntryTimestampMetadata},
    },
};

const HEADER_MAGIC: &[u8; 4] = b"SAR1";
const END_MAGIC: &[u8; 8] = b"SAREND!!";
const VERSION: u8 = 1;

#[derive(Debug)]
pub struct ArchiveReader<R: Read> {
    reader: R,
    global_flags: GlobalFlags,
    entry_count: u32,
    entries_read: u32,
    end_checked: bool,
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(mut reader: R) -> Result<Self, SarError> {
        let mut magic = [0_u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != HEADER_MAGIC {
            return Err(SarError::InvalidMagic);
        }

        let version = read_u8(&mut reader)?;
        if version != VERSION {
            return Err(SarError::UnsupportedVersion(version));
        }

        let global_flags = GlobalFlags::from(read_u32(&mut reader)?);
        let entry_count = read_u32(&mut reader)?;

        Ok(Self {
            reader,
            global_flags,
            entry_count,
            entries_read: 0,
            end_checked: false,
        })
    }

    pub fn global_flags(&self) -> GlobalFlags {
        self.global_flags
    }

    pub fn entry_count(&self) -> u32 {
        self.entry_count
    }

    pub fn next_entry(&mut self) -> Result<Option<(EntryMetadata, Vec<u8>)>, SarError> {
        if self.entries_read >= self.entry_count {
            if !self.end_checked {
                let mut end_magic = [0_u8; 8];
                self.reader.read_exact(&mut end_magic)?;
                if &end_magic != END_MAGIC {
                    return Err(SarError::InvalidEndMagic);
                }
                self.end_checked = true;
            }
            return Ok(None);
        }

        let name = read_string_u16(&mut self.reader)?;
        let path_value = if self.global_flags.contains(GlobalFlags::PATH) {
            Some(read_string_u16(&mut self.reader)?)
        } else {
            None
        };
        let entry_mode_raw = read_u32(&mut self.reader)?;
        let entry_mode = EntryMode::from(entry_mode_raw);
        let payload_size = read_u64(&mut self.reader)?;
        let kind = EntryKind::from_mode_bits(entry_mode_raw);
        let path = match path_value {
            Some(value) => presence(entry_mode.contains(EntryMode::PATH_ACTIVE), value),
            None => FieldPresence::Absent,
        };

        let stream_id = if self.global_flags.contains(GlobalFlags::STREAM_ID) {
            presence(
                entry_mode.contains(EntryMode::STREAM_ID_ACTIVE),
                read_u64(&mut self.reader)?,
            )
        } else {
            FieldPresence::Absent
        };

        let sequence_no = if self.global_flags.contains(GlobalFlags::SEQ_NO) {
            presence(
                entry_mode.contains(EntryMode::SEQ_NO_ACTIVE),
                read_u64(&mut self.reader)?,
            )
        } else {
            FieldPresence::Absent
        };

        let permissions = if self.global_flags.contains(GlobalFlags::PERMISSIONS) {
            presence(
                entry_mode.contains(EntryMode::PERMISSIONS_ACTIVE),
                EntryPermissionMetadata {
                    mode: read_u32(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let owner = if self.global_flags.contains(GlobalFlags::OWNER) {
            presence(
                entry_mode.contains(EntryMode::OWNER_ACTIVE),
                EntryOwnerMetadata {
                    uid: read_u32(&mut self.reader)?,
                    gid: read_u32(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let timestamps = if self.global_flags.contains(GlobalFlags::TIMESTAMPS) {
            presence(
                entry_mode.contains(EntryMode::TIMESTAMPS_ACTIVE),
                EntryTimestampMetadata {
                    mtime: read_timestamp(&mut self.reader)?,
                    atime: read_timestamp(&mut self.reader)?,
                    ctime: read_timestamp(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let hidden = if self.global_flags.contains(GlobalFlags::HIDDEN) {
            presence(
                entry_mode.contains(EntryMode::HIDDEN_ACTIVE),
                read_u8(&mut self.reader)? != 0,
            )
        } else {
            FieldPresence::Absent
        };

        let compression = if self.global_flags.contains(GlobalFlags::COMPRESSION) {
            presence(
                entry_mode.contains(EntryMode::COMPRESSION_ACTIVE),
                EntryCompressionMetadata {
                    algorithm: CompressionAlgorithm::from(read_u8(&mut self.reader)?),
                    compressed_size: read_u64(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let encryption = if self.global_flags.contains(GlobalFlags::ENCRYPTION) {
            presence(
                entry_mode.contains(EntryMode::ENCRYPTION_ACTIVE),
                EntryEncryptionMetadata {
                    algorithm: EncryptionAlgorithm::from(read_u8(&mut self.reader)?),
                    key_id: read_u64(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let cdc = if self.global_flags.contains(GlobalFlags::CDC) {
            presence(
                entry_mode.contains(EntryMode::CDC_ACTIVE),
                EntryCdcMetadata {
                    algorithm: CdcAlgorithm::from(read_u8(&mut self.reader)?),
                    min_chunk_size: read_u32(&mut self.reader)?,
                    avg_chunk_size: read_u32(&mut self.reader)?,
                    max_chunk_size: read_u32(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let fec = if self.global_flags.contains(GlobalFlags::FEC) {
            presence(
                entry_mode.contains(EntryMode::FEC_ACTIVE),
                EntryFecMetadata {
                    algorithm: FecAlgorithm::from(read_u8(&mut self.reader)?),
                    block_size: read_u32(&mut self.reader)?,
                    data_shards: read_u8(&mut self.reader)?,
                    parity_shards: read_u8(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let delta = if self.global_flags.contains(GlobalFlags::DELTA) {
            presence(
                entry_mode.contains(EntryMode::DELTA_ACTIVE),
                EntryDeltaMetadata {
                    algorithm: DeltaAlgorithm::from(read_u8(&mut self.reader)?),
                    base_stream_id: read_u64(&mut self.reader)?,
                    base_sequence_no: read_u64(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let fragment = if self.global_flags.contains(GlobalFlags::FRAGMENT) {
            presence(
                entry_mode.contains(EntryMode::FRAGMENT_ACTIVE),
                EntryFragmentMetadata {
                    fragment_index: read_u32(&mut self.reader)?,
                    fragment_count: read_u32(&mut self.reader)?,
                    fragment_id: read_u64(&mut self.reader)?,
                },
            )
        } else {
            FieldPresence::Absent
        };

        let sparse = if self.global_flags.contains(GlobalFlags::SPARSE) {
            let hole_count = read_u32(&mut self.reader)? as usize;
            let mut holes = Vec::with_capacity(hole_count);
            for _ in 0..hole_count {
                holes.push(SparseHole {
                    offset: read_u64(&mut self.reader)?,
                    length: read_u64(&mut self.reader)?,
                });
            }
            presence(
                entry_mode.contains(EntryMode::SPARSE_ACTIVE),
                EntrySparseMetadata { holes },
            )
        } else {
            FieldPresence::Absent
        };

        let crc32 = if self.global_flags.contains(GlobalFlags::CRC32) {
            presence(
                entry_mode.contains(EntryMode::CRC32_ACTIVE),
                read_u32(&mut self.reader)?,
            )
        } else {
            FieldPresence::Absent
        };

        let content_hash = if self.global_flags.contains(GlobalFlags::HASH) {
            let algorithm = HashAlgorithm::from(read_u8(&mut self.reader)?);
            let hash_len = read_u8(&mut self.reader)? as usize;
            let mut hash = vec![0_u8; hash_len];
            self.reader.read_exact(&mut hash)?;
            presence(
                entry_mode.contains(EntryMode::HASH_ACTIVE),
                EntryHashMetadata { algorithm, hash },
            )
        } else {
            FieldPresence::Absent
        };

        let payload_len = match &compression {
            FieldPresence::PresentActive(metadata)
                if metadata.algorithm != CompressionAlgorithm::None =>
            {
                metadata.compressed_size
            }
            _ => payload_size,
        } as usize;
        let mut payload = vec![0_u8; payload_len];
        self.reader.read_exact(&mut payload)?;

        self.entries_read += 1;

        Ok(Some((
            EntryMetadata {
                name,
                path,
                kind,
                permissions,
                owner,
                timestamps,
                hidden,
                stream_id,
                sequence_no,
                fragment,
                sparse,
                fec,
                cdc,
                delta,
                encryption,
                compression,
                crc32,
                content_hash,
                entry_mode_raw,
                payload_size,
            },
            payload,
        )))
    }
}

impl<R: Read> Iterator for ArchiveReader<R> {
    type Item = Result<(EntryMetadata, Vec<u8>), SarError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, SarError> {
    let mut buf = [0_u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, SarError> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, SarError> {
    let mut buf = [0_u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_i64<R: Read>(reader: &mut R) -> Result<i64, SarError> {
    let mut buf = [0_u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

fn read_string_u16<R: Read>(reader: &mut R) -> Result<String, SarError> {
    let len = read_u16(reader)? as usize;
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}

fn read_u16<R: Read>(reader: &mut R) -> Result<u16, SarError> {
    let mut buf = [0_u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_timestamp<R: Read>(reader: &mut R) -> Result<EntryTimestamp, SarError> {
    Ok(EntryTimestamp {
        secs: read_i64(reader)?,
        nsecs: read_u32(reader)?,
    })
}

fn presence<T>(active: bool, value: T) -> FieldPresence<T> {
    if active {
        FieldPresence::PresentActive(value)
    } else {
        FieldPresence::PresentInactive(value)
    }
}
