use crate::{
    format::flags::GlobalFlags,
    types::{
        algorithms::{
            CdcAlgorithm, CompressionAlgorithm, DeltaAlgorithm, EncryptionAlgorithm, FecAlgorithm,
            HashAlgorithm,
        },
        kind::EntryKind,
        timestamp::EntryTimestampMetadata,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPermissionMetadata {
    pub mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryOwnerMetadata {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryCompressionMetadata {
    pub algorithm: CompressionAlgorithm,
    pub compressed_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryEncryptionMetadata {
    pub algorithm: EncryptionAlgorithm,
    pub key_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryCdcMetadata {
    pub algorithm: CdcAlgorithm,
    pub min_chunk_size: u32,
    pub avg_chunk_size: u32,
    pub max_chunk_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryFecMetadata {
    pub algorithm: FecAlgorithm,
    pub block_size: u32,
    pub data_shards: u8,
    pub parity_shards: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryDeltaMetadata {
    pub algorithm: DeltaAlgorithm,
    pub base_stream_id: u64,
    pub base_sequence_no: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryFragmentMetadata {
    pub fragment_index: u32,
    pub fragment_count: u32,
    pub fragment_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseHole {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySparseMetadata {
    pub holes: Vec<SparseHole>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHashMetadata {
    pub algorithm: HashAlgorithm,
    pub hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInput {
    pub name: String,
    pub path: Option<String>,
    pub payload: Vec<u8>,
    pub kind: EntryKind,
    pub permissions: Option<EntryPermissionMetadata>,
    pub owner: Option<EntryOwnerMetadata>,
    pub timestamps: Option<EntryTimestampMetadata>,
    pub hidden: Option<bool>,
    pub stream_id: Option<u64>,
    pub sequence_no: Option<u64>,
    pub fragment: Option<EntryFragmentMetadata>,
    pub sparse: Option<EntrySparseMetadata>,
    pub fec: Option<EntryFecMetadata>,
    pub cdc: Option<EntryCdcMetadata>,
    pub delta: Option<EntryDeltaMetadata>,
    pub encryption: Option<EntryEncryptionMetadata>,
    pub compression: Option<EntryCompressionMetadata>,
    pub crc32: Option<u32>,
    pub content_hash: Option<EntryHashMetadata>,
}

impl EntryInput {
    pub fn file(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            path: None,
            payload: payload.into(),
            kind: EntryKind::RegularFile,
            permissions: None,
            owner: None,
            timestamps: None,
            hidden: None,
            stream_id: None,
            sequence_no: None,
            fragment: None,
            sparse: None,
            fec: None,
            cdc: None,
            delta: None,
            encryption: None,
            compression: None,
            crc32: None,
            content_hash: None,
        }
    }

    pub fn directory(name: impl Into<String>) -> Self {
        Self {
            payload: Vec::new(),
            kind: EntryKind::Directory,
            ..Self::file(name, Vec::new())
        }
    }

    pub fn symlink(name: impl Into<String>, target: impl Into<Vec<u8>>) -> Self {
        Self {
            payload: target.into(),
            kind: EntryKind::Symlink,
            ..Self::file(name, Vec::new())
        }
    }

    pub fn empty_area(name: impl Into<String>) -> Self {
        Self {
            payload: Vec::new(),
            kind: EntryKind::EmptyArea,
            ..Self::file(name, Vec::new())
        }
    }

    pub fn required_global_flags(&self) -> GlobalFlags {
        let mut flags = GlobalFlags::empty();

        if self.path.is_some() {
            flags |= GlobalFlags::PATH;
        }
        if self.stream_id.is_some() {
            flags |= GlobalFlags::STREAM_ID;
        }
        if self.sequence_no.is_some() {
            flags |= GlobalFlags::SEQ_NO;
        }
        if self.permissions.is_some() {
            flags |= GlobalFlags::PERMISSIONS;
        }
        if self.owner.is_some() {
            flags |= GlobalFlags::OWNER;
        }
        if self.timestamps.is_some() {
            flags |= GlobalFlags::TIMESTAMPS;
        }
        if self.hidden.is_some() {
            flags |= GlobalFlags::HIDDEN;
        }
        if self.compression.is_some() {
            flags |= GlobalFlags::COMPRESSION;
        }
        if self.encryption.is_some() {
            flags |= GlobalFlags::ENCRYPTION;
        }
        if self.cdc.is_some() {
            flags |= GlobalFlags::CDC;
        }
        if self.fec.is_some() {
            flags |= GlobalFlags::FEC;
        }
        if self.delta.is_some() {
            flags |= GlobalFlags::DELTA;
        }
        if self.fragment.is_some() {
            flags |= GlobalFlags::FRAGMENT;
        }
        if self.sparse.is_some() {
            flags |= GlobalFlags::SPARSE;
        }
        if self.crc32.is_some() {
            flags |= GlobalFlags::CRC32;
        }
        if self.content_hash.is_some() {
            flags |= GlobalFlags::HASH;
        }

        flags
    }
}
