use crate::types::{
    input::{
        EntryCdcMetadata, EntryCompressionMetadata, EntryDeltaMetadata, EntryEncryptionMetadata,
        EntryFecMetadata, EntryFragmentMetadata, EntryHashMetadata, EntryOwnerMetadata,
        EntryPermissionMetadata, EntrySparseMetadata,
    },
    kind::EntryKind,
    presence::FieldPresence,
    timestamp::EntryTimestampMetadata,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    pub name: String,
    pub path: FieldPresence<String>,
    pub kind: EntryKind,
    pub permissions: FieldPresence<EntryPermissionMetadata>,
    pub owner: FieldPresence<EntryOwnerMetadata>,
    pub timestamps: FieldPresence<EntryTimestampMetadata>,
    pub hidden: FieldPresence<bool>,
    pub stream_id: FieldPresence<u64>,
    pub sequence_no: FieldPresence<u64>,
    pub fragment: FieldPresence<EntryFragmentMetadata>,
    pub sparse: FieldPresence<EntrySparseMetadata>,
    pub fec: FieldPresence<EntryFecMetadata>,
    pub cdc: FieldPresence<EntryCdcMetadata>,
    pub delta: FieldPresence<EntryDeltaMetadata>,
    pub encryption: FieldPresence<EntryEncryptionMetadata>,
    pub compression: FieldPresence<EntryCompressionMetadata>,
    pub crc32: FieldPresence<u32>,
    pub content_hash: FieldPresence<EntryHashMetadata>,
    pub entry_mode_raw: u32,
    pub payload_size: u64,
}
