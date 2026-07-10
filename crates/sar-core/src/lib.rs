pub mod archive;
pub mod error;
pub mod format;
pub mod types;

pub use archive::{ArchiveReader, ArchiveWriter};
pub use error::SarError;
pub use format::{flags::GlobalFlags, mode::EntryMode};
pub use types::{
    algorithms::{
        CdcAlgorithm, CompressionAlgorithm, DeltaAlgorithm, EncryptionAlgorithm, FecAlgorithm,
        HashAlgorithm,
    },
    input::{
        EntryCdcMetadata, EntryCompressionMetadata, EntryDeltaMetadata, EntryEncryptionMetadata,
        EntryFecMetadata, EntryFragmentMetadata, EntryHashMetadata, EntryInput, EntryOwnerMetadata,
        EntryPermissionMetadata, EntrySparseMetadata, SparseHole,
    },
    kind::EntryKind,
    metadata::EntryMetadata,
    presence::FieldPresence,
    timestamp::{EntryTimestamp, EntryTimestampMetadata},
};
