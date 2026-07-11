#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! High-level SAR archive reader/writer and integration APIs.

/// High-level archive reader/writer APIs and integration types.
pub mod archive;
/// Archive profile validation APIs.
pub mod profile;
/// Forward-only archive stream parser APIs.
pub mod stream;

pub use archive::{
    ArchiveMetadata, ArchiveReader, ArchiveReaderOptions, ArchiveSummary, ArchiveWriter,
    ArchiveWriterOptions, CompressionSettings, EncryptionSettings, EntryInput, EntryMetadata,
    EntryReader, EntryWritten, FecSettings, LfhSizeFieldPolicy, LogicalFile, SparseWriteOptions,
    StreamWriteState, VerificationReport,
};
pub use profile::{ComplianceProfile, ProfileReport, validate_archive_profile};
pub use stream::{StreamArchiveParser, StreamArchiveSummary, StreamEvent, StreamParseState, StreamStep};
