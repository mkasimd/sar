#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! High-level SAR archive reader/writer and integration APIs.

/// High-level archive reader/writer APIs and integration types.
pub mod archive;
/// Conformance vector manifest types and schema validator (M12a).
pub mod conformance;
/// Archive profile validation APIs.
pub mod profile;
/// Archive-level Data Recovery TLV inspection, planning, and repair.
pub mod recovery;
/// Forward-only archive stream parser APIs.
pub mod stream;
/// Transform pipeline (compress/encrypt orchestration).
///
/// These types are not re-exported at the crate root.  Import via
/// `sar_archive::transform::…` when building test archives or implementing
/// custom payload pipelines on top of the SAR format.
pub mod transform;

pub use archive::{
    ArchiveMetadata, ArchiveReader, ArchiveReaderOptions, ArchiveSummary, ArchiveWriter,
    ArchiveWriterOptions, CompressionSettings, DeltaWriteOptions, EncryptionSettings, EntryInput,
    EntryMetadata, EntryReader, EntryWritten, FecSettings, LfhSizeFieldPolicy, LogicalFile,
    SparseWriteOptions, StreamWriteState, VerificationReport,
};
pub use profile::{ComplianceProfile, ProfileReport, validate_archive_profile};
pub use recovery::{
    EntryErasure, ErasureInput, ErasureRange, ProtectedRange, RecoveryMetadata, RecoveryPlan,
    RepairReport, inspect_recovery_metadata, plan_archive_repair, repair_archive,
};
pub use stream::{
    StreamArchiveParser, StreamArchiveSummary, StreamEvent, StreamParseState, StreamStep,
};
