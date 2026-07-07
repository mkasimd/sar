#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Core parser/writer and archive APIs for SAR Protocol v1.0 (Milestones 1–4).

/// Archive reader/writer APIs.
pub mod archive;
/// SAR error and status mapping types.
pub mod error;
/// Global and entry flag models and validators.
pub mod flags;
/// Binary format structures and parser/writer functions.
pub mod format;
/// Checked binary parsing/writing primitives.
pub mod io;
/// Compliance profile checks.
pub mod profile;
/// Metadata TLV parser/writer.
pub mod tlv;
/// Transform pipeline primitives.
pub mod transform;

pub use archive::{
    ArchiveMetadata, ArchiveReader, ArchiveReaderOptions, ArchiveSummary, ArchiveWriter,
    ArchiveWriterOptions, CompressionSettings, EntryInput, EntryMetadata, EntryReader,
    EntryWritten, VerificationReport,
};
pub use error::{SarError, SarStatus};
pub use flags::{
    EntryMode, GlobalFlags, validate_entry_mode_against_global, validate_global_flags,
};
pub use format::{
    CentralDictionary, Footer, GlobalHeader, KmsData, LocalFileHeader, PartitionDescriptor,
    compute_lfh_size, parse_central_dictionary, parse_footer, parse_global_header, parse_lfh,
    write_central_dictionary, write_footer, write_global_header, write_lfh,
};
pub use profile::{ComplianceProfile, ProfileReport, validate_archive_profile};
pub use transform::{
    CompressionDecoderTransform, CompressionEncoderTransform, DecoderTransform, DecodingPlan,
    EncoderTransform, EncodingPlan, decode_payload, encode_payload,
};
