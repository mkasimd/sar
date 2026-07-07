#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Core parser/writer and archive APIs for SAR Protocol v1.0 (Milestones 1–7).

/// Archive reader/writer APIs.
pub mod archive;
/// SAR error and status mapping types.
pub mod error;
/// FEC metadata validation and Data Recovery TLV support (Section 9.2).
pub mod fec;
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
    ArchiveWriterOptions, CompressionSettings, EncryptionSettings, EntryInput, EntryMetadata,
    EntryReader, EntryWritten, VerificationReport,
};
pub use error::{SarError, SarStatus};
pub use fec::{FecSummary, parse_lfh_fec_value, validate_recovery_tlv};
pub use flags::{
    EntryMode, GlobalFlags, validate_entry_mode_against_global, validate_global_flags,
};
pub use format::{
    CentralDictionary, Footer, GlobalHeader, KmsData, LocalFileHeader, PartitionDescriptor,
    compute_lfh_size, global_header_flags_bytes, lfh_to_bytes, parse_central_dictionary,
    parse_footer, parse_global_header, parse_lfh, write_central_dictionary, write_footer,
    write_global_header, write_lfh,
};
pub use profile::{ComplianceProfile, ProfileReport, validate_archive_profile};
pub use sar_crypto::{KeyProvider, KmsContext, KmsParams, SarCryptoError, SecretBytes};
pub use transform::{
    CompressionDecoderTransform, CompressionEncoderTransform, DecoderTransform, DecodingPlan,
    DecodingPlanV2, EncoderTransform, EncodingPlan, EncodingPlanV2, EntryCryptoContext,
    decode_payload, decode_payload_v2, encode_payload, encode_payload_v2,
};
