#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Core canonical wire-format, status/error, and low-level helper APIs for SAR Protocol v1.0.
/// CDC (Content-Defined Chunking) support: algorithm IDs, map parsing/writing,
/// recipe validation (Milestone 9a).
pub mod cdc;
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
/// Unified resource-limit model for the parse/read/write pipeline.
pub mod limits;
/// Expanded LFH metadata types (M11a).
pub mod metadata;
/// Archive-level Data Recovery TLV inspection, planning, and repair.
pub mod recovery;
/// Sparse-file map parsing/writing.
///
/// Wire-format parse/write lives here (`parse_sparse_map`, `write_sparse_map`).
/// Semantic validation and reconstruction are owned by [`sar_sparse`]; import
/// them directly from that crate.
pub mod sparse;
/// Metadata TLV parser/writer.
pub mod tlv;
/// Transform pipeline primitives.
pub mod transform;

pub use cdc::{
    CDC_ALGO_BUZHASH, CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL, CDC_ALGO_RABIN, CDC_RECIPE_HASH_LEN,
    CdcAlgoId, CdcChunk, CdcExtProviderMetadata, CdcMapRecord, CdcMetadata, TLV_CDC_CUSTOM,
    TLV_CDC_EXT_PROVIDER, TLV_CDC_MAP, TLV_DATA_HASH_BLAKE3, is_cdc_metadata_tlv_type,
    make_cdc_ext_provider_tlv, make_cdc_map_tlv, parse_cdc_ext_provider_tlv, parse_entry_cdc_map,
    validate_cdc_algo_id, validate_cdc_metadata_tlv, validate_recipe_payload,
};
pub use error::{SarError, SarStatus};
pub use fec::{FecSummary, parse_lfh_fec_value, validate_recovery_tlv};
pub use flags::{
    EntryMode, GlobalFlags, validate_entry_mode_against_global, validate_global_flags,
};
pub use format::{
    CentralDictionary, Footer, GlobalHeader, KmsData, LfhFragmentDescriptor, LocalFileHeader,
    PartitionDescriptor, compute_lfh_size, fec_size_field_offset, global_header_flags_bytes,
    lfh_bytes_for_aad, lfh_to_bytes, parse_central_dictionary, parse_footer, parse_global_header,
    parse_lfh, write_central_dictionary, write_footer, write_global_header, write_lfh,
};
pub use limits::ResourceLimits;
pub use metadata::{
    EntryCdcMetadata, EntryCompressionMetadata, EntryDeltaMetadata, EntryEncryptionMetadata,
    EntryFecMetadata, EntryFragmentMetadata, EntryHashMetadata, EntryKind, EntryOwnerMetadata,
    EntryPermissionMetadata, EntrySparseMetadata, EntryTimestampMetadata, FieldPresence,
};
pub use recovery::{
    EntryErasure, ErasureInput, ErasureRange, ProtectedRange, RecoveryMetadata, RecoveryPlan,
    RepairReport, inspect_recovery_metadata, plan_archive_repair, repair_archive,
};
pub use sar_cdc::CDC_MAP_RECORD_LEN;
pub use sar_cdc::CdcMap;
pub use sar_crypto::{KeyProvider, KmsContext, KmsParams, SarCryptoError, SecretBytes};
pub use sar_delta::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MAX, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH,
    PATCH_ALGO_VCDIFF, PATCH_ALGO_ZSTD_PATCH, PatchAlgoId, PatchError, apply_bsdiff,
    apply_store_patch, apply_vcdiff, bsdiff::BsdiffLimits, patch_algo_name, validate_patch_algo_id,
    vcdiff::VcdiffLimits,
};
pub use sparse::{SparseExtent, parse_sparse_map, write_sparse_map};
pub use transform::{
    CompressionDecoderTransform, CompressionEncoderTransform, DecoderTransform, DecodingPlan,
    DecodingPlanV2, EncoderTransform, EncodingPlan, EncodingPlanV2, EntryCryptoContext,
    decode_payload, decode_payload_v2, encode_payload, encode_payload_v2,
};
