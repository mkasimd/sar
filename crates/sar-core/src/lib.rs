// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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
/// Partition Manifest Version 1 codec and local validation (spec §§6.2.1, 19.1).
pub mod partition_manifest;
/// Sparse-file map parsing/writing.
///
/// Wire-format parse/write lives here (`parse_sparse_map`, `write_sparse_map`).
/// Semantic validation and reconstruction are owned by [`sar_sparse`]; import
/// them directly from that crate.
pub mod sparse;
/// Metadata TLV parser/writer.
pub mod tlv;

pub use cdc::{
    CDC_ALGO_BUZHASH, CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL, CDC_ALGO_RABIN, CDC_RECIPE_HASH_LEN,
    CdcAlgoId, CdcChunk, CdcExtProviderMetadata, CdcMapRecord, CdcMetadata, TLV_CDC_CUSTOM,
    TLV_CDC_EXT_PROVIDER, TLV_CDC_MAP, TLV_DATA_HASH_BLAKE3, compute_cdc_chunk_hash,
    is_cdc_metadata_tlv_type, make_cdc_ext_provider_tlv, make_cdc_map_tlv,
    parse_cdc_ext_provider_tlv, parse_entry_cdc_map, validate_cdc_algo_id,
    validate_cdc_metadata_tlv, validate_recipe_payload,
};
pub use error::{SarError, SarStatus};
pub use fec::{FecSummary, parse_lfh_fec_value, validate_recovery_tlv};
pub use flags::{
    EntryMode, GlobalFlags, validate_entry_mode_against_global, validate_global_flags,
};
pub use format::{
    CentralDictionary, Footer, GLOBAL_FLAGS_SIZE, GLOBAL_HEADER_FIXED_LEN,
    GLOBAL_HEADER_FLAGS_OFFSET, GlobalHeader, KmsData, LocalFileHeader, compute_lfh_size,
    decode_global_flags, fec_size_field_offset, global_header_flags_bytes, lfh_bytes_for_aad,
    lfh_to_bytes, parse_central_dictionary, parse_footer, parse_global_header, parse_lfh,
    parse_partition_central_dictionary, require_unpartitioned_processing,
    validate_global_header_prefix, validate_lfh_hash_algo_id, write_central_dictionary,
    write_footer, write_global_header, write_lfh, write_partition_central_dictionary,
};
pub use limits::ResourceLimits;
pub use metadata::{
    EntryCdcMetadata, EntryCompressionMetadata, EntryDeltaMetadata, EntryEncryptionMetadata,
    EntryFecMetadata, EntryFragmentMetadata, EntryHashMetadata, EntryKind, EntryOwnerMetadata,
    EntryPermissionMetadata, EntrySparseMetadata, EntryTimestampMetadata, FieldPresence,
};
pub use partition_manifest::{
    PARTITION_HASH_LEN, PARTITION_MANIFEST_V1_LEN, PARTITION_MANIFEST_VERSION_1,
    PARTITION_MAX_SUPPORTED_COUNT, PARTITION_SET_UUID_LEN, PARTITION_TOTAL_UNKNOWN,
    PartitionManifestFlags, PartitionManifestV1, validate_manifest_hash_algorithm_id,
    validate_partition_manifest_lfh,
};
pub use sar_cdc::CDC_MAP_RECORD_LEN;
pub use sar_cdc::CdcMap;
pub use sparse::{SparseExtent, SparseMap, parse_sparse_map, write_sparse_map};
