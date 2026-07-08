#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR Protocol v1.0 — Content-Defined Chunking (CDC) support (Milestone 9a).
//!
//! This crate provides:
//! * CDC algorithm identifiers and validation (`SAR_L_CDC`);
//! * CDC_MAP v1 header, data model types, binary parse/serialisation, and
//!   hash verification;
//! * a deterministic FastCDC chunker ([`fastcdc`] module);
//! * CDC validation helpers.
//!
//! # CDC_MAP v1 and hash algorithms
//!
//! The [`CdcMap`] type carries a `hash_algorithm_id` field that identifies the
//! SAR hash algorithm used for all record hashes.  This is **independent** of
//! the `CDC Algo ID` in the LFH: FASTCDC controls chunk *boundaries*;
//! `hash_algorithm_id` controls how chunk *hashes* are computed.
//!
//! Supported hash algorithms for CDC_MAP:
//!
//! | ID   | Name    | Status                                        |
//! |------|---------|-----------------------------------------------|
//! | 0x30 | SHA-256 | supported                                     |
//! | 0x31 | BLAKE3  | **required** for M9a CDC_MAP verification     |
//! | 0x32 | SHA3-256| assigned, not yet implemented (`SAR_ERR_UNSUPPORTED`) |
//! | other| —       | reserved (`SAR_ERR_RESERVED_VALUE`)           |
//!
//! # Supported CDC algorithms
//!
//! | ID | Name | Status |
//! |-----|-------------|---------|
//! | 0x00 | `LITERAL_MODE` | supported (no chunking) |
//! | 0x01 | `RABIN` | not implemented (`SAR_ERR_UNSUPPORTED`) |
//! | 0x02 | `FASTCDC` | **implemented** (required by spec) |
//! | 0x03 | `BUZHASH` | not implemented (`SAR_ERR_UNSUPPORTED`) |
//! | 0x04–0xEF | reserved | `SAR_ERR_RESERVED_VALUE` |
//! | 0xF0–0xFF | `CUSTOM` | `SAR_ERR_UNSUPPORTED` |
//!
//! # Transformation-domain note
//!
//! CDC chunking in this implementation applies to **logical file bytes** after
//! fragment reassembly and sparse reconstruction but before compression or
//! encryption.  In Recipe Mode the payload (after decrypt + decompress) is the
//! ordered list of 32-byte chunk hashes.  See `docs/SPEC_QUESTIONS.md` for
//! outstanding spec ambiguities.

/// CDC algorithm identifier constants.
pub mod algo;
/// FASTCDC deterministic chunker.
pub mod fastcdc;
/// CDC_MAP v1 binary parse, serialisation, and hash verification.
pub mod map;
/// CDC data-model types.
pub mod types;
/// CDC validation helpers.
pub mod validate;

pub use algo::{
    CDC_ALGO_BUZHASH, CDC_ALGO_CUSTOM_MAX, CDC_ALGO_CUSTOM_MIN, CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL,
    CDC_ALGO_RABIN, CDC_RECIPE_HASH_LEN, algo_name,
};
pub use fastcdc::{FastCdcOptions, chunk_data};
pub use map::{parse_cdc_map, verify_cdc_map_record_hash, write_cdc_map};
pub use types::{
    CDC_MAP_HEADER_SIZE, CDC_MAP_RECORD_LEN, CDC_MAP_V1_RECORD_SIZE, CDC_MAP_VERSION_V1, CdcChunk,
    CdcMap, CdcMapHeader, CdcMapRecord, CdcMetadata,
};
pub use validate::{
    validate_cdc_algo_id, validate_cdc_map_bytes, validate_cdc_map_hash_algo_id,
    validate_cdc_metadata,
};
