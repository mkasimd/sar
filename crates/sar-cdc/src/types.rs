// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! CDC data-model types.

use serde::Serialize;

/// A single content-defined chunk produced by a CDC algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcChunk {
    /// Byte offset of this chunk within the logical file.
    pub offset: u64,
    /// Byte length of this chunk.
    pub length: u64,
    /// Hash of the chunk bytes.  `None` when hash computation was not
    /// requested.
    pub hash: Option<[u8; 32]>,
}

/// CDC metadata derived from the LFH `CDC Algo ID` field plus the entry
/// payload (in Recipe Mode).
///
/// This structure is populated by the reader when `CDC_SUPPORT` is active and
/// `cdc_algo_id > 0x00` (Recipe Mode).  In Literal Mode (`cdc_algo_id == 0`)
/// this structure will be absent in [`crate::types::CdcMetadata`] terms but
/// the `algorithm_id` is still available through `EntryMetadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcMetadata {
    /// CDC algorithm identifier (one of the `CDC_ALGO_*` constants).
    pub algorithm_id: u8,
    /// Minimum chunk size used when producing the chunks (implementation
    /// default when not stored in the archive).
    pub min_size: u32,
    /// Average (target) chunk size.
    pub avg_size: u32,
    /// Maximum chunk size.
    pub max_size: u32,
    /// Ordered list of chunk descriptors that together cover the logical file.
    pub chunks: Vec<CdcChunk>,
}

// ---------------------------------------------------------------------------
// CDC_MAP v1 header constants
// ---------------------------------------------------------------------------

/// `Map_Version` value for CDC_MAP v1.
pub const CDC_MAP_VERSION_V1: u8 = 0x01;

/// Byte size of the CDC_MAP v1 header.
pub const CDC_MAP_HEADER_SIZE: usize = 16;

/// `Record_Size` value required for CDC_MAP v1 (48 bytes per record).
pub const CDC_MAP_V1_RECORD_SIZE: u16 = 48;

/// Byte length of one serialised [`CdcMapRecord`] on the wire (v1 format).
///
/// Layout (all little-endian):
///
/// | Field             | Size |
/// |-------------------|------|
/// | `Hash`            | 32 B |
/// | `Partition_ID`    |  4 B |
/// | `Absolute_Offset` |  8 B |
/// | `Compressed_Size` |  4 B |
pub const CDC_MAP_RECORD_LEN: usize = 32 + 4 + 8 + 4; // = 48

// ---------------------------------------------------------------------------
// CDC_MAP types
// ---------------------------------------------------------------------------

/// Parsed CDC_MAP v1 header (16 bytes on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcMapHeader {
    /// `Map_Version` — MUST be `0x01` for v1.
    pub map_version: u8,
    /// SAR hash algorithm registry ID used to compute all record hashes.
    ///
    /// `0x31` (BLAKE3) is required.  `0x30` (SHA-256) is supported.
    pub hash_algorithm_id: u8,
    /// `Flags` — MUST be zero for v1; non-zero bits are reserved.
    pub flags: u16,
    /// Number of `CDC_MAP_Record` entries following the header.
    pub record_count: u32,
    /// Wire byte size of each record — MUST be `48` for v1.
    pub record_size: u16,
    /// Six reserved bytes — MUST be zero.
    pub reserved: [u8; 6],
}

/// A single record in a `CDC_MAP` v1 catalog.
///
/// On-wire layout (all little-endian):
///
/// | Field             | Size     |
/// |-------------------|----------|
/// | `Hash`            | 32 bytes |
/// | `Partition_ID`    |  4 bytes |
/// | `Absolute_Offset` |  8 bytes |
/// | `Compressed_Size` |  4 bytes |
///
/// Total: 48 bytes per record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcMapRecord {
    /// 32-byte chunk hash, computed using the `Hash_Algorithm_ID` from the
    /// CDC_MAP header (not the CDC chunking algorithm ID).
    pub hash: [u8; 32],
    /// Partition identifier where the physical chunk bytes reside.
    pub partition_id: u32,
    /// Absolute byte offset of the chunk from the beginning of the archive.
    pub absolute_offset: u64,
    /// Compressed (stored) byte length of the chunk payload.
    pub compressed_size: u32,
}

/// A parsed CDC_MAP catalog (TLV type ID `0x40`).
///
/// The `hash_algorithm_id` field reflects the SAR hash algorithm registry ID
/// stored in the CDC_MAP v1 header.  It is distinct from the CDC chunking
/// algorithm ID (`CDC Algo ID` in the LFH): FASTCDC controls chunk
/// *boundaries*; `hash_algorithm_id` controls how chunk *hashes* are computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcMap {
    /// SAR hash algorithm registry ID used for all record hashes.
    ///
    /// Set to `0x31` (BLAKE3) or `0x30` (SHA-256).  Callers MUST NOT assume
    /// any particular algorithm without reading this field.
    pub hash_algorithm_id: u8,
    /// Ordered list of catalog records.
    pub records: Vec<CdcMapRecord>,
}
