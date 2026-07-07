//! CDC data-model types.

use serde::Serialize;

/// A single content-defined chunk produced by a CDC algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcChunk {
    /// Byte offset of this chunk within the logical file.
    pub offset: u64,
    /// Byte length of this chunk.
    pub length: u64,
    /// SHA-256 hash of the chunk bytes (the current implementation always uses
    /// SHA-256).  `None` when hash computation was not requested.
    ///
    /// The spec does not name the hash algorithm for recipe chunk hashes; see
    /// `docs/SPEC_QUESTIONS.md` for the open spec question.
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

/// A single record in a `CDC_MAP` catalog.
///
/// The spec (section 21.1) defines the structure as:
/// `[Hash, Partition_ID, Absolute_Offset, Compressed_Size]`
/// but does not specify field widths.  We use the following conservative
/// widths and document the ambiguity in `docs/SPEC_QUESTIONS.md`:
///
/// | Field | Width |
/// |-------|-------|
/// | Hash | 32 B |
/// | Partition_ID | 2 B (u16 LE) |
/// | Absolute_Offset | 8 B (u64 LE) |
/// | Compressed_Size | 8 B (u64 LE) |
/// Total: 50 bytes per record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcMapRecord {
    /// 32-byte chunk hash (SHA-256 in current implementation).
    ///
    /// The spec does not normatively name the hash algorithm for CDC_MAP
    /// records; SHA-256 is used as a conservative default.  See
    /// `docs/SPEC_QUESTIONS.md` for the open spec question.
    pub hash: [u8; 32],
    /// Partition identifier where the physical chunk bytes reside.
    pub partition_id: u16,
    /// Absolute byte offset of the chunk within the identified partition.
    pub absolute_offset: u64,
    /// Compressed (encoded) byte length of the stored chunk.
    pub compressed_size: u64,
}

/// Byte length of one serialised [`CdcMapRecord`] on the wire.
pub const CDC_MAP_RECORD_LEN: usize = 32 + 2 + 8 + 8; // = 50

/// A parsed CDC_MAP catalog (TLV type IDs 0x40–0x4F).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcMap {
    /// Ordered list of catalog records.
    pub records: Vec<CdcMapRecord>,
}
