// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! CDC_MAP TLV v1 binary parse, serialisation, and hash verification.
//!
//! ## On-wire format
//!
//! ```text
//! CDC_MAP_Header (16 bytes) || CDC_MAP_Record[Record_Count] (Record_Count × 48 bytes)
//! ```
//!
//! All multi-byte fields are little-endian.
//!
//! ### CDC_MAP_Header v1 (16 bytes)
//!
//! | Field              | Size | Description                                        |
//! |--------------------|------|----------------------------------------------------|
//! | `Map_Version`      | 1 B  | MUST be `0x01`                                     |
//! | `Hash_Algorithm_ID`| 1 B  | SAR hash registry ID for all record hashes         |
//! | `Flags`            | 2 B  | MUST be zero; non-zero bits are reserved           |
//! | `Record_Count`     | 4 B  | Number of records following the header             |
//! | `Record_Size`      | 2 B  | MUST be `48`                                       |
//! | `Reserved`         | 6 B  | MUST be zero                                       |
//!
//! ### CDC_MAP_Record v1 (48 bytes)
//!
//! | Field             | Size | Description                                        |
//! |-------------------|------|----------------------------------------------------|
//! | `Hash`            | 32 B | Chunk hash using `Hash_Algorithm_ID`               |
//! | `Partition_ID`    |  4 B | Partition identifier                               |
//! | `Absolute_Offset` |  8 B | Absolute byte offset from archive start            |
//! | `Compressed_Size` |  4 B | Stored chunk payload size in bytes                 |
//!
//! ## Hash algorithm vs. CDC chunking algorithm
//!
//! `Hash_Algorithm_ID` determines how stored CDC_MAP record hashes are
//! computed.  FASTCDC determines *chunk boundaries*.  These are independent:
//! do not treat the LFH `CDC Algo ID` (chunking algorithm) as the hash
//! algorithm for CDC_MAP records.

use crate::{
    types::{
        CDC_MAP_HEADER_SIZE, CDC_MAP_RECORD_LEN, CDC_MAP_V1_RECORD_SIZE, CDC_MAP_VERSION_V1,
        CdcMap, CdcMapRecord,
    },
    validate::{CdcError, validate_cdc_map_hash_algo_id},
};

/// Parses the raw TLV value bytes of a `CDC_MAP` (type ID `0x40`) into a
/// [`CdcMap`].
///
/// Performs full structural validation:
/// * TLV length ≥ 16 (header size);
/// * `Map_Version` is `0x01`;
/// * `Hash_Algorithm_ID` is assigned and supported;
/// * `Flags` are zero;
/// * `Reserved` bytes are zero;
/// * `Record_Size` is `48`;
/// * TLV length equals `16 + Record_Count × 48` (checked arithmetic);
/// * `Record_Count` ≤ `max_records`.
///
/// # Errors
///
/// Returns [`CdcError`] for any structural violation.
pub fn parse_cdc_map(bytes: &[u8], max_records: usize) -> Result<CdcMap, CdcError> {
    // Minimum length check.
    if bytes.len() < CDC_MAP_HEADER_SIZE {
        return Err(CdcError::Malformed(
            "CDC_MAP TLV too short to contain the v1 header (need ≥ 16 bytes)",
        ));
    }

    // --- Parse header fields ---
    let map_version = bytes[0];
    if map_version != CDC_MAP_VERSION_V1 {
        return Err(CdcError::Unsupported(
            "CDC_MAP Map_Version not supported (only v1 = 0x01 is defined)",
        ));
    }

    let hash_algorithm_id = bytes[1];
    validate_cdc_map_hash_algo_id(hash_algorithm_id)?;

    let flags = u16::from_le_bytes([bytes[2], bytes[3]]);
    if flags != 0 {
        return Err(CdcError::Malformed(
            "CDC_MAP Flags must be zero for v1; non-zero bits are reserved",
        ));
    }

    let record_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    let record_size = u16::from_le_bytes([bytes[8], bytes[9]]);
    if record_size != CDC_MAP_V1_RECORD_SIZE {
        return Err(CdcError::Malformed("CDC_MAP Record_Size must be 48 for v1"));
    }

    // Reserved bytes [10..16] must all be zero.
    if bytes[10..16].iter().any(|&b| b != 0) {
        return Err(CdcError::Malformed("CDC_MAP Reserved bytes must be zero"));
    }

    // --- Validate TLV length (checked arithmetic) ---
    let records_bytes = (record_count as usize)
        .checked_mul(CDC_MAP_RECORD_LEN)
        .ok_or(CdcError::Overflow(
            "CDC_MAP Record_Count × Record_Size overflow",
        ))?;
    let expected_len = records_bytes
        .checked_add(CDC_MAP_HEADER_SIZE)
        .ok_or(CdcError::Overflow("CDC_MAP total length overflow"))?;
    if bytes.len() != expected_len {
        return Err(CdcError::Malformed(
            "CDC_MAP TLV Length does not equal 16 + Record_Count × 48",
        ));
    }

    // --- Record count limit ---
    if record_count as usize > max_records {
        return Err(CdcError::LimitExceeded(
            "CDC_MAP record count exceeds configured limit",
        ));
    }

    // --- Parse records ---
    let count = record_count as usize;
    let mut records = Vec::new();
    records
        .try_reserve(count)
        .map_err(|_| CdcError::LimitExceeded("CDC_MAP allocation failed"))?;

    for i in 0..count {
        let start = CDC_MAP_HEADER_SIZE + i * CDC_MAP_RECORD_LEN;
        let rec = &bytes[start..start + CDC_MAP_RECORD_LEN];

        let hash: [u8; 32] = rec[0..32]
            .try_into()
            .map_err(|_| CdcError::Malformed("CDC_MAP hash slice wrong length"))?;

        let partition_id = u32::from_le_bytes(
            rec[32..36]
                .try_into()
                .map_err(|_| CdcError::Malformed("CDC_MAP partition_id slice wrong length"))?,
        );

        let absolute_offset = u64::from_le_bytes(
            rec[36..44]
                .try_into()
                .map_err(|_| CdcError::Malformed("CDC_MAP absolute_offset slice wrong length"))?,
        );

        let compressed_size = u32::from_le_bytes(
            rec[44..48]
                .try_into()
                .map_err(|_| CdcError::Malformed("CDC_MAP compressed_size slice wrong length"))?,
        );

        records.push(CdcMapRecord {
            hash,
            partition_id,
            absolute_offset,
            compressed_size,
        });
    }

    Ok(CdcMap {
        hash_algorithm_id,
        records,
    })
}

/// Serialises a [`CdcMap`] to its on-wire TLV v1 value bytes.
///
/// Writes the 16-byte v1 header followed by `records.len()` 48-byte records.
///
/// # Errors
///
/// * [`CdcError::Overflow`] — the record count overflows `u32` or the
///   serialised length overflows `usize`.
/// * [`CdcError::Unsupported`] / [`CdcError::ReservedValue`] — the
///   `hash_algorithm_id` is not valid.
pub fn write_cdc_map(map: &CdcMap) -> Result<Vec<u8>, CdcError> {
    validate_cdc_map_hash_algo_id(map.hash_algorithm_id)?;

    let record_count_u32 = u32::try_from(map.records.len())
        .map_err(|_| CdcError::Overflow("CDC_MAP record count overflows u32"))?;

    let records_bytes = map
        .records
        .len()
        .checked_mul(CDC_MAP_RECORD_LEN)
        .ok_or(CdcError::Overflow("CDC_MAP records length overflow"))?;

    let total = records_bytes
        .checked_add(CDC_MAP_HEADER_SIZE)
        .ok_or(CdcError::Overflow("CDC_MAP total length overflow"))?;

    let mut out = Vec::new();
    out.try_reserve(total)
        .map_err(|_| CdcError::LimitExceeded("CDC_MAP serialise allocation failed"))?;

    // Header (16 bytes)
    out.push(CDC_MAP_VERSION_V1);
    out.push(map.hash_algorithm_id);
    out.extend_from_slice(&0u16.to_le_bytes()); // Flags = 0
    out.extend_from_slice(&record_count_u32.to_le_bytes());
    out.extend_from_slice(&CDC_MAP_V1_RECORD_SIZE.to_le_bytes());
    out.extend_from_slice(&[0u8; 6]); // Reserved = 0

    // Records (48 bytes each)
    for record in &map.records {
        out.extend_from_slice(&record.hash);
        out.extend_from_slice(&record.partition_id.to_le_bytes());
        out.extend_from_slice(&record.absolute_offset.to_le_bytes());
        out.extend_from_slice(&record.compressed_size.to_le_bytes());
    }

    Ok(out)
}

/// Verifies the stored hash of a single [`CdcMapRecord`] against a slice of
/// archive bytes.
///
/// The hash covers the exact stored byte range
/// `[absolute_offset, absolute_offset + compressed_size)` within
/// `archive_bytes`.
///
/// Verification uses `hash_algorithm_id` from the CDC_MAP header — **not**
/// the CDC chunking algorithm ID.  FASTCDC determines chunk boundaries;
/// `hash_algorithm_id` determines how chunk hashes are computed.
///
/// # Arguments
///
/// * `record` — the CDC_MAP record whose hash is being verified.
/// * `hash_algorithm_id` — the `Hash_Algorithm_ID` from the CDC_MAP header.
/// * `archive_bytes` — a byte slice containing the full archive (or at least
///   the byte range referenced by `record`).
///
/// # Errors
///
/// * [`CdcError::Unsupported`] / [`CdcError::ReservedValue`] — `hash_algorithm_id` is invalid.
/// * [`CdcError::Overflow`] — `absolute_offset + compressed_size` overflows `u64`.
/// * [`CdcError::Bounds`] — the record's byte range exceeds `archive_bytes`.
pub fn verify_cdc_map_record_hash(
    record: &CdcMapRecord,
    hash_algorithm_id: u8,
    archive_bytes: &[u8],
) -> Result<bool, CdcError> {
    validate_cdc_map_hash_algo_id(hash_algorithm_id)?;

    // Checked arithmetic: absolute_offset + compressed_size.
    let end_u64 = record
        .absolute_offset
        .checked_add(u64::from(record.compressed_size))
        .ok_or(CdcError::Overflow(
            "CDC_MAP Absolute_Offset + Compressed_Size overflow",
        ))?;

    let start = usize::try_from(record.absolute_offset)
        .map_err(|_| CdcError::Bounds("CDC_MAP absolute_offset exceeds addressable range"))?;
    let end = usize::try_from(end_u64)
        .map_err(|_| CdcError::Bounds("CDC_MAP record end offset exceeds addressable range"))?;

    if end > archive_bytes.len() {
        return Err(CdcError::Bounds(
            "CDC_MAP record byte range exceeds archive bounds",
        ));
    }

    let chunk_bytes = &archive_bytes[start..end];

    let computed: [u8; 32] = match hash_algorithm_id {
        0x30 => {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(chunk_bytes);
            h.finalize().into()
        }
        0x31 => *blake3::hash(chunk_bytes).as_bytes(),
        _ => {
            return Err(CdcError::Unsupported(
                "hash algorithm not supported for CDC_MAP verification",
            ));
        }
    };

    Ok(computed == record.hash)
}
