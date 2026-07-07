//! CDC_MAP TLV binary parse and serialisation (spec section 21.1).
//!
//! The on-wire format is a flat array of 50-byte records:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │ Hash (32 B) | Partition_ID (u16 LE) | Abs_Off (u64 LE) | Comp_Sz (u64 LE) │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! Field widths are not normatively defined by the spec; see
//! `docs/SPEC_QUESTIONS.md` for the documented ambiguity.

use crate::{
    types::{CDC_MAP_RECORD_LEN, CdcMap, CdcMapRecord},
    validate::{CdcError, validate_cdc_map_bytes},
};

/// Parses the raw TLV value bytes of a `CDC_MAP` (type IDs 0x40–0x4F) into a
/// [`CdcMap`].
///
/// # Errors
///
/// * [`CdcError::Malformed`] — length is not a multiple of 50 bytes.
/// * [`CdcError::LimitExceeded`] — record count exceeds `max_records`.
pub fn parse_cdc_map(bytes: &[u8], max_records: usize) -> Result<CdcMap, CdcError> {
    validate_cdc_map_bytes(bytes, max_records)?;
    let count = bytes.len() / CDC_MAP_RECORD_LEN;
    let mut records = Vec::new();
    // Guarded capacity: count was already bounds-checked above.
    records
        .try_reserve(count)
        .map_err(|_| CdcError::LimitExceeded("CDC_MAP allocation failed"))?;

    for i in 0..count {
        let start = i * CDC_MAP_RECORD_LEN;
        let rec_bytes = &bytes[start..start + CDC_MAP_RECORD_LEN];
        let hash: [u8; 32] = rec_bytes[0..32]
            .try_into()
            .map_err(|_| CdcError::Malformed("CDC_MAP hash slice wrong length"))?;
        let partition_id = u16::from_le_bytes(
            rec_bytes[32..34]
                .try_into()
                .map_err(|_| CdcError::Malformed("CDC_MAP partition_id slice wrong length"))?,
        );
        let absolute_offset = u64::from_le_bytes(
            rec_bytes[34..42]
                .try_into()
                .map_err(|_| CdcError::Malformed("CDC_MAP absolute_offset slice wrong length"))?,
        );
        let compressed_size = u64::from_le_bytes(
            rec_bytes[42..50]
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

    Ok(CdcMap { records })
}

/// Serialises a [`CdcMap`] to its on-wire TLV value bytes.
///
/// # Errors
///
/// * [`CdcError::Overflow`] — the serialised length overflows `usize`.
pub fn write_cdc_map(map: &CdcMap) -> Result<Vec<u8>, CdcError> {
    let total = map
        .records
        .len()
        .checked_mul(CDC_MAP_RECORD_LEN)
        .ok_or(CdcError::Overflow("CDC_MAP serialised length overflow"))?;
    let mut out = Vec::new();
    out.try_reserve(total)
        .map_err(|_| CdcError::LimitExceeded("CDC_MAP serialise allocation failed"))?;
    for record in &map.records {
        out.extend_from_slice(&record.hash);
        out.extend_from_slice(&record.partition_id.to_le_bytes());
        out.extend_from_slice(&record.absolute_offset.to_le_bytes());
        out.extend_from_slice(&record.compressed_size.to_le_bytes());
    }
    Ok(out)
}
