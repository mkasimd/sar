//! CDC (Content-Defined Chunking) support for the SAR core parser/writer.
//!
//! This module bridges [`sar_cdc`] primitives with the `sar-core` type
//! system, providing:
//!
//! * [`CdcAlgoId`] — typed wrapper for the `CDC Algo ID` LFH field;
//! * [`validate_cdc_algo_id`] — per-algorithm validation against the spec
//!   (section 8.5);
//! * [`parse_entry_cdc_map`] — CDC_MAP TLV extraction from a CD metadata set;
//! * [`make_cdc_map_tlv`] — serialise a [`CdcMap`] into a Tlv;
//! * CDC recipe hash validation helpers.

use sar_cdc::{
    CdcMap,
    map::{parse_cdc_map, write_cdc_map},
    validate::{CdcError, validate_cdc_algo_id as cdc_validate_algo},
};

use crate::{SarError, limits::ResourceLimits, tlv::Tlv};

/// Type alias re-exported for callers that don't want to depend directly on
/// `sar-cdc`.
pub use sar_cdc::{
    CdcChunk, CdcMapRecord, CdcMetadata,
    algo::{
        CDC_ALGO_BUZHASH, CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL, CDC_ALGO_RABIN, CDC_RECIPE_HASH_LEN,
    },
};

/// Typed CDC algorithm identifier; wraps the raw `u8` stored in the LFH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdcAlgoId(pub u8);

impl CdcAlgoId {
    /// Returns `true` if this ID indicates Literal Mode (no recipe).
    #[must_use]
    pub fn is_literal(self) -> bool {
        self.0 == CDC_ALGO_LITERAL
    }

    /// Returns `true` if this ID indicates Recipe Mode (payload is a hash
    /// recipe that must be resolved against the CDC_MAP).
    #[must_use]
    pub fn is_recipe_mode(self) -> bool {
        self.0 != CDC_ALGO_LITERAL
    }
}

/// Converts a [`CdcError`] to a [`SarError`].
pub(crate) fn cdc_err_to_sar(e: CdcError) -> SarError {
    match e {
        CdcError::Unsupported(m) => SarError::Unsupported(m),
        CdcError::ReservedValue(m) => SarError::ReservedValue(m),
        CdcError::Overflow(m) => SarError::Overflow(m),
        CdcError::Bounds(m) => SarError::Bounds(m),
        CdcError::Malformed(m) => SarError::Malformed(m),
        CdcError::LimitExceeded(m) => SarError::LimitExceeded(m),
        CdcError::InvalidLength(m) => SarError::InvalidLength(m),
    }
}

/// Validates a raw CDC algorithm ID byte.
///
/// * `0x00` (LITERAL_MODE) — accepted.
/// * `0x02` (FASTCDC) — accepted.
/// * `0x01` / `0x03` — returns [`SarError::Unsupported`].
/// * `0xF0–0xFF` (CUSTOM) — returns [`SarError::Unsupported`].
/// * `0x04–0xEF` — returns [`SarError::ReservedValue`].
///
/// # Errors
///
/// Returns [`SarError::Unsupported`] or [`SarError::ReservedValue`].
pub fn validate_cdc_algo_id(id: u8) -> Result<(), SarError> {
    cdc_validate_algo(id).map_err(cdc_err_to_sar)
}

/// Extracts and parses the first CDC_MAP TLV (type IDs 0x40–0x4F) found in
/// `tlvs`, returning the parsed [`CdcMap`] or `None` if none is present.
///
/// # Errors
///
/// Returns [`SarError`] if the TLV is found but malformed or exceeds limits.
pub fn parse_entry_cdc_map(
    tlvs: &[Tlv],
    limits: &ResourceLimits,
) -> Result<Option<CdcMap>, SarError> {
    limits.check_cdc_metadata_bytes(0)?; // fast-fail if limit is 0

    for tlv in tlvs {
        if (0x40..=0x4F).contains(&tlv.type_id) {
            limits.check_cdc_metadata_bytes(tlv.value.len())?;
            let max_records = limits.max_cdc_chunk_count;
            let map = parse_cdc_map(&tlv.value, max_records).map_err(cdc_err_to_sar)?;
            return Ok(Some(map));
        }
    }
    Ok(None)
}

/// Serialises a [`CdcMap`] into a [`Tlv`] with type ID `0x40`.
///
/// # Errors
///
/// Returns [`SarError`] if serialisation fails or the result exceeds limits.
pub fn make_cdc_map_tlv(map: &CdcMap, limits: &ResourceLimits) -> Result<Tlv, SarError> {
    let value = write_cdc_map(map).map_err(cdc_err_to_sar)?;
    limits.check_cdc_metadata_bytes(value.len())?;
    Ok(Tlv {
        type_id: 0x40,
        value,
    })
}

/// Validates a Recipe payload (raw bytes that are an ordered list of 32-byte
/// chunk hashes) against resource limits.
///
/// Returns the number of hashes (recipe length) on success.
///
/// # Errors
///
/// * [`SarError::InvalidLength`] — payload is not a multiple of 32 bytes.
/// * [`SarError::LimitExceeded`] — hash count exceeds `max_cdc_chunk_count`, or
///   payload length exceeds `max_cdc_metadata_bytes`.
pub fn validate_recipe_payload(payload: &[u8], limits: &ResourceLimits) -> Result<usize, SarError> {
    limits.check_cdc_metadata_bytes(payload.len())?;
    if !payload.len().is_multiple_of(CDC_RECIPE_HASH_LEN) {
        return Err(SarError::InvalidLength(
            "CDC recipe payload length is not a multiple of the hash size (32)",
        ));
    }
    let count = payload.len() / CDC_RECIPE_HASH_LEN;
    limits.check_cdc_chunk_count(count)?;
    Ok(count)
}

/// Extracts the ordered list of 32-byte chunk hashes from a Recipe payload.
///
/// Callers should first call [`validate_recipe_payload`] to bounds-check the
/// slice.
pub fn recipe_hashes(payload: &[u8]) -> Vec<[u8; 32]> {
    payload
        .chunks_exact(CDC_RECIPE_HASH_LEN)
        .map(|chunk| {
            let mut h = [0u8; 32];
            h.copy_from_slice(chunk);
            h
        })
        .collect()
}
