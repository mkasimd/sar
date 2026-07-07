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
//! * [`parse_cdc_ext_provider_tlv`] — inert `CDC_EXT_PROVIDER` URI parsing;
//! * [`validate_cdc_metadata_tlv`] — per-TLV CDC metadata validation;
//! * CDC recipe hash validation helpers.

use sar_cdc::{
    CdcMap,
    map::{parse_cdc_map, write_cdc_map},
    validate::{CdcError, validate_cdc_algo_id as cdc_validate_algo},
};
use serde::Serialize;

use crate::{SarError, limits::ResourceLimits, tlv::Tlv};

/// Type alias re-exported for callers that don't want to depend directly on
/// `sar-cdc`.
pub use sar_cdc::{
    CdcChunk, CdcMapRecord, CdcMetadata,
    algo::{
        CDC_ALGO_BUZHASH, CDC_ALGO_FASTCDC, CDC_ALGO_LITERAL, CDC_ALGO_RABIN, CDC_RECIPE_HASH_LEN,
    },
};

/// DATA_HASH/BLAKE3 TLV type ID.
pub const TLV_DATA_HASH_BLAKE3: u8 = 0x31;
/// CDC_MAP TLV type ID.
pub const TLV_CDC_MAP: u8 = 0x40;
/// CDC_EXT_PROVIDER TLV type ID.
pub const TLV_CDC_EXT_PROVIDER: u8 = 0x41;
/// First reserved CDC metadata TLV type ID.
pub const TLV_CDC_RESERVED_START: u8 = 0x42;
/// Last reserved CDC metadata TLV type ID.
pub const TLV_CDC_RESERVED_END: u8 = 0x4E;
/// CDC_CUSTOM TLV type ID.
pub const TLV_CDC_CUSTOM: u8 = 0x4F;

/// Inert parsed `CDC_EXT_PROVIDER` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdcExtProviderMetadata {
    /// UTF-8 URI string carried by the TLV value.
    pub uri: String,
}

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

/// Returns true when `type_id` is within the CDC metadata registry block.
#[must_use]
pub fn is_cdc_metadata_tlv_type(type_id: u8) -> bool {
    (TLV_CDC_MAP..=TLV_CDC_CUSTOM).contains(&type_id)
}

/// Parses a `CDC_EXT_PROVIDER` TLV as an inert UTF-8 URI string.
///
/// # Errors
///
/// Returns [`SarError::Unsupported`] when `tlv.type_id` is not `0x41`,
/// [`SarError::LimitExceeded`] when the value exceeds `max_cdc_metadata_bytes`,
/// and [`SarError::Malformed`] when the value is not valid UTF-8.
pub fn parse_cdc_ext_provider_tlv(
    tlv: &Tlv,
    limits: &ResourceLimits,
) -> Result<CdcExtProviderMetadata, SarError> {
    if tlv.type_id != TLV_CDC_EXT_PROVIDER {
        return Err(SarError::Unsupported(
            "TLV is not CDC_EXT_PROVIDER (expected type 0x41)",
        ));
    }
    limits.check_cdc_metadata_bytes(tlv.value.len())?;
    let uri = std::str::from_utf8(&tlv.value)
        .map_err(|_| SarError::Malformed("CDC_EXT_PROVIDER value must be valid UTF-8"))?;
    Ok(CdcExtProviderMetadata {
        uri: uri.to_owned(),
    })
}

/// Validates one CDC metadata TLV according to the updated registry.
///
/// * `0x40` (`CDC_MAP`) — parsed structurally (v1 header + records).
/// * `0x41` (`CDC_EXT_PROVIDER`) — parsed as inert UTF-8 URI metadata only.
/// * `0x42–0x4E` — rejected as reserved.
/// * `0x4F` (`CDC_CUSTOM`) — preserved as implementation-defined opaque bytes.
///
/// # Errors
///
/// Returns [`SarError::ReservedValue`] for reserved CDC TLV IDs and the
/// corresponding parse/limit error for assigned CDC metadata types.
pub fn validate_cdc_metadata_tlv(tlv: &Tlv, limits: &ResourceLimits) -> Result<(), SarError> {
    match tlv.type_id {
        TLV_CDC_MAP => {
            limits.check_cdc_metadata_bytes(tlv.value.len())?;
            let max_records = limits.max_cdc_chunk_count;
            let _ = parse_cdc_map(&tlv.value, max_records).map_err(cdc_err_to_sar)?;
            Ok(())
        }
        TLV_CDC_EXT_PROVIDER => parse_cdc_ext_provider_tlv(tlv, limits).map(|_| ()),
        TLV_CDC_RESERVED_START..=TLV_CDC_RESERVED_END => {
            Err(SarError::ReservedValue("reserved CDC metadata TLV type"))
        }
        TLV_CDC_CUSTOM => {
            limits.check_cdc_metadata_bytes(tlv.value.len())?;
            Ok(())
        }
        _ => Err(SarError::Unsupported(
            "TLV is not in the CDC metadata registry",
        )),
    }
}

/// Builds a `CDC_EXT_PROVIDER` TLV with type ID `0x41`.
///
/// # Errors
///
/// Returns [`SarError`] if the URI exceeds configured CDC metadata limits.
pub fn make_cdc_ext_provider_tlv(uri: &str, limits: &ResourceLimits) -> Result<Tlv, SarError> {
    let value = uri.as_bytes().to_vec();
    limits.check_cdc_metadata_bytes(value.len())?;
    Ok(Tlv {
        type_id: TLV_CDC_EXT_PROVIDER,
        value,
    })
}

/// Extracts and parses the first CDC_MAP TLV (type ID `0x40`) found in
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
        if tlv.type_id == TLV_CDC_MAP {
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
        type_id: TLV_CDC_MAP,
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
