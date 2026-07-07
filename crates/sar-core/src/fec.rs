//! Data Recovery TLV parsing, writing, and validation (Section 9.2).
//!
//! This module handles the archive-level `RECOVERY` TLV block (IDs
//! `0x10–0x1F`) and integrates FEC metadata validation with the rest of
//! `sar-core`.

use sar_fec::{FecError, FecMeta, parse_fec_value, validate_fec_algo_id};
use serde::Serialize;

use crate::{error::SarError, limits::ResourceLimits};

// ---------------------------------------------------------------------------
// FecError → SarError conversion
// ---------------------------------------------------------------------------

impl From<FecError> for SarError {
    fn from(e: FecError) -> Self {
        match e {
            FecError::Truncated(m) => Self::Truncated(m),
            FecError::Malformed(m) => Self::Malformed(m),
            FecError::InvalidLength(m) => Self::InvalidLength(m),
            FecError::Overflow(m) => Self::Overflow(m),
            FecError::LimitExceeded(m) => Self::LimitExceeded(m),
            FecError::EcFailed(m) => Self::EcFailed(m),
            FecError::ReservedValue(m) => Self::ReservedValue(m),
            FecError::Unsupported(m) => Self::Unsupported(m),
            FecError::RecoveryUnavailable(m) => Self::RecoveryUnavailable(m),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery TLV ID classification
// ---------------------------------------------------------------------------

/// Classifies a RECOVERY TLV type ID (range `0x10..=0x1F`).
///
/// Returns:
/// * `Ok(())` for supported IDs (`0x11`, `0x14`).
/// * [`SarError::ReservedValue`] for `0x10` or other reserved IDs.
/// * [`SarError::Unsupported`] for assigned-but-unsupported IDs.
pub fn classify_recovery_tlv_id(type_id: u8) -> Result<(), SarError> {
    validate_fec_algo_id(type_id).map_err(SarError::from)
}

// ---------------------------------------------------------------------------
// FEC metadata summary (inspection / serialization)
// ---------------------------------------------------------------------------

/// Summary of FEC metadata for a RECOVERY TLV or LFH Selective FEC value.
/// Parity data bytes are intentionally omitted for concise reporting.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "algorithm")]
pub enum FecSummary {
    /// XOR FEC summary.
    #[serde(rename = "xor")]
    Xor {
        /// Algorithm ID.
        algo_id: u8,
        /// Data blocks per stripe.
        stripe_size: u8,
        /// Block size in bytes.
        block_size: u32,
        /// Original protected byte length.
        original_protected_len: u64,
        /// Number of stripes.
        stripe_count: u32,
        /// Parity data length in bytes.
        parity_data_len: usize,
    },
    /// Reed-Solomon FEC summary.
    #[serde(rename = "reed-solomon")]
    ReedSolomon {
        /// Algorithm ID.
        algo_id: u8,
        /// Data symbols per group (`k`).
        k: u8,
        /// Parity symbols per group (`n-k`).
        parity_count: u8,
        /// Symbol size in bytes.
        symbol_size: u32,
        /// Original protected byte length.
        original_protected_len: u64,
        /// Number of groups.
        group_count: u32,
        /// Parity data length in bytes.
        parity_data_len: usize,
    },
}

impl FecSummary {
    /// Converts a [`FecMeta`] value into an [`FecSummary`].
    #[must_use]
    pub fn from_meta(algo_id: u8, meta: &FecMeta) -> Self {
        match meta {
            FecMeta::Xor(m) => Self::Xor {
                algo_id,
                stripe_size: m.stripe_size,
                block_size: m.block_size,
                original_protected_len: m.original_protected_len,
                stripe_count: m.stripe_count,
                parity_data_len: m.parity_data_len,
            },
            FecMeta::Rs(m) => Self::ReedSolomon {
                algo_id,
                k: m.k,
                parity_count: m.parity_count,
                symbol_size: m.symbol_size,
                original_protected_len: m.original_protected_len,
                group_count: m.group_count,
                parity_data_len: m.parity_data_len,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Validate a RECOVERY TLV value
// ---------------------------------------------------------------------------

/// Parses and validates a Data Recovery TLV, returning its [`FecSummary`].
///
/// `type_id` must be in `0x10..=0x1F`.  `value` must contain the algorithm-
/// specific bytes as declared in Section 9.2.1.
///
/// # Errors
///
/// Returns [`SarError`] for reserved/unsupported algo IDs, or when the value
/// bytes are structurally invalid.
pub fn validate_recovery_tlv(
    type_id: u8,
    value: &[u8],
    limits: &ResourceLimits,
) -> Result<FecSummary, SarError> {
    classify_recovery_tlv_id(type_id)?;
    if type_id == 0x00 {
        return Err(SarError::Malformed(
            "RECOVERY TLV must have non-zero type ID",
        ));
    }
    limits.check_fec_value_bytes(value.len())?;
    let meta = parse_fec_value(type_id, value).map_err(SarError::from)?;
    Ok(FecSummary::from_meta(type_id, &meta))
}

/// Validates the FEC algo ID stored in an LFH `FEC Algo ID` field.
///
/// Returns `Ok(())` for `0x00` (disabled), supported IDs, and propagates the
/// appropriate [`SarError`] for reserved or unsupported values.
///
/// # Errors
///
/// See [`sar_fec::validate_fec_algo_id`].
pub fn validate_lfh_fec_algo_id(algo_id: u8) -> Result<(), SarError> {
    validate_fec_algo_id(algo_id).map_err(SarError::from)
}

/// Parses and validates an LFH FEC value, returning its [`FecSummary`].
///
/// When `algo_id` is `0x00` (disabled) returns `None`.  For a non-zero ID,
/// parses `fec_value` and validates lengths/counts.
///
/// # Errors
///
/// Returns [`SarError`] for reserved/unsupported algo IDs or malformed values.
pub fn parse_lfh_fec_value(
    algo_id: u8,
    fec_value: &[u8],
    limits: &ResourceLimits,
) -> Result<Option<FecSummary>, SarError> {
    if algo_id == 0x00 {
        return Ok(None);
    }
    validate_lfh_fec_algo_id(algo_id)?;
    if fec_value.is_empty() {
        return Err(SarError::InvalidLength(
            "LFH FEC value must be non-empty for non-zero algo ID",
        ));
    }
    limits.check_fec_value_bytes(fec_value.len())?;
    let meta = parse_fec_value(algo_id, fec_value).map_err(SarError::from)?;
    Ok(Some(FecSummary::from_meta(algo_id, &meta)))
}
