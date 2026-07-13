// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Algorithm registry and validation for FEC algorithm identifiers.

use crate::error::FecError;

use crate::types::{FecCodec, FecMeta, FecValue};

/// Reed-Solomon FEC algorithm ID.
pub const FEC_ALGO_REED_SOLOMON: u8 = 0x11;
/// XOR FEC algorithm ID.
pub const FEC_ALGO_XOR: u8 = 0x14;

/// Validates a FEC algorithm ID from an LFH `FEC Algo ID` field.
///
/// Returns:
/// * `Ok(())` when the ID is supported (`0x11` or `0x14`).
/// * `Ok(())` for `0x00` (disabled / none) — caller decides how to handle.
/// * [`FecError::ReservedValue`] for `0x10` (reserved).
/// * [`FecError::ReservedValue`] for other reserved values in `0x10..=0x1F`.
/// * [`FecError::Unsupported`] for assigned-but-unsupported IDs (`0x12`,
///   `0x13`, `0x15`, `0x16`).
/// * [`FecError::ReservedValue`] for any value outside `0x00..=0x1F`.
pub fn validate_fec_algo_id(algo_id: u8) -> Result<(), FecError> {
    match algo_id {
        0x00 => Ok(()), // disabled
        0x10 => Err(FecError::ReservedValue("FEC algo ID 0x10 is reserved")),
        0x11 => Ok(()), // Reed-Solomon — supported
        0x12 | 0x13 | 0x15 | 0x16 => Err(FecError::Unsupported(
            "FEC algorithm is assigned but not implemented",
        )),
        0x14 => Ok(()), // XOR — supported
        0x17..=0x1F => Err(FecError::ReservedValue("reserved FEC algo ID")),
        _ => Err(FecError::ReservedValue("FEC algo ID out of defined range")),
    }
}

/// Parses and validates a FEC value, returning structured metadata.
///
/// Dispatches to the appropriate codec based on `algo_id`.
///
/// # Errors
///
/// Returns [`SarError`] when the algo ID is unsupported/reserved, or when the
/// value bytes are malformed or have inconsistent lengths.
pub fn parse_fec_value(algo_id: u8, value_data: &[u8]) -> Result<FecMeta, FecError> {
    match algo_id {
        0x11 => {
            let codec = crate::rs::RsCodec::from_fec_value(value_data)?;
            codec.validate(value_data)?;
            Ok(FecMeta::Rs(crate::rs::parse_rs_meta(value_data)?))
        }
        0x14 => {
            let codec = crate::xor::XorCodec::from_fec_value(value_data)?;
            codec.validate(value_data)?;
            Ok(FecMeta::Xor(crate::xor::parse_xor_meta(value_data)?))
        }
        0x10 | 0x17..=0x1F => Err(FecError::ReservedValue("reserved FEC algorithm ID")),
        0x12 | 0x13 | 0x15 | 0x16 => Err(FecError::Unsupported(
            "FEC algorithm is assigned but not implemented",
        )),
        _ => Err(FecError::ReservedValue("FEC algo ID out of defined range")),
    }
}

/// Constructs a [`FecValue`] by encoding FEC parity for `protected` bytes
/// using the algorithm identified by `algo_id` and algorithm-specific `config`
/// bytes.
///
/// `config[0]` and `config[1]` are the two algorithm-specific configuration
/// bytes; `extra` supplies any additional algorithm-specific parameters (e.g.
/// symbol size for RS).
///
/// # Errors
///
/// Returns [`SarError`] on unsupported/reserved algorithm IDs or if encoding
/// fails.
#[allow(dead_code)]
pub(crate) fn encode_fec(
    algo_id: u8,
    protected: &[u8],
    config0: u8,
    config1: u8,
    symbol_size_for_rs: Option<u32>,
) -> Result<FecValue, FecError> {
    use crate::types::FecOptions;
    match algo_id {
        0x11 => {
            let symbol_size = symbol_size_for_rs.ok_or(FecError::Malformed(
                "RS codec requires a symbol_size parameter",
            ))?;
            let codec = crate::rs::RsCodec::new(config0, config1, symbol_size)?;
            codec.encode_recovery(protected, FecOptions)
        }
        0x14 => {
            let codec = crate::xor::XorCodec::new(config0, config1)?;
            codec.encode_recovery(protected, FecOptions)
        }
        0x10 | 0x17..=0x1F => Err(FecError::ReservedValue("reserved FEC algorithm ID")),
        _ => Err(FecError::Unsupported(
            "FEC algorithm is assigned but not implemented",
        )),
    }
}
