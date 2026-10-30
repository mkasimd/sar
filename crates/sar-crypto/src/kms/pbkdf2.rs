// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::algorithm::{KMS_MASTER_SECRET_SIZE, PBKDF2_PRF_HMAC_SHA256};
use crate::error::SarCryptoError;
use crate::kms::limits::KdfLimits;
use crate::kms::types::Pbkdf2Params;
use crate::secret::SecretBytes;

/// Derive the 32-byte KMS Master Secret from `password` using PBKDF2-HMAC-SHA256.
///
/// Structural validation runs first, then `limits` is checked, and only then
/// is the (expensive) derivation performed.
///
/// # Errors
///
/// * [`SarCryptoError::InvalidLength`] for a violated minimum or Derived Key Length.
/// * [`SarCryptoError::Unsupported`] / [`SarCryptoError::ReservedValue`] for the PRF.
/// * [`SarCryptoError::LimitExceeded`] when `limits` is exceeded.
pub fn derive_key(
    params: &Pbkdf2Params,
    password: &[u8],
    limits: &KdfLimits,
) -> Result<SecretBytes, SarCryptoError> {
    match params.prf_algo_id {
        PBKDF2_PRF_HMAC_SHA256 => {}
        0x02 | 0x03 => {
            return Err(SarCryptoError::Unsupported(
                "PBKDF2 PRF algorithm not implemented",
            ));
        }
        _ => {
            return Err(SarCryptoError::ReservedValue(
                "unknown PBKDF2 PRF algorithm ID",
            ));
        }
    }
    if usize::from(params.derived_key_length) != KMS_MASTER_SECRET_SIZE {
        return Err(SarCryptoError::InvalidLength(
            "PBKDF2 Derived Key Length must be 32",
        ));
    }
    if params.salt.len() < 16 {
        return Err(SarCryptoError::InvalidLength(
            "PBKDF2 salt length must be >= 16",
        ));
    }
    if params.iterations < 100_000 {
        return Err(SarCryptoError::InvalidLength(
            "PBKDF2 iterations must be >= 100000",
        ));
    }
    limits.check_pbkdf2(params)?;

    let mut key = Zeroizing::new(vec![0u8; KMS_MASTER_SECRET_SIZE]);
    pbkdf2_hmac::<Sha256>(password, &params.salt, params.iterations, &mut key);
    Ok(key)
}
