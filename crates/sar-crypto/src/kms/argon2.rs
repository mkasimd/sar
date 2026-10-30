// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::algorithm::{ARGON2_VARIANT_ID, ARGON2_VERSION_0X13, KMS_MASTER_SECRET_SIZE};
use crate::error::SarCryptoError;
use crate::kms::limits::KdfLimits;
use crate::kms::types::Argon2Params;
use crate::secret::SecretBytes;

/// Derive the 32-byte KMS Master Secret from `password` using Argon2id version 0x13.
///
/// Structural validation runs first, then `limits` is checked, and only then
/// is any memory allocated for derivation.
///
/// # Errors
///
/// * [`SarCryptoError::ReservedValue`] for a reserved variant.
/// * [`SarCryptoError::Unsupported`] for a version other than `0x13`.
/// * [`SarCryptoError::InvalidLength`] for a violated minimum or Derived Key Length.
/// * [`SarCryptoError::LimitExceeded`] when `limits` is exceeded.
pub fn derive_key(
    params: &Argon2Params,
    password: &[u8],
    limits: &KdfLimits,
) -> Result<SecretBytes, SarCryptoError> {
    if params.variant != ARGON2_VARIANT_ID {
        return Err(SarCryptoError::ReservedValue("reserved Argon2 variant"));
    }
    if params.version != ARGON2_VERSION_0X13 {
        return Err(SarCryptoError::Unsupported(
            "only Argon2 version 0x13 is supported",
        ));
    }
    if usize::from(params.derived_key_length) != KMS_MASTER_SECRET_SIZE {
        return Err(SarCryptoError::InvalidLength(
            "Argon2 Derived Key Length must be 32",
        ));
    }
    if params.memory_cost_kib == 0 || params.time_cost == 0 || params.parallelism == 0 {
        return Err(SarCryptoError::InvalidLength(
            "Argon2 memory, time and parallelism must be > 0",
        ));
    }
    if params.salt.len() < 16 {
        return Err(SarCryptoError::InvalidLength(
            "Argon2 salt length must be >= 16",
        ));
    }
    limits.check_argon2(params)?;

    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        u32::from(params.parallelism),
        Some(KMS_MASTER_SECRET_SIZE),
    )
    .map_err(|_| SarCryptoError::Unsupported("Argon2 parameters outside library capability"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = Zeroizing::new(vec![0u8; KMS_MASTER_SECRET_SIZE]);
    argon2
        .hash_password_into(password, &params.salt, &mut key)
        .map_err(|_| SarCryptoError::Internal("Argon2 key derivation failed"))?;
    Ok(key)
}
