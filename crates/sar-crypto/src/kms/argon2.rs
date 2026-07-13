// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::algorithm::{AEAD_KEY_SIZE, ARGON2_VARIANT_ID};
use crate::error::SarCryptoError;
use crate::kms::types::Argon2Params;
use crate::secret::SecretBytes;

/// Derive a 32-byte CEK from `password` using Argon2id.
pub fn derive_key(params: &Argon2Params, password: &[u8]) -> Result<SecretBytes, SarCryptoError> {
    if params.variant != ARGON2_VARIANT_ID {
        return Err(SarCryptoError::Unsupported(
            "only Argon2id (variant 0x03) is implemented",
        ));
    }
    if params.version == 0 {
        return Err(SarCryptoError::Malformed("Argon2 version must be non-zero"));
    }
    if params.salt.len() < 16 {
        return Err(SarCryptoError::Malformed(
            "Argon2 salt length must be >= 16",
        ));
    }
    if params.memory_cost_kib < 65_536 {
        return Err(SarCryptoError::Malformed(
            "Argon2 memory_cost_kib must be >= 65536",
        ));
    }
    if params.time_cost < 1 {
        return Err(SarCryptoError::Malformed("Argon2 time_cost must be >= 1"));
    }
    if params.parallelism < 1 {
        return Err(SarCryptoError::Malformed("Argon2 parallelism must be >= 1"));
    }
    if params.derived_key_length != 32 {
        return Err(SarCryptoError::Malformed(
            "Argon2 derived_key_length must be 32",
        ));
    }

    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        u32::from(params.parallelism),
        Some(AEAD_KEY_SIZE),
    )
    .map_err(|_| SarCryptoError::Malformed("invalid Argon2 parameters"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = Zeroizing::new(vec![0u8; AEAD_KEY_SIZE]);
    argon2
        .hash_password_into(password, &params.salt, &mut key)
        .map_err(|_| SarCryptoError::Internal("Argon2 key derivation failed"))?;
    Ok(key)
}
