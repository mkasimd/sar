// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use crate::error::SarCryptoError;
use crate::kms::types::{Argon2Params, Pbkdf2Params};

/// Resource ceilings applied to KDF parameters before expensive derivation.
///
/// The defaults admit the complete mandatory interoperability ranges of
/// Section 5.3.4 (PBKDF2 up to 600 000 iterations, Argon2id up to 65 536 KiB,
/// time cost 3, parallelism 4, salts up to 64 bytes) and are finite.  These
/// are local policy ceilings, not maximum legal SAR work factors.
/// `sar_core::ResourceLimits::kdf_limits` builds this from the unified limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfLimits {
    /// Maximum accepted PBKDF2 iteration count.
    pub max_pbkdf2_iterations: u32,
    /// Maximum accepted KDF salt length in bytes.
    pub max_kdf_salt_bytes: usize,
    /// Maximum accepted Argon2 memory cost in KiB.
    pub max_argon2_memory_kib: u32,
    /// Maximum accepted Argon2 time cost.
    pub max_argon2_time_cost: u32,
    /// Maximum accepted Argon2 parallelism.
    pub max_argon2_parallelism: u16,
}

impl KdfLimits {
    /// Default PBKDF2 iteration ceiling: about 3.3x the mandatory 600000.
    pub const DEFAULT_MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;
    /// Default KDF salt ceiling: the mandatory 64-byte interoperable salt.
    pub const DEFAULT_MAX_KDF_SALT_BYTES: usize = 64;
    /// Default Argon2 memory ceiling (256 MiB): 4x the mandatory 65536 KiB.
    pub const DEFAULT_MAX_ARGON2_MEMORY_KIB: u32 = 262_144;
    /// Default Argon2 time-cost ceiling: above the mandatory 3.
    pub const DEFAULT_MAX_ARGON2_TIME_COST: u32 = 6;
    /// Default Argon2 parallelism ceiling: 2x the mandatory 4.
    pub const DEFAULT_MAX_ARGON2_PARALLELISM: u16 = 8;

    /// Limits that accept every representable parameter value.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_pbkdf2_iterations: u32::MAX,
            max_kdf_salt_bytes: usize::MAX,
            max_argon2_memory_kib: u32::MAX,
            max_argon2_time_cost: u32::MAX,
            max_argon2_parallelism: u16::MAX,
        }
    }

    /// Checks structurally valid PBKDF2 parameters against these limits.
    ///
    /// # Errors
    ///
    /// Returns [`SarCryptoError::LimitExceeded`] when a limit is exceeded.
    pub fn check_pbkdf2(&self, params: &Pbkdf2Params) -> Result<(), SarCryptoError> {
        if params.salt.len() > self.max_kdf_salt_bytes {
            return Err(SarCryptoError::LimitExceeded(
                "KDF salt length exceeds configured limit",
            ));
        }
        if params.iterations > self.max_pbkdf2_iterations {
            return Err(SarCryptoError::LimitExceeded(
                "PBKDF2 iterations exceed configured limit",
            ));
        }
        Ok(())
    }

    /// Checks structurally valid Argon2 parameters against these limits.
    ///
    /// # Errors
    ///
    /// Returns [`SarCryptoError::LimitExceeded`] when a limit is exceeded.
    pub fn check_argon2(&self, params: &Argon2Params) -> Result<(), SarCryptoError> {
        if params.salt.len() > self.max_kdf_salt_bytes {
            return Err(SarCryptoError::LimitExceeded(
                "KDF salt length exceeds configured limit",
            ));
        }
        if params.memory_cost_kib > self.max_argon2_memory_kib {
            return Err(SarCryptoError::LimitExceeded(
                "Argon2 memory cost exceeds configured limit",
            ));
        }
        if params.time_cost > self.max_argon2_time_cost {
            return Err(SarCryptoError::LimitExceeded(
                "Argon2 time cost exceeds configured limit",
            ));
        }
        if params.parallelism > self.max_argon2_parallelism {
            return Err(SarCryptoError::LimitExceeded(
                "Argon2 parallelism exceeds configured limit",
            ));
        }
        Ok(())
    }
}

impl Default for KdfLimits {
    fn default() -> Self {
        Self {
            max_pbkdf2_iterations: Self::DEFAULT_MAX_PBKDF2_ITERATIONS,
            max_kdf_salt_bytes: Self::DEFAULT_MAX_KDF_SALT_BYTES,
            max_argon2_memory_kib: Self::DEFAULT_MAX_ARGON2_MEMORY_KIB,
            max_argon2_time_cost: Self::DEFAULT_MAX_ARGON2_TIME_COST,
            max_argon2_parallelism: Self::DEFAULT_MAX_ARGON2_PARALLELISM,
        }
    }
}
