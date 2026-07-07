use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::algorithm::{AEAD_KEY_SIZE, PBKDF2_PRF_HMAC_SHA256};
use crate::error::SarCryptoError;
use crate::kms::types::Pbkdf2Params;
use crate::secret::SecretBytes;

/// Derive a 32-byte CEK from `password` using PBKDF2-HMAC-SHA256.
pub fn derive_key(params: &Pbkdf2Params, password: &[u8]) -> Result<SecretBytes, SarCryptoError> {
    if params.salt.len() < 16 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 salt length must be >= 16",
        ));
    }
    if params.iterations < 100_000 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 iterations must be >= 100,000",
        ));
    }
    if params.derived_key_length != 32 {
        return Err(SarCryptoError::Malformed(
            "PBKDF2 derived_key_length must be 32",
        ));
    }
    match params.prf_algo_id {
        PBKDF2_PRF_HMAC_SHA256 => {}
        _ => return Err(SarCryptoError::Unsupported("PBKDF2 PRF not supported")),
    }

    let mut key = Zeroizing::new(vec![0u8; AEAD_KEY_SIZE]);
    pbkdf2_hmac::<Sha256>(password, &params.salt, params.iterations, &mut key);
    Ok(key)
}
