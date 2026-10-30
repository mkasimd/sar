// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Standard Entry-key derivation (specification Section 5.3.4).
//!
//! `Entry_Key = HKDF-SHA256(IKM = KMS Master Secret, salt = empty,
//! info = "SAR-v1-entry-key" || Encr Algo ID || LFH IV/Nonce field,
//! L = native key length)`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::algorithm::{KMS_MASTER_SECRET_SIZE, native_key_len};
use crate::error::SarCryptoError;
use crate::secret::SecretBytes;

type HmacSha256 = Hmac<Sha256>;

/// ASCII label that prefixes the HKDF `info` for Entry-key derivation.
pub const ENTRY_KEY_INFO_LABEL: &[u8; 16] = b"SAR-v1-entry-key";

const SHA256_LEN: usize = 32;

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; SHA256_LEN]>, SarCryptoError> {
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| SarCryptoError::Internal("HMAC-SHA256 key init failed"))?;
    for part in parts {
        mac.update(part);
    }
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// HKDF-SHA256 (RFC 5869) with an empty salt.
///
/// # Errors
///
/// Returns [`SarCryptoError::InvalidLength`] when `len` exceeds 255 blocks.
pub fn hkdf_sha256_empty_salt(
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Result<SecretBytes, SarCryptoError> {
    if len > 255 * SHA256_LEN {
        return Err(SarCryptoError::InvalidLength(
            "HKDF output length too large",
        ));
    }
    // An empty salt is a string of HashLen zero bytes (RFC 5869 §2.2).
    let prk = hmac_sha256(&[0u8; SHA256_LEN], &[ikm])?;
    let mut okm = Zeroizing::new(Vec::with_capacity(len));
    let mut previous: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut counter = 1u8;
    while okm.len() < len {
        let block = hmac_sha256(prk.as_slice(), &[previous.as_slice(), info, &[counter]])?;
        let take = (len - okm.len()).min(SHA256_LEN);
        okm.extend_from_slice(&block[..take]);
        *previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    Ok(okm)
}

/// Derives the Entry encryption key for an encrypted Entry.
///
/// `iv_nonce_field` is the complete 24-byte LFH `IV/Nonce` field exactly as
/// encoded, including reserved bytes.  The KMS Master Secret is never returned
/// or used as the Entry key.
///
/// # Errors
///
/// * [`SarCryptoError::InvalidLength`] when the master secret is not 32 bytes.
/// * The registry status of `encr_algo_id` when it has no implemented native
///   key length.
pub fn derive_entry_key(
    master_secret: &SecretBytes,
    encr_algo_id: u8,
    iv_nonce_field: &[u8; 24],
) -> Result<SecretBytes, SarCryptoError> {
    if master_secret.len() != KMS_MASTER_SECRET_SIZE {
        return Err(SarCryptoError::InvalidLength(
            "KMS Master Secret must be 32 bytes",
        ));
    }
    let key_len = native_key_len(encr_algo_id)?;
    let mut info = Vec::with_capacity(ENTRY_KEY_INFO_LABEL.len() + 1 + iv_nonce_field.len());
    info.extend_from_slice(ENTRY_KEY_INFO_LABEL);
    info.push(encr_algo_id);
    info.extend_from_slice(iv_nonce_field);
    hkdf_sha256_empty_salt(master_secret.as_slice(), &info, key_len)
}
