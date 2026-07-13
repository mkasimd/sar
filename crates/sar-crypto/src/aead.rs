// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag as AesTag};
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::algorithm::{AEAD_KEY_SIZE, AEAD_TAG_SIZE, ENCR_AES256_GCM, ENCR_XCHACHA20_POLY};
use crate::error::SarCryptoError;
use crate::secret::SecretBytes;

/// AEAD tag size.
pub const TAG_SIZE: usize = AEAD_TAG_SIZE;

/// Encrypt `plaintext` and return `ciphertext || tag`.
pub fn aead_encrypt(
    algo_id: u8,
    key: &SecretBytes,
    iv_nonce_field: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SarCryptoError> {
    if key.len() != AEAD_KEY_SIZE {
        return Err(SarCryptoError::InvalidLength("key must be 32 bytes"));
    }
    validate_nonce_field(algo_id, iv_nonce_field, true)?;

    match algo_id {
        ENCR_AES256_GCM => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| SarCryptoError::InvalidLength("AES key init failed"))?;
            let nonce = Nonce::from_slice(&iv_nonce_field[..12]);
            let mut buf = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(nonce, aad, &mut buf)
                .map_err(|_| SarCryptoError::Internal("AES-GCM encryption failed"))?;
            buf.extend_from_slice(tag.as_slice());
            Ok(buf)
        }
        ENCR_XCHACHA20_POLY => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| SarCryptoError::InvalidLength("XChaCha20 key init failed"))?;
            let nonce = XNonce::from_slice(iv_nonce_field);
            let mut buf = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(nonce, aad, &mut buf)
                .map_err(|_| SarCryptoError::Internal("XChaCha20-Poly1305 encryption failed"))?;
            buf.extend_from_slice(tag.as_slice());
            Ok(buf)
        }
        _ => Err(SarCryptoError::Unsupported("unsupported AEAD algorithm")),
    }
}

/// Decrypt and authenticate `ciphertext_with_tag`, returning plaintext on success.
pub fn aead_decrypt(
    algo_id: u8,
    key: &SecretBytes,
    iv_nonce_field: &[u8; 24],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, SarCryptoError> {
    if key.len() != AEAD_KEY_SIZE {
        return Err(SarCryptoError::InvalidLength("key must be 32 bytes"));
    }
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(SarCryptoError::InvalidLength(
            "ciphertext too short (< 16 bytes)",
        ));
    }

    let ct_len = ciphertext_with_tag.len() - TAG_SIZE;
    let (ciphertext, tag_bytes) = ciphertext_with_tag.split_at(ct_len);
    validate_nonce_field(algo_id, iv_nonce_field, true)?;

    match algo_id {
        ENCR_AES256_GCM => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| SarCryptoError::InvalidLength("AES key init failed"))?;
            let nonce = Nonce::from_slice(&iv_nonce_field[..12]);
            let tag = AesTag::from_slice(tag_bytes);
            let mut buf = ciphertext.to_vec();
            match cipher.decrypt_in_place_detached(nonce, aad, &mut buf, tag) {
                Ok(()) => Ok(buf),
                Err(_) => {
                    buf.zeroize();
                    Err(SarCryptoError::AuthFailed(
                        "AES-GCM authentication tag mismatch",
                    ))
                }
            }
        }
        ENCR_XCHACHA20_POLY => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| SarCryptoError::InvalidLength("XChaCha20 key init failed"))?;
            let nonce = XNonce::from_slice(iv_nonce_field);
            let tag = XTag::from_slice(tag_bytes);
            let mut buf = ciphertext.to_vec();
            match cipher.decrypt_in_place_detached(nonce, aad, &mut buf, tag) {
                Ok(()) => Ok(buf),
                Err(_) => {
                    buf.zeroize();
                    Err(SarCryptoError::AuthFailed(
                        "XChaCha20-Poly1305 authentication tag mismatch",
                    ))
                }
            }
        }
        _ => Err(SarCryptoError::Unsupported("unsupported AEAD algorithm")),
    }
}

/// Fill `field` with a fresh nonce for `algo_id`.
pub fn generate_nonce(algo_id: u8, field: &mut [u8; 24]) -> Result<(), SarCryptoError> {
    let mut rng = rand_core::OsRng;
    match algo_id {
        ENCR_AES256_GCM => {
            rng.fill_bytes(&mut field[..12]);
            field[12..].fill(0);
            Ok(())
        }
        ENCR_XCHACHA20_POLY => {
            rng.fill_bytes(field);
            Ok(())
        }
        _ => Err(SarCryptoError::Unsupported(
            "unsupported AEAD algorithm for nonce generation",
        )),
    }
}

/// Validate an on-wire 24-byte nonce field for `algo_id`.
pub fn validate_nonce_field(
    algo_id: u8,
    field: &[u8; 24],
    strict: bool,
) -> Result<(), SarCryptoError> {
    match algo_id {
        ENCR_AES256_GCM => {
            if strict && field[12..].iter().any(|byte| *byte != 0) {
                return Err(SarCryptoError::Malformed(
                    "AES-GCM nonce field: bytes [12..24] must be zero",
                ));
            }
            Ok(())
        }
        ENCR_XCHACHA20_POLY => Ok(()),
        _ => Err(SarCryptoError::Unsupported(
            "unsupported AEAD algorithm for nonce validation",
        )),
    }
}
