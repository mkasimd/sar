// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::algorithm::{HASH_BLAKE3, HASH_SHA3_256, HASH_SHA256};
use crate::error::SarCryptoError;

/// AEAD tag size constant (also defined in `algorithm`).
pub const AEAD_TAG_SIZE: usize = 16;

/// Compute the SHA-256 hash of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the BLAKE3 hash of `data`.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Streaming hasher abstraction.
pub trait Hasher {
    /// Update the hasher with more bytes.
    fn update(&mut self, data: &[u8]);
    /// Finalize and return the digest bytes.
    fn finalize(self: Box<Self>) -> Vec<u8>;
    /// Return the hash algorithm identifier.
    fn algorithm_id(&self) -> u8;
}

struct Sha256Hasher {
    inner: Sha256,
}

impl Hasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.inner, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.inner.finalize().to_vec()
    }

    fn algorithm_id(&self) -> u8 {
        HASH_SHA256
    }
}

struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Hasher for Blake3Hasher {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.inner.finalize().as_bytes().to_vec()
    }

    fn algorithm_id(&self) -> u8 {
        HASH_BLAKE3
    }
}

/// Create a streaming hasher for `algo_id`.
pub fn new_hasher(algo_id: u8) -> Result<Box<dyn Hasher>, SarCryptoError> {
    match algo_id {
        HASH_SHA256 => Ok(Box::new(Sha256Hasher {
            inner: Sha256::new(),
        })),
        HASH_BLAKE3 => Ok(Box::new(Blake3Hasher {
            inner: blake3::Hasher::new(),
        })),
        HASH_SHA3_256 => Err(SarCryptoError::Unsupported("SHA3-256 not yet implemented")),
        0x00..=0x2F | 0x33..=0xFF => {
            Err(SarCryptoError::ReservedValue("unknown hash algorithm ID"))
        }
    }
}

/// Compute a one-shot hash with `algo_id`.
pub fn hash_data(algo_id: u8, data: &[u8]) -> Result<Vec<u8>, SarCryptoError> {
    let mut hasher = new_hasher(algo_id)?;
    hasher.update(data);
    Ok(hasher.finalize())
}

/// Compare two digest values in constant time.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
