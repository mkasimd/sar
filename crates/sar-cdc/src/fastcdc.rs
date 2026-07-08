//! Deterministic FASTCDC chunker (spec section 8.5, algorithm `0x02`).
//!
//! FASTCDC is a gear-hash based, high-speed Content-Defined Chunking algorithm.
//! This implementation follows the original FASTCDC paper (Xia et al., 2016)
//! and produces chunk boundaries deterministically for identical inputs.
//!
//! # Spec parameters
//!
//! The spec requires FASTCDC but does not normatively define the gear-hash
//! table, normalisation levels, or default chunk-size parameters.  This
//! implementation uses the commonly-cited defaults and a fixed gear-hash table;
//! see `docs/SPEC_QUESTIONS.md` for the documented ambiguity.
//!
//! Default parameters (used by [`FastCdcOptions::default`]):
//!
//! | Parameter | Default |
//! |-----------|---------|
//! | `min_size` | 2 048 B (2 KiB) |
//! | `avg_size` | 8 192 B (8 KiB) |
//! | `max_size` | 65 536 B (64 KiB) |
//!
//! # Normalisation
//!
//! A two-level mask approach is applied:
//! * Bytes `0..min_size`: accumulate hash, no cut point.
//! * Bytes `min_size..avg_size`: cut when `(hash & MASK_S) == 0` (small mask).
//! * Bytes `avg_size..max_size`: cut when `(hash & MASK_L) == 0` (large mask).
//! * At `max_size`: mandatory cut regardless of hash.
//!
//! # No zero-length chunks
//!
//! The implementation guarantees that no produced chunk has `length == 0`.
//! The final chunk may be shorter than `min_size` when the remaining data at
//! EOF is less than `min_size`; this is permitted by the algorithm.

use sha2::{Digest, Sha256};

use crate::{types::CdcChunk, validate::CdcError};

// ---------------------------------------------------------------------------
// Gear-hash table — 256 deterministic 64-bit constants.
//
// Generated with a fixed-seed xorshift64* to ensure deterministic
// cross-platform behaviour.
// ---------------------------------------------------------------------------

const GEAR: [u64; 256] = generate_gear();

const fn generate_gear() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state: u64 = 0x9e3779b97f4a7c15; // fixed seed: Fibonacci-hashing constant (2^64 / phi)
    let mut i = 0usize;
    while i < 256 {
        // xorshift64*
        state ^= state << 12;
        state ^= state >> 25;
        state ^= state << 27;
        table[i] = state.wrapping_mul(0x2545F4914F6CDD1D);
        i += 1;
    }
    table
}

// ---------------------------------------------------------------------------

/// Configuration for the FASTCDC chunker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCdcOptions {
    /// Minimum chunk size in bytes.  No cut point is considered before this
    /// offset within the current chunk.  Must be >= 64.
    pub min_size: u32,
    /// Average (target) chunk size in bytes.  Must be >= `min_size`.
    pub avg_size: u32,
    /// Maximum chunk size in bytes.  A hard cut is forced at this offset.
    /// Must be >= `avg_size`.
    pub max_size: u32,
}

impl Default for FastCdcOptions {
    fn default() -> Self {
        Self {
            min_size: 2_048,
            avg_size: 8_192,
            max_size: 65_536,
        }
    }
}

impl FastCdcOptions {
    /// Validates the chunk-size parameters.
    ///
    /// # Errors
    ///
    /// Returns [`CdcError::Bounds`] if any of the size constraints are
    /// violated.
    pub fn validate(&self) -> Result<(), CdcError> {
        if self.min_size < 64 {
            return Err(CdcError::Bounds("FastCDC min_size must be >= 64"));
        }
        if self.avg_size < self.min_size {
            return Err(CdcError::Bounds("FastCDC avg_size must be >= min_size"));
        }
        if self.max_size < self.avg_size {
            return Err(CdcError::Bounds("FastCDC max_size must be >= avg_size"));
        }
        Ok(())
    }
}

/// Computes a bitmask for the given target size.
///
/// Returns `(1 << bits) - 1` where `bits = floor(log2(size))`, clamped to
/// `[0, 63]`.
fn mask_for_size(size: u32) -> u64 {
    if size < 2 {
        return 0;
    }
    let bits = (u32::BITS - 1 - size.leading_zeros()) as u64;
    let bits = bits.min(63);
    (1u64 << bits).wrapping_sub(1)
}

/// Applies FASTCDC to `data` and returns a list of [`CdcChunk`]s with SHA-256
/// hashes computed for each chunk.
///
/// The returned chunks are contiguous, non-overlapping, and cover all of
/// `data`.  The final chunk may be shorter than `opts.min_size` when `data`
/// length is not a multiple of `min_size`.
///
/// `max_chunks` bounds the number of chunks produced; pass
/// `usize::MAX` to disable (use only in test/trusted contexts).
///
/// # Errors
///
/// * [`CdcError::Bounds`] — invalid size parameters.
/// * [`CdcError::LimitExceeded`] — chunk count exceeds `max_chunks`.
pub fn chunk_data(
    data: &[u8],
    opts: &FastCdcOptions,
    max_chunks: usize,
) -> Result<Vec<CdcChunk>, CdcError> {
    opts.validate()?;

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let min_size = opts.min_size as usize;
    let avg_size = opts.avg_size as usize;
    let max_size = opts.max_size as usize;

    let mask_s = mask_for_size(opts.avg_size / 2);
    let mask_l = mask_for_size(opts.avg_size);

    let mut chunks = Vec::new();
    let mut pos: usize = 0;

    while pos < data.len() {
        let remaining = data.len() - pos;
        let limit = remaining.min(max_size);
        let cut = fastcdc_cut(&data[pos..pos + limit], min_size, avg_size, mask_s, mask_l);

        let end = pos + cut;
        let chunk_bytes = &data[pos..end];
        let hash = compute_sha256(chunk_bytes);

        let new_len = chunks
            .len()
            .checked_add(1)
            .ok_or(CdcError::Overflow("chunk count overflow"))?;
        if new_len > max_chunks {
            return Err(CdcError::LimitExceeded(
                "CDC chunk count exceeds configured limit",
            ));
        }

        chunks.push(CdcChunk {
            offset: u64::try_from(pos).map_err(|_| CdcError::Overflow("chunk offset overflow"))?,
            length: u64::try_from(cut).map_err(|_| CdcError::Overflow("chunk length overflow"))?,
            hash: Some(hash),
        });

        pos = end;
    }

    Ok(chunks)
}

/// Finds the cut point within `data[0..data.len()]` using the two-level mask
/// approach.  Returns the chunk length (always >= 1 when `data` is non-empty).
fn fastcdc_cut(data: &[u8], min_size: usize, avg_size: usize, mask_s: u64, mask_l: u64) -> usize {
    let n = data.len();
    if n == 0 {
        return 0;
    }
    if n <= min_size {
        return n;
    }

    let mut hash: u64 = 0;

    // Pre-accumulate bytes [0..min_size] into the gear hash before we start
    // looking for cut points.  This ensures the hash state reflects all
    // preceding content, producing content-sensitive boundaries.
    for &byte in &data[..min_size] {
        hash = hash.wrapping_shl(1).wrapping_add(GEAR[byte as usize]);
    }

    // Phase 1: bytes [min_size, min(avg_size, n)) — MASK_S (more sensitive).
    let phase1_end = avg_size.min(n);
    for i in min_size..phase1_end {
        hash = hash.wrapping_shl(1).wrapping_add(GEAR[data[i] as usize]);
        if (hash & mask_s) == 0 {
            return i + 1;
        }
    }

    // Phase 2: bytes [avg_size, n) — MASK_L (less sensitive).
    for i in avg_size..n {
        hash = hash.wrapping_shl(1).wrapping_add(GEAR[data[i] as usize]);
        if (hash & mask_l) == 0 {
            return i + 1;
        }
    }

    // Mandatory cut at max_size (= n, already sliced by caller).
    n
}

/// Computes SHA-256 over `data` and returns the 32-byte digest.
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
