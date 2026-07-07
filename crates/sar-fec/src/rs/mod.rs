//! Reed-Solomon FEC codec (algorithm ID `0x11`).
//!
//! # Parameters
//!
//! * Field: GF(2^8), primitive polynomial `0x11D`, primitive element `α = 0x02`.
//! * Code: systematic; first `k` symbols unchanged, followed by `n-k` parity
//!   symbols.
//! * Generator (Vandermonde): coefficient for parity `r`, data `c` is
//!   `α^((r+1)×c)`.
//! * RS applied independently at **each byte offset** across `k` symbols.
//!
//! # On-wire layout
//!
//! ```text
//! Config[2]                    (Byte0 = k, Byte1 = n-k)
//! Symbol Size[4]               (u32 LE, bytes per symbol)
//! Original Protected Length[8] (u64 LE)
//! Group Count[4]               (u32 LE)
//! Parity Data[variable]        (Group Count × (n-k) × Symbol Size bytes)
//! ```
//!
//! Validation invariants:
//!
//! ```text
//! Group Count == ceil(Original Protected Length / (k × Symbol Size))
//! Parity Data Length == Group Count × (n-k) × Symbol Size
//! ```

mod gf;
mod matrix;

use crate::error::FecError;

use self::{
    gf::{gf_add, gf_mul, gf_pow},
    matrix::{GfMatrix, invert, mat_vec_mul},
};
use crate::types::{FecCodec, FecOptions, FecRecoverInput, FecValue, RsMeta};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum header size: Config[2] + SymbolSize[4] + OPL[8] + GroupCount[4] = 18 bytes.
const HEADER_SIZE: usize = 18;

/// Maximum parity data per FEC scope (256 MiB).
const MAX_PARITY_SIZE: usize = 256 * 1024 * 1024;

/// Maximum parity count (n-k) supported by this implementation.
const MAX_PARITY_COUNT: u8 = 32;

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

fn parse_header(data: &[u8]) -> Result<(u8, u8, u32, u64, u32), FecError> {
    if data.len() < HEADER_SIZE {
        return Err(FecError::Truncated("RS FEC value too short for header"));
    }
    let k = data[0];
    let parity_count = data[1]; // n - k

    if k == 0 {
        return Err(FecError::ReservedValue("RS k=0 is reserved"));
    }
    if parity_count == 0 {
        return Err(FecError::ReservedValue("RS parity_count=0 is reserved"));
    }

    let sym_bytes: [u8; 4] = data[2..6]
        .try_into()
        .map_err(|_| FecError::Truncated("RS SymbolSize"))?;
    let symbol_size = u32::from_le_bytes(sym_bytes);
    if symbol_size == 0 {
        return Err(FecError::Malformed("RS symbol size must be > 0"));
    }

    let opl_bytes: [u8; 8] = data[6..14]
        .try_into()
        .map_err(|_| FecError::Truncated("RS OPL"))?;
    let original_len = u64::from_le_bytes(opl_bytes);

    let gc_bytes: [u8; 4] = data[14..18]
        .try_into()
        .map_err(|_| FecError::Truncated("RS GroupCount"))?;
    let group_count = u32::from_le_bytes(gc_bytes);

    Ok((k, parity_count, symbol_size, original_len, group_count))
}

// ---------------------------------------------------------------------------
// Checked arithmetic
// ---------------------------------------------------------------------------

fn ceil_div_u64(a: u64, b: u64) -> Result<u64, FecError> {
    if b == 0 {
        return Err(FecError::Overflow("RS ceil_div by zero"));
    }
    a.checked_add(b - 1)
        .ok_or(FecError::Overflow("RS ceil_div overflow"))?
        .checked_div(b)
        .ok_or(FecError::Overflow("RS ceil_div"))
}

fn expected_group_count(original_len: u64, k: u8, symbol_size: u32) -> Result<u32, FecError> {
    let group_size = u64::from(k)
        .checked_mul(u64::from(symbol_size))
        .ok_or(FecError::Overflow("RS group size overflow"))?;
    let gc = ceil_div_u64(original_len, group_size)?;
    u32::try_from(gc).map_err(|_| FecError::Overflow("RS group count exceeds u32"))
}

fn parity_data_len(
    group_count: u32,
    parity_count: u8,
    symbol_size: u32,
) -> Result<usize, FecError> {
    let pl = u64::from(group_count)
        .checked_mul(u64::from(parity_count))
        .ok_or(FecError::Overflow("RS parity count × group overflow"))?
        .checked_mul(u64::from(symbol_size))
        .ok_or(FecError::Overflow("RS parity length overflow"))?;
    usize::try_from(pl).map_err(|_| FecError::Overflow("RS parity length exceeds usize"))
}

// ---------------------------------------------------------------------------
// Vandermonde generator matrix
// ---------------------------------------------------------------------------

/// Builds the Vandermonde parity-generation matrix G of dimensions
/// `parity_count × k`.
///
/// G[r][c] = α^((r+1)×c), where r is 0-based parity index and c is 0-based
/// data index.
#[allow(dead_code)]
fn build_vandermonde(k: usize, parity_count: usize) -> GfMatrix {
    let _ = (k, parity_count); // delegated to build_vandermonde_rect
    GfMatrix::zeroes(0)
}

/// Returns a flat row-major `parity_count × k` Vandermonde matrix.
fn build_vandermonde_rect(k: usize, parity_count: usize) -> Vec<u8> {
    let mut g = vec![0u8; parity_count * k];
    for r in 0..parity_count {
        for c in 0..k {
            let exp = ((r + 1) as u64).wrapping_mul(c as u64).wrapping_rem(255);
            g[r * k + c] = if exp == 0 { 1 } else { gf_pow(exp as u32) };
        }
    }
    g
}

/// Encodes parity symbols for one group.
///
/// `data_symbols`: `k` vectors each of `symbol_size` bytes.
/// Returns `parity_count` vectors each of `symbol_size` bytes.
fn encode_group(
    data_symbols: &[Vec<u8>],
    k: usize,
    parity_count: usize,
    symbol_size: usize,
    vandermonde: &[u8], // parity_count × k flat
) -> Vec<Vec<u8>> {
    let mut parity: Vec<Vec<u8>> = (0..parity_count).map(|_| vec![0u8; symbol_size]).collect();
    for (r, dst) in parity.iter_mut().enumerate() {
        for (c, src) in data_symbols.iter().enumerate() {
            let coeff = vandermonde[r * k + c];
            if coeff == 0 {
                continue;
            }
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d = gf_add(*d, gf_mul(coeff, s));
            }
        }
    }
    parity
}

// ---------------------------------------------------------------------------
// Symbol extraction
// ---------------------------------------------------------------------------

/// Extracts symbol `sym_in_group` of group `group` from the protected byte
/// slice, zero-padding at the end.
fn extract_symbol(
    data: &[u8],
    group: usize,
    sym_in_group: usize,
    k: usize,
    symbol_size: usize,
    buf: &mut [u8],
) {
    debug_assert_eq!(buf.len(), symbol_size);
    let start = (group * k + sym_in_group) * symbol_size;
    if start >= data.len() {
        buf.fill(0);
        return;
    }
    let end = (start + symbol_size).min(data.len());
    buf[..end - start].copy_from_slice(&data[start..end]);
    buf[end - start..].fill(0);
}

/// Extracts parity symbol `parity_idx` of group `group` from the parity
/// blob.
fn extract_parity_symbol(
    parity_blob: &[u8],
    group: usize,
    parity_idx: usize,
    parity_count: usize,
    symbol_size: usize,
    buf: &mut [u8],
) {
    debug_assert_eq!(buf.len(), symbol_size);
    let start = (group * parity_count + parity_idx) * symbol_size;
    let end = start + symbol_size;
    if end <= parity_blob.len() {
        buf.copy_from_slice(&parity_blob[start..end]);
    } else {
        buf.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Public metadata extractor
// ---------------------------------------------------------------------------

/// Parses RS FEC metadata from a raw value slice.
///
/// # Errors
///
/// Returns [`SarError`] on structural violations.
pub fn parse_rs_meta(data: &[u8]) -> Result<RsMeta, FecError> {
    let (k, parity_count, symbol_size, original_len, group_count) = parse_header(data)?;
    let pl = parity_data_len(group_count, parity_count, symbol_size)?;
    Ok(RsMeta {
        k,
        parity_count,
        symbol_size,
        original_protected_len: original_len,
        group_count,
        parity_data_len: pl,
    })
}

// ---------------------------------------------------------------------------
// RS codec
// ---------------------------------------------------------------------------

/// Reed-Solomon FEC codec.
///
/// Configuration is provided at construction; `k` data symbols, `parity_count`
/// parity symbols, and `symbol_size` bytes per symbol.
#[derive(Debug, Clone, Copy)]
pub struct RsCodec {
    k: u8,
    parity_count: u8,
    symbol_size: u32,
}

impl RsCodec {
    /// Constructs a new [`RsCodec`].
    ///
    /// # Errors
    ///
    /// Returns [`FecError::ReservedValue`] for `k=0` or `parity_count=0`.
    /// Returns [`FecError::LimitExceeded`] when `parity_count > 32`.
    pub fn new(k: u8, parity_count: u8, symbol_size: u32) -> Result<Self, FecError> {
        if k == 0 {
            return Err(FecError::ReservedValue("RS k=0 is reserved"));
        }
        if parity_count == 0 {
            return Err(FecError::ReservedValue("RS parity_count=0 is reserved"));
        }
        if parity_count > MAX_PARITY_COUNT {
            return Err(FecError::LimitExceeded(
                "RS parity count exceeds implementation limit of 32",
            ));
        }
        if symbol_size == 0 {
            return Err(FecError::Malformed("RS symbol size must be > 0"));
        }
        Ok(Self {
            k,
            parity_count,
            symbol_size,
        })
    }

    /// Constructs an [`RsCodec`] by peeking at the first 6 bytes of a raw
    /// FEC value slice (Config[2] + SymbolSize[4]).
    ///
    /// # Errors
    ///
    /// Returns [`FecError::Truncated`] if `data` has fewer than 6 bytes, or
    /// the same errors as [`RsCodec::new`].
    pub fn from_fec_value(data: &[u8]) -> Result<Self, FecError> {
        if data.len() < 6 {
            return Err(FecError::Truncated("RS FEC value too short for config"));
        }
        let k = data[0];
        let parity_count = data[1];
        let sym: [u8; 4] = data[2..6]
            .try_into()
            .map_err(|_| FecError::Truncated("RS sym"))?;
        let symbol_size = u32::from_le_bytes(sym);
        Self::new(k, parity_count, symbol_size)
    }
}

impl FecCodec for RsCodec {
    fn algorithm_id(&self) -> u8 {
        crate::registry::FEC_ALGO_REED_SOLOMON
    }

    fn encode_recovery(
        &self,
        protected: &[u8],
        _options: FecOptions,
    ) -> Result<FecValue, FecError> {
        let k = self.k as usize;
        let pc = self.parity_count as usize;
        let ss = self.symbol_size as usize;

        let original_len = u64::try_from(protected.len())
            .map_err(|_| FecError::Overflow("RS protected length exceeds u64"))?;
        let group_count = expected_group_count(original_len, self.k, self.symbol_size)?;
        let gc = group_count as usize;

        let pl = parity_data_len(group_count, self.parity_count, self.symbol_size)?;
        if pl > MAX_PARITY_SIZE {
            return Err(FecError::LimitExceeded(
                "RS parity exceeds implementation limit",
            ));
        }

        let vandermonde = build_vandermonde_rect(k, pc);
        let mut parity_blob = vec![0u8; gc * pc * ss];
        let mut sym_buf = vec![0u8; ss];

        for g in 0..gc {
            let mut data_symbols: Vec<Vec<u8>> = Vec::with_capacity(k);
            for c in 0..k {
                extract_symbol(protected, g, c, k, ss, &mut sym_buf);
                data_symbols.push(sym_buf.clone());
            }
            let parity_syms = encode_group(&data_symbols, k, pc, ss, &vandermonde);
            for (r, parity_sym) in parity_syms.iter().enumerate() {
                let out_start = (g * pc + r) * ss;
                parity_blob[out_start..out_start + ss].copy_from_slice(parity_sym);
            }
        }

        // Encode: Config[2] || SymbolSize[4] || OPL[8] || GroupCount[4] || Parity
        let mut data = Vec::with_capacity(HEADER_SIZE + pl);
        data.push(self.k);
        data.push(self.parity_count);
        data.extend_from_slice(&self.symbol_size.to_le_bytes());
        data.extend_from_slice(&original_len.to_le_bytes());
        data.extend_from_slice(&group_count.to_le_bytes());
        data.extend_from_slice(&parity_blob);

        Ok(FecValue {
            algo_id: self.algorithm_id(),
            data,
        })
    }

    fn recover(&self, input: FecRecoverInput<'_>) -> Result<Vec<u8>, FecError> {
        let (k_cfg, pc_cfg, sym_size, original_len, group_count) =
            parse_header(input.fec_value_data)?;
        let _ = (k_cfg, pc_cfg, sym_size); // used via self.* fields for consistency

        self.validate(input.fec_value_data)?;

        if original_len != input.original_protected_len {
            return Err(FecError::InvalidLength(
                "RS recovery: original_protected_len mismatch",
            ));
        }

        let k = self.k as usize;
        let pc = self.parity_count as usize;
        let ss = self.symbol_size as usize;
        let gc = group_count as usize;
        let _n = k + pc;

        let pl = parity_data_len(group_count, self.parity_count, self.symbol_size)?;
        let parity_blob = &input.fec_value_data[HEADER_SIZE..HEADER_SIZE + pl];

        let vandermonde = build_vandermonde_rect(k, pc);

        // Build output: initially a copy of available_data, then fill in
        // recovered symbols.
        let total_data_len = gc * k * ss;
        let mut out = vec![0u8; total_data_len];
        let copy_len = out.len().min(input.available_data.len());
        out[..copy_len].copy_from_slice(&input.available_data[..copy_len]);

        let mut sym_buf = vec![0u8; ss];

        for g in 0..gc {
            // Determine which data-symbol indices (0..k) are erased in this
            // group.
            let group_sym_start = (g * k) as u64;
            let group_sym_end = ((g + 1) * k) as u64;

            let erased_data: Vec<usize> = input
                .erasures
                .iter()
                .filter_map(|e| {
                    if e.index >= group_sym_start && e.index < group_sym_end {
                        Some((e.index - group_sym_start) as usize)
                    } else {
                        None
                    }
                })
                .collect();

            if erased_data.is_empty() {
                continue; // nothing to recover
            }

            let t = erased_data.len();
            if t > pc {
                return Err(FecError::EcFailed(
                    "RS: erased data symbols exceed parity count for this group",
                ));
            }

            // Select `t` available parity rows to use for recovery.  Any t
            // rows from the Vandermonde matrix suffice (assuming non-singularity).
            // Prefer lower-index parity symbols (most likely to be available).
            //
            // Build the t×t sub-system:
            //   Vandermonde_rows × data_erased = parity_available - Vandermonde_known × data_known
            //
            // Collect known data symbols and t available parity symbols.

            // Parity rows 0..t
            let selected_parity: Vec<usize> = (0..pc).take(t).collect();

            // Build augmented system: solve for `erased_data` symbols.
            // For each selected parity equation `r`:
            //   Σ_c G[r][c] * data[c]  = parity[r]
            //   Σ_{c ∈ erased} G[r][c] * data[c]  = parity[r] - Σ_{c ∉ erased} G[r][c] * data[c]
            // Denote RHS[r] = parity[r] XOR Σ_{known c} G[r][c] * data[c]

            // Build the erased-columns sub-matrix A (t × t) and RHS vecs.
            let mut a = GfMatrix::zeroes(t);
            let mut rhs: Vec<Vec<u8>> = (0..t).map(|_| vec![0u8; ss]).collect();

            for (ri, &pr) in selected_parity.iter().enumerate() {
                // Get parity symbol `pr` for group `g`.
                extract_parity_symbol(parity_blob, g, pr, pc, ss, &mut sym_buf);
                // rhs[ri] = parity[pr] initially.
                rhs[ri].copy_from_slice(&sym_buf);

                // Sub-matrix columns: erased data indices.
                for (ci, &ec) in erased_data.iter().enumerate() {
                    let coeff = vandermonde[pr * k + ec];
                    a.set(ri, ci, coeff);
                }

                // Subtract known data contributions from RHS.
                for c in 0..k {
                    if erased_data.contains(&c) {
                        continue;
                    }
                    let coeff = vandermonde[pr * k + c];
                    if coeff == 0 {
                        continue;
                    }
                    extract_symbol(input.available_data, g, c, k, ss, &mut sym_buf);
                    for (r_byte, &s_byte) in rhs[ri].iter_mut().zip(sym_buf.iter()) {
                        *r_byte ^= gf_mul(coeff, s_byte);
                    }
                }
            }

            // Solve A * erased_syms = rhs via inversion.
            let a_inv = invert(&a)?;
            let recovered = mat_vec_mul(&a_inv, &rhs, ss);

            // Write recovered symbols into output buffer.
            for (ci, &ec) in erased_data.iter().enumerate() {
                let out_start = (g * k + ec) * ss;
                let out_end = out_start + ss;
                if out_end <= out.len() {
                    out[out_start..out_end].copy_from_slice(&recovered[ci]);
                }
            }
        }

        // Truncate to original length.
        let orig_len = usize::try_from(original_len)
            .map_err(|_| FecError::Overflow("RS original_len exceeds usize"))?;
        out.truncate(orig_len);
        Ok(out)
    }

    fn validate(&self, fec_value_data: &[u8]) -> Result<(), FecError> {
        let (k, parity_count, symbol_size, original_len, group_count) =
            parse_header(fec_value_data)?;

        // Config must match this codec.
        if k != self.k || parity_count != self.parity_count || symbol_size != self.symbol_size {
            return Err(FecError::InvalidLength("RS config mismatch in validate"));
        }

        // Parity count limit.
        if parity_count > MAX_PARITY_COUNT {
            return Err(FecError::LimitExceeded(
                "RS parity count exceeds implementation limit of 32",
            ));
        }

        // Validate group count.
        let expected_gc = expected_group_count(original_len, k, symbol_size)?;
        if group_count != expected_gc {
            return Err(FecError::InvalidLength(
                "RS group count does not match expected value",
            ));
        }

        // Validate parity data length.
        let pl = parity_data_len(group_count, parity_count, symbol_size)?;
        if pl > MAX_PARITY_SIZE {
            return Err(FecError::LimitExceeded(
                "RS parity exceeds implementation limit",
            ));
        }
        let available = fec_value_data.len().saturating_sub(HEADER_SIZE);
        if available != pl {
            return Err(FecError::InvalidLength(
                "RS parity data length does not match Group Count × (n-k) × Symbol Size",
            ));
        }

        Ok(())
    }
}

/// Validates a raw RS FEC value slice without constructing a codec.
///
/// # Errors
///
/// Returns [`SarError`] on any structural violation.
pub fn validate_rs_fec_value(data: &[u8]) -> Result<(), FecError> {
    let codec = RsCodec::from_fec_value(data)?;
    codec.validate(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Erasure;

    fn make_codec(k: u8, pc: u8, ss: u32) -> RsCodec {
        RsCodec::new(k, pc, ss).expect("test")
    }

    #[test]
    fn rs_reserved_k_zero() {
        assert!(matches!(
            RsCodec::new(0, 4, 1024),
            Err(FecError::ReservedValue(_))
        ));
    }

    #[test]
    fn rs_reserved_parity_zero() {
        assert!(matches!(
            RsCodec::new(4, 0, 1024),
            Err(FecError::ReservedValue(_))
        ));
    }

    #[test]
    fn rs_limit_exceeded_parity_33() {
        assert!(matches!(
            RsCodec::new(4, 33, 1024),
            Err(FecError::LimitExceeded(_))
        ));
    }

    #[test]
    fn rs_roundtrip_no_erasures() {
        // k=3, n-k=2, symbol_size=16 → small test
        let data: Vec<u8> = (0u8..=255).cycle().take(48).collect(); // 3 × 16
        let codec = make_codec(3, 2, 16);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        let input = FecRecoverInput {
            original_protected_len: 48,
            available_data: &data,
            fec_value_data: &fec.data,
            erasures: &[],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn rs_recover_one_erased_data_symbol() {
        // k=3, n-k=2, symbol_size=16; erase first symbol
        let data: Vec<u8> = (1u8..=255).cycle().take(48).collect();
        let codec = make_codec(3, 2, 16);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        let mut corrupted = data.clone();
        corrupted[0..16].fill(0);

        let input = FecRecoverInput {
            original_protected_len: 48,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 0 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn rs_recover_two_erased_data_symbols() {
        // k=4, n-k=3, symbol_size=16; erase symbols 0 and 2
        let data: Vec<u8> = (1u8..=255).cycle().take(64).collect();
        let codec = make_codec(4, 3, 16);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        let mut corrupted = data.clone();
        corrupted[0..16].fill(0xAB);
        corrupted[32..48].fill(0xCD);

        let input = FecRecoverInput {
            original_protected_len: 64,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 0 }, Erasure { index: 2 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn rs_too_many_erasures_fails() {
        // k=3, n-k=2; erase 3 symbols (>parity count)
        let data = vec![1u8; 48];
        let codec = make_codec(3, 2, 16);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        let input = FecRecoverInput {
            original_protected_len: 48,
            available_data: &data,
            fec_value_data: &fec.data,
            erasures: &[
                Erasure { index: 0 },
                Erasure { index: 1 },
                Erasure { index: 2 },
            ],
        };
        assert!(matches!(codec.recover(input), Err(FecError::EcFailed(_))));
    }

    #[test]
    fn rs_partial_last_group() {
        // 50 bytes, k=3, symbol_size=16: last group has 50-48=2 bytes → padded
        let data: Vec<u8> = (1u8..=255).cycle().take(50).collect();
        let codec = make_codec(3, 2, 16);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        // Erase first symbol of second group (index 3)
        let mut corrupted = data.clone();
        if corrupted.len() > 48 {
            corrupted[48] = 0xFF;
        }

        let input = FecRecoverInput {
            original_protected_len: 50,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 3 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn rs_validate_correct() {
        let data: Vec<u8> = vec![42u8; 1024];
        let codec = make_codec(4, 2, 256);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");
        assert!(codec.validate(&fec.data).is_ok());
    }

    #[test]
    fn rs_validate_bad_group_count() {
        let data: Vec<u8> = vec![42u8; 1024];
        let codec = make_codec(4, 2, 256);
        let mut fec = codec.encode_recovery(&data, FecOptions).expect("test");
        // Corrupt group count field (bytes 14..18)
        fec.data[14] = 0xFF;
        assert!(matches!(
            codec.validate(&fec.data),
            Err(FecError::InvalidLength(_))
        ));
    }

    #[test]
    fn rs_symbol_sizes_1024_4096_16384() {
        for ss in [1024u32, 4096, 16384] {
            let codec = make_codec(4, 2, ss);
            let data: Vec<u8> = (1u8..=255).cycle().take((4 * ss) as usize).collect();
            let fec = codec.encode_recovery(&data, FecOptions).expect("test");
            assert!(codec.validate(&fec.data).is_ok(), "symbol_size={ss} failed");
        }
    }

    #[test]
    fn vandermonde_gf_pow_example() {
        // α^((0+1)×0) = α^0 = 1
        // α^((0+1)×1) = α^1 = 2
        // α^((1+1)×0) = α^0 = 1
        // α^((1+1)×1) = α^2 = 4
        let g = build_vandermonde_rect(2, 2);
        assert_eq!(g[0], 1); // G[0][0] = α^(1×0) = 1
        assert_eq!(g[1], 2); // G[0][1] = α^(1×1) = 2
        assert_eq!(g[2], 1); // G[1][0] = α^(2×0) = 1
        assert_eq!(g[3], 4); // G[1][1] = α^(2×1) = 4
    }
}
