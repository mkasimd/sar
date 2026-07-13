// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! XOR FEC codec (algorithm ID `0x14`).
//!
//! # On-wire layout
//!
//! ```text
//! Config[2]                    (Byte0 = stripe_size, Byte1 = block_size_index)
//! Original Protected Length[8] (u64 LE)
//! Stripe Count[4]              (u32 LE)
//! Parity Data[variable]        (Stripe Count × Block Size bytes)
//! ```
//!
//! Validation invariants:
//!
//! ```text
//! Stripe Count == ceil(Original Protected Length / (Stripe Size × Block Size))
//! Parity Data Length == Stripe Count × Block Size
//! ```

use crate::error::FecError;

use crate::types::{FecCodec, FecOptions, FecRecoverInput, FecValue, XorMeta};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum parity data size allowed per FEC scope (256 MiB).
const MAX_PARITY_SIZE: usize = 256 * 1024 * 1024;

/// Supported block-size indices and their byte sizes.
const BLOCK_SIZE_TABLE: [(u8, u32); 9] = [
    (0x00, 256),
    (0x01, 512),
    (0x02, 1_024),
    (0x03, 2_048),
    (0x04, 4_096),
    (0x05, 8_192),
    (0x06, 16_384),
    (0x07, 32_768),
    (0x08, 65_536),
];

/// Minimum header size: Config[2] + OPL[8] + StripeCount[4] = 14 bytes.
const HEADER_SIZE: usize = 14;

// ---------------------------------------------------------------------------
// Helper: block size from index
// ---------------------------------------------------------------------------

fn block_size_for_index(index: u8) -> Result<u32, FecError> {
    for (idx, size) in BLOCK_SIZE_TABLE {
        if idx == index {
            return Ok(size);
        }
    }
    Err(FecError::ReservedValue("XOR block size index is reserved"))
}

// ---------------------------------------------------------------------------
// Helper: parse header (without parity)
// ---------------------------------------------------------------------------

fn parse_header(data: &[u8]) -> Result<(u8, u32, u64, u32), FecError> {
    if data.len() < HEADER_SIZE {
        return Err(FecError::Truncated("XOR FEC value too short for header"));
    }
    let stripe_size = data[0];
    let block_size_index = data[1];

    if stripe_size == 0x00 {
        return Err(FecError::ReservedValue("XOR stripe size 0x00 is reserved"));
    }
    let block_size = block_size_for_index(block_size_index)?;

    let opl_bytes: [u8; 8] = data[2..10]
        .try_into()
        .map_err(|_| FecError::Truncated("XOR OPL"))?;
    let original_len = u64::from_le_bytes(opl_bytes);

    let sc_bytes: [u8; 4] = data[10..14]
        .try_into()
        .map_err(|_| FecError::Truncated("XOR StripeCount"))?;
    let stripe_count = u32::from_le_bytes(sc_bytes);

    Ok((stripe_size, block_size, original_len, stripe_count))
}

// ---------------------------------------------------------------------------
// Public metadata extractor
// ---------------------------------------------------------------------------

/// Parses XOR FEC metadata from a raw value slice without allocating parity.
///
/// # Errors
///
/// Returns [`SarError`] when the header is truncated, reserved, or the
/// declared counts do not match.
pub fn parse_xor_meta(data: &[u8]) -> Result<XorMeta, FecError> {
    let (stripe_size, block_size, original_len, stripe_count) = parse_header(data)?;
    let parity_data_len = parity_len(stripe_count, block_size)?;
    Ok(XorMeta {
        stripe_size,
        block_size,
        original_protected_len: original_len,
        stripe_count,
        parity_data_len,
    })
}

// ---------------------------------------------------------------------------
// Checked arithmetic helpers
// ---------------------------------------------------------------------------

/// ceil(a / b) with overflow checking.
fn ceil_div(a: u64, b: u64) -> Result<u64, FecError> {
    if b == 0 {
        return Err(FecError::Overflow("XOR ceil_div by zero"));
    }
    a.checked_add(b - 1)
        .ok_or(FecError::Overflow("XOR ceil_div overflow"))?
        .checked_div(b)
        .ok_or(FecError::Overflow("XOR ceil_div"))
}

fn expected_stripe_count(
    original_len: u64,
    stripe_size: u8,
    block_size: u32,
) -> Result<u32, FecError> {
    let effective = u64::from(stripe_size)
        .checked_mul(u64::from(block_size))
        .ok_or(FecError::Overflow("XOR effective stripe size overflow"))?;
    let sc = ceil_div(original_len, effective)?;
    u32::try_from(sc).map_err(|_| FecError::Overflow("XOR stripe count exceeds u32"))
}

fn parity_len(stripe_count: u32, block_size: u32) -> Result<usize, FecError> {
    let pl = u64::from(stripe_count)
        .checked_mul(u64::from(block_size))
        .ok_or(FecError::Overflow("XOR parity length overflow"))?;
    usize::try_from(pl).map_err(|_| FecError::Overflow("XOR parity length exceeds usize"))
}

fn u64_to_usize(value: u64, context: &'static str) -> Result<usize, FecError> {
    usize::try_from(value).map_err(|_| FecError::Overflow(context))
}

// ---------------------------------------------------------------------------
// XOR codec
// ---------------------------------------------------------------------------

/// XOR FEC codec.
///
/// Configuration must be provided at construction time; `stripe_size` must be
/// `1..=255` and `block_size_index` must be `0x00..=0x08`.
#[derive(Debug, Clone, Copy)]
pub struct XorCodec {
    stripe_size: u8,
    block_size: u32,
    block_size_index: u8,
}

impl XorCodec {
    /// Constructs a new [`XorCodec`] from config bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FecError::ReservedValue`] for `stripe_size == 0x00` or a
    /// reserved `block_size_index`.
    /// Returns [`FecError::LimitExceeded`] for valid but unsupported indices.
    pub fn new(stripe_size: u8, block_size_index: u8) -> Result<Self, FecError> {
        if stripe_size == 0x00 {
            return Err(FecError::ReservedValue("XOR stripe size 0x00 is reserved"));
        }
        let block_size = block_size_for_index(block_size_index)?;
        Ok(Self {
            stripe_size,
            block_size,
            block_size_index,
        })
    }

    /// Constructs an [`XorCodec`] by peeking at the first two config bytes of
    /// a raw FEC value slice.
    ///
    /// # Errors
    ///
    /// Returns [`FecError::Truncated`] if `data` has fewer than 2 bytes, or
    /// the same errors as [`XorCodec::new`].
    pub fn from_fec_value(data: &[u8]) -> Result<Self, FecError> {
        if data.len() < 2 {
            return Err(FecError::Truncated("XOR FEC value too short for config"));
        }
        Self::new(data[0], data[1])
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Returns the bytes of block `block_idx` from `data`, zero-padding to
    /// `block_size`.  Returns all-zero if `block_idx` is beyond the data.
    fn block_bytes(&self, data: &[u8], block_idx: usize, buf: &mut [u8]) -> Result<(), FecError> {
        let bs = usize::try_from(self.block_size)
            .map_err(|_| FecError::Overflow("XOR block size exceeds usize"))?;
        debug_assert_eq!(buf.len(), bs);
        let start = block_idx
            .checked_mul(bs)
            .ok_or(FecError::Overflow("XOR block start overflow"))?;
        if start >= data.len() {
            buf.fill(0);
            return Ok(());
        }
        let end = (start + bs).min(data.len());
        buf[..end - start].copy_from_slice(&data[start..end]);
        buf[end - start..].fill(0);
        Ok(())
    }

    /// XORs `src` into `dst` in place.
    fn xor_into(dst: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
    }
}

impl FecCodec for XorCodec {
    fn algorithm_id(&self) -> u8 {
        crate::registry::FEC_ALGO_XOR
    }

    fn encode_recovery(
        &self,
        protected: &[u8],
        _options: FecOptions,
    ) -> Result<FecValue, FecError> {
        let original_len = u64::try_from(protected.len())
            .map_err(|_| FecError::Overflow("XOR protected length exceeds u64"))?;
        let stripe_count = expected_stripe_count(original_len, self.stripe_size, self.block_size)?;
        let pl = parity_len(stripe_count, self.block_size)?;
        if pl > MAX_PARITY_SIZE {
            return Err(FecError::LimitExceeded(
                "XOR parity exceeds implementation limit",
            ));
        }

        let ss = usize::from(self.stripe_size);
        let bs = usize::try_from(self.block_size)
            .map_err(|_| FecError::Overflow("XOR block size exceeds usize"))?;
        let sc = usize::try_from(stripe_count)
            .map_err(|_| FecError::Overflow("XOR stripe count exceeds usize"))?;

        let parity_len = sc
            .checked_mul(bs)
            .ok_or(FecError::Overflow("XOR parity allocation overflow"))?;
        let mut parity = vec![0u8; parity_len];
        let mut block_buf = vec![0u8; bs];

        for stripe in 0..sc {
            let p_slice = &mut parity[stripe * bs..(stripe + 1) * bs];
            for i in 0..ss {
                let block_idx = stripe * ss + i;
                self.block_bytes(protected, block_idx, &mut block_buf)?;
                Self::xor_into(p_slice, &block_buf);
            }
        }

        // Encode: Config[2] || OPL[8] || StripeCount[4] || Parity
        let mut data = Vec::with_capacity(HEADER_SIZE + pl);
        data.push(self.stripe_size);
        data.push(self.block_size_index);
        data.extend_from_slice(&original_len.to_le_bytes());
        data.extend_from_slice(&stripe_count.to_le_bytes());
        data.extend_from_slice(&parity);

        Ok(FecValue {
            algo_id: self.algorithm_id(),
            data,
        })
    }

    fn recover(&self, input: FecRecoverInput<'_>) -> Result<Vec<u8>, FecError> {
        let (stripe_size, block_size, original_len, stripe_count) =
            parse_header(input.fec_value_data)?;
        let _ = stripe_size; // already embedded in self

        // Validate declared lengths
        self.validate(input.fec_value_data)?;

        if original_len != input.original_protected_len {
            return Err(FecError::InvalidLength(
                "XOR recovery: original_protected_len mismatch",
            ));
        }

        let sc = usize::try_from(stripe_count)
            .map_err(|_| FecError::Overflow("XOR stripe count exceeds usize"))?;
        let ss = usize::from(self.stripe_size);
        let bs = usize::try_from(block_size)
            .map_err(|_| FecError::Overflow("XOR block size exceeds usize"))?;

        let pl = parity_len(stripe_count, block_size)?;
        let parity = &input.fec_value_data[HEADER_SIZE..HEADER_SIZE + pl];

        // Build a mutable output buffer initialised from available_data.
        let total_data_len = sc
            .checked_mul(ss)
            .and_then(|value| value.checked_mul(bs))
            .ok_or(FecError::Overflow("XOR output length overflow"))?;
        let mut out = vec![0u8; total_data_len];
        let copy_len = out.len().min(input.available_data.len());
        out[..copy_len].copy_from_slice(&input.available_data[..copy_len]);

        let mut block_buf = vec![0u8; bs];

        for stripe in 0..sc {
            // Collect erasures in this stripe.
            let stripe_start = u64::try_from(
                stripe
                    .checked_mul(ss)
                    .ok_or(FecError::Overflow("XOR stripe start overflow"))?,
            )
            .map_err(|_| FecError::Overflow("XOR stripe start exceeds u64"))?;
            let stripe_end = u64::try_from(
                (stripe + 1)
                    .checked_mul(ss)
                    .ok_or(FecError::Overflow("XOR stripe end overflow"))?,
            )
            .map_err(|_| FecError::Overflow("XOR stripe end exceeds u64"))?;
            let stripe_erasures: Vec<usize> = input
                .erasures
                .iter()
                .filter_map(|e| {
                    if e.index >= stripe_start && e.index < stripe_end {
                        u64_to_usize(e.index - stripe_start, "XOR erasure index exceeds usize").ok()
                    } else {
                        None
                    }
                })
                .collect();

            if stripe_erasures.len() > 1 {
                return Err(FecError::EcFailed(
                    "XOR: more than one erasure per stripe cannot be recovered",
                ));
            }

            if stripe_erasures.is_empty() {
                continue; // nothing to recover in this stripe
            }

            let erased_in_stripe = stripe_erasures[0];
            let erased_block_idx = stripe * ss + erased_in_stripe;

            // recovered = parity XOR (XOR of all other blocks in stripe)
            let p_slice = &parity[stripe * bs..(stripe + 1) * bs];
            let mut recovered = p_slice.to_vec();

            for i in 0..ss {
                if i == erased_in_stripe {
                    continue;
                }
                let block_idx = stripe * ss + i;
                self.block_bytes(input.available_data, block_idx, &mut block_buf)?;
                Self::xor_into(&mut recovered, &block_buf);
            }

            // Write recovered block into output
            let out_start = erased_block_idx * bs;
            let out_end = out_start + bs;
            if out_end <= out.len() {
                out[out_start..out_end].copy_from_slice(&recovered);
            }
        }

        // Truncate to original length
        let orig_len = usize::try_from(original_len)
            .map_err(|_| FecError::Overflow("XOR original_len exceeds usize"))?;
        out.truncate(orig_len);
        Ok(out)
    }

    fn validate(&self, fec_value_data: &[u8]) -> Result<(), FecError> {
        let (stripe_size, block_size, original_len, stripe_count) = parse_header(fec_value_data)?;

        // Validate config matches this codec instance
        if stripe_size != self.stripe_size || block_size != self.block_size {
            return Err(FecError::InvalidLength("XOR config mismatch in validate"));
        }

        // Validate stripe count
        let expected_sc = expected_stripe_count(original_len, stripe_size, block_size)?;
        if stripe_count != expected_sc {
            return Err(FecError::InvalidLength(
                "XOR stripe count does not match expected value",
            ));
        }

        // Validate parity data length
        let pl = parity_len(stripe_count, block_size)?;
        if pl > MAX_PARITY_SIZE {
            return Err(FecError::LimitExceeded(
                "XOR parity exceeds implementation limit",
            ));
        }
        let available = fec_value_data
            .len()
            .checked_sub(HEADER_SIZE)
            .ok_or(FecError::Truncated("XOR FEC value shorter than header"))?;
        if available != pl {
            return Err(FecError::InvalidLength(
                "XOR parity data length does not match Stripe Count × Block Size",
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Standalone validation (without a pre-constructed codec)
// ---------------------------------------------------------------------------

/// Validates a raw XOR FEC value slice without constructing a codec.
///
/// # Errors
///
/// Returns [`SarError`] on any structural violation.
pub fn validate_xor_fec_value(data: &[u8]) -> Result<(), FecError> {
    let codec = XorCodec::from_fec_value(data)?;
    codec.validate(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Erasure;

    fn make_codec(stripe: u8, bsi: u8) -> XorCodec {
        XorCodec::new(stripe, bsi).expect("test")
    }

    #[test]
    fn xor_reserved_stripe_size() {
        assert!(matches!(
            XorCodec::new(0, 0),
            Err(FecError::ReservedValue(_))
        ));
    }

    #[test]
    fn xor_reserved_block_size_index() {
        assert!(matches!(
            XorCodec::new(1, 0xFF),
            Err(FecError::ReservedValue(_))
        ));
    }

    #[test]
    fn xor_roundtrip_single_stripe() {
        // 3 blocks × 256 bytes = 768 bytes
        let data: Vec<u8> = (0u8..=255).cycle().take(768).collect();
        let codec = make_codec(3, 0x00); // stripe_size=3, block_size=256
        let fec = codec.encode_recovery(&data, FecOptions).expect("encode");

        // No erasures: recover should return identical data
        let input = FecRecoverInput {
            original_protected_len: 768,
            available_data: &data,
            fec_value_data: &fec.data,
            erasures: &[],
        };
        let out = codec.recover(input).expect("recover no erasures");
        assert_eq!(out, data);
    }

    #[test]
    fn xor_recover_erased_first_block() {
        // 3 blocks × 256 bytes = 768 bytes, 1 stripe
        let data: Vec<u8> = (0u8..=255).cycle().take(768).collect();
        let codec = make_codec(3, 0x00);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        // Corrupt block 0 (first block)
        let mut corrupted = data.clone();
        corrupted[0..256].fill(0xAB);

        let input = FecRecoverInput {
            original_protected_len: 768,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 0 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn xor_recover_erased_last_block() {
        // 3 blocks × 256 bytes = 768 bytes, 1 stripe
        let data: Vec<u8> = (0u8..=255).cycle().take(768).collect();
        let codec = make_codec(3, 0x00);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        // Corrupt block 2 (last block)
        let mut corrupted = data.clone();
        corrupted[512..768].fill(0xCD);

        let input = FecRecoverInput {
            original_protected_len: 768,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 2 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn xor_two_erasures_same_stripe_fails() {
        let data: Vec<u8> = vec![0u8; 768];
        let codec = make_codec(3, 0x00);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        let input = FecRecoverInput {
            original_protected_len: 768,
            available_data: &data,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 0 }, Erasure { index: 1 }],
        };
        assert!(matches!(codec.recover(input), Err(FecError::EcFailed(_))));
    }

    #[test]
    fn xor_partial_last_block() {
        // 300 bytes: one full block (256) and one partial block (44)
        let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
        let codec = make_codec(2, 0x00); // stripe_size=2, block_size=256
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        // Erase block 0
        let mut corrupted = data.clone();
        corrupted[0..256].fill(0xFF);

        let input = FecRecoverInput {
            original_protected_len: 300,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 0 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }

    #[test]
    fn xor_validate_correct() {
        let data: Vec<u8> = vec![1u8; 1024];
        let codec = make_codec(2, 0x02); // block_size=1024
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");
        assert!(codec.validate(&fec.data).is_ok());
    }

    #[test]
    fn xor_validate_bad_stripe_count() {
        let data: Vec<u8> = vec![1u8; 1024];
        let codec = make_codec(2, 0x02);
        let mut fec = codec.encode_recovery(&data, FecOptions).expect("test");
        // Corrupt stripe count field (bytes 10..14)
        fec.data[10] = 0xFF;
        assert!(matches!(
            codec.validate(&fec.data),
            Err(FecError::InvalidLength(_))
        ));
    }

    #[test]
    fn xor_multiple_stripes() {
        // 4 stripes of 2 blocks × 256 bytes each = 2048 bytes
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let codec = make_codec(2, 0x00);
        let fec = codec.encode_recovery(&data, FecOptions).expect("test");

        // Erase block 2 (second block of first stripe index 1)
        let mut corrupted = data.clone();
        corrupted[512..768].fill(0x00);

        let input = FecRecoverInput {
            original_protected_len: 2048,
            available_data: &corrupted,
            fec_value_data: &fec.data,
            erasures: &[Erasure { index: 2 }],
        };
        let out = codec.recover(input).expect("test");
        assert_eq!(out, data);
    }
}
