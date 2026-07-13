// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! GF(2^8) finite field arithmetic for Reed-Solomon.
//!
//! Field parameters (per SAR spec):
//! * Primitive polynomial: `0x11D` (x⁸ + x⁴ + x³ + x² + 1)
//! * Primitive element: `α = 0x02`

// ---------------------------------------------------------------------------
// Log/exp table generation
// ---------------------------------------------------------------------------

/// exp[i] = α^i in GF(2^8).  Stored as 512 elements to avoid modular wrap
/// during multiplication (indices 0..=254 + repeated 255..=509).
pub(crate) const EXP: [u8; 512] = build_exp_table();
/// log[v] = i such that α^i = v, for v ≠ 0.  log[0] is unused/undefined.
pub(crate) const LOG: [u8; 256] = build_log_table(&EXP);

const fn gf_mul_raw(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a = a.wrapping_shl(1);
        if hi != 0 {
            a ^= 0x1D; // 0x11D mod 0x100
        }
        b >>= 1;
        i += 1;
    }
    p
}

const fn build_exp_table() -> [u8; 512] {
    let mut exp = [0u8; 512];
    let mut x: u8 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x;
        exp[i + 255] = x;
        x = gf_mul_raw(x, 2);
        i += 1;
    }
    // α^255 = 1 = α^0
    exp[255] = 1;
    exp[510] = 1;
    exp[511] = 2; // α^256 = α
    exp
}

const fn build_log_table(exp: &[u8; 512]) -> [u8; 256] {
    let mut log = [0u8; 256];
    let mut i = 0usize;
    while i < 255 {
        log[exp[i] as usize] = i as u8;
        i += 1;
    }
    // log[1] = 0 already set since exp[0] = 1
    log
}

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic
// ---------------------------------------------------------------------------

/// GF(2^8) multiplication.
#[inline]
pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[(LOG[a as usize] as usize) + (LOG[b as usize] as usize)]
}

/// GF(2^8) division: `a / b`.
///
/// # Panics
///
/// Panics when `b == 0` (only in debug; in release would produce garbage).
#[inline]
pub(crate) fn gf_div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0, "GF division by zero");
    if a == 0 {
        return 0;
    }
    let log_a = LOG[a as usize] as usize;
    let log_b = LOG[b as usize] as usize;
    // Add 255 to avoid underflow in the modular subtraction.
    EXP[(log_a + 255 - log_b) % 255]
}

/// GF(2^8) addition (= XOR).
#[inline]
pub(crate) fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(2^8) power: α^n (for arbitrary n, using EXP table mod 255).
#[inline]
pub(crate) fn gf_pow(n: u32) -> u8 {
    if n == 0 {
        return 1;
    }
    EXP[(n % 255) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_table_starts_at_one() {
        assert_eq!(EXP[0], 1);
        assert_eq!(EXP[1], 2);
    }

    #[test]
    fn alpha_255_equals_one() {
        assert_eq!(EXP[255], 1);
    }

    #[test]
    fn log_inverse_of_exp() {
        for i in 0..255usize {
            assert_eq!(EXP[i], EXP[(LOG[EXP[i] as usize]) as usize]);
        }
    }

    #[test]
    fn mul_by_zero_is_zero() {
        for v in 0u8..=255 {
            assert_eq!(gf_mul(v, 0), 0);
            assert_eq!(gf_mul(0, v), 0);
        }
    }

    #[test]
    fn mul_by_one_is_identity() {
        for v in 1u8..=255 {
            assert_eq!(gf_mul(v, 1), v);
            assert_eq!(gf_mul(1, v), v);
        }
    }

    #[test]
    fn div_inverse_of_mul() {
        for a in 1u8..=255 {
            for b in 1u8..=255 {
                let ab = gf_mul(a, b);
                assert_eq!(gf_div(ab, b), a, "div({ab}, {b}) should be {a}");
            }
        }
    }

    #[test]
    fn gf_pow_examples() {
        // α^0 = 1, α^1 = 2
        assert_eq!(gf_pow(0), 1);
        assert_eq!(gf_pow(1), 2);
        // α^8 should equal 0x1D (from primitive polynomial reduction)
        // α^8 = x^8 mod (x^8 + x^4 + x^3 + x^2 + 1) = x^4+x^3+x^2+1 = 0x1D
        assert_eq!(gf_pow(8), 0x1D);
    }
}
