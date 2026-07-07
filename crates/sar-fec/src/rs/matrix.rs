//! GF(2^8) matrix operations used for Reed-Solomon erasure decoding.

use sar_core::SarError;

use super::gf::{gf_add, gf_div, gf_mul};

// ---------------------------------------------------------------------------
// Square matrix over GF(2^8)
// ---------------------------------------------------------------------------

/// A square matrix over GF(2^8), stored in row-major order.
pub(crate) struct GfMatrix {
    size: usize,
    /// Row-major storage: element (row, col) = data[row * size + col].
    data: Vec<u8>,
}

impl GfMatrix {
    /// Creates a new zero matrix of dimension `size × size`.
    pub(crate) fn zeroes(size: usize) -> Self {
        Self { size, data: vec![0u8; size * size] }
    }

    #[inline]
    pub(crate) fn get(&self, row: usize, col: usize) -> u8 {
        self.data[row * self.size + col]
    }

    #[inline]
    pub(crate) fn set(&mut self, row: usize, col: usize, v: u8) {
        self.data[row * self.size + col] = v;
    }

    /// Returns a mutable reference to row `r`.
    #[allow(dead_code)]
    fn row_mut(&mut self, r: usize) -> &mut [u8] {
        &mut self.data[r * self.size..(r + 1) * self.size]
    }

    /// Returns a copy of row `r`.
    #[allow(dead_code)]
    fn row_copy(&self, r: usize) -> Vec<u8> {
        self.data[r * self.size..(r + 1) * self.size].to_vec()
    }
}

// ---------------------------------------------------------------------------
// Augmented matrix inversion via Gauss-Jordan elimination in GF(2^8)
// ---------------------------------------------------------------------------

/// Inverts the `n × n` matrix `m` over GF(2^8) using Gauss-Jordan elimination
/// with partial pivoting.
///
/// # Errors
///
/// Returns [`SarError::EcFailed`] if the matrix is singular (decode matrix
/// is rank-deficient; too many erasures or degenerate configuration).
pub(crate) fn invert(m: &GfMatrix) -> Result<GfMatrix, SarError> {
    let n = m.size;

    // Build augmented matrix [M | I].
    let aug_cols = n * 2;
    let mut aug: Vec<u8> = vec![0u8; n * aug_cols];

    for r in 0..n {
        for c in 0..n {
            aug[r * aug_cols + c] = m.get(r, c);
        }
        aug[r * aug_cols + n + r] = 1; // identity on right half
    }

    // Forward elimination with partial pivoting.
    for col in 0..n {
        // Find pivot row: first non-zero in this column at or below `col`.
        let pivot = (col..n).find(|&r| aug[r * aug_cols + col] != 0).ok_or(
            SarError::EcFailed("RS decode: singular matrix (too many erasures)"),
        )?;

        if pivot != col {
            // Swap rows `col` and `pivot`.
            for c in 0..aug_cols {
                aug.swap(col * aug_cols + c, pivot * aug_cols + c);
            }
        }

        // Scale pivot row so diagonal element becomes 1.
        let diag = aug[col * aug_cols + col];
        for c in 0..aug_cols {
            aug[col * aug_cols + c] = gf_div(aug[col * aug_cols + c], diag);
        }

        // Eliminate all other rows.
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = aug[r * aug_cols + col];
            if factor == 0 {
                continue;
            }
            for c in 0..aug_cols {
                let pv = aug[col * aug_cols + c];
                aug[r * aug_cols + c] = gf_add(aug[r * aug_cols + c], gf_mul(factor, pv));
            }
        }
    }

    // Extract right half as result.
    let mut inv = GfMatrix::zeroes(n);
    for r in 0..n {
        for c in 0..n {
            inv.set(r, c, aug[r * aug_cols + n + c]);
        }
    }
    Ok(inv)
}

/// Multiplies an `n × n` matrix by an `n`-element column vector, returning the
/// `n`-element result.  Each element is a byte-vector of length `symbol_size`.
///
/// `mat[r][c] * vec[c]` is scalar-times-vector: multiply each byte of `vec[c]`
/// by `mat[r][c]`.
pub(crate) fn mat_vec_mul(mat: &GfMatrix, vecs: &[Vec<u8>], symbol_size: usize) -> Vec<Vec<u8>> {
    let n = mat.size;
    debug_assert_eq!(vecs.len(), n);

    let mut result: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; symbol_size]).collect();

    for (r, dst) in result.iter_mut().enumerate() {
        for (c, src) in vecs.iter().enumerate() {
            let coeff = mat.get(r, c);
            if coeff == 0 {
                continue;
            }
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d = gf_add(*d, gf_mul(coeff, s));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invert_identity() {
        let mut m = GfMatrix::zeroes(3);
        for i in 0..3 {
            m.set(i, i, 1);
        }
        let inv = invert(&m).expect("test");
        for r in 0..3 {
            for c in 0..3 {
                let expected = if r == c { 1 } else { 0 };
                assert_eq!(inv.get(r, c), expected, "identity inverse wrong at ({r},{c})");
            }
        }
    }

    #[test]
    fn invert_singular_fails() {
        let m = GfMatrix::zeroes(3); // all-zero matrix is singular
        assert!(matches!(invert(&m), Err(SarError::EcFailed(_))));
    }

    #[test]
    fn invert_2x2() {
        // Simple 2×2 matrix: [[1,2],[3,4]] → invert and verify A * A^-1 = I
        let mut m = GfMatrix::zeroes(2);
        m.set(0, 0, 1);
        m.set(0, 1, 2);
        m.set(1, 0, 3);
        m.set(1, 1, 4);

        let inv = invert(&m).expect("test");

        // Verify A * inv(A) = I
        for r in 0..2 {
            for c in 0..2 {
                let mut val = 0u8;
                for k in 0..2 {
                    val = gf_add(val, gf_mul(m.get(r, k), inv.get(k, c)));
                }
                let expected = if r == c { 1 } else { 0 };
                assert_eq!(val, expected, "product wrong at ({r},{c})");
            }
        }
    }
}
