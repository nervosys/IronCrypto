//! POLYVAL, the universal hash underneath AES-GCM-SIV (RFC 8452 section 3).
//!
//! POLYVAL and GHASH are the same field with the bits written down in opposite
//! orders. GHASH reads a 16-byte block as a polynomial with the most
//! significant coefficient first; POLYVAL reads it least-significant first, and
//! reduces modulo `x^128 + x^127 + x^126 + x^121 + 1` instead of GHASH's
//! `x^128 + x^7 + x^2 + x + 1`. The two polynomials are each other's reverse,
//! which is why the same hardware instruction serves both.
//!
//! # Two implementations, on purpose
//!
//! RFC 8452 Appendix A states the relationship exactly:
//!
//! ```text
//! POLYVAL(H, X_1, ..., X_n) =
//!     ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//!                       ByteReverse(X_1), ..., ByteReverse(X_n)))
//! ```
//!
//! So POLYVAL can be computed two entirely different ways: directly in its own
//! field, or by reversing bytes and borrowing GHASH. This module implements the
//! first; the tests implement the second over [`crate::gcm`]'s GHASH, which is
//! validated against published GCM vectors. Agreement between them is real
//! evidence rather than a round trip, and it is the one part of AES-GCM-SIV
//! that gets such evidence — see the `gcm_siv` module documentation for what
//! does not.
//!
//! # Constant time
//!
//! The multiplication is bit-by-bit with a mask, never a table lookup and never
//! a branch on data, for the same reason [`crate::gcm`]'s GHASH is: a
//! table-driven implementation leaks the key through the cache.

use ac_core::Zeroize;

/// Block size, which is also the field element width.
pub const BLOCK_LEN: usize = 16;

/// Multiply two POLYVAL field elements: `a * b * x^-128`.
///
/// Both operands are little-endian: bit `i` of the 128-bit value is the
/// coefficient of `x^i`, and byte 0 holds bits 0 through 7.
///
/// The `x^-128` factor is POLYVAL's convention, and it is what makes this field
/// line up with GHASH's under byte reversal. It is applied here as 128 explicit
/// divisions by `x` after a full 256-bit carry-less product — the slow, obvious
/// way, chosen because the fast way is where implementations go wrong and the
/// cost is paid once per block either way.
fn mul(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let a0 = u64::from_le_bytes(a[0..8].try_into().unwrap());
    let a1 = u64::from_le_bytes(a[8..16].try_into().unwrap());
    let b0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let b1 = u64::from_le_bytes(b[8..16].try_into().unwrap());

    // Carry-less product into 256 bits. `v` holds `a << i`, widened as it goes.
    let mut z = [0u64; 4];
    let mut v = [a0, a1, 0u64, 0u64];
    for i in 0..128 {
        let bit = if i < 64 {
            (b0 >> i) & 1
        } else {
            (b1 >> (i - 64)) & 1
        };
        let mask = 0u64.wrapping_sub(bit);
        for (zw, vw) in z.iter_mut().zip(v.iter()) {
            *zw ^= *vw & mask;
        }
        v[3] = (v[3] << 1) | (v[2] >> 63);
        v[2] = (v[2] << 1) | (v[1] >> 63);
        v[1] = (v[1] << 1) | (v[0] >> 63);
        v[0] <<= 1;
    }

    reduce(z)
}

/// `x^-1` in POLYVAL's field, as the high word of a little-endian 128-bit value.
///
/// Derived rather than recalled. The modulus is
/// `x^128 + x^127 + x^126 + x^121 + 1`, so in characteristic two
///
/// ```text
/// 1 = x^128 + x^127 + x^126 + x^121 = x * (x^127 + x^126 + x^125 + x^120)
/// ```
///
/// which makes `x^-1 = x^127 + x^126 + x^125 + x^120`. Bits 127, 126, 125 and
/// 120 sit at positions 63, 62, 61 and 56 of the high word, giving the constant
/// below. A different POLYVAL implementation will show a different constant
/// because it reduces a different way; this one belongs to division by `x`.
const X_INVERSE_HIGH: u64 = (1 << 63) | (1 << 62) | (1 << 61) | (1 << 56);

/// Multiply a 256-bit carry-less product by `x^-128`, reducing modulo POLYVAL's
/// polynomial.
fn reduce(mut acc: [u64; 4]) -> [u8; BLOCK_LEN] {
    for _ in 0..128 {
        // Divide by x: shift the whole 256-bit value right one bit, and fold
        // the coefficient that falls off the bottom back in as x^-1.
        let carry = acc[0] & 1;
        acc[0] = (acc[0] >> 1) | (acc[1] << 63);
        acc[1] = (acc[1] >> 1) | (acc[2] << 63);
        acc[2] = (acc[2] >> 1) | (acc[3] << 63);
        acc[3] >>= 1;
        acc[1] ^= 0u64.wrapping_sub(carry) & X_INVERSE_HIGH;
    }

    // After 128 divisions the value fits the low 128 bits.
    debug_assert_eq!(acc[2], 0, "reduction left a high word set");
    debug_assert_eq!(acc[3], 0, "reduction left a high word set");

    let mut out = [0u8; BLOCK_LEN];
    out[0..8].copy_from_slice(&acc[0].to_le_bytes());
    out[8..16].copy_from_slice(&acc[1].to_le_bytes());
    out
}

/// A POLYVAL accumulator.
pub struct Polyval {
    h: [u8; BLOCK_LEN],
    acc: [u8; BLOCK_LEN],
}

impl Polyval {
    /// Start with the hash key `h`.
    pub fn new(h: [u8; BLOCK_LEN]) -> Self {
        Self {
            h,
            acc: [0u8; BLOCK_LEN],
        }
    }

    /// Absorb one whole block.
    pub fn update_block(&mut self, block: &[u8; BLOCK_LEN]) {
        for (a, b) in self.acc.iter_mut().zip(block.iter()) {
            *a ^= *b;
        }
        self.acc = mul(&self.acc, &self.h);
    }

    /// Absorb a byte string, zero-padding the final partial block.
    pub fn update_padded(&mut self, data: &[u8]) {
        for chunk in data.chunks(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            block[..chunk.len()].copy_from_slice(chunk);
            self.update_block(&block);
        }
    }

    /// The accumulated value.
    pub fn finish(self) -> [u8; BLOCK_LEN] {
        self.acc
    }
}

impl Drop for Polyval {
    fn drop(&mut self) {
        self.h.zeroize();
        self.acc.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ByteReverse` from RFC 8452 Appendix A.
    fn byte_reverse(x: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in x.iter().enumerate() {
            out[15 - i] = *b;
        }
        out
    }

    /// `mulX_GHASH` from RFC 8452 Appendix A: multiply by x in GHASH's field.
    ///
    /// GHASH is big-endian in bit order, so "multiply by x" is a right shift of
    /// the bit string, with the reduction constant folded into the top byte.
    fn mul_x_ghash(x: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut carry = 0u8;
        for i in 0..16 {
            let next = x[i] & 1;
            out[i] = (x[i] >> 1) | (carry << 7);
            carry = next;
        }
        if carry != 0 {
            out[0] ^= 0xe1;
        }
        out
    }

    /// POLYVAL computed the other way, through the validated GHASH.
    ///
    /// This is RFC 8452 Appendix A's identity, implemented over
    /// [`crate::gcm::portable_ghash_mul`], which the GCM vectors validate.
    fn polyval_via_ghash(h: &[u8; 16], blocks: &[[u8; 16]]) -> [u8; 16] {
        let ghash_h = mul_x_ghash(&byte_reverse(h));
        let mut acc = [0u8; 16];
        for block in blocks {
            let reversed = byte_reverse(block);
            for (a, b) in acc.iter_mut().zip(reversed.iter()) {
                *a ^= *b;
            }
            crate::gcm::portable_ghash_mul(&mut acc, &ghash_h);
        }
        byte_reverse(&acc)
    }

    /// The whole reason this module implements POLYVAL directly rather than
    /// borrowing GHASH: two independent routes to the same answer.
    #[test]
    fn polyval_matches_the_ghash_construction() {
        // A small deterministic generator, so a failure is reproducible.
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for count in 0..12usize {
            let mut h = [0u8; 16];
            h[0..8].copy_from_slice(&next().to_le_bytes());
            h[8..16].copy_from_slice(&next().to_le_bytes());

            let mut blocks = Vec::new();
            for _ in 0..count {
                let mut b = [0u8; 16];
                b[0..8].copy_from_slice(&next().to_le_bytes());
                b[8..16].copy_from_slice(&next().to_le_bytes());
                blocks.push(b);
            }

            let mut p = Polyval::new(h);
            for b in &blocks {
                p.update_block(b);
            }
            let direct = p.finish();
            let via = polyval_via_ghash(&h, &blocks);
            assert_eq!(
                direct, via,
                "POLYVAL disagreed with the GHASH construction at {count} blocks"
            );
        }
    }

    /// Edge cases the random inputs above are unlikely to reach.
    #[test]
    fn polyval_handles_degenerate_inputs() {
        let zero = [0u8; 16];
        let mut one = [0u8; 16];
        one[0] = 1;

        for h in [zero, one, [0xffu8; 16]] {
            for blocks in [vec![], vec![zero], vec![one, zero], vec![[0xffu8; 16]; 3]] {
                let mut p = Polyval::new(h);
                for b in &blocks {
                    p.update_block(b);
                }
                assert_eq!(p.finish(), polyval_via_ghash(&h, &blocks));
            }
        }
    }

    #[test]
    fn padding_matches_explicit_blocks() {
        let h = [0x42u8; 16];
        let data = b"a partial final block";

        let mut padded = Polyval::new(h);
        padded.update_padded(data);

        let mut explicit = Polyval::new(h);
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            explicit.update_block(&block);
        }
        assert_eq!(padded.finish(), explicit.finish());
    }
}
