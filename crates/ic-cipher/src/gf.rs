//! Constant-time GF(2^8) arithmetic for AES.
//!
//! The AES S-box is computed *algebraically* rather than read from a lookup
//! table:
//!
//! ```text
//! S(x)    = A · x^-1  ⊕ 0x63       (inversion, then the affine map)
//! S^-1(y) = (A^-1 · y ⊕ 0x05)^-1
//! ```
//!
//! with `x^-1 = x^254` evaluated by square-and-multiply over the Rijndael
//! field. Every operation is a branch-free bitwise sequence, so no secret ever
//! reaches an address bus. That closes the cache-timing channel that table-based
//! AES (the default in many portable C implementations) leaves open.
//!
//! What is here is the byte-at-a-time form. It still runs AES decryption and
//! the key schedule, but encryption goes through [`crate::aes::bitslice`],
//! which does the same algebra for sixty-four bytes at once and is some forty
//! times faster for it.

/// The Rijndael reduction polynomial, x^8 + x^4 + x^3 + x + 1, low byte.
const MODULUS: u8 = 0x1b;

/// Constant-time multiplication in GF(2^8).
#[inline(always)]
pub const fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    let mut i = 0;
    while i < 8 {
        // Add `a` into the accumulator iff the low bit of `b` is set.
        p ^= a & (b & 1).wrapping_neg();
        // xtime(a): shift left, reduce iff the high bit was set.
        let hi = (a >> 7) & 1;
        a <<= 1;
        a ^= MODULUS & hi.wrapping_neg();
        b >>= 1;
        i += 1;
    }
    p
}

/// `x * x` in GF(2^8), without the bit-serial loop.
///
/// Squaring is linear over GF(2) -- `(a + b)^2 = a^2 + b^2`, since the cross
/// term appears twice and cancels -- so squaring a polynomial doubles every
/// exponent and nothing else. That is the bits of `x` spread apart with zeros
/// between them, followed by a reduction, where the general multiply runs its
/// bit-serial loop eight times round.
///
/// It matters because [`inv`] squares seven times and multiplies six: more than
/// half of the S-box was the general routine doing work that squaring does not
/// need. Only the even positions above 7 can be set after spreading, so the
/// reduction folds in four constants rather than seven.
///
/// Constant time: each constant is masked by its own bit, no branches.
///
/// `squaring_matches_the_general_multiply` checks this against `mul(x, x)` for
/// every one of the 256 inputs, which is the whole domain.
#[inline(always)]
pub const fn square(x: u8) -> u8 {
    // Spread bit i to position 2i.
    let t = x as u16;
    let t = (t | (t << 4)) & 0x0f0f;
    let t = (t | (t << 2)) & 0x3333;
    let t = (t | (t << 1)) & 0x5555;

    // x^8, x^10, x^12 and x^14 reduced mod x^8 + x^4 + x^3 + x + 1.
    let mut r = (t & 0xff) as u8;
    r ^= 0x1b & (((t >> 8) & 1) as u8).wrapping_neg();
    r ^= 0x6c & (((t >> 10) & 1) as u8).wrapping_neg();
    r ^= 0xab & (((t >> 12) & 1) as u8).wrapping_neg();
    r ^= 0x9a & (((t >> 14) & 1) as u8).wrapping_neg();
    r
}

/// `x * 2` in GF(2^8), the AES `xtime` operation.
#[inline(always)]
pub const fn xtime(a: u8) -> u8 {
    let hi = (a >> 7) & 1;
    (a << 1) ^ (MODULUS & hi.wrapping_neg())
}

/// Multiplicative inverse in GF(2^8), with `inv(0) == 0`.
///
/// Computed as `x^254` via the square-and-multiply chain for `0b1111_1110`,
/// which is 7 squarings and 6 multiplications, all constant-time. The
/// squarings go through [`square`] rather than the general multiply.
#[inline(always)]
pub const fn inv(x: u8) -> u8 {
    let mut r = x;
    let mut bit = 6i32;
    // Exponent 254 = 0b11111110; the leading 1 is the initial `r = x`.
    while bit >= 0 {
        r = square(r);
        if bit > 0 {
            r = mul(r, x);
        }
        bit -= 1;
    }
    r
}

/// The AES forward S-box, computed in constant time.
#[inline(always)]
pub const fn sbox(x: u8) -> u8 {
    let y = inv(x);
    y ^ y.rotate_left(1) ^ y.rotate_left(2) ^ y.rotate_left(3) ^ y.rotate_left(4) ^ 0x63
}

/// The AES inverse S-box, computed in constant time.
#[inline(always)]
pub const fn inv_sbox(y: u8) -> u8 {
    let t = y.rotate_left(1) ^ y.rotate_left(3) ^ y.rotate_left(6) ^ 0x05;
    inv(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published FIPS 197 S-box, used only to validate the algebraic
    /// construction. The library itself never indexes this table.
    const SBOX_REFERENCE: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    #[test]
    fn algebraic_sbox_matches_fips197() {
        for x in 0..=255u8 {
            assert_eq!(sbox(x), SBOX_REFERENCE[x as usize], "S({x:#04x})");
        }
    }

    #[test]
    fn inverse_sbox_undoes_sbox() {
        for x in 0..=255u8 {
            assert_eq!(inv_sbox(sbox(x)), x, "S^-1(S({x:#04x}))");
        }
    }

    #[test]
    fn field_inversion_is_correct() {
        assert_eq!(inv(0), 0);
        for x in 1..=255u8 {
            assert_eq!(mul(x, inv(x)), 1, "x * x^-1 for {x:#04x}");
        }
    }

    #[test]
    fn xtime_matches_multiplication_by_two() {
        for x in 0..=255u8 {
            assert_eq!(xtime(x), mul(x, 2));
        }
    }

    /// Closed-form squaring against the general multiply, over the whole domain.
    ///
    /// Not a sample: GF(2^8) has 256 elements, so this is every input there is,
    /// checked against the routine the S-box vectors already validate. A
    /// squaring that is wrong for one byte cannot hide from it.
    #[test]
    fn squaring_matches_the_general_multiply() {
        for x in 0..=u8::MAX {
            assert_eq!(square(x), mul(x, x), "square({x:#04x})");
        }
    }
}
