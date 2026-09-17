//! Arithmetic in GF(2^255 - 19).
//!
//! Field elements are five 51-bit limbs in a `u64`, the representation used by
//! every high-quality Curve25519 implementation: products fit a `u128` without
//! overflow, and carries propagate in a fixed pattern with no data-dependent
//! branches. Nothing here inspects a limb value to decide control flow, so the
//! whole module is constant-time with respect to secrets.

//! Indexed loops over fixed-size limb and word arrays are used throughout; they
//! mirror the index algebra in the specifications these routines implement, so
//! `needless_range_loop` is allowed rather than obscuring the correspondence.
#![allow(clippy::needless_range_loop)]

use ic_core::ct::Choice;

/// A field element modulo 2^255 - 19.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe(pub [u64; 5]);

const MASK: u64 = (1 << 51) - 1;

/// `2 * p`, used so subtraction never goes negative.
// Limb 0 is 2*(2^51 - 19) = 2^52 - 38; the rest are 2*(2^51 - 1) = 2^52 - 2.
// The digits are grouped to show all thirteen nibbles of each 52-bit limb
// rather than in fours, which would obscure the limb boundary.
#[allow(clippy::unusual_byte_groupings)]
const TWO_P: [u64; 5] = [
    0xFFFFFFFFFFFDA,
    0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE,
];

impl Fe {
    /// The additive identity.
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    /// The multiplicative identity.
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// A small integer as a field element.
    pub const fn from_u64(v: u64) -> Fe {
        Fe([v & MASK, v >> 51, 0, 0, 0])
    }

    /// Field addition.
    #[inline]
    pub fn add(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + other.0[i];
        }
        Fe(r)
    }

    /// Field subtraction, via `self + 2p - other` so limbs stay non-negative.
    #[inline]
    pub fn sub(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + TWO_P[i] - other.0[i];
        }
        Fe(r).weak_reduce()
    }

    /// Field negation.
    #[inline]
    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// One pass of carry propagation, leaving every limb below 2^51.
    #[inline]
    fn weak_reduce(self) -> Fe {
        let mut r = self.0;
        let mut carry = r[0] >> 51;
        r[0] &= MASK;
        for i in 1..5 {
            r[i] += carry;
            carry = r[i] >> 51;
            r[i] &= MASK;
        }
        r[0] += carry.wrapping_mul(19);
        Fe(r)
    }

    /// Field multiplication.
    #[inline]
    pub fn mul(&self, other: &Fe) -> Fe {
        let a = &self.0;
        let b = &other.0;
        // 19 * b_i terms let the reduction fold back into the low limbs.
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;

        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;
        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;

        let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        carry_reduce([r0, r1, r2, r3, r4])
    }

    /// Field squaring.
    #[inline]
    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    /// Repeated squaring, `self^(2^n)`.
    #[inline]
    pub fn square_n(&self, n: usize) -> Fe {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// Multiplication by the Montgomery ladder constant `a24 = 121666`.
    #[inline]
    pub fn mul121666(&self) -> Fe {
        let mut r = [0u128; 5];
        for i in 0..5 {
            r[i] = (self.0[i] as u128) * 121_666;
        }
        carry_reduce(r)
    }

    /// Multiplicative inverse, `self^(p-2)`, with `inverse(0) == 0`.
    ///
    /// Uses the standard addition chain: 254 squarings and 11 multiplications.
    pub fn invert(&self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z2_5_0 = z11.square().mul(&z9);
        let z2_10_0 = z2_5_0.square_n(5).mul(&z2_5_0);
        let z2_20_0 = z2_10_0.square_n(10).mul(&z2_10_0);
        let z2_40_0 = z2_20_0.square_n(20).mul(&z2_20_0);
        let z2_50_0 = z2_40_0.square_n(10).mul(&z2_10_0);
        let z2_100_0 = z2_50_0.square_n(50).mul(&z2_50_0);
        let z2_200_0 = z2_100_0.square_n(100).mul(&z2_100_0);
        let z2_250_0 = z2_200_0.square_n(50).mul(&z2_50_0);
        z2_250_0.square_n(5).mul(&z11)
    }

    /// `self^((p-5)/8)`, the exponent used to take square roots.
    pub fn pow22523(&self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z2_5_0 = z11.square().mul(&z9);
        let z2_10_0 = z2_5_0.square_n(5).mul(&z2_5_0);
        let z2_20_0 = z2_10_0.square_n(10).mul(&z2_10_0);
        let z2_40_0 = z2_20_0.square_n(20).mul(&z2_20_0);
        let z2_50_0 = z2_40_0.square_n(10).mul(&z2_10_0);
        let z2_100_0 = z2_50_0.square_n(50).mul(&z2_50_0);
        let z2_200_0 = z2_100_0.square_n(100).mul(&z2_100_0);
        let z2_250_0 = z2_200_0.square_n(50).mul(&z2_50_0);
        z2_250_0.square_n(2).mul(self)
    }

    /// Decode 32 little-endian bytes, ignoring the top bit as RFC 7748 requires.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&bytes[i..i + 8]);
            u64::from_le_bytes(v)
        };
        let l0 = load(0) & MASK;
        let l1 = (load(6) >> 3) & MASK;
        let l2 = (load(12) >> 6) & MASK;
        let l3 = (load(19) >> 1) & MASK;
        let l4 = (load(24) >> 12) & MASK;
        Fe([l0, l1, l2, l3, l4])
    }

    /// Encode as 32 little-endian bytes, fully reduced modulo p.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Three passes leave every limb strictly below 2^51: each pass can
        // push at most a 19 back into limb 0, so the residue shrinks each time.
        let mut t = self.weak_reduce().weak_reduce().weak_reduce().0;

        // Conditionally subtract p, in constant time.
        // q is 1 exactly when t >= p.
        let mut q = (t[0] + 19) >> 51;
        for i in 1..5 {
            q = (t[i] + q) >> 51;
        }
        t[0] += 19 * q;
        let mut carry = t[0] >> 51;
        t[0] &= MASK;
        for i in 1..5 {
            t[i] += carry;
            carry = t[i] >> 51;
            t[i] &= MASK;
        }
        // Drop the bit that overflowed past 2^255.
        t[4] &= (1 << 51) - 1;

        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut acc_bits = 0usize;
        let mut idx = 0usize;
        for limb in t.iter() {
            acc |= (*limb as u128) << acc_bits;
            acc_bits += 51;
            while acc_bits >= 8 && idx < 32 {
                out[idx] = acc as u8;
                acc >>= 8;
                acc_bits -= 8;
                idx += 1;
            }
        }
        while idx < 32 {
            out[idx] = acc as u8;
            acc >>= 8;
            idx += 1;
        }
        out
    }

    /// Constant-time conditional swap.
    #[inline]
    pub fn cswap(a: &mut Fe, b: &mut Fe, choice: Choice) {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Constant-time conditional move: `a = b` when `choice` is true.
    #[inline]
    pub fn cmov(a: &mut Fe, b: &Fe, choice: Choice) {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        for i in 0..5 {
            a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
        }
    }

    /// Constant-time test for zero.
    pub fn is_zero(&self) -> Choice {
        ic_core::ct::is_zero(&self.to_bytes())
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Fe) -> Choice {
        ic_core::ct::eq(&self.to_bytes(), &other.to_bytes())
    }

    /// The least significant bit of the canonical encoding — the "sign" used by
    /// Edwards point compression.
    pub fn is_negative(&self) -> Choice {
        Choice::from_u8(self.to_bytes()[0] & 1)
    }
}

/// Fold five 128-bit products back into 51-bit limbs.
#[inline]
fn carry_reduce(mut r: [u128; 5]) -> Fe {
    let mut carry = r[0] >> 51;
    r[0] &= MASK as u128;
    for i in 1..5 {
        r[i] += carry;
        carry = r[i] >> 51;
        r[i] &= MASK as u128;
    }
    // The carry out of the top limb re-enters at the bottom scaled by 19.
    r[0] += carry * 19;

    let mut out = [0u64; 5];
    let mut c = r[0] >> 51;
    out[0] = (r[0] & MASK as u128) as u64;
    for i in 1..5 {
        let v = r[i] + c;
        c = v >> 51;
        out[i] = (v & MASK as u128) as u64;
    }
    out[0] += (c as u64) * 19;
    Fe(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(v: u64) -> Fe {
        Fe::from_u64(v)
    }

    #[test]
    fn encode_decode_roundtrip() {
        for v in [0u64, 1, 2, 19, 1 << 51, u64::MAX] {
            let a = fe(v);
            assert_eq!(Fe::from_bytes(&a.to_bytes()).to_bytes(), a.to_bytes());
        }
    }

    #[test]
    fn small_arithmetic() {
        assert_eq!(fe(2).add(&fe(3)).to_bytes(), fe(5).to_bytes());
        assert_eq!(fe(5).sub(&fe(3)).to_bytes(), fe(2).to_bytes());
        assert_eq!(fe(6).mul(&fe(7)).to_bytes(), fe(42).to_bytes());
        assert_eq!(fe(9).square().to_bytes(), fe(81).to_bytes());
    }

    #[test]
    fn subtraction_wraps_into_the_field() {
        // 0 - 1 == p - 1, whose encoding is ec ff .. 7f.
        let r = Fe::ZERO.sub(&Fe::ONE).to_bytes();
        assert_eq!(r[0], 0xec);
        assert_eq!(r[31], 0x7f);
        for b in &r[1..31] {
            assert_eq!(*b, 0xff);
        }
    }

    #[test]
    fn p_encodes_as_zero() {
        // p itself must reduce to 0.
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&p_bytes).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn inversion_is_correct() {
        for v in [1u64, 2, 3, 19, 12345, u32::MAX as u64] {
            let a = fe(v);
            assert_eq!(a.mul(&a.invert()).to_bytes(), Fe::ONE.to_bytes(), "1/{v}");
        }
        assert_eq!(Fe::ZERO.invert().to_bytes(), [0u8; 32]);
    }

    #[test]
    fn multiplication_is_associative_and_distributive() {
        let a = Fe::from_bytes(&[0x11; 32]);
        let b = Fe::from_bytes(&[0x7a; 32]);
        let c = Fe::from_bytes(&[0xc3; 32]);
        assert_eq!(a.mul(&b).mul(&c).to_bytes(), a.mul(&b.mul(&c)).to_bytes());
        assert_eq!(
            a.mul(&b.add(&c)).to_bytes(),
            a.mul(&b).add(&a.mul(&c)).to_bytes()
        );
    }

    #[test]
    fn pow22523_gives_a_square_root() {
        // For a square x, x^((p-5)/8) * x is a square root up to a factor of i.
        let x = fe(4);
        let r = x.pow22523().mul(&x);
        let sq = r.square();
        // r^2 is either x or -x.
        assert!(
            bool::from(sq.ct_eq(&x)) || bool::from(sq.ct_eq(&x.neg())),
            "square root property"
        );
    }

    #[test]
    fn cswap_and_cmov_are_conditional() {
        let mut a = fe(1);
        let mut b = fe(2);
        Fe::cswap(&mut a, &mut b, Choice::FALSE);
        assert_eq!(a.to_bytes(), fe(1).to_bytes());
        Fe::cswap(&mut a, &mut b, Choice::TRUE);
        assert_eq!(a.to_bytes(), fe(2).to_bytes());

        let mut c = fe(5);
        Fe::cmov(&mut c, &fe(9), Choice::FALSE);
        assert_eq!(c.to_bytes(), fe(5).to_bytes());
        Fe::cmov(&mut c, &fe(9), Choice::TRUE);
        assert_eq!(c.to_bytes(), fe(9).to_bytes());
    }

    #[test]
    fn high_bit_of_input_is_ignored() {
        let mut a = [0x42u8; 32];
        let mut b = a;
        a[31] &= 0x7f;
        b[31] |= 0x80;
        assert_eq!(Fe::from_bytes(&a).to_bytes(), Fe::from_bytes(&b).to_bytes());
    }
}
