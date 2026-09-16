//! Constant-time arithmetic modulo a prime, in Montgomery form.
//!
//! Each NIST curve needs two residue rings: the coordinate field GF(p) and the
//! scalar ring Z/nZ. They differ only in their modulus and their width, so
//! the `mont_field!` macro generates all of them — four for P-256 and P-384 —
//! from one implementation.
//!
//! # Deriving the constants
//!
//! Montgomery arithmetic needs `R^2 mod m` and `-m^-1 mod 2^64`. Both are
//! computed at compile time from the modulus rather than pasted in as magic
//! numbers: `R^2` by `2 * 64 * LIMBS` constant-time doublings, and the inverse
//! by Newton iteration. A transcription error in a hand-copied constant would
//! produce a library that computes confidently wrong answers. The only
//! constants left to get wrong are the modulus, the curve coefficient, and the
//! base point — and the tests check those against the curve equation and the
//! group order.

use ac_core::ct::Choice;

/// The widest curve supported here, in 64-bit limbs (P-521 would need 9).
pub const MAX_LIMBS: usize = 8;

/// Add two multi-limb values, returning the sum and the carry out.
#[inline]
pub(crate) const fn adc<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut carry = 0u128;
    let mut i = 0;
    while i < N {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
    (out, carry as u64)
}

/// Subtract two multi-limb values, returning the difference and the borrow out.
#[inline]
pub(crate) const fn sbb<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut borrow = 0u128;
    let mut i = 0;
    while i < N {
        let diff = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        out[i] = diff as u64;
        borrow = (diff >> 127) & 1;
        i += 1;
    }
    (out, borrow as u64)
}

/// Branch-free select: `a` when `mask` is all ones, `b` when it is zero.
#[inline]
pub(crate) const fn select<const N: usize>(mask: u64, a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut i = 0;
    while i < N {
        out[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        i += 1;
    }
    out
}

/// Double `x` modulo `m`, in constant time.
#[inline]
const fn double_mod<const N: usize>(x: [u64; N], m: [u64; N]) -> [u64; N] {
    let (sum, carry) = adc(x, x);
    let (reduced, borrow) = sbb(sum, m);
    // Reduce when the sum overflowed the limb width, or is already >= m.
    let need = carry | (1 - borrow);
    select(need.wrapping_neg(), reduced, sum)
}

/// `R^2 mod m`, where `R = 2^(64*N)`.
///
/// Computed by doubling one `2 * 64 * N` times, so no constant is transcribed
/// by hand.
pub(crate) const fn compute_r2<const N: usize>(m: [u64; N]) -> [u64; N] {
    let mut x = [0u64; N];
    x[0] = 1;
    let mut i = 0;
    while i < 128 * N {
        x = double_mod(x, m);
        i += 1;
    }
    x
}

/// `-m^-1 mod 2^64`, by Newton iteration.
///
/// `x_{k+1} = x_k * (2 - m * x_k)` doubles the number of correct bits each
/// step; starting from `m` (correct to 3 bits for odd `m`), six steps cover 64.
pub(crate) const fn compute_neg_inv(m0: u64) -> u64 {
    let mut inv = m0;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// The operations the group law and the signature schemes need from a residue
/// ring.
///
/// Implemented by every type the `mont_field!` macro generates, so the point
/// arithmetic can be written once and instantiated per curve.
pub trait Field: Copy + Clone + core::fmt::Debug + PartialEq + Eq + Sized {
    /// The canonical big-endian byte encoding.
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// The additive identity.
    const ZERO: Self;
    /// The multiplicative identity.
    const ONE: Self;
    /// Width of [`Self::Bytes`].
    const BYTE_LEN: usize;

    /// Ring addition.
    fn add(&self, rhs: &Self) -> Self;
    /// Ring subtraction.
    fn sub(&self, rhs: &Self) -> Self;
    /// Ring multiplication.
    fn mul(&self, rhs: &Self) -> Self;
    /// Squaring.
    fn square(&self) -> Self;
    /// Doubling, cheaper than a general addition.
    fn double(&self) -> Self;
    /// Tripling, used by the `a = -3` doubling formula.
    fn triple(&self) -> Self;
    /// Negation.
    fn neg(&self) -> Self;
    /// Multiplicative inverse, with `inverse(0) == 0`.
    fn invert(&self) -> Self;

    /// Decode a canonical encoding, rejecting values at or above the modulus.
    fn from_bytes(bytes: &Self::Bytes) -> Option<Self>;
    /// Decode, reducing rather than rejecting.
    fn from_bytes_reduced(bytes: &Self::Bytes) -> Self;
    /// Encode canonically.
    fn to_bytes(&self) -> Self::Bytes;
    /// Build a zeroed byte buffer of the right width.
    fn zero_bytes() -> Self::Bytes;

    /// Constant-time test for zero.
    fn is_zero(&self) -> Choice;
    /// Constant-time equality.
    fn ct_eq(&self, other: &Self) -> Choice;
    /// Constant-time conditional move.
    fn cmov(a: &mut Self, b: &Self, choice: Choice);
    /// Whether the canonical integer is odd — the SEC1 compression sign bit.
    fn is_odd(&self) -> Choice;
}

/// Generate a constant-time Montgomery residue ring.
///
/// `$limbs` is the width in 64-bit words and `$bytes` is `8 * $limbs`; both are
/// passed explicitly because Rust cannot yet compute one from the other in a
/// type position.
#[macro_export]
#[doc(hidden)]
macro_rules! mont_field {
    ($name:ident, $limbs:literal, $bytes:literal, $modulus:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Values are held in Montgomery form (`a * R mod m`). Arithmetic is
        /// branch-free and carries no data-dependent memory access.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub [u64; $limbs]);

        impl $name {
            /// The modulus, as little-endian 64-bit limbs.
            pub const MODULUS: [u64; $limbs] = $modulus;
            /// `R^2 mod m`, for conversion into Montgomery form.
            const R2: [u64; $limbs] = $crate::nist::arith::compute_r2($modulus);
            /// `-m^-1 mod 2^64`.
            const NEG_INV: u64 = $crate::nist::arith::compute_neg_inv($modulus[0]);

            /// Montgomery multiplication (CIOS), the core of this module.
            const fn mont_mul_raw(a: [u64; $limbs], b: [u64; $limbs]) -> [u64; $limbs] {
                // Scratch is sized for the widest supported curve rather than
                // `$limbs + 2`, which Rust cannot yet express generically.
                let mut t = [0u64; $crate::nist::arith::MAX_LIMBS + 2];
                let mut i = 0;
                while i < $limbs {
                    // t += a * b[i]
                    let mut carry = 0u128;
                    let mut j = 0;
                    while j < $limbs {
                        let sum = (t[j] as u128) + (a[j] as u128) * (b[i] as u128) + carry;
                        t[j] = sum as u64;
                        carry = sum >> 64;
                        j += 1;
                    }
                    let sum = (t[$limbs] as u128) + carry;
                    t[$limbs] = sum as u64;
                    t[$limbs + 1] = (sum >> 64) as u64;

                    // t = (t + m * (t[0] * NEG_INV mod 2^64)) / 2^64
                    let u = t[0].wrapping_mul(Self::NEG_INV);
                    let sum = (t[0] as u128) + (u as u128) * (Self::MODULUS[0] as u128);
                    let mut carry = sum >> 64;
                    let mut j = 1;
                    while j < $limbs {
                        let sum = (t[j] as u128) + (u as u128) * (Self::MODULUS[j] as u128) + carry;
                        t[j - 1] = sum as u64;
                        carry = sum >> 64;
                        j += 1;
                    }
                    let sum = (t[$limbs] as u128) + carry;
                    t[$limbs - 1] = sum as u64;
                    t[$limbs] = (t[$limbs + 1] as u128 + (sum >> 64)) as u64;
                    t[$limbs + 1] = 0;
                    i += 1;
                }

                // A single conditional subtraction brings the result below m.
                let mut lo = [0u64; $limbs];
                let mut k = 0;
                while k < $limbs {
                    lo[k] = t[k];
                    k += 1;
                }
                let (reduced, borrow) = $crate::nist::arith::sbb(lo, Self::MODULUS);
                let need = t[$limbs] | (1 - borrow);
                $crate::nist::arith::select(need.wrapping_neg(), reduced, lo)
            }

            /// Convert a plain integer into Montgomery form.
            pub const fn to_mont(limbs: [u64; $limbs]) -> Self {
                Self(Self::mont_mul_raw(limbs, Self::R2))
            }

            /// Convert out of Montgomery form.
            pub const fn from_mont(&self) -> [u64; $limbs] {
                let mut one = [0u64; $limbs];
                one[0] = 1;
                Self::mont_mul_raw(self.0, one)
            }

            /// Repeated squaring, `self^(2^n)`.
            pub fn square_n(&self, n: usize) -> Self {
                let mut r = *self;
                for _ in 0..n {
                    r = <Self as $crate::nist::arith::Field>::square(&r);
                }
                r
            }

            /// Exponentiation by a public exponent, square-and-multiply.
            ///
            /// The exponent is always a fixed constant here (`m - 2` for
            /// inversion, `(p + 1) / 4` for square roots), so branching on its
            /// bits leaks nothing; the base stays secret throughout.
            pub fn pow(&self, exponent: &[u64; $limbs]) -> Self {
                let mut result = <Self as $crate::nist::arith::Field>::ONE;
                for i in (0..$limbs).rev() {
                    for bit in (0..64).rev() {
                        result = <Self as $crate::nist::arith::Field>::square(&result);
                        if (exponent[i] >> bit) & 1 == 1 {
                            result = <Self as $crate::nist::arith::Field>::mul(&result, self);
                        }
                    }
                }
                result
            }
        }

        impl $crate::nist::arith::Field for $name {
            type Bytes = [u8; $bytes];

            const ZERO: Self = Self([0u64; $limbs]);
            const ONE: Self = Self(Self::mont_mul_raw(
                {
                    let mut one = [0u64; $limbs];
                    one[0] = 1;
                    one
                },
                Self::R2,
            ));
            const BYTE_LEN: usize = $bytes;

            #[inline]
            fn add(&self, other: &Self) -> Self {
                let (sum, carry) = $crate::nist::arith::adc(self.0, other.0);
                let (reduced, borrow) = $crate::nist::arith::sbb(sum, Self::MODULUS);
                let need = carry | (1 - borrow);
                Self($crate::nist::arith::select(
                    need.wrapping_neg(),
                    reduced,
                    sum,
                ))
            }

            #[inline]
            fn sub(&self, other: &Self) -> Self {
                let (diff, borrow) = $crate::nist::arith::sbb(self.0, other.0);
                // On borrow, add the modulus back.
                let (fixed, _) = $crate::nist::arith::adc(diff, Self::MODULUS);
                Self($crate::nist::arith::select(
                    borrow.wrapping_neg(),
                    fixed,
                    diff,
                ))
            }

            #[inline]
            fn mul(&self, other: &Self) -> Self {
                Self(Self::mont_mul_raw(self.0, other.0))
            }

            #[inline]
            fn square(&self) -> Self {
                Self(Self::mont_mul_raw(self.0, self.0))
            }

            #[inline]
            fn double(&self) -> Self {
                <Self as $crate::nist::arith::Field>::add(self, self)
            }

            #[inline]
            fn triple(&self) -> Self {
                let d = <Self as $crate::nist::arith::Field>::double(self);
                <Self as $crate::nist::arith::Field>::add(&d, self)
            }

            #[inline]
            fn neg(&self) -> Self {
                <Self as $crate::nist::arith::Field>::sub(
                    &<Self as $crate::nist::arith::Field>::ZERO,
                    self,
                )
            }

            fn invert(&self) -> Self {
                // m - 2
                let mut two = [0u64; $limbs];
                two[0] = 2;
                let (exp, _) = $crate::nist::arith::sbb(Self::MODULUS, two);
                self.pow(&exp)
            }

            fn from_bytes(bytes: &Self::Bytes) -> Option<Self> {
                let mut limbs = [0u64; $limbs];
                for i in 0..$limbs {
                    let hi = $bytes - i * 8;
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&bytes[hi - 8..hi]);
                    limbs[i] = u64::from_be_bytes(b);
                }
                let (_, borrow) = $crate::nist::arith::sbb(limbs, Self::MODULUS);
                if borrow == 0 {
                    return None;
                }
                Some(Self::to_mont(limbs))
            }

            fn from_bytes_reduced(bytes: &Self::Bytes) -> Self {
                let mut limbs = [0u64; $limbs];
                for i in 0..$limbs {
                    let hi = $bytes - i * 8;
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&bytes[hi - 8..hi]);
                    limbs[i] = u64::from_be_bytes(b);
                }
                let (reduced, borrow) = $crate::nist::arith::sbb(limbs, Self::MODULUS);
                let limbs = $crate::nist::arith::select(borrow.wrapping_neg(), limbs, reduced);
                Self::to_mont(limbs)
            }

            fn to_bytes(&self) -> Self::Bytes {
                let limbs = self.from_mont();
                let mut out = [0u8; $bytes];
                for i in 0..$limbs {
                    let hi = $bytes - i * 8;
                    out[hi - 8..hi].copy_from_slice(&limbs[i].to_be_bytes());
                }
                out
            }

            fn zero_bytes() -> Self::Bytes {
                [0u8; $bytes]
            }

            #[inline]
            fn is_zero(&self) -> ac_core::ct::Choice {
                let mut acc = 0u64;
                for limb in self.0.iter() {
                    acc |= *limb;
                }
                ac_core::ct::Choice::from_u8(((acc | acc.wrapping_neg()) >> 63) as u8).not()
            }

            #[inline]
            fn ct_eq(&self, other: &Self) -> ac_core::ct::Choice {
                let d = <Self as $crate::nist::arith::Field>::sub(self, other);
                <Self as $crate::nist::arith::Field>::is_zero(&d)
            }

            #[inline]
            fn cmov(a: &mut Self, b: &Self, choice: ac_core::ct::Choice) {
                let mask = (choice.unwrap_u8() as u64).wrapping_neg();
                a.0 = $crate::nist::arith::select(mask, b.0, a.0);
            }

            #[inline]
            fn is_odd(&self) -> ac_core::ct::Choice {
                ac_core::ct::Choice::from_u8((self.from_mont()[0] & 1) as u8)
            }
        }
    };
}

/// Square root by `a^((p+1)/4)`, valid only when `p = 3 mod 4`.
///
/// Both P-256 and P-384 satisfy that, which is why neither needs the general
/// Tonelli-Shanks algorithm. The caller must square the result to confirm the
/// input was a quadratic residue; this returns a candidate either way.
pub fn sqrt_p3mod4<F: Field, const N: usize>(
    x: &F,
    modulus: [u64; N],
    pow: impl Fn(&F, &[u64; N]) -> F,
) -> F {
    let mut one = [0u64; N];
    one[0] = 1;
    let (sum, _) = adc(modulus, one);
    // (p + 1) / 4
    let mut exp = [0u64; N];
    let mut i = 0;
    while i < N {
        let lo = sum[i] >> 2;
        let hi = if i + 1 < N { sum[i + 1] << 62 } else { 0 };
        exp[i] = lo | hi;
        i += 1;
    }
    pow(x, &exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newton_inverse_satisfies_its_defining_equation() {
        for m0 in [
            0xffff_ffff_ffff_ffffu64,
            0xf3b9_cac2_fc63_2551,
            0x0000_0000_ffff_ffff,
            0xecec_196a_ccc5_2973,
        ] {
            // m * (-m^-1) == -1 mod 2^64
            assert_eq!(m0.wrapping_mul(compute_neg_inv(m0)), u64::MAX, "{m0:#x}");
        }
    }

    #[test]
    fn carry_and_borrow_propagate() {
        let (sum, carry) = adc([u64::MAX, 0], [1u64, 0]);
        assert_eq!(sum, [0, 1]);
        assert_eq!(carry, 0);

        let (sum, carry) = adc([u64::MAX, u64::MAX], [1u64, 0]);
        assert_eq!(sum, [0, 0]);
        assert_eq!(carry, 1);

        let (diff, borrow) = sbb([0u64, 1], [1u64, 0]);
        assert_eq!(diff, [u64::MAX, 0]);
        assert_eq!(borrow, 0);

        let (diff, borrow) = sbb([0u64, 0], [1u64, 0]);
        assert_eq!(diff, [u64::MAX, u64::MAX]);
        assert_eq!(borrow, 1);
    }

    #[test]
    fn select_is_branch_free_and_correct() {
        assert_eq!(select(u64::MAX, [1u64, 2], [3u64, 4]), [1, 2]);
        assert_eq!(select(0, [1u64, 2], [3u64, 4]), [3, 4]);
    }
}
