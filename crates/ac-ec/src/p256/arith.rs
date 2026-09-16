//! Constant-time arithmetic modulo a 256-bit prime, in Montgomery form.
//!
//! P-256 needs two residue rings: the coordinate field GF(p) and the scalar
//! ring Z/nZ. They differ only in their modulus, so the `mont_field` macro generates
//! both from one implementation.
//!
//! # Deriving the constants
//!
//! Montgomery arithmetic needs `R^2 mod m` and `-m^-1 mod 2^64`. Both are
//! computed at compile time from the modulus rather than pasted in as magic
//! numbers: `R^2` by 512 constant-time doublings, and the inverse by Newton
//! iteration. A transcription error in a hand-copied constant would produce a
//! library that computes confidently wrong answers, and the only constant left
//! to get wrong here is the modulus itself — which the tests check against the
//! curve equation.

use ac_core::ct::Choice;

/// Add two 256-bit values, returning the sum and the carry out.
#[inline]
const fn adc(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 4 {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
    (out, carry as u64)
}

/// Subtract two 256-bit values, returning the difference and the borrow out.
#[inline]
const fn sbb(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    let mut i = 0;
    while i < 4 {
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
const fn select(mask: u64, a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        out[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        i += 1;
    }
    out
}

/// Double `x` modulo `m`, in constant time.
#[inline]
const fn double_mod(x: [u64; 4], m: [u64; 4]) -> [u64; 4] {
    let (sum, carry) = adc(x, x);
    let (reduced, borrow) = sbb(sum, m);
    // Reduce when the sum overflowed 2^256, or when it is already >= m.
    let need = carry | (1 - borrow);
    select(need.wrapping_neg(), reduced, sum)
}

/// `R^2 mod m`, where `R = 2^256`.
///
/// Computed as 512 doublings of one, so no constant is transcribed by hand.
const fn compute_r2(m: [u64; 4]) -> [u64; 4] {
    let mut x = [1u64, 0, 0, 0];
    let mut i = 0;
    while i < 512 {
        x = double_mod(x, m);
        i += 1;
    }
    x
}

/// `-m^-1 mod 2^64`, by Newton iteration.
///
/// `x_{k+1} = x_k * (2 - m * x_k)` doubles the number of correct bits each
/// step; starting from `m` (correct to 3 bits for odd `m`), six steps cover 64.
const fn compute_neg_inv(m0: u64) -> u64 {
    let mut inv = m0;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// Generate a constant-time Montgomery residue ring for one 256-bit modulus.
macro_rules! mont_field {
    ($name:ident, $modulus:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Values are held in Montgomery form (`a * R mod m`). Arithmetic is
        /// branch-free and carries no data-dependent memory access.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub [u64; 4]);

        impl $name {
            /// The modulus, as little-endian 64-bit limbs.
            pub const MODULUS: [u64; 4] = $modulus;
            /// `R^2 mod m`, for conversion into Montgomery form.
            const R2: [u64; 4] = compute_r2($modulus);
            /// `-m^-1 mod 2^64`.
            const NEG_INV: u64 = compute_neg_inv($modulus[0]);

            /// Zero, which is the same in both representations.
            pub const ZERO: Self = Self([0, 0, 0, 0]);

            /// One, in Montgomery form (`R mod m`).
            pub const ONE: Self = Self(Self::mont_mul_raw([1, 0, 0, 0], Self::R2));

            /// Montgomery multiplication (CIOS), the core of this module.
            const fn mont_mul_raw(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
                let mut t = [0u64; 6];
                let mut i = 0;
                while i < 4 {
                    // t += a * b[i]
                    let mut carry = 0u128;
                    let mut j = 0;
                    while j < 4 {
                        let sum = (t[j] as u128) + (a[j] as u128) * (b[i] as u128) + carry;
                        t[j] = sum as u64;
                        carry = sum >> 64;
                        j += 1;
                    }
                    let sum = (t[4] as u128) + carry;
                    t[4] = sum as u64;
                    t[5] = (sum >> 64) as u64;

                    // t = (t + m * (t[0] * NEG_INV mod 2^64)) / 2^64
                    let u = t[0].wrapping_mul(Self::NEG_INV);
                    let sum = (t[0] as u128) + (u as u128) * (Self::MODULUS[0] as u128);
                    let mut carry = sum >> 64;
                    let mut j = 1;
                    while j < 4 {
                        let sum = (t[j] as u128) + (u as u128) * (Self::MODULUS[j] as u128) + carry;
                        t[j - 1] = sum as u64;
                        carry = sum >> 64;
                        j += 1;
                    }
                    let sum = (t[4] as u128) + carry;
                    t[3] = sum as u64;
                    t[4] = (t[5] as u128 + (sum >> 64)) as u64;
                    t[5] = 0;
                    i += 1;
                }

                // A single conditional subtraction brings the result below m.
                let lo = [t[0], t[1], t[2], t[3]];
                let (reduced, borrow) = sbb(lo, Self::MODULUS);
                let need = t[4] | (1 - borrow);
                select(need.wrapping_neg(), reduced, lo)
            }

            /// Multiplication in the ring.
            #[inline]
            pub const fn mul(&self, other: &Self) -> Self {
                Self(Self::mont_mul_raw(self.0, other.0))
            }

            /// Squaring in the ring.
            #[inline]
            pub const fn square(&self) -> Self {
                Self(Self::mont_mul_raw(self.0, self.0))
            }

            /// Repeated squaring, `self^(2^n)`.
            #[inline]
            pub fn square_n(&self, n: usize) -> Self {
                let mut r = *self;
                for _ in 0..n {
                    r = r.square();
                }
                r
            }

            /// Addition in the ring.
            #[inline]
            pub const fn add(&self, other: &Self) -> Self {
                let (sum, carry) = adc(self.0, other.0);
                let (reduced, borrow) = sbb(sum, Self::MODULUS);
                let need = carry | (1 - borrow);
                Self(select(need.wrapping_neg(), reduced, sum))
            }

            /// Subtraction in the ring.
            #[inline]
            pub const fn sub(&self, other: &Self) -> Self {
                let (diff, borrow) = sbb(self.0, other.0);
                // On borrow, add the modulus back.
                let (fixed, _) = adc(diff, Self::MODULUS);
                Self(select(borrow.wrapping_neg(), fixed, diff))
            }

            /// Negation in the ring.
            #[inline]
            pub const fn neg(&self) -> Self {
                Self::ZERO.sub(self)
            }

            /// Doubling, which is cheaper than a general addition.
            #[inline]
            pub const fn double(&self) -> Self {
                Self(double_mod(self.0, Self::MODULUS))
            }

            /// Triple, used by the point doubling formula.
            #[inline]
            pub const fn triple(&self) -> Self {
                self.double().add(self)
            }

            /// Convert a plain integer into Montgomery form.
            #[inline]
            pub const fn to_mont(limbs: [u64; 4]) -> Self {
                Self(Self::mont_mul_raw(limbs, Self::R2))
            }

            /// Convert out of Montgomery form.
            #[inline]
            pub const fn from_mont(&self) -> [u64; 4] {
                Self::mont_mul_raw(self.0, [1, 0, 0, 0])
            }

            /// Decode 32 big-endian bytes, rejecting a non-canonical encoding.
            ///
            /// Values at or above the modulus are refused rather than reduced:
            /// a non-canonical encoding is usually an attack or a bug, and
            /// silently accepting it breaks the uniqueness that signature
            /// verification depends on.
            pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
                let mut limbs = [0u64; 4];
                for i in 0..4 {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&bytes[24 - i * 8..32 - i * 8]);
                    limbs[i] = u64::from_be_bytes(b);
                }
                let (_, borrow) = sbb(limbs, Self::MODULUS);
                if borrow == 0 {
                    return None;
                }
                Some(Self::to_mont(limbs))
            }

            /// Decode 32 big-endian bytes, reducing rather than rejecting.
            ///
            /// Used where a specification calls for reduction, such as turning
            /// a hash into an ECDSA scalar.
            pub fn from_bytes_reduced(bytes: &[u8; 32]) -> Self {
                let mut limbs = [0u64; 4];
                for i in 0..4 {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&bytes[24 - i * 8..32 - i * 8]);
                    limbs[i] = u64::from_be_bytes(b);
                }
                let (reduced, borrow) = sbb(limbs, Self::MODULUS);
                let limbs = select(borrow.wrapping_neg(), limbs, reduced);
                Self::to_mont(limbs)
            }

            /// Encode as 32 big-endian bytes.
            pub fn to_bytes(&self) -> [u8; 32] {
                let limbs = self.from_mont();
                let mut out = [0u8; 32];
                for i in 0..4 {
                    out[24 - i * 8..32 - i * 8].copy_from_slice(&limbs[i].to_be_bytes());
                }
                out
            }

            /// Constant-time test for zero.
            #[inline]
            pub fn is_zero(&self) -> Choice {
                let acc = self.0[0] | self.0[1] | self.0[2] | self.0[3];
                Choice::from_u8(((acc | acc.wrapping_neg()) >> 63) as u8).not()
            }

            /// Constant-time equality.
            #[inline]
            pub fn ct_eq(&self, other: &Self) -> Choice {
                self.sub(other).is_zero()
            }

            /// Constant-time conditional move: `a = b` when `choice` is true.
            #[inline]
            pub fn cmov(a: &mut Self, b: &Self, choice: Choice) {
                let mask = (choice.unwrap_u8() as u64).wrapping_neg();
                a.0 = select(mask, b.0, a.0);
            }

            /// Whether the canonical integer is odd — the sign bit used by
            /// SEC1 point compression.
            #[inline]
            pub fn is_odd(&self) -> Choice {
                Choice::from_u8((self.from_mont()[0] & 1) as u8)
            }

            /// Exponentiation by a public exponent, square-and-multiply.
            ///
            /// The exponent is always a fixed constant here (`m - 2` for
            /// inversion, `(p + 1) / 4` for square roots), so branching on its
            /// bits leaks nothing; the base stays secret throughout.
            pub fn pow(&self, exponent: &[u64; 4]) -> Self {
                let mut result = Self::ONE;
                for i in (0..4).rev() {
                    for bit in (0..64).rev() {
                        result = result.square();
                        if (exponent[i] >> bit) & 1 == 1 {
                            result = result.mul(self);
                        }
                    }
                }
                result
            }

            /// Multiplicative inverse by Fermat's little theorem, with
            /// `inverse(0) == 0`.
            pub fn invert(&self) -> Self {
                // m - 2
                let (exp, _) = sbb(Self::MODULUS, [2, 0, 0, 0]);
                self.pow(&exp)
            }
        }
    };
}

mont_field!(
    Fp,
    [
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ],
    "The P-256 coordinate field, GF(p) with p = 2^256 - 2^224 + 2^192 + 2^96 - 1."
);

mont_field!(
    Fn,
    [
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ],
    "The P-256 scalar ring, Z/nZ where n is the order of the base point."
);

impl Fp {
    /// Square root by `a^((p+1)/4)`, valid because `p = 3 mod 4`.
    ///
    /// Returns a candidate root; the caller must square it to confirm that the
    /// input was actually a quadratic residue.
    pub fn sqrt(&self) -> Fp {
        // (p + 1) / 4
        let (sum, _) = adc(Fp::MODULUS, [1, 0, 0, 0]);
        let exp = [
            (sum[0] >> 2) | (sum[1] << 62),
            (sum[1] >> 2) | (sum[2] << 62),
            (sum[2] >> 2) | (sum[3] << 62),
            sum[3] >> 2,
        ];
        self.pow(&exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(v: u64) -> Fp {
        Fp::to_mont([v, 0, 0, 0])
    }

    fn fnn(v: u64) -> Fn {
        Fn::to_mont([v, 0, 0, 0])
    }

    /// The derived Montgomery constants must satisfy their defining equations.
    #[test]
    fn montgomery_constants_are_consistent() {
        // -m^-1 * m == -1, i.e. m * neg_inv == -1 mod 2^64.
        assert_eq!(
            Fp::MODULUS[0].wrapping_mul(Fp::NEG_INV),
            u64::MAX,
            "p neg_inv"
        );
        assert_eq!(
            Fn::MODULUS[0].wrapping_mul(Fn::NEG_INV),
            u64::MAX,
            "n neg_inv"
        );
        // For p, the low limb is 2^64-1 = -1, so the inverse is 1.
        assert_eq!(Fp::NEG_INV, 1);
    }

    #[test]
    fn one_is_the_multiplicative_identity() {
        for v in [1u64, 2, 7, u64::MAX] {
            assert_eq!(fp(v).mul(&Fp::ONE), fp(v));
            assert_eq!(fnn(v).mul(&Fn::ONE), fnn(v));
        }
        assert_eq!(Fp::ONE.from_mont(), [1, 0, 0, 0]);
        assert_eq!(Fn::ONE.from_mont(), [1, 0, 0, 0]);
    }

    #[test]
    fn small_arithmetic_matches_integers() {
        assert_eq!(fp(2).add(&fp(3)), fp(5));
        assert_eq!(fp(5).sub(&fp(3)), fp(2));
        assert_eq!(fp(6).mul(&fp(7)), fp(42));
        assert_eq!(fp(9).square(), fp(81));
        assert_eq!(fp(5).double(), fp(10));
        assert_eq!(fp(5).triple(), fp(15));
        assert_eq!(fnn(6).mul(&fnn(7)), fnn(42));
    }

    #[test]
    fn subtraction_wraps_into_the_ring() {
        // 0 - 1 == m - 1
        let (expected, _) = sbb(Fp::MODULUS, [1, 0, 0, 0]);
        assert_eq!(Fp::ZERO.sub(&Fp::ONE).from_mont(), expected);
        assert_eq!(fp(0).sub(&fp(1)), fp(0).sub(&fp(1)));
    }

    #[test]
    fn modulus_encodes_as_zero_and_is_rejected() {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[24 - i * 8..32 - i * 8].copy_from_slice(&Fp::MODULUS[i].to_be_bytes());
        }
        // Non-canonical: p itself must be refused.
        assert!(Fp::from_bytes(&bytes).is_none());
        // ...but reducing it yields zero.
        assert_eq!(Fp::from_bytes_reduced(&bytes), Fp::ZERO);
    }

    #[test]
    fn byte_encoding_round_trips() {
        for v in [0u64, 1, 0x0123_4567_89ab_cdef, u64::MAX] {
            let a = fp(v);
            assert_eq!(Fp::from_bytes(&a.to_bytes()).unwrap(), a);
        }
        // A full-width value.
        let bytes = [0x7fu8; 32];
        let a = Fp::from_bytes(&bytes).unwrap();
        assert_eq!(a.to_bytes(), bytes);
    }

    #[test]
    fn inversion_is_correct() {
        for v in [1u64, 2, 3, 19, 65537, u32::MAX as u64] {
            assert_eq!(fp(v).mul(&fp(v).invert()), Fp::ONE, "1/{v} in Fp");
            assert_eq!(fnn(v).mul(&fnn(v).invert()), Fn::ONE, "1/{v} in Fn");
        }
        assert_eq!(Fp::ZERO.invert(), Fp::ZERO);
    }

    #[test]
    fn arithmetic_laws_hold_on_large_values() {
        let a = Fp::from_bytes(&[0x3a; 32]).unwrap();
        let b = Fp::from_bytes(&[0x91; 32]).unwrap();
        let c = Fp::from_bytes(&[0xc7; 32]).unwrap();

        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)), "associativity");
        assert_eq!(a.mul(&b), b.mul(&a), "commutativity");
        assert_eq!(
            a.mul(&b.add(&c)),
            a.mul(&b).add(&a.mul(&c)),
            "distributivity"
        );
        assert_eq!(a.add(&a), a.double());
        assert_eq!(a.sub(&a), Fp::ZERO);
        assert_eq!(a.add(&a.neg()), Fp::ZERO);
    }

    #[test]
    fn square_root_inverts_squaring() {
        for v in [1u64, 4, 9, 16, 1000] {
            let x = fp(v);
            let root = x.square().sqrt();
            // The root is either x or -x; both square back to x.
            assert_eq!(root.square(), x.square(), "sqrt({v}^2)");
        }
    }

    #[test]
    fn non_residues_are_detectable() {
        // Squaring the candidate root is what reveals a non-residue; the caller
        // is expected to perform that check.
        let mut found_non_residue = false;
        for v in 2..40u64 {
            let x = fp(v);
            if x.sqrt().square() != x {
                found_non_residue = true;
                break;
            }
        }
        assert!(found_non_residue, "some small value must be a non-residue");
    }

    #[test]
    fn constant_time_helpers_behave() {
        assert!(bool::from(Fp::ZERO.is_zero()));
        assert!(!bool::from(Fp::ONE.is_zero()));
        assert!(bool::from(fp(7).ct_eq(&fp(7))));
        assert!(!bool::from(fp(7).ct_eq(&fp(8))));

        let mut a = fp(1);
        Fp::cmov(&mut a, &fp(2), Choice::FALSE);
        assert_eq!(a, fp(1));
        Fp::cmov(&mut a, &fp(2), Choice::TRUE);
        assert_eq!(a, fp(2));

        assert!(bool::from(fp(3).is_odd()));
        assert!(!bool::from(fp(4).is_odd()));
    }

    /// The two moduli must be distinct and the scalar ring smaller, which is
    /// the ordering every P-256 argument relies on.
    #[test]
    fn scalar_modulus_is_below_the_field_modulus() {
        let (_, borrow) = sbb(Fn::MODULUS, Fp::MODULUS);
        assert_eq!(borrow, 1, "n must be less than p");
    }
}
