//! P-256 field and scalar operations, for `scripts/ct-audit` to inspect after
//! LTO. Not API, not covered by semver; behind the `ct-probes` feature.
//!
//! Each takes and returns big-endian bytes, so the probe's inputs stay
//! runtime values and every operation passes through the same conversions
//! the curve code uses. These are the straight-line pieces that hashing to
//! the curve, the OPRF and every P-256 operation are composed of; the
//! compositions add loops whose counts are public, such as the fixed
//! exponent of an inversion or a square root.

use crate::nist::arith::Field;
use crate::p256::{Fn as Scalar, Fp};
use ic_core::ct::Choice;

macro_rules! probes {
    ($t:ty, $reduce:ident, $add:ident, $sub:ident, $mul:ident, $neg:ident, $cmov:ident, $eq:ident, $odd:ident) => {
        /// Reduce 32 bytes into the field and encode the result.
        #[inline(always)]
        pub fn $reduce(a: &[u8; 32]) -> [u8; 32] {
            <$t>::from_bytes_reduced(a).to_bytes()
        }
        /// `a + b`.
        #[inline(always)]
        pub fn $add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            <$t>::from_bytes_reduced(a)
                .add(&<$t>::from_bytes_reduced(b))
                .to_bytes()
        }
        /// `a - b`.
        #[inline(always)]
        pub fn $sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            <$t>::from_bytes_reduced(a)
                .sub(&<$t>::from_bytes_reduced(b))
                .to_bytes()
        }
        /// `a * b`.
        #[inline(always)]
        pub fn $mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            <$t>::from_bytes_reduced(a)
                .mul(&<$t>::from_bytes_reduced(b))
                .to_bytes()
        }
        /// `-a`.
        #[inline(always)]
        pub fn $neg(a: &[u8; 32]) -> [u8; 32] {
            <$t>::from_bytes_reduced(a).neg().to_bytes()
        }
        /// `b` if `flag` is 1, else `a`.
        #[inline(always)]
        pub fn $cmov(flag: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            let mut x = <$t>::from_bytes_reduced(a);
            <$t as Field>::cmov(
                &mut x,
                &<$t>::from_bytes_reduced(b),
                Choice::from_u8(flag & 1),
            );
            x.to_bytes()
        }
        /// 1 if `a == b` in the field.
        #[inline(always)]
        pub fn $eq(a: &[u8; 32], b: &[u8; 32]) -> u8 {
            <$t>::from_bytes_reduced(a)
                .ct_eq(&<$t>::from_bytes_reduced(b))
                .unwrap_u8()
        }
        /// The parity of `a`'s canonical value: RFC 9380's `sgn0`.
        #[inline(always)]
        pub fn $odd(a: &[u8; 32]) -> u8 {
            <$t>::from_bytes_reduced(a).is_odd().unwrap_u8()
        }
    };
}

probes!(Fp, fp_reduce, fp_add, fp_sub, fp_mul, fp_neg, fp_cmov, fp_eq, fp_is_odd);
probes!(Scalar, fn_reduce, fn_add, fn_sub, fn_mul, fn_neg, fn_cmov, fn_eq, fn_is_odd);
