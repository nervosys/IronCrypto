//! P-256 field and scalar operations, and Ed25519's scalar arithmetic modulo
//! L, for `scripts/ct-audit` to inspect after LTO. Not API, not covered by
//! semver; behind the `ct-probes` feature.
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

/// Ed25519's scalar reduction, `x mod L` for a 512-bit `x`: what turns a hash
/// into the secret nonce `r`, and finishes `S`.
#[cfg(not(ic_approved_only))]
#[inline(always)]
pub fn ed25519_reduce_wide(x: &[u8; 64]) -> [u8; 32] {
    crate::scalar::reduce_wide(x)
}

/// `(a * b + c) mod L`, which is `S = k * s + r` in Ed25519 signing.
#[cfg(not(ic_approved_only))]
#[inline(always)]
pub fn ed25519_mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    crate::scalar::mul_add(a, b, c)
}

/// The x86-64 Curve25519 backends: the four-limb field, X25519's ladder step
/// and the Edwards blocks on it, and the four-lane IFMA operations. Each is
/// straight-line by construction; these hold the compiled code to it.
///
/// The four-limb functions execute `MULX`/`ADX` and the four-lane ones need
/// AVX-512 IFMA: the probes are for reading compiled code, and calling them
/// on a CPU without those faults, as calling the field directly would.
#[cfg(all(
    not(ic_approved_only),
    target_arch = "x86_64",
    not(any(ic_limb32, ic_ec_portable))
))]
pub mod x86 {
    use crate::fe64::edwards;
    pub use crate::fe64::edwards::{Ws, Ws2};
    use crate::fe64::Fe64;

    /// The four-lane IFMA operations; `unsafe` because they need the CPU
    /// features `Ifma::get` checks for.
    pub use crate::f51x4::probes as ifma;

    /// `a * b`.
    #[inline(always)]
    pub fn fe64_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        Fe64::from_bytes(a).mul(&Fe64::from_bytes(b)).to_bytes()
    }
    /// `a^2`.
    #[inline(always)]
    pub fn fe64_square(a: &[u8; 32]) -> [u8; 32] {
        Fe64::from_bytes(a).square().to_bytes()
    }
    /// `a + b`.
    #[inline(always)]
    pub fn fe64_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        Fe64::from_bytes(a).add(&Fe64::from_bytes(b)).to_bytes()
    }
    /// `a - b`.
    #[inline(always)]
    pub fn fe64_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        Fe64::from_bytes(a).sub(&Fe64::from_bytes(b)).to_bytes()
    }
    /// `121666 a`.
    #[inline(always)]
    pub fn fe64_mul121666(a: &[u8; 32]) -> [u8; 32] {
        Fe64::from_bytes(a).mul121666().to_bytes()
    }
    /// `a^-1`, by divsteps.
    #[inline(always)]
    pub fn fe64_invert(a: &[u8; 32]) -> [u8; 32] {
        Fe64::from_bytes(a).invert().to_bytes()
    }
    /// One X25519 ladder step, the secret bit in `swap`.
    #[inline(always)]
    pub fn x25519_step(ws: &mut [u64; 76], swap: u64) {
        crate::fe64::ladder_step(ws, swap & 1)
    }
    /// Signing's step: two mixed additions, interleaved.
    #[inline(always)]
    pub fn ed25519_madd_ext2(ws: &mut Ws2) {
        edwards::madd_ext2(ws);
    }
    /// Signing's doublings and final addition.
    #[inline(always)]
    pub fn ed25519_dbl_nadd(ws: &mut Ws) {
        edwards::dbl(ws);
        edwards::to_proj(ws);
        edwards::dbl(ws);
        edwards::to_ext(ws);
        edwards::nadd(ws);
        edwards::to_ext(ws);
    }
}

// x86-64 only: the MULX/ADX field sequences and the point formulas built on
// them, which the probes above do not reach, since without `std` there is no
// run-time detection and the baseline sequence is chosen. `unsafe`: they
// require BMI2 and ADX. The probes only compile them; nothing runs them.
#[cfg(target_arch = "x86_64")]
pub use crate::nist::p256_x86::{mul_adx as fp_mul_adx, square_adx as fp_square_adx};
#[cfg(target_arch = "x86_64")]
pub use crate::nist::p256_x86_point::{
    add_adx as point_add_adx, add_affine_adx as point_add_affine_adx,
    double_adx as point_double_adx,
};
// P-384's, likewise: the two rings' multiplications and the point formulas.
#[cfg(target_arch = "x86_64")]
pub use crate::nist::mont_x86::{mul_p384_n as p384_fn_mul_adx, mul_p384_p as p384_fp_mul_adx};
#[cfg(target_arch = "x86_64")]
pub use crate::nist::p384_x86_point::{
    add_adx as p384_point_add_adx, add_affine_adx as p384_point_add_affine_adx,
    double_adx as p384_point_double_adx,
};
