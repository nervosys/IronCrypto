//! What X25519 and Ed25519 need of GF(2^255 - 19), as a trait.
//!
//! Two representations implement it: `field::Fe` -- five 51-bit limbs, or ten
//! 32-bit ones on 32-bit RISC-V and under `--cfg ic_limb32` -- which runs
//! everywhere, and `fe64::Fe64`, four 64-bit limbs on `MULX`/`ADX`, which runs
//! on x86-64 CPUs that have those instructions. The curve code is written once
//! against this trait and instantiated for each; [`dispatch!`] picks one per
//! scalar multiplication, on the CPU and never on data.
//!
//! The addition chains for inversion and the square-root exponent are here
//! rather than in each field, so the two cannot drift apart.

use ic_core::ct::Choice;

/// Call the generic function `f::<F>(args..)` with the fastest [`Field`] this
/// CPU runs: `Fe64` where [`crate::fe64::available`] says so, the portable
/// field otherwise.
///
/// The question is asked once per call, so once per scalar multiplication,
/// and depends only on the CPU. A function instantiated for `Fe64` must be
/// reached only through here.
macro_rules! dispatch {
    ($f:ident ( $($arg:expr),* $(,)? )) => {{
        #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
        {
            if crate::fe64::available() {
                $f::<crate::fe64::Fe64>($($arg),*)
            } else {
                $f::<crate::field::Fe>($($arg),*)
            }
        }
        #[cfg(not(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable)))))]
        {
            $f::<crate::field::Fe>($($arg),*)
        }
    }};
}
pub(crate) use dispatch;

/// The name of the field [`dispatch!`] selects on this machine, for tests that
/// must know which path they exercised.
#[cfg(test)]
pub(crate) fn selected() -> &'static str {
    fn name<F: Field>() -> &'static str {
        core::any::type_name::<F>()
    }
    dispatch!(name())
}

/// A field element modulo 2^255 - 19.
///
/// Every operation is constant time in the values of its operands.
pub(crate) trait Field: Copy {
    /// The additive identity.
    const ZERO: Self;
    /// The multiplicative identity.
    const ONE: Self;

    /// A value given as five 51-bit limbs, each below 2^52.
    fn from_limbs51(l: [u64; 5]) -> Self;
    /// Decode 32 little-endian bytes, ignoring the top bit.
    fn from_bytes(bytes: &[u8; 32]) -> Self;
    /// Encode as 32 little-endian bytes, fully reduced.
    fn to_bytes(self) -> [u8; 32];

    /// `self + other`.
    fn add(&self, other: &Self) -> Self;
    /// `self - other`.
    fn sub(&self, other: &Self) -> Self;
    /// `self * other`.
    fn mul(&self, other: &Self) -> Self;
    /// `self^2`.
    fn square(&self) -> Self;
    /// `self * 121666`, the Montgomery ladder constant.
    fn mul121666(&self) -> Self;
    /// `a = b` when `choice` is true.
    fn cmov(a: &mut Self, b: &Self, choice: Choice);

    /// `a = b` when the secret `bit`, 0 or 1, is 1.
    ///
    /// [`Field::cmov`] for a bit held as an integer, which is what a table
    /// scan has. A field may override it with a cheaper barrier than
    /// [`Choice`]'s. Only the `std` tables scan.
    #[cfg(feature = "std")]
    #[inline]
    fn cmov_bit(a: &mut Self, b: &Self, bit: u64) {
        Self::cmov(a, b, Choice::from_u8(bit as u8))
    }

    /// `b` when the secret `bit`, 0 or 1, is 1, and `a` when it is 0.
    #[inline]
    fn select_bit(a: &Self, b: &Self, bit: u64) -> Self {
        let mut r = *a;
        Self::cmov(&mut r, b, Choice::from_u8(bit as u8));
        r
    }

    /// `-self`.
    #[inline]
    fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// `self^(2^n)`.
    #[inline]
    fn square_n(&self, n: usize) -> Self {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// `self^(2^250 - 1)` and `self^11`, the shared prefix of both chains.
    #[inline]
    fn pow_2_250_1(&self) -> (Self, Self) {
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
        (z2_200_0.square_n(50).mul(&z2_50_0), z11)
    }

    /// Multiplicative inverse, `self^(p-2)`, with `invert(0) == 0`: 254
    /// squarings and 11 multiplications.
    #[inline]
    fn invert(&self) -> Self {
        let (z2_250_0, z11) = self.pow_2_250_1();
        z2_250_0.square_n(5).mul(&z11)
    }

    /// `self^((p-5)/8)`, the exponent used to take square roots.
    #[inline]
    fn pow22523(&self) -> Self {
        let (z2_250_0, _) = self.pow_2_250_1();
        z2_250_0.square_n(2).mul(self)
    }

    /// [`Field::pow22523`] of two values, the chains interleaved: each step
    /// of one has the other's to overlap with, which a single dependency
    /// chain lacks.
    fn pow22523_pair(a: &Self, b: &Self) -> (Self, Self) {
        let sq = |x: &Self, y: &Self, n: usize| {
            let (mut x, mut y) = (*x, *y);
            for _ in 0..n {
                x = x.square();
                y = y.square();
            }
            (x, y)
        };
        let m = |x: (Self, Self), y: (Self, Self)| (x.0.mul(&y.0), x.1.mul(&y.1));
        let z1 = (*a, *b);
        let z2 = sq(&z1.0, &z1.1, 1);
        let t = sq(&z2.0, &z2.1, 2);
        let z9 = m(t, z1);
        let z11 = m(z9, z2);
        let t = sq(&z11.0, &z11.1, 1);
        let z2_5_0 = m(t, z9);
        let t = sq(&z2_5_0.0, &z2_5_0.1, 5);
        let z2_10_0 = m(t, z2_5_0);
        let t = sq(&z2_10_0.0, &z2_10_0.1, 10);
        let z2_20_0 = m(t, z2_10_0);
        let t = sq(&z2_20_0.0, &z2_20_0.1, 20);
        let z2_40_0 = m(t, z2_20_0);
        let t = sq(&z2_40_0.0, &z2_40_0.1, 10);
        let z2_50_0 = m(t, z2_10_0);
        let t = sq(&z2_50_0.0, &z2_50_0.1, 50);
        let z2_100_0 = m(t, z2_50_0);
        let t = sq(&z2_100_0.0, &z2_100_0.1, 100);
        let z2_200_0 = m(t, z2_100_0);
        let t = sq(&z2_200_0.0, &z2_200_0.1, 50);
        let z2_250_0 = m(t, z2_50_0);
        let t = sq(&z2_250_0.0, &z2_250_0.1, 2);
        m(t, z1)
    }

    /// Whether `self` is zero in the field.
    #[inline]
    fn is_zero(&self) -> Choice {
        ic_core::ct::is_zero(&self.to_bytes())
    }

    /// Whether `self == other` in the field.
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ic_core::ct::eq(&self.to_bytes(), &other.to_bytes())
    }

    /// The low bit of the canonical encoding: Edwards compression's sign.
    #[inline]
    fn is_negative(&self) -> Choice {
        Choice::from_u8(self.to_bytes()[0] & 1)
    }
}

/// The portable field, whichever of the two limb layouts this build uses.
impl Field for crate::field::Fe {
    const ZERO: Self = crate::field::Fe::ZERO;
    const ONE: Self = crate::field::Fe::ONE;

    #[inline]
    fn from_limbs51(l: [u64; 5]) -> Self {
        crate::field::Fe::from_limbs51(l)
    }
    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        crate::field::Fe::from_bytes(bytes)
    }
    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        crate::field::Fe::to_bytes(self)
    }
    #[inline]
    fn add(&self, other: &Self) -> Self {
        crate::field::Fe::add(self, other)
    }
    #[inline]
    fn sub(&self, other: &Self) -> Self {
        crate::field::Fe::sub(self, other)
    }
    #[inline]
    fn mul(&self, other: &Self) -> Self {
        crate::field::Fe::mul(self, other)
    }
    #[inline]
    fn square(&self) -> Self {
        crate::field::Fe::square(self)
    }
    #[inline]
    fn mul121666(&self) -> Self {
        crate::field::Fe::mul121666(self)
    }
    #[inline]
    fn cmov(a: &mut Self, b: &Self, choice: Choice) {
        crate::field::Fe::cmov(a, b, choice)
    }
    #[inline]
    fn neg(&self) -> Self {
        crate::field::Fe::neg(self)
    }
    // The portable field's own chains and encodings rather than the trait's,
    // so that the code the RFC vectors have always validated is still what
    // runs on it.
    #[inline]
    fn square_n(&self, n: usize) -> Self {
        crate::field::Fe::square_n(self, n)
    }
    #[inline]
    fn invert(&self) -> Self {
        crate::field::Fe::invert(self)
    }
    #[inline]
    fn pow22523(&self) -> Self {
        crate::field::Fe::pow22523(self)
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        crate::field::Fe::is_zero(self)
    }
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        crate::field::Fe::ct_eq(self, other)
    }
    #[inline]
    fn is_negative(&self) -> Choice {
        crate::field::Fe::is_negative(self)
    }
}

/// The four-limb field. Only reachable through [`dispatch!`], which has
/// checked [`crate::fe64::available`].
#[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
impl Field for crate::fe64::Fe64 {
    const ZERO: Self = crate::fe64::Fe64::ZERO;
    const ONE: Self = crate::fe64::Fe64::ONE;

    #[inline]
    fn from_limbs51(l: [u64; 5]) -> Self {
        crate::fe64::Fe64::from_limbs51(l)
    }
    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        crate::fe64::Fe64::from_bytes(bytes)
    }
    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        crate::fe64::Fe64::to_bytes(self)
    }
    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        crate::fe64::Fe64::add(self, other)
    }
    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        crate::fe64::Fe64::sub(self, other)
    }
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        crate::fe64::Fe64::mul(self, other)
    }
    #[inline(always)]
    fn square(&self) -> Self {
        crate::fe64::Fe64::square(self)
    }
    #[inline(always)]
    fn mul121666(&self) -> Self {
        crate::fe64::Fe64::mul121666(self)
    }
    #[inline(always)]
    fn cmov(a: &mut Self, b: &Self, choice: Choice) {
        crate::fe64::Fe64::cmov(a, b, choice)
    }
    #[inline(always)]
    fn select_bit(a: &Self, b: &Self, bit: u64) -> Self {
        crate::fe64::Fe64::select_mask(a, b, crate::fe64::mask(bit))
    }
    #[cfg(feature = "std")]
    #[inline(always)]
    fn cmov_bit(a: &mut Self, b: &Self, bit: u64) {
        *a = crate::fe64::Fe64::select_mask(a, b, crate::fe64::mask(bit));
    }
    #[inline(always)]
    fn neg(&self) -> Self {
        crate::fe64::Fe64::neg(self)
    }
    /// Divsteps rather than the addition chain: see `fe64/inv.rs`.
    #[inline]
    fn invert(&self) -> Self {
        crate::fe64::Fe64::invert(self)
    }
}
