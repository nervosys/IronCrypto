//! RFC 8032 Ed25519 signatures.
//!
//! Points use extended twisted Edwards coordinates `(X : Y : Z : T)` with
//! `a = -1`. Because `d` is a non-square in GF(2^255-19), the
//! `add-2008-hwcd-3` formula is *complete*: it is correct for every input pair,
//! including doubling and the identity. That is what lets scalar multiplication
//! be a single branch-free loop with no exceptional cases to special-case, and
//! no timing signal from the shape of the scalar.

use crate::field::Fe;
use crate::field_ops::{dispatch, Field};
use crate::scalar;
use ic_core::ct::Choice;

// The precomputed basepoint table. See the module for why it is `std` only.
#[cfg(feature = "std")]
mod basepoint_table;
// The four-limb field's basepoint and double-scalar multiplications, one
// assembly block per group operation; see the module.
#[cfg(all(
    feature = "std",
    target_arch = "x86_64",
    not(any(ic_limb32, ic_ec_portable))
))]
mod fast;
// The same, four lanes at a time on AVX-512 IFMA; see the module.
#[cfg(all(
    feature = "std",
    target_arch = "x86_64",
    not(any(ic_limb32, ic_ec_portable))
))]
mod vector;
use ic_core::traits::internal::Digest;
use ic_core::traits::{Algorithm, SelfTest, SignatureScheme};
use ic_core::{ensure, Result, Zeroize};
use ic_hash::Sha512;

#[cfg(not(feature = "std"))]
pub(crate) use self::EdField as Curve;
/// What a field must provide for the operations on whole scalars here:
/// [`EdField`], and under `std` the precomputed basepoint tables too.
#[cfg(feature = "std")]
pub(crate) use basepoint_table::TableField as Curve;

/// The compressed encoding of the Ed25519 base point.
#[cfg(test)]
const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The curve constant `d = -121665/121666`, as 51-bit limbs.
const D_LIMBS: [u64; 5] = [
    929_955_233_495_203,
    466_365_720_129_213,
    1_662_059_464_998_953,
    2_033_849_074_728_123,
    1_442_794_654_840_575,
];

/// `2*d`, used directly by the addition formula.
const D2_LIMBS: [u64; 5] = [
    1_859_910_466_990_425,
    932_731_440_258_426,
    1_072_319_116_312_658,
    1_815_898_335_770_999,
    633_789_495_995_903,
];

/// A square root of -1 in GF(2^255-19), needed for point decompression.
const SQRT_M1_LIMBS: [u64; 5] = [
    1_718_705_420_411_056,
    234_908_883_556_509,
    2_233_514_472_574_048,
    2_117_202_627_021_982,
    765_476_049_583_133,
];

/// A field the curve arithmetic runs on: [`Field`] and the curve's constants
/// in its representation.
///
/// Two implement it, the portable field and, on x86-64 with BMI2 and ADX, the
/// four-limb one; every operation below is written once against this and
/// instantiated for each, and [`dispatch!`] picks one per scalar
/// multiplication.
pub(crate) trait EdField: Field + core::fmt::Debug + 'static {
    /// `d`.
    const D: Self;
    /// `2d`.
    const D2: Self;
    /// `sqrt(-1)`.
    const SQRT_M1: Self;

    /// The same element in the portable field.
    #[cfg(all(feature = "std", any(test, feature = "bench-internals")))]
    fn to_portable(self) -> Fe {
        Fe::from_bytes(&self.to_bytes())
    }

    /// The same element in this field.
    #[cfg(all(feature = "std", any(test, feature = "bench-internals")))]
    fn from_portable(x: &Fe) -> Self {
        Self::from_bytes(&x.to_bytes())
    }
}

impl EdField for Fe {
    const D: Fe = Fe::from_limbs51(D_LIMBS);
    const D2: Fe = Fe::from_limbs51(D2_LIMBS);
    const SQRT_M1: Fe = Fe::from_limbs51(SQRT_M1_LIMBS);

    #[cfg(all(feature = "std", any(test, feature = "bench-internals")))]
    fn to_portable(self) -> Fe {
        self
    }

    #[cfg(all(feature = "std", any(test, feature = "bench-internals")))]
    fn from_portable(x: &Fe) -> Self {
        *x
    }
}

#[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
impl EdField for crate::fe64::Fe64 {
    const D: Self = crate::fe64::Fe64::from_limbs51(D_LIMBS);
    const D2: Self = crate::fe64::Fe64::from_limbs51(D2_LIMBS);
    const SQRT_M1: Self = crate::fe64::Fe64::from_limbs51(SQRT_M1_LIMBS);
}

/// A point on the curve, in extended twisted Edwards coordinates.
///
/// The public face of `Ext` on the portable field. The signing and
/// verification paths do not go through it: they run on whichever field the
/// CPU selects, and this is for callers who want the group itself.
#[derive(Clone, Copy, Debug)]
pub struct Point(Ext<Fe>);

impl Point {
    /// The neutral element `(0, 1)`.
    pub const IDENTITY: Point = Point(Ext::IDENTITY);

    /// The complete `add-2008-hwcd-3` group law for `a = -1`.
    pub fn add(&self, other: &Point) -> Point {
        Point(self.0.add(&other.0))
    }

    /// Point doubling, `dbl-2008-hwcd` for `a = -1`.
    pub fn double(&self) -> Point {
        Point(self.0.double())
    }

    /// Scalar multiplication, constant-time in the scalar.
    pub fn mul_scalar(&self, s: &[u8; 32]) -> Point {
        Point(self.0.mul_scalar(s))
    }

    /// Compress to the 32-byte RFC 8032 encoding.
    pub fn compress(&self) -> [u8; 32] {
        self.0.compress()
    }

    /// Decompress a 32-byte encoding, rejecting non-curve points and
    /// non-canonical encodings.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        Ext::decompress(bytes).map(Point)
    }
}

/// A point in extended twisted Edwards coordinates, on the field `F`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ext<F> {
    x: F,
    y: F,
    z: F,
    t: F,
}

/// A point part-way through a group operation: `(X : Y : Z : T)` standing for
/// the affine point `(X/Z, Y/T)`.
///
/// Both the doubling and the addition formulas naturally produce this form --
/// it is what they compute before the four multiplications that put the result
/// back into extended coordinates. Keeping it is what makes a chain of
/// doublings cheaper: a doubling reads only `X`, `Y` and `Z`, so on the way to
/// another doubling the `T` those four multiplications would produce is never
/// read, and three of them suffice instead of four.
#[derive(Clone, Copy)]
pub(crate) struct Completed<F> {
    x: F,
    y: F,
    z: F,
    t: F,
}

/// `(X : Y : Z)`, standing for `(X/Z, Y/Z)`. No `T`.
///
/// What a doubling needs and all it needs.
#[derive(Clone, Copy)]
pub(crate) struct Projective<F> {
    x: F,
    y: F,
    z: F,
}

/// A point rearranged for addition: `(Y+X, Y-X, Z, 2d·T)`.
///
/// The addition formula wants those four quantities and nothing else, so a
/// point that will be added many times -- every entry of every table here --
/// stores them instead of `(X, Y, Z, T)`. That turns an addition from nine
/// multiplications into four: the two sums and differences are already formed,
/// and `2d·T` has already been scaled.
#[derive(Clone, Copy)]
pub(crate) struct Niels<F> {
    ypx: F,
    ymx: F,
    z: F,
    t2d: F,
}

/// A point with `Z = 1`, rearranged for addition: `(y+x, y-x, 2d·x·y)`.
///
/// [`Niels`] without the `Z`, which removes the one multiplication that used
/// it. Worth the field inversion it costs to build, for a table entry that
/// will be added sixty-four times per signature and never changes.
#[cfg(feature = "std")]
#[derive(Clone, Copy)]
pub(crate) struct AffineNiels<F> {
    ypx: F,
    ymx: F,
    t2d: F,
}

/// The constant-time table operations the windowed multiplication needs. They
/// mirror [`AffineNiels`]'s, for a table built per call and so never worth the
/// inversions that would make it affine.
#[cfg(any(not(feature = "std"), test))]
impl<F: EdField> Niels<F> {
    /// The neutral element: `Y + X = Y - X = Z = 1`, `2d·T = 0`.
    const IDENTITY: Self = Niels {
        ypx: F::ONE,
        ymx: F::ONE,
        z: F::ONE,
        t2d: F::ZERO,
    };

    /// Negation swaps the sums and differences and negates `2d·T`; `Z` is
    /// unchanged.
    fn conditional_negate(&mut self, choice: Choice) {
        let swapped_p = self.ymx;
        let swapped_m = self.ypx;
        let nt = self.t2d.neg();
        F::cmov(&mut self.ypx, &swapped_p, choice);
        F::cmov(&mut self.ymx, &swapped_m, choice);
        F::cmov(&mut self.t2d, &nt, choice);
    }

    fn cmov(&mut self, other: &Niels<F>, choice: Choice) {
        F::cmov(&mut self.ypx, &other.ypx, choice);
        F::cmov(&mut self.ymx, &other.ymx, choice);
        F::cmov(&mut self.z, &other.z, choice);
        F::cmov(&mut self.t2d, &other.t2d, choice);
    }
}

#[cfg(feature = "std")]
impl<F: EdField> AffineNiels<F> {
    /// The neutral element: `x = 0`, `y = 1`.
    pub(crate) const IDENTITY: Self = AffineNiels {
        ypx: F::ONE,
        ymx: F::ONE,
        t2d: F::ZERO,
    };

    /// Negation swaps the sums and differences and negates `2d·x·y`, which is
    /// what `-(x, y) = (-x, y)` comes to in this form.
    ///
    /// `bit` is secret, 0 or 1; it becomes a mask only inside the field's
    /// `cmov_bit`, behind that field's barrier.
    pub(crate) fn conditional_negate(&mut self, bit: u64) {
        let swapped_p = self.ymx;
        let swapped_m = self.ypx;
        let nt = self.t2d.neg();
        F::cmov_bit(&mut self.ypx, &swapped_p, bit);
        F::cmov_bit(&mut self.ymx, &swapped_m, bit);
        F::cmov_bit(&mut self.t2d, &nt, bit);
    }

    /// `self = other` when the secret `bit`, 0 or 1, is 1.
    pub(crate) fn cmov(&mut self, other: &AffineNiels<F>, bit: u64) {
        F::cmov_bit(&mut self.ypx, &other.ypx, bit);
        F::cmov_bit(&mut self.ymx, &other.ymx, bit);
        F::cmov_bit(&mut self.t2d, &other.t2d, bit);
    }
}

impl<F: EdField> Completed<F> {
    /// Drop to `(X : Y : Z)`, which is three multiplications.
    fn to_projective(self) -> Projective<F> {
        Projective {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
        }
    }

    /// Back to extended coordinates, which is four.
    ///
    /// Only needed before an addition, since that is the only operation that
    /// reads `T`.
    fn to_extended(self) -> Ext<F> {
        Ext {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: self.x.mul(&self.y),
        }
    }
}

impl<F: EdField> Projective<F> {
    /// Recover extended coordinates from projective ones.
    ///
    /// `(X : Y : Z)` stands for `(X/Z, Y/Z)`, and extended coordinates want
    /// `T` with `X*Y = T*Z`, so `T = X*Y/Z`. Only needed once, at the end.
    fn to_extended_from_projective(self) -> Ext<F> {
        // Four multiplications, not an inversion. `(X : Y : Z)` stands for
        // `(X/Z, Y/Z)`, and extended coordinates want `T` with `X*Y = T*Z`;
        // scaling every coordinate by `Z` gives `(XZ : YZ : Z^2 : XY)`, which
        // satisfies that directly. Dividing through by `Z` instead would be an
        // exponentiation -- about two hundred and fifty squarings -- to reach
        // the same point in a representation nothing here needs.
        Ext {
            x: self.x.mul(&self.z),
            y: self.y.mul(&self.z),
            z: self.z.square(),
            t: self.x.mul(&self.y),
        }
    }

    /// Double and stay projective, without writing the completed form out.
    ///
    /// The same arithmetic as `double()` followed by
    /// [`Completed::to_projective`], with the intermediate kept in locals. A
    /// `Completed` is four field elements, 160 bytes, and in a chain of
    /// doublings it exists only to be consumed by the very next statement;
    /// spilling and reloading it is pure traffic. This is the path taken at
    /// every position where the recoding has nothing to add, which is most of
    /// them.
    fn double_projective(self) -> Projective<F> {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz2 = {
            let t = self.z.square();
            t.add(&t)
        };
        let xy_sq = self.x.add(&self.y).square();
        let yy_plus_xx = yy.add(&xx);
        let yy_minus_xx = yy.sub(&xx);

        let cx = xy_sq.sub(&yy_plus_xx);
        let cy = yy_plus_xx;
        let cz = yy_minus_xx;
        let ct = zz2.sub(&yy_minus_xx);

        Projective {
            x: cx.mul(&ct),
            y: cy.mul(&cz),
            z: cz.mul(&ct),
        }
    }

    /// `dbl-2008-hwcd` for `a = -1`, stopping at the completed form.
    ///
    /// Four squarings and no multiplications at all: every multiplication in a
    /// doubling belongs to the conversion out of the completed form, which is
    /// why it is worth not doing that conversion in full.
    fn double(&self) -> Completed<F> {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz2 = {
            let t = self.z.square();
            t.add(&t)
        };
        let xy_sq = self.x.add(&self.y).square();
        let yy_plus_xx = yy.add(&xx);
        let yy_minus_xx = yy.sub(&xx);
        Completed {
            x: xy_sq.sub(&yy_plus_xx),
            y: yy_plus_xx,
            z: yy_minus_xx,
            t: zz2.sub(&yy_minus_xx),
        }
    }
}

impl<F: EdField> Ext<F> {
    /// The neutral element `(0, 1)`.
    /// `(x, y)` with `Z = 1`.
    pub(crate) fn from_affine(x: F, y: F) -> Ext<F> {
        Ext {
            x,
            y,
            z: F::ONE,
            t: x.mul(&y),
        }
    }

    /// The same point on another field.
    #[cfg(all(feature = "std", any(test, feature = "bench-internals")))]
    pub(crate) fn convert<G: EdField>(&self) -> Ext<G> {
        let c = |v: &F| G::from_portable(&v.to_portable());
        Ext {
            x: c(&self.x),
            y: c(&self.y),
            z: c(&self.z),
            t: c(&self.t),
        }
    }

    pub const IDENTITY: Self = Ext {
        x: F::ZERO,
        y: F::ONE,
        z: F::ONE,
        t: F::ZERO,
    };

    /// The complete `add-2008-hwcd-3` group law for `a = -1`.
    pub fn add(&self, other: &Ext<F>) -> Ext<F> {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&F::D2).mul(&other.t);
        let d = self.z.mul(&other.z);
        let d = d.add(&d);

        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        Ext {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Point doubling, `dbl-2008-hwcd` for `a = -1`.
    ///
    /// Adding a point to itself works and was what this did, but the general
    /// addition costs nine multiplications and needs both operands' `T`. The
    /// dedicated formula is four multiplications and four squarings, and does
    /// not read `T` at all -- doubling is a function of `X`, `Y` and `Z` alone.
    ///
    /// Worth the separate formula because scalar multiplication is doublings
    /// almost entirely: the non-adjacent form leaves about forty additions
    /// against two hundred and fifty-six doublings.
    pub fn double(&self) -> Ext<F> {
        let aa = self.x.square();
        let bb = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        // a = -1, so D = a*A = -A.
        let d = aa.neg();
        // E = (X+Y)^2 - A - B, which is 2*X*Y without a multiplication.
        let xy = self.x.add(&self.y);
        let e = xy.square().sub(&aa).sub(&bb);
        let g = d.add(&bb);
        let f = g.sub(&c);
        let h = d.sub(&bb);

        Ext {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Drop `T`, which a doubling does not read.
    fn to_projective(self) -> Projective<F> {
        Projective {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    /// Rearrange for repeated addition. See [`Niels`].
    fn to_niels(self) -> Niels<F> {
        Niels {
            ypx: self.y.add(&self.x),
            ymx: self.y.sub(&self.x),
            z: self.z,
            t2d: self.t.mul(&F::D2),
        }
    }

    /// `self + other`, in four multiplications, stopping at the completed form.
    ///
    /// The same `add-2008-hwcd-3` group law [`Point::add`] uses. It costs four
    /// rather than nine because `other` arrives with its sums, differences and
    /// `2d·T` already formed, and because the result is left completed rather
    /// than converted back.
    fn add_niels(&self, other: &Niels<F>) -> Completed<F> {
        let pp = self.y.add(&self.x).mul(&other.ypx);
        let mm = self.y.sub(&self.x).mul(&other.ymx);
        let tt2d = self.t.mul(&other.t2d);
        let zz = self.z.mul(&other.z);
        let zz2 = zz.add(&zz);
        Completed {
            x: pp.sub(&mm),
            y: pp.add(&mm),
            z: zz2.add(&tt2d),
            t: zz2.sub(&tt2d),
        }
    }

    /// `self - other`.
    ///
    /// Negating a Niels point swaps its sums and differences and negates
    /// `2d·T`, which is cheaper than negating the point it came from and
    /// rebuilding it.
    fn sub_niels(&self, other: &Niels<F>) -> Completed<F> {
        let pp = self.y.add(&self.x).mul(&other.ymx);
        let mm = self.y.sub(&self.x).mul(&other.ypx);
        let tt2d = self.t.mul(&other.t2d);
        let zz = self.z.mul(&other.z);
        let zz2 = zz.add(&zz);
        Completed {
            x: pp.sub(&mm),
            y: pp.add(&mm),
            z: zz2.sub(&tt2d),
            t: zz2.add(&tt2d),
        }
    }

    /// Rearrange for repeated addition, with `Z` divided out. See
    /// [`AffineNiels`].
    ///
    /// Costs a field inversion, which is why it is done when a table is built
    /// and never on a hot path.
    #[cfg(feature = "std")]
    pub(crate) fn to_affine_niels(self) -> AffineNiels<F> {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        AffineNiels {
            ypx: y.add(&x),
            ymx: y.sub(&x),
            t2d: x.mul(&y).mul(&F::D2),
        }
    }

    /// `self + other`, in three multiplications.
    ///
    /// One fewer than [`Point::add_niels`]: `other` has `Z = 1`, so the
    /// product of the two `Z`s is just this one's, doubled.
    #[cfg(feature = "std")]
    pub(crate) fn add_affine_niels(&self, other: &AffineNiels<F>) -> Completed<F> {
        let pp = self.y.add(&self.x).mul(&other.ypx);
        let mm = self.y.sub(&self.x).mul(&other.ymx);
        let tt2d = self.t.mul(&other.t2d);
        let zz2 = self.z.add(&self.z);
        Completed {
            x: pp.sub(&mm),
            y: pp.add(&mm),
            z: zz2.add(&tt2d),
            t: zz2.sub(&tt2d),
        }
    }

    /// `self - other`, for an affine Niels point.
    ///
    /// Negating one of these swaps its sums and differences and negates
    /// `2d·x·y`, so the subtraction is the addition with two operands
    /// exchanged and one sign flipped. Doing it here rather than by negating a
    /// copy of the table entry avoids copying it at all -- an entry is three
    /// field elements, and the variable-time path has no reason to touch it
    /// with conditional moves.
    #[cfg(feature = "std")]
    pub(crate) fn sub_affine_niels(&self, other: &AffineNiels<F>) -> Completed<F> {
        let pp = self.y.add(&self.x).mul(&other.ymx);
        let mm = self.y.sub(&self.x).mul(&other.ypx);
        let tt2d = self.t.mul(&other.t2d);
        let zz2 = self.z.add(&self.z);
        Completed {
            x: pp.sub(&mm),
            y: pp.add(&mm),
            z: zz2.sub(&tt2d),
            t: zz2.add(&tt2d),
        }
    }

    /// Constant-time conditional move.
    fn cmov(&mut self, other: &Ext<F>, choice: Choice) {
        F::cmov(&mut self.x, &other.x, choice);
        F::cmov(&mut self.y, &other.y, choice);
        F::cmov(&mut self.z, &other.z, choice);
        F::cmov(&mut self.t, &other.t, choice);
    }

    /// Scalar multiplication, constant-time in the scalar.
    ///
    /// Every iteration performs a doubling *and* an addition, selecting between
    /// the two results with a conditional move, so the instruction trace is
    /// identical for every scalar.
    pub fn mul_scalar(&self, s: &[u8; 32]) -> Ext<F> {
        let mut acc = Ext::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            let sum = acc.add(self);
            let bit = Choice::from_u8((s[i / 8] >> (i % 8)) & 1);
            acc.cmov(&sum, bit);
        }
        acc
    }

    /// Negate: `-(x, y, z, t)` is `(-x, y, z, -t)`.
    fn negate(&self) -> Ext<F> {
        Ext {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Whether two points are the same, without leaving projective space.
    ///
    /// `(X : Y : Z)` stands for the affine point `(X/Z, Y/Z)`, so two are equal
    /// exactly when `X1*Z2 == X2*Z1` and `Y1*Z2 == Y2*Z1`. That is four
    /// multiplications.
    ///
    /// The obvious alternative is to compress both and compare the bytes, and
    /// that is what verification used to do -- but compression divides by `Z`,
    /// and a division here is an exponentiation: roughly two hundred and fifty
    /// squarings each, five hundred to answer a question four multiplications
    /// settle.
    ///
    /// `to_bytes` is used only to canonicalise the two sides before comparing,
    /// which costs a carry chain and no inversion.
    /// Whether eight times this point is the identity: whether it lies in the
    /// small subgroup the cofactor admits. Variable time; for public points.
    fn has_small_order(&self) -> bool {
        self.double()
            .double()
            .double()
            .eq_projective(&Ext::<F>::IDENTITY)
    }

    fn eq_projective(&self, other: &Ext<F>) -> bool {
        self.x.mul(&other.z).to_bytes() == other.x.mul(&self.z).to_bytes()
            && self.y.mul(&other.z).to_bytes() == other.y.mul(&self.z).to_bytes()
    }

    /// Compress to the 32-byte RFC 8032 encoding.
    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut out = y.to_bytes();
        // The sign of x rides in the top bit.
        out[31] |= x.is_negative().unwrap_u8() << 7;
        out
    }

    /// Decompress a 32-byte encoding, rejecting non-curve points and
    /// non-canonical encodings.
    ///
    /// RFC 8032 section 5.1.3: a y field of p or more fails to decode. Read
    /// modulo p it would name a curve point, under an encoding no correct
    /// encoder produces; nineteen such aliases exist, and accepting them makes
    /// one point answer to two encodings.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Ext<F>> {
        let start = Decompression::<F>::start(bytes)?;
        let pow = start.uv7.pow22523();
        start.finish(&pow)
    }

    /// Two decompressions, their exponentiations run side by side.
    ///
    /// The exponentiation is 252 squarings in a single dependency chain, and
    /// two of them interleaved cost little more than one: each squaring has
    /// the other chain's to overlap with. One-shot verification decompresses
    /// both the public key and R, and this is how.
    fn decompress_pair(a: &[u8; 32], b: &[u8; 32]) -> (Option<Ext<F>>, Option<Ext<F>>) {
        match (Decompression::<F>::start(a), Decompression::<F>::start(b)) {
            (Some(sa), Some(sb)) => {
                let (pa, pb) = F::pow22523_pair(&sa.uv7, &sb.uv7);
                (sa.finish(&pa), sb.finish(&pb))
            }
            (sa, sb) => (
                sa.and_then(|s| s.finish(&s.uv7.pow22523())),
                sb.and_then(|s| s.finish(&s.uv7.pow22523())),
            ),
        }
    }
}

/// A decompression up to its exponentiation: what comes before and after
/// `(u v^7)^((p-5)/8)`, separated so two can share it.
struct Decompression<F> {
    y: F,
    u: F,
    v: F,
    uv3: F,
    uv7: F,
    sign: Choice,
}

impl<F: EdField> Decompression<F> {
    fn start(bytes: &[u8; 32]) -> Option<Self> {
        let sign = Choice::from_u8(bytes[31] >> 7);
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = F::from_bytes(&y_bytes);
        // The encoding is public, so comparing it in variable time is fine.
        if y.to_bytes() != y_bytes {
            return None;
        }

        // Solve x^2 = (y^2 - 1) / (d*y^2 + 1).
        let y2 = y.square();
        let u = y2.sub(&F::ONE);
        let v = y2.mul(&F::D).add(&F::ONE);

        // x = u*v^3 * (u*v^7)^((p-5)/8)
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        Some(Self {
            y,
            u,
            v,
            uv3: u.mul(&v3),
            uv7: u.mul(&v7),
            sign,
        })
    }

    /// The rest, given `pow = (u v^7)^((p-5)/8)`.
    fn finish(&self, pow: &F) -> Option<Ext<F>> {
        let (y, u, v, sign) = (self.y, self.u, self.v, self.sign);
        let mut x = self.uv3.mul(pow);

        let check = v.mul(&x.square());
        let correct = check.ct_eq(&u);
        let flipped = check.ct_eq(&u.neg());
        if !bool::from(correct.or(flipped)) {
            // No square root exists: the encoding is not a curve point.
            return None;
        }
        // When only the flipped case matched, multiply by sqrt(-1).
        let alt = x.mul(&F::SQRT_M1);
        F::cmov(&mut x, &alt, flipped.and(correct.not()));

        // x = 0 with a set sign bit is the one non-canonical encoding.
        if bool::from(x.is_zero()) && bool::from(sign) {
            return None;
        }
        // Match the requested sign.
        let neg = x.neg();
        let wrong_sign = Choice::from_u8(x.is_negative().unwrap_u8() ^ sign.unwrap_u8());
        F::cmov(&mut x, &neg, wrong_sign);

        Some(Ext {
            x,
            y,
            z: F::ONE,
            t: x.mul(&y),
        })
    }
}

/// Fill the basepoint tables now, for the field this CPU selects; see
/// [`crate::prepare`].
#[cfg(feature = "std")]
pub(crate) fn prepare_tables() {
    fn prepare<F: Curve>() {
        basepoint_table::prepare::<F>();
    }
    dispatch!(prepare())
}

/// `scalar * B`, through the precomputed table where there is one.
///
/// Every basepoint multiplication in this module goes through here rather than
/// calling `mul_scalar` on the basepoint directly, so the two paths cannot
/// drift apart and a caller cannot accidentally take the slow one.
fn mul_basepoint<F: Curve>(scalar: &[u8; 32]) -> Ext<F> {
    #[cfg(feature = "std")]
    {
        basepoint_table::mul::<F>(scalar)
    }
    #[cfg(not(feature = "std"))]
    {
        mul_scalar_windowed(&basepoint::<F>(), scalar)
    }
}

/// `scalar * B`, compressed, on the field this CPU selects: what signing and
/// key derivation want, and the one place they choose the field.
fn mul_basepoint_compressed(scalar: &[u8; 32]) -> [u8; 32] {
    fn on<F: Curve>(scalar: &[u8; 32]) -> [u8; 32] {
        mul_basepoint::<F>(scalar).compress()
    }
    dispatch!(on(scalar))
}

/// `[k]A + [s]B`, in one pass, variable time in both scalars.
///
/// Verification needs two scalar multiplications and then compares the
/// results. Done separately that is two independent runs of doublings -- and
/// the doublings are the whole cost, some two hundred and fifty-five of them
/// against forty-odd additions. Run together they are shared: one chain of
/// doublings, with each scalar contributing an addition at the positions where
/// its own recoding is non-zero.
///
/// The basepoint half also stops paying for constant time here. `mul_basepoint`
/// selects a table entry by reading all eight and moving conditionally, because
/// a signing scalar is secret. Nothing in a verification is: the signature, the
/// public key and the message are all in the clear, so the table is indexed
/// directly and the window widened to eight, which is a table built once and
/// about a third as many additions.
///
/// Both properties are why this is not the function signing calls.
/// [`double_scalar_mul_vartime`], reachable from the benchmark.
///
/// The benchmark lives outside this workspace and cannot see private items,
/// and comparing whole signatures cannot separate "our field arithmetic is
/// slower" from "our scalar multiplication does more work". This is how that
/// question gets answered rather than guessed at.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn double_scalar_mul_vartime_for_bench(a: &Point, k: &[u8; 32], s: &[u8; 32]) -> Point {
    fn on<F: Curve>(a: &Ext<Fe>, k: &[u8; 32], s: &[u8; 32]) -> Point {
        Point(double_scalar_mul_vartime(&a.convert::<F>(), k, s).convert::<Fe>())
    }
    dispatch!(on(&a.0, k, s))
}

/// `scalar * p` in constant time, four bits at a time, for scalars below
/// `2^255`.
///
/// What `no_std` signing uses in place of the precomputed table, and the same
/// algorithm with the table built per call: the scalar becomes 64 signed
/// radix-16 digits, `1..=8` times `p` are computed on the stack, and each digit
/// selects one of them by reading all eight with conditional moves. That is
/// 252 doublings and 64 additions, against 256 of each for
/// [`Point::mul_scalar`]'s bit-at-a-time ladder, and eight entries of 160 bytes
/// that are gone when it returns -- which is the constraint `no_std` exists
/// for.
///
/// Every scalar reaching it is a clamped secret or a value reduced modulo the
/// group order, which is what [`signed_digits`] needs. [`Point::mul_scalar`]
/// remains the public operation and takes any 32 bytes.
#[cfg(any(not(feature = "std"), test))]
fn mul_scalar_windowed<F: EdField>(p: &Ext<F>, scalar: &[u8; 32]) -> Ext<F> {
    let mut multiples = [*p; 8];
    for i in 1..8 {
        multiples[i] = multiples[i - 1].add(p);
    }
    let table: [Niels<F>; 8] = core::array::from_fn(|i| multiples[i].to_niels());

    // `digit * p` for a digit in `[-8, 8]`, without indexing by the digit.
    let select = |digit: i8| -> Niels<F> {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;
        let mut out = Niels::IDENTITY;
        for (i, entry) in table.iter().enumerate() {
            out.cmov(entry, Choice::from_u8(u8::from(magnitude == (i as u8 + 1))));
        }
        out.conditional_negate(negative);
        out
    };

    let digits = signed_digits(scalar);
    let mut acc = Ext::IDENTITY.add_niels(&select(digits[63])).to_extended();
    for i in (0..63).rev() {
        // Times sixteen: three doublings that never need `T`, then one that
        // does, since the addition after it reads `T`.
        let mut q = acc.to_projective();
        for _ in 0..3 {
            q = q.double_projective();
        }
        acc = q.double().to_extended();
        acc = acc.add_niels(&select(digits[i])).to_extended();
    }
    acc
}

/// `1, 3, 5 .. 15` times `p`, in Niels form.
fn odd_multiples<F: EdField>(p: &Ext<F>) -> [Niels<F>; 8] {
    let twice = p.double();
    let mut odd = [*p; 8];
    for i in 1..8 {
        odd[i] = odd[i - 1].add(&twice);
    }
    core::array::from_fn(|i| odd[i].to_niels())
}

/// The scalar as 64 signed radix-16 digits, each in `[-8, 8]`.
///
/// A nibble above 8 becomes `nibble - 16` with a carry into the next digit,
/// which is what keeps a table to the positive multiples.
///
/// Only the first 63 digits are recoded. The last one is left to absorb the
/// final carry, because a carry *out* of the top would be a factor of `16^64`
/// with nowhere to go -- silently dropping it would give the wrong point. That
/// works because every scalar reaching here has its top byte at most 127: the
/// clamped secret has bit 255 cleared by construction, and `r` and `s` are
/// reduced modulo the group order and so are far smaller. The top nibble is
/// then at most 7, one carry takes it to 8, and 8 is in range.
///
/// The first version of this recoded all 64 and dropped that carry. The
/// agreement test below caught it.
fn signed_digits(scalar: &[u8; 32]) -> [i8; 64] {
    debug_assert!(
        scalar[31] <= 127,
        "the top digit can only absorb the final carry for scalars below 2^255"
    );

    let mut nibbles = [0i8; 64];
    for (i, byte) in scalar.iter().enumerate() {
        nibbles[i * 2] = (byte & 0x0f) as i8;
        nibbles[i * 2 + 1] = (byte >> 4) as i8;
    }

    for i in 0..63 {
        let carry = (nibbles[i] + 8) >> 4;
        nibbles[i] -= carry << 4;
        nibbles[i + 1] += carry;
    }
    nibbles
}

#[cfg(feature = "std")]
fn double_scalar_mul_vartime<F: Curve>(a: &Ext<F>, k: &[u8; 32], s: &[u8; 32]) -> Ext<F> {
    F::double_mul(a, k, s)
}

/// [`double_scalar_mul_vartime`] in the field's own arithmetic, one method
/// call per operation.
#[cfg(feature = "std")]
fn double_scalar_mul_vartime_generic<F: Curve>(a: &Ext<F>, k: &[u8; 32], s: &[u8; 32]) -> Ext<F> {
    basepoint_table::prepare::<F>();
    shared_doublings(a, k, &wnaf(s, 8), |e, digit| {
        let n = basepoint_table::odd_multiple::<F>((digit.unsigned_abs() as usize) / 2);
        if digit > 0 {
            e.add_affine_niels(n)
        } else {
            e.sub_affine_niels(n)
        }
    })
}

/// [`double_scalar_mul_vartime`] with no stored table: the basepoint's odd
/// multiples are built per call, the same way `A`'s are, and read at width 5.
///
/// What `no_std` verification uses. It keeps the part that matters -- one chain
/// of doublings shared by both scalars, where computing `[S]B` and `[k]A`
/// separately would run two -- and gives up only the wider window, which is
/// the part that needs storage.
#[cfg(any(not(feature = "std"), test))]
fn double_scalar_mul_vartime_no_table<F: EdField>(
    a: &Ext<F>,
    k: &[u8; 32],
    s: &[u8; 32],
) -> Ext<F> {
    let odd_b = odd_multiples(&basepoint::<F>());
    shared_doublings(a, k, &wnaf(s, 5), |e, digit| {
        let n = &odd_b[(digit.unsigned_abs() as usize) / 2];
        if digit > 0 {
            e.add_niels(n)
        } else {
            e.sub_niels(n)
        }
    })
}

/// The loop both of those share: `[k]A` at width 5, plus whatever `add_b` adds
/// at each non-zero digit of `naf_b`, over a single chain of doublings.
#[inline(always)]
fn shared_doublings<F: EdField>(
    a: &Ext<F>,
    k: &[u8; 32],
    naf_b: &[i8; 258],
    add_b: impl Fn(&Ext<F>, i8) -> Completed<F>,
) -> Ext<F> {
    // 1A, 3A, 5A .. 15A, in Niels form, built for this call.
    let odd_a = odd_multiples(a);
    let naf_a = wnaf(k, 5);

    // Start at the highest position either recoding reaches, so the leading
    // doublings of the identity are skipped.
    let mut i = 257;
    while i > 0 && naf_a[i] == 0 && naf_b[i] == 0 {
        i -= 1;
    }

    // The accumulator is carried in whichever form the next step wants: a
    // doubling reads only X, Y and Z, and an addition is the only thing that
    // reads T. So a position with no addition pays three multiplications to
    // come out of the completed form instead of four.
    let mut acc = Ext::IDENTITY.to_projective();
    loop {
        // Nothing to add here, which is the common case: double straight back
        // to projective without materialising the completed form.
        if naf_a[i] == 0 && naf_b[i] == 0 {
            acc = acc.double_projective();
            if i == 0 {
                return acc.to_extended_from_projective();
            }
            i -= 1;
            continue;
        }
        let mut t = acc.double();
        if naf_a[i] != 0 {
            let e = t.to_extended();
            let n = &odd_a[(naf_a[i].unsigned_abs() as usize) / 2];
            t = if naf_a[i] > 0 {
                e.add_niels(n)
            } else {
                e.sub_niels(n)
            };
        }
        if naf_b[i] != 0 {
            t = add_b(&t.to_extended(), naf_b[i]);
        }
        if i == 0 {
            return t.to_extended();
        }
        acc = t.to_projective();
        i -= 1;
    }
}

/// [`mul_basepoint`], reachable from the benchmark. See
/// [`double_scalar_mul_vartime_for_bench`].
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn mul_basepoint_for_bench(scalar: &[u8; 32]) -> Point {
    fn on<F: Curve>(scalar: &[u8; 32]) -> Point {
        Point(mul_basepoint::<F>(scalar).convert::<Fe>())
    }
    dispatch!(on(scalar))
}

/// The basepoint in `F`.
fn basepoint<F: EdField>() -> Ext<F> {
    Ext {
        x: F::from_limbs51(BASEPOINT_X),
        y: F::from_limbs51(BASEPOINT_Y),
        z: F::ONE,
        t: F::from_limbs51(BASEPOINT_T),
    }
}

/// The basepoint in extended coordinates, `Z = 1` and `T = XY`.
///
/// It used to be decompressed from [`BASEPOINT_COMPRESSED`] on every call,
/// which is a field square root -- about a tenth of a signature on the `no_std`
/// path, where nothing caches it. The limbs were computed outside this crate
/// from `y = 4/5` and the curve equation, and
/// `the_basepoint_constant_is_the_decompressed_encoding` holds them to what
/// decompressing the RFC 8032 encoding gives.
const BASEPOINT_X: [u64; 5] = [
    1_738_742_601_995_546,
    1_146_398_526_822_698,
    2_070_867_633_025_821,
    562_264_141_797_630,
    587_772_402_128_613,
];
const BASEPOINT_Y: [u64; 5] = [
    1_801_439_850_948_184,
    1_351_079_888_211_148,
    450_359_962_737_049,
    900_719_925_474_099,
    1_801_439_850_948_198,
];
const BASEPOINT_T: [u64; 5] = [
    1_841_354_044_333_475,
    16_398_895_984_059,
    755_974_180_946_558,
    900_171_276_175_154,
    1_821_297_809_914_039,
];

/// RFC 8032 Ed25519 (PureEdDSA over Curve25519 with SHA-512).
pub struct Ed25519;

impl Algorithm for Ed25519 {
    const ID: &'static str = "ed25519";
    const NAME: &'static str = "Ed25519";
}

/// Expand a 32-byte seed into the clamped scalar and the nonce prefix.
fn expand_seed(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&h.as_ref()[..32]);
    prefix.copy_from_slice(&h.as_ref()[32..]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    (a, prefix)
}

/// Width-`w` non-adjacent form of a 256-bit scalar.
///
/// Each non-zero digit is odd and lies in `[-(2^(w-1) - 1), 2^(w-1) - 1]`, and
/// no two non-zero digits are within `w` places of each other, which puts the
/// density near `1/(w+1)`. A wider window means fewer additions and a bigger
/// table: width 5 for an arbitrary point, whose table has to be built on the
/// spot, and width 8 for the basepoint, whose table is built once.
///
/// `w` must be at most 8, so that every digit fits an `i8`.
fn wnaf(scalar: &[u8; 32], w: u32) -> [i8; 258] {
    debug_assert!((2..=8).contains(&w), "window width out of range");
    let half = 1i64 << (w - 1);
    let full = 1i64 << w;
    let mask = (full - 1) as u64;

    let mut naf = [0i8; 258];
    // Five limbs for a four-limb scalar. A negative digit adds to `k`, and for
    // a scalar near 2^256 that carries out of the top: on four limbs it wraps
    // to zero, the loop stops early, and the representation is silently short.
    // The scalars that reach this are reduced modulo the group order and could
    // not trigger it -- which is exactly the assumption that was wrong for the
    // NIST recoding, so the room is given rather than argued for.
    let mut k = [0u64; 5];
    for (i, limb) in k.iter_mut().take(4).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&scalar[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(b);
    }

    let mut i = 0;
    while k.iter().any(|&x| x != 0) {
        if k[0] & 1 == 1 {
            let mut d = (k[0] & mask) as i64;
            if d >= half {
                d -= full;
            }
            naf[i] = d as i8;
            if d > 0 {
                sub_u64(&mut k, d as u64);
            } else {
                add_u64(&mut k, d.unsigned_abs());
            }
        }
        shr1(&mut k);
        i += 1;
    }
    naf
}

/// `k -= v`, for `v` small enough not to borrow past the top.
fn sub_u64(k: &mut [u64; 5], v: u64) {
    let (d, mut borrow) = k[0].overflowing_sub(v);
    k[0] = d;
    for limb in k.iter_mut().skip(1) {
        if !borrow {
            break;
        }
        let (d, b) = limb.overflowing_sub(1);
        *limb = d;
        borrow = b;
    }
}

/// `k += v`, for `v` small enough not to carry past the top.
fn add_u64(k: &mut [u64; 5], v: u64) {
    let (d, mut carry) = k[0].overflowing_add(v);
    k[0] = d;
    for limb in k.iter_mut().skip(1) {
        if !carry {
            break;
        }
        let (d, c) = limb.overflowing_add(1);
        *limb = d;
        carry = c;
    }
}

/// `k >>= 1`.
fn shr1(k: &mut [u64; 5]) {
    for i in 0..4 {
        k[i] = (k[i] >> 1) | (k[i + 1] << 63);
    }
    k[4] >>= 1;
}

/// `SHA-512(parts...)` reduced modulo the group order.
fn hash_to_scalar(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(digest.as_ref());
    scalar::reduce_wide(&wide)
}

/// A signing key with its public key already derived.
///
/// # Why this exists
///
/// RFC 8032 signing needs the public key: it goes into the hash that produces
/// `k`. [`Ed25519::sign`] takes only the 32-byte seed, so it has to derive the
/// public key on every call -- a second basepoint multiplication, and with the
/// table in place that is most of what a signature now costs.
///
/// A key that is used more than once should derive it once. That is what a TLS
/// server does with a certificate key, and what dalek's `SigningKey` does,
/// which is why comparing `Ed25519::sign` against it was comparing two
/// different amounts of work.
///
/// The trait method still exists and still takes a seed. This changes nothing
/// for a caller signing once; it halves the cost for a caller signing twice.
pub struct Ed25519Key {
    /// The clamped scalar from the seed's hash.
    scalar: [u8; 32],
    /// The second half of that hash, which seeds the deterministic nonce.
    prefix: [u8; 32],
    /// `scalar * B`, compressed. Derived once, here.
    public: [u8; 32],
}

impl Drop for Ed25519Key {
    fn drop(&mut self) {
        self.scalar.zeroize();
        self.prefix.zeroize();
        // `public` is public, and is left alone.
    }
}

impl Ed25519Key {
    /// Expand a 32-byte seed and derive its public key.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(seed.len() == 32, InvalidLength, "ed25519 seed");
        let (scalar, prefix) = expand_seed(seed);
        let public = mul_basepoint_compressed(&scalar);
        Ok(Self {
            scalar,
            prefix,
            public,
        })
    }

    /// The public key, already derived.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Sign `message`, performing one basepoint multiplication rather than two.
    pub fn sign(&self, message: &[u8], signature: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(
            signature.len() == 64,
            InvalidLength,
            "ed25519 signature buffer"
        );

        // r = H(prefix || M), deterministic -- Ed25519 needs no RNG at signing
        // time, which removes an entire class of nonce-reuse failures.
        let mut r = hash_to_scalar(&[&self.prefix, message]);
        let big_r = mul_basepoint_compressed(&r);

        let k = hash_to_scalar(&[&big_r, &self.public, message]);
        let s = scalar::mul_add(&k, &self.scalar, &r);

        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s);
        r.zeroize();
        Ok(())
    }
}

impl SignatureScheme for Ed25519 {
    const PRIVATE_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(private_key.len() == 32, InvalidLength, "ed25519 seed");
        ensure!(out.len() == 32, InvalidLength, "ed25519 public key buffer");
        let (mut a, mut prefix) = expand_seed(private_key);
        out.copy_from_slice(&mul_basepoint_compressed(&a));
        a.zeroize();
        prefix.zeroize();
        Ok(())
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(private_key.len() == 32, InvalidLength, "ed25519 seed");
        ensure!(
            signature.len() == 64,
            InvalidLength,
            "ed25519 signature buffer"
        );

        // One shot: expand, derive the public key, sign, discard. A caller
        // signing more than once should hold an `Ed25519Key` instead and pay
        // the derivation once.
        Ed25519Key::from_seed(private_key)?.sign(message, signature)
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ic_core::module::operational()?;
        // One shot: the key and R are decompressed together, their
        // exponentiations interleaved. Only for well-formed lengths and a
        // canonical S; anything else takes the two-step path below, which
        // reports exactly the error it always has. A caller verifying more
        // than once against the same key should hold an `Ed25519VerifyKey`
        // and pay the key's decompression once.
        if public_key.len() == 32 && signature.len() == 64 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(public_key);
            let mut big_r = [0u8; 32];
            big_r.copy_from_slice(&signature[..32]);
            let mut s = [0u8; 32];
            s.copy_from_slice(&signature[32..]);
            if scalar::is_canonical(&s) {
                let k = hash_to_scalar(&[&big_r, &pk, message]);
                // The key's errors before R's, as the two-step path orders
                // them.
                return match dispatch!(check_one_shot(&pk, &big_r, &k, &s)) {
                    OneShot::Key(KeyDecode::Malformed) => Err(ic_core::err!(
                        MalformedEncoding,
                        "ed25519 public key is not on the curve or not canonical"
                    )),
                    OneShot::Key(_) => Err(ic_core::err!(
                        InvalidParameter,
                        "ed25519 public key has small order"
                    )),
                    OneShot::Signature(c) => c.into_result(),
                };
            }
        }
        Ed25519VerifyKey::from_bytes(public_key)?.verify(message, signature)
    }
}

/// A public key with its point already recovered.
///
/// Verification needs the public key as a curve point, and decompressing one
/// is a field exponentiation -- about two microseconds, against the twenty a
/// verification takes. A key used more than once should not pay that more than
/// once, which is the same reason [`Ed25519Key`] exists on the signing side.
///
/// The point is stored negated, because the equation verification checks is
/// `[S]B + [k](-A) == R`, so that is the form every signature wants.
///
/// [`Ed25519::verify`] builds one of these and throws it away, which is the
/// right thing for a caller with one signature and the wrong thing for a
/// caller with many.
pub struct Ed25519VerifyKey {
    /// The compressed encoding, which the challenge hash needs verbatim.
    compressed: [u8; 32],
    /// `-A`, decompressed once, as its canonical affine coordinates: the form
    /// either field reads directly.
    neg_a: ([u8; 32], [u8; 32]),
}

/// What decoding a public key found.
enum KeyDecode {
    /// Not on the curve, or not canonically encoded.
    Malformed,
    /// Of order dividing 8.
    SmallOrder,
    /// `-A`, as canonical affine `(x, y)`.
    Negated([u8; 32], [u8; 32]),
}

/// Decode and check a public key on the field `F`.
fn decode_key<F: Curve>(bytes: &[u8; 32]) -> KeyDecode {
    match Ext::<F>::decompress(bytes) {
        None => KeyDecode::Malformed,
        Some(a) if a.has_small_order() => KeyDecode::SmallOrder,
        // Decompression leaves Z = 1, so X and Y are the affine coordinates.
        Some(a) => {
            let n = a.negate();
            KeyDecode::Negated(n.x.to_bytes(), n.y.to_bytes())
        }
    }
}

/// What checking a signature's equation found.
#[derive(PartialEq, Eq, Debug)]
enum Check {
    /// R is not on the curve, or not canonically encoded.
    RMalformed,
    /// R is of order dividing 8.
    RSmallOrder,
    /// `[S]B + [k](-A) != R`.
    Mismatch,
    /// `[S]B + [k](-A) == R`.
    Holds,
}

impl Check {
    fn into_result(self) -> Result<()> {
        match self {
            Check::RMalformed => Err(ic_core::err!(
                MalformedEncoding,
                "ed25519 signature R is not on the curve or not canonical"
            )),
            Check::RSmallOrder => Err(ic_core::err!(
                MalformedEncoding,
                "ed25519 signature R has small order"
            )),
            Check::Mismatch => Err(ic_core::err!(AuthenticationFailed, "ed25519")),
            Check::Holds => Ok(()),
        }
    }
}

/// What one-shot verification found: a problem with the key, or the
/// signature's verdict.
enum OneShot {
    Key(KeyDecode),
    Signature(Check),
}

/// One-shot verification on the field `F`: the key and R decompressed
/// together, then the key's checks, then the signature's.
fn check_one_shot<F: Curve>(
    pk: &[u8; 32],
    big_r: &[u8; 32],
    k: &[u8; 32],
    s: &[u8; 32],
) -> OneShot {
    let (a, r) = Ext::<F>::decompress_pair(pk, big_r);
    let a = match a {
        None => return OneShot::Key(KeyDecode::Malformed),
        Some(a) if a.has_small_order() => return OneShot::Key(KeyDecode::SmallOrder),
        Some(a) => a,
    };
    OneShot::Signature(equation_holds(&a.negate(), r, k, s))
}

/// `[S]B + [k](-A) == R`, on the field `F`, everything public.
fn check_equation<F: Curve>(
    neg_a: &([u8; 32], [u8; 32]),
    big_r: &[u8; 32],
    k: &[u8; 32],
    s: &[u8; 32],
) -> Check {
    let a = Ext::from_affine(F::from_bytes(&neg_a.0), F::from_bytes(&neg_a.1));
    equation_holds(&a, Ext::<F>::decompress(big_r), k, s)
}

/// `[S]B + [k](-A) == R` for `-A` and a decompressed R.
fn equation_holds<F: Curve>(
    neg_a: &Ext<F>,
    r_point: Option<Ext<F>>,
    k: &[u8; 32],
    s: &[u8; 32],
) -> Check {
    let r_point = match r_point {
        None => return Check::RMalformed,
        Some(p) => p,
    };
    // An R of small order is what a signature made without a private key
    // looks like; a correct signer's R is a multiple of the basepoint and
    // never has one. Refused as dalek's verify_strict and libsodium do.
    if r_point.has_small_order() {
        return Check::RSmallOrder;
    }
    // [S]B + [k](-A) == R, in one interleaved pass sharing a single chain of
    // doublings. Everything here is public, so neither multiplication is
    // constant time.
    #[cfg(feature = "std")]
    let lhs = double_scalar_mul_vartime(neg_a, k, s);
    #[cfg(not(feature = "std"))]
    let lhs = double_scalar_mul_vartime_no_table(neg_a, k, s);
    if lhs.eq_projective(&r_point) {
        Check::Holds
    } else {
        Check::Mismatch
    }
}

impl Ed25519VerifyKey {
    /// Decompress `public_key`, rejecting anything not on the curve, not
    /// canonically encoded, or of small order.
    ///
    /// The last is not in RFC 8032, and is the check `verify_strict` in
    /// ed25519-dalek and libsodium's verifier also make. A key of order
    /// dividing 8 has no secret behind it worth the name: a signature under
    /// one can be made without any private key, for many messages at once,
    /// and the same signature can verify under several such keys. No key a
    /// correct signer derives has small order, so refusing them costs nothing
    /// honest.
    pub fn from_bytes(public_key: &[u8]) -> Result<Self> {
        ensure!(public_key.len() == 32, InvalidLength, "ed25519 public key");
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(public_key);
        match dispatch!(decode_key(&compressed)) {
            KeyDecode::Malformed => Err(ic_core::err!(
                MalformedEncoding,
                "ed25519 public key is not on the curve or not canonical"
            )),
            KeyDecode::SmallOrder => Err(ic_core::err!(
                InvalidParameter,
                "ed25519 public key has small order"
            )),
            KeyDecode::Negated(x, y) => Ok(Self {
                compressed,
                neg_a: (x, y),
            }),
        }
    }

    /// The key as it was given.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.compressed
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(signature.len() == 64, InvalidLength, "ed25519 signature");

        let mut big_r = [0u8; 32];
        big_r.copy_from_slice(&signature[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);

        // RFC 8032 section 5.1.7: reject a non-canonical S. Without this check
        // the signature is malleable, and any system that treats a signature
        // as a unique identifier becomes attackable.
        ensure!(
            scalar::is_canonical(&s),
            MalformedEncoding,
            "ed25519 signature S is not reduced"
        );

        let k = hash_to_scalar(&[&big_r, &self.compressed, message]);
        dispatch!(check_equation(&self.neg_a, &big_r, &k, &s)).into_result()
    }
}

impl SelfTest for Ed25519 {
    fn self_test() -> Result<()> {
        // RFC 8032 §7.1 test vector 1: the empty message.
        let mut seed = [0u8; 32];
        ic_core::codec::hex_decode(
            b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            &mut seed,
        )?;
        let mut want_pk = [0u8; 32];
        ic_core::codec::hex_decode(
            b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            &mut want_pk,
        )?;
        let mut want_sig = [0u8; 64];
        ic_core::codec::hex_decode(
            b"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            &mut want_sig,
        )?;

        let mut pk = [0u8; 32];
        <Self as SignatureScheme>::public_key(&seed, &mut pk)?;
        ensure!(
            ic_core::ct::verify(&want_pk, &pk),
            SelfTestFailed,
            "ed25519"
        );

        let mut sig = [0u8; 64];
        <Self as SignatureScheme>::sign(&seed, b"", &mut sig)?;
        ensure!(
            ic_core::ct::verify(&want_sig, &sig),
            SelfTestFailed,
            "ed25519"
        );

        <Self as SignatureScheme>::verify(&pk, b"", &sig)?;

        // A corrupted signature must be rejected.
        sig[0] ^= 1;
        ensure!(
            <Self as SignatureScheme>::verify(&pk, b"", &sig).is_err(),
            SelfTestFailed,
            "ed25519"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The curve on the portable field, which these tests were written for.
    type P = Ext<Fe>;
    const D: Fe = <Fe as EdField>::D;
    const D2: Fe = <Fe as EdField>::D2;
    const SQRT_M1: Fe = <Fe as EdField>::SQRT_M1;

    fn basepoint() -> P {
        super::basepoint::<Fe>()
    }

    fn mul_basepoint(s: &[u8; 32]) -> P {
        super::mul_basepoint::<Fe>(s)
    }

    /// `-A` as the verify key holds it, as a point.
    fn neg_a(vk: &Ed25519VerifyKey) -> P {
        P::from_affine(Fe::from_bytes(&vk.neg_a.0), Fe::from_bytes(&vk.neg_a.1))
    }
    use ic_core::codec::{hex, unhex};

    #[test]
    fn curve_constants_are_correct() {
        // d = -121665 / 121666
        let d = Fe::from_u64(121_665)
            .neg()
            .mul(&Fe::from_u64(121_666).invert());
        assert_eq!(hex(&D.to_bytes()), hex(&d.to_bytes()), "d");
        assert_eq!(hex(&D2.to_bytes()), hex(&d.add(&d).to_bytes()), "2d");
        // sqrt(-1) squares to -1.
        assert_eq!(
            hex(&SQRT_M1.square().to_bytes()),
            hex(&Fe::ONE.neg().to_bytes()),
            "sqrt(-1)"
        );
    }

    #[test]
    fn basepoint_has_the_expected_coordinates() {
        let b = basepoint();
        // y = 4/5
        let expected_y = Fe::from_u64(4).mul(&Fe::from_u64(5).invert());
        let z_inv = b.z.invert();
        assert_eq!(
            hex(&b.y.mul(&z_inv).to_bytes()),
            hex(&expected_y.to_bytes())
        );
        assert_eq!(hex(&b.compress()), hex(&BASEPOINT_COMPRESSED));
    }

    /// The dedicated doubling must agree with adding a point to itself.
    ///
    /// `add` is what RFC 8032's vectors validate, so it is the oracle here.
    /// The two formulas are different enough -- one reads `T`, the other does
    /// not -- that agreeing on the basepoint alone would not be convincing, so
    /// this walks a chain of multiples and doubles each one.
    #[test]
    fn doubling_agrees_with_adding_a_point_to_itself() {
        let mut p = basepoint();
        let mut checked = 0;
        for _ in 0..16 {
            assert_eq!(
                p.double().compress(),
                p.add(&p).compress(),
                "dedicated doubling and self-addition differ"
            );
            p = p.add(&basepoint());
            checked += 1;
        }
        assert_eq!(checked, 16, "the comparison did not run");

        // The identity doubles to itself, which the formula has to get right
        // without a special case.
        assert_eq!(P::IDENTITY.double().compress(), P::IDENTITY.compress());
    }

    /// Projective equality must agree with comparing compressed encodings.
    ///
    /// The two answer the same question by different routes -- one divides by
    /// Z, the other cross-multiplies -- so agreement is the argument. It has to
    /// hold for equal points given *different* representatives, which is the
    /// case the whole optimisation rests on, so the test scales one side by a
    /// factor and checks it still compares equal.
    #[test]
    fn projective_equality_agrees_with_compressed_equality() {
        let b = basepoint();
        let mut points = std::vec![P::IDENTITY, b];
        let mut p = b;
        for _ in 0..6 {
            p = p.double();
            points.push(p);
        }

        let mut checked = 0;
        for (i, a) in points.iter().enumerate() {
            for (j, c) in points.iter().enumerate() {
                let projective = a.eq_projective(c);
                let compressed = a.compress() == c.compress();
                assert_eq!(
                    projective, compressed,
                    "projective and compressed equality differ for {i} vs {j}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 64, "the comparison did not run");

        // The case that matters: the same point with a different Z. Adding the
        // identity re-scales the representation without moving the point.
        let scaled = b.add(&P::IDENTITY);
        assert!(b.eq_projective(&scaled), "equal points with different Z");
        assert_eq!(b.compress(), scaled.compress());
    }

    #[test]
    fn group_law_is_consistent() {
        let b = basepoint();
        // P + 0 == P
        assert_eq!(hex(&b.add(&P::IDENTITY).compress()), hex(&b.compress()));
        // 2P via doubling equals 2P via scalar multiplication.
        let mut two = [0u8; 32];
        two[0] = 2;
        assert_eq!(
            hex(&b.double().compress()),
            hex(&b.mul_scalar(&two).compress())
        );
        // (P + P) + P == 3P
        let mut three = [0u8; 32];
        three[0] = 3;
        assert_eq!(
            hex(&b.double().add(&b).compress()),
            hex(&b.mul_scalar(&three).compress())
        );
    }

    #[test]
    fn order_of_the_basepoint_is_l() {
        // [L]B must be the identity.
        assert_eq!(
            hex(&basepoint().mul_scalar(&scalar::L).compress()),
            hex(&P::IDENTITY.compress())
        );
    }

    #[test]
    fn compression_roundtrips() {
        let b = basepoint();
        for k in [1u8, 2, 3, 47, 200] {
            let mut s = [0u8; 32];
            s[0] = k;
            let p = b.mul_scalar(&s);
            let c = p.compress();
            let d = P::decompress(&c).expect("valid point");
            assert_eq!(hex(&d.compress()), hex(&c), "k = {k}");
        }
    }

    /// The identity as a public key: under the cofactorless equation alone,
    /// `[S]B + [k](-A) == R` holds with `R = [S]B` for every message and
    /// every `S`, so anyone can sign anything. The equation is shown to hold,
    /// and the key is refused before it is consulted.
    #[test]
    fn a_signature_under_the_identity_key_is_refused() {
        let identity = P::IDENTITY.compress();
        let s = scalar::reduce(&[7u8; 32]);
        let r = mul_basepoint(&s).compress();
        let k = hash_to_scalar(&[&r, &identity, b"any message"]);
        let neg_a = P::IDENTITY.negate();
        let lhs = double_scalar_mul_vartime(&neg_a, &k, &s);
        assert!(
            lhs.eq_projective(&P::decompress(&r).unwrap()),
            "the forgery satisfies the equation"
        );

        let err = Ed25519VerifyKey::from_bytes(&identity).err().unwrap();
        assert_eq!(err.kind(), ic_core::ErrorKind::InvalidParameter);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);
        assert!(Ed25519::verify(&identity, b"any message", &sig).is_err());
    }

    /// A signature whose R is the identity, made with the real private key:
    /// `S = k*a` satisfies the equation, since `[k*a]B - [k]A` is the identity.
    /// A correct signer's R is never of small order; this one is refused.
    #[test]
    fn a_signature_with_an_identity_r_is_refused() {
        let key = Ed25519Key::from_seed(&[0x42u8; 32]).unwrap();
        let r = P::IDENTITY.compress();
        let message = b"identity R";
        let k = hash_to_scalar(&[&r, &key.public, message]);
        let s = scalar::mul_add(&k, &key.scalar, &[0u8; 32]);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);

        let vk = Ed25519VerifyKey::from_bytes(&key.public).unwrap();
        let lhs = double_scalar_mul_vartime(&neg_a(&vk), &k, &s);
        assert!(
            lhs.eq_projective(&P::IDENTITY),
            "the signature satisfies the equation"
        );
        let err = vk.verify(message, &sig).unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::MalformedEncoding);
    }

    /// RFC 8032 section 5.1.3: a y field of p or more fails to decode, even
    /// where, reduced, it names a point of large order. y = 3 is one such:
    /// its canonical encoding decodes and its alias y + p does not.
    #[test]
    fn non_canonical_encodings_do_not_decode() {
        for sign in [0u8, 0x80] {
            let mut canonical = [0u8; 32];
            canonical[0] = 3;
            canonical[31] |= sign;
            let point = P::decompress(&canonical).expect("y = 3 is on the curve");
            assert!(!point.has_small_order());
            // p + 3 = 2^255 - 16, little-endian.
            let mut alias = [0xffu8; 32];
            alias[0] = 0xf0;
            alias[31] = 0x7f | sign;
            assert!(P::decompress(&alias).is_none(), "sign {sign:#x}");
        }
    }

    #[test]
    fn decompression_rejects_non_curve_points() {
        // A y value with no corresponding x.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert!(P::decompress(&bad).is_none());
    }

    /// RFC 8032 §7.1 test vectors.
    #[test]
    fn rfc8032_vectors() {
        let cases: [(&str, &str, &str, &str); 3] = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];

        for (seed_hex, pk_hex, msg_hex, sig_hex) in cases {
            let seed = unhex(seed_hex).unwrap();
            let msg = unhex(msg_hex).unwrap();

            let mut pk = [0u8; 32];
            Ed25519::public_key(&seed, &mut pk).unwrap();
            assert_eq!(hex(&pk), pk_hex, "public key for {seed_hex}");

            let mut sig = [0u8; 64];
            Ed25519::sign(&seed, &msg, &mut sig).unwrap();
            assert_eq!(hex(&sig), sig_hex, "signature for {seed_hex}");

            Ed25519::verify(&pk, &msg, &sig).unwrap();
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let seed = [0x42u8; 32];
        let mut pk = [0u8; 32];
        Ed25519::public_key(&seed, &mut pk).unwrap();
        let mut sig = [0u8; 64];
        Ed25519::sign(&seed, b"authentic", &mut sig).unwrap();
        Ed25519::verify(&pk, b"authentic", &sig).unwrap();

        // Wrong message.
        assert!(Ed25519::verify(&pk, b"forged", &sig).is_err());
        // Corrupted R.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(Ed25519::verify(&pk, b"authentic", &bad).is_err());
        // Corrupted S.
        let mut bad = sig;
        bad[40] ^= 1;
        assert!(Ed25519::verify(&pk, b"authentic", &bad).is_err());
        // Wrong public key.
        let mut other_pk = [0u8; 32];
        Ed25519::public_key(&[0x43u8; 32], &mut other_pk).unwrap();
        assert!(Ed25519::verify(&other_pk, b"authentic", &sig).is_err());
    }

    /// A signature with `S >= L` must be rejected even though it would
    /// otherwise verify; this is the malleability check.
    #[test]
    fn rejects_non_canonical_s() {
        let seed = [0x42u8; 32];
        let mut pk = [0u8; 32];
        Ed25519::public_key(&seed, &mut pk).unwrap();
        let mut sig = [0u8; 64];
        Ed25519::sign(&seed, b"msg", &mut sig).unwrap();

        // Add L to S. The verification equation still holds mod L, so only the
        // canonicality check can catch it.
        let mut carry = 0u16;
        for i in 0..32 {
            let t = sig[32 + i] as u16 + scalar::L[i] as u16 + carry;
            sig[32 + i] = t as u8;
            carry = t >> 8;
        }
        assert!(Ed25519::verify(&pk, b"msg", &sig).is_err());
    }

    /// The cached key and the seed-only call must produce the same signature.
    ///
    /// They share a code path now, which is the point -- but that is the sort
    /// of thing a later refactor separates again, and the two would then differ
    /// only for callers who use one and verify with the other. RFC 8032's
    /// vectors exercise the trait method alone and would not notice.
    #[test]
    fn the_cached_key_signs_identically_to_the_seed() {
        let mut checked = 0;
        for seed in [[0x11u8; 32], [0x9du8; 32], [0xffu8; 32]] {
            for message in [&b""[..], &b"x"[..], &b"a longer message to sign"[..]] {
                let mut from_seed = [0u8; 64];
                Ed25519::sign(&seed, message, &mut from_seed).unwrap();

                let key = Ed25519Key::from_seed(&seed).unwrap();
                let mut from_key = [0u8; 64];
                key.sign(message, &mut from_key).unwrap();

                assert_eq!(from_seed, from_key, "the two signing paths diverged");

                // And the cached public key is the one the trait derives.
                let mut derived = [0u8; 32];
                Ed25519::public_key(&seed, &mut derived).unwrap();
                assert_eq!(&derived, key.public_key());

                // Both verify, so neither is consistently wrong.
                Ed25519::verify(&derived, message, &from_key).unwrap();
                checked += 1;
            }
        }
        assert_eq!(checked, 9, "the comparison did not run");
    }

    /// Scalars that exercise the signed radix-16 recoding at its edges: digits
    /// of exactly 8, which carry; runs of 7 and 9 either side of that; the
    /// largest value the recoding accepts; the group order less one; and the
    /// shape of a clamped secret.
    fn windowed_scalars() -> std::vec::Vec<[u8; 32]> {
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut eight = [0u8; 32];
        eight[0] = 8;
        let mut top = [0xffu8; 32];
        top[31] = 0x7f;
        let mut clamped = [0x9du8; 32];
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let mut l_minus_1 = scalar::L;
        l_minus_1[0] -= 1;
        let mut out = std::vec![[0u8; 32], one, eight, top, clamped, l_minus_1];
        for fill in [0x88u8, 0x77, 0x99, 0x55, 0xaa] {
            let mut s = [fill; 32];
            s[31] &= 0x7f;
            out.push(s);
        }
        out
    }

    /// The `no_std` signing path against the bit-at-a-time ladder, on the
    /// basepoint and on a point that is not.
    ///
    /// Tests run with `std`, where signing takes the precomputed table, so
    /// without this the windowed path would be compiled into embedded builds
    /// and executed by nothing.
    /// Every coordinate, not just the compressed form: a wrong `T` still
    /// compresses correctly, since compression reads only `X`, `Y` and `Z`,
    /// and would corrupt every addition that reads it.
    #[test]
    fn the_basepoint_constant_is_the_decompressed_encoding() {
        let decoded = P::decompress(&BASEPOINT_COMPRESSED).expect("the RFC 8032 basepoint");
        let zinv = decoded.z.invert();
        for (name, constant, from_encoding) in [
            ("x", basepoint().x, decoded.x.mul(&zinv)),
            ("y", basepoint().y, decoded.y.mul(&zinv)),
            ("t", basepoint().t, decoded.t.mul(&zinv)),
        ] {
            assert_eq!(
                constant.to_bytes(),
                from_encoding.to_bytes(),
                "{name} differs"
            );
        }
        assert_eq!(basepoint().z.to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(basepoint().compress(), BASEPOINT_COMPRESSED);
    }

    #[test]
    fn the_windowed_multiplication_agrees_with_the_ladder() {
        let b = basepoint();
        let mut seven = [0u8; 32];
        seven[0] = 7;
        let p = b.mul_scalar(&seven);

        let mut checked = 0;
        for point in [b, p] {
            for scalar in windowed_scalars() {
                assert_eq!(
                    mul_scalar_windowed(&point, &scalar).compress(),
                    point.mul_scalar(&scalar).compress(),
                    "windowed and ladder differ for {scalar:02x?}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 20, "only {checked} comparisons ran");
    }

    /// The `no_std` verification path against the tabled one and against two
    /// separate ladders, which share no code with either.
    #[test]
    fn the_untabled_double_multiplication_agrees() {
        let b = basepoint();
        let mut checked = 0;
        for (i, k) in windowed_scalars().into_iter().enumerate() {
            let mut seed = [0u8; 32];
            seed[0] = 3 + i as u8;
            let a = b.mul_scalar(&seed);
            for s in [k, [0xffu8; 32], [0x9du8; 32]] {
                let untabled = double_scalar_mul_vartime_no_table(&a, &k, &s);
                let tabled = double_scalar_mul_vartime(&a, &k, &s);
                let ladders = a.mul_scalar(&k).add(&b.mul_scalar(&s));
                assert_eq!(
                    untabled.compress(),
                    tabled.compress(),
                    "k={k:02x?} s={s:02x?}"
                );
                assert_eq!(
                    untabled.compress(),
                    ladders.compress(),
                    "k={k:02x?} s={s:02x?}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 30, "only {checked} comparisons ran");
    }

    /// The recoding must represent the scalar, with the digits it promises.
    #[test]
    fn the_wnaf_digits_are_odd_sparse_and_faithful() {
        for scalar in [[1u8; 32], [0x9du8; 32], [0xffu8; 32], [0x55u8; 32]] {
            let naf = wnaf(&scalar, 5);

            let mut previous_nonzero: Option<usize> = None;
            for (i, d) in naf.iter().enumerate() {
                if *d == 0 {
                    continue;
                }
                assert!(d % 2 != 0, "digit {d} at {i} is not odd");
                assert!((-15..=15).contains(d), "digit {d} at {i} is out of range");
                if let Some(j) = previous_nonzero {
                    assert!(i - j >= 5, "digits at {j} and {i} are adjacent");
                }
                previous_nonzero = Some(i);
            }

            // And it evaluates back to the scalar, modulo a small prime that
            // has nothing to do with the curve.
            const M: u128 = 1_000_000_007;
            let mut from_digits = 0u128;
            let mut power = 1u128;
            for d in naf {
                let term = ((d as i128).rem_euclid(M as i128)) as u128;
                from_digits = (from_digits + term * power) % M;
                power = power * 2 % M;
            }
            let mut from_bytes = 0u128;
            let mut p = 1u128;
            for byte in scalar {
                from_bytes = (from_bytes + (byte as u128) * p) % M;
                p = p * 256 % M;
            }
            assert_eq!(from_digits, from_bytes, "recoding changed the value");
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let seed = [0x7fu8; 32];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        Ed25519::sign(&seed, b"same input", &mut a).unwrap();
        Ed25519::sign(&seed, b"same input", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mut out = [0u8; 32];
        assert!(Ed25519::public_key(&[0u8; 31], &mut out).is_err());
        assert!(Ed25519::sign(&[0u8; 32], b"", &mut [0u8; 63]).is_err());
        assert!(Ed25519::verify(&[0u8; 32], b"", &[0u8; 63]).is_err());
    }

    #[test]
    fn self_test_passes() {
        Ed25519::self_test().unwrap();
    }

    /// A few points on the curve, for the formula tests below.
    fn sample_points(n: usize) -> Vec<P> {
        let mut out = Vec::new();
        let mut p = basepoint();
        for _ in 0..n {
            out.push(p);
            p = p.double().add(&basepoint());
        }
        out
    }

    /// The completed-coordinate doubling is the extended one.
    ///
    /// `Projective::double` produces four squarings and no multiplications,
    /// and the multiplications a doubling needs move into whichever conversion
    /// follows. That is only sound if the two routes agree, and the signs are
    /// where it would go wrong: the completed form this uses differs from the
    /// one the extended formula implies by a factor of -1 in two coordinates,
    /// which cancels projectively and would not cancel if one of them were
    /// dropped.
    #[test]
    fn the_completed_doubling_agrees_with_the_extended_one() {
        for p in sample_points(40) {
            let want = p.double();
            let got = p.to_projective().double().to_extended();
            assert!(got.eq_projective(&want), "doubling disagrees");
            // And through the projective form, which is the route a chain of
            // doublings actually takes.
            let chained = p.to_projective().double().to_projective().double();
            let twice = p.double().double();
            assert!(chained.to_extended().eq_projective(&twice), "two doublings");
        }
    }

    /// Niels addition is the nine-multiplication addition.
    #[test]
    fn niels_addition_agrees_with_the_general_one() {
        let pts = sample_points(20);
        for p in &pts {
            for q in &pts {
                let want = p.add(q);
                let got = p.add_niels(&q.to_niels()).to_extended();
                assert!(got.eq_projective(&want), "add_niels disagrees");

                let want_sub = p.add(&q.negate());
                let got_sub = p.sub_niels(&q.to_niels()).to_extended();
                assert!(got_sub.eq_projective(&want_sub), "sub_niels disagrees");
            }
        }
    }

    /// Affine-Niels addition is the general addition.
    ///
    /// It drops the `Z` multiply on the assumption that the stored point has
    /// `Z = 1`, which `to_affine_niels` arranges by inverting. If that
    /// inversion or the `2d·x·y` were wrong the result would still be a point
    /// on the curve, just the wrong one, so it is checked against the addition
    /// the published vectors validate.
    #[test]
    fn affine_niels_addition_agrees_with_the_general_one() {
        let pts = sample_points(20);
        for p in &pts {
            for q in &pts {
                let want = p.add(q);
                let got = p.add_affine_niels(&q.to_affine_niels()).to_extended();
                assert!(got.eq_projective(&want), "add_affine_niels disagrees");

                // And the negated form, which the table's sign handling uses.
                let mut n = q.to_affine_niels();
                n.conditional_negate(1);
                let want_neg = p.add(&q.negate());
                let got_neg = p.add_affine_niels(&n).to_extended();
                assert!(got_neg.eq_projective(&want_neg), "negated form disagrees");
            }
        }
    }

    /// Where verification's time actually goes.
    ///
    /// Ignored: it is a measurement, not an assertion. Run it with
    /// `cargo test -p ic-ec --release -- --ignored --nocapture where_verify_spends`
    /// before changing anything here, because the answer decided what was
    /// worth doing and a guess would not have.
    #[test]
    #[ignore = "diagnostic, not a test"]
    fn where_verify_spends_its_time() {
        use std::time::Instant;

        let seed = [7u8; 32];
        let key = Ed25519Key::from_seed(&seed).unwrap();
        let msg = b"benchmark message";
        let mut sig = [0u8; 64];
        key.sign(msg, &mut sig).unwrap();
        let pk = *key.public_key();

        let mut big_r = [0u8; 32];
        big_r.copy_from_slice(&sig[..32]);
        let mut s_sc = [0u8; 32];
        s_sc.copy_from_slice(&sig[32..]);

        let n = 2000;
        let time = |label: &str, f: &mut dyn FnMut()| {
            let mut best = f64::INFINITY;
            for _ in 0..5 {
                let t = Instant::now();
                for _ in 0..n {
                    f();
                }
                let e = t.elapsed().as_secs_f64() / n as f64 * 1e6;
                if e < best {
                    best = e;
                }
            }
            println!("  {label:<34} {best:>9.2} us");
            best
        };

        let a_point = P::decompress(&pk).unwrap();
        let k = hash_to_scalar(&[&big_r, &pk, msg]);

        println!(
            "
ed25519 verify, cost breakdown:"
        );
        let d = time("decompress (x2 per verify)", &mut || {
            core::hint::black_box(P::decompress(&pk));
        });
        let h = time("hash_to_scalar", &mut || {
            core::hint::black_box(hash_to_scalar(&[&big_r, &pk, msg]));
        });
        let b = time("mul_basepoint (const time)", &mut || {
            core::hint::black_box(mul_basepoint(&s_sc));
        });
        let v = time("double_scalar_mul_vartime", &mut || {
            core::hint::black_box(double_scalar_mul_vartime(&a_point.negate(), &k, &s_sc));
        });
        time("  of which: wnaf(k,5)+wnaf(s,8)", &mut || {
            core::hint::black_box(wnaf(&k, 5));
            core::hint::black_box(wnaf(&s_sc, 8));
        });
        time("  of which: odd_a table build", &mut || {
            let twice = a_point.double();
            let mut odd = [a_point; 8];
            for i in 1..8 {
                odd[i] = odd[i - 1].add(&twice);
            }
            let t: [Niels<Fe>; 8] = core::array::from_fn(|i| odd[i].to_niels());
            core::hint::black_box(t);
        });
        time("  of which: 255 doublings", &mut || {
            let mut p = a_point;
            for _ in 0..255 {
                p = p.double();
            }
            core::hint::black_box(p);
        });
        time("  of which: 79 additions", &mut || {
            let mut p = a_point;
            for _ in 0..79 {
                p = p.add(&a_point);
            }
            core::hint::black_box(p);
        });
        time("compress (one inversion)", &mut || {
            core::hint::black_box(a_point.compress());
        });
        println!(
            "  {:<34} {:>9.2} us",
            "-- accounted for",
            2.0 * d + h + b + v
        );

        // One level down: if the point ops are slow, the field ops are why.
        println!(
            "
field and point primitives, nanoseconds:"
        );
        let nn = 200_000;
        let ns = |label: &str, f: &mut dyn FnMut()| {
            let mut best = f64::INFINITY;
            for _ in 0..5 {
                let t = Instant::now();
                for _ in 0..nn {
                    f();
                }
                let e = t.elapsed().as_secs_f64() / nn as f64 * 1e9;
                if e < best {
                    best = e;
                }
            }
            println!("  {label:<34} {best:>9.2} ns");
        };
        let fx = a_point.x;
        let fy = a_point.y;
        ns("Fe::mul", &mut || {
            core::hint::black_box(core::hint::black_box(&fx).mul(core::hint::black_box(&fy)));
        });
        ns("Fe::square", &mut || {
            core::hint::black_box(core::hint::black_box(&fx).square());
        });
        ns("Fe::add", &mut || {
            core::hint::black_box(core::hint::black_box(&fx).add(core::hint::black_box(&fy)));
        });
        ns("Fe::sub", &mut || {
            core::hint::black_box(core::hint::black_box(&fx).sub(core::hint::black_box(&fy)));
        });
        ns("Fe::neg", &mut || {
            core::hint::black_box(core::hint::black_box(&fx).neg());
        });
        let proj = a_point.to_projective();
        let comp = proj.double();
        let an = a_point.to_affine_niels();
        ns("Projective::double  (4S)", &mut || {
            core::hint::black_box(core::hint::black_box(&proj).double());
        });
        ns("Projective::double_projective", &mut || {
            core::hint::black_box(core::hint::black_box(proj).double_projective());
        });
        ns("Completed::to_projective (3M)", &mut || {
            core::hint::black_box(core::hint::black_box(&comp).to_projective());
        });
        ns("Completed::to_extended (4M)", &mut || {
            core::hint::black_box(core::hint::black_box(&comp).to_extended());
        });
        ns("P::add_affine_niels (3M)", &mut || {
            core::hint::black_box(
                core::hint::black_box(&a_point).add_affine_niels(core::hint::black_box(&an)),
            );
        });
        ns("P::double", &mut || {
            core::hint::black_box(core::hint::black_box(&a_point).double());
        });
        ns("P::add", &mut || {
            core::hint::black_box(
                core::hint::black_box(&a_point).add(core::hint::black_box(&a_point)),
            );
        });
    }

    /// How many point operations a verification actually performs.
    #[test]
    #[ignore = "diagnostic, not a test"]
    fn count_the_point_operations() {
        let mut doublings = 0usize;
        let mut adds_a = 0usize;
        let mut adds_b = 0usize;
        let mut state = 0x1234_5678_9abc_def0u64;
        let trials = 200;
        for _ in 0..trials {
            let mut kb = [0u8; 32];
            for c in kb.chunks_exact_mut(8) {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                c.copy_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
            }
            kb[31] &= 0x0f;
            let na = wnaf(&kb, 5);
            let nb = wnaf(&kb, 8);
            let mut i = 257;
            while i > 0 && na[i] == 0 && nb[i] == 0 {
                i -= 1;
            }
            doublings += i + 1;
            adds_a += na.iter().filter(|d| **d != 0).count();
            adds_b += nb.iter().filter(|d| **d != 0).count();
        }
        let d = doublings as f64 / trials as f64;
        let aa = adds_a as f64 / trials as f64;
        let ab = adds_b as f64 / trials as f64;
        println!(
            "
  per double-scalar multiplication, averaged over {trials} scalars:"
        );
        println!("    doublings                  {d:>8.1}");
        println!("    additions, w=5 table (A)   {aa:>8.1}");
        println!("    additions, w=8 table (B)   {ab:>8.1}");
        println!("    additions, building A      {:>8.1}", 8.0);
        println!("    ---");
        println!("    total additions            {:>8.1}", aa + ab + 8.0);
        println!(
            "    field muls, at 4M+4S per doubling and 9M per addition: {:>6.0}",
            d * 8.0 + (aa + ab + 8.0) * 9.0
        );
        println!(
            "    the same at dalek's 3M+4S and 7M:                      {:>6.0}",
            d * 7.0 + (aa + ab + 8.0) * 7.0
        );
    }
}
