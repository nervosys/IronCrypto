//! Group arithmetic for the NIST prime curves, in Jacobian coordinates.
//!
//! A Jacobian point `(X : Y : Z)` represents the affine point
//! `(X/Z^2, Y/Z^3)`, with `Z = 0` reserved for the point at infinity. Every
//! NIST prime curve has `a = -3`, which is what makes the specialized doubling
//! formula below applicable to all of them — so this module is written once and
//! instantiated per curve through [`Curve`].
//!
//! # Exceptional cases
//!
//! The Jacobian addition formula fails when its inputs are equal or opposite,
//! which a scalar multiplication loop *will* hit — `acc + P` is a doubling on
//! the first set bit of the scalar. Rather than branch on that (which would
//! leak the scalar), [`Point::add`] always computes both the addition and the
//! doubling and selects between them, together with the identity cases, using
//! constant-time moves. The cost is one extra doubling per addition; the
//! benefit is a group law with no input that misbehaves and no timing signal.

use super::arith::Field;
use ic_core::ct::Choice;

/// A short Weierstrass curve `y^2 = x^3 - 3x + b` over a prime field.
pub trait Curve: Sized {
    /// The coordinate field, GF(p).
    type Field: Field;
    /// The scalar ring, Z/nZ.
    type Scalar: Field;

    /// Display name, e.g. `"P-256"`.
    const NAME: &'static str;
    /// Width of an encoded field element.
    const FIELD_BYTES: usize;
    /// Width of an encoded scalar.
    const SCALAR_BYTES: usize;
    /// Bit length of the group order, `qlen` in RFC 6979.
    ///
    /// Not always `8 * SCALAR_BYTES`: P-521's order is 521 bits in a 66-byte
    /// encoding. RFC 6979's `bits2int` needs the true bit length, because that
    /// is how many leading bits it keeps.
    const ORDER_BITS: usize;

    /// The curve coefficient `b`.
    const B: Self::Field;
    /// The base point x-coordinate.
    const GX: Self::Field;
    /// The base point y-coordinate.
    const GY: Self::Field;

    /// Square root in the coordinate field.
    ///
    /// Every supported curve has `p = 3 mod 4`, so this is `x^((p+1)/4)`. The
    /// result is a candidate: the caller squares it to confirm the input was a
    /// quadratic residue.
    fn sqrt(x: &Self::Field) -> Self::Field;

    /// Decode a field element from exactly [`Self::FIELD_BYTES`] bytes.
    fn field_from_slice(bytes: &[u8]) -> Option<Self::Field>;

    /// Decode a scalar from exactly [`Self::SCALAR_BYTES`] bytes, rejecting a
    /// non-canonical encoding.
    fn scalar_from_slice(bytes: &[u8]) -> Option<Self::Scalar>;

    /// Decode a scalar, reducing rather than rejecting.
    ///
    /// Used where a specification calls for reduction, such as turning a hash
    /// or an x-coordinate into a scalar.
    fn scalar_reduce_slice(bytes: &[u8]) -> Self::Scalar;

    /// This curve's own doubling of Jacobian `(x, y, z)`, where it has one
    /// faster than [`Point::double`]'s formula, computing exactly the same
    /// thing; `None` to use the formula. P-256 on x86-64 with BMI2 and ADX
    /// has one: the whole formula as one block of assembly.
    #[inline(always)]
    fn double_fast(
        _x: &Self::Field,
        _y: &Self::Field,
        _z: &Self::Field,
    ) -> Option<[Self::Field; 3]> {
        None
    }

    /// The same for the Jacobian addition formula: the sum, then `h` and `r`.
    #[inline(always)]
    #[allow(clippy::type_complexity)]
    fn add_fast(
        _p: [&Self::Field; 3],
        _q: [&Self::Field; 3],
    ) -> Option<([Self::Field; 3], Self::Field, Self::Field)> {
        None
    }

    /// A faster table scan, where the curve has one: the `OR` over `entries`
    /// of each entry masked by its mask, which `gentable` uses to read one
    /// entry of a window without indexing by the digit. `None` to use the
    /// portable loop. P-256 on x86-64 has one, in SSE2 or AVX2.
    #[inline(always)]
    fn scan_affine(_entries: &[AffinePoint<Self>], _masks: &[u64]) -> Option<AffinePoint<Self>> {
        None
    }

    /// The same over Jacobian points, as coordinates.
    #[inline(always)]
    fn scan_point(_entries: &[Point<Self>], _masks: &[u64]) -> Option<[Self::Field; 3]> {
        None
    }

    /// The same for the mixed addition formula, with `q` affine.
    #[inline(always)]
    #[allow(clippy::type_complexity)]
    fn add_affine_fast(
        _p: [&Self::Field; 3],
        _q: [&Self::Field; 2],
    ) -> Option<([Self::Field; 3], Self::Field, Self::Field)> {
        None
    }
}

/// A point in Jacobian coordinates.
#[repr(C)]
pub struct Point<C: Curve> {
    x: C::Field,
    y: C::Field,
    z: C::Field,
}

// Implemented by hand so that `Point<C>` is `Copy` without requiring `C: Copy`.
impl<C: Curve> Clone for Point<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Curve> Copy for Point<C> {}

/// A point in affine coordinates, as produced by decoding or normalization.
#[repr(C)]
pub struct AffinePoint<C: Curve> {
    /// The x-coordinate.
    pub x: C::Field,
    /// The y-coordinate.
    pub y: C::Field,
}

impl<C: Curve> Clone for AffinePoint<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Curve> Copy for AffinePoint<C> {}

impl<C: Curve> Point<C> {
    /// The point at infinity, the group identity.
    pub fn identity() -> Self {
        Point {
            x: C::Field::ONE,
            y: C::Field::ONE,
            z: C::Field::ZERO,
        }
    }

    /// The standard base point `G`.
    pub fn generator() -> Self {
        Point {
            x: C::GX,
            y: C::GY,
            z: C::Field::ONE,
        }
    }

    /// Lift an affine point into Jacobian coordinates.
    pub fn from_affine(p: &AffinePoint<C>) -> Self {
        Point {
            x: p.x,
            y: p.y,
            z: C::Field::ONE,
        }
    }

    /// Whether this is the point at infinity.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Point doubling (`dbl-2001-b`, specialized for `a = -3`).
    #[inline]
    pub fn double(&self) -> Self {
        if let Some([x, y, z]) = C::double_fast(&self.x, &self.y, &self.z) {
            return Point { x, y, z };
        }
        self.double_formula()
    }

    /// [`Self::double`] in field operations, which [`Curve::double_fast`]
    /// must match.
    #[inline(never)]
    pub(crate) fn double_formula(&self) -> Self {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);

        // alpha = 3*(X - delta)*(X + delta), which is 3*X^2 - 3*Z^4 and is
        // where the a = -3 saving comes from.
        let alpha = self.x.sub(&delta).mul(&self.x.add(&delta)).triple();

        let beta4 = beta.double().double();
        let beta8 = beta4.double();
        let x3 = alpha.square().sub(&beta8);

        // Z3 = (Y + Z)^2 - gamma - delta, avoiding a multiplication.
        let z3 = self.y.add(&self.z).square().sub(&gamma).sub(&delta);

        let gamma2_8 = gamma.square().double().double().double();
        let y3 = alpha.mul(&beta4.sub(&x3)).sub(&gamma2_8);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The Jacobian addition formula (`add-2007-bl`), without case handling.
    ///
    /// Also returns `h` and `r`, whose being zero says the inputs had equal
    /// `x` and equal `y`, which [`Point::add`] uses to pick the right answer.
    ///
    /// Of the cases the formula gets wrong, one is right by accident: for
    /// `P + (-P)`, `h = 0` makes `Z3 = 0`, which is the identity. The others
    /// are an input at infinity, and `P + P`, where `r = 0` as well and the
    /// formula returns the identity instead of `2P`.
    #[inline]
    fn add_formula(&self, other: &Self) -> (Self, C::Field, C::Field) {
        if let Some(([x, y, z], h, r)) =
            C::add_fast([&self.x, &self.y, &self.z], [&other.x, &other.y, &other.z])
        {
            return (Point { x, y, z }, h, r);
        }
        self.add_formula_generic(other)
    }

    /// [`Self::add_formula`] in field operations, which [`Curve::add_fast`]
    /// must match.
    #[inline(never)]
    pub(crate) fn add_formula_generic(&self, other: &Self) -> (Self, C::Field, C::Field) {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);

        let h = u2.sub(&u1);
        let r = s2.sub(&s1).double();

        let i = h.double().square();
        let j = h.mul(&i);
        let v = u1.mul(&i);

        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());
        let z3 = self.z.add(&other.z).square().sub(&z1z1).sub(&z2z2).mul(&h);

        (
            Point {
                x: x3,
                y: y3,
                z: z3,
            },
            h,
            r,
        )
    }

    /// `self + other` for inputs that are not the same point, in constant
    /// time: correct when either is the identity, and for `P + (-P)`, but
    /// **not** for `P + P`, which returns the identity.
    ///
    /// Only for a caller that can show its inputs are never equal. Half the
    /// price of [`Point::add`], which computes a doubling beside every
    /// addition in case they are; see [`Point::mul_scalar`] for the argument
    /// that makes its loop such a caller.
    pub(crate) fn add_unequal(&self, other: &Self) -> Self {
        let (sum, _, _) = self.add_formula(other);
        // Both identity tests behind one barrier.
        let [other_inf, self_inf] =
            core::hint::black_box([other.z.zero_mask(), self.z.zero_mask()]);
        let result = Self::select_masked(other_inf, self, &sum);
        Self::select_masked(self_inf, other, &result)
    }

    /// `a` where `mask` is all ones, `b` where it is zero; the mask must
    /// already be behind a barrier.
    #[inline]
    fn select_masked(mask: u64, a: &Self, b: &Self) -> Self {
        Point {
            x: C::Field::select_mask(mask, &a.x, &b.x),
            y: C::Field::select_mask(mask, &a.y, &b.y),
            z: C::Field::select_mask(mask, &a.z, &b.z),
        }
    }

    /// `self + other`, complete, branching on the cases: for public points
    /// only, as in verification.
    pub(crate) fn add_vartime(&self, other: &Self) -> Self {
        if bool::from(self.is_identity()) {
            return *other;
        }
        if bool::from(other.is_identity()) {
            return *self;
        }
        let (sum, h, r) = self.add_formula(other);
        if bool::from(h.is_zero()) {
            return if bool::from(r.is_zero()) {
                self.double()
            } else {
                Self::identity()
            };
        }
        sum
    }

    /// `self + (x2, y2)` for an affine point (`madd-2007-bl`, `Z2 = 1`):
    /// seven multiplications and four squarings, where the general addition
    /// takes eleven and five.
    ///
    /// Constant time, and correct when `self` is the identity or `-(x2, y2)`,
    /// but not when it is `(x2, y2)` itself; the same contract as
    /// [`Point::add_unequal`].
    #[cfg(test)]
    pub(crate) fn add_affine_unequal(&self, x2: &C::Field, y2: &C::Field) -> Self {
        self.add_affine_unequal_or_keep(x2, y2, 0)
    }

    /// [`Point::add_affine_unequal`], or `self` unchanged where `keep` is
    /// all ones: the generator table's zero digit, whose identity has no
    /// affine form. `keep` need not be behind a barrier yet; it is put behind
    /// one together with the identity test, one barrier for both.
    #[cfg(feature = "std")]
    pub(crate) fn add_affine_unequal_or_keep(
        &self,
        x2: &C::Field,
        y2: &C::Field,
        keep: u64,
    ) -> Self {
        let (sum, _, _) = self.add_affine_formula(x2, y2);
        let lifted = Point {
            x: *x2,
            y: *y2,
            z: C::Field::ONE,
        };
        let [self_inf, keep] = core::hint::black_box([self.z.zero_mask(), keep]);
        let result = Self::select_masked(self_inf, &lifted, &sum);
        Self::select_masked(keep, self, &result)
    }

    /// [`Point::add_affine_unequal`], complete, branching on the cases: for
    /// public points only.
    #[cfg(feature = "std")]
    pub(crate) fn add_affine_vartime(&self, x2: &C::Field, y2: &C::Field) -> Self {
        let lifted = Point {
            x: *x2,
            y: *y2,
            z: C::Field::ONE,
        };
        if bool::from(self.is_identity()) {
            return lifted;
        }
        let (sum, h, r) = self.add_affine_formula(x2, y2);
        if bool::from(h.is_zero()) {
            return if bool::from(r.is_zero()) {
                self.double()
            } else {
                Self::identity()
            };
        }
        sum
    }

    /// The mixed addition formula, without case handling; `h` and `r` as in
    /// [`Point::add_formula`].
    #[inline]
    #[cfg(feature = "std")]
    fn add_affine_formula(&self, x2: &C::Field, y2: &C::Field) -> (Self, C::Field, C::Field) {
        if let Some(([x, y, z], h, r)) = C::add_affine_fast([&self.x, &self.y, &self.z], [x2, y2]) {
            return (Point { x, y, z }, h, r);
        }
        self.add_affine_formula_generic(x2, y2)
    }

    /// [`Self::add_affine_formula`] in field operations, which
    /// [`Curve::add_affine_fast`] must match.
    #[inline(never)]
    #[cfg(feature = "std")]
    pub(crate) fn add_affine_formula_generic(
        &self,
        x2: &C::Field,
        y2: &C::Field,
    ) -> (Self, C::Field, C::Field) {
        let z1z1 = self.z.square();
        let u2 = x2.mul(&z1z1);
        let s2 = y2.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.double().double();
        let j = h.mul(&i);
        let r = s2.sub(&self.y).double();
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        (
            Point {
                x: x3,
                y: y3,
                z: z3,
            },
            h,
            r,
        )
    }

    /// The complete group law: correct for every pair of inputs.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, h, r) = self.add_formula(other);
        let (h_zero, r_zero) = (h.is_zero(), r.is_zero());
        let doubled = self.double();

        let self_inf = self.is_identity();
        let other_inf = other.is_identity();

        // Equal x and equal y means the inputs are the same point, so the
        // answer is the doubling. Equal x with opposite y means they cancel.
        let same_point = h_zero.and(r_zero);
        let opposite = h_zero.and(r_zero.not());

        let mut result = sum;
        Self::cmov(&mut result, &doubled, same_point);
        Self::cmov(&mut result, &Self::identity(), opposite);
        // The identity cases are applied last so they take precedence: the
        // formula above produces nonsense when either input has Z = 0.
        Self::cmov(&mut result, self, other_inf);
        Self::cmov(&mut result, other, self_inf);
        result
    }

    /// Negate in place when `choice` is set.
    ///
    /// On a short Weierstrass curve `-(x, y, z)` is `(x, -y, z)`, so this is
    /// one field negation and a conditional move. Used by the signed-digit
    /// generator table, which stores only positive multiples.
    pub(crate) fn conditional_negate(&mut self, choice: Choice) {
        let ny = self.y.neg();
        <C::Field as Field>::cmov(&mut self.y, &ny, choice);
    }

    /// Constant-time conditional move.
    #[inline]
    pub(crate) fn cmov(a: &mut Self, b: &Self, choice: Choice) {
        C::Field::cmov(&mut a.x, &b.x, choice);
        C::Field::cmov(&mut a.y, &b.y, choice);
        C::Field::cmov(&mut a.z, &b.z, choice);
    }

    /// The point with these Jacobian coordinates, for a table scan.
    #[inline]
    pub(crate) fn from_coordinates(x: C::Field, y: C::Field, z: C::Field) -> Self {
        Point { x, y, z }
    }

    /// All coordinates zero: a point at infinity, since `Z = 0`, and the
    /// starting value of a table scan by [`Self::or_masked`].
    pub(crate) fn zero() -> Self {
        Point {
            x: C::Field::ZERO,
            y: C::Field::ZERO,
            z: C::Field::ZERO,
        }
    }

    /// `a |= b & mask`, coordinate by coordinate; see [`Field::or_masked`].
    #[inline]
    pub(crate) fn or_masked(a: &mut Self, b: &Self, mask: u64) {
        C::Field::or_masked(&mut a.x, &b.x, mask);
        C::Field::or_masked(&mut a.y, &b.y, mask);
        C::Field::or_masked(&mut a.z, &b.z, mask);
    }

    /// Point negation.
    pub fn neg(&self) -> Self {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Scalar multiplication, constant-time in the scalar.
    ///
    /// Five bits at a time. The scalar becomes signed digits in `[-16, 16]`,
    /// `1..=16` times this point are computed once per call, and each digit
    /// selects one of them by reading all sixteen with conditional moves, then
    /// negates it or not the same way. Every scalar of a curve has the same
    /// digit count, and every digit costs five doublings, one selection and
    /// one addition, so the trace does not depend on the scalar.
    ///
    /// ECDH is one of these, so this is most of its cost; under `no_std` it is
    /// also what multiplies the generator, since there is no stored table
    /// there. The window is sixteen points on the stack, freed on return.
    /// Four-bit windows cost thirteen more additions on P-256 and eight
    /// fewer entries to build; five measured faster.
    ///
    /// # Which additions can be incomplete
    ///
    /// Every addition but the last is [`Self::add_unequal`], which skips the
    /// doubling [`Self::add`] computes in case its inputs are equal, because
    /// they cannot be. `self` is a point of prime order `n` (every point of
    /// a NIST curve is: the cofactor is 1), or the identity. Before digit `i`
    /// is added, the accumulator is `32 * S * P`, where `S` is the integer
    /// the digits above `i` spell, and the entry is `d * P` with `|d| <= 16`.
    /// They are equal only if `32 * S - d = 0 mod n`. The scalar is below
    /// `n`, so for `i >= 1`, `|32 * S - d| <= k / 32 + 48 < n`, which makes
    /// that `32 * S = d` exactly, and with `|d| <= 16` that is `S = d = 0`:
    /// an identity on both sides, which `add_unequal` handles. At `i = 0` the
    /// bound fails -- `k = n - 2` makes the accumulator `-P` and the last
    /// digit `-1` -- so the last addition is the complete one. Selected
    /// identities, and `P + (-P)`, are handled by `add_unequal` as well.
    ///
    /// The scalars at that edge, `n - 1 .. n - 40` and `1 .. 40`, are in the
    /// tests, as is a comparison with the ladder over random scalars.
    pub fn mul_scalar(&self, scalar: &C::Scalar) -> Self {
        use super::gentable::{digit_count, signed_digits_w, Window, WIDTH};

        let bytes = scalar.to_bytes();
        let bytes = bytes.as_ref();
        let digits = signed_digits_w(bytes, WIDTH);
        let n = digit_count(bytes.len(), WIDTH);
        let window = Window::new(self);

        let mut acc = window.select(digits[n - 1]);
        for i in (1..n - 1).rev() {
            for _ in 0..WIDTH {
                acc = acc.double();
            }
            acc = acc.add_unequal(&window.select(digits[i]));
        }
        for _ in 0..WIDTH {
            acc = acc.double();
        }
        acc.add(&window.select(digits[0]))
    }

    /// The double-and-add-always ladder [`Self::mul_scalar`] replaced, kept as
    /// the reference it is tested against: one bit at a time, sharing nothing
    /// with the windowed method but the group law.
    #[cfg(test)]
    pub(crate) fn mul_scalar_ladder(&self, scalar: &C::Scalar) -> Self {
        let bytes = scalar.to_bytes();
        let bytes = bytes.as_ref();
        let mut acc = Self::identity();
        for byte in bytes.iter() {
            for bit in (0..8).rev() {
                acc = acc.double();
                let sum = acc.add(self);
                let b = Choice::from_u8((byte >> bit) & 1);
                Self::cmov(&mut acc, &sum, b);
            }
        }
        acc
    }

    /// Negate: on a short Weierstrass curve `-(x, y, z)` is `(x, -y, z)`.
    fn negate(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Scalar multiplication that is **not** constant time.
    ///
    /// # When this is allowed
    ///
    /// Only on values an attacker already has. Verification is the case: the
    /// signature, the public key and the message are public, so there is no
    /// secret whose timing could leak. ECDH and signing must never call this --
    /// their scalars are private keys.
    ///
    /// # What it does instead
    ///
    /// A width-5 non-adjacent form, as [`crate::ed25519`] uses. Roughly one
    /// digit in six is non-zero, so the additions drop from one per bit to
    /// about a sixth of that. The doublings remain: an arbitrary point has no
    /// precomputed table to remove them, and the generator -- which does -- is
    /// handled by [`Self::mul_generator`].
    pub fn mul_scalar_vartime(&self, scalar: &C::Scalar) -> Self {
        // 1P, 3P, 5P .. 15P.
        let twice = self.double();
        let mut odd = [*self; 8];
        for i in 1..8 {
            odd[i] = odd[i - 1].add_vartime(&twice);
        }

        let bytes = scalar.to_bytes();
        let (naf, len) = wnaf5(bytes.as_ref());

        let mut acc = Self::identity();
        for i in (0..len).rev() {
            acc = acc.double();
            let digit = naf[i];
            if digit != 0 {
                let entry = &odd[(digit.unsigned_abs() as usize) / 2];
                acc = if digit > 0 {
                    acc.add_vartime(entry)
                } else {
                    acc.add_vartime(&entry.negate())
                };
            }
        }
        acc
    }

    /// `a*G + b*P`, for signature verification.
    ///
    /// Verification operates entirely on public values, so this makes no
    /// constant-time claim beyond what it inherits from the primitives.
    pub fn mul_double(a: &C::Scalar, p: &Self, b: &C::Scalar) -> Self
    where
        C: super::gentable::HasGeneratorTable,
    {
        // Both halves are public here. The generator gets its table, read by
        // index and skipping zero digits; the other point gets the
        // non-adjacent form.
        #[cfg(feature = "std")]
        {
            Self::mul_generator_vartime(a).add_vartime(&p.mul_scalar_vartime(b))
        }
        // No table, so the generator costs a full chain of doublings like any
        // other point -- and the two chains can be one.
        #[cfg(not(feature = "std"))]
        {
            Self::mul_double_vartime(&Self::generator(), a, p, b)
        }
    }

    /// `a*Q + b*P` over one chain of doublings, variable time in both scalars.
    ///
    /// What `no_std` verification uses. Computing the two multiplications
    /// separately runs two chains of doublings, and the doublings are most of
    /// the cost; here each scalar contributes an addition at the positions
    /// where its own width-5 recoding is non-zero, and they share the rest.
    /// Under `std` the generator's table removes its doublings altogether,
    /// which is better still, so this is not used there.
    #[cfg(any(not(feature = "std"), test))]
    pub(crate) fn mul_double_vartime(q: &Self, a: &C::Scalar, p: &Self, b: &C::Scalar) -> Self {
        let odd = |base: &Self| {
            let twice = base.double();
            let mut odd = [*base; 8];
            for i in 1..8 {
                odd[i] = odd[i - 1].add_vartime(&twice);
            }
            odd
        };
        let (odd_q, odd_p) = (odd(q), odd(p));
        let (a_bytes, b_bytes) = (a.to_bytes(), b.to_bytes());
        let (naf_a, len_a) = wnaf5(a_bytes.as_ref());
        let (naf_b, len_b) = wnaf5(b_bytes.as_ref());

        let mut acc = Self::identity();
        for i in (0..len_a.max(len_b)).rev() {
            acc = acc.double();
            for (naf, table) in [(&naf_a, &odd_q), (&naf_b, &odd_p)] {
                let digit = naf[i];
                if digit != 0 {
                    let entry = &table[(digit.unsigned_abs() as usize) / 2];
                    acc = if digit > 0 {
                        acc.add_vartime(entry)
                    } else {
                        acc.add_vartime(&entry.negate())
                    };
                }
            }
        }
        acc
    }

    /// `scalar * G`, through the precomputed table where there is one.
    ///
    /// Every generator multiplication goes through here rather than calling
    /// `mul_scalar` on the generator, so the two cannot drift apart and no
    /// caller takes the slow path by accident; `ironcrypto`'s
    /// `fixed_base_multiplication_goes_through_its_funnel` holds that, after
    /// public-key derivation was found skipping it. Only the generator half of
    /// verification benefits; the other multiplication is against the public
    /// key and uses the non-adjacent form.
    pub fn mul_generator(scalar: &C::Scalar) -> Self
    where
        C: super::gentable::HasGeneratorTable,
    {
        C::mul_generator(scalar)
    }

    /// `scalar * G` for a public scalar, **not** constant time: the table's
    /// entries are read by index. For verification only, like
    /// [`Self::mul_scalar_vartime`].
    pub fn mul_generator_vartime(scalar: &C::Scalar) -> Self
    where
        C: super::gentable::HasGeneratorTable,
    {
        C::mul_generator_vartime(scalar)
    }

    /// The Jacobian coordinates, for the generator table's normalisation.
    #[cfg(feature = "std")]
    pub(super) fn x(&self) -> C::Field {
        self.x
    }
    #[cfg(feature = "std")]
    pub(super) fn y(&self) -> C::Field {
        self.y
    }
    #[cfg(feature = "std")]
    pub(super) fn z(&self) -> C::Field {
        self.z
    }
}

/// Limbs for the widest scalar, plus one for the carry.
///
/// P-521's scalar is 66 bytes, so nine limbs hold it and a tenth holds the
/// carry a negative digit can push out of the top. The Ed25519 version of this
/// shipped without that tenth limb and lost the carry for scalars near the top
/// of the range; the scalars arriving here are reduced modulo the group order
/// and could not trigger it, which is the same argument that was false for the
/// generator table's recoding. So the room is given rather than argued for.
const WNAF_LIMBS: usize = 10;

/// Digits for the widest scalar: `8 * 66`, with room to run past the top.
const WNAF_DIGITS: usize = 8 * 66 + 2;

/// Width-5 non-adjacent form, and how many digits of it are used.
///
/// `bytes` is big-endian, as `Field::to_bytes` produces. Each non-zero digit is
/// odd and in `[-15, 15]`, and no two are adjacent.
///
/// Variable time by construction: the loop length and digit pattern depend on
/// the scalar. See [`Point::mul_scalar_vartime`] for when that is allowed.
fn wnaf5(bytes: &[u8]) -> ([i8; WNAF_DIGITS], usize) {
    let mut naf = [0i8; WNAF_DIGITS];
    let mut k = [0u64; WNAF_LIMBS];
    for (i, byte) in bytes.iter().rev().enumerate() {
        k[i / 8] |= (*byte as u64) << ((i % 8) * 8);
    }

    let mut i = 0;
    while k.iter().any(|&x| x != 0) {
        if k[0] & 1 == 1 {
            let mut d = (k[0] & 0x1f) as i64;
            if d >= 16 {
                d -= 32;
            }
            naf[i] = d as i8;
            if d > 0 {
                wnaf_sub(&mut k, d as u64);
            } else {
                wnaf_add(&mut k, d.unsigned_abs());
            }
        }
        wnaf_shr1(&mut k);
        i += 1;
    }
    (naf, i)
}

/// `k -= v`.
fn wnaf_sub(k: &mut [u64; WNAF_LIMBS], v: u64) {
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

/// `k += v`.
fn wnaf_add(k: &mut [u64; WNAF_LIMBS], v: u64) {
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
fn wnaf_shr1(k: &mut [u64; WNAF_LIMBS]) {
    for i in 0..WNAF_LIMBS - 1 {
        k[i] = (k[i] >> 1) | (k[i + 1] << 63);
    }
    k[WNAF_LIMBS - 1] >>= 1;
}

impl<C: Curve> Point<C> {
    /// Convert to affine coordinates, or `None` for the identity.
    pub fn to_affine(self) -> Option<AffinePoint<C>> {
        if bool::from(self.is_identity()) {
            return None;
        }
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);
        Some(AffinePoint {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
        })
    }

    /// Whether this point's affine x-coordinate is one of `xs`, compared as
    /// `X == x * Z^2`, without an inversion; `false` for the identity.
    /// **Variable time**: for verification, where every value is public.
    pub(crate) fn x_is_one_of_vartime(&self, xs: &[C::Field]) -> bool {
        if bool::from(self.is_identity()) {
            return false;
        }
        let z2 = self.z.square();
        xs.iter().any(|x| x.mul(&z2) == self.x)
    }

    /// The affine x-coordinate alone, or `None` for the identity: what
    /// ECDSA's `r` needs, two multiplications fewer than [`Self::to_affine`].
    /// The identity test is the same one, on the same value.
    pub fn to_affine_x(self) -> Option<C::Field> {
        if bool::from(self.is_identity()) {
            return None;
        }
        let z_inv = self.z.invert();
        Some(self.x.mul(&z_inv.square()))
    }

    /// Constant-time equality, comparing through the projective scaling.
    pub fn ct_eq(&self, other: &Self) -> Choice {
        // X1*Z2^2 == X2*Z1^2 and Y1*Z2^3 == Y2*Z1^3
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let x_eq = self.x.mul(&z2z2).ct_eq(&other.x.mul(&z1z1));
        let y_eq = self
            .y
            .mul(&z2z2.mul(&other.z))
            .ct_eq(&other.y.mul(&z1z1.mul(&self.z)));
        let both_inf = self.is_identity().and(other.is_identity());
        let neither_inf = self.is_identity().or(other.is_identity()).not();
        both_inf.or(neither_inf.and(x_eq).and(y_eq))
    }
}

impl<C: Curve> AffinePoint<C> {
    /// Whether this point satisfies `y^2 = x^3 - 3x + b`.
    pub fn is_on_curve(&self) -> Choice {
        let lhs = self.y.square();
        let rhs = self
            .x
            .square()
            .mul(&self.x)
            .sub(&self.x.triple())
            .add(&C::B);
        lhs.ct_eq(&rhs)
    }

    /// Write the SEC1 uncompressed encoding `0x04 || X || Y` into `out`.
    ///
    /// `out` must be `1 + 2 * FIELD_BYTES` bytes.
    #[must_use = "a false return means nothing was written"]
    pub fn write_uncompressed(&self, out: &mut [u8]) -> bool {
        if out.len() != 1 + 2 * C::FIELD_BYTES {
            return false;
        }
        out[0] = 0x04;
        out[1..1 + C::FIELD_BYTES].copy_from_slice(self.x.to_bytes().as_ref());
        out[1 + C::FIELD_BYTES..].copy_from_slice(self.y.to_bytes().as_ref());
        true
    }

    /// Write the SEC1 compressed encoding into `out`, which must be
    /// `1 + FIELD_BYTES` bytes.
    #[must_use = "a false return means nothing was written"]
    pub fn write_compressed(&self, out: &mut [u8]) -> bool {
        if out.len() != 1 + C::FIELD_BYTES {
            return false;
        }
        out[0] = 0x02 | self.y.is_odd().unwrap_u8();
        out[1..].copy_from_slice(self.x.to_bytes().as_ref());
        true
    }

    /// Decode a SEC1 point encoding, rejecting anything not on the curve.
    ///
    /// Accepts both the uncompressed and compressed forms. The identity has no
    /// SEC1 encoding here, so it can never be decoded — a peer cannot force a
    /// shared secret by sending one.
    pub fn from_sec1(bytes: &[u8]) -> Option<Self> {
        let f = C::FIELD_BYTES;
        if bytes.len() == 1 + 2 * f && bytes[0] == 0x04 {
            let x = C::field_from_slice(&bytes[1..1 + f])?;
            let y = C::field_from_slice(&bytes[1 + f..])?;
            let p = AffinePoint { x, y };
            return bool::from(p.is_on_curve()).then_some(p);
        }
        if bytes.len() == 1 + f && (bytes[0] == 0x02 || bytes[0] == 0x03) {
            let x = C::field_from_slice(&bytes[1..])?;

            // y^2 = x^3 - 3x + b
            let y2 = x.square().mul(&x).sub(&x.triple()).add(&C::B);
            let y = C::sqrt(&y2);
            // Squaring the candidate root is what detects a non-residue, i.e.
            // an x that is not on the curve at all.
            if y.square() != y2 {
                return None;
            }
            // Pick the root whose parity matches the sign byte.
            let want_odd = Choice::from_u8(bytes[0] & 1);
            let flip = Choice::from_u8(y.is_odd().unwrap_u8() ^ want_odd.unwrap_u8());
            let mut chosen = y;
            C::Field::cmov(&mut chosen, &y.neg(), flip);
            return Some(AffinePoint { x, y: chosen });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nist::gentable::HasGeneratorTable;
    use crate::p256::P256;
    use crate::p384::P384;
    use crate::p521::P521;

    /// Scalars chosen for the signed radix-16 recoding rather than at random:
    /// zero and one; `n - 1`, whose top nibble is 15 and so exercises the
    /// extra carry digit; and whole-scalar runs of 8, which carry at every
    /// digit, and of 7 and 9 either side of that.
    fn scalars<C: Curve>() -> std::vec::Vec<C::Scalar> {
        let mut out = std::vec![C::Scalar::ZERO, C::Scalar::ONE, C::Scalar::ONE.neg()];
        for fill in [0x88u8, 0x77, 0x99, 0xff, 0x0f, 0xf0, 0x5a] {
            let mut bytes = C::Scalar::zero_bytes();
            for b in bytes.as_mut() {
                *b = fill;
            }
            out.push(C::Scalar::from_bytes_reduced(&bytes));
        }
        let mut eight = C::Scalar::zero_bytes();
        let last = eight.as_ref().len() - 1;
        eight.as_mut()[last] = 8;
        out.push(C::Scalar::from_bytes_reduced(&eight));
        out
    }

    fn some_point<C: Curve>() -> Point<C> {
        let mut bytes = C::Scalar::zero_bytes();
        let last = bytes.as_ref().len() - 1;
        bytes.as_mut()[last] = 7;
        Point::<C>::generator().mul_scalar_ladder(&C::Scalar::from_bytes_reduced(&bytes))
    }

    /// The windowed multiplication against the ladder it replaced, on the
    /// generator, another point, and the identity. The generator is also
    /// checked against the table, which shares the recoding and the lookup
    /// with the windowed method but not the windows.
    fn windowed_agrees_with_the_ladder<C: Curve + HasGeneratorTable>() -> usize {
        let mut checked = 0;
        for point in [
            Point::<C>::generator(),
            some_point::<C>(),
            Point::identity(),
        ] {
            for k in scalars::<C>() {
                let windowed = point.mul_scalar(&k);
                assert!(
                    bool::from(windowed.ct_eq(&point.mul_scalar_ladder(&k))),
                    "windowed and ladder differ"
                );
                checked += 1;
            }
        }
        for k in scalars::<C>() {
            let g = Point::<C>::generator();
            assert!(bool::from(
                Point::<C>::mul_generator(&k).ct_eq(&g.mul_scalar(&k))
            ));
        }
        checked
    }

    /// The shared-doubling verification path against two independent ladders,
    /// and against the `std` path of table plus non-adjacent form.
    fn shared_doublings_agree<C: Curve + HasGeneratorTable>() -> usize {
        let g = Point::<C>::generator();
        let p = some_point::<C>();
        let mut checked = 0;
        for a in scalars::<C>() {
            for b in [C::Scalar::ONE, C::Scalar::ONE.neg(), a.square()] {
                let shared = Point::mul_double_vartime(&g, &a, &p, &b);
                let ladders = g.mul_scalar_ladder(&a).add(&p.mul_scalar_ladder(&b));
                assert!(
                    bool::from(shared.ct_eq(&ladders)),
                    "shared and ladders differ"
                );
                assert!(bool::from(shared.ct_eq(&Point::mul_double(&a, &p, &b))));
                checked += 1;
            }
        }
        checked
    }

    /// Affine point arithmetic from the textbook formulas, with the identity
    /// as `None`. It shares nothing with the complete projective formulas it
    /// checks: slopes, a field inversion per operation, and each exceptional
    /// case written out as its own branch.
    fn affine_add<C: Curve>(
        p: Option<(C::Field, C::Field)>,
        q: Option<(C::Field, C::Field)>,
    ) -> Option<(C::Field, C::Field)> {
        let (Some((x1, y1)), Some((x2, y2))) = (p, q) else {
            return p.or(q);
        };
        let lambda = if bool::from(x1.ct_eq(&x2)) {
            if !bool::from(y1.ct_eq(&y2)) || bool::from(y1.is_zero()) {
                return None; // P + (-P)
            }
            // Doubling: (3x^2 - 3) / 2y, since a = -3.
            x1.square()
                .sub(&C::Field::ONE)
                .triple()
                .mul(&y1.double().invert())
        } else {
            y2.sub(&y1).mul(&x2.sub(&x1).invert())
        };
        let x3 = lambda.square().sub(&x1).sub(&x2);
        let y3 = lambda.mul(&x1.sub(&x3)).sub(&y1);
        Some((x3, y3))
    }

    fn affine_of<C: Curve>(p: &Point<C>) -> Option<(C::Field, C::Field)> {
        p.to_affine().map(|a| (a.x, a.y))
    }

    /// The complete formulas against the affine reference, on every case a
    /// complete formula exists to handle: distinct points, a point plus
    /// itself through `add` and through `double`, a point plus its negative,
    /// and the identity on either side and on both.
    fn the_group_law_agrees_with_affine<C: Curve>() -> usize {
        let g = Point::<C>::generator();
        let o = Point::<C>::identity();
        // P_1 .. P_12, built by the reference alone.
        let mut multiples = std::vec::Vec::new();
        let mut acc = None;
        for _ in 0..12 {
            acc = affine_add::<C>(acc, affine_of(&g));
            let (x, y) = acc.unwrap();
            multiples.push(Point::<C>::from_affine(&AffinePoint { x, y }));
        }
        let mut checked = 0;
        for p in &multiples {
            let ap = affine_of(p);
            let ok =
                |got: &Point<C>, want: Option<(C::Field, C::Field)>| match (affine_of(got), want) {
                    (None, None) => true,
                    (Some((a, b)), Some((c, d))) => bool::from(a.ct_eq(&c).and(b.ct_eq(&d))),
                    _ => false,
                };
            assert!(ok(&p.add(p), affine_add::<C>(ap, ap)), "P + P");
            assert!(ok(&p.double(), affine_add::<C>(ap, ap)), "2P");
            assert!(ok(&p.add(&p.neg()), None), "P + (-P)");
            assert!(ok(&p.add(&o), ap), "P + O");
            assert!(ok(&o.add(p), ap), "O + P");
            for q in &multiples {
                assert!(ok(&p.add(q), affine_add::<C>(ap, affine_of(q))), "P + Q");
                // An addition fed a non-normalised input, as a loop feeds it.
                let q2 = q.double().add(&q.neg());
                assert!(
                    ok(&p.add(&q2), affine_add::<C>(ap, affine_of(q))),
                    "P + (2Q - Q)"
                );
            }
            checked += 1;
        }
        assert!(
            ok_identity::<C>(&o.add(&o)) && ok_identity::<C>(&o.double()),
            "O + O, 2O"
        );
        checked
    }

    fn ok_identity<C: Curve>(p: &Point<C>) -> bool {
        bool::from(p.is_identity())
    }

    #[test]
    fn the_complete_formulas_agree_with_affine_arithmetic() {
        let checked = the_group_law_agrees_with_affine::<P256>()
            + the_group_law_agrees_with_affine::<P384>()
            + the_group_law_agrees_with_affine::<P521>();
        assert_eq!(checked, 36);
    }

    /// The scalars where the windowed loop's incomplete additions would go
    /// wrong if the argument in `mul_scalar` did not hold, and where its last,
    /// complete one is needed: `n - 1 .. n - 40` and `1 .. 40`, on the
    /// generator and another point, each against the ladder. The constant-time
    /// and variable-time multiplications, and the generator table, are all
    /// compared, since each has its own incomplete additions.
    fn edge_scalars_agree<C: Curve + HasGeneratorTable>() -> usize {
        let mut checked = 0;
        let mut small = C::Scalar::ZERO;
        let mut minus = C::Scalar::ZERO;
        for _ in 0..40 {
            small = small.add(&C::Scalar::ONE);
            minus = minus.sub(&C::Scalar::ONE);
            for k in [small, minus] {
                for p in [Point::<C>::generator(), some_point::<C>()] {
                    let want = p.mul_scalar_ladder(&k);
                    assert!(bool::from(p.mul_scalar(&k).ct_eq(&want)), "mul_scalar");
                    assert!(bool::from(p.mul_scalar_vartime(&k).ct_eq(&want)), "vartime");
                    checked += 1;
                }
                let g = Point::<C>::generator().mul_scalar_ladder(&k);
                assert!(bool::from(Point::<C>::mul_generator(&k).ct_eq(&g)), "table");
                assert!(
                    bool::from(Point::<C>::mul_generator_vartime(&k).ct_eq(&g)),
                    "table, variable time"
                );
            }
        }
        checked
    }

    /// A curve's own formulas against the field-operation ones, coordinate
    /// for coordinate and including `h` and `r`: on points with `Z` far from
    /// one, on the identity, and on `P + P` and `P + (-P)`, where the formulas
    /// are wrong in the same way and must still agree. On P-256 under x86-64
    /// with BMI2 and ADX these are the assembly; elsewhere both sides are the
    /// formula and the comparison is trivially true.
    fn own_formulas_agree<C: Curve>() -> usize {
        let same = |a: &Point<C>, b: &Point<C>| a.x == b.x && a.y == b.y && a.z == b.z;
        let mut points = std::vec![Point::<C>::identity(), Point::<C>::generator()];
        let mut p = some_point::<C>();
        for _ in 0..40 {
            points.push(p);
            p = p.double().add(&Point::generator());
        }
        let mut checked = 0;
        for a in &points {
            assert!(same(&a.double(), &a.double_formula()), "double");
            let affine = a.to_affine();
            for b in points.iter().chain([a.neg(), *a].iter()) {
                let (s1, h1, r1) = a.add_formula(b);
                let (s2, h2, r2) = a.add_formula_generic(b);
                assert!(same(&s1, &s2) && h1 == h2 && r1 == r2, "add");
                if let Some(q) = affine {
                    let (s1, h1, r1) = b.add_affine_formula(&q.x, &q.y);
                    let (s2, h2, r2) = b.add_affine_formula_generic(&q.x, &q.y);
                    assert!(same(&s1, &s2) && h1 == h2 && r1 == r2, "add_affine");
                }
                checked += 1;
            }
        }
        checked
    }

    /// The same comparison on arbitrary coordinates rather than curve points:
    /// the formulas are polynomials, so they agree on any input, and random
    /// field elements reach the reductions' edges -- a top word of every
    /// value in the small multiples, a sum just above `p` -- far more often
    /// than multiples of a point do. Coordinates near zero and near `p` are
    /// mixed in.
    #[test]
    fn own_point_formulas_agree_on_arbitrary_coordinates() {
        arbitrary_coordinates::<P256>();
        arbitrary_coordinates::<P384>();
    }

    fn arbitrary_coordinates<C: Curve>() {
        let mut state = 0x0b1d_u64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        type F<C> = <C as Curve>::Field;
        let edges = [
            F::<C>::ZERO,
            F::<C>::ONE,
            F::<C>::ONE.neg(),
            F::<C>::ONE.double().neg(),
        ];
        let mut field = |i: usize| -> F<C> {
            if i.is_multiple_of(7) {
                return edges[(i / 7) % edges.len()];
            }
            let mut bytes = F::<C>::zero_bytes();
            for chunk in bytes.as_mut().chunks_mut(8) {
                let word = next().to_be_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            F::<C>::from_bytes_reduced(&bytes)
        };
        let same = |a: &Point<C>, b: &Point<C>| a.x == b.x && a.y == b.y && a.z == b.z;
        for i in 0..50_000 {
            let p = Point::<C> {
                x: field(3 * i),
                y: field(3 * i + 1),
                z: field(3 * i + 2),
            };
            let q = Point::<C> {
                x: field(3 * i + 5),
                y: field(3 * i + 6),
                z: field(3 * i + 9),
            };
            assert!(same(&p.double(), &p.double_formula()), "double");
            let (s1, h1, r1) = p.add_formula(&q);
            let (s2, h2, r2) = p.add_formula_generic(&q);
            assert!(same(&s1, &s2) && h1 == h2 && r1 == r2, "add");
            let (s1, h1, r1) = p.add_affine_formula(&q.x, &q.y);
            let (s2, h2, r2) = p.add_affine_formula_generic(&q.x, &q.y);
            assert!(same(&s1, &s2) && h1 == h2 && r1 == r2, "add_affine");
        }
    }

    #[test]
    fn own_point_formulas_agree_with_the_field_operations() {
        #[cfg(target_arch = "x86_64")]
        std::println!(
            "P-256 point formulas in assembly: {}",
            crate::nist::p256_x86::has_adx()
        );
        let checked = own_formulas_agree::<P256>() + own_formulas_agree::<P384>();
        assert_eq!(checked, 2 * 42 * 44);
    }

    #[test]
    fn edge_scalars_agree_with_the_ladder() {
        let checked = edge_scalars_agree::<P256>()
            + edge_scalars_agree::<P384>()
            + edge_scalars_agree::<P521>();
        assert_eq!(checked, 3 * 160);
    }

    /// Random scalars, against the ladder, through every multiplication.
    #[test]
    fn random_scalars_agree_with_the_ladder() {
        fn run<C: Curve + HasGeneratorTable>(seed: u8) {
            let mut state = [seed; 66];
            for round in 0..24u8 {
                // A simple byte stream: enough to vary every digit.
                for (i, b) in state.iter_mut().enumerate() {
                    *b = b
                        .wrapping_mul(167)
                        .wrapping_add(round ^ (i as u8))
                        .rotate_left(3);
                }
                let mut bytes = C::Scalar::zero_bytes();
                let len = bytes.as_ref().len();
                bytes.as_mut().copy_from_slice(&state[..len]);
                let k = C::Scalar::from_bytes_reduced(&bytes);
                let p = some_point::<C>();
                let want = p.mul_scalar_ladder(&k);
                assert!(bool::from(p.mul_scalar(&k).ct_eq(&want)));
                assert!(bool::from(p.mul_scalar_vartime(&k).ct_eq(&want)));
                let g = Point::<C>::generator().mul_scalar_ladder(&k);
                assert!(bool::from(Point::<C>::mul_generator(&k).ct_eq(&g)));
                assert!(bool::from(Point::<C>::mul_generator_vartime(&k).ct_eq(&g)));
                let both = Point::<C>::mul_double(&k, &p, &k.square());
                let want2 = g.add(&p.mul_scalar_ladder(&k.square()));
                assert!(bool::from(both.ct_eq(&want2)));
            }
        }
        run::<P256>(1);
        run::<P384>(2);
        run::<P521>(3);
    }

    #[test]
    fn the_windowed_multiplication_agrees_with_the_ladder() {
        let checked = windowed_agrees_with_the_ladder::<P256>()
            + windowed_agrees_with_the_ladder::<P384>()
            + windowed_agrees_with_the_ladder::<P521>();
        assert!(checked >= 90, "only {checked} comparisons ran");
    }

    #[test]
    fn the_shared_doubling_verification_agrees() {
        let checked = shared_doublings_agree::<P256>()
            + shared_doublings_agree::<P384>()
            + shared_doublings_agree::<P521>();
        assert!(checked >= 90, "only {checked} comparisons ran");
    }
}
