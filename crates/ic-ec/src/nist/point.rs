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
}

/// A point in Jacobian coordinates.
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
    pub fn double(&self) -> Self {
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
    /// Also reports whether the inputs had equal `x` (`h == 0`) and equal `y`
    /// (`r == 0`), which [`Point::add`] uses to pick the right answer.
    fn add_raw(&self, other: &Self) -> (Self, Choice, Choice) {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);

        let h = u2.sub(&u1);
        let r = s2.sub(&s1).double();

        let h_is_zero = h.is_zero();
        let r_is_zero = r.is_zero();

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
            h_is_zero,
            r_is_zero,
        )
    }

    /// The complete group law: correct for every pair of inputs.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, h_zero, r_zero) = self.add_raw(other);
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
    /// Four bits at a time. The scalar becomes signed radix-16 digits in
    /// `[-8, 8]`, `1..=8` times this point are computed once per call, and each
    /// digit selects one of them by reading all eight with conditional moves,
    /// then negates it or not the same way. Every scalar of a curve has the
    /// same digit count, and every digit costs four doublings, one selection
    /// and one addition, so the trace does not depend on the scalar.
    ///
    /// That is an addition per four bits where the double-and-add-always
    /// ladder it replaced had one per bit. ECDH is one of these, so this is
    /// most of its cost; under `no_std` it is also what multiplies the
    /// generator, since there is no stored table there. The window is eight
    /// points on the stack, freed on return.
    ///
    /// Correct only because [`Self::add`] is complete: a selected entry can be
    /// the identity, and the accumulator can equal the entry it is added to.
    pub fn mul_scalar(&self, scalar: &C::Scalar) -> Self {
        use super::gentable::{signed_digits, Window};

        let bytes = scalar.to_bytes();
        let bytes = bytes.as_ref();
        let digits = signed_digits(bytes);
        // Every nibble, plus the carry digit above them.
        let n = bytes.len() * 2 + 1;
        let window = Window::new(self);

        let mut acc = window.select(digits[n - 1]);
        for i in (0..n - 1).rev() {
            for _ in 0..4 {
                acc = acc.double();
            }
            acc = acc.add(&window.select(digits[i]));
        }
        acc
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
            odd[i] = odd[i - 1].add(&twice);
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
                    acc.add(entry)
                } else {
                    acc.add(&entry.negate())
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
        // Both halves are public here. The generator gets its table; the
        // other point gets the non-adjacent form.
        #[cfg(feature = "std")]
        {
            Self::mul_generator(a).add(&p.mul_scalar_vartime(b))
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
                odd[i] = odd[i - 1].add(&twice);
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
                        acc.add(entry)
                    } else {
                        acc.add(&entry.negate())
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
    /// caller takes the slow path by accident; `iron-crypto`'s
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

/// The generator table's accumulator, in homogeneous projective coordinates.
///
/// `(X : Y : Z)` is the affine point `(X/Z, Y/Z)`, and the identity is
/// `(0 : 1 : 0)`. The addition is Renes, Costello and Batina's complete formula
/// for prime-order curves with `a = -3` ("Complete addition formulas for prime
/// order elliptic curves", EUROCRYPT 2016), algorithm 4 with the second input's
/// `Z` fixed at one; the doubling is their algorithm 6.
///
/// # Why only here
///
/// [`Point`]'s Jacobian addition is not complete, so [`Point::add`] computes an
/// addition *and* a doubling and selects: 420 ns on P-256, against about 300
/// for these formulas. But its doubling is the cheaper one, 153 ns against
/// about 270. Moving every point to these formulas made the generator faster
/// and variable-base multiplication, four doublings per addition, slower -- 71
/// to 90 microseconds for ECDH. Measured, not guessed: see
/// `where_the_time_goes` in `p256.rs`.
///
/// So each is used where it wins. The generator table does 65 additions and
/// four doublings for P-256, and its entries are stored affine, so this adds
/// them with `Z2 = 1` and saves a multiplication more. Everything else stays
/// Jacobian.
///
/// Behind `std`, as the table is.
#[cfg(feature = "std")]
pub(super) struct Projective<C: Curve> {
    x: C::Field,
    y: C::Field,
    z: C::Field,
}

#[cfg(feature = "std")]
impl<C: Curve> Clone for Projective<C> {
    fn clone(&self) -> Self {
        *self
    }
}
#[cfg(feature = "std")]
impl<C: Curve> Copy for Projective<C> {}

#[cfg(feature = "std")]
impl<C: Curve> Projective<C> {
    /// The point at infinity, `(0 : 1 : 0)`.
    pub(super) fn identity() -> Self {
        Projective {
            x: C::Field::ZERO,
            y: C::Field::ONE,
            z: C::Field::ZERO,
        }
    }

    /// Doubling: algorithm 6, complete. The step numbers are the paper's.
    pub(super) fn double(&self) -> Self {
        let b = C::B;
        let (x, y, z) = (self.x, self.y, self.z);
        let t0 = x.square(); // 1
        let t1 = y.square(); // 2
        let t2 = z.square(); // 3
        let t3 = x.mul(&y); // 4
        let t3 = t3.add(&t3); // 5
        let z3 = x.mul(&z); // 6
        let z3 = z3.add(&z3); // 7
        let y3 = b.mul(&t2); // 8
        let y3 = y3.sub(&z3); // 9
        let x3 = y3.add(&y3); // 10
        let y3 = x3.add(&y3); // 11
        let x3 = t1.sub(&y3); // 12
        let y3 = t1.add(&y3); // 13
        let y3 = x3.mul(&y3); // 14
        let x3 = x3.mul(&t3); // 15
        let t3 = t2.add(&t2); // 16
        let t2 = t2.add(&t3); // 17
        let z3 = b.mul(&z3); // 18
        let z3 = z3.sub(&t2); // 19
        let z3 = z3.sub(&t0); // 20
        let t3 = z3.add(&z3); // 21
        let z3 = z3.add(&t3); // 22
        let t3 = t0.add(&t0); // 23
        let t0 = t3.add(&t0); // 24
        let t0 = t0.sub(&t2); // 25
        let t0 = t0.mul(&z3); // 26
        let y3 = y3.add(&t0); // 27
        let t0 = y.mul(&z); // 28
        let t0 = t0.add(&t0); // 29
        let z3 = t0.mul(&z3); // 30
        let x3 = x3.sub(&z3); // 31
        let z3 = t0.mul(&t1); // 32
        let z3 = z3.add(&z3); // 33
        let z3 = z3.add(&z3); // 34
        Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + (x2, y2)`, for an affine point that is not the identity.
    ///
    /// Algorithm 4 with `Z2 = 1`, which the step numbers follow. Three steps
    /// change: step 3's `Z1*Z2` is `Z1`; steps 9-13, `(Y1+Z1)(Y2+Z2) - Y1*Y2 -
    /// Z1*Z2`, are `Y2*Z1 + Y1`; steps 14-18 likewise are `X2*Z1 + X1`. That is
    /// one multiplication fewer than algorithm 4, and still complete in `self`:
    /// the identity, `(x2, y2)` itself and its negation all add correctly. The
    /// caller handles an identity *second* operand, which has no affine form.
    pub(super) fn add_affine(&self, x2: &C::Field, y2: &C::Field) -> Self {
        let b = C::B;
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let t0 = x1.mul(x2); // 1
        let t1 = y1.mul(y2); // 2
        let t2 = z1; // 3
        let t3 = x1.add(&y1); // 4
        let t4 = x2.add(y2); // 5
        let t3 = t3.mul(&t4); // 6
        let t4 = t0.add(&t1); // 7
        let t3 = t3.sub(&t4); // 8
        let t4 = y2.mul(&z1).add(&y1); // 9-13
        let y3 = x2.mul(&z1).add(&x1); // 14-18
        let z3 = b.mul(&t2); // 19
        let x3 = y3.sub(&z3); // 20
        let z3 = x3.add(&x3); // 21
        let x3 = x3.add(&z3); // 22
        let z3 = t1.sub(&x3); // 23
        let x3 = t1.add(&x3); // 24
        let y3 = b.mul(&y3); // 25
        let t1 = t2.add(&t2); // 26
        let t2 = t1.add(&t2); // 27
        let y3 = y3.sub(&t2); // 28
        let y3 = y3.sub(&t0); // 29
        let t1 = y3.add(&y3); // 30
        let y3 = t1.add(&y3); // 31
        let t1 = t0.add(&t0); // 32
        let t0 = t1.add(&t0); // 33
        let t0 = t0.sub(&t2); // 34
        let t1 = t4.mul(&y3); // 35
        let t2 = t0.mul(&y3); // 36
        let y3 = x3.mul(&z3); // 37
        let y3 = y3.add(&t2); // 38
        let x3 = t3.mul(&x3); // 39
        let x3 = x3.sub(&t1); // 40
        let z3 = t4.mul(&z3); // 41
        let t1 = t3.mul(&t0); // 42
        let z3 = z3.add(&t1); // 43
        Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Constant-time conditional move.
    #[inline]
    pub(super) fn cmov(a: &mut Self, b: &Self, choice: Choice) {
        C::Field::cmov(&mut a.x, &b.x, choice);
        C::Field::cmov(&mut a.y, &b.y, choice);
        C::Field::cmov(&mut a.z, &b.z, choice);
    }

    /// The same point in Jacobian coordinates: `(X*Z : Y*Z^2 : Z)`, since
    /// `X*Z / Z^2 = X/Z` and `Y*Z^2 / Z^3 = Y/Z`. The identity maps to
    /// [`Point::identity`] by a conditional move, not a branch.
    pub(super) fn to_jacobian(self) -> Point<C> {
        let mut out = Point {
            x: self.x.mul(&self.z),
            y: self.y.mul(&self.z.square()),
            z: self.z,
        };
        Point::cmov(&mut out, &Point::identity(), self.z.is_zero());
        out
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

    /// The generator table's projective accumulator against the same
    /// reference: the identity on the left, a point plus itself and plus its
    /// negative, distinct points, accumulators that are not normalized, and
    /// doubling -- every case its loop can reach. The identity on the right
    /// has no affine form and is the caller's; `Table::mul` is tested against
    /// `mul_scalar` for that, with zero digits.
    fn the_projective_accumulator_agrees_with_affine<C: Curve>() -> usize {
        let g = Point::<C>::generator();
        let mut multiples = std::vec::Vec::new();
        let mut acc = None;
        for _ in 0..12 {
            acc = affine_add::<C>(acc, affine_of(&g));
            multiples.push(acc.unwrap());
        }
        let o = Projective::<C>::identity();
        let ok = |got: &Projective<C>, want: Option<(C::Field, C::Field)>| match (
            affine_of(&got.to_jacobian()),
            want,
        ) {
            (None, None) => true,
            (Some((a, b)), Some((c, d))) => bool::from(a.ct_eq(&c).and(b.ct_eq(&d))),
            _ => false,
        };
        let mut checked = 0;
        for &(px, py) in &multiples {
            let p = o.add_affine(&px, &py);
            let ap = Some((px, py));
            assert!(ok(&p, ap), "O + P");
            // P again, with Z far from one: 2P - P.
            let p_far = p.double().add_affine(&px, &py.neg());
            assert!(ok(&p_far, ap), "2P - P");
            for p in [p, p_far] {
                assert!(
                    ok(&p.add_affine(&px, &py), affine_add::<C>(ap, ap)),
                    "P + P"
                );
                assert!(ok(&p.double(), affine_add::<C>(ap, ap)), "2P");
                assert!(ok(&p.add_affine(&px, &py.neg()), None), "P + (-P)");
                for &(qx, qy) in &multiples {
                    assert!(
                        ok(&p.add_affine(&qx, &qy), affine_add::<C>(ap, Some((qx, qy)))),
                        "P + Q"
                    );
                }
            }
            checked += 1;
        }
        assert!(ok(&o, None) && ok(&o.double(), None), "O, 2O");
        checked
    }

    #[test]
    fn the_projective_accumulator_agrees_with_affine_arithmetic() {
        let checked = the_projective_accumulator_agrees_with_affine::<P256>()
            + the_projective_accumulator_agrees_with_affine::<P384>()
            + the_projective_accumulator_agrees_with_affine::<P521>();
        assert_eq!(checked, 36);
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
