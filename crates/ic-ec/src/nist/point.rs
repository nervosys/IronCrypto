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

    /// Constant-time conditional move.
    #[inline]
    fn cmov(a: &mut Self, b: &Self, choice: Choice) {
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
    /// A fixed double-and-add-always ladder over the full scalar width: every
    /// bit performs the same operations, and the conditional move decides
    /// whether the addition counts.
    pub fn mul_scalar(&self, scalar: &C::Scalar) -> Self {
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

    /// `a*G + b*P`, for signature verification.
    ///
    /// Verification operates entirely on public values, so this makes no
    /// constant-time claim beyond what it inherits from the primitives.
    pub fn mul_double(a: &C::Scalar, p: &Self, b: &C::Scalar) -> Self {
        Self::generator().mul_scalar(a).add(&p.mul_scalar(b))
    }

    /// Convert to affine coordinates, or `None` for the identity.
    pub fn to_affine(&self) -> Option<AffinePoint<C>> {
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
