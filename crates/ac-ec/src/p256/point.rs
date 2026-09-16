//! P-256 group arithmetic in Jacobian coordinates.
//!
//! A Jacobian point `(X : Y : Z)` represents the affine point
//! `(X/Z^2, Y/Z^3)`, with `Z = 0` reserved for the point at infinity. The
//! curve is `y^2 = x^3 - 3x + b`, and the `a = -3` doubling formula is what
//! makes the NIST curves efficient.
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

use super::arith::{Fn, Fp};
use ac_core::ct::Choice;

/// The curve coefficient `b`.
///
/// `b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b`
const B: Fp = Fp::to_mont([
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
]);

/// The base point x-coordinate.
const GX: Fp = Fp::to_mont([
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
]);

/// The base point y-coordinate.
const GY: Fp = Fp::to_mont([
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
]);

/// A point on P-256, in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: Fp,
    y: Fp,
    z: Fp,
}

/// A point in affine coordinates, as produced by decoding or normalization.
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    /// The x-coordinate.
    pub x: Fp,
    /// The y-coordinate.
    pub y: Fp,
}

impl Point {
    /// The point at infinity, the group identity.
    pub const IDENTITY: Point = Point {
        x: Fp::ONE,
        y: Fp::ONE,
        z: Fp::ZERO,
    };

    /// The standard base point `G`.
    pub const fn generator() -> Point {
        Point {
            x: GX,
            y: GY,
            z: Fp::ONE,
        }
    }

    /// Lift an affine point into Jacobian coordinates.
    pub const fn from_affine(p: &AffinePoint) -> Point {
        Point {
            x: p.x,
            y: p.y,
            z: Fp::ONE,
        }
    }

    /// Whether this is the point at infinity.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Point doubling (`dbl-2001-b`, specialized for `a = -3`).
    pub fn double(&self) -> Point {
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
    /// Also returns whether the inputs had equal `x` (`h == 0`) and equal `y`
    /// (`r == 0`), which [`Point::add`] uses to pick the right answer.
    fn add_raw(&self, other: &Point) -> (Point, Choice, Choice) {
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
    pub fn add(&self, other: &Point) -> Point {
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
        Self::cmov(&mut result, &Point::IDENTITY, opposite);
        // The identity cases are applied last so they take precedence: the
        // formula above produces nonsense when either input has Z = 0.
        Self::cmov(&mut result, self, other_inf);
        Self::cmov(&mut result, other, self_inf);
        result
    }

    /// Constant-time conditional move.
    #[inline]
    fn cmov(a: &mut Point, b: &Point, choice: Choice) {
        Fp::cmov(&mut a.x, &b.x, choice);
        Fp::cmov(&mut a.y, &b.y, choice);
        Fp::cmov(&mut a.z, &b.z, choice);
    }

    /// Point negation.
    pub fn neg(&self) -> Point {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Scalar multiplication, constant-time in the scalar.
    ///
    /// A fixed 256-iteration double-and-add-always ladder: every bit performs
    /// the same operations, and the conditional move decides whether the
    /// addition counts.
    pub fn mul_scalar(&self, scalar: &Fn) -> Point {
        let limbs = scalar.from_mont();
        let mut acc = Point::IDENTITY;
        for i in (0..4).rev() {
            for bit in (0..64).rev() {
                acc = acc.double();
                let sum = acc.add(self);
                let b = Choice::from_u8(((limbs[i] >> bit) & 1) as u8);
                Self::cmov(&mut acc, &sum, b);
            }
        }
        acc
    }

    /// `a*G + b*P`, for signature verification.
    ///
    /// Verification operates entirely on public values, so this makes no
    /// constant-time claim beyond what it inherits from the primitives.
    pub fn mul_double(a: &Fn, p: &Point, b: &Fn) -> Point {
        Point::generator().mul_scalar(a).add(&p.mul_scalar(b))
    }

    /// Convert to affine coordinates, or `None` for the identity.
    pub fn to_affine(&self) -> Option<AffinePoint> {
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
    pub fn ct_eq(&self, other: &Point) -> Choice {
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

impl AffinePoint {
    /// Whether this point satisfies `y^2 = x^3 - 3x + b`.
    pub fn is_on_curve(&self) -> Choice {
        let lhs = self.y.square();
        let rhs = self.x.square().mul(&self.x).sub(&self.x.triple()).add(&B);
        lhs.ct_eq(&rhs)
    }

    /// Encode in SEC1 uncompressed form: `0x04 || X || Y`.
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out[33..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// Encode in SEC1 compressed form: `0x02`/`0x03` || X`.
    pub fn to_compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = 0x02 | self.y.is_odd().unwrap_u8();
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// Decode a SEC1 point encoding, rejecting anything not on the curve.
    ///
    /// Accepts both the 65-byte uncompressed and the 33-byte compressed forms.
    /// The identity has no SEC1 encoding here, so it can never be decoded — a
    /// peer cannot force a shared secret by sending one.
    pub fn from_sec1(bytes: &[u8]) -> Option<AffinePoint> {
        match bytes.len() {
            65 if bytes[0] == 0x04 => {
                let mut xb = [0u8; 32];
                let mut yb = [0u8; 32];
                xb.copy_from_slice(&bytes[1..33]);
                yb.copy_from_slice(&bytes[33..]);
                let x = Fp::from_bytes(&xb)?;
                let y = Fp::from_bytes(&yb)?;
                let p = AffinePoint { x, y };
                bool::from(p.is_on_curve()).then_some(p)
            }
            33 if bytes[0] == 0x02 || bytes[0] == 0x03 => {
                let mut xb = [0u8; 32];
                xb.copy_from_slice(&bytes[1..]);
                let x = Fp::from_bytes(&xb)?;

                // y^2 = x^3 - 3x + b
                let y2 = x.square().mul(&x).sub(&x.triple()).add(&B);
                let y = y2.sqrt();
                // Squaring the candidate root is what detects a non-residue,
                // i.e. an x that is not on the curve at all.
                if y.square() != y2 {
                    return None;
                }
                // Pick the root whose parity matches the sign byte.
                let want_odd = Choice::from_u8(bytes[0] & 1);
                let flip = Choice::from_u8(y.is_odd().unwrap_u8() ^ want_odd.unwrap_u8());
                let mut chosen = y;
                Fp::cmov(&mut chosen, &y.neg(), flip);
                Some(AffinePoint { x, y: chosen })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(v: u64) -> Fn {
        Fn::to_mont([v, 0, 0, 0])
    }

    /// Validates B, GX, GY and the curve equation together: if any of the four
    /// constants were mistranscribed, the base point would not satisfy it.
    #[test]
    fn the_base_point_is_on_the_curve() {
        let g = Point::generator().to_affine().unwrap();
        assert!(bool::from(g.is_on_curve()));
    }

    /// Validates the group order n against the base point. This is the check
    /// that ties the scalar modulus to the curve.
    #[test]
    fn the_base_point_has_order_n() {
        // [n]G is the identity, so [n-1]G == -G.
        let n_minus_1 = Fn::ZERO.sub(&Fn::ONE);
        let p = Point::generator().mul_scalar(&n_minus_1);
        let neg_g = Point::generator().neg();
        assert!(bool::from(p.ct_eq(&neg_g)), "[n-1]G must equal -G");

        // And [n]G itself is the identity.
        let n_g = Point::generator()
            .mul_scalar(&n_minus_1)
            .add(&Point::generator());
        assert!(bool::from(n_g.is_identity()), "[n]G must be the identity");
    }

    #[test]
    fn identity_behaves_as_the_neutral_element() {
        let g = Point::generator();
        assert!(bool::from(g.add(&Point::IDENTITY).ct_eq(&g)));
        assert!(bool::from(Point::IDENTITY.add(&g).ct_eq(&g)));
        assert!(bool::from(
            Point::IDENTITY.add(&Point::IDENTITY).is_identity()
        ));
        assert!(bool::from(Point::IDENTITY.double().is_identity()));
        assert!(Point::IDENTITY.to_affine().is_none());
    }

    #[test]
    fn a_point_plus_its_negation_is_the_identity() {
        let g = Point::generator();
        assert!(bool::from(g.add(&g.neg()).is_identity()));
        let p = g.mul_scalar(&scalar(7));
        assert!(bool::from(p.add(&p.neg()).is_identity()));
    }

    /// The exceptional case that a naive Jacobian addition gets wrong.
    #[test]
    fn addition_handles_equal_inputs_as_a_doubling() {
        let g = Point::generator();
        assert!(bool::from(g.add(&g).ct_eq(&g.double())));

        let p = g.mul_scalar(&scalar(5));
        assert!(bool::from(p.add(&p).ct_eq(&p.double())));
    }

    #[test]
    fn scalar_multiplication_matches_repeated_addition() {
        let g = Point::generator();
        let mut acc = Point::IDENTITY;
        for k in 1..=10u64 {
            acc = acc.add(&g);
            let via_scalar = g.mul_scalar(&scalar(k));
            assert!(
                bool::from(acc.ct_eq(&via_scalar)),
                "[{k}]G by addition must match by scalar multiplication"
            );
        }
    }

    #[test]
    fn scalar_multiplication_is_linear() {
        let g = Point::generator();
        let a = scalar(1234567);
        let b = scalar(7654321);
        let lhs = g.mul_scalar(&a.add(&b));
        let rhs = g.mul_scalar(&a).add(&g.mul_scalar(&b));
        assert!(bool::from(lhs.ct_eq(&rhs)), "[a+b]G == [a]G + [b]G");

        // [a][b]G == [ab]G
        let lhs = g.mul_scalar(&a).mul_scalar(&b);
        let rhs = g.mul_scalar(&a.mul(&b));
        assert!(bool::from(lhs.ct_eq(&rhs)), "[a][b]G == [ab]G");
    }

    #[test]
    fn multiplication_by_zero_and_one() {
        let g = Point::generator();
        assert!(bool::from(g.mul_scalar(&Fn::ZERO).is_identity()));
        assert!(bool::from(g.mul_scalar(&Fn::ONE).ct_eq(&g)));
    }

    /// The published `[2]G` coordinates, an independent check on the group law
    /// rather than on self-consistency.
    #[test]
    fn two_g_matches_the_published_value() {
        let two_g = Point::generator().double().to_affine().unwrap();
        assert_eq!(
            ac_core::codec::hex(&two_g.x.to_bytes()),
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        );
        assert_eq!(
            ac_core::codec::hex(&two_g.y.to_bytes()),
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
        );
    }

    #[test]
    fn every_multiple_stays_on_the_curve() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 17, 255, 65537, u32::MAX as u64] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            assert!(bool::from(p.is_on_curve()), "[{k}]G is off the curve");
        }
    }

    #[test]
    fn sec1_uncompressed_round_trips() {
        let g = Point::generator().to_affine().unwrap();
        let encoded = g.to_uncompressed();
        assert_eq!(encoded[0], 0x04);
        let decoded = AffinePoint::from_sec1(&encoded).unwrap();
        assert_eq!(decoded.x, g.x);
        assert_eq!(decoded.y, g.y);
    }

    #[test]
    fn sec1_compressed_round_trips_for_both_parities() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 4, 5, 6, 7, 8] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            let encoded = p.to_compressed();
            assert!(encoded[0] == 0x02 || encoded[0] == 0x03);
            let decoded = AffinePoint::from_sec1(&encoded).unwrap();
            assert_eq!(decoded.x, p.x, "x for [{k}]G");
            assert_eq!(decoded.y, p.y, "y for [{k}]G");
        }
    }

    #[test]
    fn decoding_rejects_points_off_the_curve() {
        let g = Point::generator().to_affine().unwrap();

        // Corrupt the y-coordinate of an uncompressed encoding.
        let mut bad = g.to_uncompressed();
        bad[64] ^= 1;
        assert!(AffinePoint::from_sec1(&bad).is_none());

        // An x with no corresponding y. Roughly half of all x values are not
        // on the curve, so search for one that is definitely rejected.
        let mut rejected_one = false;
        for tweak in 1..32u8 {
            let mut probe = g.to_compressed();
            probe[32] = probe[32].wrapping_add(tweak);
            if AffinePoint::from_sec1(&probe).is_none() {
                rejected_one = true;
                break;
            }
        }
        assert!(rejected_one, "some tweaked x must be off the curve");
    }

    #[test]
    fn decoding_rejects_malformed_encodings() {
        let g = Point::generator().to_affine().unwrap();
        assert!(AffinePoint::from_sec1(&[]).is_none());
        assert!(AffinePoint::from_sec1(&[0x00]).is_none());
        // The identity encoding is not accepted.
        assert!(AffinePoint::from_sec1(&[0u8; 65]).is_none());
        // Wrong tag byte.
        let mut bad = g.to_uncompressed();
        bad[0] = 0x05;
        assert!(AffinePoint::from_sec1(&bad).is_none());
        // Truncated.
        assert!(AffinePoint::from_sec1(&bad[..64]).is_none());
        // Non-canonical coordinate (x = p).
        let mut bad = g.to_uncompressed();
        bad[1..33].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]);
        assert!(AffinePoint::from_sec1(&bad).is_none());
    }

    #[test]
    fn point_equality_distinguishes_correctly() {
        let g = Point::generator();
        let p = g.mul_scalar(&scalar(3));
        assert!(bool::from(p.ct_eq(&p)));
        assert!(!bool::from(p.ct_eq(&g)));
        assert!(!bool::from(p.ct_eq(&Point::IDENTITY)));
        assert!(!bool::from(Point::IDENTITY.ct_eq(&p)));
        assert!(bool::from(Point::IDENTITY.ct_eq(&Point::IDENTITY)));

        // Equality must see through a different projective representation.
        let scaled = g.double().add(&g);
        assert!(bool::from(scaled.ct_eq(&p)));
    }
}
