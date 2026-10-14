//! `a*G + b*Q` for ECDSA verification: **variable time, public inputs only**.
//!
//! Verification computes `u1*G + u2*Q` from the signature, the message
//! digest and the public key, all of which an attacker already has, so
//! nothing here needs to hide its timing, and it does not: the scalars are
//! recoded into non-adjacent forms whose length and digit pattern depend on
//! their values, the tables are read by index, the additions branch on their
//! exceptional cases, and the loop skips what it can. Nothing that touches a
//! secret -- signing, ECDH, key generation -- may call anything in this
//! module or [`super::verify_x86`]; every function here that is not obviously
//! so says `vartime` in its name.
//!
//! # The shape
//!
//! One chain of doublings, shared by both scalars (Straus). `u2*Q` is a
//! width-5 non-adjacent form against `Q, 3Q, .., 15Q`, made affine with one
//! inversion for all eight; `u1*G` is a width-8 non-adjacent form against
//! `G, 3G, .., 127G`, affine, built once per process and kept in a `static`
//! beside the generator table ([`super::gentable::HasGeneratorTable`]).
//! Every addition is the mixed one, an affine entry into the Jacobian
//! accumulator.
//!
//! What it replaced ran the two halves apart: `u1*G` from the signing table,
//! one mixed addition per six bits and no doublings, and `u2*Q` by its own
//! chain of doublings with Jacobian additions. On P-256 that is 43 mixed
//! additions for `G`; here, inside the doublings `Q` needs anyway, a
//! width-8 recoding costs one per nine bits, about 29, and `Q`'s 43 or so
//! additions become mixed ones. On P-384 it is 77 against about 43 for `G`.
//!
//! Where the curve has one, [`Curve::mul_double_vartime_fast`] runs the
//! chain; on x86-64 with BMI2 and ADX that is the formulas' assembly on one
//! buffer ([`super::verify_x86`]), with the doublings in place.

use super::arith::Field;
use super::gentable::HasGeneratorTable;
use super::point::{wnaf_vartime, AffinePoint, Curve, Point};

/// The width of `u1`'s non-adjacent form against the generator's table.
pub(crate) const G_WIDTH: u32 = 8;

/// Odd multiples of `G` kept: `1, 3, .., 2^(G_WIDTH-1) - 1` times `G`.
pub const G_ODD: usize = 1 << (G_WIDTH - 2);

/// The width of `u2`'s non-adjacent form against the public key's table.
pub(crate) const Q_WIDTH: u32 = 5;

/// Odd multiples of `Q` built per verification: `1, 3, .., 15` times `Q`.
pub(crate) const Q_ODD: usize = 1 << (Q_WIDTH - 2);

/// `base, 3*base, .., (2K-1)*base`, affine. **Variable time**, public
/// points only: the additions branch on their cases.
///
/// `base` must not be the identity, and its order must exceed `2K - 1`, so
/// that no multiple is the identity; every point of a NIST prime curve but
/// the identity has prime order `n`, far above that.
pub(crate) fn odd_multiples_affine_vartime<C: Curve, const K: usize>(
    base: &Point<C>,
) -> [AffinePoint<C>; K] {
    let twice = base.double();
    let mut points = [*base; K];
    for i in 1..K {
        points[i] = points[i - 1].add_vartime(&twice);
    }
    normalize_vartime(&points)
}

/// Every point of `points` affine, with one inversion for all of them
/// (Montgomery's trick). None may be the identity.
fn normalize_vartime<C: Curve, const K: usize>(points: &[Point<C>; K]) -> [AffinePoint<C>; K] {
    let mut prefix = [C::Field::ONE; K];
    let mut acc = C::Field::ONE;
    for (p, point) in prefix.iter_mut().zip(points.iter()) {
        *p = acc;
        acc = acc.mul(&point.z());
    }
    let mut inv = acc.invert();
    let mut out = [AffinePoint {
        x: C::Field::ZERO,
        y: C::Field::ZERO,
    }; K];
    for i in (0..K).rev() {
        let z_inv = inv.mul(&prefix[i]);
        inv = inv.mul(&points[i].z());
        let z_inv2 = z_inv.square();
        out[i] = AffinePoint {
            x: points[i].x().mul(&z_inv2),
            y: points[i].y().mul(&z_inv2.mul(&z_inv)),
        };
    }
    out
}

/// `a*G + b*p`, **variable time** in everything: for verification, where
/// `a`, `b` and `p` are public.
pub(crate) fn mul_double_vartime<C: HasGeneratorTable>(
    a: &C::Scalar,
    p: &Point<C>,
    b: &C::Scalar,
) -> Point<C> {
    // The identity has no affine multiples. A decoded public key is never
    // the identity, but `Point::mul_double` is public.
    if bool::from(p.is_identity()) {
        return Point::mul_generator_vartime(a);
    }
    let g = C::odd_generator_multiples();
    let q: [AffinePoint<C>; Q_ODD] = odd_multiples_affine_vartime(p);
    let (a_bytes, b_bytes) = (a.to_bytes(), b.to_bytes());
    let (g_naf, g_len) = wnaf_vartime(a_bytes.as_ref(), G_WIDTH);
    let (q_naf, q_len) = wnaf_vartime(b_bytes.as_ref(), Q_WIDTH);
    let len = g_len.max(q_len);
    let (g_naf, q_naf) = (&g_naf[..len], &q_naf[..len]);
    if let Some(r) = C::mul_double_vartime_fast(g, &q, g_naf, q_naf) {
        return r;
    }
    joint_vartime(g, &q, g_naf, q_naf)
}

/// The shared chain in field operations, which
/// [`Curve::mul_double_vartime_fast`] must match: the sum over `i` of
/// `g_naf[i] * 2^i * G + q_naf[i] * 2^i * Q`, with `g` and `q` the odd
/// multiples, entry `k` being `(2k + 1)` times the point. The two forms must
/// be the same length. **Variable time.**
pub(crate) fn joint_vartime<C: Curve>(
    g: &[AffinePoint<C>],
    q: &[AffinePoint<C>],
    g_naf: &[i8],
    q_naf: &[i8],
) -> Point<C> {
    debug_assert_eq!(g_naf.len(), q_naf.len());
    let mut acc = Point::identity();
    // Doubling the identity is the identity: skipped until the first digit.
    let mut started = false;
    for i in (0..g_naf.len()).rev() {
        if started {
            acc = acc.double();
        }
        for (naf, table) in [(g_naf, g), (q_naf, q)] {
            let digit = naf[i];
            if digit != 0 {
                let entry = &table[(digit.unsigned_abs() >> 1) as usize];
                let y = if digit > 0 { entry.y } else { entry.y.neg() };
                acc = acc.add_affine_vartime(&entry.x, &y);
                started = true;
            }
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256::P256;
    use crate::p384::P384;
    use crate::p521::P521;

    /// A deterministic stream of scalars: the edges, then `count`
    /// pseudo-random ones, bytes reduced into the ring.
    fn scalars<C: Curve>(count: usize) -> std::vec::Vec<C::Scalar> {
        let one = C::Scalar::ONE;
        let minus_one = C::Scalar::ZERO.sub(&one);
        let two = one.add(&one);
        let mut out = std::vec![C::Scalar::ZERO, one, two, minus_one, minus_one.sub(&one)];
        // 2^k and 2^k - 1 for a spread of k: long runs of zeros and ones,
        // where a recoding's carries go furthest.
        let mut p = one;
        for k in 0..C::ORDER_BITS {
            if k % 37 == 0 || k + 3 >= C::ORDER_BITS {
                out.push(p);
                out.push(p.sub(&one));
                out.push(p.neg());
            }
            p = p.add(&p);
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut bytes = std::vec![0u8; C::SCALAR_BYTES];
        let target = out.len() + count;
        while out.len() < target {
            for b in bytes.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            out.push(C::scalar_reduce_slice(&bytes));
        }
        out
    }

    /// `a*G + b*Q` in constant-time arithmetic that shares nothing with the
    /// code under test: the generator's comb, the windowed ladder, the
    /// complete addition.
    fn reference<C: HasGeneratorTable>(a: &C::Scalar, q: &Point<C>, b: &C::Scalar) -> Point<C> {
        Point::mul_generator(a).add(&q.mul_scalar(b))
    }

    /// The new chain, on whichever backend runs, and the field-operation
    /// chain, against the reference and against the separate-chain code it
    /// replaced, over edge and random scalars and points: `Q = G`,
    /// `Q = -G`, `u1 = u2`, `u1 = -u2`, and so on.
    fn agrees<C: HasGeneratorTable>(count: usize) {
        let ks = scalars::<C>(count);
        let g = Point::<C>::generator();
        let mut points = std::vec![g, g.neg(), g.double(), g.double().neg()];
        for k in ks.iter().skip(ks.len() - 3) {
            points.push(Point::mul_generator(k));
        }
        for (i, q) in points.iter().enumerate() {
            // Every point against `count` of the scalars, offset per point so
            // that the edges and the random ones all come round.
            let offset = (i * count) % ks.len();
            for (j, a) in ks.iter().enumerate().cycle().skip(offset).take(count) {
                // Every scalar against a few others, itself and its negation
                // among them.
                let b_list = [
                    *a,
                    a.neg(),
                    ks[(j * 7 + i) % ks.len()],
                    ks[(j + 1) % ks.len()],
                ];
                for b in b_list {
                    let want = reference::<C>(a, q, &b);
                    let got = mul_double_vartime::<C>(a, q, &b);
                    assert!(bool::from(got.ct_eq(&want)), "{} a={a:?} b={b:?}", C::NAME);
                    let old = Point::<C>::mul_double_vartime(&g, a, q, &b);
                    assert!(bool::from(old.ct_eq(&want)), "old chain");

                    // The field-operation chain, which the fast one must match.
                    let gt = C::odd_generator_multiples();
                    let qt: [AffinePoint<C>; Q_ODD] = odd_multiples_affine_vartime(q);
                    let (ab, bb) = (a.to_bytes(), b.to_bytes());
                    let (gn, gl) = wnaf_vartime(ab.as_ref(), G_WIDTH);
                    let (qn, ql) = wnaf_vartime(bb.as_ref(), Q_WIDTH);
                    let len = gl.max(ql);
                    let generic = joint_vartime(gt, &qt, &gn[..len], &qn[..len]);
                    assert!(bool::from(generic.ct_eq(&want)), "generic chain");
                }
            }
        }
        // The identity as `Q`, which takes the generator alone.
        for a in ks.iter().take(8) {
            let id = Point::<C>::identity();
            let got = mul_double_vartime::<C>(a, &id, &ks[3]);
            assert!(bool::from(got.ct_eq(&Point::mul_generator(a))));
        }
    }

    #[test]
    fn the_joint_chain_agrees_with_the_constant_time_arithmetic() {
        agrees::<P256>(40);
        agrees::<P384>(16);
        agrees::<P521>(6);
    }

    /// The odd multiples are what they say: entry `k` is `(2k + 1) * G`.
    #[test]
    fn the_generator_table_holds_odd_multiples() {
        fn check<C: HasGeneratorTable>() {
            let t = C::odd_generator_multiples();
            let g = Point::<C>::generator();
            let mut want = g;
            let twice = g.double();
            for (k, entry) in t.iter().enumerate() {
                assert!(
                    bool::from(Point::from_affine(entry).ct_eq(&want)),
                    "{} entry {k}",
                    C::NAME
                );
                want = want.add(&twice);
            }
        }
        check::<P256>();
        check::<P384>();
        check::<P521>();
    }

    /// The recoding read in place with a carry is the recoding by
    /// subtraction it replaced, digit for digit and in length, at every
    /// width from 2 to 8 and every scalar width here, on unreduced bytes too:
    /// all ones, which carries out of the top, single bits, runs, and
    /// pseudo-random strings.
    #[test]
    fn the_carry_recoding_is_the_subtraction_recoding() {
        use crate::nist::point::wnaf_by_subtraction;
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for len in [32usize, 48, 66, 5, 1] {
            let mut cases = std::vec![
                std::vec![0u8; len],
                std::vec![0xff; len],
                std::vec![0x80; len]
            ];
            for i in 0..len * 8 {
                let mut b = std::vec![0u8; len];
                b[len - 1 - i / 8] = 1 << (i % 8);
                cases.push(b.clone());
                // Ones from bit i down.
                for (j, x) in b.iter_mut().enumerate() {
                    let lo = (len - 1 - j) * 8;
                    for bit in 0..8 {
                        if lo + bit <= i {
                            *x |= 1 << bit;
                        }
                    }
                }
                cases.push(b);
            }
            for _ in 0..300 {
                let mut b = std::vec![0u8; len];
                for x in b.iter_mut() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *x = (state >> 24) as u8;
                }
                cases.push(b);
            }
            for bytes in &cases {
                for w in 2..=8 {
                    let (got, got_len) = wnaf_vartime(bytes, w);
                    let (want, want_len) = wnaf_by_subtraction(bytes, w);
                    assert_eq!(got_len, want_len, "{bytes:02x?} width {w}");
                    assert!(got == want, "{bytes:02x?} width {w}");
                }
            }
        }
    }

    /// The recoding sums back to the scalar, at every width used, with each
    /// digit odd and in range and `w - 1` zeros after each non-zero one.
    #[test]
    fn the_non_adjacent_forms_sum_to_the_scalar() {
        fn check<C: Curve>() {
            for k in scalars::<C>(64) {
                let bytes = k.to_bytes();
                for w in [Q_WIDTH, G_WIDTH] {
                    let (naf, len) = wnaf_vartime(bytes.as_ref(), w);
                    let bound = (1i16 << (w - 1)) - 1;
                    let mut last: Option<usize> = None;
                    // Horner from the top, in the scalar ring.
                    let mut sum = C::Scalar::ZERO;
                    for i in (0..len).rev() {
                        sum = sum.add(&sum);
                        let d = naf[i] as i16;
                        if d != 0 {
                            assert!(d % 2 != 0 && -bound <= d && d <= bound, "digit {d}");
                            if let Some(j) = last {
                                assert!(j - i >= w as usize, "digits {j} and {i} at width {w}");
                            }
                            last = Some(i);
                            let mut m = C::Scalar::ZERO;
                            for _ in 0..d.unsigned_abs() {
                                m = m.add(&C::Scalar::ONE);
                            }
                            sum = if d > 0 { sum.add(&m) } else { sum.sub(&m) };
                        }
                    }
                    assert!(naf[len..].iter().all(|d| *d == 0));
                    assert!(sum == k, "{} width {w}", C::NAME);
                }
            }
        }
        check::<P256>();
        check::<P384>();
    }
}
