//! Rounding and hints: FIPS 204 algorithms 35 through 40.
//!
//! ML-DSA splits coefficients into a high part that travels and a low part that
//! does not. Verification then has to reconstruct the high part from a value
//! that differs slightly from the one the signer used, and a one-bit *hint* per
//! coefficient is what bridges the gap. These six functions are that machinery.
//!
//! # Why this can be checked without a single published vector
//!
//! Every function here is pinned by an equation rather than by a table, and the
//! equations are strong enough to leave no freedom:
//!
//! - [`power2round`] and [`decompose`] are each *defined* by "the unique pair
//!   summing back to the input with the low part in range". Assert both halves
//!   and the function has no room to be wrong — there is exactly one answer.
//! - [`make_hint`] and [`use_hint`] are defined by the lemma
//!   `UseHint(MakeHint(z, r), r + z) == HighBits(r)` for `|z| <= gamma2`, which
//!   is the property the scheme actually relies on. It is also what would break
//!   first if either function were subtly wrong.
//!
//! So unlike the samplers and the encodings, nothing here is `experimental` for
//! want of a file. A vector could only confirm what the equations already fix.
//! What a vector *would* still catch is a misreading of the convention shared
//! with the rest of the scheme — which representative `mod±` picks, say — so
//! this is verified, not infallible.
//!
//! # Timing
//!
//! These branch on their inputs. That is safe here because of *what* they are
//! applied to: `power2round` splits the public key `t`, and `decompose` and the
//! hints operate on the commitment `w` and on values the signature publishes.
//! None of it is secret. The branch on `r - r0 == q - 1` in [`decompose`] is
//! the one genuine edge case in the design and is left visible rather than
//! folded into a mask, because an unreadable line here would be worse than a
//! readable one.

use crate::poly::{Poly, N, Q};

/// Dropped bits in the public key, `d` in FIPS 204. The same for every
/// parameter set.
pub const D: u32 = 13;

/// `gamma2` for ML-DSA-44: `(q - 1) / 88`.
pub const GAMMA2_88: i32 = (Q - 1) / 88;

/// `gamma2` for ML-DSA-65 and ML-DSA-87: `(q - 1) / 32`.
pub const GAMMA2_32: i32 = (Q - 1) / 32;

/// The centered representative of `r mod a`, in `(-a/2, a/2]`.
///
/// FIPS 204 writes this `mod±`. Both callers need it and the choice of
/// half-open end matters, so it is one function rather than two open-coded
/// conventions that could drift apart.
fn mod_pm(r: i32, a: i32) -> i32 {
    let r = r.rem_euclid(a);
    if r > a / 2 {
        r - a
    } else {
        r
    }
}

/// FIPS 204 Algorithm 35. Split `r` into `(r1, r0)` with `r = r1*2^d + r0`.
///
/// `r0` is the centered low `d` bits, so it lands in `(-2^(d-1), 2^(d-1)]`.
/// This is what lets the public key ship only `r1` and the signer keep `r0`.
pub fn power2round(r: i32) -> (i32, i32) {
    let r = r.rem_euclid(Q);
    let r0 = mod_pm(r, 1 << D);
    ((r - r0) >> D, r0)
}

/// FIPS 204 Algorithm 36. Split `r` into `(r1, r0)` around a multiple of
/// `2*gamma2`.
///
/// The special case is real and not defensive: when `r - r0` reaches `q - 1`
/// there is no bucket `(q-1)/(2*gamma2)` to put it in, since the buckets are
/// numbered `0` through `(q-1)/(2*gamma2) - 1`. Folding it to bucket zero and
/// paying for it in `r0` keeps the high part inside its declared range, which
/// is what the encoding's bit width assumes.
///
/// # The bound on `r0` is closed, not open
///
/// Away from that fold, `r0` is a `mod±` representative and lands in
/// `(-gamma2, gamma2]`. The fold subtracts one more, so across the whole domain
/// the correct statement is `|r0| <= gamma2` — closed at *both* ends. The
/// difference is one value at one input and it is easy to write the tighter
/// bound by mistake; the tests here assert the closed bound and separately pin
/// down exactly where the open one fails, so the distinction cannot be lost.
///
/// This matters beyond pedantry: `gamma2` is also the bound under which
/// [`make_hint`] is guaranteed to work, and ML-DSA's rejection conditions are
/// stated against `gamma2 - beta`. A bound believed to be one tighter than it
/// is would put those comparisons off by one.
pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;
    let r = r.rem_euclid(Q);
    let r0 = mod_pm(r, alpha);
    if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / alpha, r0)
    }
}

/// FIPS 204 Algorithm 37. The high part of [`decompose`].
pub fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// FIPS 204 Algorithm 38. The low part of [`decompose`].
///
/// Bounded by `|low_bits(r)| <= gamma2`, closed at both ends — see
/// [`decompose`] for why the lower end is not strict.
pub fn low_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

/// FIPS 204 Algorithm 39. Does adding `z` to `r` carry into the high bits?
///
/// One bit, and the whole point of the hint mechanism: the verifier cannot
/// compute `z`, but it can be told, in one bit per coefficient, whether `z`
/// would have moved the bucket.
#[must_use]
pub fn make_hint(z: i32, r: i32, gamma2: i32) -> bool {
    high_bits(r, gamma2) != high_bits((r + z).rem_euclid(Q), gamma2)
}

/// FIPS 204 Algorithm 40. Recover the high bits using the hint.
///
/// The direction of the correction comes from the sign of the low part: if `r0`
/// is positive the true value sat above this bucket, so step up, and otherwise
/// step down. The wrap is modulo the *bucket count*, not modulo `q`.
pub fn use_hint(hint: bool, r: i32, gamma2: i32) -> i32 {
    let buckets = (Q - 1) / (2 * gamma2);
    let (r1, r0) = decompose(r, gamma2);
    if !hint {
        return r1;
    }
    if r0 > 0 {
        (r1 + 1).rem_euclid(buckets)
    } else {
        (r1 - 1).rem_euclid(buckets)
    }
}

/// How many buckets `high_bits` can return for a given `gamma2`.
///
/// The encoding needs this to choose a bit width, and getting it from the same
/// expression `use_hint` wraps by means the two cannot disagree.
pub const fn bucket_count(gamma2: i32) -> i32 {
    (Q - 1) / (2 * gamma2)
}

/// [`power2round`] over a whole polynomial, giving `(t1, t0)`.
pub fn power2round_poly(p: &Poly) -> (Poly, Poly) {
    let mut hi = Poly::ZERO;
    let mut lo = Poly::ZERO;
    for i in 0..N {
        let (a, b) = power2round(p.c[i]);
        hi.c[i] = a;
        lo.c[i] = b;
    }
    (hi, lo)
}

/// [`decompose`] over a whole polynomial, giving `(w1, w0)`.
pub fn decompose_poly(p: &Poly, gamma2: i32) -> (Poly, Poly) {
    let mut hi = Poly::ZERO;
    let mut lo = Poly::ZERO;
    for i in 0..N {
        let (a, b) = decompose(p.c[i], gamma2);
        hi.c[i] = a;
        lo.c[i] = b;
    }
    (hi, lo)
}

/// [`make_hint`] over a whole polynomial, returning the hints and their weight.
///
/// The count is returned because ML-DSA caps the total number of set hints at
/// `omega` across the whole vector and restarts signing when it is exceeded.
/// A caller that had to recount would be a caller that could forget to.
pub fn make_hint_poly(z: &Poly, r: &Poly, gamma2: i32) -> ([bool; N], usize) {
    let mut hints = [false; N];
    let mut weight = 0;
    for ((h, zi), ri) in hints.iter_mut().zip(z.c.iter()).zip(r.c.iter()) {
        *h = make_hint(*zi, *ri, gamma2);
        if *h {
            weight += 1;
        }
    }
    (hints, weight)
}

/// [`use_hint`] over a whole polynomial.
pub fn use_hint_poly(hints: &[bool; N], r: &Poly, gamma2: i32) -> Poly {
    let mut out = Poly::ZERO;
    for ((o, h), ri) in out.c.iter_mut().zip(hints.iter()).zip(r.c.iter()) {
        *o = use_hint(*h, *ri, gamma2);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic generator, so failures reproduce exactly.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // SplitMix64. Only needs to spread inputs around, not resist anything.
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: i32) -> i32 {
            (self.next() % (n as u64)) as i32
        }
    }

    /// Inputs worth trying: dense near every bucket edge, plus a sweep.
    ///
    /// Stride sampling alone would step straight over the boundaries, which is
    /// where every off-by-one in this file would live.
    fn interesting(gamma2: i32) -> Vec<i32> {
        let alpha = 2 * gamma2;
        let mut v = Vec::new();
        for bucket in 0..=bucket_count(gamma2) {
            let base = bucket * alpha;
            for delta in -3..=3 {
                let r = base + delta;
                if (0..Q).contains(&r) {
                    v.push(r);
                }
            }
            for delta in -3..=3 {
                let r = base + gamma2 + delta;
                if (0..Q).contains(&r) {
                    v.push(r);
                }
            }
        }
        // The q-1 special case and its neighbourhood.
        for r in (Q - 8)..Q {
            v.push(r);
        }
        // The low end at stride one, then the whole range coarsely.
        v.extend(0..4096);
        v.extend((0..Q).step_by(9973));
        v
    }

    /// `power2round` is *defined* by these two facts, so asserting both leaves
    /// the function no freedom at all: exactly one pair satisfies them.
    #[test]
    fn power2round_is_pinned_by_its_definition() {
        let half = 1i32 << (D - 1);
        let mut checked = 0;
        for r in (0..Q).step_by(997).chain(0..8192).chain((Q - 8192)..Q) {
            let (r1, r0) = power2round(r);
            assert_eq!(
                (r1 * (1 << D) + r0).rem_euclid(Q),
                r,
                "r1*2^d + r0 must reconstruct r, at r={r}"
            );
            assert!(
                r0 > -half && r0 <= half,
                "r0 must be centered in (-2^(d-1), 2^(d-1)], at r={r}: {r0}"
            );
            checked += 1;
        }
        assert!(checked > 20000, "the sweep should be substantial");
    }

    /// The high part must fit the width the public key encoding gives it.
    ///
    /// `t1` is packed at 10 bits per coefficient, which is only correct if
    /// `power2round` never returns more than that.
    #[test]
    fn power2round_high_part_fits_ten_bits() {
        let mut max = 0;
        for r in (0..Q).step_by(37).chain((Q - 65536)..Q) {
            let (r1, _) = power2round(r);
            assert!(r1 >= 0, "the high part is unsigned, at r={r}");
            max = max.max(r1);
        }
        assert!(max < 1024, "t1 must fit ten bits, saw {max}");
        // And the bound is actually approached, or the test proves nothing.
        assert!(
            max > 1000,
            "the sweep should reach the top bucket, saw {max}"
        );
    }

    /// Same argument as `power2round`: the pair of properties has one solution.
    #[test]
    fn decompose_is_pinned_by_its_definition() {
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            let alpha = 2 * gamma2;
            for r in interesting(gamma2) {
                let (r1, r0) = decompose(r, gamma2);
                assert_eq!(
                    (r1 * alpha + r0).rem_euclid(Q),
                    r,
                    "r1*alpha + r0 must reconstruct r, at r={r} gamma2={gamma2}"
                );
                assert!(
                    (-gamma2..=gamma2).contains(&r0),
                    "r0 out of range at r={r} gamma2={gamma2}: {r0}"
                );
                // The open bound holds everywhere the fold does not apply, and
                // the fold applies on exactly one known interval. Asserting the
                // implication is stronger than loosening the bound and walking
                // away, because it forbids `-gamma2` appearing anywhere else.
                if r0 == -gamma2 {
                    assert_eq!(
                        r,
                        Q - gamma2,
                        "r0 may only reach -gamma2 at the very bottom of the                          folded interval, gamma2={gamma2}"
                    );
                }
                assert!(
                    (0..bucket_count(gamma2)).contains(&r1),
                    "r1 out of range at r={r} gamma2={gamma2}: {r1}"
                );
            }
        }
    }

    /// The one input where the reconstruction is deliberately *not* exact in
    /// the obvious way.
    ///
    /// Near the top of the range the natural bucket would be one past the last,
    /// so the standard folds it to zero and absorbs the difference into `r0`.
    /// Left unhandled this would overflow the `w1` encoding by one bucket.
    ///
    /// The fold covers an *interval*, not just `q - 1`: every `r` in
    /// `[q - gamma2, q - 1]` rounds up to `q - 1` and is folded. Testing only
    /// the endpoint would miss `q - gamma2`, which is the single input where
    /// `r0` reaches `-gamma2` — and that is exactly the case that caught a
    /// wrong bound in this file's first draft.
    #[test]
    fn decompose_folds_the_whole_top_interval_into_bucket_zero() {
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            for r in (Q - gamma2)..Q {
                let (r1, r0) = decompose(r, gamma2);
                assert_eq!(r1, 0, "r={r} should fold to bucket zero, gamma2={gamma2}");
                assert_eq!(
                    r0,
                    r - (Q - 1) - 1,
                    "the folded low part at r={r}, gamma2={gamma2}"
                );
                assert_eq!(
                    (r1 * 2 * gamma2 + r0).rem_euclid(Q),
                    r,
                    "it still reconstructs at r={r}"
                );
            }
            // The endpoints of the interval, named so the intent is explicit.
            assert_eq!(decompose(Q - 1, gamma2), (0, -1));
            assert_eq!(decompose(Q - gamma2, gamma2), (0, -gamma2));
            // And one step below the interval is *not* folded.
            let (r1, _) = decompose(Q - gamma2 - 1, gamma2);
            assert_ne!(r1, 0, "the fold must not extend below q - gamma2");
        }
    }

    /// The lemma the scheme rests on, and the real test of both hint functions.
    ///
    /// For `|z| <= gamma2`, a single bit is enough to recover the high bits of
    /// `r` from `r + z`. This is exactly what verification does, so if it holds
    /// across the boundary cases, the pair is doing its job.
    ///
    /// Note what this does *not* establish. The mirrored statement
    /// `use_hint(make_hint(z, r), r) == high_bits(r + z)` also holds, so this
    /// test does not distinguish the two orientations — it confirms the
    /// relationship FIPS 204 states rather than selecting it.
    #[test]
    fn a_hint_recovers_the_high_bits_after_a_bounded_shift() {
        let mut rng = Rng(0x5eed_1234);
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            let mut flipped = 0;
            let mut total = 0;
            for r in interesting(gamma2) {
                for z in [
                    0,
                    1,
                    -1,
                    gamma2,
                    -gamma2,
                    gamma2 - 1,
                    -gamma2 + 1,
                    rng.below(2 * gamma2 + 1) - gamma2,
                ] {
                    let shifted = (r + z).rem_euclid(Q);
                    let hint = make_hint(z, r, gamma2);
                    assert_eq!(
                        use_hint(hint, shifted, gamma2),
                        high_bits(r, gamma2),
                        "hint failed at r={r} z={z} gamma2={gamma2}"
                    );
                    total += 1;
                    if hint {
                        flipped += 1;
                    }
                }
            }
            // If no hint were ever set, `use_hint` returning `r1` unchanged
            // would satisfy the lemma vacuously and this test would be empty.
            assert!(
                flipped > total / 100,
                "the correcting branch must actually be exercised: \
                 {flipped} of {total} hints set for gamma2={gamma2}"
            );
        }
    }

    /// A hint that is not needed must not be set.
    ///
    /// Signing caps the number of set hints at `omega`; a function that set
    /// them liberally would still satisfy the recovery lemma while making
    /// signatures fail to fit. So "correct" here includes "minimal".
    #[test]
    fn no_hint_is_set_when_the_bucket_does_not_change() {
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            for r in interesting(gamma2) {
                for z in [0, 1, -1, 17, -17] {
                    let shifted = (r + z).rem_euclid(Q);
                    if high_bits(r, gamma2) == high_bits(shifted, gamma2) {
                        assert!(
                            !make_hint(z, r, gamma2),
                            "a hint was set with no bucket change, \
                             at r={r} z={z} gamma2={gamma2}"
                        );
                    }
                }
            }
        }
    }

    /// `high_bits` and `low_bits` must be the two halves of one `decompose`,
    /// not independent reimplementations that could drift.
    #[test]
    fn high_and_low_bits_agree_with_decompose() {
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            for r in interesting(gamma2).into_iter().step_by(7) {
                let (r1, r0) = decompose(r, gamma2);
                assert_eq!(high_bits(r, gamma2), r1);
                assert_eq!(low_bits(r, gamma2), r0);
            }
        }
    }

    /// The bucket counts the standard names, from the expression the code uses.
    #[test]
    fn bucket_counts_match_the_parameter_sets() {
        assert_eq!(bucket_count(GAMMA2_88), 44, "ML-DSA-44");
        assert_eq!(bucket_count(GAMMA2_32), 16, "ML-DSA-65 and ML-DSA-87");
        assert_eq!(GAMMA2_88, 95_232);
        assert_eq!(GAMMA2_32, 261_888);
    }

    /// The polynomial wrappers must be exactly the scalar functions applied
    /// coefficient-wise — the kind of thing a transposed index quietly breaks.
    #[test]
    fn the_polynomial_wrappers_are_coefficient_wise() {
        let mut rng = Rng(0xabcd_0001);
        let mut p = Poly::ZERO;
        let mut z = Poly::ZERO;
        for i in 0..N {
            p.c[i] = rng.below(Q);
            z.c[i] = rng.below(2 * GAMMA2_32 + 1) - GAMMA2_32;
        }

        let (t1, t0) = power2round_poly(&p);
        for i in 0..N {
            assert_eq!(
                (t1.c[i], t0.c[i]),
                power2round(p.c[i]),
                "power2round at {i}"
            );
        }

        let (w1, w0) = decompose_poly(&p, GAMMA2_32);
        for i in 0..N {
            assert_eq!(
                (w1.c[i], w0.c[i]),
                decompose(p.c[i], GAMMA2_32),
                "decompose at {i}"
            );
        }

        let (hints, weight) = make_hint_poly(&z, &p, GAMMA2_32);
        assert_eq!(
            weight,
            hints.iter().filter(|h| **h).count(),
            "the returned weight must be the actual weight"
        );

        // And the whole-polynomial round trip, which is how signing and
        // verification will use these.
        let mut shifted = Poly::ZERO;
        for i in 0..N {
            shifted.c[i] = (p.c[i] + z.c[i]).rem_euclid(Q);
        }
        let recovered = use_hint_poly(&hints, &shifted, GAMMA2_32);
        for i in 0..N {
            assert_eq!(
                recovered.c[i],
                high_bits(p.c[i], GAMMA2_32),
                "polynomial hint round trip at {i}"
            );
        }
    }
}
