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
//! So the samplers and the encodings were `experimental` for want of a file
//! until NIST's ACVP vectors arrived, and nothing here ever was: a vector could
//! only confirm what the equations already fix. What a vector *does* add is a
//! check on the convention shared with the rest of the scheme — which
//! representative `mod±` picks, say — which the equations cannot settle on
//! their own. Signing runs every function here, so the ACVP signature cases
//! cover that too.
//!
//! # Timing
//!
//! [`power2round`] and [`decompose`] handle secrets, and run in constant time:
//! no branch and no division on a value.
//!
//! This module used to say otherwise -- that they branched safely, because
//! `power2round` split only the public key and `decompose` saw only published
//! values. Neither was so. `power2round` produces `t0`, which is part of the
//! secret key, and signing decomposes `w - c*s2` for every attempt, rejected
//! ones included, which depends on `s2`. Reading the compiled code found two
//! channels: a branch on `decompose`'s fold, and -- on every target, x86-64
//! included -- hardware or library *division* by `2*gamma2` and by `q`, whose
//! time depends on the dividend on most CPUs this library runs on. That is
//! the channel KyberSlash exploited in ML-KEM implementations.
//!
//! So reduction modulo `q` is shifts, masks and one small multiplication
//! ([`reduce_q`]), and the two splits are the multiply-and-shift forms FIPS
//! 204's reference implementation uses. Their branching, dividing forms are
//! kept in the tests, and the constant-time ones are compared with them over
//! every residue.
//!
//! [`make_hint`] and [`use_hint`] are applied to values the signature
//! publishes or verification computes from public data, and may branch.

use crate::poly::{Poly, N, Q};
use core::hint::black_box;

/// Hide both the input's range and the sign mask's range. A barrier only on
/// the output still lets LLVM compute the mask with a comparison and branch.
#[inline]
fn sign_mask(value: i32) -> i32 {
    black_box(black_box(value) >> 31)
}

/// Dropped bits in the public key, `d` in FIPS 204. The same for every
/// parameter set.
pub const D: u32 = 13;

/// `gamma2` for ML-DSA-44: `(q - 1) / 88`.
pub const GAMMA2_88: i32 = (Q - 1) / 88;

/// `gamma2` for ML-DSA-65 and ML-DSA-87: `(q - 1) / 32`.
pub const GAMMA2_32: i32 = (Q - 1) / 32;

/// `r mod q`, in `[0, q)`, for every `i32`: no branch and no division.
///
/// `q = 2^23 - 2^13 + 1`, so `2^23 = 2^13 - 1` modulo `q`. Splitting `r` at bit
/// 23 and folding the top part back with that identity leaves a value in
/// `(-q, 2q)`: the low part is below `2^23` and the top part, between `-256`
/// and `255`, contributes at most `256 * (2^13 - 1)`. One masked addition and
/// one masked subtraction then land it in range.
#[inline]
pub fn reduce_q(r: i32) -> i32 {
    let hi = r >> 23;
    let lo = r & ((1 << 23) - 1);
    let r = lo + hi * ((1 << 13) - 1);
    // LTO recognizes the sign masks as conditional additions/subtractions and
    // emits secret-dependent branches on Cortex-M0. Hide the mask's range,
    // as ic_core::ct does, before LLVM can turn it back into control flow.
    let r = r + (sign_mask(r) & Q);
    r - (Q & !sign_mask(r - Q))
}

/// FIPS 204 Algorithm 35. Split `r` into `(r1, r0)` with `r = r1*2^d + r0`.
///
/// `r0` is the centered low `d` bits, so it lands in `(-2^(d-1), 2^(d-1)]`.
/// This is what lets the public key ship only `r1` and the signer keep `r0`.
///
/// `r1` is `r + 2^(d-1) - 1` shifted down by `d`: rounding half down, which is
/// what puts `r0` in that half-open interval.
pub fn power2round(r: i32) -> (i32, i32) {
    let r = reduce_q(r);
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    (r1, r - (r1 << D))
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
///
/// # Without a branch
///
/// Signing decomposes `w - c*s2`, which depends on the secret key, for every
/// coefficient of every attempt -- including rejected attempts, which are
/// never published. Whether a coefficient hit the fold is secret there, so it
/// is taken with a mask rather than an `if`; FIPS 204's reference
/// implementation does the same. The branching form it replaced is kept in
/// the tests, where every residue is checked against it.
pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let r = reduce_q(r);
    // FIPS 204's reference implementation. `r1` approximates `r / (2 gamma2)`
    // rounded, first to a multiple of 2^7 and then by a multiplication and a
    // shift chosen for each `gamma2`, whose error is too small to reach a
    // bucket boundary for any `r` below `q` -- the tests check every one.
    // The top bucket folds to zero: by a mask for `(q-1)/32`, where it is
    // bucket 16 and `& 15` is the mask, and by one for `(q-1)/88`, where it
    // is 44.
    let a = (r + 127) >> 7;
    let r1 = match gamma2 {
        GAMMA2_32 => ((a * 1025 + (1 << 21)) >> 22) & 15,
        GAMMA2_88 => {
            let r1 = (a * 11275 + (1 << 23)) >> 24;
            r1 ^ (sign_mask(43 - r1) & r1)
        }
        // Not an ML-DSA parameter set; correct, but not constant time.
        _ => return decompose_generic(r, gamma2),
    };
    let r0 = r - r1 * 2 * gamma2;
    // The fold, and the centring: above (q-1)/2, subtract q.
    (r1, r0 - (sign_mask((Q - 1) / 2 - r0) & Q))
}

/// Algorithm 36 as written, for a `gamma2` no parameter set uses. It divides,
/// and branches on the fold; nothing in ML-DSA reaches it.
fn decompose_generic(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;
    let r = r.rem_euclid(Q);
    let mut r0 = r.rem_euclid(alpha);
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
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
    high_bits(r, gamma2) != high_bits(reduce_q(r.wrapping_add(z)), gamma2)
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

    /// `mod±` as FIPS 204 section 2.3 states it, with the branch.
    fn mod_pm_branching(r: i32, a: i32) -> i32 {
        let r = r.rem_euclid(a);
        if r > a / 2 {
            r - a
        } else {
            r
        }
    }

    /// FIPS 204 Algorithm 35 as written: the oracle for `power2round`.
    fn power2round_branching(r: i32) -> (i32, i32) {
        let r = r.rem_euclid(Q);
        let r0 = mod_pm_branching(r, 1 << D);
        ((r - r0) >> D, r0)
    }

    /// FIPS 204 Algorithm 36 as written: the oracle for `decompose`.
    fn decompose_branching(r: i32, gamma2: i32) -> (i32, i32) {
        let alpha = 2 * gamma2;
        let r = r.rem_euclid(Q);
        let r0 = mod_pm_branching(r, alpha);
        if r - r0 == Q - 1 {
            (0, r0 - 1)
        } else {
            ((r - r0) / alpha, r0)
        }
    }

    /// `reduce_q` against `rem_euclid`: every value within `4q` of zero and of
    /// both ends of `i32`, and every multiple of `2^16` across the whole range,
    /// which crosses every value of the top part `r >> 23`.
    #[test]
    fn reduce_q_is_rem_euclid_across_i32() {
        let near = |c: i64| {
            (c - 4 * Q as i64..c + 4 * Q as i64)
                .filter(|&v| v >= i32::MIN as i64 && v <= i32::MAX as i64)
                .map(|v| v as i32)
        };
        let mut checked = 0u64;
        for r in near(0)
            .chain(near(i32::MIN as i64))
            .chain(near(i32::MAX as i64))
        {
            assert_eq!(reduce_q(r), r.rem_euclid(Q), "r = {r}");
            checked += 1;
        }
        for k in i32::MIN / (1 << 16)..=i32::MAX / (1 << 16) {
            for d in [-1i32, 0, 1] {
                let r = (k << 16).wrapping_add(d);
                assert_eq!(reduce_q(r), r.rem_euclid(Q), "r = {r}");
                checked += 1;
            }
        }
        assert!(checked > 100_000_000, "only {checked}");
    }

    /// `power2round` and `decompose` against Algorithms 35 and 36 as written,
    /// on every residue and both `gamma2`; and a band of negative inputs.
    #[test]
    fn constant_time_splits_agree_with_the_algorithms_everywhere() {
        for r in 0..Q {
            assert_eq!(power2round(r), power2round_branching(r), "power2round {r}");
        }
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            let mut folds = 0;
            for r in 0..Q {
                let want = decompose_branching(r, gamma2);
                assert_eq!(decompose(r, gamma2), want, "r = {r}, gamma2 = {gamma2}");
                folds += i32::from(r - mod_pm_branching(r, 2 * gamma2) == Q - 1);
            }
            for r in (-2 * Q..-Q + 4096).chain(-4096..0) {
                assert_eq!(
                    decompose(r, gamma2),
                    decompose_branching(r, gamma2),
                    "r = {r}"
                );
            }
            assert_eq!(folds, gamma2, "the fold is gamma2 residues wide");
        }
        // A gamma2 no parameter set uses still gets the right answer.
        for r in (0..Q).step_by(997) {
            assert_eq!(decompose(r, 1 << 16), decompose_branching(r, 1 << 16));
        }
    }

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
