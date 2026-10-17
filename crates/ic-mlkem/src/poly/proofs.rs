//! Bounded proofs of ML-KEM's coefficient arithmetic, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-mlkem
//! ```
//!
//! The tests check these functions at the inputs somebody thought of, and the
//! reductions at a handful of them. These check every input in the stated
//! domain, against a specification written from the integers: a congruence
//! modulo `q` and a range, not another copy of the code. `q` and `2^16` are
//! spelt out again here rather than read from the code under test.

use super::*;

/// `q`, written out independently of [`Q`].
const MODULUS: i64 = 3329;

/// `x` is congruent to `y` modulo `q`.
fn congruent(x: i64, y: i64) -> bool {
    (x - y) % MODULUS == 0
}

/// Montgomery reduction is `a * 2^-16 mod q`, in `(-q, q)`, for every `a`
/// with `|a| < 2^15 q`. That bound is the whole domain: it is what a product
/// of an `i16` and a value below `q` in magnitude stays inside, and the
/// result is out of range (or the `i32` subtraction overflows) beyond it.
#[kani::proof]
fn montgomery_reduce_is_a_times_r_inverse_in_range() {
    let a: i32 = kani::any();
    kani::assume((a as i64).abs() < (1i64 << 15) * MODULUS);
    let r = montgomery_reduce(a);
    // r * 2^16 = a (mod q) is r = a * 2^-16, since 2^16 is invertible.
    assert!(congruent(r as i64 * 65536, a as i64));
    assert!(-(MODULUS as i32) < r as i32 && (r as i32) < MODULUS as i32);
}

/// Barrett reduction returns a representative of `a mod q` in `[-1665, 1665]`,
/// for every `i16`. The first version of this harness asserted `[-1664, 1664]`,
/// which is what "`[-q/2, q/2]`" means for an integer, and Kani refused it: the
/// estimate `floor(2^26 / q) = 20158` is one short of the true quotient at the
/// extremes, and `a = 11652` returns 1665 (`a = -31626` returns -1665). The
/// bound is one wider than the doc comment said; nothing depends on the
/// narrower one (`fqmul_is_a_b_r_inverse_in_range` takes any `i16`).
#[kani::proof]
fn barrett_reduce_is_a_mod_q_nearly_centred_for_every_i16() {
    let a: i16 = kani::any();
    let r = barrett_reduce(a);
    assert!(congruent(r as i64, a as i64));
    assert!(-1665 <= r && r <= 1665);
}

/// `fqmul` is `a * b * 2^-16 mod q`, in `(-q, q)`, for every `i16` `a` and
/// every `b` in `(-q, q)`: the second operand of every call in the NTT is a
/// zeta, a Montgomery-form coefficient, or a constant below `q`.
#[kani::proof]
fn fqmul_is_a_b_r_inverse_in_range() {
    let a: i16 = kani::any();
    let b: i16 = kani::any();
    kani::assume(-(MODULUS as i16) < b && b < MODULUS as i16);
    let r = fqmul(a, b);
    assert!(congruent(r as i64 * 65536, a as i64 * b as i64));
    assert!(-(MODULUS as i16) < r && r < MODULUS as i16);
}

/// The conditional subtraction behind `normalize`: a Barrett reduction, then
/// `q` added through the sign mask. The result is the representative of
/// `a mod q` in `[0, q)`, for every `i16`.
#[kani::proof]
fn normalize_coefficient_is_a_mod_q_in_zero_to_q() {
    let a: i16 = kani::any();
    let r = normalize_coefficient(a);
    assert!(congruent(r as i64, a as i64));
    assert!(0 <= r && r < MODULUS as i16);
}

/// Every zeta is a canonical residue, so in `(-q, q)`, which is what
/// `fqmul_is_a_b_r_inverse_in_range` needs of the multiplier.
#[kani::proof]
#[kani::unwind(130)]
fn every_zeta_is_in_zero_to_q() {
    for i in 0..128 {
        assert!(0 <= ZETAS[i] && ZETAS[i] < MODULUS as i16);
    }
}

/// The forward NTT butterfly, one layer. For a zeta in `(-q, q)` and inputs
/// within `k q` in magnitude, `k` in `1..=7`:
///
/// - no `i16` operation overflows (Kani checks every one);
/// - the outputs are `a +/- zeta b 2^-16`, exactly as congruences;
/// - the outputs are within `(k + 1) q`.
///
/// Seven layers starting below `q` therefore stay below `8 q = 26632`, inside
/// `i16`, and the closing `reduce_portable` is Barrett over every `i16`. The
/// induction over the layers is argued from this step; the harness is the
/// step.
#[kani::proof]
fn ntt_butterfly_keeps_its_bound_and_value() {
    let zeta: i16 = kani::any();
    let a: i16 = kani::any();
    let b: i16 = kani::any();
    let k: i32 = kani::any();
    kani::assume(-(MODULUS as i16) < zeta && zeta < MODULUS as i16);
    kani::assume((1..=7).contains(&k));
    let bound = k * MODULUS as i32;
    kani::assume((a as i32).abs() <= bound && (b as i32).abs() <= bound);
    let (x, y) = ntt_butterfly(zeta, a, b);
    let zb = zeta as i64 * b as i64; // zeta * b = t * 2^16 (mod q)
    assert!(congruent(x as i64 * 65536, a as i64 * 65536 + zb));
    assert!(congruent(y as i64 * 65536, a as i64 * 65536 - zb));
    assert!((x as i32).abs() < bound + MODULUS as i32);
    assert!((y as i32).abs() < bound + MODULUS as i32);
}
