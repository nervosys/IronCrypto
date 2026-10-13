//! Bounded proofs of ML-DSA's rounding, for Kani.
//!
//! ```text
//! cargo kani -p ic-mldsa
//! ```
//!
//! The tests compare the constant-time forms with the branching ones over
//! every residue in `[0, q)`. These prove them over every `i32`, negatives
//! included, and prove the hint lemma -- the property the scheme rests on --
//! for every coefficient and every `z` within `gamma2`.

use super::*;

#[kani::proof]
fn reduce_q_is_r_mod_q_for_every_i32() {
    let r: i32 = kani::any();
    assert_eq!(reduce_q(r), r.rem_euclid(Q));
}

#[kani::proof]
fn power2round_splits_every_i32() {
    let r: i32 = kani::any();
    let (r1, r0) = power2round(r);
    // The unique split FIPS 204 algorithm 35 defines: the pieces sum back to
    // r mod q, the low part is centred in (-2^(d-1), 2^(d-1)], and the high
    // part fits the ten bits the public key gives it.
    assert_eq!((r1 << D) + r0, r.rem_euclid(Q));
    assert!(-(1 << (D - 1)) < r0 && r0 <= 1 << (D - 1));
    assert!((0..1 << 10).contains(&r1));
}

fn decompose_matches_algorithm_36(gamma2: i32) {
    let r: i32 = kani::any();
    assert_eq!(decompose(r, gamma2), decompose_generic(r, gamma2));
}

#[kani::proof]
fn decompose_is_algorithm_36_for_gamma2_32() {
    decompose_matches_algorithm_36(GAMMA2_32);
}

#[kani::proof]
fn decompose_is_algorithm_36_for_gamma2_88() {
    decompose_matches_algorithm_36(GAMMA2_88);
}

fn hint_lemma(gamma2: i32) {
    // FIPS 204 section 2.4: if |z| <= gamma2 then
    // UseHint(MakeHint(z, r), r + z) == HighBits(r) for every r in Z_q.
    let r: i32 = kani::any();
    let z: i32 = kani::any();
    kani::assume((0..Q).contains(&r));
    kani::assume(-gamma2 <= z && z <= gamma2);
    let h = make_hint(z, r, gamma2);
    assert_eq!(use_hint(h, reduce_q(r + z), gamma2), high_bits(r, gamma2));
}

#[kani::proof]
fn hint_lemma_holds_for_gamma2_32() {
    hint_lemma(GAMMA2_32);
}

#[kani::proof]
fn hint_lemma_holds_for_gamma2_88() {
    hint_lemma(GAMMA2_88);
}
