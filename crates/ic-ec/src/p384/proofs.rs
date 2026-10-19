//! Bounded proofs of P-384's portable field arithmetic, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-ec
//! ```
//!
//! The generic six-word field operations that `mont_field!` writes for both
//! P-384 rings: `add_raw`, `sub_raw`, and the closing conditional subtraction
//! of a Montgomery reduction (`canonical`). They mirror the P-256 proofs
//! (`nist/p256_field/proofs.rs`): every specification is written from the
//! integers, with `p` and `n` spelt out again here rather than read from
//! `P` and `N`, and the helpers are plain loops over `u64` words that share
//! no carry logic with the code under test. The domain of each proof is its
//! assumption.
//!
//! The Montgomery multiplication, `arith::wide::mont_mul`, which both rings
//! use on every target but x86-64 and as the fallback on x86-64, is proved in
//! two halves that meet in docs/PROOFS.md ("P-384 multiplication"): the loops
//! over arbitrary products in `nist/arith/proofs.rs`, for every modulus; and
//! here, for these two moduli, the digit lemma (every quotient digit clears
//! the low word) and the closing step (`close`).

use super::*;
use crate::nist::arith::wide::{close, quotient_digit, word_mul};
use crate::nist::arith::{select_ct, MAX_LIMBS};

/// `p = 2^384 - 2^128 - 2^96 + 2^32 - 1`, little-endian words, written out
/// here independently of [`P`].
const PRIME: [u64; 6] = [
    0x0000_0000_ffff_ffff,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// The order `n` of the base point (SEC 2, `secp384r1`), written out here
/// independently of [`N`].
const ORDER: [u64; 6] = [
    0xecec_196a_ccc5_2973,
    0x581a_0db2_48b0_a77a,
    0xc763_4d81_f437_2ddf,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// `a < b`, as integers: `a - b` borrows out of the top word. Straight
/// through, with no early return, as in the P-256 proofs.
fn lt<const L: usize>(a: &[u64; L], b: &[u64; L]) -> bool {
    let mut borrow: u128 = 0;
    for i in 0..L {
        let t = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        borrow = (t >> 64) & 1;
    }
    borrow == 1
}

/// `a = b`, as a conjunction of word equalities.
fn eq<const L: usize>(a: &[u64; L], b: &[u64; L]) -> bool {
    let mut same = true;
    for i in 0..L {
        same &= a[i] == b[i];
    }
    same
}

/// `a + b`, as integers. The caller sizes `L` so that no carry is lost.
fn add_n<const L: usize>(a: [u64; L], b: [u64; L]) -> [u64; L] {
    let mut r = [0u64; L];
    let mut carry: u128 = 0;
    for i in 0..L {
        let t = a[i] as u128 + b[i] as u128 + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    assert_eq!(carry, 0);
    r
}

/// `a` as seven words, zero-extended.
fn widen(a: [u64; 6]) -> [u64; 7] {
    [a[0], a[1], a[2], a[3], a[4], a[5], 0]
}

/// `a - b` as integers, seven words. The caller guarantees `a >= b`.
fn sub_n(a: [u64; 7], b: [u64; 7]) -> [u64; 7] {
    let mut r = [0u64; 7];
    let mut borrow: u128 = 0;
    for i in 0..7 {
        let t = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        r[i] = t as u64;
        borrow = (t >> 64) & 1;
    }
    assert_eq!(borrow, 0);
    r
}

/// An element below `m`, the domain of `add` and `sub`.
fn any_below(m: &[u64; 6]) -> [u64; 6] {
    let a: [u64; 6] = kani::any();
    kani::assume(lt(&a, m));
    a
}

/// [`PRIME`] is the number the module doc says: `2^384 - 2^128 - 2^96 + 2^32
/// - 1`, computed here from the powers of two, and equal to [`P`].
#[kani::proof]
#[kani::unwind(9)]
fn prime_is_its_definition() {
    let bit = |k: usize| -> [u64; 7] {
        let mut w = [0u64; 7];
        w[k / 64] = 1u64 << (k % 64);
        w
    };
    // 2^384 - 2^128 - 2^96 + 2^32 - 1, kept non-negative by adding before
    // subtracting.
    let v = add_n(bit(384), bit(32));
    let v = sub_n(v, bit(128));
    let v = sub_n(v, bit(96));
    let v = sub_n(v, bit(0));
    assert!(eq(&v, &widen(PRIME)));
    assert!(eq(&PRIME, &P));
    assert!(eq(&ORDER, &N));
}

fn add_raw_is_a_plus_b_mod<const IS_P: bool>(m: [u64; 6]) {
    let (a, b) = (any_below(&m), any_below(&m));
    let out = if IS_P {
        Fp::add_raw(a, b)
    } else {
        Fn::add_raw(a, b)
    };
    // The sum is below 2m, so out is a + b or a + b - m: the only two values
    // in [0, m) that can be congruent to it.
    let sum = add_n(widen(a), widen(b));
    assert!(lt(&out, &m));
    assert!(eq(&sum, &widen(out)) || eq(&sum, &add_n(widen(out), widen(m))));
}

fn sub_raw_is_a_minus_b_mod<const IS_P: bool>(m: [u64; 6]) {
    let (a, b) = (any_below(&m), any_below(&m));
    let out = if IS_P {
        Fp::sub_raw(a, b)
    } else {
        Fn::sub_raw(a, b)
    };
    // Adding b back gives a or a + m: the two values in [0, 2m) congruent to a.
    assert!(lt(&out, &m));
    let back = add_n(widen(out), widen(b));
    assert!(eq(&back, &widen(a)) || eq(&back, &add_n(widen(a), widen(m))));
}

/// The coordinate field's `add_raw` is `a + b mod p` for every `a`, `b` below
/// `p`, in `[0, p)`.
#[kani::proof]
#[kani::unwind(9)]
fn p384_fp_add_is_a_plus_b_mod_p() {
    add_raw_is_a_plus_b_mod::<true>(PRIME);
}

/// `sub_raw` is `a - b mod p` for every `a`, `b` below `p`, in `[0, p)`.
#[kani::proof]
#[kani::unwind(9)]
fn p384_fp_sub_is_a_minus_b_mod_p() {
    sub_raw_is_a_minus_b_mod::<true>(PRIME);
}

/// The scalar ring's `add_raw` is `a + b mod n`, in `[0, n)`.
#[kani::proof]
#[kani::unwind(9)]
fn p384_fn_add_is_a_plus_b_mod_n() {
    add_raw_is_a_plus_b_mod::<false>(ORDER);
}

/// The scalar ring's `sub_raw` is `a - b mod n`, in `[0, n)`.
#[kani::proof]
#[kani::unwind(9)]
fn p384_fn_sub_is_a_minus_b_mod_n() {
    sub_raw_is_a_minus_b_mod::<false>(ORDER);
}

/// The closing step of a Montgomery multiplication, `canonical`: given the
/// value `t + top 2^384` below `2m`, one subtraction chosen by the borrow and
/// the carry leaves a result below `m` that is `t + top 2^384` or that less
/// `m`. For both moduli, every `t` and `top`.
fn canonical_reduces_below_2m(m: [u64; 6]) {
    let t: [u64; 6] = kani::any();
    let top: u64 = kani::any();
    kani::assume(top <= 1);
    let value = [t[0], t[1], t[2], t[3], t[4], t[5], top];
    let two_m = add_n(widen(m), widen(m));
    kani::assume(lt(&value, &two_m));
    let out = canonical(t, top, m);
    assert!(lt(&out, &m));
    assert!(eq(&value, &widen(out)) || eq(&value, &add_n(widen(out), widen(m))));
}

#[kani::proof]
#[kani::unwind(9)]
fn p384_canonical_is_value_mod_p() {
    canonical_reduces_below_2m(PRIME);
}

#[kani::proof]
#[kani::unwind(9)]
fn p384_canonical_is_value_mod_n() {
    canonical_reduces_below_2m(ORDER);
}

/// The closing step of `mont_mul`, as `mont_mul_raw` uses it: given the
/// loops' buffer `t`, with `T = t[0..=6]` (seven words) below `2m` and the
/// rest of the buffer zero, `close` and the selection leave a result below `m`
/// that is `T` or `T - m`. For both moduli, every `t`.
fn close_reduces_below_2m(m: [u64; 6]) {
    let t: [u64; MAX_LIMBS + 2] = kani::any();
    for i in 7..MAX_LIMBS + 2 {
        kani::assume(t[i] == 0);
    }
    let value = [t[0], t[1], t[2], t[3], t[4], t[5], t[6]];
    let two_m = add_n(widen(m), widen(m));
    kani::assume(lt(&value, &two_m));
    let (reduced, lo, need) = close(t, m);
    let out = select_ct(need.wrapping_neg(), reduced, lo);
    assert!(lt(&out, &m));
    assert!(eq(&value, &widen(out)) || eq(&value, &add_n(widen(out), widen(m))));
}

#[kani::proof]
#[kani::unwind(12)]
fn p384_close_is_value_mod_p() {
    close_reduces_below_2m(PRIME);
}

#[kani::proof]
#[kani::unwind(12)]
fn p384_close_is_value_mod_n() {
    close_reduces_below_2m(ORDER);
}

/// The digit lemma: for every `t0`, the quotient digit `u = t0 * neg_inv`
/// makes `t0 + u m0` a multiple of `2^64`, so the word the multiplication drops
/// from the first multiply-add of each row, `l_i`, is zero. With the true
/// 64-by-64 product, for the ring's own `m0` and `neg_inv`.
fn digit_clears_the_low_word(m0: u64, neg_inv: u64) {
    let t0: u64 = kani::any();
    let u = quotient_digit(t0, neg_inv);
    let sum = t0 as u128 + word_mul(u, m0);
    assert!(sum as u64 == 0);
}

#[kani::proof]
#[kani::solver(bitwuzla)]
fn p384_fp_digit_clears_the_low_word() {
    digit_clears_the_low_word(Fp::MODULUS[0], Fp::NEG_INV);
}

#[kani::proof]
#[kani::solver(bitwuzla)]
fn p384_fn_digit_clears_the_low_word() {
    digit_clears_the_low_word(Fn::MODULUS[0], Fn::NEG_INV);
}
