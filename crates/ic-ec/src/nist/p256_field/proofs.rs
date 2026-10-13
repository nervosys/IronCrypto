//! Bounded proofs of P-256's field addition, subtraction and the final
//! conditional subtraction of Montgomery reduction, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-ec
//! ```
//!
//! Every specification here is written from the integers, not from the words
//! the code works in. `p` is spelt out again below rather than read from `P`,
//! so a change to `P` makes these proofs fail rather than being absorbed. The
//! helpers (`add_n`, `lt`, `widen`) are plain loops over `u64` words with no
//! shared carry logic. Each proof states its domain as an assumption.
//!
//! Not proved here: the Montgomery steps (`mont_step`, `montgomery_low`) and so
//! `reduce`. Their identity contains a 64-bit product by a constant, and Kani's
//! solver did not finish it within 25 minutes, for the product written as a
//! multiplication and for the same identity written as shifts and adds. The
//! composition argument is in the comment at the end of this file.

use super::*;

/// `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, little-endian words, written out
/// here independently of [`P`].
const PRIME: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// `a < b`, as integers, by scanning from the most significant word.
fn lt<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a + b`, as integers. The caller sizes `N` so that no carry is lost.
fn add_n<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut carry: u128 = 0;
    for i in 0..N {
        let t = a[i] as u128 + b[i] as u128 + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    assert_eq!(carry, 0);
    r
}

/// `a` as `N` words, zero-extended.
fn widen<const N: usize>(a: [u64; 4]) -> [u64; N] {
    let mut r = [0u64; N];
    r[..4].copy_from_slice(&a);
    r
}

/// Any element below `p`, the domain of `add` and `sub`.
fn any_residue() -> [u64; 4] {
    let a: [u64; 4] = kani::any();
    kani::assume(lt(&a, &PRIME));
    a
}

/// `add` is `a + b mod p` for every `a`, `b` below `p`: the result is below
/// `p`, and it is `a + b` or `a + b - p`, which are the only two values in
/// `[0, p)` congruent to the sum (the sum is below `2p`).
#[kani::proof]
fn add_is_a_plus_b_mod_p() {
    let (a, b) = (any_residue(), any_residue());
    let out = add(a, b);
    let sum: [u64; 5] = add_n(widen(a), widen(b));
    assert!(lt(&out, &PRIME));
    assert!(sum == widen(out) || sum == add_n(widen(out), widen(PRIME)));
}

/// `sub` is `a - b mod p` for every `a`, `b` below `p`: the result is below
/// `p`, and adding `b` back gives `a` or `a + p`, the two values in `[0, 2p)`
/// congruent to `a`.
#[kani::proof]
fn sub_is_a_minus_b_mod_p() {
    let (a, b) = (any_residue(), any_residue());
    let out = sub(a, b);
    assert!(lt(&out, &PRIME));
    let back: [u64; 5] = add_n(widen(out), widen(b));
    assert!(back == widen(a) || back == add_n(widen(a), widen(PRIME)));
}

/// `finish` is `hi + w` made canonical, for `hi` below `p` and `w` at most
/// `p`: the result is below `p`, and is `hi + w` or `hi + w - p`.
#[kani::proof]
fn finish_is_hi_plus_w_mod_p() {
    let hi: [u64; 4] = kani::any();
    let w: [u64; 4] = kani::any();
    kani::assume(lt(&hi, &PRIME));
    kani::assume(!lt(&PRIME, &w));
    let out = finish(hi, w);
    let s: [u64; 5] = add_n(widen(hi), widen(w));
    assert!(lt(&out, &PRIME));
    assert!(s == widen(out) || s == add_n(widen(out), widen(PRIME)));
}

// The composition, for `t = hi * 2^256 + lo` with `hi < p`, is not a Kani
// proof. `reduce(t)` is `finish(hi, montgomery_low(lo))` by its definition.
// With `W = montgomery_low(lo)`, the step identity `2^64 * step(w) = w + w0 * p`
// telescoped over four steps gives `2^256 W = lo + U p` for the quotient digits
// `U`, so `2^256 W = lo (mod p)`, and `finish` gives `out = hi + W` mod `p`.
// Then `2^256 out = 2^256 hi + lo = t (mod p)`. Neither the step identity nor
// the composition is machine-checked, for the reason in the module comment.
