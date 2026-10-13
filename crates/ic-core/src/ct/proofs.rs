//! Bounded proofs of the constant-time primitives, for Kani.
//!
//! ```text
//! cargo kani -p ic-core
//! ```
//!
//! The unit tests check these functions on chosen values; these check them on
//! every value. For the scalar helpers that is every input outright -- a
//! `u64` select is proved for all 2^129 combinations of choice and operands --
//! and for the slice routines every content of every length up to the bound,
//! which is stated on each proof. What a proof here establishes is that the
//! function computes what its specification says. Whether the compiled code
//! branches is a separate question, answered by `scripts/check-ct.py` and
//! `scripts/ctgrind.sh`.

use super::*;

/// The largest slice length the slice proofs cover. Every length from zero up
/// to it is covered, with every content.
const BOUND: usize = 6;

/// Any `Choice` a caller can hold: there is no other way to make one.
fn any_choice() -> Choice {
    match kani::any::<u8>() % 3 {
        0 => Choice::FALSE,
        1 => Choice::TRUE,
        _ => Choice::from_u8(kani::any()),
    }
}

#[kani::proof]
fn from_u8_is_normalised_and_means_non_zero() {
    let v: u8 = kani::any();
    let c = Choice::from_u8(v);
    assert!(c.0 == 0 || c.0 == 1);
    assert_eq!(c.0 == 1, v != 0);
}

#[kani::proof]
fn every_choice_holds_zero_or_one() {
    let c = any_choice();
    assert!(c.0 <= 1);
    assert!(c.not().0 <= 1);
    assert!(c.and(any_choice()).0 <= 1);
    assert!(c.or(any_choice()).0 <= 1);
}

#[kani::proof]
fn mask_is_all_ones_exactly_when_true() {
    let c = any_choice();
    let m = c.mask();
    assert_eq!(m, if c.0 == 1 { 0xff } else { 0x00 });
    assert_eq!(c.unwrap_u8(), c.0);
    assert_eq!(bool::from(c), c.0 == 1);
}

#[kani::proof]
fn logic_matches_bool() {
    let (a, b) = (any_choice(), any_choice());
    let (x, y) = (a.0 == 1, b.0 == 1);
    assert_eq!(a.not().0 == 1, !x);
    assert_eq!(a.and(b).0 == 1, x && y);
    assert_eq!(a.or(b).0 == 1, x || y);
}

#[kani::proof]
fn select_u8_chooses() {
    let c = any_choice();
    let (a, b): (u8, u8) = (kani::any(), kani::any());
    assert_eq!(select_u8(c, a, b), if c.0 == 1 { a } else { b });
}

#[kani::proof]
fn select_u32_chooses() {
    let c = any_choice();
    let (a, b): (u32, u32) = (kani::any(), kani::any());
    assert_eq!(select_u32(c, a, b), if c.0 == 1 { a } else { b });
}

#[kani::proof]
fn select_u64_chooses() {
    let c = any_choice();
    let (a, b): (u64, u64) = (kani::any(), kani::any());
    assert_eq!(select_u64(c, a, b), if c.0 == 1 { a } else { b });
}

/// Two slices of any lengths up to `BOUND` and any contents.
fn any_slices<'a>(a: &'a [u8; BOUND], b: &'a [u8; BOUND]) -> (&'a [u8], &'a [u8]) {
    let (la, lb): (usize, usize) = (kani::any(), kani::any());
    kani::assume(la <= BOUND && lb <= BOUND);
    (&a[..la], &b[..lb])
}

#[kani::proof]
#[kani::unwind(8)]
fn eq_and_verify_are_equality() {
    let (x, y): ([u8; BOUND], [u8; BOUND]) = (kani::any(), kani::any());
    let (a, b) = any_slices(&x, &y);
    assert_eq!(eq(a, b).0 == 1, a == b);
    assert_eq!(verify(a, b), a == b);
}

#[kani::proof]
#[kani::unwind(8)]
fn lt_be_is_big_endian_less_than() {
    let (x, y): ([u8; BOUND], [u8; BOUND]) = (kani::any(), kani::any());
    let len: usize = kani::any();
    kani::assume(len <= BOUND);
    let (a, b) = (&x[..len], &y[..len]);
    // For equal lengths, lexicographic order on big-endian bytes is the
    // numeric order, and slice comparison in Rust is lexicographic.
    assert_eq!(lt_be(a, b).0 == 1, a < b);
}

#[kani::proof]
#[kani::unwind(8)]
fn is_zero_means_every_byte_is_zero() {
    let x: [u8; BOUND] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= BOUND);
    let a = &x[..len];
    assert_eq!(is_zero(a).0 == 1, a.iter().all(|&v| v == 0));
}

#[kani::proof]
#[kani::unwind(8)]
fn cswap_swaps_exactly_when_true() {
    let (x0, y0): ([u8; BOUND], [u8; BOUND]) = (kani::any(), kani::any());
    let (mut x, mut y) = (x0, y0);
    let c = any_choice();
    cswap(c, &mut x, &mut y);
    if c.0 == 1 {
        assert!(x == y0 && y == x0);
    } else {
        assert!(x == x0 && y == y0);
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn cmov_copies_exactly_when_true() {
    let (d0, s): ([u8; BOUND], [u8; BOUND]) = (kani::any(), kani::any());
    let mut d = d0;
    let c = any_choice();
    cmov(c, &mut d, &s);
    assert!(d == if c.0 == 1 { s } else { d0 });
}
