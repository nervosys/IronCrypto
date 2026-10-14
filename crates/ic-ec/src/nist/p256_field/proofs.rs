//! Bounded proofs of P-256's field addition, subtraction and Montgomery
//! reduction, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-ec
//! ```
//!
//! Every specification here is written from the integers, not from the words
//! the code works in. `p` is spelt out again below rather than read from `P`,
//! so a change to `P` makes these proofs fail rather than being absorbed. The
//! helpers (`add_n`, `lt`, `widen`) are plain loops over `u64` words with no
//! shared carry logic. Each proof states its domain as an assumption or as a
//! contract's precondition.
//!
//! The reduction is proved in pieces, each a function contract
//! (`kani::ensures`) with its own `proof_for_contract`, and each piece above
//! the bottom proved over the contracts of the pieces it calls
//! (`stub_verified`), so the solver sees a contract where the code would have
//! a multiplier or a loop:
//!
//! - `mac`: `lo + 2^64 hi = a + b c + carry`, every input.
//! - `mont_step`: `2^64 out = w + w0 p`, every `w`. The code multiplies by
//!   `p3`; the specification writes `u p` from the shape of `p`, with no
//!   multiplication.
//! - `montgomery_low`, over `mont_step`: `2^256 w = lo + U p` for the
//!   textbook word-by-word digits `U`, and `w <= p`, every `lo`.
//! - `finish`: `out < p`, `hi + w` is `out` or `out + p`, for `hi < p`,
//!   `w <= p`.
//! - `reduce`, over `montgomery_low` and `finish`: `out < p` and
//!   `2^256 out = t + U p - e 2^256 p`, `e` in `{0, 1}`, so `2^256 out = t mod
//!   p`, for every `t` with upper half below `p`.
//!
//! A proof over a stubbed contract rests on that contract's own proof; run them
//! all.
//!
//! The products, `mul` and `square`, are proved by splitting the schoolbook
//! into a linear and a nonlinear part (see "The products" below and
//! docs/PROOFS.md): the carries and accumulation here, with the 64-by-64
//! multiplications replaced by arbitrary products; the polynomial identities
//! over the integers by Z3 and cvc5, in `crates/ic-ec/proofs/smt/`. That the
//! abstract products may be instantiated with the true ones is argued, not
//! run, and so is the last step, substituting the product into `reduce`'s
//! proved contract (a harness for it gave no verdict; see the end of this
//! file). Together: `mul` and `square` return `out < p` with `2^256 out = a b
//! mod p`, for `a`, `b` below `p`.
//!
//! The solver is Bitwuzla where named. Through it, CBMC 6.11 encodes a checked
//! multiplication wrongly (the result and the overflow flag are swapped in the
//! bit-vector it builds), so nothing proved through it contains one: the
//! specification and the code multiply with `wrapping_mul`, which cannot wrap
//! where it is used, and the formulas were checked for the faulty encoding.

use super::*;

/// `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, little-endian words, written out
/// here independently of [`P`].
const PRIME: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// `a < b`, as integers: `a - b` borrows out of the top word.
///
/// Without branches, as every helper here is. A helper that returns early
/// becomes control flow with its own path conditions at each call, and two
/// calls on equal inputs then no longer look alike to the solver; written
/// straight through, they are the same term, which matters where a stubbed
/// call assumes a postcondition and the proof asserts the same one.
fn lt<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut borrow: u128 = 0;
    for i in 0..N {
        let t = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        borrow = (t >> 64) & 1;
    }
    borrow == 1
}

/// `a = b`, as a conjunction of word equalities. Not `==`, which on arrays
/// becomes a byte-wise `memcmp` the model checker steps through; a
/// conjunction of equalities is also what lets the solver substitute one side
/// for the other when a stubbed call assumes it.
pub(super) fn eq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut same = true;
    for i in 0..N {
        same &= a[i] == b[i];
    }
    same
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
    for i in 0..4 {
        r[i] = a[i];
    }
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

// ---------------------------------------------------------------------------
// The Montgomery reduction and the products.
// ---------------------------------------------------------------------------

// The specifications below compute modulo `2^(64 N)`, with no assertion that
// nothing carries out or borrows: `add_w` and `sub_w` wrap. Each identity is
// stated at a width `N` such that every true value it compares is below
// `2^(64 N)` -- `w + u p` below `2^384` in six words, `t + U p` below `2^576`
// in nine, `a b` below `2^512` in eight -- so equality modulo `2^(64 N)` of the
// computed values is equality of the integers, however the intermediate
// sums wrap. Keeping assertions out of these functions matters because they
// are contract postconditions: a stubbed call assumes them, and an assertion
// inside would be a proof obligation at every call.

/// `a + b mod 2^(64 N)`.
fn add_w<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut carry: u128 = 0;
    for i in 0..N {
        let t = a[i] as u128 + b[i] as u128 + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    r
}

/// `a - b mod 2^(64 N)`.
fn sub_w<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut borrow: u128 = 0;
    for i in 0..N {
        let t = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        r[i] = t as u64;
        borrow = (t >> 64) & 1;
    }
    r
}

/// `u * 2^s`, as `N` words, for `s` a multiple of 32.
fn shl<const N: usize>(u: u64, s: usize) -> [u64; N] {
    let mut r = [0u64; N];
    let w = s / 64;
    if s % 64 == 0 {
        r[w] = u;
    } else {
        r[w] = u << 32;
        r[w + 1] = u >> 32;
    }
    r
}

/// `x + u * p * 2^(64 k) mod 2^(64 N)`. `u * p` is written from the shape of
/// `p` alone, `u 2^256 - u 2^224 + u 2^192 + u 2^96 - u`, with no
/// multiplication.
fn plus_u_p<const N: usize>(x: [u64; N], u: u64, k: usize) -> [u64; N] {
    let b = 64 * k;
    let pos = add_w(
        add_w(add_w(x, shl(u, b + 256)), shl(u, b + 192)),
        shl(u, b + 96),
    );
    sub_w(sub_w(pos, shl(u, b + 224)), shl(u, b))
}

/// `x * 2^(64 k)`, for `x` of four words, as `N` words.
fn at_word<const N: usize>(x: [u64; 4], k: usize) -> [u64; N] {
    let mut r = [0u64; N];
    for i in 0..4 {
        r[k + i] = x[i];
    }
    r
}

/// Word-by-word Montgomery reduction of `t`, as the textbook states it and in
/// full width: `S_0 = t`, `u_i` the word `i` of `S_i` (the quotient digit,
/// since `-p^-1 = 1 mod 2^64`), `S_(i+1) = S_i + u_i p 2^(64 i)`. Returns
/// `S_4 = t + U p`, with `U` the four digits.
fn montgomery_spec(t: [u64; 9]) -> [u64; 9] {
    let mut s = t;
    for i in 0..4 {
        s = plus_u_p(s, s[i], i);
    }
    s
}

/// What [`mont_step`] promises: `2^64 * out = w + w0 * p`, exactly.
pub(super) fn mont_step_post(w: [u64; 4], out: [u64; 4]) -> bool {
    eq(&plus_u_p::<6>(widen(w), w[0], 0), &at_word(out, 1))
}

/// What [`montgomery_low`] promises: `2^256 * w = lo + U p` for the digits the
/// specification takes, and `w <= p`.
pub(super) fn montgomery_low_post(lo: [u64; 4], w: [u64; 4]) -> bool {
    eq(&montgomery_spec(widen(lo)), &at_word(w, 4)) & !lt(&PRIME, &w)
}

/// `hi`, the upper half of `t`, is below `p`: the domain of [`reduce`].
pub(super) fn reduce_pre(t: [u64; 8]) -> bool {
    lt(&[t[4], t[5], t[6], t[7]], &PRIME)
}

/// What [`reduce`] promises: `out < p`, and `2^256 out = t + U p - e 2^256 p`
/// for `e` in `{0, 1}`, with `U` the digits [`montgomery_spec`] takes from the
/// low half of `t` (the upper half does not reach the words they are read
/// from, so they are `t`'s own digits). So `2^256 out = t mod p`.
pub(super) fn reduce_post(t: [u64; 8], out: [u64; 4]) -> bool {
    let lo = [t[0], t[1], t[2], t[3]];
    let hi = [t[4], t[5], t[6], t[7]];
    let s = add_w(montgomery_spec(widen(lo)), at_word(hi, 4));
    let mine: [u64; 9] = at_word(out, 4);
    lt(&out, &PRIME) & (eq(&s, &mine) | eq(&s, &add_w(mine, at_word(PRIME, 4))))
}

/// The domain of [`finish`]: `hi < p` and `w <= p`.
pub(super) fn finish_pre(hi: [u64; 4], w: [u64; 4]) -> bool {
    lt(&hi, &PRIME) & !lt(&PRIME, &w)
}

/// What [`finish`] promises: `out < p` and `hi + w` is `out` or `out + p`.
pub(super) fn finish_post(hi: [u64; 4], w: [u64; 4], out: [u64; 4]) -> bool {
    let s: [u64; 5] = add_w(widen(hi), widen(w));
    lt(&out, &PRIME) & (eq(&s, &widen(out)) | eq(&s, &add_w(widen(out), widen(PRIME))))
}

/// `p` is `2^256 - 2^224 + 2^192 + 2^96 - 1`: the shape [`plus_u_p`] uses is
/// the prime written out above. A constant check, with no symbolic input.
#[kani::proof]
fn the_prime_has_the_shape_the_specification_uses() {
    assert_eq!(plus_u_p::<5>([0; 5], 1, 0), widen(PRIME));
    // -p^-1 = 1 mod 2^64: p = -1 mod 2^64.
    assert_eq!(PRIME[0], u64::MAX);
}

/// `mont_step` meets its contract for every `w`: `2^64 * mont_step(w) = w +
/// w0 * p`. The code multiplies by `p3 = 2^64 - 2^32 + 1`; the specification
/// has no multiplication. Bitwuzla closes it; CaDiCaL, the default, gave no
/// verdict in 25 minutes on the same step in an earlier attempt.
#[kani::proof_for_contract(mont_step)]
#[kani::solver(bitwuzla)]
fn mont_step_meets_its_contract() {
    mont_step(kani::any());
}

/// `montgomery_low` meets its contract for every `lo`, with each of its four
/// steps replaced by `mont_step`'s contract, which the proof above checks:
/// `2^256 w = lo + U p` for the textbook digits, and `w <= p`.
#[kani::proof_for_contract(montgomery_low)]
#[kani::stub_verified(mont_step)]
#[kani::solver(bitwuzla)]
fn montgomery_low_meets_its_contract() {
    montgomery_low(kani::any());
}

/// `finish` meets its contract for every `hi < p` and `w <= p`.
#[kani::proof_for_contract(finish)]
fn finish_meets_its_contract() {
    finish(kani::any(), kani::any());
}

/// `reduce` meets its contract for every eight-word `t` with upper half below
/// `p`, over the contracts of `montgomery_low` and `finish`.
#[kani::proof_for_contract(reduce)]
#[kani::stub_verified(montgomery_low)]
#[kani::stub_verified(finish)]
#[kani::solver(bitwuzla)]
fn reduce_meets_its_contract() {
    reduce(kani::any());
}

/// `x * y` for two words, as a `u128`. `wrapping_mul` only to keep the
/// model checker off a 256-bit overflow test: a product of two 64-bit values
/// is below `2^128` and never wraps.
fn word_product(x: u64, y: u64) -> u128 {
    (x as u128).wrapping_mul(y as u128)
}

/// What [`mac`] promises: `lo + 2^64 hi = a + b c + carry`, exactly. The sum
/// is at most `2^128 - 1`, so the 128-bit arithmetic here does not wrap.
pub(super) fn mac_post(a: u64, b: u64, c: u64, carry: u64, r: (u64, u64)) -> bool {
    let want = (a as u128)
        .wrapping_add(word_product(b, c))
        .wrapping_add(carry as u128);
    (r.0 as u128 | ((r.1 as u128) << 64)) == want
}

/// `mac` meets its contract for every input, without overflow.
#[kani::proof_for_contract(mac)]
#[kani::solver(bitwuzla)]
fn mac_meets_its_contract() {
    mac(kani::any(), kani::any(), kani::any(), kani::any());
}

// ---------------------------------------------------------------------------
// The products: the schoolbooks, split into a linear and a nonlinear part.
// ---------------------------------------------------------------------------
//
// Asked whether the schoolbook equals the integer product, no solver here gave
// a verdict (docs/PROOFS.md lists what was tried): every formula kept sixteen
// symbolic 64-by-64 multiplications, even with `mac` replaced by its contract,
// whose postcondition mentions `b c`. So the claim is split.
//
// - Linear, here: with the one multiplication in `mac`, `wrapping_mul`,
//   replaced by `product_abstract`, which returns an arbitrary value no
//   larger than `(2^64 - 1)^2` and logs the operands it was given, the eight
//   words the schoolbook returns are `sum_k p_k 2^(64 (i_k + j_k))`, exactly,
//   for the schedule the log records. `mac`'s additions and the whole carry
//   structure run as written; no multiplication is left in the formula.
//   (`mac` then does not meet its contract, so these harnesses need Kani's
//   `--no-assert-contracts`, which `scripts/kani.sh` passes.)
// - Nonlinear, outside the code: `sum_(i,j) a_i b_j 2^(64 (i + j)) = a b` over
//   the integers, and the squaring identity, which are statements about
//   polynomials and are checked by Z3 and cvc5 in `crates/ic-ec/proofs/smt/`.
// - The step between: the real `wrapping_mul` of two words is their product
//   `b c`, a value the abstract proof covers since `b c <= (2^64 - 1)^2`. So
//   the real schoolbook returns the sum of the true word products at their
//   weights, which is `product_spec`. That instantiation is argued, not run:
//   it is the step from "for every `p`" to "for `p = b c`".

/// `(2^64 - 1)^2 = 2^128 - 2^65 + 1`: the largest product of two words, and
/// the only property of a true product the abstract one is given.
const MAX_WORD_PRODUCT: u128 = 0xffff_ffff_ffff_fffe_0000_0000_0000_0001;

// The ghost log: the operands of each multiplication, and the product it was
// given, in call order. Kani-only; each harness starts from the initial
// values.
static mut LOG_X: [u128; 16] = [0; 16];
static mut LOG_Y: [u128; 16] = [0; 16];
static mut LOG_P: [u128; 16] = [0; 16];
static mut LOG_LEN: usize = 0;

/// The one multiplication in `mac`, `(b as u128).wrapping_mul(c as u128)`,
/// taken away: the product is any value no larger than `(2^64 - 1)^2`, chosen
/// by the solver, and `(x, y, p)` is appended to the ghost log. Everything
/// else in `mac` -- the two additions, checked, and the split into words --
/// runs as written.
fn product_abstract(x: u128, y: u128) -> u128 {
    let p: u128 = kani::any();
    kani::assume(p <= MAX_WORD_PRODUCT);
    // SAFETY: Kani runs a harness on one thread.
    unsafe {
        let n = LOG_LEN;
        if n < 16 {
            LOG_X[n] = x;
            LOG_Y[n] = y;
            LOG_P[n] = p;
        }
        LOG_LEN = n + 1;
    }
    p
}

/// The ghost log, read once a harness has run the code.
fn ghost_log() -> (usize, [u128; 16], [u128; 16], [u128; 16]) {
    // SAFETY: as above; these are copies, not references.
    unsafe { (LOG_LEN, LOG_X, LOG_Y, LOG_P) }
}

/// `x * 2^(64 k)` for a two-word `x`, as `N` words.
fn term_at<const N: usize>(x: u128, k: usize) -> [u64; N] {
    let mut r = [0u64; N];
    r[k] = x as u64;
    r[k + 1] = (x >> 64) as u64;
    r
}

/// The low eight words of nine.
fn low8(x: [u64; 9]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..8 {
        r[i] = x[i];
    }
    r
}

/// `sum_j t_j 2^(64 j)`, five words: one row of the schoolbook, from its
/// four products, with full carries.
fn row_from(t: [u128; 4]) -> [u64; 5] {
    let mut r = [0u64; 5];
    for j in 0..4 {
        r = add_w(r, term_at(t[j], j));
    }
    r
}

/// `sum_(i,j) t_ij 2^(64 (i + j))`, nine words, row by row: the reference sum
/// for the product, from sixteen products whatever they are. Nine words, so
/// that a carry out of the eighth is kept and can be asserted zero.
fn product_from(t: [[u128; 4]; 4]) -> [u64; 9] {
    let mut s = [0u64; 9];
    for i in 0..4 {
        let row = row_from(t[i]);
        let mut term = [0u64; 9];
        for k in 0..5 {
            term[i + k] = row[k];
        }
        s = add_w(s, term);
    }
    s
}

/// `sum_i d_i 2^(128 i) + sum_(i<j) 2 x_ij 2^(64 (i + j))`, nine words: the
/// reference sum for the square, the doubling written as adding twice.
fn square_from(d: [u128; 4], x: [[u128; 4]; 4]) -> [u64; 9] {
    let mut s = [0u64; 9];
    for i in 0..4 {
        s = add_w(s, term_at(d[i], 2 * i));
        for j in i + 1..4 {
            let t = term_at(x[i][j], i + j);
            s = add_w(add_w(s, t), t);
        }
    }
    s
}

/// The sixteen word products of `a` and `b`.
fn word_products(a: [u64; 4], b: [u64; 4]) -> [[u128; 4]; 4] {
    let mut t = [[0u128; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            t[i][j] = word_product(a[i], b[j]);
        }
    }
    t
}

/// `a * b` as integers: the reference sum over the true word products. It is
/// below `2^512`, so eight words hold it; that `sum_(i,j) a_i b_j 2^(64 (i +
/// j))` is the product of the integers `a` and `b` is the polynomial identity
/// in `crates/ic-ec/proofs/smt/`.
fn product_spec(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    low8(product_from(word_products(a, b)))
}

/// `a^2` as integers, likewise: the squares at weight `2i` and the cross
/// products twice at weight `i + j`.
fn square_spec(a: [u64; 4]) -> [u64; 8] {
    let t = word_products(a, a);
    let mut d = [0u128; 4];
    for i in 0..4 {
        d[i] = t[i][i];
    }
    low8(square_from(d, t))
}

/// The order `product` multiplies in: row `i`, then column `j`.
const MUL_SCHEDULE: [(usize, usize); 16] = [
    (0, 0),
    (0, 1),
    (0, 2),
    (0, 3),
    (1, 0),
    (1, 1),
    (1, 2),
    (1, 3),
    (2, 0),
    (2, 1),
    (2, 2),
    (2, 3),
    (3, 0),
    (3, 1),
    (3, 2),
    (3, 3),
];

/// The order `square_product` multiplies in: the six cross products, then the
/// four squares.
const SQUARE_SCHEDULE: [(usize, usize); 10] = [
    (0, 1),
    (0, 2),
    (0, 3),
    (1, 2),
    (1, 3),
    (2, 3),
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
];

/// The linear part of `mul`'s schoolbook, for every `a`, `b` and every
/// sixteen products: with each multiply-add given an arbitrary product no
/// larger than `(2^64 - 1)^2`, the schoolbook asks for exactly sixteen, the
/// `k`-th of `a_i` and `b_j` for `(i, j)` the `k`-th of [`MUL_SCHEDULE`], and
/// returns `sum_k p_k 2^(64 (i_k + j_k))`, which is below `2^512`. Nothing is
/// assumed of `a` or `b`: the bound on the products is all the carries need.
#[kani::proof]
#[kani::stub(u128::wrapping_mul, product_abstract)]
fn the_schoolbook_sums_its_products_at_their_weights() {
    let (a, b): ([u64; 4], [u64; 4]) = (kani::any(), kani::any());
    let t = product(a, b);
    let (n, xs, ys, ps) = ghost_log();
    assert!(n == 16);
    let mut terms = [[0u128; 4]; 4];
    for k in 0..16 {
        let (i, j) = MUL_SCHEDULE[k];
        assert!(xs[k] == a[i] as u128 && ys[k] == b[j] as u128);
        terms[i][j] = ps[k];
    }
    let want = product_from(terms);
    assert!(want[8] == 0);
    assert!(eq(&t, &low8(want)));
}

/// The linear part of `square`'s schoolbook, likewise: ten products asked
/// for, in [`SQUARE_SCHEDULE`]'s order, and the result is the cross products
/// doubled at weight `i + j` plus the squares at weight `2i`. The doubling the
/// code does with shifts is checked here against adding twice. Bitwuzla, with
/// no multiplication left in the formula, takes about half CaDiCaL's time.
#[kani::proof]
#[kani::stub(u128::wrapping_mul, product_abstract)]
#[kani::solver(bitwuzla)]
fn the_square_schoolbook_sums_its_products_at_their_weights() {
    let a: [u64; 4] = kani::any();
    let t = square_product(a);
    let (n, xs, ys, ps) = ghost_log();
    assert!(n == 10);
    let mut d = [0u128; 4];
    let mut x = [[0u128; 4]; 4];
    for k in 0..10 {
        let (i, j) = SQUARE_SCHEDULE[k];
        assert!(xs[k] == a[i] as u128 && ys[k] == a[j] as u128);
        if i == j {
            d[i] = ps[k];
        } else {
            x[i][j] = ps[k];
        }
    }
    let want = square_from(d, x);
    assert!(want[8] == 0);
    assert!(eq(&t, &low8(want)));
}

/// For `a`, `b` below `p`, the upper half of `a b` is below `p`, so the
/// product lies in `reduce`'s domain. (`a b < p 2^256` because `b < 2^256`.)
#[kani::proof]
#[kani::solver(bitwuzla)]
fn the_product_of_residues_is_in_reduce_s_domain() {
    let (a, b) = (any_residue(), any_residue());
    assert!(reduce_pre(product_spec(a, b)));
    assert!(reduce_pre(square_spec(a)));
}

// The composition, `mul` and `square` meeting `out < p`, `2^256 out = a b mod
// p` over `reduce`'s contract with the product replaced by "any eight words
// equal to `product_spec(a, b)`", was written as a `proof_for_contract`
// harness and gave no verdict in 30 minutes on Bitwuzla, as the same harness
// over the old product contract did before. It is argued in docs/PROOFS.md:
// substitution of the schoolbook's result into `reduce`'s proved contract,
// with the domain lemma above discharging its precondition.
