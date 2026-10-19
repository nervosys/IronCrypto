//! Bounded proofs of the word-by-word Montgomery multiplication (CIOS),
//! `arith::wide::mont_mul`, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-ec
//! ```
//!
//! The multiplication is proved the way P-256's schoolbook is (docs/PROOFS.md,
//! "The products"): split into a part about carries, which Kani proves with
//! every 64-by-64 product replaced by an arbitrary bounded value, and a part
//! about multiplication, which is a polynomial identity over the integers
//! checked by Z3 and cvc5 in `crates/ic-ec/proofs/smt/`. Here, at six words
//! and for every modulus `m` and every `neg_inv` (so for both P-384 rings, and
//! not only for them):
//!
//! - the word products are replaced by [`abstract_word_mul`], which returns an
//!   arbitrary `p <= (2^64 - 1)^2` and logs its operands and itself;
//! - the quotient digits are replaced by [`abstract_digit`], which returns an
//!   arbitrary word and logs the word it was given.
//!
//! One outer iteration of the loop is two phases (`cios_mul_phase!`,
//! `cios_reduce_phase!`, macros expanded in `mont_mul` and, for the harnesses,
//! in functions of the same name). Each phase has a harness that runs the real
//! code on every state and asserts that the products were asked for in the
//! order the algorithm lists them, with the operands it lists, and that the
//! result is related to the state by an identity over the integers:
//!
//! ```text
//! mul phase:     T'              = T + sum_j pa_j 2^(64 j)
//! reduce phase:  2^64 T'' + l    = T' + sum_j pm_j 2^(64 j)
//! ```
//!
//! with `pa_j` the product asked for as `a_j b_i`, `pm_j` the one asked for as
//! `u m_j`, and `l` the low word of `t_0 + pm_0`, the word the code drops
//! (it takes only the carry of that multiply-add). The six rows telescope: from
//! `T = 0`, six times, the two relations give
//!
//! ```text
//! 2^384 T_6 + sum_i l_i 2^(64 i) = sum_(i,j) (pa_ij + pm_ij) 2^(64 (i + j))
//! ```
//!
//! and that step is linear arithmetic over the integers, checked by Z3 and
//! cvc5 in `crates/ic-ec/proofs/smt/mont-rows.smt2`. (A Kani version, one
//! harness per row, did not finish; docs/PROOFS.md.)
//!
//! What is argued rather than run is stated in docs/PROOFS.md: that the
//! phases are what `mont_mul` runs six times (read off its three-line loop),
//! that the true products may be substituted for the abstract ones, that the
//! sums are then `a b` and `U m` (the polynomial identity, `proofs/smt/`),
//! that every `l_i` is zero (the digit lemma, per ring, `p384/proofs.rs`), and
//! that `T < 2 m` follows from `a`, `b` below `m` (also `proofs/smt/`).

use super::wide::{cios_mul_phase, cios_reduce_phase, quotient_digit, word_mul};
use super::MAX_LIMBS;

/// `(2^64 - 1)^2`: the largest product of two words, and the only property of
/// a true product that the abstract one is given.
pub(crate) const MAX_WORD_PRODUCT: u128 = 0xffff_ffff_ffff_fffe_0000_0000_0000_0001;

const N: usize = 6;
/// Products a harness logs: at most the twelve of one row.
const PRODUCTS: usize = 2 * N;

// The ghost logs. Kani-only; each harness starts from the initial values.
static mut LOG_X: [u64; PRODUCTS] = [0; PRODUCTS];
static mut LOG_Y: [u64; PRODUCTS] = [0; PRODUCTS];
static mut LOG_P: [u128; PRODUCTS] = [0; PRODUCTS];
static mut LOG_LEN: usize = 0;
static mut DIG_T0: [u64; N] = [0; N];
static mut DIG_U: [u64; N] = [0; N];
static mut DIG_LEN: usize = 0;

/// The multiplication in `word_mul`, taken away: any value no larger than
/// `(2^64 - 1)^2`, with its operands and itself appended to the log.
fn abstract_word_mul(x: u64, y: u64) -> u128 {
    let p: u128 = kani::any();
    kani::assume(p <= MAX_WORD_PRODUCT);
    // SAFETY: Kani runs a harness on one thread.
    unsafe {
        let n = LOG_LEN;
        if n < PRODUCTS {
            LOG_X[n] = x;
            LOG_Y[n] = y;
            LOG_P[n] = p;
        }
        LOG_LEN = n + 1;
    }
    p
}

/// The quotient digit, taken away: any word, logged with the word it was
/// computed from.
fn abstract_digit(t0: u64, _neg_inv: u64) -> u64 {
    let u: u64 = kani::any();
    // SAFETY: as above.
    unsafe {
        let n = DIG_LEN;
        if n < N {
            DIG_T0[n] = t0;
            DIG_U[n] = u;
        }
        DIG_LEN = n + 1;
    }
    u
}

/// `a + b mod 2^(64 L)`.
fn add_w<const L: usize>(a: [u64; L], b: [u64; L]) -> [u64; L] {
    let mut r = [0u64; L];
    let mut carry: u128 = 0;
    for i in 0..L {
        let t = a[i] as u128 + b[i] as u128 + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    r
}

/// `x * 2^(64 k)` for a two-word `x`, as `L` words.
fn term_at<const L: usize>(x: u128, k: usize) -> [u64; L] {
    let mut r = [0u64; L];
    r[k] = x as u64;
    r[k + 1] = (x >> 64) as u64;
    r
}

/// `a = b`, as a conjunction of word equalities, as in the P-256 proofs.
fn eq<const L: usize>(a: &[u64; L], b: &[u64; L]) -> bool {
    let mut same = true;
    for i in 0..L {
        same &= a[i] == b[i];
    }
    same
}

/// `x * 2^(64 k)` for a two-word `x`, added into `acc`.
fn add_at<const L: usize>(acc: [u64; L], x: u128, k: usize) -> [u64; L] {
    add_w(acc, term_at(x, k))
}

/// What the multiplication phase does, for any six products: `T'` (eight
/// words) is `T` (seven) plus `sum_j pa_j 2^(64 j)`.
fn mul_identity(t_in: [u64; N + 1], pa: [u128; N], t_out: [u64; N + 2]) -> bool {
    let mut rhs = [0u64; N + 3];
    for i in 0..=N {
        rhs[i] = t_in[i];
    }
    for j in 0..N {
        rhs = add_at(rhs, pa[j], j);
    }
    let mut lhs = [0u64; N + 3];
    for i in 0..N + 2 {
        lhs[i] = t_out[i];
    }
    eq(&lhs, &rhs)
}

/// What the reduction phase does, for any six products: `2^64 T' + l = T +
/// sum_j pm_j 2^(64 j)`, `T` eight words, `T'` seven, `l` the dropped word.
fn reduce_identity(t_in: [u64; N + 2], pm: [u128; N], l: u64, t_out: [u64; N + 1]) -> bool {
    let mut lhs = [0u64; N + 3];
    for i in 0..=N {
        lhs[i + 1] = t_out[i];
    }
    lhs = add_at(lhs, l as u128, 0);
    let mut rhs = [0u64; N + 3];
    for i in 0..N + 2 {
        rhs[i] = t_in[i];
    }
    for j in 0..N {
        rhs = add_at(rhs, pm[j], j);
    }
    eq(&lhs, &rhs)
}

/// The linear part of the multiplication phase (`t += a b_i`), for every `a`,
/// `bi`, every state `t` and every six products: the phase asks for the six
/// products `a_j bi` and leaves [`mul_identity`].
#[kani::proof]
#[kani::unwind(15)]
#[kani::stub(word_mul, abstract_word_mul)]
fn cios_mul_phase_sums_its_products_at_their_weights() {
    let a: [u64; N] = kani::any();
    let bi: u64 = kani::any();
    let mut t: [u64; MAX_LIMBS + 2] = kani::any();
    let before = t;
    cios_mul_phase(&mut t, a, bi);
    // SAFETY: as above; copies, not references.
    let (n, xs, ys, ps) = unsafe { (LOG_LEN, LOG_X, LOG_Y, LOG_P) };
    assert!(n == N);
    let mut pa = [0u128; N];
    for j in 0..N {
        assert!(xs[j] == a[j] && ys[j] == bi);
        pa[j] = ps[j];
    }
    let mut t_in = [0u64; N + 1];
    let mut t_out = [0u64; N + 2];
    for i in 0..=N {
        t_in[i] = before[i];
    }
    for i in 0..N + 2 {
        t_out[i] = t[i];
    }
    assert!(mul_identity(t_in, pa, t_out));
    // The carry out of the top word is a single bit: what the reduction
    // phase's `t[N] = t[N + 1] + carry` relies on to lose nothing.
    assert!(t[N + 1] <= 1);
}

/// The linear part of the reduction phase (`t = (t + u m) / 2^64`), for every
/// `m`, `neg_inv`, every state `t` and every six products and digit: the phase
/// asks for the digit of `t[0]`, then the six products `u m_j`, for `t[N + 1]`
/// at most 1 (what the multiplication phase leaves), leaves `t[N + 1]` zero, and satisfies [`reduce_identity`] with the word it drops.
#[kani::proof]
#[kani::unwind(15)]
#[kani::stub(word_mul, abstract_word_mul)]
#[kani::stub(quotient_digit, abstract_digit)]
fn cios_reduce_phase_sums_its_products_at_their_weights() {
    let m: [u64; N] = kani::any();
    let neg_inv: u64 = kani::any();
    let mut t: [u64; MAX_LIMBS + 2] = kani::any();
    // The multiplication phase leaves a single bit here (checked above).
    kani::assume(t[N + 1] <= 1);
    let before = t;
    cios_reduce_phase(&mut t, m, neg_inv);
    // SAFETY: as above; copies, not references.
    let (n, xs, ys, ps, dn, dt, du) =
        unsafe { (LOG_LEN, LOG_X, LOG_Y, LOG_P, DIG_LEN, DIG_T0, DIG_U) };
    assert!(n == N && dn == 1 && dt[0] == before[0]);
    let mut pm = [0u128; N];
    for j in 0..N {
        assert!(xs[j] == du[0] && ys[j] == m[j]);
        pm[j] = ps[j];
    }
    // The first multiply-add adds `t0` and keeps only the carry; this is the
    // low word it drops.
    let low = (before[0] as u128 + pm[0]) as u64;
    assert!(t[N + 1] == 0);
    let mut t_in = [0u64; N + 2];
    let mut t_out = [0u64; N + 1];
    for i in 0..N + 2 {
        t_in[i] = before[i];
    }
    for i in 0..=N {
        t_out[i] = t[i];
    }
    assert!(reduce_identity(t_in, pm, low, t_out));
}

/// `word_mul` returns at most `(2^64 - 1)^2` for every pair of words: the
/// bound [`abstract_word_mul`] assumes of the product it replaces. (It is the
/// whole of what the abstract proof knows about a product.)
#[kani::proof]
#[kani::solver(bitwuzla)]
fn word_mul_is_bounded() {
    assert!(word_mul(kani::any(), kani::any()) <= MAX_WORD_PRODUCT);
}
