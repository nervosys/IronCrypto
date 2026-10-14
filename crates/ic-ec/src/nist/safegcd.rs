//! Constant-time modular inversion by Bernstein and Yang's divsteps, for
//! P-256's two rings and P-384's coordinate field.
//!
//! "Fast constant-time gcd computation and modular inversion", Bernstein and
//! Yang, TCHES 2019, in the form libsecp256k1 implements as `modinv64`
//! (`src/modinv64_impl.h`): values in signed 62-bit limbs, a batch of
//! divsteps at a time on the low limbs alone, each batch's 2x2 transition
//! matrix then applied to the full-width `f, g` and to the Bezout
//! coefficients `d, e`, which are kept reduced modulo the modulus as they go.
//! Extra divsteps after `g` reaches zero change nothing, so each count below
//! is an upper bound and not a tuning.
//!
//! # Two step counts, two kinds of step
//!
//! Below `2^256` (P-256): five limbs, Pieter Wuille's "half-delta" divsteps,
//! 59 to a batch, ten batches. 590 divsteps are enough for any modulus and
//! input below `2^256`; that bound is libsecp256k1's, computed with
//! <https://github.com/sipa/safegcd-bounds>.
//!
//! Below `2^384` (P-384's prime): seven limbs, and the paper's own divstep,
//! `delta` starting at 1, 62 to a batch, eighteen batches. That bound is the
//! paper's Theorem 11.2: for odd `f` and `f^2 + 4 g^2 <= 5 * 2^(2d)`,
//! `floor((49d + 80) / 17)` divsteps bring `g` to zero when `d >= 46`. Here
//! `f` is the prime and `g` below it, both below `2^384`, so `d = 384`
//! qualifies and the bound is 1111; eighteen batches are 1116. The half-delta
//! steps would need fewer, but their bound at this width is not one this
//! module can cite, so it uses the steps it can.
//!
//! Both batches leave a matrix, scaled by `2^62`, with `|u| + |v|` and
//! `|q| + |r|` at most `2^62`: a step either doubles a row or replaces it by
//! the sum or difference of the two, so each row's sum at most doubles per
//! step, from one (or eight, for 59 steps started at `8 * I`). That is what
//! `update_de` needs to keep `d` and `e` in `(-2m, m)`, and what keeps every
//! product in it inside an `i128`.
//!
//! # Rounds of packed steps
//!
//! Within a batch the steps run in rounds of at most 19, each on the low 20
//! bits of `f` and `g` packed with their rows of the matrix into two words
//! (see "The steps, packed", below): 19, 19, 19 and 2 for P-256's 59, 19,
//! 19, 19 and 5 for P-384's 62. The decisions are the same, on the same bits,
//! as stepping six words at a time; the tests hold every batch to the
//! divsteps taken one by one on whole integers. On x86-64 the rounds are
//! assembly (`safegcd_x86`), each decision a conditional move: with the
//! packing, that took P-384's field inversion from 2.2 to 1.55 microseconds
//! on the Zen 5 the benchmarks run on, where the packing alone, its
//! decisions still masks, changed nothing -- a step's time was the chain
//! from `g`'s parity through its mask to the next `g`, not the number of
//! words.
//!
//! # Constant time
//!
//! The number of divsteps is fixed, and each is branch-free: its two
//! decisions -- the sign of `zeta` or `delta`, whether `g` is odd -- become
//! conditional moves on x86-64 and masks behind `black_box` elsewhere, as
//! do the signs that `normalize` acts on, and `update_de`'s signs are masks.
//! The only conditions in the source are on the modulus's limbs and on limb
//! indices, and each modulus is a type ([`Modulus`]) with its own copy of the
//! inversion, so those are constants and fold away. Every multiplication is
//! 64 by 64 bits into 128, which is one instruction on the 64-bit targets
//! this is used on and is not used elsewhere: a 32-bit target would lower
//! `i128` products to library calls, so they keep Fermat. The steps are
//! written out and the batches are calls, so the compiled inversions have no
//! loop and no branch at all for `scripts/check-ct.py` to find
//! (`ct_p256_fp_invert`, `ct_p256_fn_invert`, `ct_p384_fp_invert`).
//!
//! # Why
//!
//! An inversion by Fermat's little theorem is about 255 squarings and a
//! few dozen multiplications for P-256, 385 squarings for P-384; with the
//! generic multiplication P-256's scalar inversion took 5.3 microseconds,
//! more than a third of a signature, and P-384's field inversion, even on
//! the squaring specialised to its prime, was about a tenth of an ECDH. This
//! is a fraction of each.

/// `2^62 - 1`.
const M62: u64 = u64::MAX >> 2;

/// A value in `N` signed 62-bit limbs, least significant first: every limb
/// but the top one in `[0, 2^62)` between operations, the top one signed.
type Signed62<const N: usize> = [i64; N];

/// The modulus in signed-62 form, and its inverse modulo `2^62`.
#[derive(Clone, Copy)]
pub(crate) struct ModInfo<const N: usize> {
    modulus: Signed62<N>,
    modulus_inv62: u64,
}

impl<const N: usize> ModInfo<N> {
    /// For an odd modulus of `W` little-endian words; `N` limbs must hold it
    /// with room for a sign.
    pub(crate) const fn new<const W: usize>(m: [u64; W]) -> Self {
        assert!(62 * N > 64 * W && 62 * (N - 1) < 64 * W);
        let modulus = to_signed62::<W, N>(m);
        // Inverse modulo 2^64 by Newton iteration, then reduced: each step
        // doubles the number of correct low bits, from 3 for an odd m.
        let mut inv = m[0];
        let mut i = 0;
        while i < 6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            i += 1;
        }
        ModInfo {
            modulus,
            modulus_inv62: inv & M62,
        }
    }
}

/// `W` 64-bit words as `N` 62-bit limbs, the top limb taking what is left.
const fn to_signed62<const W: usize, const N: usize>(a: [u64; W]) -> Signed62<N> {
    let mut out = [0i64; N];
    let mut i = 0;
    while i < N {
        let bit = 62 * i;
        let (word, off) = (bit / 64, bit % 64);
        let mut v = 0u64;
        if word < W {
            v = a[word] >> off;
            // The limb runs into the next word when this one has fewer than
            // 62 bits left.
            if off > 2 && word + 1 < W {
                v |= a[word + 1] << (64 - off);
            }
        }
        out[i] = if i + 1 < N {
            (v & M62) as i64
        } else {
            v as i64
        };
        i += 1;
    }
    out
}

/// `N` limbs, each in `[0, 2^62)`, as `W` 64-bit words.
#[inline(always)]
fn from_signed62<const N: usize, const W: usize>(a: &Signed62<N>) -> [u64; W] {
    let mut out = [0u64; W];
    for (i, &limb) in a.iter().enumerate() {
        let bit = 62 * i;
        let (word, off) = (bit / 64, bit % 64);
        let v = limb as u64;
        if word < W {
            out[word] |= v << off;
        }
        if off > 2 && word + 1 < W {
            out[word + 1] |= v >> (64 - off);
        }
    }
    out
}

/// The transition matrix of a batch of divsteps, scaled by `2^62`.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

// # The steps, packed
//
// A batch's steps decide on the low bits of `f` and `g` alone, and between
// them carry the matrix along: as written out by libsecp256k1, every step
// updates six words. Here each of `f` and `g` is packed with its row of the
// matrix into one word -- `f`'s low bits and its row `(a, b)` as
// `F = f + a 2^21 + b 2^42`, `g`'s likewise as `G` -- so that a step updates
// two words where it updated six, and its decisions are the same ones on the
// same low bits. The packing is linear: `G + F` and `G - F` add and subtract
// the rows with the values. A round of `s` steps starts each row at `2^s`
// times the identity and halves `G` where the step halves `g`, so after `j`
// steps every entry is a multiple of `2^(s - j)` and each halving is exact
// field by field; after `s` steps the rows are the round's matrix, scaled by
// `2^s`. Then the 64-bit words of `f` and `g` move on by that matrix, exact
// in their low `64 - s` bits, the rounds' matrices multiply, and the next
// round starts.
//
// The fields hold what they must: a round's matrix rows have `|a| + |b|` at
// most `2^s` (each step at most doubles a row sum, scaled, as the module
// documentation says), so with `s` at most 19 each entry fits the 21 bits
// between its neighbours, sign included; and the low field, `(a f0 + b g0) /
// 2^j` for `f0` and `g0` below `2^20`, stays below `2^20` in magnitude.
// Twenty steps would not fit: a row that never changes is `2^20 I`.

/// Bits of `f` and `g` a packed round starts from, and the steps it may run.
const LOW: u32 = 20;
const MAX_ROUND: u32 = 19;

/// The matrix of a round, from its packed rows: `(a, b)` from `F`, `(c, d)`
/// from `G`, each a field of 21 bits, sign-extended, above the low field.
#[inline(always)]
fn unpack(p: i64) -> (i64, i64) {
    let low = (p << 43) >> 43;
    let rest = (p - low) >> 21;
    let a = (rest << 43) >> 43;
    let b = (rest - a) >> 21;
    (a, b)
}

/// One half-delta divstep on the packed rows, branch-free, `zeta` as in
/// libsecp256k1's `secp256k1_modinv64_divsteps_59`: the same decisions on the
/// same low bits, and the same sums and halvings, on two words.
#[cfg(any(test, not(target_arch = "x86_64")))]
#[inline(always)]
fn hdstep(zeta: &mut i64, f: &mut i64, g: &mut i64) {
    // Masks for zeta < 0 and for g odd. Behind the barrier, as libsecp256k1
    // puts them behind `volatile`, so that the compiler cannot see they are 0
    // or all ones and branch on them.
    let mut mask1 = core::hint::black_box(*zeta >> 63);
    let c2 = core::hint::black_box(*g & 1);
    let mask2 = c2.wrapping_neg();
    // f, negated when zeta < 0, added to g when g is odd.
    let x = (*f ^ mask1).wrapping_sub(mask1);
    *g = g.wrapping_add(x & mask2);
    // When both, swap roles: zeta becomes -zeta - 2, otherwise zeta - 1;
    // f becomes the old g, which is the new g less (-f).
    mask1 &= mask2;
    *zeta = (*zeta ^ mask1).wrapping_sub(1);
    *f = f.wrapping_add(*g & mask1);
    *g >>= 1;
}

/// One of Bernstein and Yang's divsteps on the packed rows, branch-free:
/// where `delta > 0` and `g` is odd, `(delta, f, g)` becomes `(1 - delta, g,
/// (g - f) / 2)`; otherwise `(1 + delta, f, (g + (g mod 2) f) / 2)`.
#[cfg(any(test, not(target_arch = "x86_64")))]
#[inline(always)]
fn divstep(delta: &mut i64, f: &mut i64, g: &mut i64) {
    // Masks for delta > 0 and for g odd, behind the barrier as in `hdstep`.
    let c1 = core::hint::black_box(delta.wrapping_neg() >> 63);
    let c2 = core::hint::black_box(*g & 1);
    let odd = c2.wrapping_neg();
    let swap = c1 & odd;
    // f, negated on a swap; added to g where g is odd. On a swap f becomes
    // the old g: g now holds g - f, so adding it gives exactly that.
    let x = (*f ^ swap).wrapping_sub(swap);
    *g = g.wrapping_add(x & odd);
    *f = f.wrapping_add(*g & swap);
    // delta: 1 - delta on a swap, 1 + delta otherwise.
    *delta = (*delta ^ swap).wrapping_sub(swap).wrapping_add(1);
    *g >>= 1;
}

/// The step `$f`, written out `$n` times, for `$n` a power of two up to 16.
/// Written out rather than looped, so that the compiled inversion has no
/// loop for `scripts/check-ct.py` to find.
#[cfg(any(test, not(target_arch = "x86_64")))]
macro_rules! steps {
    ($f:ident, $d:ident, $x:ident, $y:ident, 1) => {
        $f(&mut $d, &mut $x, &mut $y);
    };
    ($f:ident, $d:ident, $x:ident, $y:ident, 2) => {
        steps!($f, $d, $x, $y, 1);
        steps!($f, $d, $x, $y, 1);
    };
    ($f:ident, $d:ident, $x:ident, $y:ident, 4) => {
        steps!($f, $d, $x, $y, 2);
        steps!($f, $d, $x, $y, 2);
    };
    ($f:ident, $d:ident, $x:ident, $y:ident, 8) => {
        steps!($f, $d, $x, $y, 4);
        steps!($f, $d, $x, $y, 4);
    };
    ($f:ident, $d:ident, $x:ident, $y:ident, 16) => {
        steps!($f, $d, $x, $y, 8);
        steps!($f, $d, $x, $y, 8);
    };
}

/// The rounds' steps, written out: in assembly on x86-64, where each
/// decision is a conditional move (`safegcd_x86`), and as the Rust steps
/// above elsewhere. The same steps either way, which the tests check.
#[cfg(target_arch = "x86_64")]
use super::safegcd_x86::{by_19, by_5, hd_19, hd_2};
#[cfg(not(target_arch = "x86_64"))]
use {rs_by_19 as by_19, rs_by_5 as by_5, rs_hd_19 as hd_19, rs_hd_2 as hd_2};

#[cfg(any(test, not(target_arch = "x86_64")))]
#[inline(always)]
fn rs_by_19(d: &mut i64, f: &mut i64, g: &mut i64) {
    let (mut d2, mut f2, mut g2) = (*d, *f, *g);
    steps!(divstep, d2, f2, g2, 16);
    steps!(divstep, d2, f2, g2, 2);
    steps!(divstep, d2, f2, g2, 1);
    (*d, *f, *g) = (d2, f2, g2);
}

#[cfg(any(test, not(target_arch = "x86_64")))]
#[inline(always)]
fn rs_by_5(d: &mut i64, f: &mut i64, g: &mut i64) {
    let (mut d2, mut f2, mut g2) = (*d, *f, *g);
    steps!(divstep, d2, f2, g2, 4);
    steps!(divstep, d2, f2, g2, 1);
    (*d, *f, *g) = (d2, f2, g2);
}

#[cfg(any(test, not(target_arch = "x86_64")))]
#[inline(always)]
fn rs_hd_19(d: &mut i64, f: &mut i64, g: &mut i64) {
    let (mut d2, mut f2, mut g2) = (*d, *f, *g);
    steps!(hdstep, d2, f2, g2, 16);
    steps!(hdstep, d2, f2, g2, 2);
    steps!(hdstep, d2, f2, g2, 1);
    (*d, *f, *g) = (d2, f2, g2);
}

#[cfg(any(test, not(target_arch = "x86_64")))]
#[inline(always)]
fn rs_hd_2(d: &mut i64, f: &mut i64, g: &mut i64) {
    let (mut d2, mut f2, mut g2) = (*d, *f, *g);
    steps!(hdstep, d2, f2, g2, 2);
    (*d, *f, *g) = (d2, f2, g2);
}

/// A round of `$n` steps, run by `$run`, from `delta` and the 64-bit words
/// `f`, `g`, into `m`, the batch's matrix so far, scaled by `2^` the steps
/// before.
macro_rules! round {
    ($run:ident, $delta:ident, $fw:ident, $gw:ident, $m:ident, $n:expr) => {{
        const S: u32 = $n;
        const _: () = assert!(S <= MAX_ROUND);
        let mut pf = ($fw & ((1 << LOW) - 1)) as i64 + ((1i64 << S) << 21);
        let mut pg = ($gw & ((1 << LOW) - 1)) as i64 + ((1i64 << S) << 42);
        $run(&mut $delta, &mut pf, &mut pg);
        let (a, b) = unpack(pf);
        let (c, d) = unpack(pg);
        // f and g move on: exact in their low 64 - S bits, which is more
        // than the steps after this round read.
        let (fi, gi) = ($fw as i64, $gw as i64);
        $fw = (a.wrapping_mul(fi).wrapping_add(b.wrapping_mul(gi)) >> S) as u64;
        $gw = (c.wrapping_mul(fi).wrapping_add(d.wrapping_mul(gi)) >> S) as u64;
        let [u, v, q, r] = $m;
        $m = [
            a.wrapping_mul(u).wrapping_add(b.wrapping_mul(q)),
            a.wrapping_mul(v).wrapping_add(b.wrapping_mul(r)),
            c.wrapping_mul(u).wrapping_add(d.wrapping_mul(q)),
            c.wrapping_mul(v).wrapping_add(d.wrapping_mul(r)),
        ];
    }};
}

/// 59 half-delta divsteps on the low words of `f` and `g`, branch-free;
/// returns the new `zeta` and the matrix, scaled by `2^62`: libsecp256k1's
/// `secp256k1_modinv64_divsteps_59`, in rounds of packed steps.
#[inline(always)]
// The last round moves `f` and `g` on too, and nothing reads them after.
#[allow(unused_assignments)]
fn divsteps_59(zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    let (mut zeta, mut f, mut g) = (zeta, f0, g0);
    let mut m = [1i64, 0, 0, 1];
    round!(hd_19, zeta, f, g, m, 19);
    round!(hd_19, zeta, f, g, m, 19);
    round!(hd_19, zeta, f, g, m, 19);
    round!(hd_2, zeta, f, g, m, 2);
    // 59 steps scale by 2^59; the caller wants 2^62.
    let [u, v, q, r] = m;
    (
        zeta,
        Trans {
            u: u << 3,
            v: v << 3,
            q: q << 3,
            r: r << 3,
        },
    )
}

/// 62 divsteps on the low words of `f` and `g`, branch-free; returns the
/// new `delta` and the matrix, scaled by `2^62`. Sixty-two bits of `f` and
/// `g` are enough: each step consumes one, and the last needs only the
/// parity.
#[inline(always)]
// The last round moves `f` and `g` on too, and nothing reads them after.
#[allow(unused_assignments)]
fn divsteps_62(delta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    let (mut delta, mut f, mut g) = (delta, f0, g0);
    let mut m = [1i64, 0, 0, 1];
    round!(by_19, delta, f, g, m, 19);
    round!(by_19, delta, f, g, m, 19);
    round!(by_19, delta, f, g, m, 19);
    round!(by_5, delta, f, g, m, 5);
    let [u, v, q, r] = m;
    (delta, Trans { u, v, q, r })
}

/// `a * b` as `i128`.
#[inline(always)]
fn m(a: i64, b: i64) -> i128 {
    a as i128 * b as i128
}

/// `[d, e] = t * [d, e] / 2^62`, adding multiples of the modulus to make the
/// division exact and keep both in `(-2m, m)`: libsecp256k1's
/// `secp256k1_modinv64_update_de_62`, over `N` limbs.
#[inline(always)]
fn update_de<const N: usize>(
    d: &mut Signed62<N>,
    e: &mut Signed62<N>,
    t: &Trans,
    info: &ModInfo<N>,
) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let md_mod = &info.modulus;
    // md, me start at zero, plus [u, q] if d is negative, plus [v, r] if e
    // is.
    let sd = d[N - 1] >> 63;
    let se = e[N - 1] >> 63;
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);
    let mut cd = m(u, d[0]) + m(v, e[0]);
    let mut ce = m(q, d[0]) + m(r, e[0]);
    // Correct md, me so that t*[d, e] + modulus*[md, me] has 62 zero low bits.
    md = md.wrapping_sub(
        (info
            .modulus_inv62
            .wrapping_mul(cd as u64)
            .wrapping_add(md as u64)
            & M62) as i64,
    );
    me = me.wrapping_sub(
        (info
            .modulus_inv62
            .wrapping_mul(ce as u64)
            .wrapping_add(me as u64)
            & M62) as i64,
    );
    cd += m(md_mod[0], md);
    ce += m(md_mod[0], me);
    debug_assert!(cd as u64 & M62 == 0 && ce as u64 & M62 == 0);
    cd >>= 62;
    ce >>= 62;
    // Limbs 1 to N - 1, each stored one place down; a zero limb of the
    // modulus, a public constant, skips its products.
    for i in 1..N {
        cd += m(u, d[i]) + m(v, e[i]);
        ce += m(q, d[i]) + m(r, e[i]);
        if md_mod[i] != 0 {
            cd += m(md_mod[i], md);
            ce += m(md_mod[i], me);
        }
        d[i - 1] = (cd as u64 & M62) as i64;
        cd >>= 62;
        e[i - 1] = (ce as u64 & M62) as i64;
        ce >>= 62;
    }
    // What remains is the top limb.
    d[N - 1] = cd as i64;
    e[N - 1] = ce as i64;
}

/// `[f, g] = t * [f, g] / 2^62`, which is exact: libsecp256k1's
/// `secp256k1_modinv64_update_fg_62`, over `N` limbs.
#[inline(always)]
fn update_fg<const N: usize>(f: &mut Signed62<N>, g: &mut Signed62<N>, t: &Trans) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut cf = m(u, f[0]) + m(v, g[0]);
    let mut cg = m(q, f[0]) + m(r, g[0]);
    debug_assert!(cf as u64 & M62 == 0 && cg as u64 & M62 == 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..N {
        cf += m(u, f[i]) + m(v, g[i]);
        cg += m(q, f[i]) + m(r, g[i]);
        f[i - 1] = (cf as u64 & M62) as i64;
        cf >>= 62;
        g[i - 1] = (cg as u64 & M62) as i64;
        cg >>= 62;
    }
    f[N - 1] = cf as i64;
    g[N - 1] = cg as i64;
}

/// Bring `r` from `(-2m, m)` to `[0, m)`, negated first when `sign` is
/// negative: libsecp256k1's `secp256k1_modinv64_normalize_62`, over `N`
/// limbs.
#[inline(always)]
fn normalize<const N: usize>(r: &mut Signed62<N>, sign: i64, info: &ModInfo<N>) {
    let md = &info.modulus;
    let m62 = M62 as i64;
    // Each mask goes behind the barrier: with the modulus a constant, LLVM
    // compiled `x += m & mask` into a branch on the sign, around the whole
    // addition, which `ct_p384_fp_invert` found.
    // Add the modulus if negative, then negate if asked: into (-m, m).
    let cond_add = core::hint::black_box(r[N - 1] >> 63);
    for (x, &mi) in r.iter_mut().zip(md) {
        *x += mi & cond_add;
    }
    let cond_negate = core::hint::black_box(sign >> 63);
    for x in r.iter_mut() {
        *x = (*x ^ cond_negate) - cond_negate;
    }
    // Carry, so every limb but the top is in [0, 2^62).
    for i in 0..N - 1 {
        r[i + 1] += r[i] >> 62;
        r[i] &= m62;
    }
    // Add the modulus again if still negative: into [0, m).
    let cond_add = core::hint::black_box(r[N - 1] >> 63);
    for (x, &mi) in r.iter_mut().zip(md) {
        *x += mi & cond_add;
    }
    for i in 0..N - 1 {
        r[i + 1] += r[i] >> 62;
        r[i] &= m62;
    }
}

/// A modulus to invert by, as a type, so that each modulus gets its own
/// copy of the inversion with its limbs as constants: a limb test in
/// `update_de` then folds away, where in code shared between moduli it
/// stays a branch, if a public one.
pub(crate) trait Modulus<const N: usize> {
    /// The modulus, for the divsteps.
    const INFO: ModInfo<N>;
}

/// The state of an inversion between batches: `zeta` or `delta`, the
/// Bezout coefficients `d` and `e`, and `f` and `g`.
struct State<const N: usize> {
    delta: i64,
    d: Signed62<N>,
    e: Signed62<N>,
    f: Signed62<N>,
    g: Signed62<N>,
}

impl<const N: usize> State<N> {
    /// Start inverting `x`, already in limbs, from `delta` (or `zeta`).
    #[inline(always)]
    fn new(delta: i64, x: Signed62<N>, info: &ModInfo<N>) -> Self {
        let mut e = [0; N];
        e[0] = 1;
        State {
            delta,
            d: [0; N],
            e,
            f: info.modulus,
            g: x,
        }
    }

    /// A batch's matrix applied to `d, e, f, g`.
    #[inline(always)]
    fn apply(&mut self, delta: i64, t: &Trans, info: &ModInfo<N>) {
        self.delta = delta;
        update_de(&mut self.d, &mut self.e, t, info);
        update_fg(&mut self.f, &mut self.g, t);
    }

    /// The inverse, once `g` is zero and `f` is `+-1` (or `+-m`, for
    /// `x = 0`, which leaves `d = 0`).
    #[inline(always)]
    fn finish<const W: usize>(mut self, info: &ModInfo<N>) -> [u64; W] {
        normalize(&mut self.d, self.f[N - 1], info);
        from_signed62(&self.d)
    }
}

/// One batch of [`invert`]: 59 half-delta divsteps, then the matrix
/// applied. Out of line, so that the ten batches are ten calls and not a
/// loop.
#[inline(never)]
fn batch_256<M: Modulus<5>>(s: &mut State<5>) {
    let (zeta, t) = divsteps_59(s.delta, s.f[0] as u64, s.g[0] as u64);
    s.apply(zeta, &t, &M::INFO);
}

/// `x^-1 mod m` for `x` in `[0, m)` and `m` below `2^256`, with `0` for
/// `0`, in constant time: ten batches of 59 half-delta divsteps, the 590
/// libsecp256k1's analysis requires, written out. `x` and the result are
/// plain integers, not Montgomery form.
pub(crate) fn invert<M: Modulus<5>>(x: &[u64; 4]) -> [u64; 4] {
    let mut s = State::new(-1, to_signed62::<4, 5>(*x), &M::INFO);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    batch_256::<M>(&mut s);
    #[cfg(test)]
    debug_assert!(s.g == [0; 5], "g did not reach zero");
    s.finish(&M::INFO)
}

/// Batches of 62 in a 384-bit inversion: enough for Theorem 11.2's
/// `floor((49d + 80) / 17)` divsteps at `d = 384`.
const BATCHES_384: usize = 18;
const _: () = assert!(62 * BATCHES_384 >= (49 * 384 + 80) / 17);

/// One batch of [`invert_384`]: 62 divsteps, then the matrix applied.
/// Out of line, so that the eighteen batches are eighteen calls and not a
/// loop.
#[inline(never)]
fn batch_384<M: Modulus<7>>(s: &mut State<7>) {
    let (delta, t) = divsteps_62(s.delta, s.f[0] as u64, s.g[0] as u64);
    s.apply(delta, &t, &M::INFO);
}

/// `x^-1 mod m` for `x` in `[0, m)` and `m` an odd modulus below `2^384`,
/// with `0` for `0`, in constant time: 1116 of the paper's divsteps, at
/// least the 1111 its Theorem 11.2 requires at this width. Plain integers
/// in and out, as [`invert`].
pub(crate) fn invert_384<M: Modulus<7>>(x: &[u64; 6]) -> [u64; 6] {
    let mut s = State::new(1, to_signed62::<6, 7>(*x), &M::INFO);
    // Eighteen batches of 62, written out: `BATCHES_384` of them.
    const _: () = assert!(BATCHES_384 == 18);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    batch_384::<M>(&mut s);
    #[cfg(test)]
    debug_assert!(s.g == [0; 7], "g did not reach zero");
    s.finish(&M::INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P-256's two moduli, each with its inversion.
    #[allow(clippy::type_complexity)]
    fn moduli() -> [([u64; 4], fn(&[u64; 4]) -> [u64; 4]); 2] {
        [
            (crate::nist::p256_field::P, invert::<crate::p256::FpModulus>),
            (
                <crate::p256::P256 as crate::nist::point::Curve>::Scalar::MODULUS,
                invert::<crate::p256::FnModulus>,
            ),
        ]
    }

    /// `a * b mod m`, by schoolbook and long division by shift-and-subtract:
    /// slow, and sharing nothing with the code under test or with Montgomery.
    fn mulmod<const W: usize>(a: [u64; W], b: [u64; W], m: [u64; W]) -> [u64; W] {
        // The double-width product.
        let mut p = std::vec![0u64; 2 * W];
        for i in 0..W {
            let mut carry = 0u128;
            for j in 0..W {
                let t = p[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
                p[i + j] = t as u64;
                carry = t >> 64;
            }
            p[i + W] = carry as u64;
        }
        // Reduce bit by bit from the top: r = 2r + bit, minus m when r >= m.
        let mut r = std::vec![0u64; W + 1];
        for bit in (0..128 * W).rev() {
            // r <<= 1
            for k in (1..W + 1).rev() {
                r[k] = r[k] << 1 | r[k - 1] >> 63;
            }
            r[0] = r[0] << 1 | (p[bit / 64] >> (bit % 64)) & 1;
            // if r >= m: r -= m
            let mut ge = r[W] != 0;
            if !ge {
                ge = true;
                for k in (0..W).rev() {
                    if r[k] != m[k] {
                        ge = r[k] > m[k];
                        break;
                    }
                }
            }
            if ge {
                let mut borrow = 0u128;
                for k in 0..W + 1 {
                    let mk = if k < W { m[k] } else { 0 };
                    let t = (r[k] as u128).wrapping_sub(mk as u128).wrapping_sub(borrow);
                    r[k] = t as u64;
                    borrow = (t >> 127) & 1;
                }
            }
        }
        let mut out = [0u64; W];
        out.copy_from_slice(&r[..W]);
        out
    }

    /// The inverse times the input is one, for the edges and a hundred
    /// thousand random inputs per modulus, and zero maps to zero.
    #[test]
    fn inverses_are_inverses() {
        let mut state = 0x05af_e9cd_u64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for (m, invert) in moduli() {
            assert_eq!(invert(&[0; 4]), [0; 4]);
            let below = |x: [u64; 4]| {
                (0..4)
                    .rev()
                    .find(|&k| x[k] != m[k])
                    .is_some_and(|k| x[k] < m[k])
            };
            let mut inputs = std::vec![
                [1u64, 0, 0, 0],
                [2, 0, 0, 0],
                [m[0] - 1, m[1], m[2], m[3]],
                [m[0] - 2, m[1], m[2], m[3]],
                [0, 0, 0, 1 << 63],
                [u64::MAX, u64::MAX, u64::MAX, m[3] - 1],
            ];
            while inputs.len() < 100_000 {
                let x = [next(), next(), next(), next()];
                if below(x) {
                    inputs.push(x);
                }
            }
            for (i, x) in inputs.iter().enumerate() {
                let inv = invert(x);
                assert!(below(inv), "{x:x?}");
                // The slow product only on a sample; the rest by a second
                // inversion, which must give back x.
                if i < 2_000 {
                    assert_eq!(mulmod(*x, inv, m), [1, 0, 0, 0], "{x:x?}");
                } else {
                    assert_eq!(invert(&inv), *x, "{x:x?}");
                }
            }
        }
    }

    /// `divsteps_62` is the paper's divstep, step for step, and not merely
    /// some step that also converges -- the bound in the module notes is
    /// for that one. A transcription of the definition on exact integers,
    /// branching as it is written: `delta > 0` and `g` odd swap to
    /// `(1 - delta, g, (g - f) / 2)`, else `(1 + delta, f, (g + (g mod 2) f)
    /// / 2)`. After 62 steps from 62-bit `f` (odd) and `g`, `delta` must
    /// match, and the matrix must take the start to `2^62` times the end. On
    /// random words and on `delta` from -70 to 70, so that the first steps'
    /// decisions go both ways.
    #[test]
    fn the_batch_is_the_papers_divstep() {
        let mut state = 0x62_u64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for round in 0..20_000 {
            let f0 = (next() & M62) | 1;
            let g0 = match round % 4 {
                0 => next() & M62,
                1 => f0,
                2 => 0,
                _ => (next() & M62) & !((1 << (round % 40)) - 1),
            };
            let delta0 = (round % 141) as i64 - 70;
            let (mut delta, mut f, mut g) = (delta0, f0 as i128, g0 as i128);
            for _ in 0..62 {
                if delta > 0 && g & 1 == 1 {
                    (delta, f, g) = (1 - delta, g, (g - f) / 2);
                } else {
                    (delta, g) = (1 + delta, (g + (g & 1) * f) / 2);
                }
            }
            let (got, t) = divsteps_62(delta0, f0, g0);
            assert_eq!(got, delta, "{f0:x} {g0:x} {delta0}");
            let (f0, g0) = (f0 as i128, g0 as i128);
            assert_eq!(t.u as i128 * f0 + t.v as i128 * g0, f << 62, "f");
            assert_eq!(t.q as i128 * f0 + t.r as i128 * g0, g << 62, "g");
            // And the row sums stay within 2^62, as `update_de` needs.
            assert!(t.u.unsigned_abs() + t.v.unsigned_abs() <= 1 << 62);
            assert!(t.q.unsigned_abs() + t.r.unsigned_abs() <= 1 << 62);
        }
    }

    /// The same for P-256's batch, whose 590-step count is libsecp256k1's
    /// bound for exactly its step: the half-delta divstep, `zeta = -(delta +
    /// 1/2)` with `delta` starting at 1/2, so the swap is where `zeta < 0`
    /// and `g` is odd, and `zeta` becomes `-zeta - 2` on a swap and `zeta - 1`
    /// otherwise. 59 steps from the identity times 8 scale by `2^62`.
    #[test]
    fn the_256_batch_is_the_half_delta_divstep() {
        let mut state = 0x59_u64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for round in 0..20_000 {
            let f0 = (next() & M62) | 1;
            let g0 = match round % 4 {
                0 => next() & M62,
                1 => f0,
                2 => 0,
                _ => (next() & M62) & !((1 << (round % 40)) - 1),
            };
            let zeta0 = (round % 141) as i64 - 70;
            let (mut zeta, mut f, mut g) = (zeta0, f0 as i128, g0 as i128);
            for _ in 0..59 {
                if zeta < 0 && g & 1 == 1 {
                    (zeta, f, g) = (-zeta - 2, g, (g - f) / 2);
                } else {
                    (zeta, g) = (zeta - 1, (g + (g & 1) * f) / 2);
                }
            }
            let (got, t) = divsteps_59(zeta0, f0, g0);
            assert_eq!(got, zeta, "{f0:x} {g0:x} {zeta0}");
            let (f0, g0) = (f0 as i128, g0 as i128);
            assert_eq!(t.u as i128 * f0 + t.v as i128 * g0, f << 62, "f");
            assert_eq!(t.q as i128 * f0 + t.r as i128 * g0, g << 62, "g");
            assert!(t.u.unsigned_abs() + t.v.unsigned_abs() <= 1 << 62);
            assert!(t.q.unsigned_abs() + t.r.unsigned_abs() <= 1 << 62);
        }
    }

    /// The assembly's rounds against the Rust steps they replace on
    /// x86-64: the same `delta` or `zeta` and the same packed words after
    /// every round length, from random packed words and `delta` from -70 to
    /// 70, so that the decisions go both ways.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_assembly_runs_the_same_steps() {
        use super::super::safegcd_x86 as x;
        let mut state = 0x86_u64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        type Run = fn(&mut i64, &mut i64, &mut i64);
        let pairs: [(Run, Run); 4] = [
            (x::by_19, rs_by_19),
            (x::by_5, rs_by_5),
            (x::hd_19, rs_hd_19),
            (x::hd_2, rs_hd_2),
        ];
        for round in 0..50_000 {
            let d0 = (round % 141) as i64 - 70;
            let f0 = (next() & ((1 << LOW) - 1)) as i64 | 1;
            let g0 = (next() & ((1 << LOW) - 1)) as i64;
            let (f0, g0) = (f0 + ((1i64 << 19) << 21), g0 + ((1i64 << 19) << 42));
            for (asm, rust) in pairs {
                let (mut d1, mut f1, mut g1) = (d0, f0, g0);
                let (mut d2, mut f2, mut g2) = (d0, f0, g0);
                asm(&mut d1, &mut f1, &mut g1);
                rust(&mut d2, &mut f2, &mut g2);
                assert_eq!((d1, f1, g1), (d2, f2, g2), "{d0} {f0:x} {g0:x}");
            }
        }
    }

    /// The packed rows come apart into the matrix entries at every extreme
    /// a round can leave them at: the low field anywhere in `(-2^20, 2^20)`,
    /// each entry anywhere in `[-2^19, 2^19]`. A round's low field reaches
    /// the far ends rarely, since `g` mostly shrinks as the steps go, so the
    /// batches' tests above do not show a wrong sign extension of it; this
    /// does.
    #[test]
    fn the_packed_fields_come_apart_at_their_extremes() {
        let lows = [
            -(1i64 << 20) + 1,
            -(1 << 19) - 1,
            -(1 << 19),
            -1,
            0,
            1,
            1 << 19,
            (1 << 20) - 1,
        ];
        let entries = [
            -(1i64 << 19),
            -(1 << 19) + 1,
            -1,
            0,
            1,
            (1 << 19) - 1,
            1 << 19,
        ];
        for x in lows {
            for a in entries {
                for b in entries {
                    let p = x + (a << 21) + (b << 42);
                    assert_eq!(unpack(p), (a, b), "{x} {a} {b}");
                }
            }
        }
    }

    /// The limb conversions are inverses of each other, at both widths.
    #[test]
    fn limbs_round_trip() {
        let a6 = [
            0x0123_4567_89ab_cdef,
            u64::MAX,
            0,
            0x8000_0000_0000_0001,
            0xdead_beef_0bad_f00d,
            0x0fff_ffff_ffff_ffff,
        ];
        assert_eq!(from_signed62::<7, 6>(&to_signed62::<6, 7>(a6)), a6);
        let a4 = [a6[0], a6[1], a6[2], a6[3]];
        assert_eq!(from_signed62::<5, 4>(&to_signed62::<4, 5>(a4)), a4);
        for limb in to_signed62::<6, 7>(a6) {
            assert!((0..1 << 62).contains(&limb));
        }
    }

    /// The 384-bit inversion over P-384's prime: inverse times input is one,
    /// by the slow product, on the edges and twenty thousand random inputs;
    /// zero maps to zero; and `g` reaches zero inside the bound, which the
    /// `debug_assert` in [`invert_384`] checks on every call here.
    #[test]
    fn inverses_are_inverses_at_384_bits() {
        let m = crate::p384::Fp::MODULUS;
        let invert_384 = invert_384::<crate::p384::FpModulus>;
        assert_eq!(invert_384(&[0; 6]), [0; 6]);
        let below = |x: [u64; 6]| {
            (0..6)
                .rev()
                .find(|&k| x[k] != m[k])
                .is_some_and(|k| x[k] < m[k])
        };
        let mut state = 0x0384_u64;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let mut inputs = std::vec![
            [1u64, 0, 0, 0, 0, 0],
            [2, 0, 0, 0, 0, 0],
            [3, 0, 0, 0, 0, 0],
            [m[0] - 1, m[1], m[2], m[3], m[4], m[5]],
            [m[0] - 2, m[1], m[2], m[3], m[4], m[5]],
            [0, 0, 0, 0, 0, 1 << 63],
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, m[5] - 1],
            // (p - 1) / 2 and (p + 1) / 2.
            [
                m[0] >> 1 | m[1] << 63,
                m[1] >> 1 | m[2] << 63,
                m[2] >> 1 | m[3] << 63,
                m[3] >> 1 | m[4] << 63,
                m[4] >> 1 | m[5] << 63,
                m[5] >> 1,
            ],
        ];
        let h = inputs[7];
        inputs.push([h[0] + 1, h[1], h[2], h[3], h[4], h[5]]);
        for k in 0..384 {
            let mut x = [0u64; 6];
            x[k / 64] = 1 << (k % 64);
            if below(x) {
                inputs.push(x);
            }
        }
        while inputs.len() < 20_000 {
            let x = [next(), next(), next(), next(), next(), next()];
            if below(x) {
                inputs.push(x);
            }
        }
        for (i, x) in inputs.iter().enumerate() {
            let inv = invert_384(x);
            assert!(below(inv), "{x:x?}");
            if i < 3_000 {
                assert_eq!(mulmod(*x, inv, m), [1, 0, 0, 0, 0, 0], "{x:x?}");
            } else {
                assert_eq!(invert_384(&inv), *x, "{x:x?}");
            }
        }
    }
}
