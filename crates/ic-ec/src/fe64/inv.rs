//! Constant-time inversion modulo 2^255 - 19 by Bernstein-Yang divsteps.
//!
//! # Why
//!
//! Fermat inversion, `x^(p-2)`, is 254 squarings and 11 multiplications in a
//! single dependency chain, so it costs the latency of every one of them: 1.9
//! microseconds on the four-limb field, an eighth of an X25519 agreement and
//! a fifth of a signature, which ends in one to compress `R`.
//!
//! Bernstein and Yang, "Fast constant-time gcd computation and modular
//! inversion" (TCHES 2019), replace it with a fixed number of "divsteps" on
//! machine words. This follows the form libsecp256k1 published and analysed
//! as `secp256k1_modinv64` (constant-time variant; see its
//! `doc/safegcd_implementation.md`), written here independently from that
//! description: 59 divsteps at a time on the low 64 bits of `f` and `g`,
//! collected into a 2x2 transition matrix scaled by 2^62, then applied to the
//! full-width `f`, `g` and to the Bezout coefficients `d`, `e` in signed
//! 62-bit limbs. Ten rounds make 590 divsteps, the bound that analysis
//! establishes for any input below 2^256.
//!
//! # Constant time
//!
//! The number of rounds and of divsteps is fixed, and the rounds are ten
//! calls written out. The divsteps are assembly, each choice a mask or a
//! `CMOV`, so there is nothing for the optimiser to turn into a jump -- the C
//! original uses `volatile` for that. The final normalisation's masks pass
//! through [`opaque`], an empty register-only assembly block, for the same
//! reason. Products are 64x64 -> 128-bit `imul`. The only conditions in the
//! code are on the limbs of the modulus, which are constants;
//! `ct_fe64_invert` in `scripts/check-ct.py` holds the compiled code to
//! having no branch.

/// `2^62 - 1`.
const M62: u64 = u64::MAX >> 2;

/// `p = 2^255 - 19` in signed 62-bit limbs, the sparse form: `-19 + 128 *
/// 2^248`. Three zero limbs let `update_de` skip their products.
const P: [i64; 5] = [-19, 0, 0, 0, 128];

/// `p^-1 mod 2^62`.
const P_INV62: u64 = {
    // Newton's iteration for the inverse of an odd number modulo 2^64:
    // each step doubles the number of correct low bits, from 3 (any odd x is
    // its own inverse modulo 8) to 96.
    let p0: u64 = 0u64.wrapping_sub(19); // p mod 2^64
    let mut inv = p0;
    let mut i = 0;
    while i < 5 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(inv)));
        i += 1;
    }
    inv & M62
};

/// The value, unchanged, through a barrier the optimiser cannot see into.
#[inline(always)]
fn opaque(mut x: u64) -> u64 {
    // SAFETY: an empty assembly block with one register operand: it executes
    // nothing, reads and writes no memory, and touches no other register.
    unsafe {
        core::arch::asm!("/* {x} */", x = inout(reg) x, options(pure, nomem, nostack, preserves_flags));
    }
    x
}

/// The transition matrix of 59 divsteps, scaled by 2^62.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 59 divsteps on the low words `f0` (odd) and `g0`, from `zeta`.
///
/// `zeta` is `-(delta + 1/2)` in Bernstein and Yang's terms. Each step:
/// when `delta > 0` and `g` is odd, `(delta, f, g) <- (1 - delta, g, (g -
/// f) / 2)`; otherwise when `g` is odd, `g <- (g + f) / 2`, else `g <- g /
/// 2`, with `delta <- 1 + delta`. The matrix records what was done to `f`
/// and `g` so the full-width values can follow.
///
/// Assembly, all 59 steps in one straight-line block. As Rust, LTO moved the
/// matrix entries into vector registers and paid a transfer between register
/// files on every step, which doubled the cost of the inversion. In assembly
/// every choice is a mask or a `CMOV` by construction, so it needs no
/// barrier either; `CMOV` on `g`'s parity rather than a mask built from it
/// takes two instructions off the dependency chain each step carries.
#[inline(always)]
fn divsteps_59(zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    // The identity times 8: the caller wants the matrix times 2^62, and 59
    // steps double each entry 59 times.
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g, mut z) = (f0, g0, zeta as u64);
    // SAFETY: integer instructions on registers only (`nomem`), present on
    // every x86-64 CPU; `.rept` repeats the block at assembly time, so no
    // branch is emitted.
    unsafe {
        core::arch::asm!(
            "xor {zero:e}, {zero:e}",
            ".rept 59",
            // c1 = zeta < 0 (delta > 0), as a mask.
            "mov {c1}, {z}",
            "sar {c1}, 63",
            // x, y, w = f, u, v, negated when c1.
            "mov {x}, {f}",
            "xor {x}, {c1}",
            "sub {x}, {c1}",
            "mov {y}, {u}",
            "xor {y}, {c1}",
            "sub {y}, {c1}",
            "mov {w}, {v}",
            "xor {w}, {c1}",
            "sub {w}, {c1}",
            // When g is even, none of it applies: zero x, y, w and c1 by
            // CMOV, which moves or not in the same time either way. c1 is
            // then the mask for both conditions.
            "test {g}, 1",
            "cmovz {x}, {zero}",
            "cmovz {y}, {zero}",
            "cmovz {w}, {zero}",
            "cmovz {c1}, {zero}",
            // g, q, r += x, y, w.
            "add {g}, {x}",
            "add {q}, {y}",
            "add {r}, {w}",
            // When both: zeta <- -zeta - 2 and f, u, v += g, q, r (the new
            // ones, so f becomes the old g); otherwise zeta <- zeta - 1.
            "xor {z}, {c1}",
            "sub {z}, 1",
            "mov {x}, {g}",
            "and {x}, {c1}",
            "add {f}, {x}",
            "mov {y}, {q}",
            "and {y}, {c1}",
            "add {u}, {y}",
            "mov {w}, {r}",
            "and {w}, {c1}",
            "add {v}, {w}",
            // Halve g; double u and v instead of halving q and r.
            "shr {g}, 1",
            "add {u}, {u}",
            "add {v}, {v}",
            ".endr",
            z = inout(reg) z,
            f = inout(reg) f,
            g = inout(reg) g,
            u = inout(reg) u,
            v = inout(reg) v,
            q = inout(reg) q,
            r = inout(reg) r,
            c1 = out(reg) _,
            zero = out(reg) _,
            x = out(reg) _,
            y = out(reg) _,
            w = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    let _ = f;
    let _ = g;
    (
        z as i64,
        Trans {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// `a * b`, widened. The products and the sums below cannot overflow an
/// i128, by the bounds the algorithm keeps; they are written wrapping so an
/// overflow-checked build does not add a `jo` on secret data to each one.
#[inline(always)]
fn m(a: i64, b: i64) -> i128 {
    (a as i128).wrapping_mul(b as i128)
}

/// `[d, e] <- t * [d, e] / 2^62 (mod p)`, keeping both in `(-2p, p)`.
///
/// A multiple of `p` is added to each so the bottom 62 bits of the product
/// are zero, which makes the division by 2^62 exact.
#[inline(always)]
fn update_de(d: &mut [i64; 5], e: &mut [i64; 5], t: &Trans) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    // Start md, me at [u, q] if d is negative, plus [v, r] if e is, which
    // keeps the results in range.
    let sd = d[4] >> 63;
    let se = e[4] >> 63;
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);
    let mut cd = m(u, d[0]).wrapping_add(m(v, e[0]));
    let mut ce = m(q, d[0]).wrapping_add(m(r, e[0]));
    // Choose md, me so that the bottom 62 bits cancel.
    md = md.wrapping_sub((P_INV62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64);
    me = me.wrapping_sub((P_INV62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64);
    cd = cd.wrapping_add(m(P[0], md));
    ce = ce.wrapping_add(m(P[0], me));
    debug_assert_eq!(cd as u64 & M62, 0);
    debug_assert_eq!(ce as u64 & M62, 0);
    cd >>= 62;
    ce >>= 62;
    // Limbs 1 to 4; the modulus's limbs 1 to 3 are zero.
    for i in 1..5 {
        cd = cd.wrapping_add(m(u, d[i])).wrapping_add(m(v, e[i]));
        ce = ce.wrapping_add(m(q, d[i])).wrapping_add(m(r, e[i]));
        if P[i] != 0 {
            cd = cd.wrapping_add(m(P[i], md));
            ce = ce.wrapping_add(m(P[i], me));
        }
        d[i - 1] = (cd as u64 & M62) as i64;
        e[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d[4] = cd as i64;
    e[4] = ce as i64;
}

/// `[f, g] <- t * [f, g] / 2^62`, exact.
#[inline(always)]
fn update_fg(f: &mut [i64; 5], g: &mut [i64; 5], t: &Trans) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut cf = m(u, f[0]).wrapping_add(m(v, g[0]));
    let mut cg = m(q, f[0]).wrapping_add(m(r, g[0]));
    debug_assert_eq!(cf as u64 & M62, 0);
    debug_assert_eq!(cg as u64 & M62, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf = cf.wrapping_add(m(u, f[i])).wrapping_add(m(v, g[i]));
        cg = cg.wrapping_add(m(q, f[i])).wrapping_add(m(r, g[i]));
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[4] = cf as i64;
    g[4] = cg as i64;
}

/// Bring `r`, in `(-2p, p)`, to `[0, p)`, negating first when `sign < 0`.
#[inline(always)]
fn normalize(r: &mut [i64; 5], sign: i64) {
    // Add p if negative: now in (-p, p).
    let add = opaque((r[4] >> 63) as u64) as i64;
    for i in 0..5 {
        r[i] = r[i].wrapping_add(P[i] & add);
    }
    // Negate if asked: still in (-p, p).
    let neg = opaque((sign >> 63) as u64) as i64;
    for limb in r.iter_mut() {
        *limb = (*limb ^ neg).wrapping_sub(neg);
    }
    carry(r);
    // Add p if still negative: now in [0, p).
    let add = opaque((r[4] >> 63) as u64) as i64;
    for i in 0..5 {
        r[i] = r[i].wrapping_add(P[i] & add);
    }
    carry(r);
}

/// Propagate each limb's bits above 62 into the next.
#[inline(always)]
fn carry(r: &mut [i64; 5]) {
    for i in 0..4 {
        r[i + 1] = r[i + 1].wrapping_add(r[i] >> 62);
        r[i] &= M62 as i64;
    }
}

/// The inversion's state between rounds.
struct State {
    d: [i64; 5],
    e: [i64; 5],
    f: [i64; 5],
    g: [i64; 5],
    zeta: i64,
}

/// One round: 59 divsteps on the low words, then their matrix applied to
/// the full-width values.
#[inline(never)]
fn round(st: &mut State) {
    let (z, t) = divsteps_59(st.zeta, st.f[0] as u64, st.g[0] as u64);
    st.zeta = z;
    update_de(&mut st.d, &mut st.e, &t);
    update_fg(&mut st.f, &mut st.g, &t);
}

/// `x^-1 mod p` for canonical `x` (below p) in four 64-bit limbs, with
/// `0^-1 = 0`. The result is canonical.
pub(super) fn invert(x: [u64; 4]) -> [u64; 4] {
    let g0 = [
        (x[0] & M62) as i64,
        (((x[0] >> 62) | (x[1] << 2)) & M62) as i64,
        (((x[1] >> 60) | (x[2] << 4)) & M62) as i64,
        (((x[2] >> 58) | (x[3] << 6)) & M62) as i64,
        (x[3] >> 56) as i64,
    ];
    let mut st = State {
        d: [0; 5],
        e: [1, 0, 0, 0, 0],
        f: P,
        g: g0,
        // zeta = -(delta + 1/2) with delta = 1/2 to start.
        zeta: -1,
    };
    // Ten rounds of 59, written out rather than looped: the count is fixed,
    // and as calls they leave no loop branch in the compiled code for the
    // constant-time gate to have to tell from a secret one.
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    round(&mut st);
    let State { mut d, f, .. } = st;
    // g is now zero and f is +-1, its sign that of the top limb; d is +-x^-1.
    normalize(&mut d, f[4]);
    let w = d.map(|l| l as u64);
    [
        w[0] | (w[1] << 62),
        (w[1] >> 2) | (w[2] << 60),
        (w[2] >> 4) | (w[3] << 58),
        (w[3] >> 6) | (w[4] << 56),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inverse_constant_is_an_inverse() {
        // p mod 2^62 is 2^62 - 19.
        let p_lo = (1u64 << 62) - 19;
        assert_eq!(p_lo.wrapping_mul(P_INV62) & M62, 1);
    }
}
