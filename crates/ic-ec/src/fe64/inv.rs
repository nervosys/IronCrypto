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
//! description: divsteps on the low bits of `f` and `g`, collected into a
//! 2x2 transition matrix scaled by 2^62, then applied to the full-width `f`,
//! `g` and to the Bezout coefficients `d`, `e` in signed 62-bit limbs. Ten
//! rounds of 60 make 600 divsteps, above the 590 that analysis establishes
//! for any input below 2^256.
//!
//! Where libsecp256k1 runs 59 steps on whole words, each step updating `f`,
//! `g` and four matrix entries apart, this runs three batches of twenty
//! with each of `f` and `g` packed into one word beside its row of the
//! matrix, so that a step is half the instructions; Bernstein and Yang's
//! own code packs the same way. See [`divsteps_20`].
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

/// The transition matrix of 60 divsteps, scaled by 2^62.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 20 divsteps on the low 20 bits of `f` (odd) and `g`, from `zeta`, with
/// `f`, `g` and their rows of the transition matrix packed into one word
/// each. Returns the new `zeta` and the matrix scaled by 2^20, `[u, v, q, r]`.
///
/// `zeta` is `-(delta + 1/2)` in Bernstein and Yang's terms. Each step:
/// when `delta > 0` and `g` is odd, `(delta, f, g) <- (1 - delta, g, (g -
/// f) / 2)`; otherwise when `g` is odd, `g <- (g + f) / 2`, else `g <- g /
/// 2`, with `delta <- 1 + delta`.
///
/// # The packing
///
/// A word holds `f + u * 2^21 + v * 2^42`: the low bits of `f`, below 2^20
/// in magnitude, and the row `(u, v)` of the matrix that takes the starting
/// `f` and `g` to this one, as an exact sum of signed integers. A divstep is
/// linear in `f` and `g` and moves their rows by the same operations, so one
/// addition, subtraction, move or halving of the packed words performs it on
/// all three fields at once: half the instructions of tracking the six
/// values apart. The fields do not disturb one another: the matrix starts
/// as the identity scaled by `-2^20`, so its entries are multiples of 2^20
/// that are halved at most twenty times and stay integers, and every entry
/// stays in `[-2^20, 2^20)`, which is what a 21-bit field holds. (Only an
/// entry of a row never halved reaches `2^20` in magnitude, and those start
/// at `-2^20`; a halved row's entries are below the larger of two entries
/// that bound them, and so below `2^20`.) The low field's parity is `g`'s,
/// since the fields above it are multiples of 2^21.
///
/// Assembly, straight-line, with every choice a `CMOV`. The step computes
/// both `g + f` and `g - f` before it knows which it wants, so its chain is
/// an addition, two `CMOV`s and a shift.
#[inline(always)]
fn divsteps_20(zeta: i64, f0: u64, g0: u64) -> (i64, [i64; 4]) {
    const LOW: u64 = (1 << 20) - 1;
    // f + (-2^20) * 2^21, and g + (-2^20) * 2^42.
    let mut f = ((f0 & LOW) as i64).wrapping_sub(1 << 41);
    let mut g = ((g0 & LOW) as i64).wrapping_sub(1 << 62);
    let mut z = zeta;
    // SAFETY: integer instructions on registers only (`nomem`), present on
    // every x86-64 CPU; `.rept` repeats the text at assembly time, so no
    // branch is emitted.
    unsafe {
        core::arch::asm!(
            ".p2align 6",
            ".rept 10",
            // Step one: from f, g, z into f2, g1, zs.
            "lea {g1}, [{g} + {f}]",
            "mov {g2}, {g}",
            "sub {g2}, {f}",
            "mov {zs}, -2",
            "sub {zs}, {z}",
            "lea {zm}, [{z} - 1]",
            "mov {f2}, {f}",
            // delta > 0: g - f, f taking g's place, zeta to -zeta - 2.
            "test {z}, {z}",
            "cmovs {g1}, {g2}",
            "cmovs {f2}, {g}",
            "cmovns {zs}, {zm}",
            // g even: g alone, f kept, zeta to zeta - 1.
            "test {g}, 1",
            "cmovz {g1}, {g}",
            "cmovz {f2}, {f}",
            "cmovz {zs}, {zm}",
            "sar {g1}, 1",
            // Step two: the same, from f2, g1, zs back into f, g, z.
            "lea {g}, [{g1} + {f2}]",
            "mov {g2}, {g1}",
            "sub {g2}, {f2}",
            "mov {z}, -2",
            "sub {z}, {zs}",
            "lea {zm}, [{zs} - 1]",
            "mov {f}, {f2}",
            "test {zs}, {zs}",
            "cmovs {g}, {g2}",
            "cmovs {f}, {g1}",
            "cmovns {z}, {zm}",
            "test {g1}, 1",
            "cmovz {g}, {g1}",
            "cmovz {f}, {f2}",
            "cmovz {z}, {zm}",
            "sar {g}, 1",
            ".endr",
            f = inout(reg) f,
            g = inout(reg) g,
            z = inout(reg) z,
            f2 = out(reg) _,
            g1 = out(reg) _,
            g2 = out(reg) _,
            zs = out(reg) _,
            zm = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    // Unpack. `f + 2^20` is in (0, 2^21), so adding it clears the low field
    // without a borrow and the shift leaves u + v * 2^21 exactly; then the
    // same for u. The matrix is the negation of the fields'.
    let (u, v) = unpack(f);
    let (q, r) = unpack(g);
    (
        z,
        [
            u.wrapping_neg(),
            v.wrapping_neg(),
            q.wrapping_neg(),
            r.wrapping_neg(),
        ],
    )
}

/// The two matrix fields of a packed word; see [`divsteps_20`].
#[inline(always)]
fn unpack(w: i64) -> (i64, i64) {
    let t = w.wrapping_add(1 << 20) >> 21;
    let hi = t.wrapping_add(1 << 20) >> 21;
    (t.wrapping_sub(hi << 21), hi)
}

/// `(a * x + b * y) / 2^20` on the low words, wrapping: the low 44 bits are
/// exact, and the next batch reads 20.
#[inline(always)]
fn next_low(a: i64, b: i64, x: u64, y: u64) -> u64 {
    ((a.wrapping_mul(x as i64)).wrapping_add(b.wrapping_mul(y as i64)) >> 20) as u64
}

/// 60 divsteps on the low words `f0` (odd) and `g0`, from `zeta`: three
/// batches of [`divsteps_20`], each starting from the low words the last
/// one's matrix gives, and their matrices multiplied together.
///
/// The product is the matrix of 60 steps scaled by 2^60, and its entries
/// are below 2^60 in magnitude; times four it is scaled by 2^62, the bound
/// `update_de` and `update_fg` are written for, as the 59 steps times eight
/// of libsecp256k1's form are.
#[inline(always)]
fn divsteps_60(zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    let (z, [u1, v1, q1, r1]) = divsteps_20(zeta, f0, g0);
    let (f1, g1) = (next_low(u1, v1, f0, g0), next_low(q1, r1, f0, g0));
    let (z, [u2, v2, q2, r2]) = divsteps_20(z, f1, g1);
    let (f2, g2) = (next_low(u2, v2, f1, g1), next_low(q2, r2, f1, g1));
    let (z, [u3, v3, q3, r3]) = divsteps_20(z, f2, g2);
    // M2 * M1, entries below 2^40; then M3 times that, below 2^60.
    let w = |a: i64, b: i64, c: i64, d: i64| a.wrapping_mul(b).wrapping_add(c.wrapping_mul(d));
    let (u21, v21) = (w(u2, u1, v2, q1), w(u2, v1, v2, r1));
    let (q21, r21) = (w(q2, u1, r2, q1), w(q2, v1, r2, r1));
    let (u, v) = (w(u3, u21, v3, q21), w(u3, v21, v3, r21));
    let (q, r) = (w(q3, u21, r3, q21), w(q3, v21, r3, r21));
    (
        z,
        Trans {
            u: u << 2,
            v: v << 2,
            q: q << 2,
            r: r << 2,
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

/// One round: 60 divsteps on the low words, then their matrix applied to
/// the full-width values.
#[inline(never)]
fn round(st: &mut State) {
    let (z, t) = divsteps_60(st.zeta, st.f[0] as u64, st.g[0] as u64);
    st.zeta = z;
    // f and g first: the next round's divsteps wait on them and not on d
    // and e, so this order lets the core start those while d and e finish.
    update_fg(&mut st.f, &mut st.g, &t);
    update_de(&mut st.d, &mut st.e, &t);
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
    // Ten rounds of 60, written out rather than looped: the count is fixed,
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

    /// Divsteps exactly as Bernstein and Yang define them, on whole `i128`
    /// values with the matrix in rationals made integers by scaling by
    /// 2^60: the reference the packed batches are compared with.
    fn reference_60(zeta: i64, f0: i128, g0: i128) -> (i64, [i128; 4]) {
        let (mut z, mut f, mut g) = (zeta, f0, g0);
        let (mut u, mut v, mut q, mut r) = (1i128 << 60, 0i128, 0i128, 1i128 << 60);
        for _ in 0..60 {
            assert!(f & 1 == 1, "f stays odd");
            if z < 0 && g & 1 == 1 {
                // delta > 0 and g odd: (1 - delta, g, (g - f) / 2).
                (z, f, g) = (-z - 2, g, (g - f) / 2);
                (u, v, q, r) = (q, r, (q - u) / 2, (r - v) / 2);
            } else if g & 1 == 1 {
                (z, g) = (z - 1, (g + f) / 2);
                (q, r) = ((q + u) / 2, (r + v) / 2);
            } else {
                (z, g) = (z - 1, g / 2);
                (q, r) = (q / 2, r / 2);
            }
        }
        // The matrix takes the start to 2^60 times the end.
        assert_eq!(u * f0 + v * g0, f << 60);
        assert_eq!(q * f0 + r * g0, g << 60);
        (z, [u, v, q, r])
    }

    /// The packed batches against [`reference_60`]: random words, words
    /// with long runs of zeros and ones (long runs of halvings and of
    /// swaps), and `zeta` across the range ten rounds reach.
    #[test]
    fn packed_divsteps_agree_with_the_definition() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        let n = if cfg!(debug_assertions) {
            20_000
        } else {
            400_000
        };
        let mut checked = 0;
        for i in 0..n {
            let shape = |w: u64, k: u64| match k % 4 {
                0 => w,
                1 => w & (w >> 7) & (w >> 13),
                2 => w | (w << 9) | (w << 17),
                _ => w >> (k % 61),
            };
            let f0 = shape(next(), i) | 1;
            let g0 = shape(next(), i / 4);
            let zeta = (next() % 1201) as i64 - 600;
            let (z, t) = divsteps_60(zeta, f0, g0);
            // The reference needs only the low 60 bits to agree on the
            // decisions; give it the full words, sign-extended both ways.
            for (f, g) in [
                (f0 as i128, g0 as i128),
                (f0 as i64 as i128, g0 as i64 as i128),
            ] {
                let (rz, m) = reference_60(zeta, f, g);
                assert_eq!(z, rz, "zeta for {f0:x} {g0:x} {zeta}");
                assert_eq!(
                    [t.u as i128, t.v as i128, t.q as i128, t.r as i128],
                    m.map(|e| e * 4),
                    "matrix for {f0:x} {g0:x} {zeta}"
                );
            }
            checked += 1;
        }
        assert_eq!(checked, n);
    }

    /// [`unpack`] at the edges of its ranges, which random divsteps rarely
    /// reach: the low field at both ends of `(-2^20, 2^20)` and the matrix
    /// fields at both ends of `[-2^20, 2^20)`, every combination.
    #[test]
    fn unpacking_holds_at_the_edges() {
        let lows = [-(1i64 << 20) + 1, -1, 0, 1, (1 << 20) - 1];
        let fields = [-(1i64 << 20), -(1 << 20) + 1, -1, 0, 1, (1 << 20) - 1];
        let mut checked = 0;
        for f in lows {
            for u in fields {
                for v in fields {
                    let w = f.wrapping_add(u << 21).wrapping_add(v << 42);
                    assert_eq!(unpack(w), (u, v), "f {f} u {u} v {v}");
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 5 * 6 * 6);
    }

    #[test]
    fn the_inverse_constant_is_an_inverse() {
        // p mod 2^62 is 2^62 - 19.
        let p_lo = (1u64 << 62) - 19;
        assert_eq!(p_lo.wrapping_mul(P_INV62) & M62, 1);
    }
}
