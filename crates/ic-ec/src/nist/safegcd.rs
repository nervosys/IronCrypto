//! Constant-time modular inversion by Bernstein and Yang's divsteps, for
//! moduli below `2^256`.
//!
//! "Fast constant-time gcd computation and modular inversion", Bernstein and
//! Yang, CHES 2019, in the form libsecp256k1 implements as `modinv64`
//! (Pieter Wuille's "half-delta" divsteps, `src/modinv64_impl.h`): values in
//! five signed 62-bit limbs, 59 divsteps at a time on the low words alone,
//! each batch's 2x2 transition matrix then applied to the full-width `f, g`
//! and to the Bezout coefficients `d, e`, which are kept reduced modulo the
//! modulus as they go. Ten batches, 590 divsteps, are enough for any
//! modulus and input below `2^256`; that bound is libsecp256k1's, from
//! <https://github.com/sipa/safegcd-bounds>. Extra divsteps after `g`
//! reaches zero change nothing, so the count is an upper bound and not a
//! tuning.
//!
//! # Constant time
//!
//! The number of divsteps is fixed, and each is branch-free: its two
//! decisions -- whether `zeta < 0`, whether `g` is odd -- become masks, as do
//! the signs that `update_de` and `normalize` act on. The only conditions
//! are on the modulus's limbs, which are public constants. Every
//! multiplication is 64 by 64 bits into 128, which is one instruction on the
//! 64-bit targets this is used on and is not used elsewhere: a 32-bit target
//! would lower `i128` products to library calls, so they keep Fermat.
//!
//! # Why
//!
//! An inversion by Fermat's little theorem is about 255 squarings and a
//! few dozen multiplications; with the generic multiplication P-256's scalar
//! inversion took 5.3 microseconds, more than a third of a signature. This is
//! a fraction of that, and it is the same algorithm for both of P-256's
//! residue rings.

/// `2^62 - 1`.
const M62: u64 = u64::MAX >> 2;

/// A value in five signed 62-bit limbs, least significant first.
type Signed62 = [i64; 5];

/// The modulus in signed-62 form, and its inverse modulo `2^62`.
#[derive(Clone, Copy)]
pub(crate) struct ModInfo {
    modulus: Signed62,
    modulus_inv62: u64,
}

impl ModInfo {
    /// For an odd modulus below `2^256`, given as four little-endian words.
    pub(crate) const fn new(m: [u64; 4]) -> Self {
        let modulus = to_signed62(m);
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

/// Four 64-bit words as five 62-bit limbs.
const fn to_signed62(a: [u64; 4]) -> Signed62 {
    [
        (a[0] & M62) as i64,
        ((a[0] >> 62 | a[1] << 2) & M62) as i64,
        ((a[1] >> 60 | a[2] << 4) & M62) as i64,
        ((a[2] >> 58 | a[3] << 6) & M62) as i64,
        (a[3] >> 56) as i64,
    ]
}

/// Five 62-bit limbs, each in `[0, 2^62)`, as four 64-bit words.
fn from_signed62(a: &Signed62) -> [u64; 4] {
    let (a0, a1, a2, a3, a4) = (
        a[0] as u64,
        a[1] as u64,
        a[2] as u64,
        a[3] as u64,
        a[4] as u64,
    );
    [
        a0 | a1 << 62,
        a1 >> 2 | a2 << 60,
        a2 >> 4 | a3 << 58,
        a3 >> 6 | a4 << 56,
    ]
}

/// The transition matrix of a batch of divsteps, scaled by `2^62`.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 59 divsteps on the low words of `f` and `g`, branch-free; returns the new
/// `zeta` and the matrix. A line-for-line transcription of libsecp256k1's
/// `secp256k1_modinv64_divsteps_59`.
#[inline(always)]
fn divsteps_59(mut zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    // The matrix starts as the identity times 8, because the caller wants it
    // scaled by 2^62 and 59 steps scale it by 2^59.
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        // Masks for zeta < 0 and for g odd. Behind the barrier, as
        // libsecp256k1 puts them behind `volatile`, so that the compiler
        // cannot see they are 0 or all ones and branch on them; measured, it
        // costs under three percent of an inversion.
        let c1 = core::hint::black_box((zeta >> 63) as u64);
        let mut mask1 = c1;
        let c2 = core::hint::black_box(g & 1);
        let mask2 = c2.wrapping_neg();
        // x, y, z: f, u, v, negated when zeta < 0.
        let x = (f ^ mask1).wrapping_sub(mask1);
        let y = (u ^ mask1).wrapping_sub(mask1);
        let z = (v ^ mask1).wrapping_sub(mask1);
        // Added to g, q, r when g is odd.
        g = g.wrapping_add(x & mask2);
        q = q.wrapping_add(y & mask2);
        r = r.wrapping_add(z & mask2);
        // When both, swap roles: zeta becomes -zeta - 2, otherwise zeta - 1.
        mask1 &= mask2;
        zeta = (zeta ^ mask1 as i64).wrapping_sub(1);
        f = f.wrapping_add(g & mask1);
        u = u.wrapping_add(q & mask1);
        v = v.wrapping_add(r & mask1);
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    (
        zeta,
        Trans {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// `a * b` as `i128`.
#[inline(always)]
fn m(a: i64, b: i64) -> i128 {
    a as i128 * b as i128
}

/// `[d, e] = t * [d, e] / 2^62`, adding multiples of the modulus to make the
/// division exact and keep both in `(-2m, m)`: libsecp256k1's
/// `secp256k1_modinv64_update_de_62`.
#[inline(always)]
fn update_de(d: &mut Signed62, e: &mut Signed62, t: &Trans, info: &ModInfo) {
    let [d0, d1, d2, d3, d4] = *d;
    let [e0, e1, e2, e3, e4] = *e;
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let md_mod = &info.modulus;
    // md, me start at zero, plus [u, q] if d is negative, plus [v, r] if e
    // is.
    let sd = d4 >> 63;
    let se = e4 >> 63;
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);
    let mut cd = m(u, d0) + m(v, e0);
    let mut ce = m(q, d0) + m(r, e0);
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
    // Limbs 1 to 4, each stored one place down.
    cd += m(u, d1) + m(v, e1);
    ce += m(q, d1) + m(r, e1);
    if md_mod[1] != 0 {
        cd += m(md_mod[1], md);
        ce += m(md_mod[1], me);
    }
    d[0] = (cd as u64 & M62) as i64;
    cd >>= 62;
    e[0] = (ce as u64 & M62) as i64;
    ce >>= 62;
    cd += m(u, d2) + m(v, e2);
    ce += m(q, d2) + m(r, e2);
    if md_mod[2] != 0 {
        cd += m(md_mod[2], md);
        ce += m(md_mod[2], me);
    }
    d[1] = (cd as u64 & M62) as i64;
    cd >>= 62;
    e[1] = (ce as u64 & M62) as i64;
    ce >>= 62;
    cd += m(u, d3) + m(v, e3);
    ce += m(q, d3) + m(r, e3);
    if md_mod[3] != 0 {
        cd += m(md_mod[3], md);
        ce += m(md_mod[3], me);
    }
    d[2] = (cd as u64 & M62) as i64;
    cd >>= 62;
    e[2] = (ce as u64 & M62) as i64;
    ce >>= 62;
    cd += m(u, d4) + m(v, e4);
    ce += m(q, d4) + m(r, e4);
    cd += m(md_mod[4], md);
    ce += m(md_mod[4], me);
    d[3] = (cd as u64 & M62) as i64;
    cd >>= 62;
    e[3] = (ce as u64 & M62) as i64;
    ce >>= 62;
    // What remains is the top limb.
    d[4] = cd as i64;
    e[4] = ce as i64;
}

/// `[f, g] = t * [f, g] / 2^62`, which is exact: libsecp256k1's
/// `secp256k1_modinv64_update_fg_62`.
#[inline(always)]
fn update_fg(f: &mut Signed62, g: &mut Signed62, t: &Trans) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut cf = m(u, f[0]) + m(v, g[0]);
    let mut cg = m(q, f[0]) + m(r, g[0]);
    debug_assert!(cf as u64 & M62 == 0 && cg as u64 & M62 == 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf += m(u, f[i]) + m(v, g[i]);
        cg += m(q, f[i]) + m(r, g[i]);
        f[i - 1] = (cf as u64 & M62) as i64;
        cf >>= 62;
        g[i - 1] = (cg as u64 & M62) as i64;
        cg >>= 62;
    }
    f[4] = cf as i64;
    g[4] = cg as i64;
}

/// Bring `r` from `(-2m, m)` to `[0, m)`, negated first when `sign` is
/// negative: libsecp256k1's `secp256k1_modinv64_normalize_62`.
#[inline(always)]
fn normalize(r: &mut Signed62, sign: i64, info: &ModInfo) {
    let md = &info.modulus;
    let m62 = M62 as i64;
    let [mut r0, mut r1, mut r2, mut r3, mut r4] = *r;
    // Add the modulus if negative, then negate if asked: into (-m, m).
    let cond_add = r4 >> 63;
    r0 += md[0] & cond_add;
    r1 += md[1] & cond_add;
    r2 += md[2] & cond_add;
    r3 += md[3] & cond_add;
    r4 += md[4] & cond_add;
    let cond_negate = sign >> 63;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    // Carry, so every limb but the top is in [0, 2^62).
    r1 += r0 >> 62;
    r0 &= m62;
    r2 += r1 >> 62;
    r1 &= m62;
    r3 += r2 >> 62;
    r2 &= m62;
    r4 += r3 >> 62;
    r3 &= m62;
    // Add the modulus again if still negative: into [0, m).
    let cond_add = r4 >> 63;
    r0 += md[0] & cond_add;
    r1 += md[1] & cond_add;
    r2 += md[2] & cond_add;
    r3 += md[3] & cond_add;
    r4 += md[4] & cond_add;
    r1 += r0 >> 62;
    r0 &= m62;
    r2 += r1 >> 62;
    r1 &= m62;
    r3 += r2 >> 62;
    r2 &= m62;
    r4 += r3 >> 62;
    r3 &= m62;
    *r = [r0, r1, r2, r3, r4];
}

/// `x^-1 mod m` for `x` in `[0, m)`, with `0` for `0`, in constant time.
/// `x` and the result are plain integers, not Montgomery form.
pub(crate) fn invert(x: &[u64; 4], info: &ModInfo) -> [u64; 4] {
    let mut d: Signed62 = [0; 5];
    let mut e: Signed62 = [1, 0, 0, 0, 0];
    let mut f = info.modulus;
    let mut g = to_signed62(*x);
    let mut zeta = -1i64;
    for _ in 0..10 {
        let (z, t) = divsteps_59(zeta, f[0] as u64, g[0] as u64);
        zeta = z;
        update_de(&mut d, &mut e, &t, info);
        update_fg(&mut f, &mut g, &t);
    }
    // g is now zero and f is +-1 (or +-m, for x = 0, which leaves d = 0).
    normalize(&mut d, f[4], info);
    from_signed62(&d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moduli() -> [[u64; 4]; 2] {
        [
            crate::nist::p256_field::P,
            <crate::p256::P256 as crate::nist::point::Curve>::Scalar::MODULUS,
        ]
    }

    /// `a * b mod m`, by schoolbook and long division by shift-and-subtract:
    /// slow, and sharing nothing with the code under test or with Montgomery.
    fn mulmod(a: [u64; 4], b: [u64; 4], m: [u64; 4]) -> [u64; 4] {
        // 512-bit product.
        let mut p = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = p[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
                p[i + j] = t as u64;
                carry = t >> 64;
            }
            p[i + 4] = carry as u64;
        }
        // Reduce bit by bit from the top: r = 2r + bit, minus m when r >= m.
        let mut r = [0u64; 5];
        for bit in (0..512).rev() {
            // r <<= 1
            for k in (1..5).rev() {
                r[k] = r[k] << 1 | r[k - 1] >> 63;
            }
            r[0] = r[0] << 1 | (p[bit / 64] >> (bit % 64)) & 1;
            // if r >= m: r -= m
            let mut ge = r[4] != 0;
            if !ge {
                ge = true;
                for k in (0..4).rev() {
                    if r[k] != m[k] {
                        ge = r[k] > m[k];
                        break;
                    }
                }
            }
            if ge {
                let mut borrow = 0u128;
                for k in 0..5 {
                    let mk = if k < 4 { m[k] } else { 0 };
                    let t = (r[k] as u128).wrapping_sub(mk as u128).wrapping_sub(borrow);
                    r[k] = t as u64;
                    borrow = (t >> 127) & 1;
                }
            }
        }
        [r[0], r[1], r[2], r[3]]
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
        for m in moduli() {
            let info = ModInfo::new(m);
            assert_eq!(invert(&[0; 4], &info), [0; 4]);
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
                let inv = invert(x, &info);
                assert!(below(inv), "{x:x?}");
                // The slow product only on a sample; the rest by a second
                // inversion, which must give back x.
                if i < 2_000 {
                    assert_eq!(mulmod(*x, inv, m), [1, 0, 0, 0], "{x:x?}");
                } else {
                    assert_eq!(invert(&inv, &info), *x, "{x:x?}");
                }
            }
        }
    }
}
