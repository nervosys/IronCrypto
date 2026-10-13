//! P-256's coordinate field, specialised to the shape of its prime.
//!
//! `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`. The generic Montgomery
//! multiplication in [`super::arith`] treats `p` as four arbitrary words and
//! spends sixteen multiplications reducing; this file uses what the words
//! are.
//!
//! # The reduction
//!
//! `-p^-1 mod 2^64` is 1, because `p = -1 mod 2^64`. So each Montgomery step's
//! quotient digit `u` is the low word itself, and adding `u * p` is:
//!
//! ```text
//! u * p = u*2^256 - u*2^224 + u*2^192 + u*2^96 - u
//! (w + u*p) / 2^64 = w1 + u*2^32 + w2*2^64 + (w3 + u*(2^64 - 2^32 + 1))*2^128
//! ```
//!
//! The low word cancels exactly, `u*2^32` is a shift, and only the top word
//! `p3 = 2^64 - 2^32 + 1` needs a multiplication. Four steps cost four
//! multiplications where the generic loop spends sixteen. A product is then
//! the 16-multiplication schoolbook, a square the 10-multiplication one with
//! the cross terms doubled, and both share the reduction.
//!
//! # Bounds
//!
//! Every value held here is below `p`. A product `t` is then below `p^2`, and
//! after reducing its low half `w = (lo + U*p) / 2^256 <= p`, so `hi + w` is
//! below `2p` and one conditional subtraction makes it canonical. That
//! subtraction is chosen with [`select_ct`] behind the same barrier every
//! other runtime selection here uses.
//!
//! # Where it runs
//!
//! On 64-bit targets only, where a `u64 * u64 -> u128` product is one or two
//! instructions. The 32-bit targets keep the generic word loop, whose compiled
//! code `scripts/check-ct.py` has read and whose findings are recorded in
//! `docs/CONSTANT_TIME.md`; a new shape there would be a new set of findings
//! to read for no gain, since a 32-bit target has no 64-bit multiplier to
//! exploit. The tests compare these functions with the generic ones on every
//! target that builds them.

// Only `P` is used where the generic loop runs, and only `active` and `P` on
// x86-64, where `active` is the assembly; the tests use the rest everywhere.
#![cfg_attr(
    any(target_arch = "x86_64", not(target_pointer_width = "64"), ic_limb32),
    allow(dead_code)
)]

use super::arith::select_ct;

/// `p`, little-endian.
pub(crate) const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// `a + b * c + carry`, as (low, high). Cannot overflow: at most
/// `(2^64 - 1) + (2^64 - 1)^2 + (2^64 - 1) = 2^128 - 1`.
#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a + b + carry`, as (sum, carry out).
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a - b - borrow`, as (difference, borrow out), borrows being 0 or 1.
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128)
        .wrapping_sub(b as u128)
        .wrapping_sub(borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

/// Montgomery-reduce `t` (eight words, below `p^2`): `t / 2^256 mod p`,
/// canonical.
#[inline(always)]
fn reduce(t: [u64; 8]) -> [u64; 4] {
    let [mut w0, mut w1, mut w2, mut w3, t4, t5, t6, t7] = t;
    // Four steps, each dividing the low window by 2^64 after adding u*p;
    // see the module documentation for the algebra.
    let mut i = 0;
    while i < 4 {
        let u = w0;
        let (n0, c) = adc(w1, u << 32, 0);
        let (n1, c) = adc(w2, u >> 32, c);
        let (n2, n3) = mac(w3, u, P[3], c);
        (w0, w1, w2, w3) = (n0, n1, n2, n3);
        i += 1;
    }
    // hi + w < 2p.
    let (s0, c) = adc(t4, w0, 0);
    let (s1, c) = adc(t5, w1, c);
    let (s2, c) = adc(t6, w2, c);
    let (s3, top) = adc(t7, w3, c);
    let (d0, b) = sbb(s0, P[0], 0);
    let (d1, b) = sbb(s1, P[1], b);
    let (d2, b) = sbb(s2, P[2], b);
    let (d3, b) = sbb(s3, P[3], b);
    // Subtract when the sum overflowed 256 bits or did not borrow.
    let need = top | (1 - b);
    select_ct(need.wrapping_neg(), [d0, d1, d2, d3], [s0, s1, s2, s3])
}

/// `a * b * 2^-256 mod p`.
#[inline]
pub(crate) fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (r0, c) = mac(0, a[0], b[0], 0);
    let (r1, c) = mac(0, a[0], b[1], c);
    let (r2, c) = mac(0, a[0], b[2], c);
    let (r3, r4) = mac(0, a[0], b[3], c);

    let (r1, c) = mac(r1, a[1], b[0], 0);
    let (r2, c) = mac(r2, a[1], b[1], c);
    let (r3, c) = mac(r3, a[1], b[2], c);
    let (r4, r5) = mac(r4, a[1], b[3], c);

    let (r2, c) = mac(r2, a[2], b[0], 0);
    let (r3, c) = mac(r3, a[2], b[1], c);
    let (r4, c) = mac(r4, a[2], b[2], c);
    let (r5, r6) = mac(r5, a[2], b[3], c);

    let (r3, c) = mac(r3, a[3], b[0], 0);
    let (r4, c) = mac(r4, a[3], b[1], c);
    let (r5, c) = mac(r5, a[3], b[2], c);
    let (r6, r7) = mac(r6, a[3], b[3], c);

    reduce([r0, r1, r2, r3, r4, r5, r6, r7])
}

/// `a^2 * 2^-256 mod p`: the six cross products once, doubled by a shift,
/// then the four squares.
#[inline]
pub(crate) fn square(a: [u64; 4]) -> [u64; 4] {
    // Cross terms a_i * a_j, i < j, at weight i + j.
    let (r1, c) = mac(0, a[0], a[1], 0);
    let (r2, c) = mac(0, a[0], a[2], c);
    let (r3, r4) = mac(0, a[0], a[3], c);

    let (r3, c) = mac(r3, a[1], a[2], 0);
    let (r4, r5) = mac(r4, a[1], a[3], c);

    let (r5, r6) = mac(r5, a[2], a[3], 0);

    // Doubled: r7 takes the bit shifted out of r6.
    let r7 = r6 >> 63;
    let r6 = (r6 << 1) | (r5 >> 63);
    let r5 = (r5 << 1) | (r4 >> 63);
    let r4 = (r4 << 1) | (r3 >> 63);
    let r3 = (r3 << 1) | (r2 >> 63);
    let r2 = (r2 << 1) | (r1 >> 63);
    let r1 = r1 << 1;

    // Plus the squares a_i^2 at weight 2i. The total is below 2^512, so the
    // last carry out is zero.
    let (s0, s1) = mac(0, a[0], a[0], 0);
    let (s2, s3) = mac(0, a[1], a[1], 0);
    let (s4, s5) = mac(0, a[2], a[2], 0);
    let (s6, s7) = mac(0, a[3], a[3], 0);
    let (r1, c) = adc(r1, s1, 0);
    let (r2, c) = adc(r2, s2, c);
    let (r3, c) = adc(r3, s3, c);
    let (r4, c) = adc(r4, s4, c);
    let (r5, c) = adc(r5, s5, c);
    let (r6, c) = adc(r6, s6, c);
    let (r7, _) = adc(r7, s7, c);

    reduce([s0, r1, r2, r3, r4, r5, r6, r7])
}

/// `a + b mod p`.
#[inline]
pub(crate) fn add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (s0, c) = adc(a[0], b[0], 0);
    let (s1, c) = adc(a[1], b[1], c);
    let (s2, c) = adc(a[2], b[2], c);
    let (s3, top) = adc(a[3], b[3], c);
    let (d0, b0) = sbb(s0, P[0], 0);
    let (d1, b0) = sbb(s1, P[1], b0);
    let (d2, b0) = sbb(s2, P[2], b0);
    let (d3, b0) = sbb(s3, P[3], b0);
    let need = top | (1 - b0);
    select_ct(need.wrapping_neg(), [d0, d1, d2, d3], [s0, s1, s2, s3])
}

/// `a - b mod p`: on a borrow, add back `p` masked by it, behind the barrier
/// for the reason the generic `sub` gives.
#[inline]
pub(crate) fn sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (d0, br) = sbb(a[0], b[0], 0);
    let (d1, br) = sbb(a[1], b[1], br);
    let (d2, br) = sbb(a[2], b[2], br);
    let (d3, br) = sbb(a[3], b[3], br);
    let mask = core::hint::black_box(br.wrapping_neg());
    let (r0, c) = adc(d0, P[0] & mask, 0);
    let (r1, c) = adc(d1, P[1] & mask, c);
    let (r2, c) = adc(d2, P[2] & mask, c);
    let (r3, _) = adc(d3, P[3] & mask, c);
    [r0, r1, r2, r3]
}

/// `a^-1 = a^(p-2)`, with `0^-1 = 0`, by a fixed addition chain: 255
/// squarings and 12 multiplications, where square-and-multiply over the bits
/// of `p - 2` costs 255 and 128.
///
/// ```text
/// p - 2 = ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd
/// ```
///
/// With `x_k = a^(2^k - 1)`, a run of `k` ones: build `x_32`, then shift and
/// multiply in each run of the exponent from the top. The exponent is a public
/// constant, so the sequence of operations is the same for every input.
///
/// Over whichever multiplication and squaring it is given, so the chain is
/// written once for the Rust and the assembly.
#[inline(always)]
fn invert_with(
    a: [u64; 4],
    mul: impl Fn([u64; 4], [u64; 4]) -> [u64; 4],
    square: impl Fn([u64; 4]) -> [u64; 4],
) -> [u64; 4] {
    let square_n = |mut a: [u64; 4], n: usize| {
        for _ in 0..n {
            a = square(a);
        }
        a
    };
    let x1 = a;
    let x2 = mul(square(x1), x1);
    let x3 = mul(square(x2), x1);
    let x6 = mul(square_n(x3, 3), x3);
    let x12 = mul(square_n(x6, 6), x6);
    let x15 = mul(square_n(x12, 3), x3);
    let x30 = mul(square_n(x15, 15), x15);
    let x32 = mul(square_n(x30, 2), x2);
    // ffffffff | 00000001
    let t = mul(square_n(x32, 32), x1);
    // | 00000000 00000000 00000000 | ffffffff ffffffff
    let t = mul(square_n(t, 96 + 32), x32);
    let t = mul(square_n(t, 32), x32);
    // | fffffffd: thirty ones, a zero, a one.
    let t = mul(square_n(t, 30), x30);
    mul(square_n(t, 2), x1)
}

/// The inversion over the Rust arithmetic above.
pub(crate) fn invert(a: [u64; 4]) -> [u64; 4] {
    invert_with(a, mul, square)
}

/// What the field runs: the assembly in [`super::p256_x86`] on x86-64, the Rust
/// above on other 64-bit targets. Both compute the same function, and the tests
/// hold them, and the generic word loop, to each other.
pub(crate) mod active {
    #[cfg(target_arch = "x86_64")]
    use super::super::p256_x86 as imp;

    /// Which implementation this build runs, for the tests to assert.
    #[cfg(test)]
    pub(crate) const BACKEND: &str = if cfg!(target_arch = "x86_64") {
        "x86-64 assembly"
    } else {
        "portable"
    };

    /// `a * b * 2^-256 mod p`.
    #[inline(always)]
    pub(crate) fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        #[cfg(target_arch = "x86_64")]
        return imp::mul(&a, &b);
        #[cfg(not(target_arch = "x86_64"))]
        return super::mul(a, b);
    }

    /// `a^2 * 2^-256 mod p`.
    #[inline(always)]
    pub(crate) fn square(a: [u64; 4]) -> [u64; 4] {
        #[cfg(target_arch = "x86_64")]
        return imp::square(&a);
        #[cfg(not(target_arch = "x86_64"))]
        return super::square(a);
    }

    /// `a + b mod p`.
    #[inline(always)]
    pub(crate) fn add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        #[cfg(target_arch = "x86_64")]
        return imp::add(&a, &b);
        #[cfg(not(target_arch = "x86_64"))]
        return super::add(a, b);
    }

    /// `a - b mod p`.
    #[inline(always)]
    pub(crate) fn sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        #[cfg(target_arch = "x86_64")]
        return imp::sub(&a, &b);
        #[cfg(not(target_arch = "x86_64"))]
        return super::sub(a, b);
    }

    /// `a^-1 mod p`, `0` for `0`.
    pub(crate) fn invert(a: [u64; 4]) -> [u64; 4] {
        super::invert_with(a, mul, square)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nist::arith::{compute_neg_inv, select, wide};

    /// The generic word loop, which every result here must match bit for bit.
    fn reference_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let (reduced, lo, need) = wide::mont_mul(a, b, P, compute_neg_inv(P[0]));
        select(need.wrapping_neg(), reduced, lo)
    }

    /// SplitMix64: a reproducible source of operands.
    pub(crate) struct Rng(pub(crate) u64);
    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        /// Below p: a uniform 256-bit value, rejected until it is.
        fn below_p(&mut self) -> [u64; 4] {
            loop {
                let x = [self.next(), self.next(), self.next(), self.next()];
                if wide::sbb(x, P).1 == 1 {
                    return x;
                }
            }
        }
        /// Below p, but with whole words of zeros and ones, where carries run
        /// the full width.
        fn structured(&mut self) -> [u64; 4] {
            loop {
                let r = self.next();
                let mut x = [0u64; 4];
                for (i, limb) in x.iter_mut().enumerate() {
                    *limb = match (r >> (2 * i)) & 3 {
                        0 => 0,
                        1 => u64::MAX,
                        2 => self.next(),
                        _ => 1 << (self.next() % 64),
                    };
                }
                if wide::sbb(x, P).1 == 1 {
                    return x;
                }
            }
        }
    }

    /// Values at the edges: zero, one, two, p - 1, p - 2, 2^256 mod p, the
    /// largest value with each top word, and powers of two near the top.
    fn edges() -> std::vec::Vec<[u64; 4]> {
        let one = [1u64, 0, 0, 0];
        let mut v = std::vec![
            [0u64; 4],
            one,
            [2, 0, 0, 0],
            wide::sbb(P, one).0,
            wide::sbb(P, [2, 0, 0, 0]).0,
            // 2^256 - p, which is R mod p: one in Montgomery form.
            wide::sbb([0; 4], P).0,
            [u64::MAX, u64::MAX, u64::MAX, 0xffff_ffff_0000_0000],
            [0, 0, 0, 0xffff_ffff_0000_0000],
            [u64::MAX, 0xffff_ffff, 0, 0xffff_ffff_0000_0000],
            [0, 0, 0, 1 << 63],
            [u64::MAX, u64::MAX, u64::MAX, (1 << 63) - 1],
            [0, 1 << 32, 0, 0],
            [0xffff_ffff, 0, 0, 0],
        ];
        for k in [3u64, 0xffff_ffff, 1 << 32, 1 << 63] {
            v.push(wide::sbb(P, [k, 0, 0, 0]).0);
        }
        v
    }

    #[test]
    fn edge_cases_agree_with_the_generic_loop() {
        let e = edges();
        let mut checked = 0;
        for a in &e {
            assert_eq!(square(*a), reference_mul(*a, *a), "square {a:x?}");
            for b in &e {
                assert_eq!(mul(*a, *b), reference_mul(*a, *b), "{a:x?} * {b:x?}");
                checked += 1;
            }
        }
        assert_eq!(checked, e.len() * e.len());
    }

    /// A million random products and two million squares, half uniform and
    /// half built from whole words of zeros and ones.
    #[test]
    fn random_operands_agree_with_the_generic_loop() {
        let mut rng = Rng(0x0256);
        for i in 0..1 << 20 {
            let (a, b) = if i % 2 == 0 {
                (rng.below_p(), rng.below_p())
            } else {
                (rng.structured(), rng.structured())
            };
            assert_eq!(mul(a, b), reference_mul(a, b), "{a:x?} * {b:x?}");
            assert_eq!(square(a), reference_mul(a, a), "{a:x?}^2");
            assert_eq!(square(b), reference_mul(b, b), "{b:x?}^2");
        }
    }

    /// The generic addition and subtraction, which these must match.
    fn reference_add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let (sum, carry) = wide::adc(a, b);
        let (reduced, borrow) = wide::sbb(sum, P);
        select((carry | (1 - borrow)).wrapping_neg(), reduced, sum)
    }
    fn reference_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let (diff, borrow) = wide::sbb(a, b);
        let (fixed, _) = wide::adc(diff, P);
        select(borrow.wrapping_neg(), fixed, diff)
    }

    /// Every operation the field runs, against the Rust and the generic word
    /// loop: the same edge cases and two million random pairs.
    fn check_active(a: [u64; 4], b: [u64; 4]) {
        let want = reference_mul(a, b);
        assert_eq!(active::mul(a, b), want, "active {a:x?} * {b:x?}");
        assert_eq!(mul(a, b), want, "rust {a:x?} * {b:x?}");
        let want = reference_mul(a, a);
        assert_eq!(active::square(a), want, "active {a:x?}^2");
        assert_eq!(square(a), want, "rust {a:x?}^2");
        let want = reference_add(a, b);
        assert_eq!(active::add(a, b), want, "active {a:x?} + {b:x?}");
        assert_eq!(add(a, b), want, "rust {a:x?} + {b:x?}");
        let want = reference_sub(a, b);
        assert_eq!(active::sub(a, b), want, "active {a:x?} - {b:x?}");
        assert_eq!(sub(a, b), want, "rust {a:x?} - {b:x?}");
    }

    #[test]
    fn the_active_backend_agrees_with_the_generic_loop() {
        // On this CPU the assembly is what runs; say so, so that a build that
        // quietly fell back to the Rust would fail here rather than pass
        // having tested the wrong thing.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(active::BACKEND, "x86-64 assembly");
        #[cfg(not(target_arch = "x86_64"))]
        assert_eq!(active::BACKEND, "portable");

        let e = edges();
        for a in &e {
            for b in &e {
                check_active(*a, *b);
            }
        }
        let mut rng = Rng(0xa5a5);
        for i in 0..1 << 20 {
            let (a, b) = if i % 2 == 0 {
                (rng.below_p(), rng.below_p())
            } else {
                (rng.structured(), rng.structured())
            };
            check_active(a, b);
        }
        // And the chain over the active arithmetic.
        let one = wide::sbb([0; 4], P).0;
        for a in e.iter().chain([rng.below_p(), rng.structured()].iter()) {
            let inv = active::invert(*a);
            assert_eq!(inv, invert(*a));
            if *a != [0; 4] {
                assert_eq!(active::mul(*a, inv), one);
            }
        }
    }

    /// The addition chain against square-and-multiply over the bits of
    /// `p - 2`, written out here independently of `pow`, and against the
    /// defining property.
    #[test]
    fn the_inversion_chain_is_fermat() {
        let fermat = |a: [u64; 4]| {
            let e = wide::sbb(P, [2, 0, 0, 0]).0;
            // Montgomery one.
            let mut r = wide::sbb([0; 4], P).0;
            for i in (0..256).rev() {
                r = reference_mul(r, r);
                if (e[i / 64] >> (i % 64)) & 1 == 1 {
                    r = reference_mul(r, a);
                }
            }
            r
        };
        let one = wide::sbb([0; 4], P).0;
        let mut rng = Rng(7);
        let mut inputs = edges();
        for _ in 0..64 {
            inputs.push(rng.below_p());
        }
        for a in inputs {
            let inv = invert(a);
            assert_eq!(inv, fermat(a), "{a:x?}");
            if a != [0; 4] {
                assert_eq!(mul(a, inv), one, "{a:x?}");
            } else {
                assert_eq!(inv, [0; 4]);
            }
        }
    }
}
