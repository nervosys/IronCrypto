//! Poly1305 four blocks per step, in four 64-bit lanes, on AVX2.
//!
//! # The arithmetic
//!
//! The scalar path's radix `2^26`, with each 64-bit lane of a `ymm` register
//! holding one limb of an independent accumulator. `vpmuludq` multiplies the
//! low 32 bits of each lane into a 64-bit product, which is exactly the
//! 26-by-26-bit limb product the scalar `mul_unreduced` forms one at a time.
//!
//! Lane `i` absorbs every fourth block. Each step multiplies all four
//! accumulators by `r^4` and adds the next four blocks:
//!
//! ```text
//! H_i  <-  H_i * r^4 + m_(4t + i)
//! ```
//!
//! and the last step multiplies lane `i` by `r^(4 - i)` instead, after which
//! the sum of the lanes is the Horner evaluation the scalar code computes.
//! The scalar accumulator enters as an addend to the first block, exactly as
//! `absorb4` adds it to its oldest block. The four products per step are
//! independent, so the loop-carried chain is one multiplication and one carry
//! pass per sixty-four bytes rather than per sixteen.
//!
//! The loads put blocks `0, 2, 1, 3` of each group in lanes `0, 1, 2, 3` --
//! what `vpunpck[lh]qdq` gives without a cross-lane permute -- so the last
//! step's powers are `r^4, r^2, r^3, r` in that lane order.
//!
//! # Bounds
//!
//! The carry pass is the two interleaved chains of the usual AVX2 Poly1305
//! (`d3 -> d4 -> d0 -> d1` beside `d0 -> d1 -> d2 -> d3 -> d4`). From products
//! summed below `2^58` it leaves every limb below `2^26 + 2^10`. A message limb
//! is below `2^26`, so a limb entering the multiplication is below `2^27.01`,
//! a product with `5 * r_j < 2^28.33` below `2^55.4`, and five of them below
//! `2^57.8`: the same `2^58` the carry pass was entered with. Nothing comes
//! near the top of a 64-bit lane. The scalar accumulator enters with limbs
//! below `2^26 + 2^15` and only on the first block, inside the same bound.
//!
//! # Trusting it
//!
//! `chacha::tests::the_avx2_poly1305_agrees_with_the_serial_one` compares
//! tags against the one-block-at-a-time path at every length from 0 to 600
//! bytes and several longer ones, split at every offset that matters, with
//! the largest message limbs and the largest clamped `r`.
//!
//! # Constant-time properties
//!
//! Multiplies, adds, shifts and masks; no branch on a value and no
//! data-dependent address. The loop runs once per sixty-four bytes, which is
//! public. `ct_poly1305_avx2_step` and `ct_poly1305_avx2_finish` in
//! `scripts/ct-audit` hold the step and the lane folding to that.
//!
//! # Safety
//!
//! `unsafe` because `#[target_feature]` requires it: the caller must not
//! invoke these without AVX2. The only other unsafe operations are the
//! unaligned loads, each of 32 bytes inside a 64-byte group.

use core::arch::x86_64::*;

/// One limb of four accumulators, or of four multipliers.
pub type Limbs = [__m256i; 5];

const MASK26: i64 = 0x3ff_ffff;

/// `r` limbs, and `5 * r` for limbs 1..=4, for one lane arrangement.
pub struct Mul {
    r: Limbs,
    s: [__m256i; 4],
}

impl Mul {
    /// `p` in every lane.
    #[target_feature(enable = "avx2")]
    pub fn splat(p: &[u32; 5]) -> Mul {
        Mul::lanes([p, p, p, p])
    }

    /// Lane `i` multiplies by `p[i]`.
    #[target_feature(enable = "avx2")]
    pub fn lanes(p: [&[u32; 5]; 4]) -> Mul {
        let limb = |j: usize| {
            _mm256_setr_epi64x(
                p[0][j] as i64,
                p[1][j] as i64,
                p[2][j] as i64,
                p[3][j] as i64,
            )
        };
        let r = [limb(0), limb(1), limb(2), limb(3), limb(4)];
        let five = |x: __m256i| _mm256_add_epi64(_mm256_slli_epi64::<2>(x), x);
        let s = [five(r[1]), five(r[2]), five(r[3]), five(r[4])];
        Mul { r, s }
    }
}

/// Four whole blocks, as limbs in lanes `0, 1, 2, 3` = blocks `0, 2, 1, 3`.
///
/// # Safety
///
/// The CPU must support AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn load(blocks: &[u8; 64]) -> Limbs {
    // SAFETY: two 32-byte unaligned loads inside a 64-byte array.
    let (a, b) = unsafe {
        (
            _mm256_loadu_si256(blocks.as_ptr() as *const __m256i),
            _mm256_loadu_si256(blocks.as_ptr().add(32) as *const __m256i),
        )
    };
    // a = [b0.lo, b0.hi, b1.lo, b1.hi], b = [b2.lo, b2.hi, b3.lo, b3.hi].
    let lo = _mm256_unpacklo_epi64(a, b);
    let hi = _mm256_unpackhi_epi64(a, b);
    let mask = _mm256_set1_epi64x(MASK26);
    [
        _mm256_and_si256(lo, mask),
        _mm256_and_si256(_mm256_srli_epi64::<26>(lo), mask),
        _mm256_and_si256(
            _mm256_or_si256(_mm256_srli_epi64::<52>(lo), _mm256_slli_epi64::<12>(hi)),
            mask,
        ),
        _mm256_and_si256(_mm256_srli_epi64::<14>(hi), mask),
        // Whole blocks, so the 2^128 bit is always set.
        _mm256_or_si256(_mm256_srli_epi64::<40>(hi), _mm256_set1_epi64x(1 << 24)),
    ]
}

/// `h * r`, carried back to 26-bit limbs (see the module's bounds).
#[inline]
#[target_feature(enable = "avx2")]
fn mul(h: &Limbs, m: &Mul) -> Limbs {
    let (r, s) = (&m.r, &m.s);
    let p = |a: __m256i, b: __m256i| _mm256_mul_epu32(a, b);
    let add = |a: __m256i, b: __m256i| _mm256_add_epi64(a, b);
    let d0 = add(
        add(
            add(p(h[0], r[0]), p(h[1], s[3])),
            add(p(h[2], s[2]), p(h[3], s[1])),
        ),
        p(h[4], s[0]),
    );
    let d1 = add(
        add(
            add(p(h[0], r[1]), p(h[1], r[0])),
            add(p(h[2], s[3]), p(h[3], s[2])),
        ),
        p(h[4], s[1]),
    );
    let d2 = add(
        add(
            add(p(h[0], r[2]), p(h[1], r[1])),
            add(p(h[2], r[0]), p(h[3], s[3])),
        ),
        p(h[4], s[2]),
    );
    let d3 = add(
        add(
            add(p(h[0], r[3]), p(h[1], r[2])),
            add(p(h[2], r[1]), p(h[3], r[0])),
        ),
        p(h[4], s[3]),
    );
    let d4 = add(
        add(
            add(p(h[0], r[4]), p(h[1], r[3])),
            add(p(h[2], r[2]), p(h[3], r[1])),
        ),
        p(h[4], r[0]),
    );
    carry([d0, d1, d2, d3, d4])
}

/// Two interleaved carry chains, folding `2^130` back in as `5`.
#[inline]
#[target_feature(enable = "avx2")]
fn carry(d: [__m256i; 5]) -> Limbs {
    let mask = _mm256_set1_epi64x(MASK26);
    let [mut d0, mut d1, mut d2, mut d3, mut d4] = d;
    let shr = |x: __m256i| _mm256_srli_epi64::<26>(x);
    let and = |x: __m256i| _mm256_and_si256(x, mask);
    let add = |a: __m256i, b: __m256i| _mm256_add_epi64(a, b);

    let c3 = shr(d3);
    d3 = and(d3);
    d4 = add(d4, c3);
    let c0 = shr(d0);
    d0 = and(d0);
    d1 = add(d1, c0);

    let c4 = shr(d4);
    d4 = and(d4);
    d0 = add(d0, add(c4, _mm256_slli_epi64::<2>(c4)));
    let c1 = shr(d1);
    d1 = and(d1);
    d2 = add(d2, c1);

    let c2 = shr(d2);
    d2 = and(d2);
    d3 = add(d3, c2);
    let c0 = shr(d0);
    d0 = and(d0);
    d1 = add(d1, c0);

    let c3 = shr(d3);
    d3 = and(d3);
    d4 = add(d4, c3);
    [d0, d1, d2, d3, d4]
}

#[inline]
#[target_feature(enable = "avx2")]
fn add_limbs(a: &Limbs, b: &Limbs) -> Limbs {
    [
        _mm256_add_epi64(a[0], b[0]),
        _mm256_add_epi64(a[1], b[1]),
        _mm256_add_epi64(a[2], b[2]),
        _mm256_add_epi64(a[3], b[3]),
        _mm256_add_epi64(a[4], b[4]),
    ]
}

/// One step: `h * r^4 + next four blocks`.
///
/// # Safety
///
/// The CPU must support AVX2.
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn step(h: &Limbs, r4: &Mul, blocks: &[u8; 64]) -> Limbs {
    // SAFETY: AVX2, as the caller guarantees.
    let m = unsafe { load(blocks) };
    add_limbs(&mul(h, r4), &m)
}

/// The last multiplication, by `r^4, r^2, r^3, r` in lanes `0..4`, and the sum
/// of the lanes, as five 64-bit limbs below `2^28` for the scalar `reduce`.
///
/// # Safety
///
/// The CPU must support AVX2.
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn finish(h: &Limbs, last: &Mul) -> [u64; 5] {
    let h = mul(h, last);
    let mut out = [0u64; 5];
    for (o, v) in out.iter_mut().zip(h) {
        // Fold the four lanes: high half onto low, then the two that remain.
        let x = _mm_add_epi64(_mm256_castsi256_si128(v), _mm256_extracti128_si256::<1>(v));
        let x = _mm_add_epi64(x, _mm_unpackhi_epi64(x, x));
        *o = _mm_cvtsi128_si64(x) as u64;
    }
    out
}

/// Absorb `data`, a whole number of 64-byte groups and at least one, into the
/// scalar accumulator `acc`; returns the five unreduced limbs of the result
/// for the scalar `reduce`.
///
/// `powers` are `r^2, r^3, r^4`, as `Poly1305` keeps them.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn absorb(
    acc: &[u32; 5],
    r: &[u32; 5],
    powers: &[[u32; 5]; 3],
    data: &[u8],
) -> [u64; 5] {
    debug_assert!(!data.is_empty() && data.len().is_multiple_of(64));
    // `chunks_exact` makes every conversion succeed.
    let mut groups = data.chunks_exact(64).flat_map(<&[u8; 64]>::try_from);
    let Some(first) = groups.next() else {
        return [
            acc[0] as u64,
            acc[1] as u64,
            acc[2] as u64,
            acc[3] as u64,
            acc[4] as u64,
        ];
    };
    // SAFETY: AVX2, as the caller guarantees.
    let mut h = unsafe { load(first) };
    // The accumulator joins the oldest block, which is lane 0.
    let a = |j: usize| _mm256_setr_epi64x(acc[j] as i64, 0, 0, 0);
    h = add_limbs(&h, &[a(0), a(1), a(2), a(3), a(4)]);

    let r4 = Mul::splat(&powers[2]);
    for g in groups {
        // SAFETY: AVX2, as the caller guarantees.
        h = unsafe { step(&h, &r4, g) };
    }
    let last = Mul::lanes([&powers[2], &powers[0], &powers[1], r]);
    // SAFETY: AVX2, as the caller guarantees.
    unsafe { finish(&h, &last) }
}
