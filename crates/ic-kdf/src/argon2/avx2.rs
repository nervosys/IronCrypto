//! Argon2's compression function `G` with AVX2.
//!
//! The scalar form in the parent module is the definition, checked against
//! RFC 9106 and libargon2; this computes the same function four words at a
//! time, and is checked against it block for block.
//!
//! # Layout
//!
//! `P` works on sixteen words as a 4x4 matrix of rows `a`, `b`, `c`, `d`,
//! each of four words, which is one 256-bit register. The column step is
//! BlaMka's `G` applied lane-wise to the four registers. The diagonal step is
//! the same after rotating `b`, `c` and `d` left by one, two and three lanes,
//! and rotating them back after. A row of the block is sixteen consecutive
//! words, so four aligned loads; a column is eight pairs of words, one pair
//! from each row, so pairs of 128-bit loads.
//!
//! # BlaMka
//!
//! `x + y + 2 * lo(x) * lo(y)`: `_mm256_mul_epu32` multiplies the low 32
//! bits of each 64-bit lane into a full 64-bit product, which is exactly
//! `lo(x) * lo(y)`. Rotations by 32, 24 and 16 are byte shuffles; by 63 it is
//! a shift right by 63 and a doubling.
//!
//! Nothing here depends on secret data for control flow or addressing: the
//! function is a fixed sequence of arithmetic, like the scalar one.

use core::arch::x86_64::*;

use super::{Block, BLOCK_WORDS};

/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn blamka(x: __m256i, y: __m256i) -> __m256i {
    let z = _mm256_mul_epu32(x, y);
    _mm256_add_epi64(_mm256_add_epi64(x, y), _mm256_add_epi64(z, z))
}

/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotr32(x: __m256i) -> __m256i {
    _mm256_shuffle_epi32::<0b10_11_00_01>(x)
}

/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotr24(x: __m256i) -> __m256i {
    let m = _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13,
        14, 15, 8, 9, 10,
    );
    _mm256_shuffle_epi8(x, m)
}

/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotr16(x: __m256i) -> __m256i {
    let m = _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12,
        13, 14, 15, 8, 9,
    );
    _mm256_shuffle_epi8(x, m)
}

/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotr63(x: __m256i) -> __m256i {
    _mm256_xor_si256(_mm256_srli_epi64::<63>(x), _mm256_add_epi64(x, x))
}

/// BlaMka's `G` on four columns at once.
///
/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn g(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    *a = blamka(*a, *b);
    *d = rotr32(_mm256_xor_si256(*d, *a));
    *c = blamka(*c, *d);
    *b = rotr24(_mm256_xor_si256(*b, *c));
    *a = blamka(*a, *b);
    *d = rotr16(_mm256_xor_si256(*d, *a));
    *c = blamka(*c, *d);
    *b = rotr63(_mm256_xor_si256(*b, *c));
}

/// The permutation `P`: columns, then diagonals.
///
/// # Safety
///
/// The CPU must have AVX2. Register arithmetic only, reached only from `compress`,
/// which `compress_into` calls after `have_avx2()` confirmed AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn p(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    g(a, b, c, d);
    // Lane i of b, c, d moves to lane i - 1, i - 2, i - 3: the diagonals
    // (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14) become columns.
    *b = _mm256_permute4x64_epi64::<0b00_11_10_01>(*b);
    *c = _mm256_permute4x64_epi64::<0b01_00_11_10>(*c);
    *d = _mm256_permute4x64_epi64::<0b10_01_00_11>(*d);
    g(a, b, c, d);
    *b = _mm256_permute4x64_epi64::<0b10_01_00_11>(*b);
    *c = _mm256_permute4x64_epi64::<0b01_00_11_10>(*c);
    *d = _mm256_permute4x64_epi64::<0b00_11_10_01>(*d);
}

/// `G(x, y)`, written to `out`, or XORed into it when `xor` is set.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn compress(x: &Block, y: &Block, out: &mut Block, xor: bool) {
    let mut r = [0u64; BLOCK_WORDS];
    for ((slot, a), b) in r.iter_mut().zip(x.iter()).zip(y.iter()) {
        *slot = a ^ b;
    }
    let mut q = r;
    let qp = q.as_mut_ptr();

    // Rows: words 16*row .. 16*row + 16, four registers. Every offset below
    // is at most 16*7 + 12, and each load is four words, so within 128.
    for row in 0..8 {
        let base = qp.add(row * 16);
        let mut a = _mm256_loadu_si256(base as *const __m256i);
        let mut b = _mm256_loadu_si256(base.add(4) as *const __m256i);
        let mut c = _mm256_loadu_si256(base.add(8) as *const __m256i);
        let mut d = _mm256_loadu_si256(base.add(12) as *const __m256i);
        p(&mut a, &mut b, &mut c, &mut d);
        _mm256_storeu_si256(base as *mut __m256i, a);
        _mm256_storeu_si256(base.add(4) as *mut __m256i, b);
        _mm256_storeu_si256(base.add(8) as *mut __m256i, c);
        _mm256_storeu_si256(base.add(12) as *mut __m256i, d);
    }

    // Columns: the pair at 16*i + 2*col for rows i = 0..8, two rows to a
    // register. The highest offset is 16*7 + 14, plus two words, so 128.
    for col in 0..8 {
        let pair = |i: usize| qp.add(16 * i + 2 * col);
        let load = |lo: usize, hi: usize| {
            _mm256_set_m128i(
                _mm_loadu_si128(pair(hi) as *const __m128i),
                _mm_loadu_si128(pair(lo) as *const __m128i),
            )
        };
        let mut a = load(0, 1);
        let mut b = load(2, 3);
        let mut c = load(4, 5);
        let mut d = load(6, 7);
        p(&mut a, &mut b, &mut c, &mut d);
        let store = |v: __m256i, lo: usize, hi: usize| {
            _mm_storeu_si128(pair(lo) as *mut __m128i, _mm256_castsi256_si128(v));
            _mm_storeu_si128(pair(hi) as *mut __m128i, _mm256_extracti128_si256::<1>(v));
        };
        store(a, 0, 1);
        store(b, 2, 3);
        store(c, 4, 5);
        store(d, 6, 7);
    }

    if xor {
        for ((o, a), b) in out.iter_mut().zip(q.iter()).zip(r.iter()) {
            *o ^= a ^ b;
        }
    } else {
        for ((o, a), b) in out.iter_mut().zip(q.iter()).zip(r.iter()) {
            *o = a ^ b;
        }
    }
}
