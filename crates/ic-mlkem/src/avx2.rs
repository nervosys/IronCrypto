//! The NTT, its inverse, base multiplication and reduction with AVX2, sixteen
//! coefficients to a register.
//!
//! # Bit for bit, not merely equivalent
//!
//! Every function here computes exactly the integers its scalar counterpart in
//! [`crate::poly`] does, in every coefficient, not just the same values modulo
//! `q`. Montgomery multiplication is the scalar one split into the halves of a
//! 32-bit product: the scalar form computes `t = low16(a * b) * q^-1` and then
//! `(a * b - t * q) >> 16`, and since the low halves of the two products are
//! equal by construction, that difference is exactly
//! `high16(a * b) - high16(t * q)` -- which is `vpmulhw` twice and a
//! subtraction. Barrett reduction rounds the way the scalar one does, by the
//! identity `floor((x + 2^25) / 2^26) = floor((floor(x / 2^16) + 2^9) / 2^10)`.
//! The butterflies are the scalar butterflies in the scalar order.
//!
//! That is what lets the tests demand equality with the portable code on every
//! input rather than agreement after normalisation, and it means the bounds
//! the scalar code relies on -- no coefficient overflowing sixteen bits -- hold
//! here for the same reasons.
//!
//! # The last three layers
//!
//! The NTT's first four layers pair whole registers. Its last three pair
//! coefficients eight, four and two apart, inside a register, so for those the
//! coefficients of two registers are shuffled so that the pairs line up across
//! them -- 128-bit halves exchanged, then 64-bit words interleaved, then
//! 32-bit words -- and shuffled back afterwards, so that the transform's output
//! is in the standard order and nothing outside this file knows any of it
//! happened. Each shuffle is its own inverse. The zetas each layer needs are
//! laid out to match, by `const fn`s below that read them from
//! [`crate::poly::ZETAS`] rather than restating them.
//!
//! # Safety
//!
//! Every function is `unsafe` because `#[target_feature]` requires it: the
//! caller must have established that the CPU supports AVX2, as
//! [`crate::poly`] does once through `avx2()`. The loads and stores are
//! unaligned and stay within the 256-coefficient arrays the references point
//! to: every offset is `16 * r` for `r < 16`.
//!
//! # Constant time
//!
//! No branch and no memory index here depends on a coefficient. The
//! multiplications, additions, shifts and shuffles are single instructions
//! whose timing does not depend on their operands.

use core::arch::x86_64::*;

use crate::poly::{N, Q, ZETAS};

/// `q^-1 mod 2^16`, as the scalar `montgomery_reduce` uses it.
const QINV: i16 = -3327;
/// `floor(2^26 / q)`, computed by the expression the scalar `barrett_reduce`
/// uses rather than restated. (It is 20158; writing 20159, `round(2^26 / q)`,
/// gives a reduction that is still correct modulo `q` and differs from the
/// scalar one at 1 in 3329 inputs, which the exhaustive test here found.)
const BARRETT_V: i16 = ((1i32 << 26) / Q as i32) as i16;
/// `2^16 * 2^-7 mod q`: the inverse transform's scaling, in Montgomery form.
const INV_SCALE: i16 = 1441;

/// `x * q^-1 mod 2^16`, the companion constant a Montgomery multiplication
/// by `x` needs.
const fn qinv_of(x: i16) -> i16 {
    (x as i32).wrapping_mul(QINV as i32) as i16
}

/// A table of sixteen-lane registers and their Montgomery companions.
type Table<const R: usize> = ([[i16; 16]; R], [[i16; 16]; R]);

const fn with_qinv<const R: usize>(z: [[i16; 16]; R]) -> Table<R> {
    let mut q = [[0i16; 16]; R];
    let mut r = 0;
    while r < R {
        let mut l = 0;
        while l < 16 {
            q[r][l] = qinv_of(z[r][l]);
            l += 1;
        }
        r += 1;
    }
    (z, q)
}

/// Zetas for the layer pairing coefficients eight apart, in the order the
/// shuffled registers hold them: register `p` covers coefficients
/// `32p..32p + 32`, whose two groups of sixteen take `zeta(base + 2p)` and
/// `zeta(base + 2p + 1)`, one per 128-bit half. `step` is +1 for the forward
/// transform's increasing zeta index and -1 for the inverse's decreasing one.
const fn layer8(base: usize, step: isize) -> Table<8> {
    let mut z = [[0i16; 16]; 8];
    let mut p = 0;
    while p < 8 {
        let mut l = 0;
        while l < 16 {
            let g = 2 * p + l / 8;
            z[p][l] = ZETAS[(base as isize + step * g as isize) as usize];
            l += 1;
        }
        p += 1;
    }
    with_qinv(z)
}

/// Zetas for the layer pairing coefficients four apart: one per 64-bit word,
/// the four groups of eight in a 32-coefficient block in order.
const fn layer4(base: usize, step: isize) -> Table<8> {
    let mut z = [[0i16; 16]; 8];
    let mut p = 0;
    while p < 8 {
        let mut l = 0;
        while l < 16 {
            let g = 4 * p + l / 4;
            z[p][l] = ZETAS[(base as isize + step * g as isize) as usize];
            l += 1;
        }
        p += 1;
    }
    with_qinv(z)
}

/// Zetas for the layer pairing coefficients two apart: one per 32-bit word,
/// the eight groups of four in a 32-coefficient block in order.
const fn layer2(base: usize, step: isize) -> Table<8> {
    let mut z = [[0i16; 16]; 8];
    let mut p = 0;
    while p < 8 {
        let mut l = 0;
        while l < 16 {
            let g = 8 * p + l / 2;
            z[p][l] = ZETAS[(base as isize + step * g as isize) as usize];
            l += 1;
        }
        p += 1;
    }
    with_qinv(z)
}

/// Zetas for base multiplication, in the even lanes: the pair starting at
/// coefficient `4i` takes `zeta(64 + i)` and the pair at `4i + 2` its
/// negation. The odd lanes are unused.
const fn basemul_zetas() -> Table<16> {
    let mut z = [[0i16; 16]; 16];
    let mut v = 0;
    while v < 16 {
        let mut l = 0;
        while l < 16 {
            let i = 4 * v + l / 4;
            z[v][l] = match l % 4 {
                0 => ZETAS[64 + i],
                2 => -ZETAS[64 + i],
                _ => 0,
            };
            l += 1;
        }
        v += 1;
    }
    with_qinv(z)
}

const NTT_8: Table<8> = layer8(16, 1);
const NTT_4: Table<8> = layer4(32, 1);
const NTT_2: Table<8> = layer2(64, 1);
const INV_2: Table<8> = layer2(127, -1);
const INV_4: Table<8> = layer4(63, -1);
const INV_8: Table<8> = layer8(31, -1);
const BASEMUL: Table<16> = basemul_zetas();

/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. `r`
/// must be below 16, so the sixteen coefficients accessed lie inside `c`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn load(c: &[i16; N], r: usize) -> __m256i {
    // SAFETY: `r < 16`, so `16 * r + 16 <= N`; the load is unaligned.
    unsafe { _mm256_loadu_si256(c.as_ptr().add(16 * r).cast()) }
}

/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. `r`
/// must be below 16, so the sixteen coefficients accessed lie inside `c`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn store(c: &mut [i16; N], r: usize, v: __m256i) {
    // SAFETY: as for `load`.
    unsafe { _mm256_storeu_si256(c.as_mut_ptr().add(16 * r).cast(), v) }
}

/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. `t`
/// is sixteen lanes, read whole by the unaligned load.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn row(t: &[i16; 16]) -> __m256i {
    // SAFETY: sixteen readable lanes; the load is unaligned.
    unsafe { _mm256_loadu_si256(t.as_ptr().cast()) }
}

/// Montgomery multiplication by a constant `z`, given `zq = z * q^-1`.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn fqmul_const(a: __m256i, z: __m256i, zq: __m256i) -> __m256i {
    let t = _mm256_mullo_epi16(a, zq);
    let hi = _mm256_mulhi_epi16(a, z);
    _mm256_sub_epi16(hi, _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q)))
}

/// Montgomery multiplication of two variables.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn fqmul(a: __m256i, b: __m256i) -> __m256i {
    let lo = _mm256_mullo_epi16(a, b);
    let hi = _mm256_mulhi_epi16(a, b);
    let t = _mm256_mullo_epi16(lo, _mm256_set1_epi16(QINV));
    _mm256_sub_epi16(hi, _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q)))
}

/// The scalar `barrett_reduce`, sixteen at a time.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn barrett(a: __m256i) -> __m256i {
    let h = _mm256_mulhi_epi16(a, _mm256_set1_epi16(BARRETT_V));
    let t = _mm256_srai_epi16::<10>(_mm256_add_epi16(h, _mm256_set1_epi16(512)));
    _mm256_sub_epi16(a, _mm256_mullo_epi16(t, _mm256_set1_epi16(Q)))
}

/// Cooley-Tukey: `t = zeta * hi; (lo + t, lo - t)`.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn ct(lo: &mut __m256i, hi: &mut __m256i, z: __m256i, zq: __m256i) {
    let t = fqmul_const(*hi, z, zq);
    *hi = _mm256_sub_epi16(*lo, t);
    *lo = _mm256_add_epi16(*lo, t);
}

/// Gentleman-Sande: `(barrett(lo + hi), zeta * (hi - lo))`.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn gs(lo: &mut __m256i, hi: &mut __m256i, z: __m256i, zq: __m256i) {
    let t = *lo;
    *lo = barrett(_mm256_add_epi16(t, *hi));
    *hi = fqmul_const(_mm256_sub_epi16(*hi, t), z, zq);
}

/// Exchange 128-bit halves: `(a, b) -> ([a.lo, b.lo], [a.hi, b.hi])`.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn swap128(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_permute2x128_si256::<0x20>(a, b),
        _mm256_permute2x128_si256::<0x31>(a, b),
    )
}

/// Interleave 64-bit words within each half.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn swap64(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    (_mm256_unpacklo_epi64(a, b), _mm256_unpackhi_epi64(a, b))
}

/// Interleave 32-bit words: `([a0, b0, a2, b2, ..], [a1, b1, a3, b3, ..])`.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn swap32(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    (
        _mm256_blend_epi32::<0xaa>(a, _mm256_slli_epi64::<32>(b)),
        _mm256_blend_epi32::<0xaa>(_mm256_srli_epi64::<32>(a), b),
    )
}

/// The forward NTT, `Poly::ntt`'s arithmetic, final reduction included.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn ntt(c: &mut [i16; N]) {
    let mut r = [_mm256_setzero_si256(); 16];
    for (i, v) in r.iter_mut().enumerate() {
        *v = load(c, i);
    }

    // len 128, 64, 32, 16: whole registers, `dist` apart, one zeta per group.
    let mut k = 1;
    for dist in [8usize, 4, 2, 1] {
        let mut start = 0;
        while start < 16 {
            let z = _mm256_set1_epi16(ZETAS[k]);
            let zq = _mm256_set1_epi16(qinv_of(ZETAS[k]));
            k += 1;
            for j in start..start + dist {
                let (lo, hi) = r.split_at_mut(j + dist);
                ct(&mut lo[j], &mut hi[0], z, zq);
            }
            start += 2 * dist;
        }
    }

    // len 8, 4, 2: within each pair of registers.
    for p in 0..8 {
        let (a, b) = swap128(r[2 * p], r[2 * p + 1]);
        let (mut a, mut b) = (a, b);
        ct(&mut a, &mut b, row(&NTT_8.0[p]), row(&NTT_8.1[p]));
        let (mut x, mut y) = swap64(a, b);
        ct(&mut x, &mut y, row(&NTT_4.0[p]), row(&NTT_4.1[p]));
        let (mut s, mut t) = swap32(x, y);
        ct(&mut s, &mut t, row(&NTT_2.0[p]), row(&NTT_2.1[p]));
        let (x, y) = swap32(s, t);
        let (a, b) = swap64(x, y);
        let (a, b) = swap128(a, b);
        store(c, 2 * p, barrett(a));
        store(c, 2 * p + 1, barrett(b));
    }
}

/// The inverse NTT, `Poly::inv_ntt`'s arithmetic, scaling included.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn inv_ntt(c: &mut [i16; N]) {
    let mut r = [_mm256_setzero_si256(); 16];

    // len 2, 4, 8, then 16: within each pair of registers.
    for p in 0..8 {
        let (a, b) = swap128(load(c, 2 * p), load(c, 2 * p + 1));
        let (x, y) = swap64(a, b);
        let (mut s, mut t) = swap32(x, y);
        gs(&mut s, &mut t, row(&INV_2.0[p]), row(&INV_2.1[p]));
        let (mut x, mut y) = swap32(s, t);
        gs(&mut x, &mut y, row(&INV_4.0[p]), row(&INV_4.1[p]));
        let (mut a, mut b) = swap64(x, y);
        gs(&mut a, &mut b, row(&INV_8.0[p]), row(&INV_8.1[p]));
        let (mut a, mut b) = swap128(a, b);
        let z = ZETAS[15 - p];
        gs(
            &mut a,
            &mut b,
            _mm256_set1_epi16(z),
            _mm256_set1_epi16(qinv_of(z)),
        );
        r[2 * p] = a;
        r[2 * p + 1] = b;
    }

    // len 32, 64, 128: whole registers.
    let mut k = 7usize;
    for dist in [2usize, 4, 8] {
        let mut start = 0;
        while start < 16 {
            let z = _mm256_set1_epi16(ZETAS[k]);
            let zq = _mm256_set1_epi16(qinv_of(ZETAS[k]));
            k = k.wrapping_sub(1);
            for j in start..start + dist {
                let (lo, hi) = r.split_at_mut(j + dist);
                gs(&mut lo[j], &mut hi[0], z, zq);
            }
            start += 2 * dist;
        }
    }

    let f = _mm256_set1_epi16(INV_SCALE);
    let fq = _mm256_set1_epi16(qinv_of(INV_SCALE));
    for (i, v) in r.iter().enumerate() {
        store(c, i, fqmul_const(*v, f, fq));
    }
}

/// Swap the two sixteen-bit halves of every 32-bit word.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn swap_pairs(a: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32::<16>(a), _mm256_srli_epi32::<16>(a))
}

/// `acc += a o b`: `Poly::basemul_add`.
///
/// For each pair `(a0, a1)`, `(b0, b1)` with its `zeta`:
/// `out0 = fqmul(fqmul(a1, b1), zeta) + fqmul(a0, b0)` and
/// `out1 = fqmul(a0, b1) + fqmul(a1, b0)`, the scalar expressions. A
/// lane-wise product puts `a0 b0` in the even lanes and `a1 b1` in the odd;
/// against `b` with its halves swapped it puts `a0 b1` and `a1 b0` there.
/// Swapping halves again lines each sum's terms up.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn basemul_add(acc: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for v in 0..16 {
        let x = load(a, v);
        let y = load(b, v);
        let same = fqmul(x, y);
        let cross = fqmul(x, swap_pairs(y));
        let twisted = fqmul_const(swap_pairs(same), row(&BASEMUL.0[v]), row(&BASEMUL.1[v]));
        let even = _mm256_add_epi16(twisted, same);
        let odd = _mm256_add_epi16(cross, swap_pairs(cross));
        let product = _mm256_blend_epi16::<0xaa>(even, odd);
        store(acc, v, _mm256_add_epi16(load(acc, v), product));
    }
}

/// `Compress_d` of every coefficient, by the scalar `compress`'s arithmetic,
/// eight coefficients to a register.
///
/// The scalar function is `t = (x << d) + q/2`, an estimate
/// `e = ((t >> 8) * 40318) >> 19` of `t / q` that is exact or one short, and a
/// correction adding one when `t - e q` reached `q`, taken from the sign bit
/// of `(q - 1) - (t - e q)`. Those are the operations here, in 32-bit lanes:
/// no division, and no branch for the correction. `x` is expected in
/// `[0, q)`, as it is for the scalar function; the tests compare the two at
/// every such `x` for every width ML-KEM uses.
///
/// The scalar function hides its correction behind `black_box` so that no
/// compiler turns it into a branch on Cortex-M0. That is not a risk here:
/// these are vector instructions, and there is no vector branch.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn compress(c: &[i16; N], d: u32, out: &mut [i16; N]) {
    let count = _mm_cvtsi32_si128(d as i32);
    let mask = _mm256_set1_epi32(((1u32 << d) - 1) as i32);
    for v in 0..16 {
        let x = load(c, v);
        let lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(x));
        let hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256::<1>(x));
        // `packus` works within 128-bit halves, leaving the 64-bit words in
        // the order lo[0..4], hi[0..4], lo[4..8], hi[4..8]; restore it.
        let packed = _mm256_packus_epi32(compress8(lo, count, mask), compress8(hi, count, mask));
        store(out, v, _mm256_permute4x64_epi64::<0xd8>(packed));
    }
}

/// [`compress`] for eight coefficients in 32-bit lanes.
///
/// # Safety
///
/// The CPU must have AVX2, which `poly::avx2()` establishes before every call. These
/// touch no memory; they are register arithmetic on their arguments.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn compress8(x: __m256i, count: __m128i, mask: __m256i) -> __m256i {
    let q = _mm256_set1_epi32(Q as i32);
    let t = _mm256_add_epi32(_mm256_sll_epi32(x, count), _mm256_set1_epi32(Q as i32 / 2));
    let e = _mm256_srli_epi32::<19>(_mm256_mullo_epi32(
        _mm256_srli_epi32::<8>(t),
        _mm256_set1_epi32(40318),
    ));
    let r = _mm256_sub_epi32(t, _mm256_mullo_epi32(e, q));
    let below = _mm256_sub_epi32(_mm256_set1_epi32(Q as i32 - 1), r);
    let e = _mm256_add_epi32(e, _mm256_srli_epi32::<31>(below));
    _mm256_and_si256(e, mask)
}

/// For each eight-bit mask, the `pshufb` pattern that moves the sixteen-bit
/// lanes whose bits are set to the front, in order.
const fn compaction_table() -> [[u8; 16]; 256] {
    let mut t = [[0xffu8; 16]; 256];
    let mut m = 0;
    while m < 256 {
        let mut at = 0;
        let mut lane = 0;
        while lane < 8 {
            if (m >> lane) & 1 == 1 {
                t[m][at] = 2 * lane as u8;
                t[m][at + 1] = 2 * lane as u8 + 1;
                at += 2;
            }
            lane += 1;
        }
        m += 1;
    }
    t
}

static COMPACTION: [[u8; 16]; 256] = compaction_table();

/// Byte pattern that spreads 24 bytes, held as bytes 0..16 in the low half
/// and 8..24 in the high, into sixteen sixteen-bit words each holding one
/// twelve-bit candidate: candidate `2k` in bytes `3k, 3k+1` and `2k + 1` in
/// `3k + 1, 3k + 2`.
const SPREAD: [i8; 32] = [
    0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, //
    4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15,
];

/// The rejection step of `SampleNTT`, sixteen candidates at a time:
/// `crate::sample::rej_uniform`'s result, from the same bytes.
///
/// Candidates below `q` are moved to the front of each half-register by a
/// shuffle looked up from the comparison's mask, and stored at the end of
/// what has been accepted so far. The lookup is indexed by which candidates
/// were accepted, and that depends only on the public seed `rho`; this
/// function never sees a secret. Whatever is left over -- the last few
/// coefficients, or a tail of the buffer shorter than 24 bytes -- goes
/// through the scalar function.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn rej_uniform(out: &mut [i16; N], mut filled: usize, buf: &[u8]) -> usize {
    let spread = _mm256_loadu_si256(SPREAD.as_ptr().cast());
    let twelve = _mm256_set1_epi16(0x0fff);
    let q = _mm256_set1_epi16(Q);
    let mut pos = 0;
    // Two stores of up to eight lanes each must fit below `N`.
    while filled + 16 <= N && pos + 24 <= buf.len() {
        // SAFETY: `pos + 24 <= buf.len()`, so both sixteen-byte loads, at
        // `pos` and `pos + 8`, are in bounds; they are unaligned.
        let (lo, hi) = unsafe {
            (
                _mm_loadu_si128(buf.as_ptr().add(pos).cast()),
                _mm_loadu_si128(buf.as_ptr().add(pos + 8).cast()),
            )
        };
        let f = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(lo), hi);
        let f = _mm256_shuffle_epi8(f, spread);
        // Even words take their low twelve bits; odd words the twelve above
        // the low four.
        let f = _mm256_blend_epi16::<0xaa>(f, _mm256_srli_epi16::<4>(f));
        let f = _mm256_and_si256(f, twelve);
        let good = _mm256_cmpgt_epi16(q, f);
        let bits = _mm256_movemask_epi8(_mm256_packs_epi16(good, good)) as u32;
        for (half, m) in [
            (_mm256_castsi256_si128(f), bits & 0xff),
            (_mm256_extracti128_si256::<1>(f), (bits >> 16) & 0xff),
        ] {
            let pattern = _mm_loadu_si128(COMPACTION[m as usize].as_ptr().cast());
            // SAFETY: `filled + 8 <= N` here, since `filled` started this
            // iteration at most `N - 16` and the first half added at most 8;
            // the store writes eight lanes from `filled`, unaligned.
            unsafe {
                _mm_storeu_si128(
                    out.as_mut_ptr().add(filled).cast(),
                    _mm_shuffle_epi8(half, pattern),
                )
            };
            filled += m.count_ones() as usize;
        }
        pos += 24;
    }
    crate::sample::rej_uniform_scalar(out, filled, &buf[pos..])
}

/// Sixteen twelve-bit fields from 24 bytes, at `pos`.
///
/// # Safety
///
/// The CPU must support AVX2, and `pos + 24 <= bytes.len()`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn twelve_bit_fields(bytes: &[u8], pos: usize) -> __m256i {
    debug_assert!(pos + 24 <= bytes.len());
    // SAFETY: the caller keeps `pos + 24` within `bytes`, so both
    // sixteen-byte loads, at `pos` and `pos + 8`, are in bounds.
    let (lo, hi) = unsafe {
        (
            _mm_loadu_si128(bytes.as_ptr().add(pos).cast()),
            _mm_loadu_si128(bytes.as_ptr().add(pos + 8).cast()),
        )
    };
    let f = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(lo), hi);
    let f = _mm256_shuffle_epi8(f, _mm256_loadu_si256(SPREAD.as_ptr().cast()));
    // Even words take their low twelve bits; odd words the twelve above the
    // low four.
    let f = _mm256_blend_epi16::<0xaa>(f, _mm256_srli_epi16::<4>(f));
    _mm256_and_si256(f, _mm256_set1_epi16(0x0fff))
}

/// `ByteDecode_12`, with the reduction modulo `q`: `byte_decode(.., 12, ..)`
/// coefficient for coefficient, the reduction being the scalar
/// `reduce_12`'s subtraction and sign mask.
///
/// Constant time: a decapsulation key's secret vector comes through here.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn decode12(bytes: &[u8; 384], out: &mut [i16; N]) {
    let q = _mm256_set1_epi16(Q);
    for v in 0..16 {
        let f = twelve_bit_fields(bytes, 24 * v);
        let r = _mm256_sub_epi16(f, q);
        let r = _mm256_add_epi16(r, _mm256_and_si256(_mm256_srai_epi16::<15>(r), q));
        store(out, v, r);
    }
}

/// Whether every twelve-bit field of `bytes` is below `q`, for the
/// encapsulation key's modulus check. `bytes.len()` must be a multiple of 24;
/// otherwise this answers `false`.
///
/// The key is public, so the single branch at the end, on the answer, reveals
/// nothing; the loop itself does not stop early.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn all_below_q_12(bytes: &[u8]) -> bool {
    if !bytes.len().is_multiple_of(24) {
        return false;
    }
    let limit = _mm256_set1_epi16(Q - 1);
    let mut over = _mm256_setzero_si256();
    for pos in (0..bytes.len()).step_by(24) {
        let f = twelve_bit_fields(bytes, pos);
        over = _mm256_or_si256(over, _mm256_cmpgt_epi16(f, limit));
    }
    _mm256_testz_si256(over, over) == 1
}

/// `SamplePolyCBD_2` of 128 bytes: `sample_poly_cbd(2, ..)` coefficient for
/// coefficient.
///
/// Each byte holds two coefficients: the low nibble's two bit-counts give
/// coefficient `2j`, the high nibble's give `2j + 1`. The counts are formed
/// for every byte at once by adding the word to itself shifted, as the
/// scalar `cbd2` does for a 32-bit word, the differences taken per byte, and
/// the bytes interleaved and widened to sixteen bits in order.
///
/// Constant time: these are secret bits, and nothing here branches or
/// indexes memory on them.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn cbd2(bytes: &[u8; 128], out: &mut [i16; N]) {
    let m55 = _mm_set1_epi8(0x55);
    let m03 = _mm_set1_epi8(0x03);
    for chunk in 0..8 {
        // SAFETY: `16 * chunk + 16 <= 128`; the load is unaligned.
        let w = unsafe { _mm_loadu_si128(bytes.as_ptr().add(16 * chunk).cast()) };
        // Two-bit fields holding the sums of adjacent bit pairs.
        let d = _mm_add_epi8(
            _mm_and_si128(w, m55),
            _mm_and_si128(_mm_srli_epi16::<1>(w), m55),
        );
        // The four fields of each byte. Shifting sixteen-bit words moves the
        // next byte's low bits into this byte's top, which the mask drops.
        let f0 = _mm_and_si128(d, m03);
        let f1 = _mm_and_si128(_mm_srli_epi16::<2>(d), m03);
        let f2 = _mm_and_si128(_mm_srli_epi16::<4>(d), m03);
        let f3 = _mm_and_si128(_mm_srli_epi16::<6>(d), m03);
        let lo = _mm_sub_epi8(f0, f1);
        let hi = _mm_sub_epi8(f2, f3);
        let first = _mm256_cvtepi8_epi16(_mm_unpacklo_epi8(lo, hi));
        let second = _mm256_cvtepi8_epi16(_mm_unpackhi_epi8(lo, hi));
        store(out, 2 * chunk, first);
        store(out, 2 * chunk + 1, second);
    }
}

/// `Poly::normalize`: Barrett-reduce, then add `q` where the result is
/// negative, the sign taken by an arithmetic shift rather than a comparison.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn normalize(c: &mut [i16; N]) {
    let q = _mm256_set1_epi16(Q);
    for v in 0..16 {
        let x = barrett(load(c, v));
        let fix = _mm256_and_si256(_mm256_srai_epi16::<15>(x), q);
        store(c, v, _mm256_add_epi16(x, fix));
    }
}

/// `Poly::to_mont`: Montgomery multiplication by `2^32 mod q`.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn to_mont(c: &mut [i16; N]) {
    // 1353 = 2^32 mod q, as the scalar `to_mont` uses.
    const R2: i16 = 1353;
    let z = _mm256_set1_epi16(R2);
    let zq = _mm256_set1_epi16(qinv_of(R2));
    for v in 0..16 {
        store(c, v, fqmul_const(load(c, v), z, zq));
    }
}

/// `Poly::add_assign`: `a += b`, coefficient by coefficient.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn add_assign(a: &mut [i16; N], b: &[i16; N]) {
    for v in 0..16 {
        store(a, v, _mm256_add_epi16(load(a, v), load(b, v)));
    }
}

/// `Poly::reduce`: Barrett-reduce every coefficient.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn reduce(c: &mut [i16; N]) {
    for v in 0..16 {
        store(c, v, barrett(load(c, v)));
    }
}
