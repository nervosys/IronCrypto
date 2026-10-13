//! Four elements of GF(2^255 - 19) at once, on AVX-512 IFMA, and the
//! Edwards-curve operations built on them.
//!
//! # Why
//!
//! The four-limb field in `fe64.rs` is latency-bound inside a point
//! operation: each multiplication is one long carry chain, and a doubling's
//! squarings and multiplications wait on one another. An Edwards point is
//! four coordinates, and its formulas multiply them four at a time -- a
//! doubling is four squarings and then four multiplications, a mixed
//! addition two rounds of four multiplications -- so on a CPU with
//! `VPMADD52LUQ`/`VPMADD52HUQ` (IFMA), which multiply 52-bit limbs in each of
//! four 64-bit lanes, a point operation is two vector multiplications. This
//! is the layout curve25519-dalek's IFMA backend uses, written here
//! independently.
//!
//! # Representation
//!
//! A lane holds an element as five limbs of radix 2^51 (limb `i` weighs
//! `2^(51 i)`). IFMA reads only the low 52 bits of each operand, so every
//! input to a multiplication has limbs below 2^52; that is what [`reduce`]
//! leaves, and every operation here ends with it.
//!
//! The bounds, for inputs with limbs below 2^52: a limb product is below
//! 2^104, split by IFMA into 52-bit low and high halves. Column `k` of the
//! product takes the low halves of the products with `i + j = k` and twice
//! the high halves of those with `i + j = k - 1` (the high half weighs
//! `2^52 = 2 * 2^51` above its column): at most `5 * 2^52 + 10 * 2^52 < 2^56`.
//! Columns 5 to 9 fold onto 0 to 4 times 19 (`2^255 = 19`): below `20 * 2^56
//! < 2^60.4`. One parallel carry pass then leaves limbs below `2^51 + 2^10`,
//! and limb 0 below `2^51 + 19 * 2^10`: under 2^52.
//!
//! Subtraction adds `16p` first, whose limbs are about 2^55, so nothing goes
//! negative for inputs below 2^53.
//!
//! # Constant time
//!
//! Every operation is a fixed sequence of vector instructions, with no
//! branch and no data-dependent address; lane selection is by permutes and
//! blends with constant immediates or by masks. The constant-time table
//! selection blends every entry under a mask.
//!
//! # Toolchain
//!
//! The crate's declared minimum Rust predates the stabilisation of the
//! AVX-512 intrinsics and target features, so the two IFMA instructions are
//! each a one-instruction assembly block on `ymm` registers, the rest are
//! AVX2 intrinsics, and support is detected by CPUID and XGETBV here rather
//! than through `is_x86_feature_detected!`.

// Limb loops index five arrays in step, as the algebra does.
#![allow(clippy::needless_range_loop)]
// The Edwards operations serve the `std` tables' paths and the probes; a
// `no_std` build uses only X25519's ladder from here.
#![cfg_attr(not(any(feature = "std", feature = "ct-probes")), allow(dead_code))]

use core::arch::asm;
use core::arch::x86_64::*;

use crate::fe64::Fe64;

/// Proof that this CPU runs IFMA on 256-bit vectors, and that the operating
/// system saves the AVX-512 state, so the instructions will not fault.
///
/// Only [`Ifma::get`] makes one. Every operation takes one, which is what
/// makes them safe to call: the unsafe code behind them is reachable only
/// with a token in hand.
#[derive(Clone, Copy)]
pub struct Ifma(());

impl Ifma {
    /// The token, if this CPU and OS support what the code here needs:
    /// AVX2, AVX-512F, AVX-512DQ, AVX-512VL and AVX-512 IFMA, with the OS
    /// saving the
    /// SSE, AVX and AVX-512 register state; and BMI2 and ADX, for the
    /// four-limb field the conversions here use.
    #[inline]
    pub fn get() -> Option<Ifma> {
        use core::sync::atomic::{AtomicU8, Ordering};
        // 0 not yet asked, 1 yes, 2 no.
        static CACHED: AtomicU8 = AtomicU8::new(0);
        let have = match CACHED.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                let have = detect() && crate::fe64::available();
                CACHED.store(if have { 1 } else { 2 }, Ordering::Relaxed);
                have
            }
        };
        if have {
            Some(Ifma(()))
        } else {
            None
        }
    }
}

/// `cpuid` with `eax = leaf`, `ecx = sub`: `(eax, ebx, ecx, edx)`.
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d): (u32, u64, u32, u32);
    // SAFETY: CPUID exists on every x86-64 CPU and has no effect beyond its
    // four output registers. LLVM reserves rbx, so it is saved in another
    // register around the instruction and swapped back.
    unsafe {
        asm!(
            "mov {b}, rbx",
            "cpuid",
            "xchg {b}, rbx",
            b = out(reg) b,
            inout("eax") leaf => a,
            inout("ecx") sub => c,
            out("edx") d,
            options(nostack, preserves_flags, nomem),
        );
    }
    (a, b as u32, c, d)
}

fn detect() -> bool {
    let (max, _, _, _) = cpuid(0, 0);
    if max < 7 {
        return false;
    }
    let (_, _, ecx1, _) = cpuid(1, 0);
    // OSXSAVE (27) and AVX (28).
    if ecx1 & (1 << 27) == 0 || ecx1 & (1 << 28) == 0 {
        return false;
    }
    let xcr0: u64 = {
        let (lo, hi): (u32, u32);
        // SAFETY: XGETBV with ecx = 0 is available when OSXSAVE is set,
        // which was just checked; it reads XCR0 into edx:eax and nothing
        // else.
        unsafe {
            asm!(
                "xgetbv",
                in("ecx") 0u32,
                out("eax") lo,
                out("edx") hi,
                options(nostack, preserves_flags, nomem),
            );
        }
        (u64::from(hi) << 32) | u64::from(lo)
    };
    // SSE (1), AVX (2), and AVX-512's opmask (5), ZMM_Hi256 (6) and
    // Hi16_ZMM (7) state: without them EVEX instructions fault.
    let needed = 0b1110_0110;
    if xcr0 & needed != needed {
        return false;
    }
    let (_, ebx7, _, _) = cpuid(7, 0);
    // AVX2 (5), AVX-512F (16), AVX-512DQ (17), AVX-512 IFMA (21),
    // AVX-512VL (31).
    let want = (1 << 5) | (1 << 16) | (1 << 17) | (1 << 21) | (1 << 31);
    ebx7 & want == want
}

/// Five limb vectors; lane `l` of vector `i` is limb `i` of element `l`.
#[derive(Clone, Copy)]
pub struct F4([__m256i; 5]);

/// An Edwards point `(X : Y : Z : T)`, one coordinate per lane in that
/// order.
#[derive(Clone, Copy)]
pub struct P4(F4);

/// The operand of an addition, `(Y - X, Y + X, 2d T, 2 Z)` of the point
/// being added, one per lane in that order: what the formula multiplies the
/// accumulator's `(Y - X, Y + X, T, Z)` by.
#[derive(Clone, Copy)]
pub struct N4(F4);

const M51: i64 = (1 << 51) - 1;

/// `16p` in radix 2^51: added before a subtraction so no limb goes negative.
const P16_0: i64 = 16 * ((1 << 51) - 19);
const P16_I: i64 = 16 * ((1 << 51) - 1);

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn madd52lo(acc: __m256i, a: __m256i, b: __m256i) -> __m256i {
    let mut r = acc;
    asm!(
        "vpmadd52luq {r}, {a}, {b}",
        r = inout(ymm_reg) r,
        a = in(ymm_reg) a,
        b = in(ymm_reg) b,
        options(pure, nomem, nostack, preserves_flags),
    );
    r
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn madd52hi(acc: __m256i, a: __m256i, b: __m256i) -> __m256i {
    let mut r = acc;
    asm!(
        "vpmadd52huq {r}, {a}, {b}",
        r = inout(ymm_reg) r,
        a = in(ymm_reg) a,
        b = in(ymm_reg) b,
        options(pure, nomem, nostack, preserves_flags),
    );
    r
}

/// `19 x`, lane-wise: one `VPMULLQ` (AVX-512DQ).
///
/// In assembly: as intrinsics `16 x + 2 x + x` is four instructions, and
/// LLVM, recognising the multiplication, made it AVX2's 32-bit multiplies
/// instead, three of them and their shifts per 64-bit lane.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn times19(x: __m256i) -> __m256i {
    let r: __m256i;
    asm!(
        "vpmullq {r}, {x}, {k}",
        x = in(ymm_reg) x,
        k = in(ymm_reg) _mm256_set1_epi64x(19),
        r = lateout(ymm_reg) r,
        options(pure, nomem, nostack, preserves_flags),
    );
    r
}

/// One parallel carry pass: limbs below 2^64 in, below 2^52 out.
///
/// Each limb keeps its low 51 bits and receives the carry from the limb
/// below; limb 0 receives 19 times the carry off the top. For inputs below
/// 2^60.4, as every caller here gives, a carry is below 2^9.4 and the
/// results are below `2^51 + 19 * 2^9.4 < 2^52`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn reduce(z: [__m256i; 5]) -> F4 {
    let m = _mm256_set1_epi64x(M51);
    let c0 = _mm256_srli_epi64::<51>(z[0]);
    let c1 = _mm256_srli_epi64::<51>(z[1]);
    let c2 = _mm256_srli_epi64::<51>(z[2]);
    let c3 = _mm256_srli_epi64::<51>(z[3]);
    let c4 = _mm256_srli_epi64::<51>(z[4]);
    F4([
        _mm256_add_epi64(_mm256_and_si256(z[0], m), times19(c4)),
        _mm256_add_epi64(_mm256_and_si256(z[1], m), c0),
        _mm256_add_epi64(_mm256_and_si256(z[2], m), c1),
        _mm256_add_epi64(_mm256_and_si256(z[3], m), c2),
        _mm256_add_epi64(_mm256_and_si256(z[4], m), c3),
    ])
}

/// Lane-wise `a * b`, as an expression, for use inside a function compiled
/// with AVX2.
///
/// A macro rather than a function because it must be inlined into the point
/// operations: LLVM judges it too large to inline, `#[inline(always)]`
/// cannot be combined with `#[target_feature]`, and as a call it passed five
/// vectors in and out through memory, which cost as much as the arithmetic.
macro_rules! mul4 {
    ($a:expr, $b:expr) => {{
        let a: &[__m256i; 5] = &($a).0;
        let b: &[__m256i; 5] = &($b).0;
        let zero = _mm256_setzero_si256();
        let mut lo = [zero; 9];
        let mut hi = [zero; 9];
        // Written out: the indices are all constants, which keeps every
        // accumulator in a register.
        macro_rules! row {
            ($i:literal) => {
                lo[$i] = madd52lo(lo[$i], a[$i], b[0]);
                hi[$i] = madd52hi(hi[$i], a[$i], b[0]);
                lo[$i + 1] = madd52lo(lo[$i + 1], a[$i], b[1]);
                hi[$i + 1] = madd52hi(hi[$i + 1], a[$i], b[1]);
                lo[$i + 2] = madd52lo(lo[$i + 2], a[$i], b[2]);
                hi[$i + 2] = madd52hi(hi[$i + 2], a[$i], b[2]);
                lo[$i + 3] = madd52lo(lo[$i + 3], a[$i], b[3]);
                hi[$i + 3] = madd52hi(hi[$i + 3], a[$i], b[3]);
                lo[$i + 4] = madd52lo(lo[$i + 4], a[$i], b[4]);
                hi[$i + 4] = madd52hi(hi[$i + 4], a[$i], b[4]);
            };
        }
        row!(0);
        row!(1);
        row!(2);
        row!(3);
        row!(4);
        finish(&lo, &hi)
    }};
}

/// Lane-wise `a^2`, as an expression: the ten products off the diagonal
/// once, doubled by doubling their accumulators, and the five on it. A macro
/// for the reason [`mul4!`] is.
macro_rules! square4 {
    ($a:expr) => {{
        let a: &[__m256i; 5] = &($a).0;
        let zero = _mm256_setzero_si256();
        let mut lo = [zero; 9];
        let mut hi = [zero; 9];
        macro_rules! off {
            ($i:literal, $j:literal) => {
                lo[$i + $j] = madd52lo(lo[$i + $j], a[$i], a[$j]);
                hi[$i + $j] = madd52hi(hi[$i + $j], a[$i], a[$j]);
            };
        }
        off!(0, 1);
        off!(0, 2);
        off!(0, 3);
        off!(0, 4);
        off!(1, 2);
        off!(1, 3);
        off!(1, 4);
        off!(2, 3);
        off!(2, 4);
        off!(3, 4);
        for k in 0..9 {
            lo[k] = _mm256_add_epi64(lo[k], lo[k]);
            hi[k] = _mm256_add_epi64(hi[k], hi[k]);
        }
        off!(0, 0);
        off!(1, 1);
        off!(2, 2);
        off!(3, 3);
        off!(4, 4);
        finish(&lo, &hi)
    }};
}

/// Lane-wise `a * b`.
#[cfg(test)]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul(a: &F4, b: &F4) -> F4 {
    mul4!(a, b)
}

/// Lane-wise `a^2`.
#[cfg(test)]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn square(a: &F4) -> F4 {
    square4!(a)
}

/// Columns from the low and high halves, folded and carried.
///
/// `lo[k]` weighs `2^(51 k)` and `hi[k]` weighs `2^(51 k + 52)`, which is
/// twice `2^(51 (k + 1))`. A squaring's columns are at most what a
/// multiplication's are, so the bounds in the module note hold for both.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn finish(lo: &[__m256i; 9], hi: &[__m256i; 9]) -> F4 {
    let mut t = [_mm256_setzero_si256(); 10];
    t[0] = lo[0];
    for k in 1..9 {
        t[k] = _mm256_add_epi64(lo[k], _mm256_add_epi64(hi[k - 1], hi[k - 1]));
    }
    t[9] = _mm256_add_epi64(hi[8], hi[8]);
    reduce([
        _mm256_add_epi64(t[0], times19(t[5])),
        _mm256_add_epi64(t[1], times19(t[6])),
        _mm256_add_epi64(t[2], times19(t[7])),
        _mm256_add_epi64(t[3], times19(t[8])),
        _mm256_add_epi64(t[4], times19(t[9])),
    ])
}

/// Lane-wise `a + b`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn add(a: &F4, b: &F4) -> F4 {
    reduce(add_raw(&a.0, &b.0))
}

/// Lane-wise limb sums, unreduced.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn add_raw(a: &[__m256i; 5], b: &[__m256i; 5]) -> [__m256i; 5] {
    let mut r = *a;
    for i in 0..5 {
        r[i] = _mm256_add_epi64(a[i], b[i]);
    }
    r
}

/// `16p - b`, lane-wise, unreduced: limbs below 2^56 for `b` below 2^53.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn neg16(b: &F4) -> [__m256i; 5] {
    let p0 = _mm256_set1_epi64x(P16_0);
    let pi = _mm256_set1_epi64x(P16_I);
    [
        _mm256_sub_epi64(p0, b.0[0]),
        _mm256_sub_epi64(pi, b.0[1]),
        _mm256_sub_epi64(pi, b.0[2]),
        _mm256_sub_epi64(pi, b.0[3]),
        _mm256_sub_epi64(pi, b.0[4]),
    ]
}

/// `b`, negated in the lanes whose bit is set in `LANES` (bit `l` for lane
/// `l`), unreduced.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn negate_lanes<const DWORDS: i32>(b: &F4) -> [__m256i; 5] {
    let mut n = neg16(b);
    for i in 0..5 {
        n[i] = _mm256_blend_epi32::<DWORDS>(b.0[i], n[i]);
    }
    n
}

/// The dword blend mask selecting 64-bit lanes `l` where bit `l` is set.
const fn lanes(bits: i32) -> i32 {
    let mut m = 0;
    let mut l = 0;
    while l < 4 {
        if bits & (1 << l) != 0 {
            m |= 0b11 << (2 * l);
        }
        l += 1;
    }
    m
}

/// Every limb vector of `a` permuted by `IMM` (`_mm256_permute4x64_epi64`).
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn permute<const IMM: i32>(a: &F4) -> F4 {
    let mut r = a.0;
    for i in 0..5 {
        r[i] = _mm256_permute4x64_epi64::<IMM>(a.0[i]);
    }
    F4(r)
}

/// Lanes of `b` where `DWORDS` selects, of `a` elsewhere.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn blend<const DWORDS: i32>(a: &F4, b: &F4) -> F4 {
    let mut r = a.0;
    for i in 0..5 {
        r[i] = _mm256_blend_epi32::<DWORDS>(a.0[i], b.0[i]);
    }
    F4(r)
}

/// `_MM_SHUFFLE`-style immediate: lane 0 takes `l0`, and so on.
const fn sel(l0: i32, l1: i32, l2: i32, l3: i32) -> i32 {
    l0 | (l1 << 2) | (l2 << 4) | (l3 << 6)
}

/// From a completed point `(X : Y : Z : T)` standing for `(X/Z, Y/T)`, in
/// lanes, to extended coordinates: `(X T, Y Z, Z T, X Y)`.
macro_rules! completed_to_extended {
    ($c:expr) => {{
        let c: &F4 = $c;
        let l = permute::<{ sel(0, 1, 2, 0) }>(c); // (X, Y, Z, X)
        let r = permute::<{ sel(3, 2, 3, 1) }>(c); // (T, Z, T, Y)
        P4(mul4!(&l, &r))
    }};
}

#[target_feature(enable = "avx2")]
unsafe fn double_impl(p: &P4) -> P4 {
    let p = &p.0;
    // (X, Y, Z, X + Y).
    let u = permute::<{ sel(0, 1, 2, 0) }>(p);
    let w = permute::<{ sel(1, 1, 1, 1) }>(p);
    let w = blend::<{ lanes(0b1000) }>(&F4([_mm256_setzero_si256(); 5]), &w);
    let v = add(&u, &w);
    // (S1, S2, S3, S4) = (X^2, Y^2, Z^2, (X + Y)^2).
    let s = square4!(&v);
    // The completed point, `dbl-2008-hwcd` for a = -1, as
    // `ed25519::Projective::double` writes it:
    //   X' = S4 - S1 - S2    Y' = S1 + S2
    //   Z' = S2 - S1         T' = 2 S3 - S2 + S1
    // as (S4, S1, S2, 2 S3) + (-S1, S2, -S1, S1) + (-S2, 0, 0, -S2).
    let a = permute::<{ sel(3, 0, 1, 2) }>(&s);
    // Unreduced: the sum below is reduced once, and 2 S3 is below 2^53.
    let a = blend::<{ lanes(0b1000) }>(&a, &F4(add_raw(&a.0, &a.0)));
    let b = negate_lanes::<{ lanes(0b0101) }>(&permute::<{ sel(0, 1, 0, 0) }>(&s));
    let c = negate_lanes::<{ lanes(0b1001) }>(&permute::<{ sel(1, 1, 1, 1) }>(&s));
    let c = blend::<{ lanes(0b0110) }>(&F4(c), &F4([_mm256_setzero_si256(); 5]));
    let sum = reduce(add_raw(&add_raw(&a.0, &b), &c.0));
    completed_to_extended!(&sum)
}

#[target_feature(enable = "avx2")]
unsafe fn add_impl(p: &P4, n: &N4) -> P4 {
    let p = &p.0;
    // (Y - X, Y + X, T, Z).
    let u = permute::<{ sel(1, 1, 3, 2) }>(p);
    let x = permute::<{ sel(0, 0, 0, 0) }>(p);
    let x = blend::<{ lanes(0b1100) }>(&x, &F4([_mm256_setzero_si256(); 5]));
    let x = negate_lanes::<{ lanes(0b0001) }>(&x);
    let v = reduce(add_raw(&u.0, &x));
    // (MM, PP, TT, ZZ) = (Y - X, Y + X, T, Z) * (Y' - X', Y' + X', 2d T', 2 Z').
    let prod = mul4!(&v, &n.0);
    // The completed point, as `ed25519::Ext::add_niels` writes it:
    //   (PP - MM, PP + MM, ZZ + TT, ZZ - TT).
    let s1 = permute::<{ sel(1, 1, 3, 3) }>(&prod);
    let s2 = negate_lanes::<{ lanes(0b1001) }>(&permute::<{ sel(0, 0, 2, 2) }>(&prod));
    let c = reduce(add_raw(&s1.0, &s2));
    completed_to_extended!(&c)
}

#[target_feature(enable = "avx2")]
unsafe fn negate_operand_impl(n: &N4) -> N4 {
    // -(x, y) = (-x, y): Y - X and Y + X trade places, 2d T changes sign,
    // 2 Z stays.
    let swapped = permute::<{ sel(1, 0, 2, 3) }>(&n.0);
    N4(reduce(negate_lanes::<{ lanes(0b0100) }>(&swapped)))
}

#[target_feature(enable = "avx2")]
unsafe fn select_impl(table: &[N4; 8], digit: i8) -> N4 {
    // The sign and |digit|, without a branch.
    let negative = u64::from((digit as u8) >> 7);
    let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u64;
    // The identity's operand: (1, 1, 0, 2).
    let mut out = identity_operand();
    for (i, entry) in table.iter().enumerate() {
        let hit = (magnitude ^ (i as u64 + 1)).wrapping_sub(1) >> 63;
        let m = _mm256_set1_epi64x(crate::fe64::mask(hit) as i64);
        for k in 0..5 {
            out.0 .0[k] = _mm256_blendv_epi8(out.0 .0[k], entry.0 .0[k], m);
        }
    }
    let neg = negate_operand_impl(&out);
    let m = _mm256_set1_epi64x(crate::fe64::mask(negative) as i64);
    for k in 0..5 {
        out.0 .0[k] = _mm256_blendv_epi8(out.0 .0[k], neg.0 .0[k], m);
    }
    out
}

/// Lane-wise `121666 * e + d`, reduced.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mul121666_add(e: &F4, d: &F4) -> F4 {
    let k = _mm256_set1_epi64x(121_666);
    let zero = _mm256_setzero_si256();
    // e_i * 121666 is below 2^69: a low half at limb i, and a high half
    // below 2^17 that weighs twice limb i + 1.
    let mut lo = [zero; 5];
    let mut hi = [zero; 5];
    for i in 0..5 {
        lo[i] = madd52lo(d.0[i], e.0[i], k);
        hi[i] = madd52hi(zero, e.0[i], k);
    }
    let h4 = _mm256_add_epi64(hi[4], hi[4]);
    reduce([
        _mm256_add_epi64(lo[0], times19(h4)),
        _mm256_add_epi64(lo[1], _mm256_add_epi64(hi[0], hi[0])),
        _mm256_add_epi64(lo[2], _mm256_add_epi64(hi[1], hi[1])),
        _mm256_add_epi64(lo[3], _mm256_add_epi64(hi[2], hi[2])),
        _mm256_add_epi64(lo[4], _mm256_add_epi64(hi[3], hi[3])),
    ])
}

/// One step of the X25519 ladder in the form `x25519::ladder_in` documents,
/// on the state `(xm, zm, xn, zn)` in lanes, choosing the doubling's input by
/// the secret `swap`, as a mask of all ones or zero.
#[target_feature(enable = "avx2")]
unsafe fn ladder_step_impl(state: &F4, x1: &F4, swap: __m256i) -> F4 {
    // (sm, dm, sn, dn) = (xm + zm, xm - zm, xn + zn, xn - zn).
    let a = permute::<{ sel(0, 0, 2, 2) }>(state);
    let b = negate_lanes::<{ lanes(0b1010) }>(&permute::<{ sel(1, 1, 3, 3) }>(state));
    let c = reduce(add_raw(&a.0, &b));
    // The doubling's input, (s, d): m's when swap is set, n's when not.
    // Lanes 0 and 1 are the addition's and do not depend on it.
    //   L1 = (dm, sm, d, s), R1 = (sn, dn, d, s).
    let l_n = permute::<{ sel(1, 0, 3, 2) }>(&c);
    let l_m = permute::<{ sel(1, 0, 1, 0) }>(&c);
    let r_n = permute::<{ sel(2, 3, 3, 2) }>(&c);
    let r_m = permute::<{ sel(2, 3, 1, 0) }>(&c);
    let mut l1 = l_n;
    let mut r1 = r_n;
    for i in 0..5 {
        l1.0[i] = _mm256_blendv_epi8(l_n.0[i], l_m.0[i], swap);
        r1.0[i] = _mm256_blendv_epi8(r_n.0[i], r_m.0[i], swap);
    }
    // (dmsn, dnsm, dd, ss).
    let m1 = mul4!(&l1, &r1);
    // L2 = (t1, t2, ss, e) = (dmsn - dnsm, dmsn + dnsm, ss, ss - dd).
    let p = permute::<{ sel(0, 0, 3, 3) }>(&m1);
    let q = permute::<{ sel(1, 1, 2, 2) }>(&m1);
    let q = blend::<{ lanes(0b0100) }>(&q, &F4([_mm256_setzero_si256(); 5]));
    let l2 = reduce(add_raw(&p.0, &negate_lanes::<{ lanes(0b1001) }>(&q)));
    // R2 = (t1, t2, dd, dd + 121666 e): RFC 7748's E * (AA + 121665 E)
    // written E * (BB + 121666 E), as in `ladder_in`.
    let dd = permute::<{ sel(2, 2, 2, 2) }>(&m1);
    let e = permute::<{ sel(3, 3, 3, 3) }>(&l2);
    let t3 = mul121666_add(&e, &dd);
    let r2 = blend::<{ lanes(0b1100) }>(&l2, &blend::<{ lanes(0b1000) }>(&dd, &t3));
    // (t1^2, xm', xn', zn') = (t1^2, t2^2, ss dd, e t3).
    let m2 = mul4!(&l2, &r2);
    // zm' = x1 t1^2.
    let m3 = mul4!(&permute::<{ sel(0, 0, 0, 0) }>(&m2), x1);
    // (xm', zm', xn', zn').
    let s = permute::<{ sel(1, 1, 2, 3) }>(&m2);
    blend::<{ lanes(0b0010) }>(&s, &m3)
}

#[target_feature(enable = "avx2")]
unsafe fn x25519_impl(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = Fe64::from_bytes(u);
    let x14 = pack([&x1, &x1, &x1, &x1]);
    // The RFC's initial state: (x2, z2) = (1, 0) in n, (x3, z3) = (u, 1) in m.
    let mut state = pack([&x1, &Fe64::ONE, &Fe64::ONE, &Fe64::ZERO]);
    let mut prev = 0u64;
    for pos in (0..255).rev() {
        let bit = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);
        let swap = _mm256_set1_epi64x(crate::fe64::mask(bit ^ prev) as i64);
        state = ladder_step_impl(&state, &x14, swap);
        prev = bit;
    }
    let [xm, zm, xn, zn] = unpack(&state);
    // The RFC's last swap: its (x2, z2) is n, or m when the final flag is set.
    let m = crate::fe64::mask(prev);
    let x = Fe64::select_mask(&xn, &xm, m);
    let z = Fe64::select_mask(&zn, &zm, m);
    x.mul(&z.invert()).to_bytes()
}

impl Ifma {
    /// X25519's ladder, `scalar * u`, four lanes at a time: the
    /// `x25519::ladder_in` step with its three rounds of multiplications
    /// done four at once.
    pub fn x25519_ladder(self, scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        // SAFETY: as in `point`.
        unsafe { x25519_impl(scalar, u) }
    }
}

#[target_feature(enable = "avx2")]
unsafe fn identity_operand() -> N4 {
    let z = _mm256_setzero_si256();
    N4(F4([_mm256_set_epi64x(2, 0, 1, 1), z, z, z, z]))
}

/// Four elements into lanes.
#[target_feature(enable = "avx2")]
unsafe fn pack(e: [&Fe64; 4]) -> F4 {
    let limbs = [
        to_limbs51(e[0]),
        to_limbs51(e[1]),
        to_limbs51(e[2]),
        to_limbs51(e[3]),
    ];
    let mut r = [_mm256_setzero_si256(); 5];
    for i in 0..5 {
        r[i] = _mm256_set_epi64x(
            limbs[3][i] as i64,
            limbs[2][i] as i64,
            limbs[1][i] as i64,
            limbs[0][i] as i64,
        );
    }
    F4(r)
}

/// Lanes back to four elements.
#[target_feature(enable = "avx2")]
unsafe fn unpack(a: &F4) -> [Fe64; 4] {
    let mut v = [[0u64; 4]; 5];
    for (i, limb) in v.iter_mut().enumerate() {
        _mm256_storeu_si256(limb.as_mut_ptr() as *mut __m256i, a.0[i]);
    }
    core::array::from_fn(|l| Fe64::from_limbs51([v[0][l], v[1][l], v[2][l], v[3][l], v[4][l]]))
}

/// Split four 64-bit limbs into five of 51 bits; the top one takes the last
/// 52 bits, so any 256-bit value fits below 2^52 per limb.
fn to_limbs51(x: &Fe64) -> [u64; 5] {
    let w = x.0;
    let m = (1u64 << 51) - 1;
    [
        w[0] & m,
        ((w[0] >> 51) | (w[1] << 13)) & m,
        ((w[1] >> 38) | (w[2] << 26)) & m,
        ((w[2] >> 25) | (w[3] << 39)) & m,
        w[3] >> 12,
    ]
}

impl Ifma {
    /// The point `(X : Y : Z : T)`.
    #[inline]
    pub fn point(self, x: &Fe64, y: &Fe64, z: &Fe64, t: &Fe64) -> P4 {
        // SAFETY: the token exists only where `get` found the features
        // `pack` is compiled for.
        unsafe { P4(pack([x, y, z, t])) }
    }

    /// `(X, Y, Z, T)` of a point.
    #[inline]
    pub fn coordinates(self, p: &P4) -> [Fe64; 4] {
        // SAFETY: as in `point`.
        unsafe { unpack(&p.0) }
    }

    /// The operand for adding the point with these `(Y - X, Y + X, 2d T,
    /// 2 Z)`.
    #[inline]
    pub fn operand(self, ymx: &Fe64, ypx: &Fe64, t2d: &Fe64, z2: &Fe64) -> N4 {
        // SAFETY: as in `point`.
        unsafe { N4(pack([ymx, ypx, t2d, z2])) }
    }

    /// `2 P`, in extended coordinates.
    #[inline]
    pub fn double(self, p: &P4) -> P4 {
        // SAFETY: as in `point`.
        unsafe { double_impl(p) }
    }

    /// `P + N`, in extended coordinates.
    #[inline]
    pub fn add(self, p: &P4, n: &N4) -> P4 {
        // SAFETY: as in `point`.
        unsafe { add_impl(p, n) }
    }

    /// The operand of `-N`.
    #[inline]
    pub fn negate(self, n: &N4) -> N4 {
        // SAFETY: as in `point`.
        unsafe { negate_operand_impl(n) }
    }

    /// `digit * base` for `digit` in `[-8, 8]`, from the operands of `1..=8`
    /// times `base`, in constant time: every entry is read and blended under
    /// a mask, and the sign applied the same way.
    #[inline]
    pub fn select(self, table: &[N4; 8], digit: i8) -> N4 {
        // SAFETY: as in `point`.
        unsafe { select_impl(table, digit) }
    }

    /// Lane-wise `a * b`, for the tests.
    #[cfg(test)]
    fn mul4(self, a: [&Fe64; 4], b: [&Fe64; 4]) -> [Fe64; 4] {
        // SAFETY: as in `point`.
        unsafe { unpack(&mul(&pack(a), &pack(b))) }
    }

    /// Lane-wise `a^2`, for the tests.
    #[cfg(test)]
    fn square4(self, a: [&Fe64; 4]) -> [Fe64; 4] {
        // SAFETY: as in `point`.
        unsafe { unpack(&square(&pack(a))) }
    }
}

/// The four-lane operations for `scripts/ct-audit` to read compiled; behind
/// the `ct-probes` feature, not API.
#[cfg(feature = "ct-probes")]
#[doc(hidden)]
pub mod probes {
    use super::*;

    /// Four elements as `[u64; 4]` limbs, as the probes pass them.
    pub type Lanes = [[u64; 4]; 4];

    #[target_feature(enable = "avx2")]
    unsafe fn load(x: &Lanes) -> F4 {
        let e = x.map(Fe64);
        pack([&e[0], &e[1], &e[2], &e[3]])
    }

    #[target_feature(enable = "avx2")]
    unsafe fn store(a: &F4) -> Lanes {
        unpack(a).map(|e| e.0)
    }

    /// One X25519 ladder step on four lanes.
    ///
    /// # Safety
    ///
    /// Only on a CPU `Ifma::get` accepts.
    #[target_feature(enable = "avx2")]
    pub unsafe fn ladder_step(state: &Lanes, x1: &[u64; 4], swap: u64) -> Lanes {
        let x1 = Fe64(*x1);
        let mask = _mm256_set1_epi64x(crate::fe64::mask(swap & 1) as i64);
        store(&ladder_step_impl(
            &load(state),
            &pack([&x1, &x1, &x1, &x1]),
            mask,
        ))
    }

    /// The constant-time table selection.
    ///
    /// # Safety
    ///
    /// As [`ladder_step`].
    #[target_feature(enable = "avx2")]
    pub unsafe fn select(table: &[Lanes; 8], digit: i8) -> Lanes {
        let t: [N4; 8] = [
            N4(load(&table[0])),
            N4(load(&table[1])),
            N4(load(&table[2])),
            N4(load(&table[3])),
            N4(load(&table[4])),
            N4(load(&table[5])),
            N4(load(&table[6])),
            N4(load(&table[7])),
        ];
        store(&select_impl(&t, digit).0)
    }

    /// A mixed addition.
    ///
    /// # Safety
    ///
    /// As [`ladder_step`].
    #[target_feature(enable = "avx2")]
    pub unsafe fn add(p: &Lanes, n: &Lanes) -> Lanes {
        store(&add_impl(&P4(load(p)), &N4(load(n))).0)
    }

    /// A doubling.
    ///
    /// # Safety
    ///
    /// As [`ladder_step`].
    #[target_feature(enable = "avx2")]
    pub unsafe fn double(p: &Lanes) -> Lanes {
        store(&double_impl(&P4(load(p))).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> Option<Ifma> {
        let t = Ifma::get();
        if t.is_none() {
            std::eprintln!("f51x4: no AVX-512 IFMA here; four-lane field not exercised");
        }
        t
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn fe(&mut self) -> Fe64 {
            let pick = |r: u64, n: u64| match r % 6 {
                0 => u64::MAX,
                1 => 0,
                2 => u64::MAX - (n % 64),
                _ => n,
            };
            Fe64(core::array::from_fn(|_| {
                let (r, n) = (self.next(), self.next());
                pick(r, n)
            }))
        }
    }

    #[test]
    fn the_four_lane_field_agrees_with_the_four_limb_one() {
        let Some(t) = token() else { return };
        let mut rng = Rng(0x1357_9bdf_2468_ace0);
        let n = if cfg!(debug_assertions) {
            20_000
        } else {
            400_000
        };
        for _ in 0..n {
            let a: [Fe64; 4] = core::array::from_fn(|_| rng.fe());
            let b: [Fe64; 4] = core::array::from_fn(|_| rng.fe());
            let ar = [&a[0], &a[1], &a[2], &a[3]];
            let br = [&b[0], &b[1], &b[2], &b[3]];
            let got = t.mul4(ar, br);
            let sq = t.square4(ar);
            for l in 0..4 {
                assert_eq!(
                    got[l].to_bytes(),
                    a[l].mul(&b[l]).to_bytes(),
                    "mul lane {l}"
                );
                assert_eq!(
                    sq[l].to_bytes(),
                    a[l].square().to_bytes(),
                    "square lane {l}"
                );
            }
            // And a product of products, so outputs are tested as inputs.
            let again = t.mul4(
                [&got[0], &got[1], &got[2], &got[3]],
                [&sq[0], &sq[1], &sq[2], &sq[3]],
            );
            for l in 0..4 {
                assert_eq!(
                    again[l].to_bytes(),
                    a[l].mul(&b[l]).mul(&a[l].square()).to_bytes(),
                    "chained lane {l}"
                );
            }
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn vector_mul_costs() {
        use std::time::Instant;
        let Some(_t) = token() else { return };
        let a: [Fe64; 4] = core::array::from_fn(|i| Fe64([i as u64 + 3, 5, 7, 11]));
        let n = 1_000_000u32;
        let run = |label: &str, f: &mut dyn FnMut()| {
            let mut best = f64::INFINITY;
            for _ in 0..7 {
                let s = Instant::now();
                f();
                best = best.min(s.elapsed().as_secs_f64() / n as f64 * 1e9);
            }
            std::println!("{label:<28} {best:.2} ns");
        };
        // SAFETY: `token` found the features.
        unsafe {
            let x = pack([&a[0], &a[1], &a[2], &a[3]]);
            let mut y = x;
            run("mul4 chain (latency)", &mut || {
                for _ in 0..n {
                    y = mul(&y, &x);
                }
            });
            let (mut p, mut q, mut r, mut s) = (x, x, x, x);
            run("mul4, 4 chains /4", &mut || {
                for _ in 0..n / 4 {
                    p = mul(&p, &x);
                    q = mul(&q, &x);
                    r = mul(&r, &x);
                    s = mul(&s, &x);
                }
            });
            run("square4 chain (latency)", &mut || {
                for _ in 0..n {
                    y = square(&y);
                }
            });
            run("reduce chain (latency)", &mut || {
                for _ in 0..n {
                    y = reduce(y.0);
                }
            });
            core::hint::black_box((y, p, q, r, s));
        }
    }

    #[test]
    fn packing_round_trips() {
        let Some(t) = token() else { return };
        let mut rng = Rng(42);
        for _ in 0..10_000 {
            let a: [Fe64; 4] = core::array::from_fn(|_| rng.fe());
            let p = t.point(&a[0], &a[1], &a[2], &a[3]);
            let back = t.coordinates(&p);
            for l in 0..4 {
                assert_eq!(back[l].to_bytes(), a[l].to_bytes());
            }
        }
    }
}
