//! Four Keccak-f[1600] permutations at once, one per 64-bit lane of an AVX2
//! register.
//!
//! # What this is for
//!
//! ML-KEM spends most of its time in SHAKE: nine independent SHAKE128 streams
//! expand the public matrix of ML-KEM-768, and up to eight SHAKE256 calls draw
//! its noise. The streams do not depend on one another, and a 256-bit
//! register holds one 64-bit lane of each of four states, so every step of
//! the permutation can be applied to four states for the cost of one vector
//! instruction. AVX2 has no 64-bit rotate -- that arrived with AVX-512 -- so a
//! rotation is two shifts and an or, and the four-way permutation costs a
//! little more than one scalar permutation rather than a quarter of one. It
//! is still close to four permutations for the price of one.
//!
//! # Trusting it
//!
//! It is the scalar [`super::keccak_f1600`] written over vectors, step for
//! step, with the same theta, rho-and-pi, chi and iota listing and the same
//! round constants read from [`super::RC`]. It is not checked against itself:
//! `the_avx2_permutation_agrees_with_the_scalar_one` runs both over the same
//! four states, with every lane different, and compares every word.
//!
//! # Safety
//!
//! [`permute`] is `unsafe` because `#[target_feature]` requires it: a caller
//! must not invoke it on a CPU without AVX2. [`super::avx2`] asks once and
//! caches the answer. The loads and stores are unaligned and stay inside the
//! 800-byte state the reference points to.
//!
//! # Constant-time properties
//!
//! Keccak has no key-indexed table and no data-dependent branch, and none is
//! introduced here: every instruction is a shift, an or, an and-not or an xor
//! of whole registers, whose latency does not depend on the values.

use core::arch::x86_64::*;

use super::RC;

/// Rotate each 64-bit lane left by `$n`.
macro_rules! rol {
    ($x:expr, $n:literal) => {
        _mm256_or_si256(
            _mm256_slli_epi64::<$n>($x),
            _mm256_srli_epi64::<{ 64 - $n }>($x),
        )
    };
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn x(a: __m256i, b: __m256i) -> __m256i {
    _mm256_xor_si256(a, b)
}

/// `!a & b`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn andn(a: __m256i, b: __m256i) -> __m256i {
    _mm256_andnot_si256(a, b)
}

/// Apply Keccak-f[1600] to four interleaved states.
///
/// `state[w][s]` is word `w` of state `s`, so `state[w]` is one register.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn permute(state: &mut [[u64; 4]; 25]) {
    let mut a = [_mm256_setzero_si256(); 25];
    for (v, words) in a.iter_mut().zip(state.iter()) {
        // SAFETY: `words` is 32 readable bytes; the load is unaligned.
        *v = unsafe { _mm256_loadu_si256(words.as_ptr().cast()) };
    }

    for rc in RC.iter() {
        // theta
        let c0 = x(x(x(a[0], a[5]), x(a[10], a[15])), a[20]);
        let c1 = x(x(x(a[1], a[6]), x(a[11], a[16])), a[21]);
        let c2 = x(x(x(a[2], a[7]), x(a[12], a[17])), a[22]);
        let c3 = x(x(x(a[3], a[8]), x(a[13], a[18])), a[23]);
        let c4 = x(x(x(a[4], a[9]), x(a[14], a[19])), a[24]);
        let d0 = x(c4, rol!(c1, 1));
        let d1 = x(c0, rol!(c2, 1));
        let d2 = x(c1, rol!(c3, 1));
        let d3 = x(c2, rol!(c4, 1));
        let d4 = x(c3, rol!(c0, 1));

        // rho and pi, with theta's D applied as each lane is read -- the same
        // listing as the scalar permutation.
        let b0 = x(a[0], d0);
        let b1 = rol!(x(a[6], d1), 44);
        let b2 = rol!(x(a[12], d2), 43);
        let b3 = rol!(x(a[18], d3), 21);
        let b4 = rol!(x(a[24], d4), 14);
        let b5 = rol!(x(a[3], d3), 28);
        let b6 = rol!(x(a[9], d4), 20);
        let b7 = rol!(x(a[10], d0), 3);
        let b8 = rol!(x(a[16], d1), 45);
        let b9 = rol!(x(a[22], d2), 61);
        let b10 = rol!(x(a[1], d1), 1);
        let b11 = rol!(x(a[7], d2), 6);
        let b12 = rol!(x(a[13], d3), 25);
        let b13 = rol!(x(a[19], d4), 8);
        let b14 = rol!(x(a[20], d0), 18);
        let b15 = rol!(x(a[4], d4), 27);
        let b16 = rol!(x(a[5], d0), 36);
        let b17 = rol!(x(a[11], d1), 10);
        let b18 = rol!(x(a[17], d2), 15);
        let b19 = rol!(x(a[23], d3), 56);
        let b20 = rol!(x(a[2], d2), 62);
        let b21 = rol!(x(a[8], d3), 55);
        let b22 = rol!(x(a[14], d4), 39);
        let b23 = rol!(x(a[15], d0), 41);
        let b24 = rol!(x(a[21], d1), 2);

        // chi: b[i] ^ (!b[i+1] & b[i+2]) within each row of five
        a[0] = x(b0, andn(b1, b2));
        a[1] = x(b1, andn(b2, b3));
        a[2] = x(b2, andn(b3, b4));
        a[3] = x(b3, andn(b4, b0));
        a[4] = x(b4, andn(b0, b1));
        a[5] = x(b5, andn(b6, b7));
        a[6] = x(b6, andn(b7, b8));
        a[7] = x(b7, andn(b8, b9));
        a[8] = x(b8, andn(b9, b5));
        a[9] = x(b9, andn(b5, b6));
        a[10] = x(b10, andn(b11, b12));
        a[11] = x(b11, andn(b12, b13));
        a[12] = x(b12, andn(b13, b14));
        a[13] = x(b13, andn(b14, b10));
        a[14] = x(b14, andn(b10, b11));
        a[15] = x(b15, andn(b16, b17));
        a[16] = x(b16, andn(b17, b18));
        a[17] = x(b17, andn(b18, b19));
        a[18] = x(b18, andn(b19, b15));
        a[19] = x(b19, andn(b15, b16));
        a[20] = x(b20, andn(b21, b22));
        a[21] = x(b21, andn(b22, b23));
        a[22] = x(b22, andn(b23, b24));
        a[23] = x(b23, andn(b24, b20));
        a[24] = x(b24, andn(b20, b21));

        // iota
        a[0] = x(a[0], _mm256_set1_epi64x(*rc as i64));
    }

    for (words, v) in state.iter_mut().zip(a.iter()) {
        // SAFETY: `words` is 32 writable bytes; the store is unaligned.
        unsafe { _mm256_storeu_si256(words.as_mut_ptr().cast(), *v) };
    }
}

/// `vprolq`: rotate each 64-bit lane left by `$n`, in one instruction.
///
/// AVX-512VL, on 256-bit registers. Written as inline assembly because the
/// intrinsic was stabilised after this workspace's minimum Rust version; the
/// instruction is the same either way.
macro_rules! vprolq {
    ($x:expr, $n:literal) => {{
        let out: __m256i;
        // SAFETY: a register-to-register instruction with no memory operand.
        // The caller has established AVX-512F and AVX-512VL; see
        // `permute_avx512vl`.
        unsafe {
            core::arch::asm!(
                "vprolq {o}, {i}, {n}",
                o = lateout(ymm_reg) out,
                i = in(ymm_reg) $x,
                n = const $n,
                options(pure, nomem, nostack, preserves_flags),
            )
        };
        out
    }};
}

/// `vpternlogq`: any three-input bitwise function, chosen by `$imm`, in one
/// instruction. `0x96` is `a ^ b ^ c`; `0xd2` is `a ^ (!b & c)`, Keccak's chi.
macro_rules! vpternlogq {
    ($a:expr, $b:expr, $c:expr, $imm:literal) => {{
        let mut r: __m256i = $a;
        // SAFETY: as for `vprolq!`.
        unsafe {
            core::arch::asm!(
                "vpternlogq {r}, {b}, {c}, {imm}",
                r = inout(ymm_reg) r,
                b = in(ymm_reg) $b,
                c = in(ymm_reg) $c,
                imm = const $imm,
                options(pure, nomem, nostack, preserves_flags),
            )
        };
        r
    }};
}

/// [`permute`] with AVX-512VL's rotate and three-input logic.
///
/// A rotation is one instruction instead of three, a five-way xor two
/// instead of four, and a chi step one instead of two: about half the
/// instructions per round.
///
/// # Safety
///
/// The CPU must support AVX2, AVX-512F and AVX-512VL. [`super::avx512vl`]
/// asks once and caches the answer.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn permute_avx512vl(state: &mut [[u64; 4]; 25]) {
    let mut a = [_mm256_setzero_si256(); 25];
    for (v, words) in a.iter_mut().zip(state.iter()) {
        // SAFETY: `words` is 32 readable bytes; the load is unaligned.
        *v = unsafe { _mm256_loadu_si256(words.as_ptr().cast()) };
    }

    for rc in RC.iter() {
        // theta
        let c0 = vpternlogq!(vpternlogq!(a[0], a[5], a[10], 0x96), a[15], a[20], 0x96);
        let c1 = vpternlogq!(vpternlogq!(a[1], a[6], a[11], 0x96), a[16], a[21], 0x96);
        let c2 = vpternlogq!(vpternlogq!(a[2], a[7], a[12], 0x96), a[17], a[22], 0x96);
        let c3 = vpternlogq!(vpternlogq!(a[3], a[8], a[13], 0x96), a[18], a[23], 0x96);
        let c4 = vpternlogq!(vpternlogq!(a[4], a[9], a[14], 0x96), a[19], a[24], 0x96);
        let d0 = x(c4, vprolq!(c1, 1));
        let d1 = x(c0, vprolq!(c2, 1));
        let d2 = x(c1, vprolq!(c3, 1));
        let d3 = x(c2, vprolq!(c4, 1));
        let d4 = x(c3, vprolq!(c0, 1));

        // rho and pi, the same listing as `permute`
        let b0 = x(a[0], d0);
        let b1 = vprolq!(x(a[6], d1), 44);
        let b2 = vprolq!(x(a[12], d2), 43);
        let b3 = vprolq!(x(a[18], d3), 21);
        let b4 = vprolq!(x(a[24], d4), 14);
        let b5 = vprolq!(x(a[3], d3), 28);
        let b6 = vprolq!(x(a[9], d4), 20);
        let b7 = vprolq!(x(a[10], d0), 3);
        let b8 = vprolq!(x(a[16], d1), 45);
        let b9 = vprolq!(x(a[22], d2), 61);
        let b10 = vprolq!(x(a[1], d1), 1);
        let b11 = vprolq!(x(a[7], d2), 6);
        let b12 = vprolq!(x(a[13], d3), 25);
        let b13 = vprolq!(x(a[19], d4), 8);
        let b14 = vprolq!(x(a[20], d0), 18);
        let b15 = vprolq!(x(a[4], d4), 27);
        let b16 = vprolq!(x(a[5], d0), 36);
        let b17 = vprolq!(x(a[11], d1), 10);
        let b18 = vprolq!(x(a[17], d2), 15);
        let b19 = vprolq!(x(a[23], d3), 56);
        let b20 = vprolq!(x(a[2], d2), 62);
        let b21 = vprolq!(x(a[8], d3), 55);
        let b22 = vprolq!(x(a[14], d4), 39);
        let b23 = vprolq!(x(a[15], d0), 41);
        let b24 = vprolq!(x(a[21], d1), 2);

        // chi
        a[0] = vpternlogq!(b0, b1, b2, 0xd2);
        a[1] = vpternlogq!(b1, b2, b3, 0xd2);
        a[2] = vpternlogq!(b2, b3, b4, 0xd2);
        a[3] = vpternlogq!(b3, b4, b0, 0xd2);
        a[4] = vpternlogq!(b4, b0, b1, 0xd2);
        a[5] = vpternlogq!(b5, b6, b7, 0xd2);
        a[6] = vpternlogq!(b6, b7, b8, 0xd2);
        a[7] = vpternlogq!(b7, b8, b9, 0xd2);
        a[8] = vpternlogq!(b8, b9, b5, 0xd2);
        a[9] = vpternlogq!(b9, b5, b6, 0xd2);
        a[10] = vpternlogq!(b10, b11, b12, 0xd2);
        a[11] = vpternlogq!(b11, b12, b13, 0xd2);
        a[12] = vpternlogq!(b12, b13, b14, 0xd2);
        a[13] = vpternlogq!(b13, b14, b10, 0xd2);
        a[14] = vpternlogq!(b14, b10, b11, 0xd2);
        a[15] = vpternlogq!(b15, b16, b17, 0xd2);
        a[16] = vpternlogq!(b16, b17, b18, 0xd2);
        a[17] = vpternlogq!(b17, b18, b19, 0xd2);
        a[18] = vpternlogq!(b18, b19, b15, 0xd2);
        a[19] = vpternlogq!(b19, b15, b16, 0xd2);
        a[20] = vpternlogq!(b20, b21, b22, 0xd2);
        a[21] = vpternlogq!(b21, b22, b23, 0xd2);
        a[22] = vpternlogq!(b22, b23, b24, 0xd2);
        a[23] = vpternlogq!(b23, b24, b20, 0xd2);
        a[24] = vpternlogq!(b24, b20, b21, 0xd2);

        // iota
        a[0] = x(a[0], _mm256_set1_epi64x(*rc as i64));
    }

    for (words, v) in state.iter_mut().zip(a.iter()) {
        // SAFETY: `words` is 32 writable bytes; the store is unaligned.
        unsafe { _mm256_storeu_si256(words.as_mut_ptr().cast(), *v) };
    }
}
