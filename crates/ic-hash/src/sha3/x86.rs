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
//! instruction.
//!
//! AVX2 has no 64-bit rotate, so there a rotation is two shifts and an or.
//! AVX-512VL has one, `vprolq`, and a three-input logic instruction,
//! `vpternlogq`, that does chi's `a ^ (!b & c)` in one; where the CPU has
//! them they are used on the same 256-bit registers. Measured on a Zen 5
//! part, over 21 squeezed blocks of four streams: 6.6 us with AVX2, 5.1 us
//! with AVX-512VL, against 3.9 us for one scalar stream.
//!
//! # A row at a time
//!
//! Both forms compute each round an output row at a time, into a second
//! state, rather than as the scalar listing is written: all twenty-five
//! rho-and-pi words, then chi. Theta needs the whole input state, but each
//! output row needs only five gathered words, so computing a row and then its
//! chi keeps five values live where the other order keeps twenty-five -- and
//! with sixteen vector registers, most of those went to the stack and back.
//! The row order was worth about a tenth with AVX-512VL and a twentieth with
//! AVX2. Theta's column parities are four plain xors rather than two
//! `vpternlogq`s: on this core the rotates and three-input operations share
//! two of the four vector pipes, and the two forms measured the same.
//!
//! # Trusting it
//!
//! It is the scalar [`super::keccak_f1600`] written over vectors, with the
//! same theta, rho-and-pi, chi and iota, the rho-and-pi listing regrouped by
//! output row, and the round constants read from [`super::RC`].
//! `the_avx2_permutation_agrees_with_the_scalar_one` and its AVX-512VL
//! counterpart run each against four scalar permutations over the same four
//! states, every lane different, and compare every word.
//!
//! # Safety
//!
//! Both functions are `unsafe` because `#[target_feature]` requires it: a
//! caller must not invoke [`permute`] on a CPU without AVX2, or
//! [`permute_avx512vl`] on one without AVX-512F and AVX-512VL as well.
//! [`super::keccak_f1600_x4`] asks once and caches the answers. The loads and
//! stores are unaligned and stay inside the 800-byte state the reference
//! points to. The AVX-512 instructions are inline assembly, because their
//! intrinsics were stabilised after this workspace's minimum Rust version;
//! each is register to register, touches no memory and no flags.
//!
//! # What is left on the stack
//!
//! `a` and `e` are not arrays in the compiled code: the compiler splits them
//! into twenty-five values each and keeps them in registers, and what does
//! not fit -- a few hundred bytes of intermediate state, the four states
//! may be secret -- goes to spill slots it allocates itself. Wrapping the
//! two arrays in a wiping guard was tried and wiped nothing that held the
//! state: the guard made the arrays real memory (1600 more bytes of frame,
//! zeroed on entry and wiped on exit) while the rounds went on spilling to
//! their own slots. No source-level wipe reaches those slots; only a scrub
//! of the dead frame by its depth would, which is not done here
//! (`docs/CONSTANT_TIME.md`, "Registers and stack after a kernel").
//!
//! # Constant-time properties
//!
//! Keccak has no key-indexed table and no data-dependent branch, and none is
//! introduced here: every instruction is a shift, a rotate, a bitwise logic
//! operation or a load or store at a fixed offset, none of whose timing
//! depends on the values.

use core::arch::x86_64::*;

use super::RC;

/// Rotate each 64-bit lane left by `$n`: AVX2, two shifts and an or.
macro_rules! rol_avx2 {
    ($x:expr, $n:literal) => {
        _mm256_or_si256(
            _mm256_slli_epi64::<$n>($x),
            _mm256_srli_epi64::<{ 64 - $n }>($x),
        )
    };
}

/// `a ^ (!b & c)`: AVX2.
macro_rules! chi_avx2 {
    ($a:expr, $b:expr, $c:expr) => {
        _mm256_xor_si256($a, _mm256_andnot_si256($b, $c))
    };
}

/// `vprolq`: rotate each 64-bit lane left by `$n`, in one instruction.
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

/// `a ^ (!b & c)` in one `vpternlogq`: `0xd2` is that function's truth table,
/// indexed by `a b c` as a three-bit number.
macro_rules! chi_ternlog {
    ($a:expr, $b:expr, $c:expr) => {{
        let mut r: __m256i = $a;
        // SAFETY: as for `vprolq!`.
        unsafe {
            core::arch::asm!(
                "vpternlogq {r}, {b}, {c}, 0xd2",
                r = inout(ymm_reg) r,
                b = in(ymm_reg) $b,
                c = in(ymm_reg) $c,
                options(pure, nomem, nostack, preserves_flags),
            )
        };
        r
    }};
}

macro_rules! xor2 {
    ($a:expr, $b:expr) => {
        _mm256_xor_si256($a, $b)
    };
}

macro_rules! xor5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_xor_si256($a, $b), _mm256_xor_si256($c, $d)),
            $e,
        )
    };
}

/// One round from `$s` into `$o`, an output row at a time, with `$rol` and
/// `$chi` the rotate and chi step to use.
///
/// The rho-and-pi listing is the scalar permutation's, regrouped so that the
/// five words each output row needs are gathered together.
/// Store a round's word `$i` into the array `$o`.
macro_rules! put_array {
    ($o:ident, $i:literal, $v:expr) => {
        $o[$i] = $v
    };
}

/// Store a round's word `$i` straight to `$o[$i]`, the caller's state.
macro_rules! put_state {
    ($o:ident, $i:literal, $v:expr) => {{
        let v = $v;
        // SAFETY: `$o[$i]` is 32 writable bytes; the store is unaligned.
        unsafe { _mm256_storeu_si256($o[$i].as_mut_ptr().cast(), v) }
    }};
}

macro_rules! round_rows {
    ($s:ident, $o:ident, $put:ident, $rc:expr, $rol:ident, $chi:ident) => {{
        let c0 = xor5!($s[0], $s[5], $s[10], $s[15], $s[20]);
        let c1 = xor5!($s[1], $s[6], $s[11], $s[16], $s[21]);
        let c2 = xor5!($s[2], $s[7], $s[12], $s[17], $s[22]);
        let c3 = xor5!($s[3], $s[8], $s[13], $s[18], $s[23]);
        let c4 = xor5!($s[4], $s[9], $s[14], $s[19], $s[24]);
        let d0 = xor2!(c4, $rol!(c1, 1));
        let d1 = xor2!(c0, $rol!(c2, 1));
        let d2 = xor2!(c1, $rol!(c3, 1));
        let d3 = xor2!(c2, $rol!(c4, 1));
        let d4 = xor2!(c3, $rol!(c0, 1));

        let b0 = xor2!($s[0], d0);
        let b1 = $rol!(xor2!($s[6], d1), 44);
        let b2 = $rol!(xor2!($s[12], d2), 43);
        let b3 = $rol!(xor2!($s[18], d3), 21);
        let b4 = $rol!(xor2!($s[24], d4), 14);
        $put!(
            $o,
            0,
            xor2!($chi!(b0, b1, b2), _mm256_set1_epi64x($rc as i64))
        );
        $put!($o, 1, $chi!(b1, b2, b3));
        $put!($o, 2, $chi!(b2, b3, b4));
        $put!($o, 3, $chi!(b3, b4, b0));
        $put!($o, 4, $chi!(b4, b0, b1));

        let b0 = $rol!(xor2!($s[3], d3), 28);
        let b1 = $rol!(xor2!($s[9], d4), 20);
        let b2 = $rol!(xor2!($s[10], d0), 3);
        let b3 = $rol!(xor2!($s[16], d1), 45);
        let b4 = $rol!(xor2!($s[22], d2), 61);
        $put!($o, 5, $chi!(b0, b1, b2));
        $put!($o, 6, $chi!(b1, b2, b3));
        $put!($o, 7, $chi!(b2, b3, b4));
        $put!($o, 8, $chi!(b3, b4, b0));
        $put!($o, 9, $chi!(b4, b0, b1));

        let b0 = $rol!(xor2!($s[1], d1), 1);
        let b1 = $rol!(xor2!($s[7], d2), 6);
        let b2 = $rol!(xor2!($s[13], d3), 25);
        let b3 = $rol!(xor2!($s[19], d4), 8);
        let b4 = $rol!(xor2!($s[20], d0), 18);
        $put!($o, 10, $chi!(b0, b1, b2));
        $put!($o, 11, $chi!(b1, b2, b3));
        $put!($o, 12, $chi!(b2, b3, b4));
        $put!($o, 13, $chi!(b3, b4, b0));
        $put!($o, 14, $chi!(b4, b0, b1));

        let b0 = $rol!(xor2!($s[4], d4), 27);
        let b1 = $rol!(xor2!($s[5], d0), 36);
        let b2 = $rol!(xor2!($s[11], d1), 10);
        let b3 = $rol!(xor2!($s[17], d2), 15);
        let b4 = $rol!(xor2!($s[23], d3), 56);
        $put!($o, 15, $chi!(b0, b1, b2));
        $put!($o, 16, $chi!(b1, b2, b3));
        $put!($o, 17, $chi!(b2, b3, b4));
        $put!($o, 18, $chi!(b3, b4, b0));
        $put!($o, 19, $chi!(b4, b0, b1));

        let b0 = $rol!(xor2!($s[2], d2), 62);
        let b1 = $rol!(xor2!($s[8], d3), 55);
        let b2 = $rol!(xor2!($s[14], d4), 39);
        let b3 = $rol!(xor2!($s[15], d0), 41);
        let b4 = $rol!(xor2!($s[21], d1), 2);
        $put!($o, 20, $chi!(b0, b1, b2));
        $put!($o, 21, $chi!(b1, b2, b3));
        $put!($o, 22, $chi!(b2, b3, b4));
        $put!($o, 23, $chi!(b3, b4, b0));
        $put!($o, 24, $chi!(b4, b0, b1));
    }};
}

/// Load the four interleaved states, run the 24 rounds, and store them back.
///
/// The first round reads the state, and the last writes it, directly; only
/// the 22 rounds between them, run two at a time between `a` and `e`, work on
/// arrays the loop carries. Loading the state into such an array first, and
/// storing the array back after, made LLVM copy all 25 words through
/// `vmovups`, applied to secret state, a float-domain instruction Intel's
/// Data Operand Independent Timing list does not cover. A word that a
/// vector-integer instruction consumes straight from the state is kept in
/// the integer domain.
macro_rules! permute_with {
    ($state:ident, $rol:ident, $chi:ident) => {{
        let mut a = [_mm256_setzero_si256(); 25];
        let mut e = [_mm256_setzero_si256(); 25];
        {
            let mut first = [_mm256_setzero_si256(); 25];
            for (v, words) in first.iter_mut().zip($state.iter()) {
                // SAFETY: `words` is 32 readable bytes; the load is unaligned.
                *v = unsafe { _mm256_loadu_si256(words.as_ptr().cast()) };
            }
            round_rows!(first, e, put_array, RC[0], $rol, $chi);
        }
        for pair in RC[1..23].chunks_exact(2) {
            round_rows!(e, a, put_array, pair[0], $rol, $chi);
            round_rows!(a, e, put_array, pair[1], $rol, $chi);
        }
        round_rows!(e, $state, put_state, RC[23], $rol, $chi);
    }};
}

/// Apply Keccak-f[1600] to four interleaved states, with AVX2.
///
/// `state[w][s]` is word `w` of state `s`, so `state[w]` is one register.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn permute(state: &mut [[u64; 4]; 25]) {
    permute_with!(state, rol_avx2, chi_avx2);
}

/// [`permute`], with AVX-512VL's rotate and three-input logic on the same
/// registers.
///
/// # Safety
///
/// The CPU must support AVX2, AVX-512F and AVX-512VL.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn permute_avx512vl(state: &mut [[u64; 4]; 25]) {
    permute_with!(state, vprolq, chi_ternlog);
}
