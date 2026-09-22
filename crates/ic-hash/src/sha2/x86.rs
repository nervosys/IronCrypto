//! The x86-64 SHA-NI backend for SHA-256.
//!
//! # What is and is not reimplemented here
//!
//! Only the block compression function. Message buffering, length counting,
//! padding and finalisation stay in [`super`], which calls this for whole
//! blocks and nothing else. Those parts are not on the hot path and a second
//! implementation of them would buy nothing and risk a divergence.
//!
//! The round constants are read from [`super::K256`] rather than written out
//! again as SIMD literals. That is deliberate: the published vectors already
//! validate that table, and a transcription of sixty-four constants into
//! `_mm_set_epi64x` pairs is exactly the kind of thing that is wrong in one
//! place and passes every test that does not happen to reach it.
//!
//! SHA-512 has no equivalent instruction set here and keeps the portable path.
//! That is why SHA-512 is only slightly behind its counterpart while SHA-256
//! was far behind: the gap was never the arithmetic.
//!
//! # Safety
//!
//! These functions are `unsafe` because `#[target_feature]` requires it: a
//! caller must not invoke them on a CPU without SHA-NI, SSE2, SSSE3 and
//! SSE4.1. [`super::Core256::compress`] checks for them once and caches the
//! answer. The intrinsics themselves are safe once the features are enabled in
//! scope, so the only genuinely unsafe operations are the raw-pointer loads and
//! stores, and those are the only things inside an `unsafe` block.
//!
//! # Constant-time properties
//!
//! SHA-256 is not a secret-dependent computation in the sense AES is -- it has
//! no key and no table indexed by anything -- but the property still holds
//! here: `SHA256RNDS2` and its companions are single instructions with
//! data-independent latency, and this backend indexes no table at all.

use core::arch::x86_64::*;

use super::K256;

/// Compress whole 64-byte blocks into `state`.
///
/// # Safety
///
/// The CPU must support `sha`, `sse2`, `ssse3` and `sse4.1`. `blocks` must be a
/// whole number of 64-byte blocks.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert!(blocks.len() % 64 == 0);

    // The byte-swap for big-endian message words.
    let shuffle = _mm_set_epi64x(
        0x0c0d_0e0f_0809_0a0bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    // SHA-NI keeps the state as ABEF and CDGH rather than A..H in order, so
    // loading and storing it means two shuffles at each end.
    let mut tmp = unsafe { _mm_loadu_si128(state.as_ptr() as *const __m128i) };
    let mut state1 = unsafe { _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i) };

    tmp = _mm_shuffle_epi32(tmp, 0xb1); // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1b); // EFGH
    let mut state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xf0); // CDGH

    for block in blocks.chunks_exact(64) {
        let save0 = state0;
        let save1 = state1;

        // The sixteen message words, byte-swapped into four registers.
        let mut m0 = _mm_shuffle_epi8(
            unsafe { _mm_loadu_si128(block.as_ptr() as *const __m128i) },
            shuffle,
        );
        let mut m1 = _mm_shuffle_epi8(
            unsafe { _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i) },
            shuffle,
        );
        let mut m2 = _mm_shuffle_epi8(
            unsafe { _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i) },
            shuffle,
        );
        let mut m3 = _mm_shuffle_epi8(
            unsafe { _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i) },
            shuffle,
        );

        // Four rounds per step, sixteen steps. The first four steps use the
        // message words as loaded; the rest schedule new ones as they go.
        macro_rules! rounds {
            ($m:expr, $i:literal) => {{
                let k = unsafe { _mm_loadu_si128(K256.as_ptr().add($i * 4) as *const __m128i) };
                let mut w = _mm_add_epi32($m, k);
                state1 = _mm_sha256rnds2_epu32(state1, state0, w);
                w = _mm_shuffle_epi32(w, 0x0e);
                state0 = _mm_sha256rnds2_epu32(state0, state1, w);
            }};
        }

        /// One scheduling step: `a` advances using the next three registers.
        macro_rules! schedule {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                $a = _mm_sha256msg1_epu32($a, $b);
                let t = _mm_alignr_epi8($d, $c, 4);
                $a = _mm_add_epi32($a, t);
                $a = _mm_sha256msg2_epu32($a, $d);
            }};
        }

        rounds!(m0, 0);
        rounds!(m1, 1);
        rounds!(m2, 2);
        rounds!(m3, 3);

        schedule!(m0, m1, m2, m3);
        rounds!(m0, 4);
        schedule!(m1, m2, m3, m0);
        rounds!(m1, 5);
        schedule!(m2, m3, m0, m1);
        rounds!(m2, 6);
        schedule!(m3, m0, m1, m2);
        rounds!(m3, 7);

        schedule!(m0, m1, m2, m3);
        rounds!(m0, 8);
        schedule!(m1, m2, m3, m0);
        rounds!(m1, 9);
        schedule!(m2, m3, m0, m1);
        rounds!(m2, 10);
        schedule!(m3, m0, m1, m2);
        rounds!(m3, 11);

        schedule!(m0, m1, m2, m3);
        rounds!(m0, 12);
        schedule!(m1, m2, m3, m0);
        rounds!(m1, 13);
        schedule!(m2, m3, m0, m1);
        rounds!(m2, 14);
        schedule!(m3, m0, m1, m2);
        rounds!(m3, 15);

        state0 = _mm_add_epi32(state0, save0);
        state1 = _mm_add_epi32(state1, save1);
    }

    // Back to A..H order.
    tmp = _mm_shuffle_epi32(state0, 0x1b); // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xb1); // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xf0); // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8); // HGFE

    unsafe {
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state0);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, state1);
    }
}
