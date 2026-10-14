//! The x86-64 SHA-NI backend for SHA-256.
//!
//! # What is and is not reimplemented here
//!
//! The block compression function, and three compositions of it that keep the
//! chaining value in the instructions' register layout from one block to the
//! next rather than storing and reloading it between calls: a message's
//! blocks followed by its padding block ([`compress_parts`]), HMAC's two
//! key-pad blocks ([`compress_pads`]), and HMAC's last two compressions, the
//! inner hash's final blocks and then the outer hash's one block, built from
//! the inner digest in registers ([`hmac_tail`]). Buffering, length counting
//! and the bytes of the padding stay in [`super`].
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
//! data-independent latency, and this backend indexes no table at all. The
//! HMAC compositions hold key-derived chaining values and branch only on the
//! message's length.

use core::arch::x86_64::*;

use super::K256;

/// The byte-swap for big-endian message words.
macro_rules! bswap_mask {
    () => {
        _mm_set_epi64x(
            0x0c0d_0e0f_0809_0a0bu64 as i64,
            0x0405_0607_0001_0203u64 as i64,
        )
    };
}

/// Load `A..H` from `$state` into SHA-NI's `ABEF` and `CDGH` registers.
macro_rules! load_state {
    ($state:expr) => {{
        // SAFETY: `$state` is eight `u32`, two 16-byte loads.
        let tmp = unsafe { _mm_loadu_si128($state.as_ptr() as *const __m128i) };
        let s1 = unsafe { _mm_loadu_si128($state.as_ptr().add(4) as *const __m128i) };
        let tmp = _mm_shuffle_epi32(tmp, 0xb1); // CDAB
        let s1 = _mm_shuffle_epi32(s1, 0x1b); // EFGH
        (
            _mm_alignr_epi8(tmp, s1, 8),    // ABEF
            _mm_blend_epi16(s1, tmp, 0xf0), // CDGH
        )
    }};
}

/// `ABEF` and `CDGH` back to two registers holding `A..D` and `E..H` in
/// order, as they are stored and as an outer HMAC block's first words.
macro_rules! unshuffle_state {
    ($s0:expr, $s1:expr) => {{
        let tmp = _mm_shuffle_epi32($s0, 0x1b); // FEBA
        let s1 = _mm_shuffle_epi32($s1, 0xb1); // DCHG
        (
            _mm_blend_epi16(tmp, s1, 0xf0), // DCBA
            _mm_alignr_epi8(s1, tmp, 8),    // HGFE
        )
    }};
}

/// Store `ABEF` and `CDGH` as `A..H` into `$state`.
macro_rules! store_state {
    ($s0:expr, $s1:expr, $state:expr) => {{
        let (abcd, efgh) = unshuffle_state!($s0, $s1);
        // SAFETY: `$state` is eight `u32`, two 16-byte stores.
        unsafe {
            _mm_storeu_si128($state.as_mut_ptr() as *mut __m128i, abcd);
            _mm_storeu_si128($state.as_mut_ptr().add(4) as *mut __m128i, efgh);
        }
    }};
}

/// The four message registers of the 64-byte block at `$p`, byte-swapped.
macro_rules! load_block {
    ($p:expr, $shuffle:expr) => {{
        // SAFETY: the caller's `$p` points at 64 readable bytes.
        unsafe {
            (
                _mm_shuffle_epi8(_mm_loadu_si128($p as *const __m128i), $shuffle),
                _mm_shuffle_epi8(_mm_loadu_si128($p.add(16) as *const __m128i), $shuffle),
                _mm_shuffle_epi8(_mm_loadu_si128($p.add(32) as *const __m128i), $shuffle),
                _mm_shuffle_epi8(_mm_loadu_si128($p.add(48) as *const __m128i), $shuffle),
            )
        }
    }};
}

/// One compression of the message words `$m0..$m3` (in order, already
/// native-endian) into `$state0`/`$state1`, feed-forward included.
macro_rules! block {
    ($state0:ident, $state1:ident, $m:expr) => {{
        let (mut m0, mut m1, mut m2, mut m3) = $m;
        let save0 = $state0;
        let save1 = $state1;

        // Four rounds per step, sixteen steps. The first four steps use the
        // message words as loaded; the rest schedule new ones as they go.
        macro_rules! rounds {
            ($mm:expr, $i:literal) => {{
                // SAFETY: `K256` has 64 words; `$i * 4 + 4 <= 64`.
                let k = unsafe { _mm_loadu_si128(K256.as_ptr().add($i * 4) as *const __m128i) };
                let mut w = _mm_add_epi32($mm, k);
                $state1 = _mm_sha256rnds2_epu32($state1, $state0, w);
                w = _mm_shuffle_epi32(w, 0x0e);
                $state0 = _mm_sha256rnds2_epu32($state0, $state1, w);
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

        $state0 = _mm_add_epi32($state0, save0);
        $state1 = _mm_add_epi32($state1, save1);
    }};
}

/// Compress whole 64-byte blocks into `state`.
///
/// # Safety
///
/// The CPU must support `sha`, `sse2`, `ssse3` and `sse4.1`. `blocks` must be a
/// whole number of 64-byte blocks.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    // SAFETY: as the caller guarantees.
    unsafe { compress_parts(state, blocks, &[]) }
}

/// Compress the whole blocks of `first` and then those of `second` into
/// `state`, holding it in registers across both: a message's own blocks, then
/// its padding block from a buffer, for one shuffle of the state in and one
/// out rather than two each.
///
/// # Safety
///
/// As [`compress`]; both lengths are whole numbers of blocks.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn compress_parts(state: &mut [u32; 8], first: &[u8], second: &[u8]) {
    debug_assert!(first.len().is_multiple_of(64));
    debug_assert!(second.len().is_multiple_of(64));
    let shuffle = bswap_mask!();
    let (mut state0, mut state1) = load_state!(state);
    for part in [first, second] {
        for b in part.chunks_exact(64) {
            block!(state0, state1, load_block!(b.as_ptr(), shuffle));
        }
    }
    store_state!(state0, state1, state);
}

/// HMAC's two key-pad blocks, each compressed into its own state: two
/// independent chains in one function, which the CPU runs side by side.
/// `ipad` is the key XOR `0x36`; the outer pad, the key XOR `0x5c`, is made
/// from it in registers, since `0x36 ^ 0x5c` is the same in every byte and so
/// survives the byte swap: one buffer of key material rather than two.
///
/// # Safety
///
/// As [`compress`].
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn compress_pads(inner: &mut [u32; 8], outer: &mut [u32; 8], ipad: &[u8; 64]) {
    let shuffle = bswap_mask!();
    let (mut i0, mut i1) = load_state!(inner);
    let (mut o0, mut o1) = load_state!(outer);
    let (m0, m1, m2, m3) = load_block!(ipad.as_ptr(), shuffle);
    let flip = _mm_set1_epi8(0x36 ^ 0x5c);
    let opad = (
        _mm_xor_si128(m0, flip),
        _mm_xor_si128(m1, flip),
        _mm_xor_si128(m2, flip),
        _mm_xor_si128(m3, flip),
    );
    block!(i0, i1, (m0, m1, m2, m3));
    block!(o0, o1, opad);
    store_state!(i0, i1, inner);
    store_state!(o0, o1, outer);
}

/// HMAC-SHA256's end: the inner hash's last blocks -- `blocks`, the
/// message's whole blocks, then `tail`, its padded final one or two -- and
/// then the outer hash's one block, which is the inner digest, `0x80`, zeros
/// and the length 768 bits. The inner digest goes from registers to the
/// outer block's message words without a store: its big-endian bytes, read
/// back as big-endian words, are the state words themselves. Returns the
/// outer state, `A..H`, through `outer`.
///
/// # Safety
///
/// As [`compress`]; `blocks` and `tail` are whole numbers of blocks.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn hmac_tail(inner: &[u32; 8], blocks: &[u8], tail: &[u8], outer: &mut [u32; 8]) {
    debug_assert!(blocks.len().is_multiple_of(64));
    debug_assert!(tail.len().is_multiple_of(64));
    let shuffle = bswap_mask!();
    let (mut i0, mut i1) = load_state!(inner);
    for part in [blocks, tail] {
        for b in part.chunks_exact(64) {
            block!(i0, i1, load_block!(b.as_ptr(), shuffle));
        }
    }
    let (abcd, efgh) = unshuffle_state!(i0, i1);
    let pad = _mm_setr_epi32(0x8000_0000u32 as i32, 0, 0, 0);
    let len = _mm_setr_epi32(0, 0, 0, (64 + 32) * 8);
    let (mut o0, mut o1) = load_state!(outer);
    block!(o0, o1, (abcd, efgh, pad, len));
    store_state!(o0, o1, outer);
}
