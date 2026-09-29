//! Carry-less multiplication in GF(2^128) for GHASH, using `PCLMULQDQ`.
//!
//! # Why this matters more than AES-NI does
//!
//! The portable GHASH multiplies bit by bit: 128 iterations per block, each
//! touching sixteen bytes. AES-NI reduces a block encryption to roughly ten
//! instructions. Accelerating AES without accelerating GHASH would therefore
//! leave AES-GCM almost exactly as slow as before, with GHASH taking well over
//! ninety percent of the time. This module is what makes the AEAD fast rather
//! than just the cipher.
//!
//! # The bit-reflection problem
//!
//! GCM numbers the bits of its field elements in the opposite order to the one
//! `PCLMULQDQ` assumes: GCM's bit 0 is the *most* significant bit of the first
//! byte. The usual treatment, which this follows, is to byte-reverse the
//! operands on load, multiply, correct for the one-bit offset the reflection
//! introduces, reduce, and byte-reverse on store.
//!
//! That correction step is fiddly, so correctness here does not rest on reading
//! the code: [`mul`] is differentially tested against the portable
//! implementation over both fixed and pseudo-random inputs, and the portable
//! one is validated by the GCM specification's own test vectors.

use core::arch::x86_64::*;

/// The byte-reversal shuffle, turning GCM's big-endian byte order into the
/// little-endian order the multiplier expects, and back.
#[inline]
#[target_feature(enable = "pclmulqdq,ssse3")]
fn byte_swap() -> __m128i {
    _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
}

/// The unreduced 128x128 carry-less product, as `(lo, mid, hi)` with `mid`
/// not yet folded in.
///
/// Returned unfolded so that a caller summing several products can sum these
/// three and fold, shift and reduce once: every step after the multiplies is
/// linear over GF(2), so reducing a sum is the sum of the reductions.
#[inline]
#[target_feature(enable = "pclmulqdq,ssse3")]
fn product(a: __m128i, b: __m128i) -> (__m128i, __m128i, __m128i) {
    (
        _mm_clmulepi64_si128(a, b, 0x00),
        _mm_xor_si128(
            _mm_clmulepi64_si128(a, b, 0x10),
            _mm_clmulepi64_si128(a, b, 0x01),
        ),
        _mm_clmulepi64_si128(a, b, 0x11),
    )
}

/// Fold `mid` into the 256-bit product, undo the reflection's one-bit offset,
/// and reduce modulo `x^128 + x^7 + x^2 + x + 1`.
#[inline]
#[target_feature(enable = "pclmulqdq,ssse3")]
fn reduce(lo: __m128i, mid: __m128i, hi: __m128i) -> __m128i {
    let mut lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    let mut hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    // The reflected representation puts the product one bit low; shift the
    // whole 256-bit value left by one to line it back up.
    let carry_lo = _mm_srli_epi32(lo, 31);
    let carry_hi = _mm_srli_epi32(hi, 31);
    lo = _mm_slli_epi32(lo, 1);
    hi = _mm_slli_epi32(hi, 1);
    lo = _mm_or_si128(lo, _mm_slli_si128(carry_lo, 4));
    hi = _mm_or_si128(hi, _mm_slli_si128(carry_hi, 4));
    hi = _mm_or_si128(hi, _mm_srli_si128(carry_lo, 12));

    // The three shifts fold the top half down; the second group completes the
    // reduction.
    let t = _mm_xor_si128(
        _mm_xor_si128(_mm_slli_epi32(lo, 31), _mm_slli_epi32(lo, 30)),
        _mm_slli_epi32(lo, 25),
    );
    let spill = _mm_srli_si128(t, 4);
    lo = _mm_xor_si128(lo, _mm_slli_si128(t, 12));

    let fold = _mm_xor_si128(
        _mm_xor_si128(_mm_srli_epi32(lo, 1), _mm_srli_epi32(lo, 2)),
        _mm_xor_si128(_mm_srli_epi32(lo, 7), spill),
    );
    lo = _mm_xor_si128(lo, fold);
    _mm_xor_si128(hi, lo)
}

/// Multiply `x` by `h` in GCM's GF(2^128), in place.
///
/// # Safety
///
/// Requires the `pclmulqdq` and `ssse3` target features. The intrinsics
/// themselves are safe once those are enabled in scope, so only the
/// raw-pointer loads and stores below are wrapped in an `unsafe` block.
#[target_feature(enable = "pclmulqdq,ssse3")]
pub unsafe fn mul(x: &mut [u8; 16], h: &[u8; 16]) {
    let mask = byte_swap();

    // SAFETY: both operands are exactly 16 bytes and the loads are unaligned.
    let (a, b) = unsafe {
        (
            _mm_shuffle_epi8(_mm_loadu_si128(x.as_ptr() as *const __m128i), mask),
            _mm_shuffle_epi8(_mm_loadu_si128(h.as_ptr() as *const __m128i), mask),
        )
    };
    let (lo, mid, hi) = product(a, b);
    let result = reduce(lo, mid, hi);

    // SAFETY: `x` is exactly 16 bytes and the store is unaligned.
    unsafe {
        _mm_storeu_si128(
            x.as_mut_ptr() as *mut __m128i,
            _mm_shuffle_epi8(result, mask),
        );
    }
}

/// Absorb `blocks` into the GHASH accumulator `acc`, eight blocks at a time.
///
/// `powers[i]` is `H^(i+1)`, in GCM byte order. Each group of eight is
/// `Y' = (Y ^ X0)*H^8 ^ X1*H^7 ^ .. ^ X7*H`: eight independent products,
/// summed unreduced and reduced once.
///
/// Where the time went before: the four-block path called [`mul`] per
/// product, and every call byte-swapped `H` again, reduced its own product,
/// and passed the result back through memory; `mul` cannot inline into a
/// caller built without these features. Measured on a 16 KiB buffer that was
/// about 29 cycles a block and three quarters of AES-128-GCM. Here the powers
/// are swapped once per call, the accumulator stays in a register for the
/// whole buffer, and a block costs four multiplies and its share of one
/// reduction.
///
/// # Safety
///
/// Requires the `pclmulqdq` and `ssse3` target features. `blocks.len()` must
/// be a multiple of 128; the caller handles the tail.
#[target_feature(enable = "pclmulqdq,ssse3")]
pub unsafe fn absorb8(acc: &mut [u8; 16], powers: &[[u8; 16]; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % 128, 0);
    let mask = byte_swap();
    let mut h = [_mm_setzero_si128(); 8];
    for (slot, p) in h.iter_mut().zip(powers) {
        // SAFETY: each power is exactly 16 bytes and the load is unaligned.
        *slot = _mm_shuffle_epi8(
            unsafe { _mm_loadu_si128(p.as_ptr() as *const __m128i) },
            mask,
        );
    }
    // SAFETY: `acc` is exactly 16 bytes and the load is unaligned.
    let mut y = _mm_shuffle_epi8(
        unsafe { _mm_loadu_si128(acc.as_ptr() as *const __m128i) },
        mask,
    );

    for group in blocks.chunks_exact(128) {
        let p = group.as_ptr();
        let (mut lo, mut mid, mut hi) = (
            _mm_setzero_si128(),
            _mm_setzero_si128(),
            _mm_setzero_si128(),
        );
        for i in 0..8 {
            // SAFETY: `group` is exactly 128 bytes, so block `i` is in bounds,
            // and the load is unaligned.
            let mut x = _mm_shuffle_epi8(
                unsafe { _mm_loadu_si128(p.add(i * 16) as *const __m128i) },
                mask,
            );
            if i == 0 {
                x = _mm_xor_si128(x, y);
            }
            // The oldest block takes the highest power.
            let (l, m, u) = product(x, h[7 - i]);
            lo = _mm_xor_si128(lo, l);
            mid = _mm_xor_si128(mid, m);
            hi = _mm_xor_si128(hi, u);
        }
        y = reduce(lo, mid, hi);
    }

    // SAFETY: `acc` is exactly 16 bytes and the store is unaligned.
    unsafe {
        _mm_storeu_si128(acc.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(y, mask));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcm::portable_ghash_mul;

    fn available() -> bool {
        std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("ssse3")
    }

    /// A tiny xorshift, so the differential test covers a wide spread of
    /// inputs without pulling in an RNG.
    fn pseudo_random(seed: &mut u64) -> [u8; 16] {
        let mut out = [0u8; 16];
        for chunk in out.chunks_mut(8) {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            chunk.copy_from_slice(&seed.to_be_bytes());
        }
        out
    }

    /// The accelerated multiply must agree with the portable one exactly. The
    /// portable one is validated by the GCM specification vectors, so this is
    /// what makes the acceleration trustworthy.
    #[test]
    fn matches_the_portable_multiply() {
        if !available() {
            return;
        }
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        for i in 0..512 {
            let x = pseudo_random(&mut seed);
            let h = pseudo_random(&mut seed);

            let mut a = x;
            let mut b = x;
            portable_ghash_mul(&mut a, &h);
            // SAFETY: guarded by the runtime feature check above.
            unsafe { mul(&mut b, &h) };
            assert_eq!(a, b, "mismatch on iteration {i}");
        }
    }

    /// Structural cases the random sweep might not reach.
    #[test]
    fn matches_on_edge_cases() {
        if !available() {
            return;
        }
        let mut one = [0u8; 16];
        one[0] = 0x80; // the multiplicative identity in GCM's bit order.
        let cases: [[u8; 16]; 5] = [
            [0u8; 16],
            one,
            [0xffu8; 16],
            {
                let mut v = [0u8; 16];
                v[15] = 1;
                v
            },
            {
                let mut v = [0u8; 16];
                v[0] = 1;
                v
            },
        ];

        for x in cases {
            for h in cases {
                let mut a = x;
                let mut b = x;
                portable_ghash_mul(&mut a, &h);
                // SAFETY: guarded by the runtime feature check above.
                unsafe { mul(&mut b, &h) };
                assert_eq!(a, b, "x={x:02x?} h={h:02x?}");
            }
        }
    }

    /// Multiplying by the identity must be a no-op, which pins down the bit
    /// ordering independently of the portable implementation.
    #[test]
    fn identity_is_a_no_op() {
        if !available() {
            return;
        }
        let mut one = [0u8; 16];
        one[0] = 0x80;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..32 {
            let x = pseudo_random(&mut seed);
            let mut got = x;
            // SAFETY: guarded by the runtime feature check above.
            unsafe { mul(&mut got, &one) };
            assert_eq!(got, x);
        }
    }
}
