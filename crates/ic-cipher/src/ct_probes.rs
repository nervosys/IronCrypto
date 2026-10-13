//! The x86-64 ChaCha20 and Poly1305 kernels, for `scripts/ct-audit` to
//! inspect after LTO. Not API, not covered by semver; behind the `ct-probes`
//! feature.
//!
//! Each is one straight-line piece: a sixteen-block keystream group, one
//! four-lane Poly1305 step, and the lanes' final multiplication and folding.
//! What the library composes from them adds only loops over the message
//! length, which is public. Never executed: they need AVX-512F or AVX2, and
//! are compiled to be read.

#[cfg(target_arch = "x86_64")]
pub use x86::*;

#[cfg(target_arch = "x86_64")]
mod x86 {
    use crate::chacha::{poly_avx2, zmm};
    use core::arch::x86_64::*;
    use core::mem::ManuallyDrop;

    /// Sixteen ChaCha20 blocks from `counter`, xored into `data`.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX-512F.
    pub unsafe fn chacha20_zmm_group(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8; zmm::STRIDE],
    ) {
        // Not dropped, so the probe holds the kernel and its constructor and
        // not the wipe's loop, which is over a fixed sixteen words.
        let start = ManuallyDrop::new(zmm::Start::new(key, nonce, counter));
        // SAFETY: as the caller guarantees.
        unsafe { zmm::group(&start, data) }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn limbs(h: &[[u64; 4]; 5]) -> poly_avx2::Limbs {
        // SAFETY: each row is 32 bytes, the width of the load.
        core::array::from_fn(|j| unsafe { _mm256_loadu_si256(h[j].as_ptr() as *const __m256i) })
    }

    /// One four-lane Poly1305 step: `h * r^4 + blocks`, carried.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn poly1305_avx2_step(
        h: &[[u64; 4]; 5],
        r4: &[u32; 5],
        blocks: &[u8; 64],
    ) -> [[u64; 4]; 5] {
        // SAFETY: AVX2, as the caller guarantees.
        let next = unsafe { poly_avx2::step(&limbs(h), &poly_avx2::Mul::splat(r4), blocks) };
        let mut out = [[0u64; 4]; 5];
        for (o, v) in out.iter_mut().zip(next) {
            // SAFETY: each row is 32 bytes, the width of the store.
            unsafe { _mm256_storeu_si256(o.as_mut_ptr() as *mut __m256i, v) };
        }
        out
    }

    /// The last multiplication, by a different power in each lane, and the
    /// sum of the lanes.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn poly1305_avx2_finish(h: &[[u64; 4]; 5], powers: &[[u32; 5]; 4]) -> [u64; 5] {
        let last = poly_avx2::Mul::lanes([&powers[0], &powers[1], &powers[2], &powers[3]]);
        // SAFETY: AVX2, as the caller guarantees.
        unsafe { poly_avx2::finish(&limbs(h), &last) }
    }
}
