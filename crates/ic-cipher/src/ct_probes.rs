//! The x86-64 ChaCha20, Poly1305 and AES-GCM kernels, and the ARMv8 AES and
//! `PMULL` GHASH backends, for `scripts/ct-audit` to inspect after LTO. Not API, not covered by semver; behind the
//! `ct-probes` feature.
//!
//! The ChaCha20 and Poly1305 ones are each one straight-line piece: a
//! sixteen-block keystream group, one four-lane Poly1305 step, and the lanes'
//! final multiplication and folding. The AES-GCM ones are the 128- and
//! 256-bit bulk loops over a fixed count of groups. What the library composes
//! from them adds only loops and choices over the message length, which is
//! public. Never executed: they need AVX-512F, AVX2, VAES or AES-NI, and are
//! compiled to be read.

#[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto"))]
pub use armv8::*;
#[cfg(target_arch = "x86_64")]
pub use gcm::*;
#[cfg(target_arch = "x86_64")]
pub use x86::*;

/// The 128- and 256-bit AES-GCM loops (`gcm_x86_asm`) at AES-256, and the
/// twist of a power of `H`. Each seal and open runs its loop over a fixed
/// count of groups; the loop's back edge is the only branch, and its counter
/// is that count. What the library adds around them -- choosing the call by
/// the message length -- branches only on lengths.
#[cfg(target_arch = "x86_64")]
mod gcm {
    use crate::gcm_x86_asm as k;
    use core::arch::x86_64::*;

    /// Sixteen powers of `H` (or their Karatsuba factors), aligned as the
    /// eight-block kernel's legacy-encoded memory operands require.
    #[repr(C, align(16))]
    pub struct Powers(pub [[u8; 16]; 16]);

    /// Three groups of eight blocks sealed: one alone, two stitched
    /// iterations, the last group hashed alone. `st` is the accumulator, then
    /// the counter.
    ///
    /// # Safety
    ///
    /// The CPU must have AES-NI, `PCLMULQDQ` and SSSE3.
    pub unsafe fn gcm_clmul8_seal(
        data: &mut [u8; 384],
        rk: &[__m128i; 15],
        pw: &Powers,
        pk: &Powers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as the caller guarantees; every region is the size the
        // kernel's contract names.
        unsafe {
            k::x8_seal::<14>(
                data.as_mut_ptr(),
                2,
                rk.as_ptr().cast(),
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// Three groups of eight blocks opened, each hashed by its own iteration.
    ///
    /// # Safety
    ///
    /// As [`gcm_clmul8_seal`].
    pub unsafe fn gcm_clmul8_open(
        data: &mut [u8; 384],
        rk: &[__m128i; 15],
        pw: &Powers,
        pk: &Powers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::x8_open::<14>(
                data.as_mut_ptr(),
                3,
                rk.as_ptr().cast(),
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// One group of eight blocks sealed alone, as a one-group message is:
    /// counter mode, then GHASH.
    ///
    /// # Safety
    ///
    /// As [`gcm_clmul8_seal`].
    pub unsafe fn gcm_clmul8_group(
        data: &mut [u8; 128],
        rk: &[__m128i; 15],
        pw: &Powers,
        pk: &Powers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::x8_aes::<14>(data.as_mut_ptr(), rk.as_ptr().cast(), st.as_mut_ptr());
            k::x8_ghash(
                data.as_ptr(),
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            );
        }
    }

    /// [`gcm_clmul8_seal`] on the sixteen-block kernel: three groups.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX2, `VAES` and `VPCLMULQDQ`.
    pub unsafe fn gcm_vaes256_seal(
        data: &mut [u8; 768],
        rk: &[__m128i; 15],
        pw: &Powers,
        pk: &Powers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::y16_seal::<14>(
                data.as_mut_ptr(),
                2,
                rk.as_ptr().cast(),
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// [`gcm_clmul8_open`] on the sixteen-block kernel.
    ///
    /// # Safety
    ///
    /// As [`gcm_vaes256_seal`].
    pub unsafe fn gcm_vaes256_open(
        data: &mut [u8; 768],
        rk: &[__m128i; 15],
        pw: &Powers,
        pk: &Powers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::y16_open::<14>(
                data.as_mut_ptr(),
                3,
                rk.as_ptr().cast(),
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// [`gcm_clmul8_group`] on the sixteen-block kernel.
    ///
    /// # Safety
    ///
    /// As [`gcm_vaes256_seal`].
    pub unsafe fn gcm_vaes256_group(
        data: &mut [u8; 256],
        rk: &[__m128i; 15],
        pw: &Powers,
        pk: &Powers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::y16_aes::<14>(data.as_mut_ptr(), rk.as_ptr().cast(), st.as_mut_ptr());
            k::y16_ghash(
                data.as_ptr(),
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            );
        }
    }

    /// A power of `H` multiplied by `x^-1`, as the key setup twists each one:
    /// a shift and a masked XOR, on a secret's top bit.
    pub fn gcm_twist(h: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        // SAFETY: both are 16 bytes; the load and store are unaligned. SSE2
        // is part of x86-64.
        unsafe {
            let t = k::twist(_mm_loadu_si128(h.as_ptr().cast()));
            _mm_storeu_si128(out.as_mut_ptr().cast(), t);
        }
        out
    }
}

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

/// The ARMv8 AES and `PMULL` GHASH backends (`aes::aarch64`, `pmull`), for
/// the `aarch64-unknown-linux-gnu` target of `scripts/check-ct.py`. AES is
/// held at AES-256, fourteen rounds, so the round count is a constant in the
/// code read; the library's own branches on it are on the key length.
/// Compiled to be read, never run by the audit.
#[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto"))]
mod armv8 {
    use crate::aes::aarch64::{self as aes, Keys};
    use crate::aes::portable::Schedule;
    use crate::pmull;

    /// The ARM path's key setup after expansion: the round keys into
    /// registers and the equivalent inverse cipher's keys through `AESIMC`.
    /// Read inlined into the probes below, not on its own: returning the
    /// keys would copy them out with a call to `memcpy`.
    ///
    /// # Safety
    ///
    /// The CPU must have the AES instructions.
    #[target_feature(enable = "neon,aes")]
    #[inline]
    unsafe fn aes256_armv8_load(round_keys: &[u8; 240]) -> Keys {
        let sched = Schedule::from_aes256_round_keys(round_keys);
        // SAFETY: as the caller guarantees.
        unsafe { Keys::load(&sched) }
    }

    /// One block encrypted under an AES-256 key, loaded as above.
    ///
    /// # Safety
    ///
    /// As [`aes256_armv8_load`].
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn aes256_armv8_encrypt(round_keys: &[u8; 240], block: &mut [u8; 16]) {
        // SAFETY: as the caller guarantees.
        unsafe {
            let keys = aes256_armv8_load(round_keys);
            // The length is the block's, so this cannot fail.
            let _ = aes::encrypt_block(&keys, block);
        }
    }

    /// One block decrypted under an AES-256 key, loaded as above.
    ///
    /// # Safety
    ///
    /// As [`aes256_armv8_load`].
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn aes256_armv8_decrypt(round_keys: &[u8; 240], block: &mut [u8; 16]) {
        // SAFETY: as the caller guarantees.
        unsafe {
            let keys = aes256_armv8_load(round_keys);
            let _ = aes::decrypt_block(&keys, block);
        }
    }

    /// One batch of `PARALLEL_BLOCKS` (four) blocks encrypted together, the
    /// path counter mode takes.
    ///
    /// # Safety
    ///
    /// As [`aes256_armv8_load`].
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn aes256_armv8_encrypt4(round_keys: &[u8; 240], data: &mut [u8; 64]) {
        // SAFETY: as the caller guarantees.
        unsafe {
            let keys = aes256_armv8_load(round_keys);
            let _ = aes::encrypt_blocks(&keys, data);
        }
    }

    /// One GHASH multiplication, `x = x * h`, on `PMULL`.
    ///
    /// # Safety
    ///
    /// The CPU must have `PMULL` (the `aes` feature).
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn ghash_pmull_mul(x: &mut [u8; 16], h: &[u8; 16]) {
        // SAFETY: as the caller guarantees.
        unsafe { pmull::mul(x, h) }
    }

    /// Three groups of eight blocks absorbed against eight powers of `H`.
    ///
    /// # Safety
    ///
    /// As [`ghash_pmull_mul`].
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn ghash_pmull_absorb8(
        acc: &mut [u8; 16],
        powers: &[[u8; 16]; 8],
        blocks: &[u8; 384],
    ) {
        // SAFETY: as the caller guarantees.
        unsafe { pmull::absorb8(acc, powers, blocks) }
    }
}
