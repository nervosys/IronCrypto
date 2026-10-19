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

/// The 128-, 256- and 512-bit AES-GCM loops (`gcm_x86_asm`) at AES-256, and
/// the twist of a power of `H`. Each seal and open runs its loop over a fixed
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

    /// Sixteen powers of `H` (or their Karatsuba factors) for the 512-bit
    /// kernel, aligned to a cache line as its `zmm` loads are.
    #[repr(C, align(64))]
    pub struct ZmmPowers(pub [[u8; 16]; 16]);

    /// Thirty-two powers of `H` (or their Karatsuba factors) for the 512-bit
    /// kernel's thirty-two-block loop, aligned as [`ZmmPowers`].
    #[repr(C, align(64))]
    pub struct ZmmPowers32(pub [[u8; 16]; 32]);

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

    /// [`gcm_vaes256_seal`] on the 512-bit kernel: three groups of sixteen
    /// blocks.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX-512F, AVX-512BW, VAES and VPCLMULQDQ.
    pub unsafe fn gcm_vaes512_seal(
        data: &mut [u8; 768],
        rk: &[__m128i; 15],
        pw: &ZmmPowers,
        pk: &ZmmPowers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: the caller has the features. `data` is three 256-byte groups;
        // `rk` is the 15 round keys of AES-256 with round key 14 last, so
        // `rk_last` and `rounds` (14) are its; `pw` and `pk` are 256 bytes;
        // `st` is 32.
        unsafe {
            k::zmm_groups::<true>(
                data.as_mut_ptr(),
                3,
                rk.as_ptr().cast(),
                rk.as_ptr().add(14).cast(),
                14,
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// [`gcm_vaes256_open`] on the 512-bit kernel.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX-512F, AVX-512BW, VAES and VPCLMULQDQ.
    pub unsafe fn gcm_vaes512_open(
        data: &mut [u8; 768],
        rk: &[__m128i; 15],
        pw: &ZmmPowers,
        pk: &ZmmPowers,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::zmm_groups::<false>(
                data.as_mut_ptr(),
                3,
                rk.as_ptr().cast(),
                rk.as_ptr().add(14).cast(),
                14,
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// [`gcm_vaes512_seal`] on the thirty-two-block loop: two groups of
    /// thirty-two blocks, `zmm32_groups`.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX-512F, AVX-512BW, VAES and VPCLMULQDQ.
    pub unsafe fn gcm_vaes512x32_seal(
        data: &mut [u8; 1024],
        rk: &[__m128i; 15],
        pw: &ZmmPowers32,
        pk: &ZmmPowers32,
        st: &mut [u8; 32],
    ) {
        // SAFETY: the caller has the features. `data` is two 512-byte groups;
        // `rk` and the rounds are as in `gcm_vaes512_seal`; `pw` and `pk` are
        // 512 bytes; `st` is 32.
        unsafe {
            k::zmm32_groups::<true>(
                data.as_mut_ptr(),
                2,
                rk.as_ptr().cast(),
                rk.as_ptr().add(14).cast(),
                14,
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
        }
    }

    /// [`gcm_vaes512x32_seal`] opening.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX-512F, AVX-512BW, VAES and VPCLMULQDQ.
    pub unsafe fn gcm_vaes512x32_open(
        data: &mut [u8; 1024],
        rk: &[__m128i; 15],
        pw: &ZmmPowers32,
        pk: &ZmmPowers32,
        st: &mut [u8; 32],
    ) {
        // SAFETY: as above.
        unsafe {
            k::zmm32_groups::<false>(
                data.as_mut_ptr(),
                2,
                rk.as_ptr().cast(),
                rk.as_ptr().add(14).cast(),
                14,
                pw.0.as_ptr().cast(),
                pk.0.as_ptr().cast(),
                st.as_mut_ptr(),
            )
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
    use crate::chacha::{avx2, poly64, poly_avx2, zmm};
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

    /// # Safety
    ///
    /// The CPU must support AVX2. Its only callers, `poly1305_avx2_step` and
    /// `poly1305_avx2_finish`, are `unsafe` and carry the same requirement.
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

    /// Two ChaCha20 blocks on AVX2, side by side in each register: the short
    /// messages' kernel, which gives an AEAD its Poly1305 key and its first
    /// block of keystream.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    pub unsafe fn chacha20_avx2_pair(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        out: &mut [u8; 128],
    ) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::pair(key, nonce, counter, out) }
    }

    /// Four ChaCha20 blocks on AVX2, as two such pairs.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    pub unsafe fn chacha20_avx2_two_pairs(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        out: &mut [u8; 256],
    ) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::two_pairs(key, nonce, counter, out) }
    }

    /// The eight-block kernel's keystream scratch, as the library holds it.
    /// The probe takes it from its caller, so the probe itself zeroes and
    /// wipes nothing; the library's wipe is `Scratch`'s, outside the kernel.
    #[repr(C, align(32))]
    pub struct Ws8(avx2::Words);

    /// Eight ChaCha20 blocks on AVX2, xored into `out`, the keystream going
    /// through `ws`: the message kernel the library runs over whole 512-byte
    /// groups.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    pub unsafe fn chacha20_avx2_eight_blocks(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        out: &mut [u8; 512],
        ws: &mut Ws8,
    ) {
        // SAFETY: as the caller guarantees; `out` is `avx2::STRIDE` bytes.
        unsafe { avx2::eight_blocks(key, nonce, counter, out, &mut ws.0) }
    }

    /// The AEAD's tag in radix 2^64, under the one-time key `key`, over
    /// thirteen bytes of associated data and sixty-four of ciphertext -- a
    /// TLS 1.2 record's header and a short record -- so that both the padded
    /// partial block and the whole blocks are in the code read. No feature
    /// needed: `MUL`, `ADC` and masks.
    pub fn poly1305_short(key: &[u8; 32], aad: &[u8; 13], ct: &[u8; 64]) -> [u8; 16] {
        poly64::aead_tag(key, aad, ct)
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

/// The ARMv8 probe wrappers, executed. The audit only reads them; these run
/// each one on fixed inputs and hold it to an independent answer, so a wrapper
/// that compiles but computes the wrong thing fails here. Needs the
/// instructions, so it runs under QEMU (`scripts/test-aarch64.sh`), and asserts
/// the detection rather than skipping: a probe that never ran is not a pass.
#[cfg(all(test, target_arch = "aarch64", feature = "aarch64-crypto"))]
mod armv8_probe_tests {
    use super::armv8::*;
    use crate::aes::portable;
    use crate::armv8_ghash_model::tests::check_mul;
    use crate::gcm::portable_ghash_mul;

    /// FIPS 197, Appendix C.3: AES-256, key 00 01 .. 1f, plaintext
    /// 00 11 22 .. ff, ciphertext 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89.
    const C3_CIPHERTEXT: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    /// The expanded AES-256 schedule as the probes take it: fifteen round keys
    /// of sixteen bytes, in order.
    fn round_keys(sched: &portable::Schedule) -> [u8; 240] {
        let mut out = [0u8; 240];
        for (r, chunk) in out.chunks_exact_mut(16).enumerate() {
            chunk.copy_from_slice(sched.round_key(r));
        }
        out
    }

    #[test]
    fn aes256_probes_match_fips197_and_the_portable_backend() {
        assert!(
            crate::aes::armv8_aes_available(),
            "no ARMv8 AES instructions: the probes were not run"
        );
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let sched = portable::Schedule::expand(&key).unwrap();
        let rk = round_keys(&sched);
        let plain: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x11));

        let mut enc = plain;
        // SAFETY: guarded by the detection above.
        unsafe { aes256_armv8_encrypt(&rk, &mut enc) };
        assert_eq!(
            enc, C3_CIPHERTEXT,
            "aes256_armv8_encrypt against FIPS 197 C.3"
        );

        let mut dec = C3_CIPHERTEXT;
        // SAFETY: guarded by the detection above.
        unsafe { aes256_armv8_decrypt(&rk, &mut dec) };
        assert_eq!(dec, plain, "aes256_armv8_decrypt against FIPS 197 C.3");

        // Other blocks, against the portable backend.
        for seed in 0..8u8 {
            let block: [u8; 16] =
                core::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8));
            let mut want = block;
            portable::encrypt_block(&sched, &mut want).unwrap();
            let mut got = block;
            // SAFETY: guarded by the detection above.
            unsafe { aes256_armv8_encrypt(&rk, &mut got) };
            assert_eq!(got, want, "aes256_armv8_encrypt, seed {seed}");
        }

        // The four-block batch, which takes its own path through the rounds.
        let batch: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a);
        let mut want = batch;
        for block in want.chunks_exact_mut(16) {
            portable::encrypt_block(&sched, block).unwrap();
        }
        let mut got = batch;
        // SAFETY: guarded by the detection above.
        unsafe { aes256_armv8_encrypt4(&rk, &mut got) };
        assert_eq!(got, want, "aes256_armv8_encrypt4");
    }

    #[test]
    fn ghash_probes_match_the_portable_multiply() {
        assert!(
            ic_core::cpu::has_ghash_pmull(),
            "no PMULL: the probes were not run"
        );
        // SAFETY: guarded by the detection above.
        check_mul(|x, h| unsafe { ghash_pmull_mul(x, h) });

        // Eight powers of a fixed H, H^1 .. H^8, and three groups of eight
        // blocks, held to the serial portable absorb.
        let h: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x3b) ^ 0xa5);
        let mut powers = [h; 8];
        for i in 1..8 {
            let mut p = powers[i - 1];
            portable_ghash_mul(&mut p, &h);
            powers[i] = p;
        }
        let blocks: [u8; 384] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(7));
        let start: [u8; 16] = core::array::from_fn(|i| 0x80 ^ i as u8);
        let mut want = start;
        for block in blocks.chunks_exact(16) {
            for (w, b) in want.iter_mut().zip(block) {
                *w ^= b;
            }
            portable_ghash_mul(&mut want, &h);
        }
        let mut got = start;
        // SAFETY: guarded by the detection above.
        unsafe { ghash_pmull_absorb8(&mut got, &powers, &blocks) };
        assert_eq!(
            got, want,
            "ghash_pmull_absorb8 against the serial portable GHASH"
        );
    }
}
