//! The x86-64 AES-NI backend.
//!
//! # What is and is not reimplemented here
//!
//! Only the *round function* is accelerated. Key expansion stays in
//! [`portable::Schedule`][super::portable::Schedule], and this backend loads
//! its output into SIMD registers. Expansion happens once per key and is not on
//! the hot path, so a second implementation of it would buy nothing and risk a
//! divergence — particularly for AES-192, whose SIMD key schedule is the
//! fiddliest part of a typical AES-NI implementation.
//!
//! Decryption uses the equivalent inverse cipher: the encryption round keys are
//! passed through `AESIMC` and reversed at construction, which is what lets
//! `AESDEC` run the inverse rounds in the same shape as the forward ones.
//!
//! # Safety
//!
//! These functions are `unsafe` because `#[target_feature]` requires it: a
//! caller must not invoke them on a CPU without AES-NI. The intrinsics
//! themselves are safe once that feature is enabled in scope, so the only
//! genuinely unsafe operations are the raw-pointer loads and stores — and those
//! are the only things wrapped in an `unsafe` block.
//!
//! # Constant-time properties
//!
//! `AESENC` and friends are single instructions with data-independent latency,
//! so this backend is constant-time for the same reason the portable one is —
//! and it never touches a lookup table at all.

use super::portable::{Schedule, BLOCK_LEN};
use ic_core::{ensure, Result, Zeroize};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// How many blocks the batch path processes at once.
///
/// `AESENC` has a latency of around four cycles but is fully pipelined, so
/// interleaving eight independent blocks keeps the unit busy instead of
/// stalling on each result. This is where most of the speedup over the portable
/// backend comes from in CTR and GCM.
pub const PARALLEL_BLOCKS: usize = 8;

/// AES round keys held in SIMD registers.
#[derive(Clone, Copy)]
pub struct Keys {
    enc: [__m128i; 15],
    dec: [__m128i; 15],
    rounds: usize,
}

impl Keys {
    /// Load an expanded schedule into SIMD registers.
    ///
    /// # Safety
    ///
    /// The caller must ensure the `aes` and `sse2` target features are
    /// available on this CPU.
    #[target_feature(enable = "aes")]
    pub unsafe fn load(sched: &Schedule) -> Keys {
        let rounds = sched.rounds;
        let mut enc = [_mm_setzero_si128(); 15];
        let mut dec = [_mm_setzero_si128(); 15];

        for (r, slot) in enc.iter_mut().enumerate().take(rounds + 1) {
            let rk = sched.round_key(r);
            // SAFETY: `round_key` always returns exactly BLOCK_LEN bytes, and
            // the unaligned load has no alignment requirement.
            *slot = unsafe { _mm_loadu_si128(rk.as_ptr() as *const __m128i) };
        }

        // Equivalent inverse cipher: reverse the round keys and apply AESIMC to
        // everything except the first and last.
        dec[0] = enc[rounds];
        for i in 1..rounds {
            dec[i] = _mm_aesimc_si128(enc[rounds - i]);
        }
        dec[rounds] = enc[0];

        Keys { enc, dec, rounds }
    }

    /// Encrypt one block in registers.
    ///
    /// # Safety
    ///
    /// Requires the `aes` target feature.
    #[target_feature(enable = "aes")]
    #[inline]
    unsafe fn encrypt(&self, block: __m128i) -> __m128i {
        let mut b = _mm_xor_si128(block, self.enc[0]);
        for r in 1..self.rounds {
            b = _mm_aesenc_si128(b, self.enc[r]);
        }
        _mm_aesenclast_si128(b, self.enc[self.rounds])
    }

    /// Decrypt one block in registers.
    ///
    /// # Safety
    ///
    /// Requires the `aes` target feature.
    #[target_feature(enable = "aes")]
    #[inline]
    unsafe fn decrypt(&self, block: __m128i) -> __m128i {
        let mut b = _mm_xor_si128(block, self.dec[0]);
        for r in 1..self.rounds {
            b = _mm_aesdec_si128(b, self.dec[r]);
        }
        _mm_aesdeclast_si128(b, self.dec[self.rounds])
    }
}

/// Encrypt one block in place.
///
/// # Safety
///
/// Requires the `aes` target feature.
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_block(keys: &Keys, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    // SAFETY: `block` is exactly BLOCK_LEN bytes, checked above; the loads and
    // stores are unaligned and so have no alignment requirement.
    unsafe {
        let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let out = keys.encrypt(b);
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, out);
    }
    Ok(())
}

/// Decrypt one block in place.
///
/// # Safety
///
/// Requires the `aes` target feature.
#[target_feature(enable = "aes")]
pub unsafe fn decrypt_block(keys: &Keys, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    // SAFETY: as above.
    unsafe {
        let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let out = keys.decrypt(b);
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, out);
    }
    Ok(())
}

/// Encrypt a whole number of blocks in place, eight at a time.
///
/// # Safety
///
/// Requires the `aes` target feature.
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_blocks(keys: &Keys, data: &mut [u8]) -> Result<()> {
    ensure!(
        data.len().is_multiple_of(BLOCK_LEN),
        InvalidLength,
        "aes batch must be block-aligned"
    );

    let mut chunks = data.chunks_exact_mut(BLOCK_LEN * PARALLEL_BLOCKS);
    for chunk in &mut chunks {
        let p = chunk.as_mut_ptr();
        let mut b = [_mm_setzero_si128(); PARALLEL_BLOCKS];

        // SAFETY: the chunk is exactly PARALLEL_BLOCKS * BLOCK_LEN bytes, so
        // every offset below is in bounds, and the loads are unaligned.
        unsafe {
            for (i, slot) in b.iter_mut().enumerate() {
                *slot = _mm_loadu_si128(p.add(i * BLOCK_LEN) as *const __m128i);
            }
        }

        // Interleave the rounds across all eight blocks so the pipeline stays
        // full rather than waiting on each AESENC.
        for slot in b.iter_mut() {
            *slot = _mm_xor_si128(*slot, keys.enc[0]);
        }
        for r in 1..keys.rounds {
            let rk = keys.enc[r];
            for slot in b.iter_mut() {
                *slot = _mm_aesenc_si128(*slot, rk);
            }
        }
        let last = keys.enc[keys.rounds];
        for slot in b.iter_mut() {
            *slot = _mm_aesenclast_si128(*slot, last);
        }

        // SAFETY: same bounds as the loads above.
        unsafe {
            for (i, slot) in b.iter().enumerate() {
                _mm_storeu_si128(p.add(i * BLOCK_LEN) as *mut __m128i, *slot);
            }
        }
    }

    // Whatever is left over is fewer than PARALLEL_BLOCKS blocks.
    for block in chunks.into_remainder().chunks_exact_mut(BLOCK_LEN) {
        // SAFETY: the caller established the `aes` feature for this call.
        unsafe { encrypt_block(keys, block)? };
    }
    Ok(())
}

/// XOR `data` with the CTR keystream starting at `counter`, advancing the
/// counter's last 32 bits big-endian and wrapping within them -- GCM's
/// `inc32` -- eight blocks at a time.
///
/// GCM used to reach AES through `encrypt_blocks` eight blocks per call, with
/// the counters built and the keystream XORed byte by byte around each call:
/// 8.5 GiB/s where one call over the whole buffer runs at 15. Here the
/// counters are written straight into the blocks, the keystream never leaves
/// registers on the whole-block path, and there is one call per message.
///
/// The counter blocks are assembled with plain stores rather than a byte
/// shuffle, so this needs nothing beyond the `aes` feature the caller already
/// checked; building eight 16-byte blocks is noise beside eighty `AESENC`s.
///
/// On return `counter` is the block after the last one used.
///
/// # Safety
///
/// Requires the `aes` target feature.
#[target_feature(enable = "aes")]
pub unsafe fn ctr32_xor(keys: &Keys, counter: &mut [u8; BLOCK_LEN], data: &mut [u8]) {
    let mut n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    let mut blocks = [[0u8; BLOCK_LEN]; PARALLEL_BLOCKS];
    for block in blocks.iter_mut() {
        block[..12].copy_from_slice(&counter[..12]);
    }

    for chunk in data.chunks_mut(BLOCK_LEN * PARALLEL_BLOCKS) {
        for (i, block) in blocks.iter_mut().enumerate() {
            block[12..].copy_from_slice(&n.wrapping_add(i as u32).to_be_bytes());
        }
        let mut b = [_mm_setzero_si128(); PARALLEL_BLOCKS];
        for (slot, block) in b.iter_mut().zip(blocks.iter()) {
            // SAFETY: `block` is exactly 16 bytes and the load is unaligned.
            *slot = _mm_xor_si128(
                unsafe { _mm_loadu_si128(block.as_ptr() as *const __m128i) },
                keys.enc[0],
            );
        }
        for r in 1..keys.rounds {
            let rk = keys.enc[r];
            for slot in b.iter_mut() {
                *slot = _mm_aesenc_si128(*slot, rk);
            }
        }
        let last = keys.enc[keys.rounds];
        for slot in b.iter_mut() {
            *slot = _mm_aesenclast_si128(*slot, last);
        }

        let p = chunk.as_mut_ptr();
        if chunk.len() == BLOCK_LEN * PARALLEL_BLOCKS {
            for (i, ks) in b.iter().enumerate() {
                // SAFETY: the chunk is exactly PARALLEL_BLOCKS blocks, so every
                // offset is in bounds; loads and stores are unaligned.
                unsafe {
                    let d = _mm_loadu_si128(p.add(i * BLOCK_LEN) as *const __m128i);
                    _mm_storeu_si128(p.add(i * BLOCK_LEN) as *mut __m128i, _mm_xor_si128(d, *ks));
                }
            }
        } else {
            // The final, shorter chunk: through a buffer, and only as far as
            // the data goes. The keystream past the end is discarded.
            let mut stream = [0u8; BLOCK_LEN * PARALLEL_BLOCKS];
            for (i, ks) in b.iter().enumerate() {
                // SAFETY: `stream` holds PARALLEL_BLOCKS blocks.
                unsafe {
                    _mm_storeu_si128(stream.as_mut_ptr().add(i * BLOCK_LEN) as *mut __m128i, *ks)
                };
            }
            for (d, k) in chunk.iter_mut().zip(stream.iter()) {
                *d ^= k;
            }
            stream.zeroize();
        }
        n = n.wrapping_add(chunk.len().div_ceil(BLOCK_LEN) as u32);
    }
    counter[12..].copy_from_slice(&n.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::portable;

    fn available() -> bool {
        std::arch::is_x86_feature_detected!("aes")
    }

    /// The whole point of this backend is that it agrees with the portable one
    /// exactly. This is the differential test that makes the acceleration safe
    /// to trust: the portable path is validated against FIPS 197 vectors, and
    /// this asserts bit-for-bit equality with it.
    #[test]
    fn matches_the_portable_backend_on_every_key_length() {
        if !available() {
            return;
        }
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| (i * 7 + 1) as u8).collect();
            let sched = portable::Schedule::expand(&key).unwrap();
            // SAFETY: guarded by the runtime feature check above.
            let keys = unsafe { Keys::load(&sched) };

            for seed in 0..64u8 {
                let original: [u8; 16] =
                    core::array::from_fn(|i| seed ^ (i as u8).wrapping_mul(31));

                let mut a = original;
                let mut b = original;
                portable::encrypt_block(&sched, &mut a).unwrap();
                unsafe { encrypt_block(&keys, &mut b).unwrap() };
                assert_eq!(a, b, "encrypt mismatch, key_len {key_len}, seed {seed}");

                let mut a = original;
                let mut b = original;
                portable::decrypt_block(&sched, &mut a).unwrap();
                unsafe { decrypt_block(&keys, &mut b).unwrap() };
                assert_eq!(a, b, "decrypt mismatch, key_len {key_len}, seed {seed}");
            }
        }
    }

    /// The batch path must agree with the single-block path, including at the
    /// boundary where the eight-way loop hands off to the remainder.
    #[test]
    fn batch_matches_single_block_at_every_length() {
        if !available() {
            return;
        }
        let sched = portable::Schedule::expand(&[0x2bu8; 32]).unwrap();
        // SAFETY: guarded by the runtime feature check above.
        let keys = unsafe { Keys::load(&sched) };

        for blocks in 0..=(PARALLEL_BLOCKS * 2 + 3) {
            let data: Vec<u8> = (0..blocks * BLOCK_LEN).map(|i| (i * 13) as u8).collect();

            let mut batched = data.clone();
            unsafe { encrypt_blocks(&keys, &mut batched).unwrap() };

            let mut one_at_a_time = data.clone();
            for block in one_at_a_time.chunks_exact_mut(BLOCK_LEN) {
                unsafe { encrypt_block(&keys, block).unwrap() };
            }

            assert_eq!(batched, one_at_a_time, "{blocks} blocks");
        }
    }

    #[test]
    fn batch_rejects_unaligned_input() {
        if !available() {
            return;
        }
        let sched = portable::Schedule::expand(&[0u8; 16]).unwrap();
        // SAFETY: guarded by the runtime feature check above.
        let keys = unsafe { Keys::load(&sched) };
        let mut data = [0u8; BLOCK_LEN + 1];
        assert!(unsafe { encrypt_blocks(&keys, &mut data) }.is_err());
    }

    /// Decryption inverts encryption within the accelerated backend itself.
    #[test]
    fn decryption_inverts_encryption() {
        if !available() {
            return;
        }
        let sched = portable::Schedule::expand(&[0x42u8; 24]).unwrap();
        // SAFETY: guarded by the runtime feature check above.
        let keys = unsafe { Keys::load(&sched) };
        let original: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut block = original;
        unsafe {
            encrypt_block(&keys, &mut block).unwrap();
            assert_ne!(block, original);
            decrypt_block(&keys, &mut block).unwrap();
        }
        assert_eq!(block, original);
    }
}
