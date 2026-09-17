//! The ARMv8 cryptographic extension backend for AES.
//!
//! # This has never been executed by its author
//!
//! It was written and cross-compiled on an x86-64 machine. Every other backend
//! in this library was run before it was committed; this one was not, and that
//! is why it is behind the off-by-default `aarch64-crypto` feature rather than
//! selected automatically the way AES-NI is.
//!
//! CI runs the workspace with `--all-features` on `macos-latest`, which is
//! arm64, so the differential tests below do execute on real hardware there.
//! When that has passed, the feature can become the default on aarch64. Until
//! then an ARM build keeps using the portable backend, which is slower and
//! known to be right — the correct way round for a library nobody has a reason
//! to trust yet.
//!
//! # How this differs from the x86 backend
//!
//! The two architectures divide the round differently, and translating one to
//! the other by intuition produces something that is wrong in a way test
//! vectors catch and casual reading does not.
//!
//! - x86 `AESENC(state, key)` performs ShiftRows, SubBytes, MixColumns, and
//!   *then* adds the round key.
//! - ARM `AESE(state, key)` adds the round key *first*, then does SubBytes and
//!   ShiftRows, and leaves MixColumns to a separate `AESMC`.
//!
//! So the ARM loop is `AESMC(AESE(state, rk[r]))` for the middle rounds, a bare
//! `AESE` for the last, and an explicit XOR of the final round key — which x86
//! gets for free from `AESENCLAST`. The same shift applies to decryption, where
//! the round keys are used in plain reverse order and `AESIMC` is applied to
//! the *state* rather than pre-applied to the keys as it is on x86.
//!
//! # Scope: AES only
//!
//! This accelerates the block cipher and nothing else. There is no `PMULL`
//! GHASH backend, so AES-GCM on ARM still computes its authentication tag with
//! the portable code, where GHASH costs far more per block than AES does.
//!
//! That is why `ic_ontology::runtime::backend()` keeps reporting
//! `portable-constant-time` on ARM even with this feature on, and why
//! `recommend` keeps choosing ChaCha20-Poly1305 there. Both are correct: the
//! ontology's `hardware-accelerated` means the cipher *and* the multiply, and
//! claiming it on the strength of half would make an agent pick AES-GCM for a
//! workload where it is the slower answer.
//!
//! # Verification
//!
//! Against the portable backend, which is itself validated against the FIPS 197
//! and SP 800-38A vectors. That is the same arrangement the x86 backend has: an
//! optimisation is held to the output of something already known to be correct,
//! rather than to a second reading of the same specification.

use super::portable::{Schedule, BLOCK_LEN};
use core::arch::aarch64::*;
use ic_core::{ensure, Result};

/// Blocks encrypted per batch.
///
/// `AESE`/`AESMC` are pipelined on every ARMv8 implementation worth optimising
/// for, so independent blocks can be kept in flight. Four rather than the x86
/// backend's eight: ARM has thirty-two vector registers, but the round keys
/// occupy a large share of them, and going wider spills.
pub const PARALLEL_BLOCKS: usize = 4;

/// AES round keys held in vector registers.
#[derive(Clone, Copy)]
pub struct Keys {
    enc: [uint8x16_t; 15],
    dec: [uint8x16_t; 15],
    rounds: usize,
}

impl Keys {
    /// Load an expanded schedule into vector registers.
    ///
    /// # Safety
    ///
    /// The caller must ensure the `aes` and `neon` target features are present
    /// on this CPU.
    #[target_feature(enable = "neon")]
    #[target_feature(enable = "aes")]
    pub unsafe fn load(sched: &Schedule) -> Keys {
        let rounds = sched.rounds;
        let zero = vdupq_n_u8(0);
        let mut enc = [zero; 15];
        let mut dec = [zero; 15];

        for (r, slot) in enc.iter_mut().enumerate().take(rounds + 1) {
            let rk = sched.round_key(r);
            // SAFETY: `round_key` always returns exactly BLOCK_LEN bytes, and
            // `vld1q_u8` has no alignment requirement.
            *slot = unsafe { vld1q_u8(rk.as_ptr()) };
        }

        // Plain reversal. Unlike the x86 equivalent inverse cipher, AESIMC is
        // not pre-applied to the keys here: on ARM it is applied to the state
        // inside the loop, so doing both would invert twice.
        for i in 0..=rounds {
            dec[i] = enc[rounds - i];
        }

        Keys { enc, dec, rounds }
    }

    /// Encrypt one block in registers.
    ///
    /// # Safety
    ///
    /// Requires the `aes` and `neon` target features.
    #[target_feature(enable = "neon")]
    #[target_feature(enable = "aes")]
    #[inline]
    unsafe fn encrypt(&self, block: uint8x16_t) -> uint8x16_t {
        let mut b = block;
        for r in 0..self.rounds - 1 {
            b = vaesmcq_u8(vaeseq_u8(b, self.enc[r]));
        }
        b = vaeseq_u8(b, self.enc[self.rounds - 1]);
        veorq_u8(b, self.enc[self.rounds])
    }

    /// Decrypt one block in registers.
    ///
    /// # Safety
    ///
    /// Requires the `aes` and `neon` target features.
    #[target_feature(enable = "neon")]
    #[target_feature(enable = "aes")]
    #[inline]
    unsafe fn decrypt(&self, block: uint8x16_t) -> uint8x16_t {
        let mut b = block;
        for r in 0..self.rounds - 1 {
            b = vaesimcq_u8(vaesdq_u8(b, self.dec[r]));
        }
        b = vaesdq_u8(b, self.dec[self.rounds - 1]);
        veorq_u8(b, self.dec[self.rounds])
    }
}

/// Encrypt one block in place.
///
/// # Safety
///
/// Requires the `aes` and `neon` target features.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_block(keys: &Keys, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    // SAFETY: `block` is exactly BLOCK_LEN bytes, checked above; these loads
    // and stores are unaligned and so have no alignment requirement.
    unsafe {
        let b = vld1q_u8(block.as_ptr());
        let out = keys.encrypt(b);
        vst1q_u8(block.as_mut_ptr(), out);
    }
    Ok(())
}

/// Decrypt one block in place.
///
/// # Safety
///
/// Requires the `aes` and `neon` target features.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
pub unsafe fn decrypt_block(keys: &Keys, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    // SAFETY: as above.
    unsafe {
        let b = vld1q_u8(block.as_ptr());
        let out = keys.decrypt(b);
        vst1q_u8(block.as_mut_ptr(), out);
    }
    Ok(())
}

/// Encrypt a whole number of blocks in place, batching where possible.
///
/// # Safety
///
/// Requires the `aes` and `neon` target features.
#[target_feature(enable = "neon")]
#[target_feature(enable = "aes")]
pub unsafe fn encrypt_blocks(keys: &Keys, data: &mut [u8]) -> Result<()> {
    ensure!(
        data.len() % BLOCK_LEN == 0,
        InvalidLength,
        "aes block sequence"
    );

    let mut chunks = data.chunks_exact_mut(BLOCK_LEN * PARALLEL_BLOCKS);
    for chunk in chunks.by_ref() {
        // SAFETY: the chunk is exactly PARALLEL_BLOCKS whole blocks, so every
        // offset below is in bounds.
        unsafe {
            let mut state = [vdupq_n_u8(0); PARALLEL_BLOCKS];
            for (i, slot) in state.iter_mut().enumerate() {
                *slot = vld1q_u8(chunk.as_ptr().add(i * BLOCK_LEN));
            }
            for slot in state.iter_mut() {
                *slot = keys.encrypt(*slot);
            }
            for (i, slot) in state.iter().enumerate() {
                vst1q_u8(chunk.as_mut_ptr().add(i * BLOCK_LEN), *slot);
            }
        }
    }

    for block in chunks.into_remainder().chunks_exact_mut(BLOCK_LEN) {
        // SAFETY: each block is exactly BLOCK_LEN bytes.
        unsafe { encrypt_block(keys, block)? };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::portable;

    /// Skip when the CPU cannot run these instructions.
    ///
    /// A build for aarch64 does not guarantee the extension is present, so the
    /// tests report a skip rather than failing on hardware that never claimed
    /// to support it.
    fn available() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
    }

    /// The differential test this backend exists to pass.
    ///
    /// The portable backend is validated against FIPS 197 and SP 800-38A; this
    /// one is validated against the portable backend. Holding an optimisation
    /// to the output of something already known to be correct catches the
    /// errors a second reading of the specification would reproduce -- which is
    /// the real risk here, because the ARM round structure differs from x86 in
    /// exactly the way a careless translation gets wrong.
    #[test]
    fn matches_the_portable_backend_for_every_key_size() {
        if !available() {
            eprintln!("aarch64 aes extension not available; skipping");
            return;
        }
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let sched = portable::Schedule::expand(&key).unwrap();
            // SAFETY: guarded by the detection above.
            let keys = unsafe { Keys::load(&sched) };

            for seed in 0..16u8 {
                let mut want = [0u8; BLOCK_LEN];
                for (i, b) in want.iter_mut().enumerate() {
                    *b = seed.wrapping_mul(31).wrapping_add(i as u8);
                }
                let mut got = want;

                portable::encrypt_block(&sched, &mut want).unwrap();
                // SAFETY: guarded by the detection above.
                unsafe { encrypt_block(&keys, &mut got).unwrap() };
                assert_eq!(got, want, "encrypt, key_len={key_len} seed={seed}");

                // And back again, which is what catches a decryption schedule
                // that is reversed correctly but inverted twice.
                // SAFETY: guarded by the detection above.
                unsafe { decrypt_block(&keys, &mut got).unwrap() };
                let mut original = [0u8; BLOCK_LEN];
                for (i, b) in original.iter_mut().enumerate() {
                    *b = seed.wrapping_mul(31).wrapping_add(i as u8);
                }
                assert_eq!(got, original, "decrypt, key_len={key_len} seed={seed}");
            }
        }
    }

    /// Batched encryption must equal block-at-a-time encryption.
    ///
    /// The batch path keeps several blocks in flight, and an index error there
    /// produces output that is wrong only for some blocks -- which a
    /// single-block test never reaches.
    #[test]
    fn batching_matches_single_blocks() {
        if !available() {
            eprintln!("aarch64 aes extension not available; skipping");
            return;
        }
        let key = [0x3cu8; 32];
        let sched = portable::Schedule::expand(&key).unwrap();
        // SAFETY: guarded by the detection above.
        let keys = unsafe { Keys::load(&sched) };

        // Deliberately not a multiple of PARALLEL_BLOCKS, so the remainder
        // path runs too.
        for blocks in [1usize, 3, 4, 5, 9] {
            let mut batched: Vec<u8> = (0..blocks * BLOCK_LEN).map(|i| (i % 251) as u8).collect();
            let mut single = batched.clone();

            // SAFETY: guarded by the detection above.
            unsafe { encrypt_blocks(&keys, &mut batched).unwrap() };
            for block in single.chunks_exact_mut(BLOCK_LEN) {
                // SAFETY: guarded by the detection above.
                unsafe { encrypt_block(&keys, block).unwrap() };
            }
            assert_eq!(batched, single, "blocks={blocks}");
        }
    }

    /// A misshapen input is refused rather than silently mishandled.
    #[test]
    fn lengths_are_checked() {
        if !available() {
            eprintln!("aarch64 aes extension not available; skipping");
            return;
        }
        let sched = portable::Schedule::expand(&[0u8; 16]).unwrap();
        // SAFETY: guarded by the detection above.
        let keys = unsafe { Keys::load(&sched) };
        let mut short = [0u8; 15];
        // SAFETY: guarded by the detection above.
        assert!(unsafe { encrypt_block(&keys, &mut short) }.is_err());
        let mut ragged = [0u8; BLOCK_LEN + 1];
        // SAFETY: guarded by the detection above.
        assert!(unsafe { encrypt_blocks(&keys, &mut ragged) }.is_err());
    }
}
