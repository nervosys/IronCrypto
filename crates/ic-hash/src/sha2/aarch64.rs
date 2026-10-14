//! The ARMv8 SHA-2 backend: `SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1` for
//! SHA-256 and `SHA512H`/`SHA512H2`/`SHA512SU0`/`SHA512SU1` for SHA-512.
//!
//! # Status
//!
//! Behind the off-by-default `aarch64-crypto` feature, like the ARMv8 AES
//! backend in `ic-cipher`, and for the same reason: nobody has run it on ARM
//! hardware. It has been executed under QEMU user-mode emulation (`-cpu max`,
//! see `scripts/test-aarch64.sh`), where the differential tests below compare it
//! with the portable compression at every length from 0 to 600 bytes and on
//! large inputs. That is a check of what the instructions compute, as QEMU
//! models them; it says nothing about speed, and nothing has measured that.
//!
//! # What is reimplemented
//!
//! Only block compression, as with SHA-NI: buffering, padding and
//! finalisation stay in [`super`]. The round constants are read from
//! [`super::K256`] and [`super::K512`], not transcribed again.
//!
//! The block structure is the macro in [`super::armv8_rounds`], which
//! `super::armv8_model` also expands over a software model of the
//! instructions. So the composition is checked on any host, and the
//! instructions' meaning under QEMU.
//!
//! # Constant time
//!
//! The SHA-2 instructions are fixed-latency vector operations with no
//! data-dependent behaviour, and nothing here indexes memory or branches on
//! the message or the state. Every branch is on the block count or the round
//! number. The compiled code is checked by `scripts/check-ct.py` on
//! `aarch64-unknown-linux-gnu` (`ct_sha256_armv8_compress`,
//! `ct_sha512_armv8_compress`); see `docs/CONSTANT_TIME.md`.

use super::armv8_rounds::{
    armv8_sha256_blocks, armv8_sha256_quad, armv8_sha512_blocks, armv8_sha512_pair,
};
use super::{K256, K512};

/// Whether this CPU has the SHA-256 instructions. Asked once.
#[cfg(feature = "std")]
pub(super) fn sha256_available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 not yet asked, 1 yes, 2 no.
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = std::arch::is_aarch64_feature_detected!("neon")
                && std::arch::is_aarch64_feature_detected!("sha2");
            CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
            have
        }
    }
}

/// Whether this CPU has the SHA-512 instructions. Asked once.
///
/// Rust's `sha3` target feature is `FEAT_SHA512` together with `FEAT_SHA3`;
/// there is no separate name for the SHA-512 half.
#[cfg(feature = "std")]
pub(super) fn sha512_available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = std::arch::is_aarch64_feature_detected!("neon")
                && std::arch::is_aarch64_feature_detected!("sha3");
            CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
            have
        }
    }
}

/// The SHA-256 operations the shared structure expands over.
mod ops256 {
    use core::arch::aarch64::*;

    pub(super) type V = uint32x4_t;

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn from_words(w: [u32; 4]) -> V {
        // SAFETY: `w` is four `u32`s, exactly what one load reads.
        unsafe { vld1q_u32(w.as_ptr()) }
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn to_words(v: V) -> [u32; 4] {
        let mut w = [0u32; 4];
        // SAFETY: `w` has room for exactly the four lanes stored.
        unsafe { vst1q_u32(w.as_mut_ptr(), v) };
        w
    }

    /// Four big-endian message words. `b` is always sixteen bytes; the
    /// fallback for anything shorter cannot be reached and costs nothing.
    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn load_be(b: &[u8]) -> V {
        let Some(b) = b.first_chunk::<16>() else {
            return vdupq_n_u32(0);
        };
        // SAFETY: `b` is sixteen bytes, and `vld1q_u8` has no alignment
        // requirement.
        let raw = unsafe { vld1q_u8(b.as_ptr()) };
        vreinterpretq_u32_u8(vrev32q_u8(raw))
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn add(a: V, b: V) -> V {
        vaddq_u32(a, b)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn sha256h(abcd: V, efgh: V, wk: V) -> V {
        vsha256hq_u32(abcd, efgh, wk)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn sha256h2(efgh: V, abcd: V, wk: V) -> V {
        vsha256h2q_u32(efgh, abcd, wk)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn sha256su0(w0: V, w4: V) -> V {
        vsha256su0q_u32(w0, w4)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    pub(super) fn sha256su1(t: V, w8: V, w12: V) -> V {
        vsha256su1q_u32(t, w8, w12)
    }
}

/// The SHA-512 operations the shared structure expands over.
mod ops512 {
    use core::arch::aarch64::*;

    pub(super) type V = uint64x2_t;

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn from_words(w: [u64; 2]) -> V {
        // SAFETY: `w` is two `u64`s, exactly what one load reads.
        unsafe { vld1q_u64(w.as_ptr()) }
    }

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn to_words(v: V) -> [u64; 2] {
        let mut w = [0u64; 2];
        // SAFETY: `w` has room for exactly the two lanes stored.
        unsafe { vst1q_u64(w.as_mut_ptr(), v) };
        w
    }

    /// Two big-endian message words; see `ops256::load_be`.
    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn load_be(b: &[u8]) -> V {
        let Some(b) = b.first_chunk::<16>() else {
            return vdupq_n_u64(0);
        };
        // SAFETY: `b` is sixteen bytes, and `vld1q_u8` has no alignment
        // requirement.
        let raw = unsafe { vld1q_u8(b.as_ptr()) };
        vreinterpretq_u64_u8(vrev64q_u8(raw))
    }

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn add(a: V, b: V) -> V {
        vaddq_u64(a, b)
    }

    /// `[a[1], b[0]]`.
    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn ext1(a: V, b: V) -> V {
        vextq_u64::<1>(a, b)
    }

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn sha512h(sum: V, x: V, y: V) -> V {
        vsha512hq_u64(sum, x, y)
    }

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn sha512h2(sum: V, x: V, y: V) -> V {
        vsha512h2q_u64(sum, x, y)
    }

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn sha512su0(w0: V, w2: V) -> V {
        vsha512su0q_u64(w0, w2)
    }

    #[inline]
    #[target_feature(enable = "neon,sha3")]
    pub(super) fn sha512su1(t: V, w14: V, w9: V) -> V {
        vsha512su1q_u64(t, w14, w9)
    }
}

/// Compress whole 64-byte blocks into the SHA-256 `state`.
///
/// # Safety
///
/// The CPU must support `neon` and `sha2`; [`sha256_available`] is that test.
/// `blocks` must be a whole number of 64-byte blocks (a ragged tail is
/// ignored).
#[target_feature(enable = "neon,sha2")]
pub(super) unsafe fn compress256(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(64));
    armv8_sha256_blocks!(ops256, state, blocks, K256);
}

/// Compress whole 128-byte blocks into the SHA-512 `state`.
///
/// # Safety
///
/// The CPU must support `neon` and `sha3` (which is how Rust names
/// `FEAT_SHA512`); [`sha512_available`] is that test. `blocks` must be a whole
/// number of 128-byte blocks (a ragged tail is ignored).
#[target_feature(enable = "neon,sha3")]
pub(super) unsafe fn compress512(state: &mut [u64; 8], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(128));
    armv8_sha512_blocks!(ops512, state, blocks, K512);
}
