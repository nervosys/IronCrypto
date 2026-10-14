//! GHASH on the ARMv8 `PMULL` carry-less multiply.
//!
//! The ARM counterpart of `crate::clmul`, with the same two entry points --
//! one multiply, and eight blocks per reduction -- so `gcm::Ghash` dispatches
//! to either without caring which. The structure is the macros in
//! `crate::armv8_ghash`, shared with the software model in
//! `crate::armv8_ghash_model`; the representation and the reduction are
//! described there.
//!
//! # Status
//!
//! Behind the off-by-default `aarch64-crypto` feature, beside the ARMv8 AES
//! backend. It has run under QEMU user-mode emulation (`-cpu max`,
//! `scripts/test-aarch64.sh`), where the tests below hold it to the portable
//! bit-by-bit multiply and `gcm`'s tests hold AES-GCM to the SP 800-38D
//! vectors, Wycheproof, and the portable path at every length to 600 bytes.
//! It has not run on ARM hardware, and its speed has not been measured.

use crate::armv8_ghash::{
    armv8_ghash_absorb8, armv8_ghash_mul, armv8_ghash_product, armv8_ghash_reduce,
};

/// The operations the shared structure expands over.
mod ops {
    use core::arch::aarch64::*;

    pub(super) type V = uint64x2_t;

    /// Sixteen bytes in GCM order, each bit-reversed, as two 64-bit lanes.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn load(b: &[u8; 16]) -> V {
        // SAFETY: `b` is sixteen bytes and `vld1q_u8` has no alignment
        // requirement.
        let raw = unsafe { vld1q_u8(b.as_ptr()) };
        vreinterpretq_u64_u8(vrbitq_u8(raw))
    }

    /// The inverse of [`load`].
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn store(v: V) -> [u8; 16] {
        let mut out = [0u8; 16];
        // SAFETY: `out` has room for exactly the sixteen bytes stored.
        unsafe { vst1q_u8(out.as_mut_ptr(), vrbitq_u8(vreinterpretq_u8_u64(v))) };
        out
    }

    /// Lane 0 times lane 0.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn pmull(a: V, b: V) -> V {
        vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(b)))
    }

    /// Lane 1 times lane 1.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn pmull2(a: V, b: V) -> V {
        vreinterpretq_u64_p128(vmull_high_p64(
            vreinterpretq_p64_u64(a),
            vreinterpretq_p64_u64(b),
        ))
    }

    /// `[a[1], b[0]]`.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn ext8(a: V, b: V) -> V {
        vextq_u64::<1>(a, b)
    }

    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn xor(a: V, b: V) -> V {
        veorq_u64(a, b)
    }

    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn zero() -> V {
        vdupq_n_u64(0)
    }

    /// `x^7 + x^2 + x + 1` in both lanes.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub(super) fn poly() -> V {
        vdupq_n_u64(0x87)
    }
}

/// Multiply `x` by `h` in GCM's GF(2^128), in place.
///
/// # Safety
///
/// Requires the `neon` and `aes` target features (`aes` is how Rust names the
/// extension that includes `PMULL`); [`ic_core::cpu::has_ghash_pmull`] is the
/// test.
#[target_feature(enable = "neon,aes")]
pub unsafe fn mul(x: &mut [u8; 16], h: &[u8; 16]) {
    armv8_ghash_mul!(ops, x, h);
}

/// Absorb `blocks` into the GHASH accumulator `acc`, eight blocks at a time.
///
/// `powers[i]` is `H^(i+1)`, in GCM byte order.
///
/// # Safety
///
/// As [`mul`]. `blocks.len()` must be a multiple of 128; a ragged tail is
/// ignored, and the caller handles it.
#[target_feature(enable = "neon,aes")]
pub unsafe fn absorb8(acc: &mut [u8; 16], powers: &[[u8; 16]; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % 128, 0);
    armv8_ghash_absorb8!(ops, acc, powers, blocks);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::armv8_ghash_model::tests::{check_absorb8, check_mul};

    fn available() -> bool {
        ic_core::cpu::has_ghash_pmull()
    }

    /// The real multiply against the portable one; see `check_mul`.
    #[test]
    fn matches_the_portable_multiply() {
        if !available() {
            println!("no PMULL on this CPU; the backend was not exercised");
            return;
        }
        // SAFETY: guarded by the detection above.
        check_mul(|x, h| unsafe { mul(x, h) });
    }

    /// The real eight-block absorb against eight serial portable steps.
    #[test]
    fn absorb8_matches_the_serial_portable_ghash() {
        if !available() {
            println!("no PMULL on this CPU; the backend was not exercised");
            return;
        }
        // SAFETY: guarded by the detection above; `check_absorb8` passes
        // whole groups only.
        check_absorb8(|acc, powers, blocks| unsafe { absorb8(acc, powers, blocks) });
    }
}
