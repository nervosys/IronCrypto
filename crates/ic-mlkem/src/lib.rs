//! ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (FIPS 203) post-quantum key
//! encapsulation, each checked against NIST's ACVP vectors.
//!
//! Read [`VERIFICATION`] before using any of this.

#![cfg_attr(not(feature = "std"), no_std)]
// `deny` rather than `forbid`: the AVX2 module is allowed unsafe, for the
// intrinsics, and so is each runtime-detected call into it, one
// `#[allow(unsafe_code)]` function at a time. Unsafe anywhere else is a
// compile error.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

// AVX2 NTT and base multiplication, behind runtime detection. See `avx2`.
#[cfg(all(target_arch = "x86_64", any(feature = "std", feature = "ct-probes")))]
#[cfg_attr(not(feature = "std"), allow(dead_code))]
#[allow(unsafe_code)]
mod avx2;

/// The AVX2 routines that see secrets, for `scripts/ct-audit` to read after
/// LTO. Not API, not covered by semver. Never executed.
///
/// `rej_uniform` and `all_below_q_12` are left out: the matrix `A` and the
/// encapsulation key they read are public.
#[cfg(all(target_arch = "x86_64", feature = "ct-probes"))]
#[allow(unsafe_code)]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod ct_probes {
    use super::avx2;

    /// The forward NTT, on `s`, `e`, `y` and the rest.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn ntt(c: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::ntt(c) }
    }

    /// The inverse NTT.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn inv_ntt(c: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::inv_ntt(c) }
    }

    /// Base multiplication, accumulating; decapsulation's `s` is one input.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn basemul_add(acc: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::basemul_add(acc, a, b) }
    }

    /// Compression to one bit: the message decryption recovers.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_1(c: &[i16; 256], out: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::compress(c, 1, out) }
    }

    /// Compression to eleven bits, of the re-encryption's `u` at ML-KEM-1024.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_11(c: &[i16; 256], out: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::compress(c, 11, out) }
    }

    /// Twelve-bit decoding, of the decapsulation key's `s`.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn decode12(bytes: &[u8; 384], out: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::decode12(bytes, out) }
    }

    /// `SamplePolyCBD_2`, of the noise's secret bits.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn cbd2(bytes: &[u8; 128], out: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::cbd2(bytes, out) }
    }

    /// Reduction to canonical form, before a secret polynomial is encoded.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn normalize(c: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::normalize(c) }
    }

    /// Conversion to Montgomery form.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn to_mont(c: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::to_mont(c) }
    }

    /// Addition.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn add_assign(a: &mut [i16; 256], b: &[i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::add_assign(a, b) }
    }

    /// Barrett reduction.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn reduce(c: &mut [i16; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { avx2::reduce(c) }
    }
}
pub mod encode;
pub mod kem;
pub mod kem1024;
pub mod kem512;
#[cfg(feature = "std")]
mod lanes;
pub mod poly;
pub mod sample;
mod scheme;

pub use kem::MlKem768;
pub use kem1024::MlKem1024;
pub use kem512::MlKem512;

/// [`kem::PreparedEncapsulationKey`]: an ML-KEM-768 encapsulation key
/// checked and expanded once, for repeated encapsulation to it.
pub type MlKem768PreparedEncapsulationKey = kem::PreparedEncapsulationKey;
/// [`kem::PreparedDecapsulationKey`]: an ML-KEM-768 decapsulation key
/// checked and expanded once.
pub type MlKem768PreparedDecapsulationKey = kem::PreparedDecapsulationKey;
/// [`kem512::PreparedEncapsulationKey`], for ML-KEM-512.
pub type MlKem512PreparedEncapsulationKey = kem512::PreparedEncapsulationKey;
/// [`kem512::PreparedDecapsulationKey`], for ML-KEM-512.
pub type MlKem512PreparedDecapsulationKey = kem512::PreparedDecapsulationKey;
/// [`kem1024::PreparedEncapsulationKey`], for ML-KEM-1024.
pub type MlKem1024PreparedEncapsulationKey = kem1024::PreparedEncapsulationKey;
/// [`kem1024::PreparedDecapsulationKey`], for ML-KEM-1024.
pub type MlKem1024PreparedDecapsulationKey = kem1024::PreparedDecapsulationKey;

/// What has and has not been checked.
pub const VERIFICATION: &str = "components verified against independent oracles; \
                                each parameter set against 50 NIST ACVP cases \
                                (25 key generation, 25 encapsulation)";
