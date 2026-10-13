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
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[allow(unsafe_code)]
mod avx2;
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
