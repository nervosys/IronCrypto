//! ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (FIPS 203) post-quantum key
//! encapsulation, each checked against NIST's ACVP vectors.
//!
//! Read [`VERIFICATION`] before using any of this.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod encode;
pub mod kem;
pub mod kem1024;
pub mod kem512;
pub mod poly;
pub mod sample;
mod scheme;

pub use kem::MlKem768;
pub use kem1024::MlKem1024;
pub use kem512::MlKem512;

/// What has and has not been checked.
pub const VERIFICATION: &str = "components verified against independent oracles; \
                                each parameter set against 50 NIST ACVP cases \
                                (25 key generation, 25 encapsulation)";
