//! ML-KEM (FIPS 203) — **experimental, not interoperability-tested**.
//!
//! Read [`VERIFICATION`] before using any of this.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod encode;
pub mod kem;
pub mod poly;
pub mod sample;

pub use kem::MlKem768;

/// What has and has not been checked.
pub const VERIFICATION: &str = "components verified against independent oracles; \
                                full-scheme interoperability unverified";
