//! ML-KEM (FIPS 203) — **experimental, not interoperability-tested**.
//!
//! Read [`VERIFICATION`] before using any of this.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod poly;

/// What has and has not been checked.
pub const VERIFICATION: &str = "components verified against independent oracles; \
                                full-scheme interoperability unverified";
