//! # ic-drbg — SP 800-90A deterministic random bit generators
//!
//! * [`HmacDrbg`] — HMAC_DRBG, generic over the HMAC instantiation.
//! * [`CtrDrbg`] — CTR_DRBG over AES-256 without a derivation function.
//! * [`Rng`] — an OS-seeded, auto-reseeding generator for everyday use.
//!
//! ## Why the indirection
//!
//! FIPS 140-3 does not let a module hand out raw OS bytes as key material. The
//! OS source is *entropy input* to an approved DRBG, and that DRBG is what
//! generates keys, nonces, and IVs. [`Rng`] wires that up so the correct thing
//! is also the easy thing:
//!
//! ```no_run
//! use ic_drbg::Rng;
//!
//! let mut rng = Rng::from_os()?;
//! let mut key = [0u8; 32];
//! rng.fill(&mut key)?;
//! # Ok::<(), ic_core::Error>(())
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

mod ctr;
mod hmac_drbg;
#[cfg(feature = "std")]
mod rng;

pub use ctr::CtrDrbg;
pub use hmac_drbg::{HmacDrbg, HmacDrbgSha256, HmacDrbgSha512};
#[cfg(feature = "std")]
pub use rng::Rng;

/// Maximum number of [`generate`][ic_core::traits::Drbg::generate] calls
/// between reseeds, per SP 800-90A Table 2 and Table 3.
///
/// The spec permits 2^48; this library uses a far smaller interval so that a
/// long-lived process reseeds on a human timescale rather than a geological
/// one. Exceeding it is an error, never a silent continuation.
pub const RESEED_INTERVAL: u64 = 1 << 20;

/// Minimum entropy input in bytes for a 256-bit security strength instantiation.
pub const MIN_ENTROPY_LEN: usize = 32;

/// Ontology identifiers for the DRBGs this crate provides.
pub const DRBG_IDS: &[&str] = &[
    "hmac-drbg-sha2-256",
    "hmac-drbg-sha2-512",
    "ctr-drbg-aes-256",
];
