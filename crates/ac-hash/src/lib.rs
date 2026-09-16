//! # ac-hash — FIPS 180-4 and FIPS 202 hash functions
//!
//! Pure-Rust, `no_std`, allocation-free implementations of the SHA-2 and SHA-3
//! families plus the SHAKE extendable-output functions.
//!
//! ```
//! use ac_hash::Sha256;
//! use ac_core::traits::Digest;
//!
//! let d = Sha256::digest(b"abc");
//! assert_eq!(
//!     ac_core::codec::hex(d.as_ref()),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//! );
//! ```
//!
//! Every type here implements [`ac_core::traits::Digest`] (or [`ac_core::traits::Xof`])
//! and [`ac_core::traits::SelfTest`], so `ac-fips` can drive their known-answer
//! tests generically.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod blake2;
mod sha2;
mod sha3;

pub use blake2::{blake2b_long, Blake2b};
pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

/// Dynamic identifiers for the digests in this crate, as used by the ontology
/// and the agent-facing dispatch layer.
pub const DIGEST_IDS: &[&str] = &[
    "blake2b",
    "sha2-224",
    "sha2-256",
    "sha2-384",
    "sha2-512",
    "sha2-512-224",
    "sha2-512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
];

/// Dynamic identifiers for the extendable-output functions in this crate.
pub const XOF_IDS: &[&str] = &["shake128", "shake256"];
