//! # ic-hash — FIPS 180-4 and FIPS 202 hash functions
//!
//! Pure-Rust, `no_std`, allocation-free implementations of the SHA-2 and SHA-3
//! families plus the SHAKE extendable-output functions.
//!
//! ```
//! use ic_hash::Sha256;
//! use ic_core::traits::Digest;
//!
//! let d = Sha256::digest(b"abc");
//! assert_eq!(
//!     ic_core::codec::hex(d.as_ref()),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//! );
//! ```
//!
//! Every type here implements [`ic_core::traits::Digest`] (or [`ic_core::traits::Xof`])
//! and [`ic_core::traits::SelfTest`], so `ic-fips` can drive their known-answer
//! tests generically.
#![cfg_attr(not(feature = "std"), no_std)]
// `deny` rather than `forbid`, and the difference is the point: one module is
// allowed unsafe and every other line in this crate is a compile error. The
// allowance below marks the only place a CPU intrinsic is called. This crate
// forbade it outright until SHA-256 gained a SHA-NI backend, which was worth
// roughly seven times the throughput on hardware that has it and cannot be
// written any other way.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod blake2;
// SHA-NI, behind runtime detection. See `sha2::x86`.
#[allow(unsafe_code)]
mod sha2;
mod sha3;
pub mod sp800_185;

pub use blake2::{blake2b_long, Blake2b};
pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, XofReader};
pub use sp800_185::{CShake128, CShake256};
pub use sp800_185::{ParallelHash128, ParallelHash256, TupleHash128, TupleHash256};

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
