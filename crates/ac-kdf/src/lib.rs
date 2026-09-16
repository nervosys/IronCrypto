//! # ac-kdf — key derivation
//!
//! * [`hkdf`] — RFC 5869 extract-and-expand (SP 800-56C two-step).
//! * [`pbkdf2()`] — SP 800-132 password-based derivation.
//! * [`kbkdf`] — SP 800-108 counter-mode KDF over HMAC.
//!
//! Each function is generic over the HMAC instantiation, so the same code path
//! serves SHA-256, SHA-384, SHA-512, and the SHA-3 family.
//!
//! ```
//! use ac_kdf::hkdf::Hkdf;
//! use ac_core::traits::Kdf;
//! use ac_mac::HmacSha256;
//!
//! let mut key = [0u8; 32];
//! Hkdf::<HmacSha256>::derive(b"input keying material", b"salt", b"app v1", &mut key)?;
//! # Ok::<(), ac_core::Error>(())
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod hkdf;
pub mod kbkdf;
pub mod pbkdf2;

pub use hkdf::Hkdf;
pub use kbkdf::kbkdf_counter;
pub use pbkdf2::pbkdf2;

/// Ontology identifiers for the KDFs this crate provides.
pub const KDF_IDS: &[&str] = &[
    "hkdf-sha2-256",
    "hkdf-sha2-384",
    "hkdf-sha2-512",
    "pbkdf2-hmac-sha2-256",
    "pbkdf2-hmac-sha2-512",
    "sp800-108-counter-hmac-sha2-256",
];

/// The SP 800-132 floor for PBKDF2 iterations in new deployments.
///
/// SP 800-132 sets 1 000 as an absolute minimum; OWASP and the CMVP guidance
/// for modern hardware put the practical floor far higher. An agent that
/// derives a password-based key below this is warned by
/// [`pbkdf2::check_iterations`].
pub const PBKDF2_MIN_RECOMMENDED_ITERATIONS: u32 = 600_000;
