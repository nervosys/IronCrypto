//! # ic-ec — elliptic-curve cryptography
//!
//! Curve25519 in two guises:
//!
//! * [`X25519`] — RFC 7748 key agreement.
//! * [`Ed25519`] — RFC 8032 signatures.
//!
//! Both are built on a shared constant-time field implementation
//! ([`field::Fe`]) with 51-bit limbs.
//!
//! ```
//! use ic_ec::X25519;
//! use ic_core::traits::KeyAgreement;
//!
//! let alice_sk = [0x11u8; 32];
//! let bob_sk = [0x22u8; 32];
//! let (mut alice_pk, mut bob_pk) = ([0u8; 32], [0u8; 32]);
//! X25519::public_key(&alice_sk, &mut alice_pk)?;
//! X25519::public_key(&bob_sk, &mut bob_pk)?;
//!
//! let (mut s1, mut s2) = ([0u8; 32], [0u8; 32]);
//! X25519::agree(&alice_sk, &bob_pk, &mut s1)?;
//! X25519::agree(&bob_sk, &alice_pk, &mut s2)?;
//! assert_eq!(s1, s2);
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! ## FIPS position
//!
//! Curve25519 is **not** on the FIPS 186-5 / SP 800-186 approved list for
//! signatures, and X25519 is not an approved SP 800-56A scheme. They are here
//! because modern protocols require them, and the ontology marks them
//! accordingly so `ic-fips` blocks them in approved mode. The approved curves
//! (P-256/384/521, ECDSA, ECDH) and the post-quantum FIPS 203/204 schemes are
//! registered in the ontology with `implementation_status: Planned` — an agent
//! querying for an approved signature scheme gets an honest "not available
//! here" rather than a silent substitution.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod ed25519;
pub mod field;
pub mod nist;
pub mod p256;
pub mod p384;
pub mod p521;
pub mod scalar;
pub mod x25519;

pub use ed25519::{Ed25519, Ed25519Key};
pub use p256::{EcdhP256, EcdsaP256Sha256};
pub use p384::{EcdhP384, EcdsaP384Sha384};
pub use x25519::X25519;

/// Ontology identifiers for the schemes implemented here.
pub const EC_IDS: &[&str] = &[
    "x25519",
    "ed25519",
    "ecdh-p256",
    "ecdsa-p256-sha256",
    "ecdh-p384",
    "ecdsa-p384-sha384",
];
