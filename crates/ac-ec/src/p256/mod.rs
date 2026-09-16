//! NIST P-256 (secp256r1, prime256v1).
//!
//! The FIPS-approved curve, and the one most of the deployed world uses: TLS,
//! X.509, JWT/JOSE, COSE, WebAuthn, and Secure Boot all default to it.
//!
//! * [`EcdsaP256Sha256`] — FIPS 186-5 signatures, with RFC 6979 deterministic
//!   nonces so there is no RNG in the signing path.
//! * [`EcdhP256`] — SP 800-56A key agreement.
//!
//! # Structure
//!
//! | module | contents |
//! |---|---|
//! | [`arith`] | Montgomery arithmetic for both GF(p) and Z/nZ |
//! | [`point`] | the group law, in Jacobian coordinates |
//! | [`ecdsa`] | signing and verification |
//! | [`ecdh`] | key agreement |
//!
//! # Why this is the constant-time story it is
//!
//! P-256 has no Montgomery ladder to fall back on, so the scalar multiplication
//! here is a double-and-add-always loop over a group law that has been made
//! total: [`point::Point::add`] computes both the addition and the doubling and
//! selects between them without branching. That costs roughly a third more
//! field multiplications than a formula with exceptional cases, and buys an
//! implementation where no input — including the identity and a point plus
//! itself — takes a different path.

pub mod arith;
pub mod ecdh;
pub mod ecdsa;
pub mod point;

pub use ecdh::EcdhP256;
pub use ecdsa::EcdsaP256Sha256;
pub use point::{AffinePoint, Point};
