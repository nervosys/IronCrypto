//! The NIST prime curves, P-256 and P-384.
//!
//! These are the FIPS-approved curves, and the ones most of the deployed world
//! uses: TLS, X.509, JWT/JOSE, COSE, WebAuthn, and Secure Boot all default to
//! one of them.
//!
//! # One implementation, two curves
//!
//! Every NIST prime curve has `a = -3` and a prime of the form that admits the
//! same Montgomery arithmetic, so the field, the group law, ECDSA, and ECDH are
//! written once here and instantiated per curve:
//!
//! | module | contents |
//! |---|---|
//! | [`arith`] | Montgomery arithmetic, generic over limb count |
//! | [`point`] | the group law, in Jacobian coordinates |
//! | [`ecdsa`] | signing and verification, with RFC 6979 nonces |
//! | [`ecdh`] | key agreement |
//!
//! Sharing matters more here than it looks: a bug fixed in a duplicated group
//! law gets fixed once and forgotten once. The per-curve modules supply only
//! constants and widths.
//!
//! # Why the group law is shaped the way it is
//!
//! These curves have no Montgomery ladder to fall back on, so scalar
//! multiplication is a double-and-add-always loop over a group law that has
//! been made total: [`point::Point::add`] computes both the addition and the
//! doubling and selects between them without branching. That costs roughly a
//! third more field multiplications than a formula with exceptional cases, and
//! buys an implementation where no input — including the identity and a point
//! plus itself — takes a different path.

pub mod arith;
pub mod ecdh;
pub mod ecdsa;
pub mod point;
