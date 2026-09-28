//! ML-DSA-65 (FIPS 204) post-quantum signatures, checked against NIST's ACVP
//! vectors.
//!
//! [`sign`] is the scheme: key generation, signing and verification, the
//! pre-hash variants, and a deterministic variant alongside the hedged one.
//! Beneath it sit `Z_q[X]/(X^256 + 1)` with `q = 8380417`, the number-theoretic
//! transform over it, the rejection-bound check the signing loop turns on, the
//! rounding and hint machinery of FIPS 204 algorithms 35 through 40, and the
//! bit packing of algorithms 16 through 21.
//!
//! The assembled scheme agrees with 55 of NIST's ACVP cases for ML-DSA-65 --
//! all 25 key-generation cases and all 30 signature cases, 15 deterministic and
//! 15 hedged -- and is registered `available` in the ontology. Those vectors
//! are the check on the whole; the layers beneath were each verified on their
//! own before any of them existed, and that is still worth describing.
//!
//! The layers are verified differently, and it is worth being precise about
//! which is which. The NTT is checked against schoolbook multiplication and the
//! packing against a bit-at-a-time reference — in both cases an independent
//! computation of the same thing. The rounding functions are checked against
//! their defining equations, which admit exactly one answer each, so for those
//! a published vector could only confirm what the equations already fix.
//!
//! What those checks alone could not rule out was a convention misread
//! consistently across the whole crate — a byte order, a `mod±`
//! representative, an offset direction — which produces a scheme that agrees
//! with itself and with nobody else. That is exactly what the ACVP vectors
//! close: they were produced by another implementation, so a consistent misread
//! anywhere in the stack fails them.
//!
//! The foundation is worth having on its own. The NTT is the part of a lattice
//! scheme most likely to be subtly wrong, the hint functions the part most
//! likely to be subtly *asymmetric* — correct in one direction and not the
//! other — and the packing the part most likely to be self-consistently wrong,
//! where a round trip passes and nothing interoperates. All three are settled
//! before anything is built on top of them.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod encode;
pub mod poly;
pub mod rounding;
pub mod sample;
pub mod sign;
