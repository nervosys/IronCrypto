//! ML-DSA-65 (FIPS 204) — **experimental**: implemented, not vector-tested.
//!
//! This crate currently provides `Z_q[X]/(X^256 + 1)` with `q = 8380417`, the
//! number-theoretic transform over it, the rejection-bound check that ML-DSA's
//! signing loop turns on, the rounding and hint machinery of FIPS 204
//! algorithms 35 through 40, and the bit packing of algorithms 16 through 21.
//! There is no signature scheme here yet, and nothing is registered in the
//! ontology as available: an algorithm that does not exist should not be
//! discoverable as though it did.
//!
//! The layers are verified differently, and it is worth being precise about
//! which is which. The NTT is checked against schoolbook multiplication and the
//! packing against a bit-at-a-time reference — in both cases an independent
//! computation of the same thing. The rounding functions are checked against
//! their defining equations, which admit exactly one answer each, so for those
//! a published vector could only confirm what the equations already fix.
//!
//! None of it is checked against another implementation of ML-DSA. What that
//! leaves open is a convention misread consistently across the whole crate —
//! a byte order, a `mod±` representative, an offset direction. Each of those is
//! pinned as tightly as it can be from the spec text alone, and that is a
//! weaker guarantee than interoperating with someone else's code.
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
