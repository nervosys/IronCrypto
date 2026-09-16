//! ML-DSA (FIPS 204) — **incomplete**: the ring arithmetic and rounding only.
//!
//! This crate currently provides `Z_q[X]/(X^256 + 1)` with `q = 8380417`, the
//! number-theoretic transform over it, the rejection-bound check that ML-DSA's
//! signing loop turns on, and the rounding and hint machinery of FIPS 204
//! algorithms 35 through 40. There is no signature scheme here yet, and nothing
//! is registered in the ontology as available: an algorithm that does not exist
//! should not be discoverable as though it did.
//!
//! The two layers are verified differently, and it is worth being precise about
//! which is which. The NTT is checked against schoolbook multiplication — an
//! independent computation of the same thing. The rounding functions are
//! checked against their defining equations, which admit exactly one answer
//! each, so for those a published vector could only confirm what the equations
//! already fix. Neither is checked against another implementation of ML-DSA.
//!
//! The foundation is worth having on its own. The NTT is the part of a lattice
//! scheme most likely to be subtly wrong, and the hint functions are the part
//! most likely to be subtly *asymmetric* — correct in one direction and not the
//! other. Both are settled before anything is built on top of them.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod poly;
pub mod rounding;
