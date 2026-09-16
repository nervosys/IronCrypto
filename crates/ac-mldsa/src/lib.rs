//! ML-DSA (FIPS 204) — **incomplete**: the ring arithmetic only.
//!
//! This crate currently provides `Z_q[X]/(X^256 + 1)` with `q = 8380417`, the
//! number-theoretic transform over it, and the rejection-bound check that
//! ML-DSA's signing loop turns on. There is no signature scheme here yet, and
//! nothing is registered in the ontology as available: an algorithm that does
//! not exist should not be discoverable as though it did.
//!
//! The foundation is worth having on its own. The NTT is the part of a lattice
//! scheme most likely to be subtly wrong, and it is verified here against
//! schoolbook multiplication before anything is built on top of it.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod poly;
