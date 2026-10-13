//! # ic-ec — elliptic-curve cryptography
//!
//! Curve25519 in two guises:
//!
//! * [`X25519`] — RFC 7748 key agreement.
//! * [`Ed25519`] — RFC 8032 signatures.
//!
//! Both are built on a shared constant-time field implementation
//! (`field::Fe`) with 51-bit limbs.
//!
//! ```
//! # #[cfg(not(ic_approved_only))]
//! # fn main() -> ic_core::Result<()> {
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
//! # Ok(())
//! # }
//! # #[cfg(ic_approved_only)]
//! # fn main() {}
//! ```
//!
//! ## FIPS position
//!
//! Curve25519 is **not** on the FIPS 186-5 / SP 800-186 approved list for
//! signatures, and X25519 is not an approved SP 800-56A scheme. They are here
//! because modern protocols require them, and the ontology marks them
//! accordingly so `ic-fips` blocks them in approved mode, and the
//! `ic_approved_only` cfg leaves them out of the build. The approved curves
//! are here too: ECDSA and ECDH over P-256, P-384 and P-521, in [`p256`],
//! [`p384`] and [`p521`].
#![cfg_attr(not(feature = "std"), no_std)]
// `deny` rather than `forbid`, so that the x86-64 assembly for P-256 and
// P-384 can be allowed it -- `nist::p256_x86`, `nist::p384_x86` and the
// generated `nist::p256_x86_point`, `nist::p384_x86_point` and
// `nist::mont_x86` -- which is `asm!` and so `unsafe` by construction.
// Everywhere else in this crate `unsafe` is a compile error. This crate
// forbade it outright until that backend, which with the rest of that work
// took P-256 ECDH from 68 to 26 microseconds on a Zen 5; see the module for
// what the assembly buys that the Rust beside it could not.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(clippy::all)]

// Each `not(ic_approved_only)` below is an algorithm FIPS approved mode does
// not permit, left out of that build; see `ic_core::APPROVED_ONLY`.
#[cfg(not(ic_approved_only))]
pub mod ed25519;
#[cfg(not(ic_approved_only))]
pub mod hash_to_curve;
#[cfg(not(ic_approved_only))]
pub mod oprf;
// GF(2^255 - 19). Five 51-bit limbs where a 64x64 multiply is cheap; ten limbs
// of 26 and 25 bits on 32-bit RISC-V, where 128-bit arithmetic compiles to
// branches on secret carries. `--cfg ic_limb32` selects the second anywhere, so
// the Curve25519 vectors can be run against it on a host.
#[cfg(all(not(ic_approved_only), not(any(target_arch = "riscv32", ic_limb32))))]
mod field;
#[cfg(all(not(ic_approved_only), any(target_arch = "riscv32", ic_limb32)))]
#[path = "field32.rs"]
mod field;
// Compiled beside the five-limb field under test, to be compared with it.
#[cfg(all(
    test,
    not(ic_approved_only),
    not(any(target_arch = "riscv32", ic_limb32))
))]
mod field32;

#[cfg(feature = "ct-probes")]
#[doc(hidden)]
pub mod ct_probes;
mod nist;
pub mod p256;
pub mod p384;
pub mod p521;
#[cfg(not(ic_approved_only))]
mod scalar;
#[cfg(not(ic_approved_only))]
pub mod x25519;

#[cfg(not(ic_approved_only))]
pub use ed25519::{Ed25519, Ed25519Key, Ed25519VerifyKey};
pub use p256::{EcdhP256, EcdsaP256Sha256};
pub use p384::{EcdhP384, EcdsaP384Sha384};
#[cfg(not(ic_approved_only))]
pub use x25519::X25519;

/// Digest widths ECDSA's `verify_prehash` accepts.
pub use nist::ecdsa::PREHASH_LENS;

/// The narrowest digest ECDSA's `verify_prehash` accepts on a curve.
pub use nist::ecdsa::min_prehash_len;

/// Build every precomputed table now, rather than on first use.
///
/// Under `std`, the generator tables for P-256, P-384 and P-521 and the
/// Ed25519 basepoint tables are built the first time an operation needs them:
/// about one scalar multiplication per curve, a few hundred microseconds in
/// all on a host. They live in statics, so building them allocates nothing
/// whenever it happens. What this changes is *when* the time is spent: a
/// caller that wants its first handshake to cost what every later one does can
/// pay it at start-up instead.
///
/// Safe to call more than once and from several threads: the work is done
/// once, and a second caller waits for the first. Under `no_std` there are no
/// tables, and this does nothing.
pub fn prepare() {
    use nist::gentable::HasGeneratorTable;
    p256::P256::prepare_generator_table();
    p384::P384::prepare_generator_table();
    p521::P521::prepare_generator_table();
    #[cfg(all(feature = "std", not(ic_approved_only)))]
    ed25519::prepare_tables();
}

/// Ontology identifiers for the schemes implemented here.
pub const EC_IDS: &[&str] = &[
    #[cfg(not(ic_approved_only))]
    "x25519",
    #[cfg(not(ic_approved_only))]
    "ed25519",
    "ecdh-p256",
    "ecdsa-p256-sha256",
    "ecdh-p384",
    "ecdsa-p384-sha384",
];
