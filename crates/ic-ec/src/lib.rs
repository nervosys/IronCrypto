//! # ic-ec — elliptic-curve cryptography
//!
//! Curve25519 in two guises:
//!
//! * [`X25519`] — RFC 7748 key agreement.
//! * [`Ed25519`] — RFC 8032 signatures.
//!
//! Both are built on a shared constant-time field implementation
//! (`field::Fe`) with 51-bit limbs, and on x86-64 CPUs with BMI2 and ADX on a
//! four-limb field (`fe64::Fe64`) whose multiplication is `MULX`/`ADX`
//! assembly. The second is chosen at run time, once per operation; the first
//! is the fallback and the reference the second is tested against.
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
// Denied rather than forbidden so that one module can allow it: `fe64`, whose
// field multiplication is inline assembly. Nothing else here uses `unsafe`.
#![deny(unsafe_code)]
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
// GF(2^255 - 19) in four 64-bit limbs, for x86-64 CPUs with BMI2 and ADX,
// selected at run time; see `field_ops::dispatch!`. Not under `ic_limb32`,
// whose purpose is to run the curve vectors against the ten-limb field, nor
// under `ic_ec_portable`, which runs everything on the portable field.
#[cfg(all(
    not(ic_approved_only),
    target_arch = "x86_64",
    not(any(ic_limb32, ic_ec_portable))
))]
#[allow(unsafe_code)]
pub(crate) mod fe64;
// Four field elements at once on AVX-512 IFMA, and the Edwards operations on
// them; selected at run time where the CPU has it. Same conditions as `fe64`,
// which it converts through.
#[cfg(all(
    not(ic_approved_only),
    target_arch = "x86_64",
    not(any(ic_limb32, ic_ec_portable))
))]
#[allow(unsafe_code)]
pub(crate) mod f51x4;
#[cfg(not(ic_approved_only))]
mod field_ops;

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

/// The implementation of GF(2^255 - 19) that X25519 and Ed25519 run on here.
///
/// A published vector passes whichever implementation runs, so it cannot tell
/// which one did; this can.
#[cfg(not(ic_approved_only))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve25519Backend {
    /// Four elements at once on AVX-512 IFMA (x86-64), for X25519 and, under
    /// `std`, Ed25519's scalar multiplications; the MULX/ADX field for the
    /// rest.
    Ifma,
    /// Four 64-bit limbs on MULX and ADX (x86-64).
    MulxAdx,
    /// The portable field: five 51-bit limbs, or ten of 26 and 25 bits on
    /// 32-bit RISC-V and under `--cfg ic_limb32`.
    Portable,
}

/// Which [`Curve25519Backend`] this CPU and build run, chosen at run time on
/// the CPU's features alone.
#[cfg(not(ic_approved_only))]
#[must_use]
pub fn curve25519_backend() -> Curve25519Backend {
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    {
        if f51x4::Ifma::get().is_some() {
            return Curve25519Backend::Ifma;
        }
        if fe64::available() {
            return Curve25519Backend::MulxAdx;
        }
    }
    Curve25519Backend::Portable
}

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
