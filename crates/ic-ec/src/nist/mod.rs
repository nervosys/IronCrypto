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
//! multiplication is a fixed-window loop -- five doublings and an addition per
//! digit, the same for every scalar. [`point::Point::add`] is total: it
//! computes both the addition and the doubling and selects between them
//! without branching. That costs roughly a third more field multiplications
//! than a formula with exceptional cases, so the loops use it only where an
//! exceptional case can arise; elsewhere they use the incomplete formula,
//! with the identity handled by selection, and say in a comment why equal
//! inputs cannot reach it (`Point::mul_scalar`, `gentable::mul`).
//!
//! # P-256 on x86-64
//!
//! [`p256_field`] specialises P-256's reduction to its prime; on x86-64 that is
//! assembly (`p256_x86`), and with BMI2 and ADX the point formulas are each one
//! block of it (`p256_x86_point`), selected through hooks on [`point::Curve`]
//! that other curves leave at their default. `safegcd` inverts P-256's two
//! rings on 64-bit targets. P-384 has the same MULX/ADX multiplications and
//! point formulas, with field operations generic in the modulus
//! (`mont_x86`, `p384_x86_point`), selected the same way.

pub mod arith;
pub mod ecdh;
pub mod ecdsa;
pub mod gentable;
pub mod p256_field;
// With the modules below, the only places in this crate allowed `unsafe`:
// inline assembly for P-256 and P-384 on x86-64. See the modules, and
// `lib.rs`, for why.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod p256_x86;
// The same, for whole point formulas; generated.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod p256_x86_point;
// P-384's multiplications in the same assembly; generated, and its dispatch.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod mont_x86;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod p384_x86;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod p384_x86_point;
pub mod point;
#[cfg(all(target_pointer_width = "64", not(ic_limb32)))]
pub(crate) mod safegcd;
