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
//! rings and P-384's field on 64-bit targets.
//!
//! # P-384 on x86-64
//!
//! With BMI2 and ADX, P-384's field operations are specialised to its prime
//! too: Montgomery reduction takes two `mulx` per word where a generic
//! modulus takes six, squaring computes each cross product once, and the
//! doubling folds its small multiples into three fused operations. They and
//! the point formulas are generated into `p384_x86_point` and dispatched from
//! `p384_x86`; the scalar ring's multiplication stays generic in the modulus
//! (`mont_x86`).
//!
//! # Without AVX-512 IFMA
//!
//! Where the CPU has BMI2 and ADX but not IFMA, `p256_x86::mul_scalar` and
//! `p384_x86::mul_scalar` run [`point::Point::mul_scalar`]'s loop on one
//! buffer, the accumulator's slots shared by the in-place doubling and the
//! addition, so a digit's five doublings run back to back with nothing
//! copied; P-384's window is affine, its additions mixed. P-256's generator
//! table runs the same way (`p256_x86::table_mul`).

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
// P-256's and P-384's point formulas on AVX-512 IFMA, generated, and the
// scalar multiplications built on them, selected at run time.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod ifma;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod ifma_kernels;
// Inputs on both sides of the fused operations' fold, for the tests of the
// x86-64 assembly above.
#[cfg(all(test, target_arch = "x86_64"))]
mod fold_edges;
pub mod point;
// Verification's `u1*G + u2*Q`: variable time, for public inputs only.
#[cfg(all(target_pointer_width = "64", not(ic_limb32)))]
pub(crate) mod safegcd;
#[cfg(feature = "std")]
pub(crate) mod verify;
// Its chain on the P-256 and P-384 formulas' assembly; also variable time.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) mod verify_x86;
// Its divsteps in assembly, each decision a conditional move.
#[cfg(all(target_arch = "x86_64", not(ic_limb32)))]
#[allow(unsafe_code)]
pub(crate) mod safegcd_x86;
