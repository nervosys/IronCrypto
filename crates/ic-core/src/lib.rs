//! # ic-core — foundational types for IronCrypto
//!
//! Zero-dependency, `no_std`-first building blocks shared by every other crate in
//! the workspace:
//!
//! * [`Error`] / [`Result`] — a single, exhaustive, non-panicking error domain.
//! * [`ct`] — constant-time comparison and selection primitives.
//! * [`Zeroizing`] — scope-bound secret erasure with a compiler-fence barrier.
//! * [`traits`] — the object-safe algorithm contracts (`Digest`, `Mac`, `Aead`, …).
//! * [`codec`] — hex / base64 encoding used by the agent-facing surfaces.
//! * [`cpu`] — CPU feature detection, shared by the backends and the ontology.
//! * [`entropy`] — OS entropy acquisition (SP 800-90B conditioned input).
//!
//! Every public function in this crate is total: it returns `Result` rather than
//! panicking, so an autonomous agent can drive the library without tripping an
//! abort in a sandbox.
#![cfg_attr(not(feature = "std"), no_std)]
// Unsafe is confined to the two modules that cannot avoid it, each of which
// carries an explicit allowance and says why. Anywhere else in this crate it is
// a compile error rather than a review comment.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod codec;
pub mod cpu;
pub mod ct;
// The operating system's entropy source is a syscall; there is no safe way to
// ask for it.
#[allow(unsafe_code)]
pub mod entropy;
pub mod module;
pub mod sig;
pub mod traits;

mod error;
// Zeroing must survive the optimiser, which means volatile writes, which are
// unsafe by construction. A safe loop here would be deleted as dead stores and
// the secret would stay in memory -- the exact failure this module exists to
// prevent.
#[allow(unsafe_code)]
mod zeroize;

pub use error::{Error, ErrorKind, Result};
pub use zeroize::{Zeroize, Zeroizing};

/// The semantic version of the IronCrypto core contract.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether this build leaves out every algorithm FIPS 140-3 approved mode does
/// not permit.
///
/// Set by building with `--cfg ic_approved_only` in `RUSTFLAGS`, and in
/// `RUSTDOCFLAGS` for the documentation tests. A cfg rather than a Cargo
/// feature, for two reasons. Removing API is not additive, and Cargo unifies
/// features across a dependency graph, so a feature that any dependency turned
/// on would strip these algorithms from every other crate in the build; a cfg
/// is set only by whoever builds the final binary, which is who decides where a
/// module boundary lies. And `--all-features`, which tooling and this
/// repository's own checks use, would otherwise build only the restricted
/// configuration.
pub const APPROVED_ONLY: bool = cfg!(ic_approved_only);
