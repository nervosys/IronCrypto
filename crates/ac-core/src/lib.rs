//! # ac-core — foundational types for AgenticCrypto
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
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod codec;
pub mod cpu;
pub mod ct;
pub mod entropy;
pub mod traits;

mod error;
mod zeroize;

pub use error::{Error, ErrorKind, Result};
pub use zeroize::{Zeroize, Zeroizing};

/// The semantic version of the AgenticCrypto core contract.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
