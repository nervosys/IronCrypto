//! The module's error state, where every crate can see it.
//!
//! A cryptographic module that finds itself wrong -- a known-answer test that
//! fails, corruption detected by its host -- must stop producing output, and
//! must not start again until it is restarted. `ic_fips` runs the tests and
//! holds the rest of the module's state, but the primitive crates cannot
//! depend on it: it depends on them. So the one fact they all need lives
//! here, below them, as a flag that can be set and never cleared.
//!
//! Once [`enter_error_state`] has been called, every operation in this
//! library that can report an error reports
//! [`ErrorKind::ModuleErrorState`] and does nothing else: encryption and decryption, signing and verification,
//! key generation and agreement, MACs made from a key, key derivation and
//! random generation. The operations that return `bool` return `false`.
//!
//! # What this does not gate
//!
//! What has no error to return cannot refuse, and goes on working in the
//! error state:
//!
//! - Hash functions and XOFs: `Sha256::new`, `update` and `finalize`, and
//!   BLAKE2 with or without a key.
//! - KMAC, whose constructor and `mac` are infallible. Only `verify` refuses.
//! - A MAC object's `update` and `finalize`, once it exists. HMAC, CMAC and
//!   Poly1305 refuse where they are made, in `Mac::new`.
//! - ML-KEM's `keygen_deterministic` and `encapsulate_deterministic`, the
//!   interfaces that take their randomness as arguments.
//!
//! One thing that could refuse is left ungated on purpose: a block cipher
//! object's `encrypt_block`, `decrypt_block` and `encrypt_blocks`. They are
//! the inner loop of every mode, and every mode refuses at its own entry, as
//! does `BlockCipher::new`; a check per block would be paid by all of them
//! to stop only raw single-block use of a key made before the failure.
//!
//! Parsing and encoding, which use no key, are not gated either.
//!
//! Nor does anything here require the self-tests to have run. A primitive
//! called before `ic_fips::initialize` works; only a module that has failed
//! refuses. `ic_fips::check` remains the gate for that and for approved
//! mode.
//!
//! # Cost
//!
//! One relaxed load of one byte per operation.

use crate::{Error, ErrorKind, Result};
use core::sync::atomic::{AtomicBool, Ordering};

static FAILED: AtomicBool = AtomicBool::new(false);

/// Put the module into its error state.
///
/// There is no way back short of restarting the process, by design: nothing
/// in this library clears the flag. Applications call
/// `ic_fips::enter_error_state`, which calls this.
pub fn enter_error_state() {
    FAILED.store(true, Ordering::SeqCst);
}

/// Whether the module is in its error state.
#[inline]
#[must_use = "whether the module has failed; discarding it gates nothing"]
pub fn in_error_state() -> bool {
    FAILED.load(Ordering::Relaxed)
}

/// `Ok(())` unless the module is in its error state.
///
/// The first line of every operation that can refuse:
///
/// ```
/// fn service() -> ic_core::Result<()> {
///     ic_core::module::operational()?;
///     // ...
///     Ok(())
/// }
/// # service().unwrap();
/// ```
#[inline]
pub fn operational() -> Result<()> {
    if in_error_state() {
        return Err(Error::new(
            ErrorKind::ModuleErrorState,
            "module in error state",
        ));
    }
    Ok(())
}
