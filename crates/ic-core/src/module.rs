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
//! key generation and agreement, MACs, hashes and XOFs, key derivation and
//! random generation. The operations that return `bool` return `false`.
//!
//! Hashes, XOFs and MACs refuse on output -- `finalize`, `digest`, `xof`, a
//! reader's `read` or `fill`, `mac` -- so an object made before the failure
//! produces nothing after it. Making one and feeding it input produce no
//! output, and are not refused. Until 0.3.0 those interfaces had no error to
//! return and could not refuse at all; they were the gate's stated limit.
//!
//! # What this does not gate
//!
//! The primitives call one another through `ic_core::traits::internal`, which
//! does not refuse: a signature or a KDF refuses at its own entry, and does
//! not check again for each hash on the way to its answer. That module is
//! hidden and not API; a caller who names it has stepped inside the boundary.
//!
//! One thing that could refuse is left ungated on purpose: a block cipher
//! object's `encrypt_block`, `decrypt_block` and `encrypt_blocks`. They are
//! the inner loop of every mode, and every mode refuses at its own entry, as
//! does `BlockCipher::new`; a check per block would be paid by all of them
//! to stop only raw single-block use of a key made before the failure.
//!
//! Parsing and encoding, which use no key, are not gated either.
//!
//! # Before the self-tests
//!
//! In the default build nothing here requires the self-tests to have run: a
//! primitive called before `ic_fips::initialize` works, and only a module that
//! has failed refuses. `ic_fips::check` is the gate for that.
//!
//! A build with `--cfg ic_approved_only` closes it. There, every operation
//! that consults [`operational`] also refuses, with
//! [`ErrorKind::ModuleErrorState`], until `ic_fips::initialize` has run the
//! known-answer tests and they have passed. FIPS 140-3 asks for the
//! self-tests before a service is first used, and in that build it no longer
//! depends on the caller asking for them.
//!
//! While the tests run, the primitives they call are let through, since the
//! tests are made of them. A second thread that calls a primitive in that
//! window is let through too: nothing below `ic_fips` can tell the two threads
//! apart without `std`. A program that starts threads before `initialize`
//! returns should not use the library from them until it does.
//!
//! This repository's own test suites are made of primitive calls that do not
//! go through `ic_fips`, and the crates that hold them cannot depend on it, so
//! `scripts/approved-only.sh` runs them with `--cfg ic_startup_gate_off` as
//! well, which turns this gate, and only this gate, off. It is a test switch:
//! a build with it does not run its self-tests before use. The same script
//! then runs the tests that show the gate refusing, without it.
//!
//! # Cost
//!
//! One relaxed load of one byte per operation.

use crate::{Error, ErrorKind, Result};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static FAILED: AtomicBool = AtomicBool::new(false);

const UNTESTED: u8 = 0;
const TESTING: u8 = 1;
const PASSED: u8 = 2;

/// How far the known-answer tests have got. Consulted only in a build with
/// `--cfg ic_approved_only`; see the module documentation.
static SELF_TESTS: AtomicU8 = AtomicU8::new(UNTESTED);

/// Whether this build refuses service until the self-tests have passed.
const STARTUP_GATE: bool = cfg!(all(ic_approved_only, not(ic_startup_gate_off)));

/// Record that the known-answer tests have started.
///
/// For `ic_fips::initialize`, which runs them. Until [`self_tests_passed`] is
/// called the primitives the tests use are let through, so that the tests can
/// run at all.
pub fn self_tests_started() {
    // Only forward: a module that has passed does not go back to testing
    // when `initialize` is called again. A load and a store rather than a
    // compare-exchange, which Cortex-M0 does not have; two racing callers can
    // at worst leave the state at TESTING after a pass, which lets service
    // through as PASSED does.
    if SELF_TESTS.load(Ordering::SeqCst) == UNTESTED {
        SELF_TESTS.store(TESTING, Ordering::SeqCst);
    }
}

/// Record that every known-answer test passed.
///
/// For `ic_fips::initialize`. Calling it any other way skips the tests it
/// stands for; the error state still overrides it.
pub fn self_tests_passed() {
    SELF_TESTS.store(PASSED, Ordering::SeqCst);
}

/// Whether the known-answer tests have passed in this process.
#[must_use]
pub fn self_tests_have_passed() -> bool {
    SELF_TESTS.load(Ordering::SeqCst) == PASSED
}

/// Put the module into its error state.
///
/// There is no way back short of restarting the process, by design: nothing
/// in this library clears the flag. Applications call
/// `ic_fips::enter_error_state`, which calls this.
pub fn enter_error_state() {
    FAILED.store(true, Ordering::SeqCst);
}

/// Pass on the result of a conditional self-test, entering the error state
/// if it failed.
///
/// A conditional self-test is one a module runs on its own work as it goes:
/// the pairwise consistency test on a key pair it has just generated. Its
/// input is the module's own output, never a caller's, so a failure is not
/// something a peer can cause -- it means this module computed two things
/// that should agree and do not, and nothing it computes afterwards can be
/// vouched for.
///
/// Key generation wraps its test in this. The test functions themselves do
/// not enter the state, so that they can be shown rejecting a mismatched
/// pair without ending the process that shows it.
pub fn conditional_self_test(result: Result<()>) -> Result<()> {
    if result.is_err() {
        enter_error_state();
    }
    result
}

/// Whether the module is in its error state.
#[inline]
#[must_use = "whether the module has failed; discarding it gates nothing"]
pub fn in_error_state() -> bool {
    FAILED.load(Ordering::Relaxed)
}

/// `Ok(())` unless the module is in its error state -- or, in a build with
/// `--cfg ic_approved_only`, has not yet passed its self-tests.
///
/// The first line of every operation that can refuse:
///
/// ```
/// fn service() -> ic_core::Result<()> {
///     ic_core::module::operational()?;
///     // ...
///     Ok(())
/// }
/// # ic_core::module::self_tests_passed(); // what ic_fips::initialize records
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
    if STARTUP_GATE && SELF_TESTS.load(Ordering::Relaxed) == UNTESTED {
        return Err(Error::new(
            ErrorKind::ModuleErrorState,
            "self-tests have not run; call ic_fips::initialize() first",
        ));
    }
    Ok(())
}
