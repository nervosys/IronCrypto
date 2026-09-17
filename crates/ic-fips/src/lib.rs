//! # ic-fips — the FIPS 140-3 module boundary
//!
//! ## What this is, and what it is not
//!
//! This crate implements the *discipline* FIPS 140-3 asks for: a defined module
//! boundary, pre-operational self-tests, per-algorithm known-answer tests
//! (CASTs), a latching error state, an approved mode of operation that refuses
//! unapproved algorithms, and a service indicator that reports whether each
//! call was approved.
//!
//! **It is not a validated module.** IronCrypto holds no CMVP certificate,
//! and running [`initialize`] does not create one. Validation is a laboratory
//! process against a specific binary on specific platforms. What this crate
//! gives you is a codebase that is *shaped* for that process, and a runtime
//! that tells the truth about its own status — see
//! [`ic_ontology::runtime::has`] with `"fips-validated"`, which returns `false`
//! and will keep returning `false` until a certificate exists.
//!
//! Claiming otherwise to an auditor, a customer, or an agent would be a
//! misrepresentation, so every surface here is written to make the distinction
//! impossible to miss.
//!
//! ## Using it
//!
//! ```
//! use ic_fips::{initialize, Mode, ServiceIndicator};
//!
//! // Runs every known-answer test. Refuses service if any of them fail.
//! initialize()?;
//! ic_fips::set_mode(Mode::Approved)?;
//!
//! // Approved: AES-256-GCM is an approved security function.
//! assert_eq!(ic_fips::check("aes-256-gcm")?, ServiceIndicator::Approved);
//!
//! // Refused: ChaCha20-Poly1305 is not approved, so approved mode blocks it
//! // rather than letting it through with a warning.
//! assert!(ic_fips::check("chacha20-poly1305").is_err());
//! # Ok::<(), ic_core::Error>(())
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use core::sync::atomic::{AtomicU8, Ordering};

use ic_core::{ensure, Error, ErrorKind, Result};
use ic_ontology::{FipsStatus, ImplStatus};

pub mod selftest;

pub use selftest::{run_all_self_tests, SelfTestReport, TestOutcome};

// ---------------------------------------------------------------------------
// Module state machine
// ---------------------------------------------------------------------------

const STATE_UNINITIALIZED: u8 = 0;
const STATE_TESTING: u8 = 1;
const STATE_OPERATIONAL_UNRESTRICTED: u8 = 2;
const STATE_OPERATIONAL_APPROVED: u8 = 3;
const STATE_ERROR: u8 = 4;

static STATE: AtomicU8 = AtomicU8::new(STATE_UNINITIALIZED);

/// The module's operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Only algorithms the ontology marks as permitted in approved mode may be
    /// used. Everything else is refused.
    Approved,
    /// Every implemented algorithm is available.
    Unrestricted,
}

impl Mode {
    /// Stable identifier used in CLI and MCP output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Unrestricted => "unrestricted",
        }
    }
}

/// The module's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Self-tests have not run; no cryptographic service is available.
    Uninitialized,
    /// Self-tests are running.
    SelfTestInProgress,
    /// Operating normally in the given mode.
    Operational(Mode),
    /// A self-test failed. The module refuses all service until the process
    /// restarts; FIPS 140-3 requires the error state to latch.
    Error,
}

impl State {
    /// Stable identifier used in CLI and MCP output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::SelfTestInProgress => "self-test-in-progress",
            Self::Operational(Mode::Approved) => "operational-approved",
            Self::Operational(Mode::Unrestricted) => "operational-unrestricted",
            Self::Error => "error",
        }
    }
}

fn decode(raw: u8) -> State {
    match raw {
        STATE_TESTING => State::SelfTestInProgress,
        STATE_OPERATIONAL_UNRESTRICTED => State::Operational(Mode::Unrestricted),
        STATE_OPERATIONAL_APPROVED => State::Operational(Mode::Approved),
        STATE_ERROR => State::Error,
        _ => State::Uninitialized,
    }
}

/// The module's current state.
pub fn state() -> State {
    decode(STATE.load(Ordering::SeqCst))
}

/// The current mode, or `None` when the module is not operational.
pub fn mode() -> Option<Mode> {
    match state() {
        State::Operational(m) => Some(m),
        _ => None,
    }
}

/// Run the pre-operational self-tests and bring the module up.
///
/// Idempotent: calling it again once operational is a no-op that preserves the
/// current mode. If any known-answer test fails, the module latches into
/// [`State::Error`] and every subsequent call fails with
/// [`ErrorKind::ModuleErrorState`].
///
/// The module comes up [`Mode::Unrestricted`]; call [`set_mode`] to enter
/// approved mode. That ordering is deliberate — entering approved mode is a
/// decision the operator makes explicitly, never a default the caller might not
/// have noticed.
pub fn initialize() -> Result<SelfTestReport> {
    match state() {
        State::Error => {
            return Err(Error::new(
                ErrorKind::ModuleErrorState,
                "module in error state",
            ))
        }
        State::Operational(_) => return Ok(run_all_self_tests()),
        _ => {}
    }

    STATE.store(STATE_TESTING, Ordering::SeqCst);
    let report = run_all_self_tests();

    if report.failed > 0 {
        STATE.store(STATE_ERROR, Ordering::SeqCst);
        return Err(Error::new(
            ErrorKind::SelfTestFailed,
            "pre-operational self-test failed; module latched in error state",
        ));
    }

    STATE.store(STATE_OPERATIONAL_UNRESTRICTED, Ordering::SeqCst);
    Ok(report)
}

/// Switch the operating mode.
///
/// Requires the module to be operational; returns
/// [`ErrorKind::ModuleErrorState`] otherwise.
pub fn set_mode(new_mode: Mode) -> Result<()> {
    match state() {
        State::Operational(_) => {
            STATE.store(
                match new_mode {
                    Mode::Approved => STATE_OPERATIONAL_APPROVED,
                    Mode::Unrestricted => STATE_OPERATIONAL_UNRESTRICTED,
                },
                Ordering::SeqCst,
            );
            Ok(())
        }
        State::Error => Err(Error::new(
            ErrorKind::ModuleErrorState,
            "module in error state",
        )),
        _ => Err(Error::new(
            ErrorKind::ModuleErrorState,
            "call initialize() before selecting a mode",
        )),
    }
}

/// Force the module into its error state.
///
/// Exposed so an application that detects corruption elsewhere can bring the
/// module down with it. There is no way back short of restarting the process,
/// by design.
pub fn enter_error_state() {
    STATE.store(STATE_ERROR, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Service indicator
// ---------------------------------------------------------------------------

/// FIPS 140-3 requires a module to tell the caller whether the service it just
/// used was an approved one. This is that indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceIndicator {
    /// An approved security function, used in the approved mode.
    Approved,
    /// Permitted, but not itself an approved security function — a raw block
    /// cipher used as a component, for example.
    ApprovedAsComponent,
    /// A non-approved algorithm, used outside approved mode.
    NotApproved,
}

impl ServiceIndicator {
    /// Stable identifier used in CLI and MCP output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ApprovedAsComponent => "approved-as-component",
            Self::NotApproved => "not-approved",
        }
    }
}

/// Check whether `algorithm_id` may be used right now, and report its status.
///
/// This is the function every guarded call routes through. It enforces, in
/// order: the module is operational, the algorithm exists in the ontology, it
/// is implemented in this build, and — in approved mode — that it is permitted.
pub fn check(algorithm_id: &str) -> Result<ServiceIndicator> {
    match state() {
        State::Operational(_) => {}
        State::Error => {
            return Err(Error::new(
                ErrorKind::ModuleErrorState,
                "module in error state",
            ))
        }
        _ => {
            return Err(Error::new(
                ErrorKind::ModuleErrorState,
                "module not initialized; call ic_fips::initialize()",
            ))
        }
    }

    let entry = ic_ontology::get(algorithm_id)
        .ok_or(Error::new(ErrorKind::Unsupported, "unknown algorithm"))?;

    ensure!(
        entry.status == ImplStatus::Available,
        Unsupported,
        "algorithm is described by the ontology but not implemented in this build"
    );

    let approved_mode = mode() == Some(Mode::Approved);
    if approved_mode && !entry.fips.permitted_in_approved_mode() {
        return Err(Error::new(
            ErrorKind::NotApprovedInFipsMode,
            "algorithm is not approved; select an approved alternative or leave approved mode",
        ));
    }

    Ok(match entry.fips {
        FipsStatus::Approved | FipsStatus::Deprecated => ServiceIndicator::Approved,
        FipsStatus::AllowedAsComponent => ServiceIndicator::ApprovedAsComponent,
        FipsStatus::NotApproved | FipsStatus::Disallowed => ServiceIndicator::NotApproved,
    })
}

/// Run `op` only if `algorithm_id` is permitted, returning the result along
/// with the service indicator.
///
/// ```
/// use ic_fips::{guarded, initialize};
/// use ic_core::traits::Digest;
///
/// initialize()?;
/// let (digest, indicator) = guarded("sha2-256", || ic_hash::Sha256::digest(b"data"))?;
/// assert_eq!(indicator, ic_fips::ServiceIndicator::Approved);
/// # let _ = digest;
/// # Ok::<(), ic_core::Error>(())
/// ```
pub fn guarded<T, F: FnOnce() -> T>(algorithm_id: &str, op: F) -> Result<(T, ServiceIndicator)> {
    let indicator = check(algorithm_id)?;
    Ok((op(), indicator))
}

/// A statement of this module's validation status, for display to humans and
/// agents that ask.
///
/// Deliberately blunt: an agent reading capability flags should never be able
/// to conclude that an uncertified module is certified.
pub const VALIDATION_STATEMENT: &str = "\
IronCrypto implements the FIPS 140-3 operational discipline (approved-mode \
policy, pre-operational and conditional self-tests, a latching error state, and \
service indicators). It has NOT been submitted to or validated by the CMVP, and \
holds no certificate number. Do not represent it as FIPS validated.";

#[cfg(test)]
mod tests {
    use super::*;

    /// The module state is process-global, so the state-machine assertions run
    /// as one test rather than racing each other across threads.
    #[test]
    fn module_lifecycle_and_policy() {
        assert_eq!(state(), State::Uninitialized);

        // Nothing is permitted before initialization.
        assert_eq!(
            check("sha2-256").unwrap_err().kind(),
            ErrorKind::ModuleErrorState
        );
        assert_eq!(
            set_mode(Mode::Approved).unwrap_err().kind(),
            ErrorKind::ModuleErrorState
        );

        let report = initialize().unwrap();
        assert!(report.passed > 0);
        assert_eq!(report.failed, 0);
        assert_eq!(state(), State::Operational(Mode::Unrestricted));

        // Unrestricted mode permits everything implemented.
        assert_eq!(check("sha2-256").unwrap(), ServiceIndicator::Approved);
        assert_eq!(
            check("chacha20-poly1305").unwrap(),
            ServiceIndicator::NotApproved
        );
        assert_eq!(
            check("aes-256").unwrap(),
            ServiceIndicator::ApprovedAsComponent
        );

        // Unknown and unimplemented algorithms are distinguished from policy
        // refusals.
        assert_eq!(
            check("nonsense").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        // ML-KEM-768 and ML-DSA-65 used to be refused here. They were
        // FIPS-approved algorithms with working code and the status gated them
        // anyway, because approval is about the algorithm while availability is
        // about whether this implementation has been shown to *be* that
        // algorithm -- and only the second gates use. They are checked against
        // ACVP vectors now, so the second condition holds and they are accepted.
        assert!(check("ml-kem-768").is_ok());
        assert!(check("ml-dsa-65").is_ok());

        // AES-GCM-SIV still demonstrates the rule: it has working code and no
        // published vector wired in, so availability refuses it regardless of
        // what its approval status says.
        assert_eq!(
            check("aes-256-gcm-siv").unwrap_err().kind(),
            ErrorKind::Unsupported
        );

        // Approved mode refuses unapproved algorithms.
        set_mode(Mode::Approved).unwrap();
        assert_eq!(mode(), Some(Mode::Approved));
        assert_eq!(check("aes-256-gcm").unwrap(), ServiceIndicator::Approved);
        assert_eq!(
            check("chacha20-poly1305").unwrap_err().kind(),
            ErrorKind::NotApprovedInFipsMode
        );
        assert_eq!(
            check("ed25519").unwrap_err().kind(),
            ErrorKind::NotApprovedInFipsMode
        );
        assert_eq!(
            check("x25519").unwrap_err().kind(),
            ErrorKind::NotApprovedInFipsMode
        );

        // `guarded` gates the closure on the same policy.
        let (n, ind) = guarded("sha2-256", || 42).unwrap();
        assert_eq!(n, 42);
        assert_eq!(ind, ServiceIndicator::Approved);
        assert!(guarded("chacha20-poly1305", || 42).is_err());

        // Re-initializing is a no-op that preserves the mode.
        initialize().unwrap();
        assert_eq!(mode(), Some(Mode::Approved));

        set_mode(Mode::Unrestricted).unwrap();
        assert!(check("chacha20-poly1305").is_ok());

        // The error state latches: nothing works after it, including
        // initialize() and set_mode().
        enter_error_state();
        assert_eq!(state(), State::Error);
        assert_eq!(
            check("sha2-256").unwrap_err().kind(),
            ErrorKind::ModuleErrorState
        );
        assert_eq!(
            initialize().unwrap_err().kind(),
            ErrorKind::ModuleErrorState
        );
        assert_eq!(
            set_mode(Mode::Unrestricted).unwrap_err().kind(),
            ErrorKind::ModuleErrorState
        );
        assert_eq!(mode(), None);
    }

    #[test]
    fn state_identifiers_are_distinct() {
        let ids = [
            State::Uninitialized.id(),
            State::SelfTestInProgress.id(),
            State::Operational(Mode::Approved).id(),
            State::Operational(Mode::Unrestricted).id(),
            State::Error.id(),
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn validation_statement_denies_certification() {
        assert!(VALIDATION_STATEMENT.contains("NOT been submitted"));
        assert!(!ic_ontology::runtime::has("fips-validated"));
    }
}
