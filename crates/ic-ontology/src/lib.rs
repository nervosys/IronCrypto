//! # ic-ontology — the machine-readable cryptographic ontology
//!
//! This crate is what makes IronCrypto *agentic-first*. A conventional
//! crypto library documents itself for humans: prose, examples, a changelog.
//! An agent has to guess which primitive fits its task, guess whether its
//! deployment allows it, and guess what will go wrong. Each guess is a chance
//! to ship something broken.
//!
//! The ontology replaces those guesses with data:
//!
//! * **[`registry`]** — every algorithm, described in closed vocabulary terms:
//!   class, purpose, strength against classical *and* quantum adversaries,
//!   FIPS standing, standards, parameter bounds, usage constraints with
//!   severities, relations to other algorithms, and the exact Rust path to
//!   call.
//! * **[`Query`]** — filter by what the task needs, not by name.
//! * **[`select`]** — go straight from an [`Intent`] and a [`Policy`] to a
//!   [`Recommendation`] carrying the choice, the reasoning, the rejected
//!   alternatives, and the rules the caller must honour.
//! * **[`export`]** — emit the whole thing as JSON, JSON-LD, Turtle, or JSON
//!   Schema for tools that do not speak Rust.
//!
//! ## The property that matters most
//!
//! The registry describes algorithms this library does **not** implement. An
//! agent asked for a FIPS-approved signature learns that ECDSA P-256 is the
//! answer *and* that it is unavailable here, rather than being handed Ed25519
//! as a near-enough substitute:
//!
//! ```
//! use ic_ontology::select::{recommend, Intent, NoRecommendation, Policy};
//!
//! // ML-KEM is the right answer for post-quantum key agreement, and is not
//! // implemented here, so the selector declines rather than offering X25519.
//! let outcome = recommend(Intent::AgreeKey, Policy::POST_QUANTUM);
//! assert_eq!(
//!     outcome.unwrap_err(),
//!     NoRecommendation::KnownButUnavailable { id: "ml-kem-768" }
//! );
//! ```
//!
//! An honest "no" is worth more to an autonomous caller than a plausible
//! "yes".
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

#[cfg(feature = "std")]
extern crate std;

pub mod query;
pub mod registry;
pub mod select;
pub mod standards;
pub mod types;

#[cfg(feature = "std")]
pub mod export;
pub mod frameworks;

pub mod runtime;

pub use query::{all, get, related, Query};
pub use registry::REGISTRY;
pub use select::{recommend, Intent, NoRecommendation, Policy, Recommendation};
pub use types::{
    Class, Constraint, Edge, Entry, FipsStatus, ImplStatus, Param, Performance, Purpose, Relation,
    Severity, Strength, Unit,
};

/// The ontology's schema version.
///
/// Bumped when the vocabulary changes shape, independently of the library
/// version, so a consumer can tell whether its parser still applies.
pub const ONTOLOGY_VERSION: &str = "1.0";

/// The error catalog, mirroring [`ic_core::ErrorKind`].
///
/// Exposed here so an agent can learn the full failure vocabulary — and each
/// kind's recovery semantics — without triggering the errors first.
pub mod errors {
    use ic_core::ErrorKind;

    /// A described error kind.
    #[derive(Debug, Clone, Copy)]
    pub struct ErrorDoc {
        /// Stable identifier, matching [`ic_core::ErrorKind::id`].
        pub id: &'static str,
        /// What the failure means.
        pub meaning: &'static str,
        /// What the caller should do about it.
        pub recovery: &'static str,
        /// Whether retrying the identical call could succeed.
        pub retryable: bool,
        /// Whether changing the inputs could succeed.
        pub caller_correctable: bool,
    }

    const KINDS: &[(ErrorKind, &str, &str)] = &[
        (
            ErrorKind::InvalidLength,
            "A buffer was the wrong size for the algorithm's contract.",
            "Read the parameter bounds from the ontology entry and resize the buffer.",
        ),
        (
            ErrorKind::InvalidParameter,
            "A key, nonce, or parameter was structurally unacceptable.",
            "Check the entry's parameters and constraints; do not retry unchanged.",
        ),
        (
            ErrorKind::AuthenticationFailed,
            "A MAC, AEAD tag, or signature did not verify.",
            "Treat the data as hostile. Do not use any plaintext produced alongside it, and do not \
             report which byte differed.",
        ),
        (
            ErrorKind::Unsupported,
            "The algorithm is described by the ontology but not implemented in this build.",
            "Query the ontology for an available alternative, or obtain the algorithm elsewhere.",
        ),
        (
            ErrorKind::NotApprovedInFipsMode,
            "The operation is not permitted while the module is in approved mode.",
            "Select an approved algorithm, or leave approved mode deliberately and record that \
             decision.",
        ),
        (
            ErrorKind::SelfTestFailed,
            "A known-answer test failed; the module has entered its error state.",
            "Do not retry. The binary is corrupt or the build is broken; stop and investigate.",
        ),
        (
            ErrorKind::ModuleErrorState,
            "The module is latched in its error state and refuses all service.",
            "Restart the process. A latched error state is not clearable at runtime by design.",
        ),
        (
            ErrorKind::EntropyFailure,
            "The entropy source failed or was unavailable.",
            "Retry; if it persists, seed the DRBG from a source you supply.",
        ),
        (
            ErrorKind::CounterExhausted,
            "A DRBG reseed interval, GCM invocation limit, or sequence number ran out.",
            "Reseed or rekey. Continuing past the limit voids the security claim.",
        ),
        (
            ErrorKind::MalformedEncoding,
            "Input could not be decoded, or was encoded non-canonically.",
            "Fix the encoding. A non-canonical encoding is often an attack, not a bug.",
        ),
        (
            ErrorKind::Internal,
            "A library invariant was violated.",
            "This is a bug in IronCrypto. Report it with the context string.",
        ),
    ];

    /// Every error kind, documented.
    pub fn catalog() -> impl Iterator<Item = ErrorDoc> {
        KINDS.iter().map(|(kind, meaning, recovery)| ErrorDoc {
            id: kind.id(),
            meaning,
            recovery,
            retryable: kind.retryable(),
            caller_correctable: kind.caller_correctable(),
        })
    }

    /// Look up one error kind by identifier.
    pub fn get(id: &str) -> Option<ErrorDoc> {
        catalog().find(|d| d.id == id)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Every `ErrorKind` must be in the catalog.
        ///
        /// The test below checks the entries are unique and say something.
        /// Neither property notices an entry that is *absent*, and an
        /// undocumented error is the one case the catalog exists for: an agent
        /// that hits it gets a kind identifier and no guidance.
        ///
        /// Completeness is delegated to `ErrorKind::ALL`, because this type is
        /// `#[non_exhaustive]` and no crate but `ic-core` can match on it
        /// exhaustively. The compiler enforces the list there; this asserts the
        /// catalog covers it.
        #[test]
        fn every_error_kind_is_documented() {
            for kind in ErrorKind::ALL {
                assert!(
                    get(kind.id()).is_some(),
                    "{} has no catalog entry, so an agent that hits it gets an identifier and no guidance",
                    kind.id()
                );
            }
            assert_eq!(
                catalog().count(),
                ErrorKind::ALL.len(),
                "the catalog and the variant list disagree on how many kinds there are"
            );
        }

        #[test]
        fn catalog_is_complete_and_unique() {
            let docs: std::vec::Vec<_> = catalog().collect();
            assert_eq!(docs.len(), KINDS.len());
            for (i, a) in docs.iter().enumerate() {
                for b in docs.iter().skip(i + 1) {
                    assert_ne!(a.id, b.id);
                }
                assert!(!a.meaning.is_empty());
                assert!(!a.recovery.is_empty());
            }
        }

        #[test]
        fn authentication_failure_is_not_retryable_or_correctable() {
            let d = get("authentication-failed").unwrap();
            assert!(!d.retryable);
            assert!(!d.caller_correctable);
        }

        #[test]
        fn entropy_failure_is_the_retryable_one() {
            assert!(get("entropy-failure").unwrap().retryable);
            assert!(!get("internal").unwrap().retryable);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_available_entry_names_a_real_module_path() {
        // The path must at least point into one of the workspace crates.
        let prefixes = [
            "ic_hash::",
            "ic_mac::",
            "ic_cipher::",
            "ic_kdf::",
            "ic_drbg::",
            "ic_ec::",
            "ic_rsa::",
            "ic_mlkem::",
            "ic_mldsa::",
        ];
        for e in REGISTRY
            .iter()
            .filter(|e| matches!(e.status, ImplStatus::Available | ImplStatus::Experimental))
        {
            assert!(
                prefixes.iter().any(|p| e.rust_path.starts_with(p)),
                "{} points at {}, which is not a workspace crate",
                e.id,
                e.rust_path
            );
        }
    }

    #[test]
    fn ontology_version_is_set() {
        assert!(!ONTOLOGY_VERSION.is_empty());
    }
}
