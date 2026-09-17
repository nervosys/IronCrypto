//! The single error domain for the whole library.

use core::fmt;

/// Result alias used by every fallible operation in IronCrypto.
pub type Result<T> = core::result::Result<T, Error>;

/// Machine-actionable classification of a failure.
///
/// The discriminants are stable and are mirrored verbatim into the ontology
/// (`ic-ontology::error_catalog`) so an agent can reason about recovery
/// strategy without parsing English prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A buffer was too short or too long for the algorithm's contract.
    InvalidLength,
    /// A key, nonce, or parameter was structurally unacceptable.
    InvalidParameter,
    /// Authentication (MAC / AEAD tag / signature) failed to verify.
    AuthenticationFailed,
    /// The requested algorithm exists but is not implemented in this build.
    Unsupported,
    /// The operation is not permitted while the module is in FIPS approved mode.
    NotApprovedInFipsMode,
    /// A FIPS 140-3 self-test failed; the module has entered the error state.
    SelfTestFailed,
    /// The module is in a hard error state and refuses all cryptographic service.
    ModuleErrorState,
    /// The entropy source failed or did not pass its health tests.
    EntropyFailure,
    /// A counter (DRBG reseed, GCM invocation, sequence number) was exhausted.
    CounterExhausted,
    /// Input could not be decoded (hex, base64, DER, point encoding).
    MalformedEncoding,
    /// An internal invariant was violated — always a library bug.
    Internal,
}

impl ErrorKind {
    /// Every kind, for callers that enumerate them.
    ///
    /// This type is `#[non_exhaustive]`, so no other crate can match on it
    /// exhaustively and none can tell whether it has seen them all. That is
    /// deliberate — it lets a variant be added without breaking callers — but
    /// it also means a list like the ontology's error catalog cannot check its
    /// own completeness. This crate can, so the list is published from here and
    /// a test keeps it honest.
    pub const ALL: &'static [ErrorKind] = &[
        ErrorKind::InvalidLength,
        ErrorKind::InvalidParameter,
        ErrorKind::AuthenticationFailed,
        ErrorKind::MalformedEncoding,
        ErrorKind::Unsupported,
        ErrorKind::NotApprovedInFipsMode,
        ErrorKind::SelfTestFailed,
        ErrorKind::ModuleErrorState,
        ErrorKind::EntropyFailure,
        ErrorKind::CounterExhausted,
        ErrorKind::Internal,
    ];

    /// Stable kebab-case identifier used in ontology exports and CLI/MCP output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::InvalidLength => "invalid-length",
            Self::InvalidParameter => "invalid-parameter",
            Self::AuthenticationFailed => "authentication-failed",
            Self::Unsupported => "unsupported",
            Self::NotApprovedInFipsMode => "not-approved-in-fips-mode",
            Self::SelfTestFailed => "self-test-failed",
            Self::ModuleErrorState => "module-error-state",
            Self::EntropyFailure => "entropy-failure",
            Self::CounterExhausted => "counter-exhausted",
            Self::MalformedEncoding => "malformed-encoding",
            Self::Internal => "internal",
        }
    }

    /// Whether retrying the identical call could plausibly succeed.
    ///
    /// Agents use this to decide between *retry*, *re-parameterize*, and *abort*.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::EntropyFailure)
    }

    /// Whether the caller should change inputs and try again.
    #[must_use]
    pub const fn caller_correctable(self) -> bool {
        matches!(
            self,
            Self::InvalidLength
                | Self::InvalidParameter
                | Self::MalformedEncoding
                | Self::Unsupported
                | Self::NotApprovedInFipsMode
                | Self::CounterExhausted
        )
    }
}

/// A failure from any IronCrypto operation.
///
/// Deliberately opaque about *why* an authentication check failed — the
/// [`ErrorKind`] is the only distinguishing datum for verification failures, so
/// error handling cannot become a decryption oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    context: &'static str,
}

impl Error {
    /// Construct an error with a static context string (an algorithm or field name).
    pub const fn new(kind: ErrorKind, context: &'static str) -> Self {
        Self { kind, context }
    }

    /// The machine-actionable classification.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// A short static hint naming the failing parameter or component.
    pub const fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.id(), self.context)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Shorthand for building an [`Error`].
#[macro_export]
macro_rules! err {
    ($kind:ident, $ctx:literal) => {
        $crate::Error::new($crate::ErrorKind::$kind, $ctx)
    };
}

/// Shorthand for `return Err(err!(..))` guarded by a condition.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $kind:ident, $ctx:literal) => {
        if !($cond) {
            return Err($crate::Error::new($crate::ErrorKind::$kind, $ctx));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` must really be all of them.
    ///
    /// The match below is exhaustive, and this is the crate that defines the
    /// type, so `#[non_exhaustive]` does not apply here and adding a variant
    /// stops this compiling until it is handled. Requiring `ALL` to contain
    /// each one is what turns "the compiler noticed" into "the list was
    /// updated".
    #[test]
    fn the_variant_list_is_complete() {
        // The match is a no-op by construction, and that is the point: it
        // exists so the compiler refuses this file when a variant is added,
        // not to compute anything. Clippy is right that it does nothing and
        // wrong that it is therefore unnecessary.
        #[allow(clippy::needless_match)]
        fn identify(kind: ErrorKind) -> ErrorKind {
            match kind {
                ErrorKind::InvalidLength => ErrorKind::InvalidLength,
                ErrorKind::InvalidParameter => ErrorKind::InvalidParameter,
                ErrorKind::AuthenticationFailed => ErrorKind::AuthenticationFailed,
                ErrorKind::MalformedEncoding => ErrorKind::MalformedEncoding,
                ErrorKind::Unsupported => ErrorKind::Unsupported,
                ErrorKind::NotApprovedInFipsMode => ErrorKind::NotApprovedInFipsMode,
                ErrorKind::SelfTestFailed => ErrorKind::SelfTestFailed,
                ErrorKind::ModuleErrorState => ErrorKind::ModuleErrorState,
                ErrorKind::EntropyFailure => ErrorKind::EntropyFailure,
                ErrorKind::CounterExhausted => ErrorKind::CounterExhausted,
                ErrorKind::Internal => ErrorKind::Internal,
            }
        }

        // The match catches a variant being added: it stops compiling until
        // the new one is handled, and handling it means editing the list right
        // there. It does not catch one being dropped from `ALL`, because a
        // shorter list still maps each of its members to itself. This count
        // sits beside the match so the two are edited together.
        assert_eq!(ErrorKind::ALL.len(), 11);

        for kind in ErrorKind::ALL {
            assert_eq!(identify(*kind), *kind);
        }

        // Identifiers are the join key the ontology matches on, so a duplicate
        // would make two kinds indistinguishable to every consumer. Compared
        // pairwise rather than collected, since this crate has no allocator.
        for (i, a) in ErrorKind::ALL.iter().enumerate() {
            for b in ErrorKind::ALL.iter().skip(i + 1) {
                assert_ne!(a.id(), b.id(), "two kinds share an identifier");
            }
            assert!(!a.id().is_empty());
        }
    }
}
