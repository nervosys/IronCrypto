//! The standards knowledgebase: documents, and the obligations they impose.
//!
//! [`crate::registry`] says what algorithms exist. This says what *documents*
//! define them, and what those documents require of an implementation. Before
//! this module, `standards: &["FIPS 203"]` was a bare string — nothing knew
//! what FIPS 203 was, whether it was current, or whether the library did what
//! it says.
//!
//! # Self-reinforcing, not merely adjacent
//!
//! A knowledgebase that sits beside the code and is never checked against it
//! rots, and rotted documentation is worse than none because people believe it.
//! So the tests here couple the two in both directions:
//!
//! - Every standard cited by a registry entry must exist here, and every
//!   standard here must be cited by an entry or declared as governing the
//!   module. Neither list can grow without the other noticing.
//! - Every requirement's `applies_to` must name real algorithms.
//! - **A requirement claiming to be met must name a file that exists and a
//!   symbol that appears in it.** Rename the function and the knowledgebase
//!   fails the build rather than going quietly out of date. This is the check
//!   that makes the difference between a document and a fixture.
//! - A superseded or withdrawn document cannot be the sole basis of an
//!   algorithm the library presents as available.
//! - Prose carries no embedded whitespace runs, because these strings are what
//!   the CLI and the MCP responses print.
//!
//! # What is claimed here, and what is not
//!
//! Titles, years and identifiers are transcribed from the publication record.
//! The *internal* consistency of this module is machine-checked; the external
//! facts are not, because nothing in this repository can reach a publisher.
//! Anything load-bearing for a compliance decision should be confirmed against
//! the document itself, and [`Standard::url`] is constructed from each
//! publisher's canonical scheme — asserted as a rule in the tests — rather than
//! transcribed link by link.
//!
//! Nothing here asserts that this library is FIPS 140-3 validated. It is not.
//! A requirement marked [`Compliance::Met`] means the code does what the
//! document asks, as far as the tests can show; it does not mean a laboratory
//! has agreed, and no amount of this file changes that.

use crate::registry::REGISTRY;

/// Whether a document governs one algorithm or the module as a whole.
///
/// This exists so the "every document must be cited by an entry" rule can have
/// a principled exception rather than a hardcoded identifier. FIPS 140-3 binds
/// the module and names no algorithm; neither does SP 800-131A, which is about
/// transitions rather than constructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Defines constructions that registry entries implement.
    Algorithm,
    /// Governs the module as a whole, and is cited by no entry.
    Module,
}

impl Scope {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Algorithm => "algorithm",
            Self::Module => "module",
        }
    }
}

/// Who published a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// NIST: FIPS publications and the SP 800 series.
    Nist,
    /// The IETF: RFCs.
    Ietf,
}

impl Body {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Nist => "nist",
            Self::Ietf => "ietf",
        }
    }
}

/// Whether a document is still the one to build against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardStatus {
    /// In force.
    Current,
    /// Replaced by a later document, named in [`Standard::superseded_by`].
    Superseded,
    /// Withdrawn without a direct replacement.
    Withdrawn,
    /// Never normative — published for information, or cited here only as
    /// background for an algorithm defined elsewhere.
    Informational,
}

impl StandardStatus {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Superseded => "superseded",
            Self::Withdrawn => "withdrawn",
            Self::Informational => "informational",
        }
    }

    /// Whether new work should be built against this document.
    pub const fn is_current(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// How binding a requirement is, in the drafting sense.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Obligation {
    /// The document says "shall": mandatory.
    Shall,
    /// The document says "shall not": prohibited.
    ShallNot,
    /// The document says "should": recommended.
    Should,
    /// The document says "may": permitted.
    May,
}

impl Obligation {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Shall => "shall",
            Self::ShallNot => "shall-not",
            Self::Should => "should",
            Self::May => "may",
        }
    }

    /// Whether ignoring this is a conformance failure rather than a choice.
    pub const fn is_mandatory(self) -> bool {
        matches!(self, Self::Shall | Self::ShallNot)
    }
}

/// What this library does about a requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compliance {
    /// Implemented, and here is the evidence.
    ///
    /// `file` is relative to the workspace root and `symbol` must appear in
    /// it. The tests check both, so this cannot silently go stale.
    ///
    /// `symbol` names either the implementing function or the test that
    /// demonstrates the obligation is met, whichever is the better evidence.
    /// For a requirement like "decapsulation must never fail on a bad
    /// ciphertext" there is no function to point at — the obligation is a
    /// property of the whole path, and the test that exercises it is the only
    /// honest citation.
    Met {
        /// Workspace-relative path to the implementing file.
        file: &'static str,
        /// A symbol or phrase that must appear in that file.
        symbol: &'static str,
    },
    /// Implemented as far as a pure-source library can, with the gap named.
    ///
    /// This variant exists because forcing a binary answer produces a false
    /// one. The module integrity test is the case that motivated it: what runs
    /// is a real check over the embedded constant pool, but it is not a check
    /// over the executable image, and calling that either met or unmet would
    /// mislead in opposite directions.
    Partial {
        /// Workspace-relative path to what is implemented.
        file: &'static str,
        /// A symbol or phrase that must appear in that file.
        symbol: &'static str,
        /// What is still missing, and what closing it would take.
        gap: &'static str,
    },
    /// Out of scope, with a reason.
    NotApplicable {
        /// Why this library is not obliged.
        why: &'static str,
    },
    /// Applies, and is not done. Recorded rather than hidden.
    Unmet {
        /// What is missing, and what it would take.
        why: &'static str,
    },
}

impl Compliance {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Met { .. } => "met",
            Self::Partial { .. } => "partial",
            Self::NotApplicable { .. } => "not-applicable",
            Self::Unmet { .. } => "unmet",
        }
    }
}

/// One normative obligation drawn from a document.
#[derive(Debug, Clone, Copy)]
pub struct Requirement {
    /// Stable identifier, unique across the knowledgebase.
    pub id: &'static str,
    /// Where in the document it comes from.
    pub section: &'static str,
    /// How binding it is.
    pub obligation: Obligation,
    /// What the document requires, in plain words.
    pub statement: &'static str,
    /// Why it exists — the failure it prevents.
    pub rationale: &'static str,
    /// Registry entry ids this bears on. Empty means the whole library.
    pub applies_to: &'static [&'static str],
    /// What this library does about it.
    pub compliance: Compliance,
}

/// A published document.
#[derive(Debug, Clone, Copy)]
pub struct Standard {
    /// Citation as it appears in registry entries, e.g. `"FIPS 203"`.
    pub id: &'static str,
    /// Full title.
    pub title: &'static str,
    /// Publisher.
    pub body: Body,
    /// Whether it governs an algorithm or the whole module.
    pub scope: Scope,
    /// Year of the edition this describes.
    pub year: u16,
    /// Whether it is still in force.
    pub status: StandardStatus,
    /// Documents that replaced it.
    pub superseded_by: &'static [&'static str],
    /// Canonical locator, constructed from the publisher's scheme.
    pub url: &'static str,
    /// What it covers, and why an implementer would open it.
    pub summary: &'static str,
    /// Obligations drawn from it that bear on this library.
    pub requirements: &'static [Requirement],
}

impl Standard {
    /// Whether any registry entry cites this document.
    pub fn is_cited(&self) -> bool {
        REGISTRY.iter().any(|e| e.standards.contains(&self.id))
    }

    /// Registry entries that cite this document.
    pub fn algorithms(&self) -> impl Iterator<Item = &'static str> + '_ {
        REGISTRY
            .iter()
            .filter(move |e| e.standards.contains(&self.id))
            .map(|e| e.id)
    }
}

/// Look a document up by its citation.
pub fn standard(id: &str) -> Option<&'static Standard> {
    STANDARDS.iter().find(|s| s.id.eq_ignore_ascii_case(id))
}

/// Look a requirement up by its identifier.
pub fn requirement(id: &str) -> Option<(&'static Standard, &'static Requirement)> {
    STANDARDS.iter().find_map(|s| {
        s.requirements
            .iter()
            .find(|r| r.id.eq_ignore_ascii_case(id))
            .map(|r| (s, r))
    })
}

/// Every requirement in the knowledgebase, with the document it came from.
pub fn requirements() -> impl Iterator<Item = (&'static Standard, &'static Requirement)> {
    STANDARDS
        .iter()
        .flat_map(|s| s.requirements.iter().map(move |r| (s, r)))
}

/// Documents that define the algorithms a given entry provides.
pub fn standards_for(algorithm_id: &str) -> impl Iterator<Item = &'static Standard> + '_ {
    STANDARDS.iter().filter(move |s| {
        REGISTRY
            .iter()
            .any(|e| e.id == algorithm_id && e.standards.contains(&s.id))
    })
}

// ---------------------------------------------------------------------------
// Requirements, grouped with the documents they come from.
// ---------------------------------------------------------------------------

const FIPS203_REQS: [Requirement; 3] = [
    Requirement {
        id: "fips-203-encaps-key-check",
        section: "7.2",
        obligation: Obligation::Shall,
        statement: "Before encapsulating, check that the encapsulation key decodes and \
                    re-encodes to itself, rejecting coefficients at or above q.",
        rationale: "ByteDecode12 folds an out-of-range coefficient back into the field, so \
                    without the check a peer who sends a malformed key controls which key it \
                    is silently reinterpreted as.",
        applies_to: &["ml-kem-768"],
        compliance: Compliance::Met {
            file: "crates/ic-mlkem/src/kem.rs",
            symbol: "validate_encapsulation_key",
        },
    },
    Requirement {
        id: "fips-203-decaps-key-hash-check",
        section: "7.3",
        obligation: Obligation::Shall,
        statement: "Before decapsulating, check that the hash stored in the decapsulation key \
                    matches a hash of the encapsulation key it carries.",
        rationale: "Catches corruption, and catches a key assembled from two different key \
                    pairs, which would otherwise surface only as shared secrets that never \
                    agree with the peer.",
        applies_to: &["ml-kem-768"],
        compliance: Compliance::Met {
            file: "crates/ic-mlkem/src/kem.rs",
            symbol: "validate_decapsulation_key",
        },
    },
    Requirement {
        id: "fips-203-implicit-rejection",
        section: "6.3",
        obligation: Obligation::Shall,
        statement: "Decapsulation of a ciphertext that does not re-encrypt to itself shall \
                    return a pseudorandom shared secret derived from the rejection seed, not \
                    an error.",
        rationale: "The error would itself be a decryption oracle, which is precisely what the Fujisaki-Okamoto transform exists to remove. Returning a secret either way is necessary but not sufficient: the two paths must also be indistinguishable by timing, or the oracle returns through the side door. `ic timing mlkem-decapsulate` measures exactly that.",
        applies_to: &["ml-kem-768"],
        compliance: Compliance::Met {
            file: "crates/ic-mlkem/src/kem.rs",
            symbol: "no_ciphertext_can_make_decapsulation_fail",
        },
    },
];

const FIPS204_REQS: [Requirement; 3] = [
    Requirement {
        id: "fips-204-hint-decoding",
        section: "7.2",
        obligation: Obligation::Shall,
        statement: "Signature decoding shall reject a hint block whose indices are not \
                    strictly increasing within a polynomial, whose counts decrease or exceed \
                    omega, or whose unused bytes are nonzero.",
        rationale: "Without all three, one signature has several encodings and can be rewritten \
                    without invalidating it.",
        applies_to: &["ml-dsa-65"],
        compliance: Compliance::Met {
            file: "crates/ic-mldsa/src/encode.rs",
            symbol: "hint_unpack",
        },
    },
    Requirement {
        id: "fips-204-prehash-variant",
        section: "5.4",
        obligation: Obligation::May,
        statement: "An implementation may offer HashML-DSA, which signs a digest of the message rather than the message itself.",
        rationale: "The two variants use different domain separator bytes, so they are not interchangeable. A caller that needs the pre-hash variant must not approximate it by handing a digest to pure ML-DSA: the result verifies against nothing.",
        applies_to: &["ml-dsa-65"],
        compliance: Compliance::Met {
            file: "crates/ic-mldsa/src/sign.rs",
            symbol: "the_pure_and_prehash_variants_are_separated",
        },
    },
    Requirement {
        id: "fips-204-z-bound",
        section: "8.3",
        obligation: Obligation::Shall,
        statement: "Verification shall reject a signature whose z has any coefficient at or \
                    above gamma1 - beta in absolute value.",
        rationale: "The bound is what stops a forger enlarging z; nothing else in verification \
                    fails without it.",
        applies_to: &["ml-dsa-65"],
        compliance: Compliance::Met {
            file: "crates/ic-mldsa/src/sign.rs",
            symbol: "an_oversized_z_is_refused",
        },
    },
];

const FIPS186_REQS: [Requirement; 2] = [
    Requirement {
        id: "fips-186-5-unique-k",
        section: "6.4",
        obligation: Obligation::Shall,
        statement: "Each ECDSA signature shall use a per-message secret k that is unique and \
                    unpredictable.",
        rationale: "Two signatures under one k reveal the private key by elementary algebra. \
                    This library derives k deterministically per RFC 6979, so uniqueness holds \
                    by construction and there is no RNG in the signing path.",
        applies_to: &[
            "ecdsa-p256-sha256",
            "ecdsa-p384-sha384",
            "ecdsa-p521-sha512",
        ],
        compliance: Compliance::Met {
            file: "crates/ic-ec/src/nist/ecdsa.rs",
            symbol: "bits2int",
        },
    },
    Requirement {
        id: "fips-186-5-point-validation",
        section: "A.4",
        obligation: Obligation::Shall,
        statement: "A public key received from elsewhere shall be checked to lie on the curve \
                    before use.",
        rationale: "An off-curve point places the computation in a group the attacker chose, \
                    which leaks the private scalar a few bits at a time.",
        applies_to: &["ecdh-p256", "ecdh-p384", "ecdsa-p256-sha256"],
        compliance: Compliance::Met {
            file: "crates/ic-ec/src/nist/point.rs",
            symbol: "is_on_curve",
        },
    },
];

const FIPS140_REQS: [Requirement; 6] = [
    Requirement {
        id: "fips-140-3-cast-before-use",
        section: "AS10.35",
        obligation: Obligation::Shall,
        statement: "Each approved algorithm shall pass a cryptographic algorithm self-test \
                    before its first operational use.",
        rationale: "A module that never checks itself cannot know it is computing the function \
                    it claims, and a corrupted build looks exactly like a correct one.",
        applies_to: &[],
        compliance: Compliance::Met {
            file: "crates/ic-fips/src/selftest.rs",
            symbol: "tested_algorithms",
        },
    },
    Requirement {
        id: "fips-140-3-error-state",
        section: "AS10.37",
        obligation: Obligation::Shall,
        statement: "On a self-test failure the module shall enter an error state and refuse \
                    cryptographic services until reset.",
        rationale: "Continuing after a failed self-test produces output nobody can vouch for \
                    while reporting success.",
        applies_to: &[],
        compliance: Compliance::Met {
            file: "crates/ic-fips/src/lib.rs",
            symbol: "enter_error_state",
        },
    },
    Requirement {
        id: "fips-140-3-pairwise-consistency",
        section: "AS10.35 / IG 10.3.A",
        obligation: Obligation::Shall,
        statement: "A generated asymmetric key pair shall pass a pairwise consistency test before the key is used.",
        rationale: "Catches a key pair whose halves do not correspond: a faulted exponent, a mis-assembled CRT parameter, a bit flipped after the primality tests passed. Every structural check still passes on such a key, and only applying both operations in turn reveals it. Otherwise the failure appears at the far end, as signatures nobody can verify.",
        applies_to: &["rsa-pkcs1-sha256", "ml-kem-768", "ml-dsa-65"],
        compliance: Compliance::Met {
            file: "crates/ic-mlkem/src/kem.rs",
            symbol: "the_pairwise_consistency_test_rejects_a_mismatched_pair",
        },
    },
    Requirement {
        id: "fips-140-3-software-integrity",
        section: "AS10.32",
        obligation: Obligation::Shall,
        statement: "The module shall verify the integrity of its executable image before providing any cryptographic service.",
        rationale: "A corrupted or partially linked binary looks exactly like a correct one until it computes the wrong answer.",
        applies_to: &[],
        compliance: Compliance::Partial {
            file: "crates/ic-fips/src/selftest.rs",
            symbol: "integrity_check",
            gap: "What runs is an HMAC over the self-test vector table. That detects a corrupted constant pool and is a real check: flip a byte in any embedded vector and it fails. It is not a check over the executable image. Doing that needs a post-link step that patches a digest into the binary, which is a property of the build system rather than of any source file, so no amount of work in this repository alone closes it.",
        },
    },
    Requirement {
        id: "fips-140-3-zeroization",
        section: "AS09.28",
        obligation: Obligation::Shall,
        statement: "Secret and private key material shall be zeroized when no longer needed.",
        rationale: "Key material left in freed memory outlives the operation that needed it, and can be recovered from a core dump, a swapped page or a reused allocation.",
        applies_to: &[],
        compliance: Compliance::Partial {
            file: "crates/iron-crypto/tests/api_hygiene.rs",
            symbol: "secret_bearing_types_wipe_on_drop",
            gap: "Rust cannot guarantee a wipe survives moves and optimisation, so every case here is best-effort rather than a guarantee, and that is the honest ceiling on this requirement. Within it, the types that hold secret or key-derived state are enumerated in `api_hygiene.rs` and each is asserted to implement Drop, so removing one fails the build. Hmac is deliberately not on that list: it holds two digest states with the key already absorbed, and those states wipe themselves, so it inherits the property through field drop rather than restating it. What is not covered is material a caller holds -- a private key passed in as a slice is the caller's memory and the caller's responsibility, and no library can discharge that."
        },
    },
    Requirement {
        id: "fips-140-3-validation-claim",
        section: "General",
        obligation: Obligation::ShallNot,
        statement: "A module shall not be represented as validated unless a certificate has \
                    been issued for it.",
        rationale: "This library has no certificate. Every surface that could imply otherwise \
                    reports false, and this entry exists so the claim is recorded as a \
                    requirement that is deliberately and permanently met by saying no.",
        applies_to: &[],
        compliance: Compliance::Met {
            file: "crates/ic-ontology/src/runtime.rs",
            symbol: "fips-validated",
        },
    },
];

const SP80090A_REQS: [Requirement; 3] = [
    Requirement {
        id: "sp-800-90a-reseed-interval",
        section: "10.2.1",
        obligation: Obligation::Shall,
        statement: "A CTR_DRBG shall not generate more than the reseed interval's worth of \
                    output without reseeding.",
        rationale: "The bound is what keeps the generator's output computationally separated \
                    from its internal state over time.",
        applies_to: &["ctr-drbg-aes-256"],
        compliance: Compliance::Met {
            file: "crates/ic-drbg/src/ctr.rs",
            symbol: "reseed_counter",
        },
    },
    Requirement {
        id: "sp-800-90a-health-tests",
        section: "11.3",
        obligation: Obligation::Shall,
        statement: "A DRBG shall perform health testing on its instantiate, generate and reseed functions.",
        rationale: "A generator that has silently stopped generating, returning a constant or repeating a state, produces output indistinguishable from success to every caller.",
        applies_to: &["ctr-drbg-aes-256", "hmac-drbg-sha2-256"],
        compliance: Compliance::Partial {
            file: "crates/ic-fips/src/selftest.rs",
            symbol: "ctr-drbg-aes-256",
            gap: "Known-answer tests run on both DRBGs as part of the pre-operational self tests, which covers the on-demand half of the requirement. Continuous health testing during operation, re-running a known answer periodically as output is drawn, is not implemented.",
        },
    },
    Requirement {
        id: "sp-800-90a-instantiate-entropy",
        section: "8.6.3",
        obligation: Obligation::Shall,
        statement: "Instantiation shall draw at least the security strength in entropy, and \
                    shall fail rather than proceed with less.",
        rationale: "A generator seeded with less entropy than its declared strength is weaker \
                    than it claims, in a way no later operation can repair.",
        applies_to: &["ctr-drbg-aes-256"],
        compliance: Compliance::Met {
            file: "crates/ic-drbg/src/rng.rs",
            symbol: "from_entropy",
        },
    },
];

const SP80038D_REQS: [Requirement; 1] = [Requirement {
    id: "sp-800-38d-unique-iv",
    section: "8.2",
    obligation: Obligation::Shall,
    statement: "A key and IV pair shall never be used for more than one encryption.",
    rationale: "Repeating a nonce under one key in GCM reveals the XOR of the plaintexts and \
                leaks the authentication subkey, which allows forgery of further messages.",
    applies_to: &["aes-256-gcm", "aes-128-gcm"],
    compliance: Compliance::NotApplicable {
        why: "Nonce management belongs to the protocol, not the primitive. The library cannot \
              enforce it without owning the counter, so it states the consequence as a \
              Critical constraint on the registry entry instead of pretending to guarantee it.",
    },
}];

const RFC8017_REQS: [Requirement; 1] = [Requirement {
    id: "rfc-8017-no-signature-parsing",
    section: "8.2.2",
    obligation: Obligation::Should,
    statement: "PKCS#1 v1.5 verification should re-encode the expected block and compare, \
                rather than parsing the recovered block.",
    rationale: "Parsing is where the Bleichenbacher 2006 forgeries came from: a lenient parser \
                accepts padding with attacker-chosen bytes after the digest.",
    applies_to: &["rsa-pkcs1-sha256"],
    compliance: Compliance::Met {
        file: "crates/ic-rsa/src/pkcs1.rs",
        symbol: "encoding_matches_an_independent_construction",
    },
}];

const SP800131A_REQS: [Requirement; 2] = [
    Requirement {
        id: "sp-800-131a-rsa-minimum",
        section: "3",
        obligation: Obligation::ShallNot,
        statement: "RSA keys shorter than 2048 bits shall not be used for new signatures.",
        rationale: "A 1024-bit modulus is within reach of a well-resourced adversary. The floor is enforced at construction rather than documented as advice, so a short key cannot be loaded and then used.",
        applies_to: &["rsa-pkcs1-sha256", "rsa-pss-sha256"],
        compliance: Compliance::Met {
            file: "crates/ic-rsa/src/key.rs",
            symbol: "MIN_MODULUS_BITS",
        },
    },
    Requirement {
        id: "sp-800-131a-disallowed-algorithms",
        section: "1.1",
        obligation: Obligation::ShallNot,
        statement: "Algorithms whose transition has completed, among them Triple DES and SHA-1 for signature generation, shall not be used to protect new data.",
        rationale: "This library keeps them in the registry so a request resolves to a refusal with a reason, rather than to silence a caller might read as not-implemented-yet and work around.",
        applies_to: &["3des", "sha-1"],
        compliance: Compliance::Met {
            file: "crates/ic-ontology/src/types.rs",
            symbol: "Excluded",
        },
    },
];

const NO_REQS: [Requirement; 0] = [];

// ---------------------------------------------------------------------------
// The documents.
// ---------------------------------------------------------------------------

/// Every document the registry cites, plus the ones that govern the module.
pub static STANDARDS: &[Standard] = &[
    Standard {
        id: "FIPS 140-3",
        title: "Security Requirements for Cryptographic Modules",
        body: Body::Nist,
        scope: Scope::Module,
        year: 2019,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.140-3",
        summary: "The module-level standard: self-tests, error states, service indicators, key \
                  management and the validation programme itself. It is cited by no registry \
                  entry because it governs the module rather than any one algorithm, which is \
                  why it is marked as context.",
        requirements: &FIPS140_REQS,
    },
    Standard {
        id: "FIPS 180-4",
        title: "Secure Hash Standard (SHS)",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2015,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.180-4",
        summary: "SHA-1 and the SHA-2 family. The source for SHA-256, SHA-384 and SHA-512, and \
                  also for SHA-1, which this library implements only so that a request for it \
                  resolves to a refusal with a reason.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "FIPS 186-5",
        title: "Digital Signature Standard (DSS)",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2023,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.186-5",
        summary: "ECDSA, EdDSA and RSA signatures, with the curve and key-size choices that go \
                  with them. The edition that added Ed25519 and removed DSA.",
        requirements: &FIPS186_REQS,
    },
    Standard {
        id: "FIPS 197",
        title: "Advanced Encryption Standard (AES)",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2001,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.197",
        summary: "The block cipher itself: the key schedule and the round function, with no \
                  mode of operation. Everything about how to use it safely is in SP 800-38.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "FIPS 198-1",
        title: "The Keyed-Hash Message Authentication Code (HMAC)",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2008,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.198-1",
        summary: "HMAC over an approved hash. The NIST counterpart to RFC 2104, which defines \
                  the same construction.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "FIPS 202",
        title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2015,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.202",
        summary: "Keccak: the SHA-3 hashes and the SHAKE extendable-output functions. The \
                  sponge that both post-quantum schemes are built on.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "FIPS 203",
        title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2024,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.203",
        summary: "ML-KEM, the standardized form of Kyber. Defines the ring, the samplers, the \
                  Fujisaki-Okamoto transform and, in section 7, the input checks an \
                  implementation must perform on keys it did not generate.",
        requirements: &FIPS203_REQS,
    },
    Standard {
        id: "FIPS 204",
        title: "Module-Lattice-Based Digital Signature Standard",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2024,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.204",
        summary: "ML-DSA, the standardized form of Dilithium. Defines the rounding and hint \
                  machinery, the rejection-sampling signing loop, and the encodings whose \
                  canonicity verification must enforce.",
        requirements: &FIPS204_REQS,
    },
    Standard {
        id: "FIPS 205",
        title: "Stateless Hash-Based Digital Signature Standard",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2024,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.FIPS.205",
        summary: "SLH-DSA, the standardized form of SPHINCS+. Not implemented here.",
        requirements: &[],
    },
    Standard {
        id: "SP 800-38A",
        title: "Recommendation for Block Cipher Modes of Operation: Methods and Techniques",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2001,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-38A",
        summary: "The classical confidentiality-only modes: ECB, CBC, CFB, OFB and CTR. None \
                  of them authenticates, which is the single most important thing about them.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-38B",
        title: "Recommendation for Block Cipher Modes of Operation: The CMAC Mode for \
                Authentication",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2005,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-38B",
        summary: "CMAC, the block-cipher message authentication code, and the subkey \
                  derivation that fixes CBC-MAC's length-extension weakness.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-38D",
        title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) \
                and GMAC",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2007,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-38D",
        summary: "AES-GCM. Section 8 is the one to read: the uniqueness requirement on the IV \
                  is not advice, and violating it costs the authentication key.",
        requirements: &SP80038D_REQS,
    },
    Standard {
        id: "SP 800-38F",
        title: "Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2012,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-38F",
        summary: "AES-KW and AES-KWP, the deterministic authenticated modes for wrapping key \
                  material. Deterministic on purpose: there is no nonce to get wrong.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-56A",
        title: "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete \
                Logarithm Cryptography",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2018,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-56A",
        summary: "Diffie-Hellman and ECDH key establishment, including the public-key \
                  validation an implementation must perform on a peer's contribution.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-56C",
        title: "Recommendation for Key-Derivation Methods in Key-Establishment Schemes",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2020,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-56C",
        summary: "How to turn a shared secret into keys: the extract-then-expand construction, \
                  and why the raw secret is never itself a key.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-67",
        title: "Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2017,
        status: StandardStatus::Withdrawn,
        superseded_by: &["FIPS 197"],
        url: "https://doi.org/10.6028/NIST.SP.800-67",
        summary: "Triple DES. Withdrawn: the 64-bit block is the problem, and Sweet32 made it \
                  a practical one. Present in this library only so a request for it resolves \
                  to a refusal that explains itself.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-90A",
        title: "Recommendation for Random Number Generation Using Deterministic Random Bit \
                Generators",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2015,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-90A",
        summary: "The approved DRBGs. This library implements CTR_DRBG over AES-256; the \
                  Dual_EC generator this document once contained was removed in this revision.",
        requirements: &SP80090A_REQS,
    },
    Standard {
        id: "SP 800-108r1",
        title: "Recommendation for Key Derivation Using Pseudorandom Functions",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2022,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-108r1",
        summary: "KBKDF in counter, feedback and double-pipeline modes, for deriving keys from \
                  a key rather than from a shared secret.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-132",
        title: "Recommendation for Password-Based Key Derivation",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2010,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-132",
        summary: "PBKDF2. Approved, and also the weakest of the password KDFs here: it has no \
                  memory cost, so an attacker's hardware advantage is unbounded.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-131A",
        title: "Transitioning the Use of Cryptographic Algorithms and Key Lengths",
        body: Body::Nist,
        scope: Scope::Module,
        year: 2019,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-131A",
        summary: "What has stopped being acceptable, and when. It defines no construction of its own, which is why no registry entry cites it: it constrains the ones defined elsewhere. The key-length floors here are enforced at construction rather than left as advice.",
        requirements: &SP800131A_REQS,
    },
    Standard {
        id: "SP 800-185",
        title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2016,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-185",
        summary: "The functions built on cSHAKE, including the unambiguous encodings that make \
                  TupleHash's domain separation work.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "SP 800-186",
        title: "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve \
                Domain Parameters",
        body: Body::Nist,
        scope: Scope::Algorithm,
        year: 2023,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://doi.org/10.6028/NIST.SP.800-186",
        summary: "The curve parameters themselves, for the NIST prime curves and the \
                  Montgomery and Edwards curves adopted alongside them.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 1321",
        title: "The MD5 Message-Digest Algorithm",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 1992,
        status: StandardStatus::Informational,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc1321",
        summary: "MD5. Collisions are trivial and have been for two decades. Present here only \
                  so that a request for it resolves to a refusal with a reason.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 2104",
        title: "HMAC: Keyed-Hashing for Message Authentication",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 1997,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc2104",
        summary: "The original HMAC definition, equivalent to FIPS 198-1's.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 3394",
        title: "Advanced Encryption Standard (AES) Key Wrap Algorithm",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2002,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc3394",
        summary: "AES-KW, with the published test vectors this library checks against. Those \
                  vectors are bundled in `testvectors/aes-kw.json`.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 5649",
        title: "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2009,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc5649",
        summary: "AES-KWP, extending key wrap to inputs that are not a multiple of eight bytes.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 5869",
        title: "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2010,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc5869",
        summary: "HKDF. The extract step concentrates entropy, the expand step stretches it, \
                  and conflating the two is the usual mistake.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 6979",
        title: "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic \
                Curve Digital Signature Algorithm (ECDSA)",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2013,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc6979",
        summary: "Deriving the ECDSA nonce from the key and message by HMAC, so uniqueness \
                  holds by construction and signing needs no random source. Step h accumulates \
                  until the output covers the order's bit length, which matters at P-521.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 7693",
        title: "The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2015,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc7693",
        summary: "BLAKE2b and BLAKE2s, with keying built in rather than bolted on through HMAC.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 7748",
        title: "Elliptic Curves for Security",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2016,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc7748",
        summary: "Curve25519 and Curve448, and the X25519 and X448 functions over them.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 8017",
        title: "PKCS #1: RSA Cryptography Specifications Version 2.2",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2016,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc8017",
        summary: "RSA encryption and signatures: OAEP, PSS and the v1.5 paddings, with the \
                  DigestInfo prefixes that section 9.2 specifies.",
        requirements: &RFC8017_REQS,
    },
    Standard {
        id: "RFC 8018",
        title: "PKCS #5: Password-Based Cryptography Specification Version 2.1",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2017,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc8018",
        summary: "PBKDF2 as the IETF states it, matching SP 800-132.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 8032",
        title: "Edwards-Curve Digital Signature Algorithm (EdDSA)",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2017,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc8032",
        summary: "Ed25519 and Ed448: deterministic signatures with no per-message randomness \
                  and no nonce to reuse.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 8439",
        title: "ChaCha20 and Poly1305 for IETF Protocols",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2018,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc8439",
        summary: "ChaCha20-Poly1305. Fast and constant-time in software without hardware \
                  support, which is why it is the right default where AES-NI is absent.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 8452",
        title: "AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2019,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc8452",
        summary: "The nonce-misuse-resistant mode. Repeating a nonce leaks only whether two \
                  plaintexts were equal, rather than costing the authentication key as it does \
                  in GCM. Appendix C carries the vectors this library still wants.",
        requirements: &NO_REQS,
    },
    Standard {
        id: "RFC 9106",
        title: "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work \
                Applications",
        body: Body::Ietf,
        scope: Scope::Algorithm,
        year: 2021,
        status: StandardStatus::Current,
        superseded_by: &[],
        url: "https://www.rfc-editor.org/rfc/rfc9106",
        summary: "Argon2. Memory-hard, which is what denies an attacker the hardware advantage \
                  that PBKDF2 concedes. Not FIPS-approved.",
        requirements: &NO_REQS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ImplStatus;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// The workspace root, found by walking up from this crate.
    fn workspace_root() -> PathBuf {
        let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..4 {
            if here.join("Cargo.toml").is_file() && here.join("crates").is_dir() {
                return here;
            }
            if !here.pop() {
                break;
            }
        }
        panic!("could not find the workspace root");
    }

    /// Every document a registry entry cites must be described here.
    ///
    /// This is the first half of the coupling: the registry cannot start citing
    /// something the knowledgebase has never heard of.
    #[test]
    fn every_cited_standard_is_in_the_knowledgebase() {
        let mut missing: BTreeSet<&str> = BTreeSet::new();
        for e in REGISTRY {
            for s in e.standards {
                if standard(s).is_none() {
                    missing.insert(s);
                }
            }
        }
        assert!(
            missing.is_empty(),
            "registry entries cite documents the knowledgebase does not describe: {missing:?}"
        );
    }

    /// And the second half: nothing here is unused unless it says why.
    ///
    /// Without this the knowledgebase could accumulate documents nobody
    /// implements, which is how a reference turns into a wish list.
    #[test]
    fn every_standard_is_cited_or_marked_as_context() {
        for s in STANDARDS {
            if s.is_cited() {
                continue;
            }
            // The only uncited documents allowed are the ones that govern the
            // module rather than an algorithm, and they must declare it.
            assert_eq!(
                s.scope,
                Scope::Module,
                "{} is in the knowledgebase but no entry cites it, and it is not declared as governing the module",
                s.id
            );
        }
        // And the converse: a module-scoped document must not be cited by an
        // entry, or the distinction has stopped meaning anything.
        for s in STANDARDS {
            if s.scope == Scope::Module {
                assert!(
                    !s.is_cited(),
                    "{} is declared module-scoped but an entry cites it",
                    s.id
                );
            }
        }
    }

    /// The check that makes this a fixture rather than a document.
    ///
    /// A requirement claiming to be met names a file and a symbol, and both
    /// must be real. Rename the function and this fails, which is the whole
    /// point: the knowledgebase cannot drift away from the code silently.
    #[test]
    fn every_met_requirement_points_at_code_that_exists() {
        let root = workspace_root();
        let mut checked = 0;
        for (std_doc, req) in requirements() {
            let (file, symbol) = match req.compliance {
                Compliance::Met { file, symbol } => (file, symbol),
                // A partial claim names code too, and is held to the same
                // standard. Otherwise "partial" becomes the place unverifiable
                // claims go to hide.
                Compliance::Partial { file, symbol, gap } => {
                    assert!(
                        gap.len() > 40,
                        "{} is partial and must say what is missing",
                        req.id
                    );
                    (file, symbol)
                }
                _ => continue,
            };
            let path = root.join(file);
            assert!(
                path.is_file(),
                "{} ({}) names a file that does not exist: {file}",
                req.id,
                std_doc.id
            );
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} cannot read {file}: {e}", req.id));
            assert!(
                text.contains(symbol),
                "{} ({}) names {symbol:?}, which does not appear in {file}",
                req.id,
                std_doc.id
            );
            checked += 1;
        }
        assert!(
            checked >= 12,
            "too few requirements are wired to code: {checked}"
        );
    }

    /// Requirements must bear on algorithms that exist.
    #[test]
    fn requirement_targets_resolve() {
        for (std_doc, req) in requirements() {
            for target in req.applies_to {
                assert!(
                    REGISTRY.iter().any(|e| e.id == *target),
                    "{} ({}) applies to {target:?}, which is not a registry entry",
                    req.id,
                    std_doc.id
                );
            }
        }
    }

    /// Identifiers are the join keys for every export, so they must be unique.
    #[test]
    fn identifiers_are_unique() {
        let mut seen = BTreeSet::new();
        for s in STANDARDS {
            assert!(seen.insert(s.id), "duplicate standard id {}", s.id);
        }
        let mut seen = BTreeSet::new();
        for (_, r) in requirements() {
            assert!(seen.insert(r.id), "duplicate requirement id {}", r.id);
        }
    }

    /// `superseded_by` must name documents that are here.
    #[test]
    fn supersession_links_resolve() {
        for s in STANDARDS {
            for target in s.superseded_by {
                assert!(
                    standard(target).is_some(),
                    "{} is superseded by {target:?}, which is not described",
                    s.id
                );
            }
            if s.status == StandardStatus::Superseded {
                assert!(
                    !s.superseded_by.is_empty(),
                    "{} is marked superseded but names no successor",
                    s.id
                );
            }
        }
    }

    /// An algorithm the library offers must not rest solely on a withdrawn
    /// document.
    ///
    /// This is the invariant that keeps the knowledgebase honest about the
    /// registry: if Triple DES were ever promoted to available, this would
    /// fail, and it should.
    #[test]
    fn nothing_available_rests_only_on_a_withdrawn_document() {
        for e in REGISTRY {
            if e.status != ImplStatus::Available {
                continue;
            }
            let live = e
                .standards
                .iter()
                .any(|id| standard(id).map(|s| s.status.is_current()).unwrap_or(false));
            assert!(
                live,
                "{} is available but every document it cites is withdrawn or superseded",
                e.id
            );
        }
    }

    /// URLs follow each publisher's scheme rather than being transcribed one at
    /// a time.
    ///
    /// The module doc says this is a constructed locator, not a verified link.
    /// Asserting the rule is what makes that claim meaningful.
    #[test]
    fn locators_follow_the_publisher_scheme() {
        for s in STANDARDS {
            match s.body {
                Body::Nist => assert!(
                    s.url.starts_with("https://doi.org/10.6028/NIST."),
                    "{} does not use the NIST DOI scheme: {}",
                    s.id,
                    s.url
                ),
                Body::Ietf => assert!(
                    s.url.starts_with("https://www.rfc-editor.org/rfc/rfc"),
                    "{} does not use the RFC editor scheme: {}",
                    s.id,
                    s.url
                ),
            }
        }
    }

    /// Every document must actually say something.
    #[test]
    fn documents_are_described() {
        for s in STANDARDS {
            assert!(!s.title.is_empty(), "{} has no title", s.id);
            assert!(s.summary.len() > 40, "{} has a thin summary", s.id);
            assert!(s.year >= 1977 && s.year <= 2026, "{} has an odd year", s.id);
        }
        for (_, r) in requirements() {
            assert!(!r.statement.is_empty(), "{} has no statement", r.id);
            assert!(!r.rationale.is_empty(), "{} has no rationale", r.id);
            assert!(!r.section.is_empty(), "{} cites no section", r.id);
        }
    }

    /// Nothing here may claim validation. The one requirement about it must
    /// resolve to a refusal.
    #[test]
    fn the_knowledgebase_does_not_claim_validation() {
        let (_, req) = requirement("fips-140-3-validation-claim").expect("the entry must exist");
        assert_eq!(req.obligation, Obligation::ShallNot);
        assert!(
            req.rationale.contains("no certificate"),
            "the rationale must state plainly that there is no certificate"
        );
        for s in STANDARDS {
            for (_, r) in requirements() {
                assert!(
                    !r.statement.contains("is validated"),
                    "{} appears to claim validation",
                    r.id
                );
            }
            assert!(
                !s.summary.contains("validated by"),
                "{} appears to claim validation",
                s.id
            );
        }
    }

    /// Prose must not carry the wreckage of its own line wrapping.
    ///
    /// These strings reach the CLI, the MCP responses and every export. When a
    /// wrapped literal goes wrong, the source indentation ends up *inside* the
    /// string, and it surfaces as a stray gap in the middle of a sentence that
    /// looks like a bug in whatever is displaying it rather than a data problem
    /// here.
    ///
    /// This has now happened twice, which is why it is a test rather than a
    /// resolution to be careful. It covers the registry as well, since the same
    /// prose fields and the same wrapping style are used there, and the first
    /// thing it caught was damage already committed in that file.
    #[test]
    fn prose_has_no_embedded_whitespace_runs() {
        fn check(what: &str, text: &str) {
            // Two spaces. Written via a constant so a whitespace-normalising
            // pass over this file cannot quietly turn the check into "contains
            // a space", which every string does.
            const RUN: &str = "  ";
            assert_eq!(RUN.len(), 2, "the guard's own pattern was rewritten");
            assert!(!text.contains(RUN), "{what} has a run of spaces: {text:?}");
            assert!(!text.contains('\t'), "{what} has a tab: {text:?}");
            assert!(!text.contains('\n'), "{what} has a newline: {text:?}");
        }

        for s in STANDARDS {
            check(&format!("{} title", s.id), s.title);
            check(&format!("{} summary", s.id), s.summary);
        }
        for (_, r) in requirements() {
            check(&format!("{} statement", r.id), r.statement);
            check(&format!("{} rationale", r.id), r.rationale);
            match r.compliance {
                Compliance::Partial { gap, .. } => check(&format!("{} gap", r.id), gap),
                Compliance::NotApplicable { why } | Compliance::Unmet { why } => {
                    check(&format!("{} reason", r.id), why)
                }
                Compliance::Met { .. } => {}
            }
        }
        for e in REGISTRY {
            check(&format!("{} summary", e.id), e.summary);
            check(&format!("{} notes", e.id), e.notes);
            for c in e.constraints {
                check(&format!("{}/{} requirement", e.id, c.id), c.requirement);
                check(&format!("{}/{} consequence", e.id, c.id), c.consequence);
            }
        }
    }

    /// Lookups work by the citation string the registry uses, case-insensitively.
    #[test]
    fn lookup_works_the_way_callers_will_use_it() {
        assert_eq!(standard("FIPS 203").map(|s| s.id), Some("FIPS 203"));
        assert_eq!(standard("fips 203").map(|s| s.id), Some("FIPS 203"));
        assert!(standard("FIPS 999").is_none());

        let (doc, req) = requirement("fips-203-encaps-key-check").unwrap();
        assert_eq!(doc.id, "FIPS 203");
        assert_eq!(req.obligation, Obligation::Shall);

        let for_kem: Vec<_> = standards_for("ml-kem-768").map(|s| s.id).collect();
        assert!(for_kem.contains(&"FIPS 203"), "got {for_kem:?}");

        let algs: Vec<_> = standard("FIPS 203").unwrap().algorithms().collect();
        assert!(algs.contains(&"ml-kem-768"), "got {algs:?}");
    }
}
