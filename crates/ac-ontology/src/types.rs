//! The ontology vocabulary: the types every registry entry is built from.
//!
//! These enums are the *terms* of the ontology. They are deliberately closed
//! (not free text) so that an agent can reason over them — filter, compare,
//! and rank — without natural-language understanding. Every variant carries a
//! stable kebab-case [`id`](Class::id) used in JSON, JSON-LD, and CLI output.

/// What kind of cryptographic object an algorithm is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// A fixed-output hash function.
    Hash,
    /// An extendable-output function.
    Xof,
    /// A keyed message authentication code.
    Mac,
    /// A raw block cipher (a primitive, not a usable encryption scheme).
    BlockCipher,
    /// An unauthenticated confidentiality mode.
    CipherMode,
    /// An authenticated cipher with associated data.
    Aead,
    /// A key derivation function.
    Kdf,
    /// A password-based key derivation function.
    PasswordKdf,
    /// A deterministic random bit generator.
    Drbg,
    /// A key agreement (Diffie-Hellman style) scheme.
    KeyAgreement,
    /// A key encapsulation mechanism.
    Kem,
    /// A digital signature scheme.
    Signature,
}

impl Class {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Xof => "xof",
            Self::Mac => "mac",
            Self::BlockCipher => "block-cipher",
            Self::CipherMode => "cipher-mode",
            Self::Aead => "aead",
            Self::Kdf => "kdf",
            Self::PasswordKdf => "password-kdf",
            Self::Drbg => "drbg",
            Self::KeyAgreement => "key-agreement",
            Self::Kem => "kem",
            Self::Signature => "signature",
        }
    }

    /// Every class term, for enumeration and schema generation.
    pub const ALL: &'static [Class] = &[
        Class::Hash,
        Class::Xof,
        Class::Mac,
        Class::BlockCipher,
        Class::CipherMode,
        Class::Aead,
        Class::Kdf,
        Class::PasswordKdf,
        Class::Drbg,
        Class::KeyAgreement,
        Class::Kem,
        Class::Signature,
    ];

    /// Parse a class from its identifier.
    pub fn from_id(id: &str) -> Option<Class> {
        Self::ALL.iter().copied().find(|c| c.id() == id)
    }
}

/// The security goal an algorithm serves.
///
/// This is the axis an agent searches on: a task says "I need integrity", not
/// "I need SHA-384".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// Detect accidental or malicious modification, without a key.
    Integrity,
    /// Hide the content of a message.
    Confidentiality,
    /// Prove a message came from a holder of the key.
    Authentication,
    /// Produce keys from other keying material.
    KeyDerivation,
    /// Produce keys from a low-entropy password.
    PasswordHashing,
    /// Establish a shared secret with a peer.
    KeyEstablishment,
    /// Generate unpredictable bits.
    RandomGeneration,
    /// Prove authorship in a way a third party can check.
    NonRepudiation,
    /// Bind a value to a commitment or identifier.
    Commitment,
}

impl Purpose {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Confidentiality => "confidentiality",
            Self::Authentication => "authentication",
            Self::KeyDerivation => "key-derivation",
            Self::PasswordHashing => "password-hashing",
            Self::KeyEstablishment => "key-establishment",
            Self::RandomGeneration => "random-generation",
            Self::NonRepudiation => "non-repudiation",
            Self::Commitment => "commitment",
        }
    }

    /// Every purpose term.
    pub const ALL: &'static [Purpose] = &[
        Purpose::Integrity,
        Purpose::Confidentiality,
        Purpose::Authentication,
        Purpose::KeyDerivation,
        Purpose::PasswordHashing,
        Purpose::KeyEstablishment,
        Purpose::RandomGeneration,
        Purpose::NonRepudiation,
        Purpose::Commitment,
    ];

    /// Parse a purpose from its identifier.
    pub fn from_id(id: &str) -> Option<Purpose> {
        Self::ALL.iter().copied().find(|p| p.id() == id)
    }
}

/// An algorithm's standing under FIPS 140-3 and the SP 800-131A transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FipsStatus {
    /// Approved for use in the FIPS-approved mode of operation.
    Approved,
    /// Allowed in approved mode as a component, but not itself an approved
    /// security function (for example a raw block cipher inside a mode).
    AllowedAsComponent,
    /// Not approved; usable only outside approved mode.
    NotApproved,
    /// Approved today, scheduled for withdrawal.
    Deprecated,
    /// Withdrawn; must not be used for protection.
    Disallowed,
}

impl FipsStatus {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::AllowedAsComponent => "allowed-as-component",
            Self::NotApproved => "not-approved",
            Self::Deprecated => "deprecated",
            Self::Disallowed => "disallowed",
        }
    }

    /// Whether the FIPS policy engine permits this in approved mode.
    pub const fn permitted_in_approved_mode(self) -> bool {
        matches!(
            self,
            Self::Approved | Self::AllowedAsComponent | Self::Deprecated
        )
    }
}

/// Whether the algorithm actually exists in this build.
///
/// A registry that only listed what is implemented would let an agent conclude
/// "AgenticCrypto has no approved signature scheme, so I'll use Ed25519" —
/// exactly the wrong inference. Listing planned algorithms with an honest
/// status lets the agent conclude "not available here; use another module".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImplStatus {
    /// Implemented, vector-tested, and callable today.
    Available,
    /// Specified in the ontology, not yet implemented.
    Planned,
    /// Deliberately excluded; see the entry's `notes`.
    Excluded,
}

impl ImplStatus {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Planned => "planned",
            Self::Excluded => "excluded",
        }
    }
}

/// Rough throughput expectation on the **portable** backend.
///
/// This is deliberately a static, backend-independent property: the same
/// algorithm is `Slow` on a microcontroller and fast on a server with AES-NI,
/// and an entry cannot be both. Consult
/// [`runtime::backend()`][crate::runtime::backend] for what the machine in
/// front of you will actually do — a `Slow` AES entry on a
/// `HardwareAccelerated` backend runs at GB/s, not MB/s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Performance {
    /// Fast enough for bulk data on any target.
    Fast,
    /// Usable for bulk data, noticeably slower than a hardware backend.
    Moderate,
    /// Acceptable for keys and small messages; avoid for bulk data.
    Slow,
    /// Intentionally expensive (password hashing).
    DeliberatelySlow,
}

impl Performance {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Moderate => "moderate",
            Self::Slow => "slow",
            Self::DeliberatelySlow => "deliberately-slow",
        }
    }
}

/// A named size or count constraint on an algorithm's inputs.
#[derive(Debug, Clone, Copy)]
pub struct Param {
    /// Parameter name, e.g. `"key"`, `"nonce"`, `"tag"`, `"iterations"`.
    pub name: &'static str,
    /// Unit the bounds are expressed in.
    pub unit: Unit,
    /// Smallest acceptable value, inclusive.
    pub min: u64,
    /// Largest acceptable value, inclusive.
    pub max: u64,
    /// The value to use absent a reason to differ.
    pub recommended: u64,
    /// What the parameter is for.
    pub note: &'static str,
}

/// The unit a [`Param`] bound is measured in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// A length in bytes.
    Bytes,
    /// A repetition count.
    Count,
}

impl Unit {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Count => "count",
        }
    }
}

/// A machine-checkable usage rule.
///
/// The `severity` is what makes this actionable: an agent can refuse to
/// generate code that violates a `Critical` constraint, and merely warn on an
/// `Advisory` one.
#[derive(Debug, Clone, Copy)]
pub struct Constraint {
    /// Stable identifier, e.g. `"unique-nonce-per-key"`.
    pub id: &'static str,
    /// What the caller must do.
    pub requirement: &'static str,
    /// What goes wrong if they do not.
    pub consequence: &'static str,
    /// How bad the violation is.
    pub severity: Severity,
}

/// How serious a [`Constraint`] violation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Violation breaks the security property outright.
    Critical,
    /// Violation weakens the security property materially.
    Serious,
    /// Violation is a best-practice issue.
    Advisory,
}

impl Severity {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Serious => "serious",
            Self::Advisory => "advisory",
        }
    }
}

/// Security strength in bits, against classical and quantum adversaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strength {
    /// Bits of security against a classical adversary.
    pub classical: u16,
    /// Bits of security against a quantum adversary, accounting for Grover
    /// (symmetric, halved) and Shor (classical asymmetric, broken to 0).
    pub quantum: u16,
}

impl Strength {
    /// A symmetric primitive: Grover halves the effective strength.
    pub const fn symmetric(bits: u16) -> Strength {
        Strength {
            classical: bits,
            quantum: bits / 2,
        }
    }

    /// A discrete-log or factoring primitive: Shor reduces it to nothing.
    pub const fn classical_only(bits: u16) -> Strength {
        Strength {
            classical: bits,
            quantum: 0,
        }
    }
}

/// A typed relation between two registry entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// This algorithm is constructed from the target.
    BuiltOn,
    /// This algorithm should be used instead of the target.
    Supersedes,
    /// The target should be used instead of this algorithm.
    SupersededBy,
    /// This algorithm is commonly paired with the target.
    PairsWith,
    /// This algorithm is a parameterization of the target family.
    Specializes,
}

impl Relation {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::BuiltOn => "built-on",
            Self::Supersedes => "supersedes",
            Self::SupersededBy => "superseded-by",
            Self::PairsWith => "pairs-with",
            Self::Specializes => "specializes",
        }
    }
}

/// An outgoing edge in the ontology graph.
#[derive(Debug, Clone, Copy)]
pub struct Edge {
    /// The kind of relation.
    pub relation: Relation,
    /// The `id` of the target entry.
    pub target: &'static str,
}

/// A complete ontology entry for one algorithm.
///
/// Every field is machine-readable. `rust_path` and `example` close the loop:
/// after an agent selects an algorithm, it knows exactly what to call and what
/// the call looks like, without searching the source tree.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// Stable, unique, kebab-case identifier.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Other names this algorithm is known by, for lookup.
    pub aliases: &'static [&'static str],
    /// One-sentence description of what it is and when to use it.
    pub summary: &'static str,
    /// The kind of object.
    pub class: Class,
    /// Family grouping, e.g. `"SHA-2"`.
    pub family: &'static str,
    /// The security goals it serves.
    pub purposes: &'static [Purpose],
    /// Security strength.
    pub strength: Strength,
    /// FIPS standing.
    pub fips: FipsStatus,
    /// Whether it exists in this build.
    pub status: ImplStatus,
    /// Defining standards documents.
    pub standards: &'static [&'static str],
    /// Input size and count constraints.
    pub params: &'static [Param],
    /// Usage rules.
    pub constraints: &'static [Constraint],
    /// Relations to other entries.
    pub edges: &'static [Edge],
    /// Throughput expectation.
    pub performance: Performance,
    /// Fully-qualified Rust path to the implementation, or `""` when planned.
    pub rust_path: &'static str,
    /// A minimal, copy-pasteable usage snippet, or `""` when planned.
    pub example: &'static str,
    /// Anything an implementer needs to know that the fields above do not say.
    pub notes: &'static str,
}

impl Entry {
    /// Whether this entry serves the given purpose.
    pub fn serves(&self, purpose: Purpose) -> bool {
        self.purposes.contains(&purpose)
    }

    /// Whether `needle` matches this entry's id or any alias, case-insensitively.
    pub fn matches_name(&self, needle: &str) -> bool {
        if eq_ignore_case(self.id, needle) || eq_ignore_case(self.name, needle) {
            return true;
        }
        self.aliases.iter().any(|a| eq_ignore_case(a, needle))
    }

    /// Whether this entry can be used while the module is in approved mode.
    pub fn approved_mode_ok(&self) -> bool {
        self.fips.permitted_in_approved_mode() && self.status == ImplStatus::Available
    }

    /// The most severe constraint attached to this entry, if any.
    pub fn worst_constraint(&self) -> Option<&'static Constraint> {
        self.constraints.iter().min_by_key(|c| c.severity)
    }
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_ids_roundtrip() {
        for c in Class::ALL {
            assert_eq!(Class::from_id(c.id()), Some(*c));
        }
        assert_eq!(Class::from_id("nonsense"), None);
    }

    #[test]
    fn purpose_ids_roundtrip() {
        for p in Purpose::ALL {
            assert_eq!(Purpose::from_id(p.id()), Some(*p));
        }
    }

    #[test]
    fn approved_mode_policy_is_explicit() {
        assert!(FipsStatus::Approved.permitted_in_approved_mode());
        assert!(FipsStatus::AllowedAsComponent.permitted_in_approved_mode());
        assert!(FipsStatus::Deprecated.permitted_in_approved_mode());
        assert!(!FipsStatus::NotApproved.permitted_in_approved_mode());
        assert!(!FipsStatus::Disallowed.permitted_in_approved_mode());
    }

    #[test]
    fn quantum_strength_models_grover_and_shor() {
        assert_eq!(Strength::symmetric(256).quantum, 128);
        assert_eq!(Strength::classical_only(128).quantum, 0);
    }

    #[test]
    fn severity_orders_critical_first() {
        assert!(Severity::Critical < Severity::Serious);
        assert!(Severity::Serious < Severity::Advisory);
    }

    #[test]
    fn case_insensitive_name_matching() {
        assert!(eq_ignore_case("SHA-256", "sha-256"));
        assert!(!eq_ignore_case("SHA-256", "sha-384"));
        assert!(!eq_ignore_case("SHA-256", "sha-2560"));
    }
}
