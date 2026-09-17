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
    /// Every variant, for callers that enumerate them.
    ///
    /// The published JSON Schema builds its `enum` from this. It used to
    /// carry the strings inline, which is how `implementationStatus` came
    /// to omit `experimental` after that status was added -- the schema
    /// then rejected the very entries it most needed to describe.
    pub const ALL: &'static [FipsStatus] = &[
        FipsStatus::Approved,
        FipsStatus::AllowedAsComponent,
        FipsStatus::NotApproved,
        FipsStatus::Deprecated,
        FipsStatus::Disallowed,
    ];

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
/// "IronCrypto has no approved signature scheme, so I'll use Ed25519" —
/// exactly the wrong inference. Listing planned algorithms with an honest
/// status lets the agent conclude "not available here; use another module".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImplStatus {
    /// Implemented, vector-tested, and callable today.
    ///
    /// "Vector-tested" is the load-bearing word: the implementation has been
    /// checked against values produced by something other than itself, so it
    /// interoperates. See [`ImplStatus::Experimental`] for the case where that
    /// evidence does not exist.
    Available,
    /// Implemented and property-tested, but never checked against a published
    /// vector or a second implementation.
    ///
    /// The distinction matters more than it sounds. A cryptographic primitive
    /// can be internally consistent — encrypt and decrypt round-trip, every
    /// component behaves — and still compute something no other implementation
    /// agrees with, because one constant or one byte order is wrong. Such a
    /// build passes every test you can write against it alone.
    ///
    /// Anything marked this way is safe to experiment with and unsafe to
    /// interoperate with. It is excluded from the FIPS approved mode and from
    /// [`crate::select::recommend`] regardless of what its `fips` field says.
    Experimental,
    /// Specified in the ontology, not yet implemented.
    Planned,
    /// Deliberately excluded; see the entry's `notes`.
    Excluded,
}

impl ImplStatus {
    /// Every variant, for callers that enumerate them.
    ///
    /// The published JSON Schema builds its `enum` from this. It used to
    /// carry the strings inline, which is how `implementationStatus` came
    /// to omit `experimental` after that status was added -- the schema
    /// then rejected the very entries it most needed to describe.
    pub const ALL: &'static [ImplStatus] = &[
        ImplStatus::Available,
        ImplStatus::Experimental,
        ImplStatus::Planned,
        ImplStatus::Excluded,
    ];

    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Experimental => "experimental",
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
    /// Every variant, for callers that enumerate them.
    ///
    /// The published JSON Schema builds its `enum` from this. It used to
    /// carry the strings inline, which is how `implementationStatus` came
    /// to omit `experimental` after that status was added -- the schema
    /// then rejected the very entries it most needed to describe.
    pub const ALL: &'static [Performance] = &[
        Performance::Fast,
        Performance::Moderate,
        Performance::Slow,
        Performance::DeliberatelySlow,
    ];

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
    /// Every variant, for callers that enumerate them.
    ///
    /// The published JSON Schema builds its `enum` from this. It used to
    /// carry the strings inline, which is how `implementationStatus` came
    /// to omit `experimental` after that status was added -- the schema
    /// then rejected the very entries it most needed to describe.
    pub const ALL: &'static [Unit] = &[Unit::Bytes, Unit::Count];

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
    /// Every variant, for callers that enumerate them.
    ///
    /// The published JSON Schema builds its `enum` from this. It used to
    /// carry the strings inline, which is how `implementationStatus` came
    /// to omit `experimental` after that status was added -- the schema
    /// then rejected the very entries it most needed to describe.
    pub const ALL: &'static [Severity] =
        &[Severity::Critical, Severity::Serious, Severity::Advisory];

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
    /// Every variant, for callers that enumerate them.
    ///
    /// The published JSON Schema builds its `enum` from this. It used to
    /// carry the strings inline, which is how `implementationStatus` came
    /// to omit `experimental` after that status was added -- the schema
    /// then rejected the very entries it most needed to describe.
    pub const ALL: &'static [Relation] = &[
        Relation::BuiltOn,
        Relation::Supersedes,
        Relation::SupersededBy,
        Relation::PairsWith,
        Relation::Specializes,
    ];

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
    ///
    /// This is `min_by_key`, not `max_by_key`, because [`Severity`] is declared
    /// worst-first so that its derived `Ord` sorts the way a priority list
    /// reads. That is a real dependency on the order of an enum's variants, so
    /// the tests pin it: reordering `Severity` must fail loudly rather than
    /// quietly turn this into `mildest_constraint`.
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

    /// Every `ALL` list must really be all of them.
    ///
    /// The matches are exhaustive and this is the crate that defines the types,
    /// so adding a variant stops this compiling until it is handled. Without
    /// that, a list like this is a second place to remember, and the schema's
    /// stale `implementationStatus` is what forgetting looks like.
    #[test]
    fn the_variant_lists_are_complete() {
        #[allow(clippy::needless_match)]
        fn identify_status(v: ImplStatus) -> ImplStatus {
            match v {
                ImplStatus::Available => ImplStatus::Available,
                ImplStatus::Experimental => ImplStatus::Experimental,
                ImplStatus::Planned => ImplStatus::Planned,
                ImplStatus::Excluded => ImplStatus::Excluded,
            }
        }
        #[allow(clippy::needless_match)]
        fn identify_fips(v: FipsStatus) -> FipsStatus {
            match v {
                FipsStatus::Approved => FipsStatus::Approved,
                FipsStatus::AllowedAsComponent => FipsStatus::AllowedAsComponent,
                FipsStatus::NotApproved => FipsStatus::NotApproved,
                FipsStatus::Deprecated => FipsStatus::Deprecated,
                FipsStatus::Disallowed => FipsStatus::Disallowed,
            }
        }
        #[allow(clippy::needless_match)]
        fn identify_perf(v: Performance) -> Performance {
            match v {
                Performance::Fast => Performance::Fast,
                Performance::Moderate => Performance::Moderate,
                Performance::Slow => Performance::Slow,
                Performance::DeliberatelySlow => Performance::DeliberatelySlow,
            }
        }
        #[allow(clippy::needless_match)]
        fn identify_severity(v: Severity) -> Severity {
            match v {
                Severity::Critical => Severity::Critical,
                Severity::Serious => Severity::Serious,
                Severity::Advisory => Severity::Advisory,
            }
        }
        #[allow(clippy::needless_match)]
        fn identify_unit(v: Unit) -> Unit {
            match v {
                Unit::Bytes => Unit::Bytes,
                Unit::Count => Unit::Count,
            }
        }
        #[allow(clippy::needless_match)]
        fn identify_relation(v: Relation) -> Relation {
            match v {
                Relation::BuiltOn => Relation::BuiltOn,
                Relation::Supersedes => Relation::Supersedes,
                Relation::SupersededBy => Relation::SupersededBy,
                Relation::PairsWith => Relation::PairsWith,
                Relation::Specializes => Relation::Specializes,
            }
        }

        for v in ImplStatus::ALL {
            assert_eq!(identify_status(*v), *v);
        }
        for v in FipsStatus::ALL {
            assert_eq!(identify_fips(*v), *v);
        }
        for v in Performance::ALL {
            assert_eq!(identify_perf(*v), *v);
        }
        for v in Severity::ALL {
            assert_eq!(identify_severity(*v), *v);
        }
        for v in Unit::ALL {
            assert_eq!(identify_unit(*v), *v);
        }
        for v in Relation::ALL {
            assert_eq!(identify_relation(*v), *v);
        }

        // Identifiers are the join key every serialized form uses.
        fn distinct(ids: &[&str]) -> bool {
            ids.iter()
                .enumerate()
                .all(|(i, a)| !ids[i + 1..].contains(a))
        }
        assert!(distinct(
            &ImplStatus::ALL.iter().map(|v| v.id()).collect::<Vec<_>>()
        ));
        assert!(distinct(
            &FipsStatus::ALL.iter().map(|v| v.id()).collect::<Vec<_>>()
        ));
        assert!(distinct(
            &Relation::ALL.iter().map(|v| v.id()).collect::<Vec<_>>()
        ));
    }

    /// `Severity` is ordered worst-first, and something depends on it.
    ///
    /// [`Entry::worst_constraint`] selects with `min_by_key`. If these variants
    /// were ever reordered — alphabetized, or a new one inserted at the top —
    /// that selection would silently invert and every caller asking "what is
    /// the worst thing about this algorithm" would be told the mildest.
    #[test]
    fn severity_is_ordered_worst_first() {
        assert!(Severity::Critical < Severity::Serious);
        assert!(Severity::Serious < Severity::Advisory);
        assert_eq!(
            [Severity::Advisory, Severity::Critical, Severity::Serious]
                .iter()
                .min(),
            Some(&Severity::Critical),
            "min() must mean worst, which is what worst_constraint relies on"
        );
    }

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
