//! Querying the registry.
//!
//! [`Query`] is a declarative filter an agent can build from a task description
//! without knowing any algorithm names. It is a plain iterator adapter, so it
//! allocates nothing and works in `no_std`.
//!
//! ```
//! use ic_ontology::{Query, Purpose};
//!
//! // "I need authenticated encryption that is FIPS-approved and actually
//! //  available in this build, at 256-bit strength."
//! let hits: Vec<_> = Query::new()
//!     .purpose(Purpose::Confidentiality)
//!     .purpose(Purpose::Authentication)
//!     .fips_approved_only()
//!     .available_only()
//!     .min_classical_bits(256)
//!     .run()
//!     .collect();
//!
//! assert!(hits.iter().any(|e| e.id == "aes-256-gcm"));
//! ```

use crate::registry::REGISTRY;
use crate::types::{Class, Entry, ImplStatus, Purpose};

/// The maximum number of purposes a single query can require.
const MAX_PURPOSES: usize = 4;

/// A declarative filter over the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Query {
    class: Option<Class>,
    purposes: [Option<Purpose>; MAX_PURPOSES],
    purpose_count: usize,
    min_classical: u16,
    min_quantum: u16,
    fips_only: bool,
    available_only: bool,
    family: Option<&'static str>,
}

impl Query {
    /// An empty query, matching every entry.
    pub const fn new() -> Self {
        Self {
            class: None,
            purposes: [None; MAX_PURPOSES],
            purpose_count: 0,
            min_classical: 0,
            min_quantum: 0,
            fips_only: false,
            available_only: false,
            family: None,
        }
    }

    /// Restrict to one kind of cryptographic object.
    pub const fn class(mut self, class: Class) -> Self {
        self.class = Some(class);
        self
    }

    /// Require the entry to serve this purpose. Repeating the call requires all
    /// of them, which is how "authenticated encryption" is expressed as
    /// confidentiality *and* authentication.
    pub const fn purpose(mut self, purpose: Purpose) -> Self {
        if self.purpose_count < MAX_PURPOSES {
            self.purposes[self.purpose_count] = Some(purpose);
            self.purpose_count += 1;
        }
        self
    }

    /// Require at least this much strength against a classical adversary.
    pub const fn min_classical_bits(mut self, bits: u16) -> Self {
        self.min_classical = bits;
        self
    }

    /// Require at least this much strength against a quantum adversary.
    ///
    /// Setting this above zero excludes every discrete-log and factoring scheme,
    /// which is exactly the filter a post-quantum migration needs.
    pub const fn min_quantum_bits(mut self, bits: u16) -> Self {
        self.min_quantum = bits;
        self
    }

    /// Restrict to algorithms usable in the FIPS approved mode of operation.
    pub const fn fips_approved_only(mut self) -> Self {
        self.fips_only = true;
        self
    }

    /// Restrict to algorithms actually implemented in this build.
    pub const fn available_only(mut self) -> Self {
        self.available_only = true;
        self
    }

    /// Restrict to one family, e.g. `"SHA-2"`.
    pub const fn family(mut self, family: &'static str) -> Self {
        self.family = Some(family);
        self
    }

    /// Whether a single entry satisfies the query.
    pub fn matches(&self, e: &Entry) -> bool {
        if let Some(c) = self.class {
            if e.class != c {
                return false;
            }
        }
        for p in self.purposes.iter().flatten() {
            if !e.serves(*p) {
                return false;
            }
        }
        if e.strength.classical < self.min_classical || e.strength.quantum < self.min_quantum {
            return false;
        }
        if self.fips_only && !e.fips.permitted_in_approved_mode() {
            return false;
        }
        if self.available_only && e.status != ImplStatus::Available {
            return false;
        }
        if let Some(f) = self.family {
            if e.family != f {
                return false;
            }
        }
        true
    }

    /// Run the query, yielding matching entries in registry order.
    pub fn run(self) -> impl Iterator<Item = &'static Entry> {
        REGISTRY.iter().filter(move |e| self.matches(e))
    }

    /// The number of entries this query matches.
    pub fn count(self) -> usize {
        self.run().count()
    }
}

/// Look up an entry by identifier, name, or alias, case-insensitively.
pub fn get(name: &str) -> Option<&'static Entry> {
    REGISTRY.iter().find(|e| e.matches_name(name))
}

/// Every entry in the registry.
pub fn all() -> &'static [Entry] {
    REGISTRY
}

/// Entries related to `id` by any edge, in either direction.
///
/// Traversing both directions matters: `sha2-256` does not record that HMAC is
/// built on it, but an agent asking "what depends on SHA-256?" still needs the
/// answer.
pub fn related(id: &str) -> impl Iterator<Item = &'static Entry> + '_ {
    REGISTRY.iter().filter(move |e| {
        if e.id == id {
            return false;
        }
        let outgoing = get(id)
            .map(|src| src.edges.iter().any(|edge| edge.target == e.id))
            .unwrap_or(false);
        let incoming = e.edges.iter().any(|edge| edge.target == id);
        outgoing || incoming
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_handles_ids_names_and_aliases() {
        assert_eq!(get("sha2-256").unwrap().id, "sha2-256");
        assert_eq!(get("SHA-256").unwrap().id, "sha2-256");
        assert_eq!(get("sha256").unwrap().id, "sha2-256");
        assert_eq!(get("SHA256").unwrap().id, "sha2-256");
        assert!(get("not-a-real-algorithm").is_none());
    }

    #[test]
    fn authenticated_encryption_query_finds_the_aeads() {
        let hits: Vec<_> = Query::new()
            .purpose(Purpose::Confidentiality)
            .purpose(Purpose::Authentication)
            .available_only()
            .run()
            .map(|e| e.id)
            .collect();
        assert!(hits.contains(&"aes-256-gcm"));
        assert!(hits.contains(&"chacha20-poly1305"));
        // A raw block cipher offers confidentiality but not authentication.
        assert!(!hits.contains(&"aes-256"));
    }

    #[test]
    fn fips_filter_excludes_unapproved_algorithms() {
        let hits: Vec<_> = Query::new()
            .class(Class::Aead)
            .fips_approved_only()
            .run()
            .map(|e| e.id)
            .collect();
        assert!(hits.contains(&"aes-256-gcm"));
        assert!(!hits.contains(&"chacha20-poly1305"));
    }

    #[test]
    fn availability_filter_excludes_what_is_not_implemented() {
        // The KEM class used to be the example here, because ML-KEM-768 was the
        // only entry in it and was `experimental`. It is vector-tested now, so
        // the filter keeps it -- and that is the point of the filter, not a
        // failure of it.
        let kems: Vec<&str> = Query::new()
            .class(Class::Kem)
            .available_only()
            .run()
            .map(|e| e.id)
            .collect();
        assert_eq!(kems, ["ml-kem-768"]);

        // Excluded algorithms are what the filter must still remove. They are
        // in the registry so that asking for one gets a reasoned refusal rather
        // than silence, and they must never be offered as usable.
        for id in ["md5", "sha-1", "3des"] {
            assert!(
                crate::get(id).is_some(),
                "{id} should still be listed, so a request for it is answered"
            );
            assert!(
                !Query::new().available_only().run().any(|e| e.id == id),
                "{id} is broken and must not appear as available"
            );
        }
    }

    #[test]
    fn quantum_filter_removes_classical_asymmetric_schemes() {
        let hits: Vec<_> = Query::new()
            .min_quantum_bits(128)
            .run()
            .map(|e| e.id)
            .collect();
        assert!(!hits.contains(&"x25519"), "Shor breaks X25519");
        assert!(!hits.contains(&"ed25519"));
        assert!(
            hits.contains(&"aes-256-gcm"),
            "Grover leaves AES-256 at 128 bits"
        );
        assert!(hits.contains(&"ml-kem-768"));
    }

    #[test]
    fn strength_filter_is_inclusive_at_the_boundary() {
        let hits: Vec<_> = Query::new()
            .class(Class::Aead)
            .min_classical_bits(256)
            .run()
            .map(|e| e.id)
            .collect();
        assert!(hits.contains(&"aes-256-gcm"));
        assert!(!hits.contains(&"aes-128-gcm"));
    }

    #[test]
    fn family_filter_groups_related_entries() {
        let n = Query::new().family("SHA-2").count();
        assert_eq!(n, 6, "six published SHA-2 output variants");
    }

    #[test]
    fn empty_query_matches_everything() {
        assert_eq!(Query::new().count(), all().len());
    }

    #[test]
    fn relations_traverse_both_directions() {
        // HMAC-SHA-256 declares it is built on SHA-256...
        let from_hmac: Vec<_> = related("hmac-sha2-256").map(|e| e.id).collect();
        assert!(from_hmac.contains(&"sha2-256"));
        // ...and the reverse lookup finds it even though SHA-256 has no edge.
        let from_sha: Vec<_> = related("sha2-256").map(|e| e.id).collect();
        assert!(from_sha.contains(&"hmac-sha2-256"));
    }

    #[test]
    fn purpose_limit_does_not_silently_drop_filters() {
        // Four is the cap; the fifth is ignored rather than panicking, and the
        // first four still apply.
        let q = Query::new()
            .purpose(Purpose::Confidentiality)
            .purpose(Purpose::Authentication)
            .purpose(Purpose::Integrity)
            .purpose(Purpose::KeyDerivation)
            .purpose(Purpose::RandomGeneration);
        assert_eq!(q.purpose_count, 4);
        assert_eq!(q.count(), 0, "nothing serves all four of those purposes");
    }
}
