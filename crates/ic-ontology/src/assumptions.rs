//! The hardness assumptions each algorithm rests on.
//!
//! [`Strength`](crate::Strength) says how much work the best *known* attack
//! needs. This module says what that figure is a claim about, so that when a
//! result weakens one assumption -- a better lattice reduction, a structural
//! attack on a curve, a break of a hash's compression function -- an agent can
//! ask which algorithms it touches with one call to [`affected_by`] instead of
//! auditing the registry by hand.
//!
//! Only primitives declare assumptions directly, in [`DIRECT`]. Everything
//! built from them inherits theirs through the registry's
//! [`BuiltOn`](crate::Relation::BuiltOn) and
//! [`Specializes`](crate::Relation::Specializes) edges, so the composition is
//! stated once: PBES2 rests on SHA-2 and AES because the registry says it is
//! built on PBKDF2-HMAC-SHA-256 and AES-CBC, not because a second table says
//! so. A test fails if any entry ends up resting on nothing, unless it is
//! listed in [`UNCONDITIONAL`].
//!
//! The reading is conservative: an entry rests on an assumption if a break of
//! that assumption would affect it under *some* parameter set or suite it
//! offers. HPKE over X25519 lists AES and ChaCha because it offers both AEADs,
//! not because one message uses both.

use crate::{Entry, Relation, REGISTRY};

/// A hardness assumption: a problem believed hard, or a primitive believed to
/// behave as an ideal object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Assumption {
    /// The RSA problem, and through it integer factorization.
    Rsa,
    /// Discrete logarithms, and the Diffie-Hellman problems, on elliptic
    /// curves: the NIST P-curves and Curve25519.
    EcDiscreteLog,
    /// Module learning with errors (FIPS 203 and 204).
    ModuleLwe,
    /// Module short integer solution, in its self-target form (FIPS 204).
    ModuleSis,
    /// AES as a pseudorandom permutation.
    Aes,
    /// The ChaCha permutation as a pseudorandom function.
    ChaCha,
    /// The Salsa20 core, as scrypt uses it.
    Salsa20,
    /// The SHA-2 compression functions: collision, preimage and PRF security.
    Sha2,
    /// The Keccak-f permutation behind SHA-3, SHAKE and cSHAKE.
    Keccak,
    /// The BLAKE2 compression function, which BLAKE3 reuses with fewer rounds.
    Blake2,
    /// SHA-1's compression function. Collisions are already practical.
    Sha1,
    /// MD5's compression function. Collisions are already practical.
    Md5,
    /// Blowfish as a pseudorandom permutation, as bcrypt uses it.
    Blowfish,
    /// DES as a pseudorandom permutation, for 3DES.
    Des,
}

impl Assumption {
    /// Every variant, in declaration order.
    pub const ALL: &'static [Assumption] = &[
        Assumption::Rsa,
        Assumption::EcDiscreteLog,
        Assumption::ModuleLwe,
        Assumption::ModuleSis,
        Assumption::Aes,
        Assumption::ChaCha,
        Assumption::Salsa20,
        Assumption::Sha2,
        Assumption::Keccak,
        Assumption::Blake2,
        Assumption::Sha1,
        Assumption::Md5,
        Assumption::Blowfish,
        Assumption::Des,
    ];

    /// Stable kebab-case identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Assumption::Rsa => "rsa",
            Assumption::EcDiscreteLog => "ec-discrete-log",
            Assumption::ModuleLwe => "module-lwe",
            Assumption::ModuleSis => "module-sis",
            Assumption::Aes => "aes",
            Assumption::ChaCha => "chacha",
            Assumption::Salsa20 => "salsa20",
            Assumption::Sha2 => "sha-2",
            Assumption::Keccak => "keccak",
            Assumption::Blake2 => "blake2",
            Assumption::Sha1 => "sha-1",
            Assumption::Md5 => "md5",
            Assumption::Blowfish => "blowfish",
            Assumption::Des => "des",
        }
    }

    /// One sentence on what is assumed.
    pub const fn summary(self) -> &'static str {
        match self {
            Assumption::Rsa => "Inverting RSA without the private key, and so factoring, is infeasible.",
            Assumption::EcDiscreteLog => {
                "Discrete logarithms and the Diffie-Hellman problems on the P-curves and Curve25519 are infeasible."
            }
            Assumption::ModuleLwe => "Module-LWE is hard for the FIPS 203 and 204 parameter sets.",
            Assumption::ModuleSis => "Self-target Module-SIS is hard for the FIPS 204 parameter sets.",
            Assumption::Aes => "AES is indistinguishable from a random permutation.",
            Assumption::ChaCha => "The ChaCha20 block function is indistinguishable from a random function.",
            Assumption::Salsa20 => "The Salsa20/8 core mixes as scrypt requires.",
            Assumption::Sha2 => "The SHA-2 compression functions resist collisions and preimages and act as PRFs.",
            Assumption::Keccak => "The Keccak-f[1600] permutation behaves as a random permutation in the sponge.",
            Assumption::Blake2 => "The BLAKE2 compression function resists collisions and preimages.",
            Assumption::Sha1 => "SHA-1 resists preimages; its collision resistance is already broken.",
            Assumption::Md5 => "MD5 resists preimages; its collision resistance is already broken.",
            Assumption::Blowfish => "Blowfish is indistinguishable from a random permutation.",
            Assumption::Des => "DES is indistinguishable from a random permutation, so 3DES is too.",
        }
    }

    /// The variant with this identifier.
    pub fn from_id(id: &str) -> Option<Assumption> {
        Assumption::ALL.iter().copied().find(|a| a.id() == id)
    }

    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

/// The assumptions primitives declare themselves. Entries not listed here
/// inherit theirs through their edges.
pub static DIRECT: &[(&str, &[Assumption])] = &[
    // hashes and XOFs
    ("sha2-224", &[Assumption::Sha2]),
    ("sha2-256", &[Assumption::Sha2]),
    ("sha2-384", &[Assumption::Sha2]),
    ("sha2-512", &[Assumption::Sha2]),
    ("sha2-512-224", &[Assumption::Sha2]),
    ("sha2-512-256", &[Assumption::Sha2]),
    ("sha3-224", &[Assumption::Keccak]),
    ("sha3-256", &[Assumption::Keccak]),
    ("sha3-384", &[Assumption::Keccak]),
    ("sha3-512", &[Assumption::Keccak]),
    ("shake128", &[Assumption::Keccak]),
    ("shake256", &[Assumption::Keccak]),
    ("sha-1", &[Assumption::Sha1]),
    ("md5", &[Assumption::Md5]),
    ("blake2b", &[Assumption::Blake2]),
    ("blake2s", &[Assumption::Blake2]),
    ("salsa20-8-core", &[Assumption::Salsa20]),
    // block ciphers, and the modes the registry does not build on one
    ("aes-128", &[Assumption::Aes]),
    ("aes-192", &[Assumption::Aes]),
    ("aes-256", &[Assumption::Aes]),
    ("aes-cbc", &[Assumption::Aes]),
    ("aes-ctr", &[Assumption::Aes]),
    ("blowfish", &[Assumption::Blowfish]),
    ("3des", &[Assumption::Des]),
    // ChaCha: the registry has no entry for the bare cipher
    ("chacha20-poly1305", &[Assumption::ChaCha]),
    ("hchacha20", &[Assumption::ChaCha]),
    // elliptic curves
    ("x25519", &[Assumption::EcDiscreteLog]),
    ("ed25519", &[Assumption::EcDiscreteLog]),
    ("ecdh-p256", &[Assumption::EcDiscreteLog]),
    ("ecdh-p384", &[Assumption::EcDiscreteLog]),
    ("ecdh-p521", &[Assumption::EcDiscreteLog]),
    ("ecdsa-p256-sha256", &[Assumption::EcDiscreteLog]),
    ("ecdsa-p384-sha384", &[Assumption::EcDiscreteLog]),
    ("ecdsa-p521-sha512", &[Assumption::EcDiscreteLog]),
    // the OPRF's one-more-gap Diffie-Hellman is a P-256 assumption
    ("oprf-p256-sha256", &[Assumption::EcDiscreteLog]),
    // lattices
    ("ml-kem-512", &[Assumption::ModuleLwe]),
    ("ml-kem-768", &[Assumption::ModuleLwe]),
    ("ml-kem-1024", &[Assumption::ModuleLwe]),
    ("ml-dsa-44", &[Assumption::ModuleLwe, Assumption::ModuleSis]),
    ("ml-dsa-65", &[Assumption::ModuleLwe, Assumption::ModuleSis]),
    ("ml-dsa-87", &[Assumption::ModuleLwe, Assumption::ModuleSis]),
    // RSA
    ("rsa-pkcs1-sha256", &[Assumption::Rsa]),
    ("rsa-pkcs1-sha384", &[Assumption::Rsa]),
    ("rsa-pkcs1-sha512", &[Assumption::Rsa]),
    ("rsa-pss-sha256", &[Assumption::Rsa]),
    ("rsa-pss-sha384", &[Assumption::Rsa]),
    ("rsa-pss-sha512", &[Assumption::Rsa]),
    // XMSS has no edges to its hashes; RFC 8391 and SP 800-208 offer both
    ("xmss", &[Assumption::Sha2, Assumption::Keccak]),
    // OPAQUE only pairs with its key stretching function in the registry, but
    // a real one is required (opaque-real-ksf): Argon2id rests on BLAKE2, and
    // scrypt on Salsa20 and SHA-2, which the HKDF edge already brings
    (
        "opaque-3dh-p256",
        &[Assumption::Blake2, Assumption::Salsa20],
    ),
];

/// Entries whose security assumes no hard problem: Poly1305 with a one-time
/// key, and Shamir's scheme over GF(2^8). Each is secure against an unbounded
/// adversary, so no result about hardness can touch it.
pub static UNCONDITIONAL: &[&str] = &["poly1305", "shamir-gf256"];

/// A set of assumptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Assumptions(u32);

impl Assumptions {
    /// Whether the set contains `a`.
    pub const fn contains(self, a: Assumption) -> bool {
        self.0 & a.bit() != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The members, in [`Assumption::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Assumption> {
        Assumption::ALL
            .iter()
            .copied()
            .filter(move |a| self.contains(*a))
    }
}

/// The assumptions `id` itself declares, without inheritance.
pub fn direct(id: &str) -> &'static [Assumption] {
    DIRECT
        .iter()
        .find(|(e, _)| *e == id)
        .map(|(_, a)| *a)
        .unwrap_or(&[])
}

/// Deep enough for any chain in the registry; a cycle stops here instead of
/// recursing forever, and a test checks the registry never gets this deep.
const MAX_DEPTH: usize = 8;

fn collect(id: &str, depth: usize) -> u32 {
    let mut bits = direct(id).iter().fold(0, |m, a| m | a.bit());
    if depth == 0 {
        return bits;
    }
    if let Some(e) = REGISTRY.iter().find(|e| e.id == id) {
        for edge in e.edges {
            if matches!(edge.relation, Relation::BuiltOn | Relation::Specializes) {
                bits |= collect(edge.target, depth - 1);
            }
        }
    }
    bits
}

/// Every assumption the algorithm `name` rests on: its own and, through its
/// [`BuiltOn`](Relation::BuiltOn) and [`Specializes`](Relation::Specializes)
/// edges, those of everything it is built from. `name` may be an id, a name or
/// an alias, as for [`get`](crate::get). `None` if it names nothing, so an
/// unknown name is never mistaken for an entry in [`UNCONDITIONAL`], whose set
/// is empty.
pub fn rests_on(name: &str) -> Option<Assumptions> {
    crate::get(name).map(|e| Assumptions(collect(e.id, MAX_DEPTH)))
}

/// Every registry entry that rests on `a`.
pub fn affected_by(a: Assumption) -> impl Iterator<Item = &'static Entry> {
    REGISTRY
        .iter()
        .filter(move |e| Assumptions(collect(e.id, MAX_DEPTH)).contains(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(a: Assumption) -> std::vec::Vec<&'static str> {
        affected_by(a).map(|e| e.id).collect()
    }

    #[test]
    fn every_entry_rests_on_something_or_on_nothing_by_design() {
        for e in REGISTRY {
            let unconditional = UNCONDITIONAL.contains(&e.id);
            assert_eq!(
                rests_on(e.id).unwrap().is_empty(),
                unconditional,
                "{}: {}",
                e.id,
                if unconditional {
                    "listed as unconditional but rests on an assumption"
                } else {
                    "rests on no assumption; declare one in DIRECT or give it a BuiltOn edge"
                }
            );
        }
    }

    #[test]
    fn the_tables_name_only_registry_entries_once() {
        let known = |id: &str| REGISTRY.iter().any(|e| e.id == id);
        for (i, (id, a)) in DIRECT.iter().enumerate() {
            assert!(known(id), "{id} is not in the registry");
            assert!(!a.is_empty(), "{id} declares an empty list");
            assert!(
                !DIRECT[..i].iter().any(|(x, _)| x == id),
                "{id} is listed twice"
            );
            assert!(
                !UNCONDITIONAL.contains(id),
                "{id} is both direct and unconditional"
            );
        }
        for id in UNCONDITIONAL {
            assert!(known(id), "{id} is not in the registry");
        }
    }

    #[test]
    fn no_chain_reaches_the_depth_limit() {
        // collect() stops at MAX_DEPTH; if a chain were that long, or a
        // cycle existed, the answer could be silently short
        fn depth(id: &str, seen: &mut std::vec::Vec<&'static str>) -> usize {
            let Some(e) = REGISTRY.iter().find(|e| e.id == id) else {
                return 0;
            };
            assert!(!seen.contains(&e.id), "cycle through {}", e.id);
            seen.push(e.id);
            let d = e
                .edges
                .iter()
                .filter(|x| matches!(x.relation, Relation::BuiltOn | Relation::Specializes))
                .map(|x| 1 + depth(x.target, seen))
                .max()
                .unwrap_or(0);
            seen.pop();
            d
        }
        for e in REGISTRY {
            assert!(
                depth(e.id, &mut std::vec::Vec::new()) < MAX_DEPTH,
                "{}",
                e.id
            );
        }
    }

    #[test]
    fn identifiers_round_trip_and_fit_the_set() {
        assert!(Assumption::ALL.len() <= 32);
        for (i, a) in Assumption::ALL.iter().enumerate() {
            assert_eq!(*a as usize, i, "ALL is out of declaration order");
            assert_eq!(Assumption::from_id(a.id()), Some(*a));
        }
        assert_eq!(Assumption::from_id("eth"), None);
    }

    #[test]
    fn composites_inherit_through_their_edges() {
        let set = |id| rests_on(id).unwrap().iter().collect::<std::vec::Vec<_>>();
        use Assumption::*;
        // PBKDF2-HMAC-SHA-256 and AES-CBC
        assert_eq!(set("pkcs8-pbes2"), [Aes, Sha2]);
        // X25519, HKDF-SHA-256, and AES-GCM or ChaCha20-Poly1305
        assert_eq!(
            set("hpke-x25519-sha256"),
            [EcDiscreteLog, Aes, ChaCha, Sha2]
        );
        assert_eq!(set("ml-dsa-65"), [ModuleLwe, ModuleSis, Keccak]);
        assert_eq!(set("ml-kem-768"), [ModuleLwe, Keccak]);
        // hash-based: nothing but its hashes
        assert_eq!(set("slh-dsa"), [Sha2, Keccak]);
        assert_eq!(set("hss-lms"), [Sha2, Keccak]);
        assert_eq!(set("cshake128"), [Keccak]);
        assert_eq!(set("passphrase-seal"), [ChaCha, Blake2]);
        // the key stretching function OPAQUE requires, either one
        assert_eq!(
            set("opaque-3dh-p256"),
            [EcDiscreteLog, Salsa20, Sha2, Blake2]
        );
        assert_eq!(rests_on("poly1305"), Some(Assumptions::default()));
    }

    #[test]
    fn names_resolve_as_get_does_and_unknown_ones_say_so() {
        // an alias reaches the entry, not the empty set that would read as
        // "unconditional"
        assert_eq!(rests_on("sha256"), rests_on("sha2-256"));
        assert!(rests_on("sha256").unwrap().contains(Assumption::Sha2));
        assert_eq!(rests_on("no-such-algorithm"), None);
    }

    #[test]
    fn a_lattice_break_reaches_exactly_the_lattice_schemes() {
        let mut hit = ids(Assumption::ModuleLwe);
        hit.sort_unstable();
        assert_eq!(
            hit,
            [
                "ml-dsa-44",
                "ml-dsa-65",
                "ml-dsa-87",
                "ml-kem-1024",
                "ml-kem-512",
                "ml-kem-768"
            ]
        );
        // nothing hash-based or symmetric is on that list, which is the
        // point of deploying SLH-DSA or LMS beside ML-DSA
        assert!(!ids(Assumption::ModuleSis).contains(&"slh-dsa"));
    }

    #[test]
    fn a_curve_break_reaches_the_protocols_built_on_curves() {
        let hit = ids(Assumption::EcDiscreteLog);
        for id in [
            "x25519",
            "ed25519",
            "hpke-p384-sha384",
            "opaque-3dh-p256",
            "ecdsa-p521-sha512",
        ] {
            assert!(hit.contains(&id), "{id}");
        }
        for id in ["ml-kem-768", "aes-256-gcm", "slh-dsa"] {
            assert!(!hit.contains(&id), "{id}");
        }
    }
}
