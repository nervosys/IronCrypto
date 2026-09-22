//! Security frameworks: weaknesses, adversary techniques, and CMMC practices.
//!
//! [`crate::standards`] answers "what do the documents that define these
//! algorithms require". This answers a different question that auditors,
//! agents and procurement all ask instead: "which known weakness classes does
//! this avoid, which adversary techniques does it bear on, and does it satisfy
//! the practice my contract names".
//!
//! Three frameworks, because they are three different kinds of thing and
//! collapsing them would lose that:
//!
//! - **CWE** — classes of weakness. A library does not "comply with CVE"; CVEs
//!   are instances, and what an implementation can do is avoid the classes they
//!   belong to. [`cve_posture`] covers the other half, the part that is about
//!   supply chain rather than code.
//! - **MITRE ATT&CK** — what an adversary does. A cryptographic library is not
//!   a detection product, so most of the matrix is irrelevant; the entries here
//!   are the techniques its controls genuinely bear on, and nothing is claimed
//!   about the rest.
//! - **CMMC 2.0** — contractual practices, drawn from NIST SP 800-171.
//!
//! # The most important entry in this file
//!
//! `SC.L2-3.13.11` requires **FIPS-validated** cryptography. IronCrypto has no
//! CMVP certificate, so it **cannot satisfy that practice**, and no amount of
//! correctness evidence changes that — validation is a process with a
//! laboratory and a certificate number, not a property of source code.
//!
//! It is recorded as [`Compliance::Unmet`] with the reason spelled out, and a
//! test asserts it stays that way. If this module ever let a reader believe
//! otherwise it would be worse than not existing, because someone would rely on
//! it for an attestation they are not entitled to make.
//!
//! # Coupling
//!
//! Same rules as the standards knowledgebase. A control claiming to be met or
//! partially met names a file and a symbol, and the tests check both exist, so
//! a rename breaks the build rather than leaving a stale compliance claim.
//! Referenced algorithms must be real registry entries and referenced documents
//! must be real entries in [`crate::standards`].

use crate::standards::Compliance;

/// Which framework a control comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    /// MITRE's Common Weakness Enumeration.
    Cwe,
    /// MITRE ATT&CK, the adversary technique catalogue.
    Attack,
    /// CMMC 2.0, the US Department of Defense maturity model.
    Cmmc,
}

impl Framework {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Cwe => "cwe",
            Self::Attack => "attack",
            Self::Cmmc => "cmmc",
        }
    }

    /// The framework's full name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cwe => "MITRE Common Weakness Enumeration",
            Self::Attack => "MITRE ATT&CK",
            Self::Cmmc => "Cybersecurity Maturity Model Certification 2.0",
        }
    }
}

/// One weakness class, adversary technique, or contractual practice.
#[derive(Debug, Clone, Copy)]
pub struct Control {
    /// The framework's own identifier, e.g. `CWE-327` or `SC.L2-3.13.11`.
    pub id: &'static str,
    /// Which framework it belongs to.
    pub framework: Framework,
    /// The framework's title for it.
    pub title: &'static str,
    /// What the framework means by it, in plain words.
    pub description: &'static str,
    /// How it bears on a cryptographic library specifically.
    ///
    /// Most of ATT&CK and much of CMMC is about systems rather than libraries.
    /// This field is where the scope gets stated instead of implied.
    pub bearing: &'static str,
    /// What IronCrypto does about it.
    pub compliance: Compliance,
    /// Registry entries this control bears on. Empty means the whole library.
    pub algorithms: &'static [&'static str],
    /// Documents in [`crate::standards`] that this control leans on.
    pub standards: &'static [&'static str],
}

/// Look a control up by its framework identifier.
pub fn control(id: &str) -> Option<&'static Control> {
    CONTROLS.iter().find(|c| c.id.eq_ignore_ascii_case(id))
}

/// Every control in one framework.
pub fn by_framework(framework: Framework) -> impl Iterator<Item = &'static Control> {
    CONTROLS.iter().filter(move |c| c.framework == framework)
}

/// Controls bearing on a given algorithm.
///
/// A control with an empty `algorithms` list applies to the whole library, so
/// it matches every algorithm rather than none.
pub fn for_algorithm(algorithm_id: &str) -> impl Iterator<Item = &'static Control> + '_ {
    CONTROLS
        .iter()
        .filter(move |c| c.algorithms.is_empty() || c.algorithms.contains(&algorithm_id))
}

/// The library's posture toward published vulnerabilities.
///
/// This is the part of "CVE compliance" that is not about weakness classes. It
/// is deliberately a function returning prose rather than a boolean, because
/// the honest answer has three parts and a boolean would flatten it.
pub fn cve_posture() -> &'static str {
    "Every IronCrypto crate that implements cryptography depends on nothing \
     outside this workspace, enforced per crate by `scripts/no-third-party.sh`, \
     which CI and the pre-commit hook both run. Those crates have no transitive \
     CVE surface: there is no dependency whose advisory could apply to \
     it. That is the strongest claim available and it is a narrow one. It says nothing about \
     defects in IronCrypto's own code, for which the answer is the evidence recorded in \
     `docs/FIPS.md` and the weakness classes in this module. No CVE has been issued against \
     IronCrypto, which at this stage reflects that it is a young and privately held project \
     rather than any assurance. One crate is outside this: `ic-rustls` \
     implements rustls's traits and so depends on rustls, which brings five \
     crates with it. Anything depending on `ic-rustls` inherits their \
     advisories; nothing else here does. SECURITY.md carries the disclosure \
     process."
}

// ---------------------------------------------------------------------------
// The controls.
// ---------------------------------------------------------------------------

/// Every control across the three frameworks.
pub static CONTROLS: &[Control] = &[
    // -- CWE ----------------------------------------------------------------
    Control {
        id: "CWE-327",
        framework: Framework::Cwe,
        title: "Use of a Broken or Risky Cryptographic Algorithm",
        description: "The product uses a cryptographic algorithm that is broken, or risky enough that its use is itself the defect.",
        bearing: "The central weakness for a cryptographic library, and the one a registry is built to answer. Broken algorithms are present as Excluded entries so that a request for them resolves to a refusal with a reason, rather than to silence a caller reads as not-implemented-yet and works around.",
        compliance: Compliance::Met {
            file: "crates/ic-ontology/src/registry.rs",
            symbol: "ImplStatus::Excluded",
        },
        algorithms: &["sha-1", "md5", "3des"],
        standards: &["SP 800-131A"],
    },
    Control {
        id: "CWE-328",
        framework: Framework::Cwe,
        title: "Use of Weak Hash",
        description: "A hash function is used whose collision or preimage resistance is inadequate for the purpose.",
        bearing: "MD5 and SHA-1 are implemented only so that a request for them is refused with a reason. Neither is reachable through the approved-mode policy or through recommend.",
        compliance: Compliance::Met {
            file: "crates/ic-fips/src/lib.rs",
            symbol: "NotApprovedInFipsMode",
        },
        algorithms: &["sha-1", "md5"],
        standards: &["FIPS 180-4"],
    },
    Control {
        id: "CWE-330",
        framework: Framework::Cwe,
        title: "Use of Insufficiently Random Values",
        description: "Security depends on values an attacker can predict.",
        bearing: "Instantiation draws at least the declared security strength in entropy and fails rather than proceeding with less, which is the failure mode that cannot be repaired by any later operation.",
        compliance: Compliance::Met {
            file: "crates/ic-drbg/src/rng.rs",
            symbol: "from_entropy",
        },
        algorithms: &["ctr-drbg-aes-256"],
        standards: &["SP 800-90A"],
    },
    Control {
        id: "CWE-338",
        framework: Framework::Cwe,
        title: "Use of Cryptographically Weak Pseudo-Random Number Generator",
        description: "A PRNG not intended for security is used where unpredictability matters.",
        bearing: "The library offers only approved DRBGs and takes entropy from the caller or the platform. Nothing here wraps a general-purpose PRNG, and the only non-cryptographic generators in the tree are in test code, where they exist so failures reproduce.",
        compliance: Compliance::Met {
            file: "crates/ic-drbg/src/ctr.rs",
            symbol: "reseed_counter",
        },
        algorithms: &["ctr-drbg-aes-256", "hmac-drbg-sha2-256"],
        standards: &["SP 800-90A"],
    },
    Control {
        id: "CWE-347",
        framework: Framework::Cwe,
        title: "Improper Verification of Cryptographic Signature",
        description: "A signature is accepted that should have been rejected, or the verification result is not acted on.",
        bearing: "Two distinct failures, and the second is the one libraries usually miss. Verification is checked against hostile input for totality and soundness, and every function returning a verification result is marked must_use, so discarding the answer does not compile.",
        compliance: Compliance::Met {
            file: "crates/iron-crypto/tests/api_hygiene.rs",
            symbol: "public_predicates_cannot_be_ignored",
        },
        algorithms: &["ecdsa-p256-sha256", "ed25519", "rsa-pss-sha256", "ml-dsa-65"],
        standards: &["FIPS 186-5", "FIPS 204"],
    },
    Control {
        id: "CWE-354",
        framework: Framework::Cwe,
        title: "Improper Validation of Integrity Check Value",
        description: "Corrupted or forged data is accepted because its integrity check was not properly validated.",
        bearing: "A failed AEAD open releases nothing. A caller who ignores the error and reads the buffer anyway is making a mistake, and handing them decrypted-but-unauthenticated bytes is what would make that mistake dangerous.",
        compliance: Compliance::Met {
            file: "crates/iron-crypto/tests/hostile_input.rs",
            symbol: "aead_opening_is_total_and_sound",
        },
        algorithms: &["aes-256-gcm", "chacha20-poly1305"],
        standards: &["SP 800-38D", "RFC 8439"],
    },
    Control {
        id: "CWE-208",
        framework: Framework::Cwe,
        title: "Observable Timing Discrepancy",
        description: "The time taken by an operation reveals information about secret data.",
        bearing: "Comparisons are constant time, scalar multiplication does not branch on secret bits, and the AEAD tag check cannot be short-circuited. What is not done is measurement: an argument that code is constant time is not the same as evidence, and this library has the argument.",
        compliance: Compliance::Partial {
            file: "crates/ic-cli/src/timing.rs",
            symbol: "the_positive_control_detects_its_own_leak",
            gap: "A dudect-style leakage detector ships as `icrypto timing`, so the claim is measurable rather than only argued. It is a tool and not a gating test, because timing measurement needs a quiet machine and a test that fails when a laptop indexes its disk teaches people to ignore failures. It carries a positive control, since a detector that has never detected anything proves nothing. Nine targets now, including both signing paths, which are the severe case: a distinguisher on verification tells an attacker whether a signature was valid, which they usually learn anyway, while one on signing leaks the private key. On a developer machine the constant-time comparison, P-256 scalar multiplication, X25519, AES, ML-KEM decapsulation, ECDSA signing and RSA signing all show no evidence of leakage against a control registering above 1000; AEAD open differs, for the documented reason that its failure path zeroizes the buffer, which is a branch on already-public output. What is still missing is measurement on quiet reference hardware rather than a loaded developer machine. The RSA and ECDSA targets also run at a lower iteration ceiling because each operation costs milliseconds, so they have less statistical power than the cheap targets, and a null result on a noisy machine remains weak evidence of absence rather than a proof."
        },
        algorithms: &[],
        standards: &[],
    },
    Control {
        id: "CWE-323",
        framework: Framework::Cwe,
        title: "Reusing a Nonce, Key Pair in Encryption",
        description: "A nonce is reused under the same key, destroying the mode's security guarantees.",
        bearing: "The library cannot enforce this without owning the counter, and pretending otherwise would be worse than saying so. Every AEAD entry carries a Critical constraint stating exactly what reuse costs under that mode, and AES-GCM-SIV is offered for callers who cannot guarantee uniqueness.",
        compliance: Compliance::NotApplicable {
            why: "Nonce management belongs to the protocol, not the primitive. What a library can do is make the consequence discoverable before the mistake rather than after, which is what the registry constraint does, and offer a mode that survives it.",
        },
        algorithms: &["aes-256-gcm", "aes-256-gcm-siv"],
        standards: &["SP 800-38D", "RFC 8452"],
    },
    Control {
        id: "CWE-759",
        framework: Framework::Cwe,
        title: "Use of a One-Way Hash without a Salt",
        description: "Password hashing without a salt allows precomputation across users.",
        bearing: "The password KDFs take a salt as a required argument rather than defaulting one, so omitting it is not expressible.",
        compliance: Compliance::Met {
            file: "crates/ic-kdf/src/pbkdf2.rs",
            symbol: "salt",
        },
        algorithms: &["pbkdf2-hmac-sha2-256", "argon2id"],
        standards: &["SP 800-132", "RFC 9106"],
    },
    Control {
        id: "CWE-1104",
        framework: Framework::Cwe,
        title: "Use of Unmaintained Third Party Components",
        description: "The product depends on components whose maintenance status it does not control.",
        bearing: "Every crate implementing cryptography here depends on nothing outside the workspace, checked per crate by scripts/no-third-party.sh, which CI and the pre-commit hook both run. This is the structural half of the CVE question: those crates have no transitive advisory surface because they have nothing transitive. The exception is ic-rustls, the rustls provider, which must depend on rustls to implement its traits; what rustls may bring is listed by name in that script, so it cannot grow unnoticed.",
        compliance: Compliance::Met {
            file: "scripts/no-third-party.sh",
            symbol: "cargo tree",
        },
        algorithms: &[],
        standards: &[],
    },
    Control {
        id: "CWE-1240",
        framework: Framework::Cwe,
        title: "Use of a Risky Cryptographic Primitive",
        description: "A primitive is used whose properties do not match what the design assumes of it.",
        bearing: "The ontology answers this before the mistake: each entry states its purposes, its strength, what it does not provide, and what pairs with it. A cipher mode entry has to say what integrity it provides, which is an invariant the registry enforces rather than a convention.",
        compliance: Compliance::Met {
            file: "crates/ic-ontology/src/registry.rs",
            symbol: "Constraint",
        },
        algorithms: &[],
        standards: &[],
    },
    // -- MITRE ATT&CK -------------------------------------------------------
    Control {
        id: "T1600",
        framework: Framework::Attack,
        title: "Weaken Encryption",
        description: "An adversary compromises a system's cryptography to make protected traffic readable.",
        bearing: "The library-level defence is that weakening is not reachable through the API: key-size floors are enforced at construction rather than documented, and approved mode refuses unapproved algorithms outright rather than warning.",
        compliance: Compliance::Met {
            file: "crates/ic-rsa/src/key.rs",
            symbol: "MIN_MODULUS_BITS",
        },
        algorithms: &[],
        standards: &["SP 800-131A"],
    },
    Control {
        id: "T1600.001",
        framework: Framework::Attack,
        title: "Weaken Encryption: Reduce Key Space",
        description: "An adversary reduces the key space a system uses, so that keys become brute-forceable.",
        bearing: "Key sizes are not caller-selectable below the floor. RSA refuses a modulus under 2048 bits at construction, so a short key cannot be loaded and then used, and the registry states each algorithm's strength so a downgrade is visible rather than inferred.",
        compliance: Compliance::Met {
            file: "crates/ic-rsa/src/key.rs",
            symbol: "rsa modulus must be 2048",
        },
        algorithms: &["rsa-pkcs1-sha256", "rsa-pss-sha256"],
        standards: &["SP 800-131A"],
    },
    Control {
        id: "T1552",
        framework: Framework::Attack,
        title: "Unsecured Credentials",
        description: "An adversary recovers credentials or key material left accessible.",
        bearing: "Key material is zeroized when it goes out of scope, so it does not outlive the operation that needed it in a core dump, a swapped page, or a reused allocation. What the library cannot control is where a caller copies it afterwards.",
        compliance: Compliance::Met {
            file: "crates/ic-core/src/zeroize.rs",
            symbol: "Zeroize",
        },
        algorithms: &[],
        standards: &["FIPS 140-3"],
    },
    Control {
        id: "T1557",
        framework: Framework::Attack,
        title: "Adversary-in-the-Middle",
        description: "An adversary positions between two parties to read or alter what passes between them.",
        bearing: "Peer key validation is the library's part: a public key that is not on the curve, or a low-order X25519 point, is refused rather than used. Everything above that -- identity, trust decisions, certificate path validation -- is out of scope and deliberately not implemented rather than partially implemented.",
        compliance: Compliance::Met {
            file: "crates/ic-ec/src/nist/point.rs",
            symbol: "is_on_curve",
        },
        algorithms: &["ecdh-p256", "x25519"],
        standards: &["SP 800-56A", "RFC 7748"],
    },
    Control {
        id: "T1195.001",
        framework: Framework::Attack,
        title: "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        description: "An adversary compromises a dependency so that the compromise reaches everyone who builds against it.",
        bearing: "The cryptographic crates have no dependencies, so there is nothing there to compromise. ic-rustls is the exception and a real one: depending on rustls means depending on whoever publishes it and the five crates beneath it, which is the technique working as described. The build also still trusts the Rust toolchain, which is unclosed either way, and saying otherwise would be a claim this library cannot support.",
        compliance: Compliance::Partial {
            file: "scripts/no-third-party.sh",
            symbol: "cargo tree",
            gap: "No dependency surface, but the toolchain itself remains trusted, and the build is not reproducible in the bit-for-bit sense that would let a third party confirm a binary matches this source. Closing that needs a reproducible build pipeline, which is a property of the release process rather than of any source file.",
        },
        algorithms: &[],
        standards: &[],
    },
    Control {
        id: "T1110",
        framework: Framework::Attack,
        title: "Brute Force",
        description: "An adversary guesses credentials or keys by exhaustive search.",
        bearing: "For keys, the floors under T1600.001. For passwords, a memory-hard KDF is available and recommended over PBKDF2, because PBKDF2 has no memory cost and so concedes an unbounded hardware advantage to the attacker.",
        compliance: Compliance::Met {
            file: "crates/ic-kdf/src/argon2.rs",
            symbol: "memory_kib",
        },
        algorithms: &["argon2id", "pbkdf2-hmac-sha2-256"],
        standards: &["RFC 9106", "SP 800-132"],
    },
    Control {
        id: "T1565",
        framework: Framework::Attack,
        title: "Data Manipulation",
        description: "An adversary alters data to influence an outcome.",
        bearing: "Authenticated encryption and signatures are the countermeasure, and the library's contribution is that its verification paths are total and sound against hostile input, and that their results cannot be silently discarded.",
        compliance: Compliance::Met {
            file: "crates/iron-crypto/tests/hostile_input.rs",
            symbol: "aead_opening_is_total_and_sound",
        },
        algorithms: &["aes-256-gcm", "ed25519"],
        standards: &["SP 800-38D"],
    },
    // -- CMMC 2.0 -----------------------------------------------------------
    Control {
        id: "SC.L2-3.13.11",
        framework: Framework::Cmmc,
        title: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI",
        description: "Cryptography used to protect Controlled Unclassified Information must be FIPS-validated, meaning it carries a CMVP certificate.",
        bearing: "This is the practice IronCrypto cannot satisfy, and the most important entry in this module. Validation is a process with a laboratory and a certificate number; it is not a property of source code and no amount of correctness evidence substitutes for it.",
        compliance: Compliance::Unmet {
            why: "IronCrypto has no CMVP certificate and is not FIPS-validated. Do not use it where this practice applies. The library implements FIPS 140-3's operational discipline -- approved-mode policy, self-tests before first use, a latching error state, service indicators -- which is a prerequisite for pursuing validation and is not validation. has(\"fips-validated\") returns false and is asserted to keep returning false until a certificate exists.",
        },
        algorithms: &[],
        standards: &["FIPS 140-3"],
    },
    Control {
        id: "SC.L2-3.13.8",
        framework: Framework::Cmmc,
        title: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission",
        description: "Transmitted CUI must be protected by cryptographic mechanisms unless otherwise protected by physical safeguards.",
        bearing: "The library supplies the mechanisms; a system satisfies the practice. Note that satisfying this practice for CUI also requires SC.L2-3.13.11, which IronCrypto does not satisfy.",
        compliance: Compliance::Met {
            file: "crates/ic-cipher/src/gcm.rs",
            symbol: "Aes256Gcm",
        },
        algorithms: &["aes-256-gcm", "chacha20-poly1305"],
        standards: &["SP 800-38D", "RFC 8439"],
    },
    Control {
        id: "SC.L2-3.13.16",
        framework: Framework::Cmmc,
        title: "Protect the confidentiality of CUI at rest",
        description: "CUI held at rest must be protected, commonly by encryption.",
        bearing: "The library supplies authenticated encryption and key wrapping. Key management, storage and rotation are the system's, and are the part that usually fails.",
        compliance: Compliance::Met {
            file: "crates/ic-cipher/src/keywrap.rs",
            symbol: "Aes256Kw",
        },
        algorithms: &["aes-256-gcm", "aes-256-kw"],
        standards: &["SP 800-38F"],
    },
    Control {
        id: "IA.L2-3.5.10",
        framework: Framework::Cmmc,
        title: "Store and transmit only cryptographically-protected passwords",
        description: "Passwords must not be held or sent in recoverable form.",
        bearing: "The library supplies password-based KDFs with required salts, and the ontology recommends the memory-hard one over PBKDF2 where the deployment allows a non-approved algorithm.",
        compliance: Compliance::Met {
            file: "crates/ic-kdf/src/argon2.rs",
            symbol: "Argon2Params",
        },
        algorithms: &["argon2id", "pbkdf2-hmac-sha2-256"],
        standards: &["SP 800-132", "RFC 9106"],
    },
    Control {
        id: "MP.L2-3.8.6",
        framework: Framework::Cmmc,
        title: "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport",
        description: "CUI on media in transit must be cryptographically protected unless otherwise safeguarded.",
        bearing: "Same mechanisms as SC.L2-3.13.16, and the same boundary: the library encrypts, the system decides what and when.",
        compliance: Compliance::Met {
            file: "crates/ic-cipher/src/gcm.rs",
            symbol: "Aes256Gcm",
        },
        algorithms: &["aes-256-gcm"],
        standards: &["SP 800-38D"],
    },
    Control {
        id: "SC.L2-3.13.10",
        framework: Framework::Cmmc,
        title: "Establish and manage cryptographic keys for cryptography employed in the system",
        description: "Keys must be generated, distributed, stored and destroyed under a defined process.",
        bearing: "The library generates keys from an approved DRBG, checks generated key pairs for pairwise consistency before releasing them, and zeroizes material when it goes out of scope. Distribution, escrow and rotation are the system's and are not modelled here.",
        compliance: Compliance::Partial {
            file: "crates/ic-mlkem/src/kem.rs",
            symbol: "pairwise_consistency",
            gap: "Generation and destruction are covered. Distribution, storage and rotation are system responsibilities that no library can discharge, so a deployment claiming this practice needs its own key management process and cannot point at IronCrypto for the whole of it.",
        },
        algorithms: &[],
        standards: &["FIPS 140-3", "SP 800-56A"],
    },
    Control {
        id: "AU.L2-3.3.8",
        framework: Framework::Cmmc,
        title: "Protect audit information and audit logging tools from unauthorized access, modification and deletion",
        description: "Audit records and the tools that produce them must be protected.",
        bearing: "IronCrypto has no audit subsystem and does not log. It supplies the MACs and signatures a system would use to protect its own audit trail, which is a contribution rather than a satisfaction of the practice.",
        compliance: Compliance::NotApplicable {
            why: "The library produces no audit records. Recorded rather than omitted because a reader scanning for this practice should find the scope boundary stated, not an absence they have to interpret.",
        },
        algorithms: &["hmac-sha2-256"],
        standards: &["FIPS 198-1"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::REGISTRY;
    use crate::standards::standard;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

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

    /// The entry this module exists to get right.
    ///
    /// If IronCrypto ever appeared to satisfy the FIPS-validated-cryptography
    /// practice, someone could rely on this file for an attestation they are not
    /// entitled to make. That is a worse outcome than the module not existing,
    /// so it is asserted rather than trusted to review.
    #[test]
    fn the_fips_validation_practice_is_unmet_and_says_why() {
        let c = control("SC.L2-3.13.11").expect("the practice must be present");
        match c.compliance {
            Compliance::Unmet { why } => {
                assert!(
                    why.contains("no CMVP certificate"),
                    "the reason must name the missing certificate: {why}"
                );
                assert!(
                    why.contains("not FIPS-validated"),
                    "the reason must say plainly that it is not validated: {why}"
                );
            }
            other => panic!("SC.L2-3.13.11 must be Unmet, found {}", other.id()),
        }
    }

    /// No control anywhere may claim validation.
    #[test]
    fn nothing_here_claims_validation() {
        for c in CONTROLS {
            for text in [c.title, c.description, c.bearing] {
                let lower = text.to_ascii_lowercase();
                assert!(
                    !lower.contains("is fips-validated")
                        && !lower.contains("fips validated cryptography is provided"),
                    "{} appears to claim validation: {text}",
                    c.id
                );
            }
        }
    }

    /// A met or partial claim must point at code that exists.
    #[test]
    fn evidence_points_at_real_files() {
        let root = workspace_root();
        let mut checked = 0;
        for c in CONTROLS {
            let (file, symbol) = match c.compliance {
                Compliance::Met { file, symbol } => (file, symbol),
                Compliance::Partial { file, symbol, gap } => {
                    assert!(gap.len() > 40, "{} is partial and must name the gap", c.id);
                    (file, symbol)
                }
                _ => continue,
            };
            let path = root.join(file);
            assert!(path.is_file(), "{} names a missing file: {file}", c.id);
            let text = std::fs::read_to_string(&path).expect("readable");
            assert!(
                text.contains(symbol),
                "{} names {symbol:?}, absent from {file}",
                c.id
            );

            // And it must appear as code, not only in prose.
            //
            // `contains` alone accepts a symbol that occurs nowhere but a
            // comment, which is the weakest possible form of this evidence: a
            // control could cite a function that was deleted, keep passing on
            // the sentence that still mentions it, and read as satisfied. The
            // citation is the whole claim here, so it has to point at something
            // that runs.
            //
            // A line-level test rather than a parse. `symbol` is documented as
            // "a symbol or phrase", and some controls legitimately cite a
            // phrase -- `cargo tree` for T1195.001 -- so requiring a `fn`
            // declaration would reject honest entries. Requiring one
            // non-comment line rejects the dishonest ones and nothing else.
            //
            // The comment marker depends on the language, and getting that
            // wrong is not a detail: two controls cite `scripts/no-third-party.sh`,
            // where comments open with `#`. A version of this check that knew
            // only `//` accepted a citation pointing at shell prose, which is
            // exactly what it exists to reject. `#` is not treated as a comment
            // in Rust, where it opens an attribute.
            let comment = if file.ends_with(".rs") { "//" } else { "#" };
            let in_code = text
                .lines()
                .any(|line| line.contains(symbol) && !line.trim_start().starts_with(comment));
            assert!(
                in_code,
                "{} cites {symbol:?} in {file}, where it appears only in a comment. \
                 Evidence has to name something that runs, not something a sentence \
                 mentions.",
                c.id
            );
            checked += 1;
        }
        // The literal is the count today. It catches a control losing its
        // evidence and being quietly downgraded to a variant this loop skips,
        // which a floor of 14 would have let through.
        assert!(
            checked >= 22,
            "too few controls are wired to code: {checked}"
        );
    }

    /// Cross-references must resolve, in both directions.
    #[test]
    fn references_resolve() {
        for c in CONTROLS {
            for a in c.algorithms {
                assert!(
                    REGISTRY.iter().any(|e| e.id == *a),
                    "{} references algorithm {a:?}, which is not in the registry",
                    c.id
                );
            }
            for s in c.standards {
                assert!(
                    standard(s).is_some(),
                    "{} references document {s:?}, which is not in the knowledgebase",
                    c.id
                );
            }
        }
    }

    #[test]
    fn identifiers_are_unique_and_described() {
        let mut seen = BTreeSet::new();
        for c in CONTROLS {
            assert!(seen.insert(c.id), "duplicate control id {}", c.id);
            assert!(!c.title.is_empty(), "{} has no title", c.id);
            assert!(c.description.len() > 30, "{} has a thin description", c.id);
            assert!(
                c.bearing.len() > 60,
                "{} must say how it bears on a library",
                c.id
            );
        }
    }

    /// Every framework must actually be represented.
    #[test]
    fn all_three_frameworks_are_covered() {
        for f in [Framework::Cwe, Framework::Attack, Framework::Cmmc] {
            let n = by_framework(f).count();
            assert!(n >= 5, "{} has only {n} controls", f.name());
        }
    }

    /// Library-wide controls match every algorithm, which a naive filter drops.
    #[test]
    fn algorithm_scoping_includes_library_wide_controls() {
        let hits: Vec<&str> = for_algorithm("aes-256-gcm").map(|c| c.id).collect();
        assert!(
            hits.contains(&"CWE-354"),
            "specific control missing: {hits:?}"
        );
        assert!(
            hits.contains(&"CWE-208"),
            "library-wide control missing: {hits:?}"
        );
        assert!(control("CWE-9999").is_none());
    }

    /// The CVE posture must state the limit of its own claim.
    #[test]
    fn the_cve_posture_is_not_an_assurance() {
        let text = cve_posture();
        assert!(text.contains("depends on nothing"));
        // The claim narrowed when the rustls provider arrived, and a reader is
        // entitled to know where it stops. Asserting the exception is named
        // stops the narrower claim quietly widening back.
        assert!(
            text.contains("ic-rustls"),
            "the posture must name the one crate that does have dependencies"
        );
        assert!(
            text.contains("says nothing about defects in IronCrypto's own code"),
            "the posture must bound its own claim"
        );
        assert!(
            text.contains("rather than any assurance"),
            "absence of CVEs must not be presented as evidence"
        );
    }

    /// Prose reaches the CLI and MCP responses, so it carries no wrapping
    /// wreckage. Same rule as the standards knowledgebase.
    #[test]
    fn prose_has_no_embedded_whitespace_runs() {
        const RUN: &str = "  ";
        assert_eq!(RUN.len(), 2, "the guard's own pattern was rewritten");
        for c in CONTROLS {
            for (what, text) in [
                ("title", c.title),
                ("description", c.description),
                ("bearing", c.bearing),
            ] {
                assert!(!text.contains(RUN), "{} {what} has a run of spaces", c.id);
                assert!(!text.contains('\n'), "{} {what} has a newline", c.id);
            }
        }
        assert!(!cve_posture().contains(RUN));
    }
}
