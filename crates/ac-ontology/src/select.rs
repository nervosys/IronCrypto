//! Intent-driven algorithm selection.
//!
//! [`Query`] answers "which algorithms match these predicates?".
//! This module answers the question an agent actually has: *"I need to do X
//! under constraints Y — what should I call, and what will bite me?"*
//!
//! The output is a [`Recommendation`] carrying the chosen algorithm, the
//! reasoning, the rejected alternatives with *why* they were rejected, and the
//! constraints the caller must honour. An agent can act on it; a human can
//! audit it.
//!
//! ```
//! use ac_ontology::select::{recommend, Intent, Policy};
//!
//! let r = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
//! assert_eq!(r.primary.id, "aes-256-gcm");
//!
//! let r = recommend(Intent::EncryptMessage, Policy::DEFAULT).unwrap();
//! assert_eq!(r.primary.id, "chacha20-poly1305");
//! ```

use crate::query::Query;
use crate::types::{Class, Constraint, Entry, ImplStatus, Purpose};

/// What the caller is trying to accomplish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Intent {
    /// Encrypt a message so it cannot be read or altered.
    EncryptMessage,
    /// Detect modification of data, with no key involved.
    HashData,
    /// Authenticate a message with a shared key.
    AuthenticateMessage,
    /// Turn a shared secret or master key into application keys.
    DeriveKey,
    /// Turn a user password into a key, or store it for later verification.
    HashPassword,
    /// Establish a shared secret with a remote peer.
    AgreeKey,
    /// Sign data so a third party can verify authorship.
    SignData,
    /// Generate unpredictable bytes.
    GenerateRandom,
}

impl Intent {
    /// Stable identifier used in CLI and MCP output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::EncryptMessage => "encrypt-message",
            Self::HashData => "hash-data",
            Self::AuthenticateMessage => "authenticate-message",
            Self::DeriveKey => "derive-key",
            Self::HashPassword => "hash-password",
            Self::AgreeKey => "agree-key",
            Self::SignData => "sign-data",
            Self::GenerateRandom => "generate-random",
        }
    }

    /// Every intent, for enumeration.
    pub const ALL: &'static [Intent] = &[
        Intent::EncryptMessage,
        Intent::HashData,
        Intent::AuthenticateMessage,
        Intent::DeriveKey,
        Intent::HashPassword,
        Intent::AgreeKey,
        Intent::SignData,
        Intent::GenerateRandom,
    ];

    /// Parse an intent from its identifier.
    pub fn from_id(id: &str) -> Option<Intent> {
        Self::ALL.iter().copied().find(|i| i.id() == id)
    }

    /// The class and purpose this intent maps onto.
    ///
    /// `AgreeKey` deliberately leaves the class open: a Diffie-Hellman scheme
    /// and a KEM are different objects that serve the same goal, and a
    /// post-quantum migration needs the KEM to surface for this intent.
    const fn shape(self) -> (Option<Class>, Purpose) {
        match self {
            Self::EncryptMessage => (Some(Class::Aead), Purpose::Confidentiality),
            Self::HashData => (Some(Class::Hash), Purpose::Integrity),
            Self::AuthenticateMessage => (Some(Class::Mac), Purpose::Authentication),
            Self::DeriveKey => (Some(Class::Kdf), Purpose::KeyDerivation),
            Self::HashPassword => (Some(Class::PasswordKdf), Purpose::PasswordHashing),
            Self::AgreeKey => (None, Purpose::KeyEstablishment),
            Self::SignData => (Some(Class::Signature), Purpose::NonRepudiation),
            Self::GenerateRandom => (Some(Class::Drbg), Purpose::RandomGeneration),
        }
    }
}

/// Deployment constraints that shape the choice.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Only algorithms usable in the FIPS approved mode are acceptable.
    pub require_fips: bool,
    /// Minimum classical security strength in bits.
    pub min_classical_bits: u16,
    /// Minimum quantum security strength in bits; above zero this excludes
    /// every classical asymmetric scheme.
    pub min_quantum_bits: u16,
    /// The target has AES hardware acceleration.
    ///
    /// The portable backend has none, so absent a hardware backend this makes
    /// ChaCha20-Poly1305 the faster choice by a wide margin.
    pub aes_hardware: bool,
}

impl Policy {
    /// Sensible defaults: 128-bit strength, no FIPS requirement, no AES
    /// hardware assumed.
    pub const DEFAULT: Policy = Policy {
        require_fips: false,
        min_classical_bits: 128,
        min_quantum_bits: 0,
        aes_hardware: false,
    };

    /// Everything must be usable in the FIPS approved mode of operation.
    pub const FIPS_APPROVED: Policy = Policy {
        require_fips: true,
        min_classical_bits: 128,
        min_quantum_bits: 0,
        aes_hardware: false,
    };

    /// The default policy, with `aes_hardware` filled in from the CPU.
    ///
    /// Prefer this over [`Policy::DEFAULT`] in a running program: on a machine
    /// with AES-NI it flips the authenticated-encryption recommendation from
    /// ChaCha20-Poly1305 to AES-256-GCM, which is the faster answer there.
    pub fn detected() -> Policy {
        Policy {
            aes_hardware: crate::runtime::backend().fast_bulk_symmetric(),
            ..Policy::DEFAULT
        }
    }

    /// A FIPS policy with `aes_hardware` filled in from the CPU.
    pub fn detected_fips() -> Policy {
        Policy {
            aes_hardware: crate::runtime::backend().fast_bulk_symmetric(),
            ..Policy::FIPS_APPROVED
        }
    }

    /// Resist a future quantum adversary.
    pub const POST_QUANTUM: Policy = Policy {
        require_fips: false,
        min_classical_bits: 128,
        min_quantum_bits: 128,
        aes_hardware: false,
    };
}

impl Default for Policy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An algorithm that was considered and passed over.
#[derive(Debug, Clone, Copy)]
pub struct Rejected {
    /// The algorithm's identifier.
    pub id: &'static str,
    /// Why it was not chosen.
    pub reason: &'static str,
}

/// The result of a selection.
#[derive(Debug, Clone, Copy)]
pub struct Recommendation {
    /// The intent this answers.
    pub intent: Intent,
    /// The recommended algorithm.
    pub primary: &'static Entry,
    /// Why this one.
    pub rationale: &'static str,
    /// A second choice, when one exists.
    pub alternative: Option<&'static Entry>,
    /// Algorithms considered and passed over, with reasons.
    pub rejected: [Option<Rejected>; 3],
    /// The constraints the caller must honour to use `primary` safely.
    pub must_observe: &'static [Constraint],
}

impl Recommendation {
    /// Iterate the rejected candidates.
    pub fn rejected(&self) -> impl Iterator<Item = &Rejected> {
        self.rejected.iter().flatten()
    }
}

/// Why no algorithm could satisfy the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRecommendation {
    /// The registry knows a suitable algorithm, but it is not implemented here.
    KnownButUnavailable {
        /// The algorithm the caller should obtain elsewhere.
        id: &'static str,
    },
    /// Nothing in the registry satisfies the policy at all.
    NothingSatisfiesPolicy,
}

/// Choose an algorithm for `intent` under `policy`.
///
/// Returns [`NoRecommendation::KnownButUnavailable`] rather than silently
/// downgrading when the correct answer exists but this build does not provide
/// it — the failure mode that would otherwise push an agent into using an
/// unapproved algorithm to satisfy a FIPS requirement.
pub fn recommend(intent: Intent, policy: Policy) -> Result<Recommendation, NoRecommendation> {
    let (class, purpose) = intent.shape();

    let base = Query::new().purpose(purpose);
    let base = match class {
        Some(c) => base.class(c),
        None => base,
    };
    let base = base
        .min_classical_bits(policy.min_classical_bits)
        .min_quantum_bits(policy.min_quantum_bits);
    let base = if policy.require_fips {
        base.fips_approved_only()
    } else {
        base
    };

    // Is there a suitable algorithm at all, implemented or not?
    let any_suitable = base.run().next();
    let available = base.available_only().run().next();

    if available.is_none() {
        return match any_suitable {
            Some(e) => Err(NoRecommendation::KnownButUnavailable { id: e.id }),
            None => Err(NoRecommendation::NothingSatisfiesPolicy),
        };
    }

    Ok(build(intent, policy, base))
}

/// Rank the available candidates for an intent.
fn build(intent: Intent, policy: Policy, base: Query) -> Recommendation {
    let pick = |id: &str| crate::query::get(id).filter(|e| base.matches(e));
    let available = |id: &str| pick(id).filter(|e| e.status == ImplStatus::Available);

    let (primary, rationale, alternative, rejected) = match intent {
        Intent::EncryptMessage => {
            // Without AES hardware the portable AES backend is far slower than
            // ChaCha20, so the ranking flips on `aes_hardware` — but a FIPS
            // policy removes ChaCha20 from consideration entirely.
            let chacha = available("chacha20-poly1305");
            let aes = available("aes-256-gcm");
            match (policy.require_fips, policy.aes_hardware, chacha, aes) {
                (false, false, Some(c), a) => (
                    c,
                    "ChaCha20-Poly1305 is authenticated, needs no hardware support, and on a CPU \
                     without AES instructions is far faster than the portable constant-time AES.",
                    a,
                    [
                        Some(Rejected {
                            id: "aes-256-gcm",
                            reason: "Approved and equally secure, but this CPU has no AES \
                                     instructions, so the portable backend is far slower.",
                        }),
                        Some(Rejected {
                            id: "aes-cbc",
                            reason: "Unauthenticated; needs a separate MAC and invites padding \
                                     oracles.",
                        }),
                        None,
                    ],
                ),
                (_, _, c, Some(a)) => (
                    a,
                    "AES-256-GCM is the approved authenticated cipher and retains 128-bit strength \
                     against a quantum adversary.",
                    c,
                    [
                        Some(Rejected {
                            id: "chacha20-poly1305",
                            reason: if policy.require_fips {
                                "Not approved for the FIPS approved mode of operation."
                            } else {
                                "Faster in software, but AES hardware makes AES-GCM the better \
                                 choice."
                            },
                        }),
                        Some(Rejected {
                            id: "aes-ctr",
                            reason: "Unauthenticated; it is the confidentiality half of GCM.",
                        }),
                        None,
                    ],
                ),
                (_, _, Some(c), None) => (c, "The only available authenticated cipher.", None, [None, None, None]),
                _ => unreachable!("recommend() checked that a candidate exists"),
            }
        }
        Intent::HashData => {
            let sha256 = available("sha2-256");
            let sha512 = available("sha2-512");
            let sha3 = available("sha3-256");
            match (sha256, sha512) {
                (Some(a), b) => (
                    a,
                    "SHA-256 is approved, universally interoperable, and fast on every target.",
                    b,
                    [
                        Some(Rejected {
                            id: "sha3-256",
                            reason: "Equally sound; choose it only when algorithm diversity from \
                                     SHA-2 is a requirement.",
                        }),
                        Some(Rejected {
                            id: "sha-1",
                            reason: "Chosen-prefix collisions are practical; disallowed.",
                        }),
                        None,
                    ],
                ),
                (None, Some(b)) => (
                    b,
                    "SHA-512 meets the requested strength.",
                    sha3,
                    [None, None, None],
                ),
                _ => fallback(base),
            }
        }
        Intent::AuthenticateMessage => match available("hmac-sha2-256") {
            Some(a) => (
                a,
                "HMAC-SHA-256 is approved, fast, and the interoperable default.",
                available("hmac-sha2-512"),
                [
                    Some(Rejected {
                        id: "cmac-aes-256",
                        reason:
                            "Approved, but slow here and only preferable with AES hardware and \
                                 no hash accelerator.",
                    }),
                    Some(Rejected {
                        id: "poly1305",
                        reason: "One-time keys only; use the ChaCha20-Poly1305 AEAD instead.",
                    }),
                    None,
                ],
            ),
            None => fallback(base),
        },
        Intent::DeriveKey => match available("hkdf-sha2-256") {
            Some(a) => (
                a,
                "HKDF extracts then expands, so it is correct for non-uniform input such as a \
                 Diffie-Hellman shared secret.",
                available("sp800-108-counter-hmac-sha2-256"),
                [
                    Some(Rejected {
                        id: "sp800-108-counter-hmac-sha2-256",
                        reason:
                            "Preferable when the input is already a uniform key-derivation key.",
                    }),
                    Some(Rejected {
                        id: "pbkdf2-hmac-sha2-256",
                        reason: "For passwords only; needlessly slow for key material.",
                    }),
                    None,
                ],
            ),
            None => fallback(base),
        },
        Intent::HashPassword => {
            let argon2 = available("argon2id");
            let pbkdf2 = available("pbkdf2-hmac-sha2-256");
            match (argon2, pbkdf2) {
                // Outside FIPS, memory-hardness is the whole point: PBKDF2 is
                // attacked far faster on a GPU than it is defended on a CPU.
                (Some(a), p) => (
                    a,
                    "Argon2id is memory-hard, so an attacker must spend RAM as well as time. Its \
                     first half-pass indexes data-independently and the rest data-dependently, \
                     which is why RFC 9106 recommends it over the other two variants.",
                    p,
                    [
                        Some(Rejected {
                            id: "pbkdf2-hmac-sha2-256",
                            reason: "Approved, but not memory-hard: choose it only when FIPS \
                                     approval is a requirement.",
                        }),
                        Some(Rejected {
                            id: "sha2-256",
                            reason: "A bare hash is far too fast to protect a password.",
                        }),
                        None,
                    ],
                ),
                (None, Some(p)) => (
                    p,
                    "PBKDF2 is the only approved password-based KDF. Use at least 600000 \
                     iterations and a fresh 128-bit salt; it is not memory-hard, so the iteration \
                     count is the only lever you have.",
                    None,
                    [
                        Some(Rejected {
                            id: "argon2id",
                            reason: "Memory-hard and stronger, but not approved for the FIPS \
                                     approved mode of operation.",
                        }),
                        Some(Rejected {
                            id: "sha2-256",
                            reason: "A bare hash is far too fast to protect a password.",
                        }),
                        None,
                    ],
                ),
                _ => fallback(base),
            }
        }
        Intent::AgreeKey => {
            let x25519 = available("x25519");
            let p256 = available("ecdh-p256");
            match (x25519, p256) {
                // Outside a FIPS policy, X25519 is the safer default: no point
                // validation to get wrong, and no invalid-curve attack surface.
                (Some(x), p) => (
                    x,
                    "X25519 is fast and hard to misuse. Run the shared secret through HKDF \
                     together with both public keys before using it.",
                    p,
                    [
                        Some(Rejected {
                            id: "ecdh-p256",
                            reason: "Approved and implemented here, but it needs peer-key \
                                     validation that X25519 does not.",
                        }),
                        Some(Rejected {
                            id: "ml-kem-768",
                            reason: "Post-quantum, but not implemented in this build.",
                        }),
                        None,
                    ],
                ),
                (None, Some(p)) => (
                    p,
                    "ECDH P-256 is the approved key agreement scheme. Peer public keys are \
                     validated against the curve equation, and the shared secret must go through \
                     a KDF before use.",
                    None,
                    [
                        Some(Rejected {
                            id: "x25519",
                            reason: "Not approved for the FIPS approved mode of operation.",
                        }),
                        Some(Rejected {
                            id: "ml-kem-768",
                            reason: "Post-quantum, but not implemented in this build.",
                        }),
                        None,
                    ],
                ),
                _ => fallback(base),
            }
        }
        Intent::SignData => {
            let ed = available("ed25519");
            let ecdsa = available("ecdsa-p256-sha256");
            match (ed, ecdsa) {
                (Some(e), other) => (
                    e,
                    "Ed25519 signs deterministically, so there is no nonce to leak or repeat, and \
                     it has no point-validation step to get wrong.",
                    other,
                    [
                        Some(Rejected {
                            id: "ecdsa-p256-sha256",
                            reason: "Approved and implemented here; choose it when you need FIPS \
                                     approval or interoperability with X.509 and TLS.",
                        }),
                        Some(Rejected {
                            id: "ml-dsa-65",
                            reason: "Post-quantum, but not implemented in this build.",
                        }),
                        None,
                    ],
                ),
                (None, Some(p)) => (
                    p,
                    "ECDSA P-256 is the approved signature scheme. This implementation derives \
                     its nonce per RFC 6979, so the usual ECDSA nonce-reuse failure cannot occur.",
                    None,
                    [
                        Some(Rejected {
                            id: "ed25519",
                            reason: "Not approved for the FIPS approved mode of operation.",
                        }),
                        Some(Rejected {
                            id: "ml-dsa-65",
                            reason: "Post-quantum, but not implemented in this build.",
                        }),
                        None,
                    ],
                ),
                _ => fallback(base),
            }
        }
        Intent::GenerateRandom => match available("hmac-drbg-sha2-256") {
            Some(a) => (
                a,
                "HMAC_DRBG conditions its own entropy input. Reach for it through ac_drbg::Rng, \
                 which seeds from the OS and reseeds on schedule.",
                available("ctr-drbg-aes-256"),
                [
                    Some(Rejected {
                        id: "ctr-drbg-aes-256",
                        reason: "Requires exactly 48 bytes of already-uniform entropy.",
                    }),
                    None,
                    None,
                ],
            ),
            None => fallback(base),
        },
    };

    Recommendation {
        intent,
        primary,
        rationale,
        alternative,
        rejected,
        must_observe: primary.constraints,
    }
}

/// Fall back to the first matching entry when the curated ranking has nothing
/// to say — for example under an unusual strength floor.
fn fallback(
    base: Query,
) -> (
    &'static Entry,
    &'static str,
    Option<&'static Entry>,
    [Option<Rejected>; 3],
) {
    let mut it = base.available_only().run();
    let primary = it
        .next()
        .expect("recommend() checked that a candidate exists");
    (
        primary,
        "The only available algorithm matching the requested class and strength.",
        it.next(),
        [None, None, None],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_policy_selects_aes_gcm_over_chacha() {
        let r = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
        assert_eq!(r.primary.id, "aes-256-gcm");
        assert!(r
            .rejected()
            .any(|x| x.id == "chacha20-poly1305" && x.reason.contains("approved mode")));
    }

    #[test]
    fn without_aes_hardware_chacha_wins() {
        let r = recommend(Intent::EncryptMessage, Policy::DEFAULT).unwrap();
        assert_eq!(r.primary.id, "chacha20-poly1305");
        assert_eq!(r.alternative.map(|e| e.id), Some("aes-256-gcm"));
    }

    #[test]
    fn with_aes_hardware_the_ranking_flips() {
        let policy = Policy {
            aes_hardware: true,
            ..Policy::DEFAULT
        };
        let r = recommend(Intent::EncryptMessage, policy).unwrap();
        assert_eq!(r.primary.id, "aes-256-gcm");
    }

    #[test]
    fn recommendations_carry_the_constraints_that_matter() {
        let r = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
        assert!(r
            .must_observe
            .iter()
            .any(|c| c.id == "unique-nonce-per-key"));
    }

    #[test]
    fn fips_policy_never_substitutes_an_unapproved_scheme() {
        // Ed25519 and X25519 are available but unapproved; the approved
        // alternatives must be chosen, never the convenient ones.
        let r = recommend(Intent::SignData, Policy::FIPS_APPROVED).unwrap();
        assert_eq!(r.primary.id, "ecdsa-p256-sha256");
        assert!(r
            .rejected()
            .any(|x| x.id == "ed25519" && x.reason.contains("approved mode")));

        let r = recommend(Intent::AgreeKey, Policy::FIPS_APPROVED).unwrap();
        assert_eq!(r.primary.id, "ecdh-p256");
        assert!(r
            .rejected()
            .any(|x| x.id == "x25519" && x.reason.contains("approved mode")));
    }

    /// Outside a FIPS policy the Curve25519 options stay the default, with the
    /// approved alternatives offered rather than hidden.
    #[test]
    fn default_policy_prefers_curve25519_but_offers_the_approved_option() {
        let r = recommend(Intent::SignData, Policy::DEFAULT).unwrap();
        assert_eq!(r.primary.id, "ed25519");
        assert_eq!(r.alternative.map(|e| e.id), Some("ecdsa-p256-sha256"));

        let r = recommend(Intent::AgreeKey, Policy::DEFAULT).unwrap();
        assert_eq!(r.primary.id, "x25519");
        assert_eq!(r.alternative.map(|e| e.id), Some("ecdh-p256"));
    }

    /// The "honest no" path still exists for algorithms genuinely absent.
    #[test]
    fn unavailable_schemes_are_reported_not_substituted() {
        let err = recommend(Intent::AgreeKey, Policy::POST_QUANTUM).unwrap_err();
        assert_eq!(
            err,
            NoRecommendation::KnownButUnavailable { id: "ml-kem-768" }
        );

        let err = recommend(Intent::SignData, Policy::POST_QUANTUM).unwrap_err();
        assert_eq!(
            err,
            NoRecommendation::KnownButUnavailable { id: "ml-dsa-65" }
        );
    }

    #[test]
    fn post_quantum_policy_reports_what_is_missing() {
        let err = recommend(Intent::AgreeKey, Policy::POST_QUANTUM).unwrap_err();
        assert_eq!(
            err,
            NoRecommendation::KnownButUnavailable { id: "ml-kem-768" }
        );
    }

    #[test]
    fn symmetric_intents_survive_a_post_quantum_policy() {
        let r = recommend(Intent::EncryptMessage, Policy::POST_QUANTUM).unwrap();
        assert_eq!(r.primary.strength.quantum, 128);
    }

    #[test]
    fn every_intent_resolves_under_the_default_policy() {
        for intent in Intent::ALL {
            let outcome = recommend(*intent, Policy::DEFAULT);
            assert!(
                outcome.is_ok(),
                "{} produced no recommendation: {:?}",
                intent.id(),
                outcome.err()
            );
        }
    }

    #[test]
    fn recommended_algorithms_are_always_actually_available() {
        for intent in Intent::ALL {
            for policy in [Policy::DEFAULT, Policy::FIPS_APPROVED, Policy::POST_QUANTUM] {
                if let Ok(r) = recommend(*intent, policy) {
                    assert_eq!(r.primary.status, ImplStatus::Available, "{}", intent.id());
                    assert!(!r.primary.rust_path.is_empty());
                    if policy.require_fips {
                        assert!(
                            r.primary.fips.permitted_in_approved_mode(),
                            "{} recommended an unapproved algorithm under a FIPS policy",
                            intent.id()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn intent_ids_roundtrip() {
        for i in Intent::ALL {
            assert_eq!(Intent::from_id(i.id()), Some(*i));
        }
    }

    /// Outside FIPS the memory-hard option wins; under FIPS the approved one
    /// does, and each names the other as the road not taken.
    #[test]
    fn password_hashing_tracks_the_policy() {
        let r = recommend(Intent::HashPassword, Policy::DEFAULT).unwrap();
        assert_eq!(r.primary.id, "argon2id");
        assert_eq!(r.alternative.map(|e| e.id), Some("pbkdf2-hmac-sha2-256"));
        assert!(r
            .rejected()
            .any(|x| x.id == "pbkdf2-hmac-sha2-256" && x.reason.contains("memory-hard")));

        let r = recommend(Intent::HashPassword, Policy::FIPS_APPROVED).unwrap();
        assert_eq!(r.primary.id, "pbkdf2-hmac-sha2-256");
        assert!(r
            .rejected()
            .any(|x| x.id == "argon2id" && x.reason.contains("approved mode")));
    }
}
