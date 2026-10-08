//! Named algorithm suites: what a profile permits, and nothing else.
//!
//! [`crate::select::Policy`] chooses by thresholds -- a strength floor, a FIPS
//! requirement. Some rules are not thresholds. CNSA 2.0 does not say "at least
//! 192 bits"; it names algorithms, and an algorithm of equal strength that it
//! does not name is not in it. A profile here is that list, each member with
//! the role the profile gives it, tied to registry entries so that it cannot
//! name something this library does not describe.
//!
//! # CNSA 2.0
//!
//! The list is taken from the NSA-authored IETF drafts that profile CNSA 2.0
//! for protocols, read on 2026-10-08:
//! `draft-jenkins-cnsa2-pkix-profile-05` section 3 --
//!
//! > NSA has selected two: ML-DSA-87 \[FIPS204\] for signing and ML-KEM-1024
//! > \[FIPS203\] for key establishment. With SHA-384 (preferred, or
//! > alternatively SHA-512), AES-256, and LMS/XMSS, these comprise the CNSA
//! > Suite 2.0.
//!
//! -- and `draft-becker-cnsa2-tls-profile-05` section 4, which names AES-256
//! in GCM and SHA-384 for HKDF. NSA's own advisory and FAQ were not read: its
//! site refuses automated retrieval. So this records the suite's algorithms
//! and none of its transition dates, which those drafts do not give.
//!
//! Being in the list is not being fit for a national security system.
//! IronCrypto is not CMVP validated and is not an NSA-approved product; the
//! profile says which algorithms a CNSA 2.0 design uses, so that code written
//! here chooses them.

use crate::query::get;
use crate::select::Intent;
use crate::types::{Entry, ImplStatus};

/// One algorithm a profile permits.
#[derive(Debug, Clone, Copy)]
pub struct Member {
    /// The registry identifier.
    pub id: &'static str,
    /// What the profile uses it for.
    pub role: &'static str,
    /// Anything the profile says about how.
    pub note: &'static str,
}

/// A named suite of algorithms.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    /// Stable identifier, e.g. `cnsa-2.0`.
    pub id: &'static str,
    /// The profile's name.
    pub name: &'static str,
    /// What it is and who sets it.
    pub summary: &'static str,
    /// Where the list was taken from, and when.
    pub source: &'static str,
    /// The algorithms it permits.
    pub members: &'static [Member],
    /// What the profile leaves out that a caller might expect, and why.
    pub exclusions: &'static str,
}

impl Profile {
    /// Whether the profile permits the algorithm with this registry id.
    #[must_use = "whether the algorithm is in the profile; discarding it enforces nothing"]
    pub fn permits(&self, id: &str) -> bool {
        self.members.iter().any(|m| m.id == id)
    }

    /// The profile's members as registry entries.
    pub fn entries(&self) -> impl Iterator<Item = (&'static Member, &'static Entry)> + '_ {
        self.members
            .iter()
            .filter_map(|m| get(m.id).map(|entry| (m, entry)))
    }

    /// The profile's algorithm for an intent that this build implements, if
    /// the profile names one.
    ///
    /// `None` is an answer: the profile does not cover that intent, and a
    /// caller under the profile should not reach for something else that
    /// happens to be approved.
    pub fn choose(&self, intent: Intent) -> Option<&'static Entry> {
        let id = match (self.id, intent) {
            ("cnsa-2.0", Intent::EncryptMessage) => "aes-256-gcm",
            ("cnsa-2.0", Intent::HashData) => "sha2-384",
            ("cnsa-2.0", Intent::AuthenticateMessage) => "hmac-sha2-384",
            ("cnsa-2.0", Intent::DeriveKey) => "hkdf-sha2-384",
            ("cnsa-2.0", Intent::AgreeKey) => "ml-kem-1024",
            ("cnsa-2.0", Intent::SignData) => "ml-dsa-87",
            _ => return None,
        };
        get(id).filter(|e| self.permits(e.id) && e.status == ImplStatus::Available)
    }
}

/// The Commercial National Security Algorithm Suite 2.0.
pub const CNSA_2_0: Profile = Profile {
    id: "cnsa-2.0",
    name: "Commercial National Security Algorithm Suite 2.0",
    summary: "The algorithms NSA selects for protecting US national security systems against \
              an adversary with a quantum computer: ML-KEM-1024, ML-DSA-87, AES-256, SHA-384 \
              or SHA-512, and the stateful hash-based signatures LMS and XMSS.",
    source: "draft-jenkins-cnsa2-pkix-profile-05 section 3 and \
             draft-becker-cnsa2-tls-profile-05 sections 3 and 4, both NSA-authored, read on \
             2026-10-08. NSA's advisory and FAQ were not read; no transition date is recorded.",
    members: &[
        Member {
            id: "ml-kem-1024",
            role: "key establishment",
            note: "The only key-establishment algorithm in the suite.",
        },
        Member {
            id: "ml-dsa-87",
            role: "digital signature",
            note: "Pure ML-DSA; the TLS profile does not permit HashML-DSA.",
        },
        Member {
            id: "aes-256-gcm",
            role: "authenticated encryption",
            note: "AES with 256-bit keys; the TLS profile names GCM.",
        },
        Member {
            id: "aes-256",
            role: "block cipher",
            note: "The cipher itself, for the modes built on it.",
        },
        Member {
            id: "sha2-384",
            role: "hashing",
            note: "Preferred.",
        },
        Member {
            id: "sha2-512",
            role: "hashing",
            note: "The permitted alternative to SHA-384.",
        },
        Member {
            id: "hmac-sha2-384",
            role: "message authentication",
            note: "Not named by the drafts read; it is HMAC over the suite's preferred hash.",
        },
        Member {
            id: "hkdf-sha2-384",
            role: "key derivation",
            note: "The TLS profile requires SHA-384 for HKDF.",
        },
        Member {
            id: "hss-lms",
            role: "firmware and software signature verification",
            note: "Verification only here; signing belongs in hardware.",
        },
        Member {
            id: "xmss",
            role: "firmware and software signature verification",
            note: "In the suite and not implemented by this library.",
        },
    ],
    exclusions: "Nothing classical is in it: no RSA, no ECDSA or ECDH on any curve, no Ed25519 \
                 or X25519, and so no HPKE suite here, each of which rests on one of them. No \
                 ML-KEM or ML-DSA parameter set below the largest. No SHA-256 or SHA-3 as a \
                 general-purpose hash -- LMS and XMSS use SHA-256 or SHAKE256 inside them, \
                 which is theirs to do -- and no ChaCha20-Poly1305. It names no password hash \
                 and no random bit generator, so the profile has no answer for those intents.",
};

/// Every profile.
pub const PROFILES: &[Profile] = &[CNSA_2_0];

/// Look a profile up by its identifier.
pub fn profile(id: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FipsStatus;

    /// A profile cannot name something the registry does not describe, and
    /// everything CNSA 2.0 names is a FIPS-approved algorithm.
    #[test]
    fn every_member_is_a_registry_entry_and_approved() {
        for p in PROFILES {
            assert_eq!(p.entries().count(), p.members.len(), "{}", p.id);
            for (m, e) in p.entries() {
                assert!(!m.role.is_empty() && !m.note.is_empty(), "{}", m.id);
                assert!(
                    matches!(
                        e.fips,
                        FipsStatus::Approved | FipsStatus::AllowedAsComponent
                    ),
                    "{} is in {} and is not approved",
                    e.id,
                    p.id
                );
            }
        }
    }

    /// The suite as the drafts state it: these and no others of their kind.
    #[test]
    fn cnsa_2_0_permits_what_it_names_and_nothing_classical() {
        let p = profile("CNSA-2.0").unwrap();
        for id in [
            "ml-kem-1024",
            "ml-dsa-87",
            "aes-256-gcm",
            "sha2-384",
            "sha2-512",
            "hss-lms",
            "xmss",
        ] {
            assert!(p.permits(id), "{id}");
        }
        for id in [
            "ml-kem-768",
            "ml-dsa-65",
            "ecdsa-p384-sha384",
            "ecdh-p384",
            "rsa-pss-sha384",
            "ed25519",
            "x25519",
            "aes-128-gcm",
            "sha2-256",
            "sha3-384",
            "chacha20-poly1305",
            "hpke-p384-sha384",
        ] {
            assert!(!p.permits(id), "{id} must not be in CNSA 2.0");
        }
    }

    #[test]
    fn choose_answers_from_the_suite_or_not_at_all() {
        let p = &CNSA_2_0;
        let chosen = |i| p.choose(i).map(|e| e.id);
        assert_eq!(chosen(Intent::EncryptMessage), Some("aes-256-gcm"));
        assert_eq!(chosen(Intent::HashData), Some("sha2-384"));
        assert_eq!(chosen(Intent::AuthenticateMessage), Some("hmac-sha2-384"));
        assert_eq!(chosen(Intent::DeriveKey), Some("hkdf-sha2-384"));
        assert_eq!(chosen(Intent::AgreeKey), Some("ml-kem-1024"));
        assert_eq!(chosen(Intent::SignData), Some("ml-dsa-87"));
        // The suite names neither, so the profile does not answer.
        assert_eq!(chosen(Intent::HashPassword), None);
        assert_eq!(chosen(Intent::GenerateRandom), None);
    }

    /// The claim this module must never make.
    #[test]
    fn the_profile_does_not_claim_fitness() {
        for p in PROFILES {
            for text in [p.summary, p.source, p.exclusions] {
                let lower = text.to_ascii_lowercase();
                assert!(
                    !lower.contains("validated") || lower.contains("not"),
                    "{}",
                    p.id
                );
                assert!(!lower.contains("nsa-approved product"), "{}", p.id);
            }
        }
    }
}
