//! The rules that hold for every algorithm, as data.
//!
//! The registry's constraints belong to entries: GCM's nonce rule is on GCM.
//! These are the rules that hold whichever entry is chosen, and that an agent
//! writing code against this library needs before it writes the first call.
//!
//! They lived in the repository's `AGENTS.md`, which is not in any published
//! package, so an agent that found this library on crates.io never saw them.
//! Here they ship with every build: the MCP server sends them when a client
//! connects, `ic rules` prints them, and the `ironcrypto` documentation lists
//! them. A test in `ironcrypto` fails if `AGENTS.md` or that documentation
//! drifts from this list.

use crate::types::Severity;

/// A rule that holds whichever algorithm is chosen.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Stable identifier.
    pub id: &'static str,
    /// The rule, as one imperative sentence.
    pub rule: &'static str,
    /// What breaks if it is not followed.
    pub why: &'static str,
    /// What to call instead, by Rust path, CLI command or MCP tool.
    pub instead: &'static str,
    /// How much it matters, on the registry's scale.
    pub severity: Severity,
}

/// Every rule, most severe first.
pub const RULES: &[Rule] = &[
    Rule {
        id: "no-nonce-reuse",
        rule: "Never reuse a (key, nonce) pair.",
        why: "Under GCM a repeated nonce leaks the authentication subkey and allows forgery; \
              under ChaCha20-Poly1305 it XORs the two plaintexts.",
        instead: "ic_cipher::Sealer chooses each nonce and ic_cipher::Opener refuses replays. \
                  Through MCP, omit crypto_seal's nonce and one is drawn.",
        severity: Severity::Critical,
    },
    Rule {
        id: "no-unauthenticated-mode",
        rule: "Never use an unauthenticated mode alone.",
        why: "CBC and CTR ciphertexts are malleable and expose padding and chosen-ciphertext \
              oracles.",
        instead: "An AEAD: ic_cipher::Aes256Gcm through ic_cipher::Sealer.",
        severity: Severity::Critical,
    },
    Rule {
        id: "no-tag-equality",
        rule: "Never compare tags or MACs with ==.",
        why: "An early-exit comparison reveals how many leading bytes matched, which lets a \
              forger find a valid tag a byte at a time.",
        instead: "ic_core::ct::verify, or the Mac and Aead verify and open methods.",
        severity: Severity::Critical,
    },
    Rule {
        id: "no-plain-password-hash",
        rule: "Never hash a password with a plain hash.",
        why: "A fast hash lets an attacker who has the hash try billions of guesses per second.",
        instead: "ic_kdf::pbkdf2 with at least 600000 iterations and 16 bytes of fresh salt, \
                  or Argon2id.",
        severity: Severity::Critical,
    },
    Rule {
        id: "no-raw-os-bytes",
        rule: "Never use raw OS bytes as key material.",
        why: "OS entropy is the input to an approved DRBG, not a replacement for one; reading \
              it directly skips the SP 800-90A generator and the self-tests that guard it.",
        instead: "ic_drbg::Rng::from_os(), or crypto_random through MCP.",
        severity: Severity::Serious,
    },
    Rule {
        id: "no-raw-shared-secret",
        rule: "Never use a raw X25519 or ECDH shared secret as a key.",
        why: "The shared secret is not uniformly random and is not bound to who agreed it.",
        instead: "HKDF over the shared secret, with both public keys in info; or ic_hpke, which \
                  does this.",
        severity: Severity::Serious,
    },
    Rule {
        id: "wrap-secrets",
        rule: "Wrap secrets in Zeroizing.",
        why: "A key left in freed memory outlives its use and can be read back from a crash \
              dump, swap or a later allocation.",
        instead: "ic_core::Zeroizing around keys, derived keys and shared secrets.",
        severity: Severity::Advisory,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_every_field_is_filled() {
        for (i, r) in RULES.iter().enumerate() {
            assert!(
                !r.rule.is_empty() && !r.why.is_empty() && !r.instead.is_empty(),
                "{}",
                r.id
            );
            assert!(
                RULES[..i].iter().all(|o| o.id != r.id),
                "duplicate {}",
                r.id
            );
        }
    }

    #[test]
    fn most_severe_first() {
        let rank = |s: Severity| match s {
            Severity::Critical => 0,
            Severity::Serious => 1,
            Severity::Advisory => 2,
        };
        assert!(RULES
            .windows(2)
            .all(|w| rank(w[0].severity) <= rank(w[1].severity)));
    }
}
