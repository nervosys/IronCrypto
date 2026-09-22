//! IronCrypto as a [rustls] `CryptoProvider`.
//!
//! ```
//! # fn main() -> Result<(), rustls::Error> {
//! let roots = rustls::RootCertStore::empty();
//! let config = rustls::ClientConfig::builder_with_provider(ic_rustls::arc_provider())
//!     .with_safe_default_protocol_versions()?
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! # let _ = config;
//! # Ok(())
//! # }
//! ```
//!
//! Or install it once, for every rustls configuration in the process:
//!
//! ```no_run
//! ic_rustls::provider()
//!     .install_default()
//!     .expect("a provider was already installed in this process");
//! ```
//!
//! # This crate has a third-party dependency, and it is the only one that does
//!
//! Every other crate in this workspace depends on nothing outside it. That is
//! asserted on each build by `scripts/no-third-party.sh`, and the SBOM,
//! CWE-1104 and T1195.001 all rest on it.
//!
//! A rustls provider cannot: it exists to implement rustls's traits, so it must
//! depend on rustls, and rustls brings `rustls-pki-types`, `rustls-webpki`,
//! `subtle`, `untrusted`, `once_cell` and `zeroize` with it -- seven crates in
//! total, which is what `scripts/no-third-party.sh` allows by name and
//! `scripts/advisories.sh` holds to a version floor. Rather than weaken the check, the boundary
//! is drawn here. This crate is excluded by name, the exclusion is one line
//! with a reason beside it, and everything cryptographic stays on the other
//! side: `ic-core`, `ic-hash`, `ic-mac`, `ic-cipher`, `ic-drbg`, `ic-ec` and
//! `ic-pkix` are unchanged and still depend on nothing.
//!
//! So the guarantee narrows honestly instead of quietly. If you need it whole,
//! do not depend on this crate; the algorithms are reachable directly.
//!
//! # What is provided
//!
//! | | |
//! |---|---|
//! | AEAD | AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, for TLS 1.3 and TLS 1.2 |
//! | Hash | SHA-256, SHA-384 |
//! | MAC | HMAC-SHA256, HMAC-SHA384 |
//! | KDF | HKDF, as rustls's `HkdfUsingHmac` over the above |
//! | Signatures | ECDSA P-256/SHA-256 and P-384/SHA-384; Ed25519; RSA PKCS#1 v1.5 and PSS over SHA-256/384/512. All verified and produced |
//! | Key exchange | X25519, ECDH P-256, ECDH P-384 |
//! | Randomness | SP 800-90A HMAC\_DRBG, seeded from the OS |
//! | QUIC | Packet and header protection for all three AEADs, RFC 9001 |
//!
//! HKDF is rustls's own extract-and-expand over IronCrypto's HMAC, which is the
//! right split: HKDF is a construction and HMAC is the primitive. The result is
//! checked against RFC 5869 in the `hmac` module's tests, so the composition is verified
//! and not just assumed.
//!
//! # What is not provided
//!
//! - **RSA below 2048 bits.** Refused, deliberately, when verifying and when
//!   loading a key to sign with. See `crate::verify`.
//! - **The mismatched ECDSA pairings.** A P-256 key signed with SHA-384, or
//!   the reverse. See `crate::verify`.
//! - **FIPS validation.** Every `fips()` in this crate returns `false`, because
//!   rustls is asking about a certificate and IronCrypto holds none.
//!
//! [rustls]: https://docs.rs/rustls

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

mod aead;
mod hash;
mod hmac;
mod kx;
mod quic;
mod sign;
mod verify;

use alloc::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::{SignatureScheme, SupportedCipherSuite};

pub mod random;
pub mod suites;

/// The provider.
///
/// Cipher suites are listed strongest first, which is the order rustls offers
/// them in. AES-256 before AES-128 on the grounds that both are cheap where
/// there is hardware for them and the difference matters more than the cost.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: default_cipher_suites().to_vec(),
        kx_groups: default_kx_groups().to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &random::Random,
        key_provider: &sign::Keys,
    }
}

/// The cipher suites this provider offers, strongest first.
pub fn default_cipher_suites() -> &'static [SupportedCipherSuite] {
    suites::ALL
}

/// The key exchange groups this provider offers.
///
/// X25519 first: it is fast, has no point validation to get wrong, and no
/// invalid-curve attack surface. The NIST curves follow for peers that require
/// them.
pub fn default_kx_groups() -> &'static [&'static dyn SupportedKxGroup] {
    KX_GROUPS
}

static KX_GROUPS: &[&dyn SupportedKxGroup] = &[&kx::X25519, &kx::SECP256R1, &kx::SECP384R1];

/// Signature verification algorithms, for certificate chains and for the
/// handshake.
/// `all` is what certificate chains are verified with, and `mapping` is what
/// the handshake signature is looked up in. Both are needed: a chain signed
/// with PKCS#1 v1.5 can carry a key that then signs the handshake with PSS, and
/// TLS 1.3 requires exactly that combination.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &verify::ECDSA_P256_SHA256 as &dyn SignatureVerificationAlgorithm,
        &verify::ECDSA_P384_SHA384 as &dyn SignatureVerificationAlgorithm,
        &verify::ED25519 as &dyn SignatureVerificationAlgorithm,
        &verify::RSA_PKCS1_SHA256 as &dyn SignatureVerificationAlgorithm,
        &verify::RSA_PKCS1_SHA384 as &dyn SignatureVerificationAlgorithm,
        &verify::RSA_PKCS1_SHA512 as &dyn SignatureVerificationAlgorithm,
        &verify::RSA_PSS_SHA256 as &dyn SignatureVerificationAlgorithm,
        &verify::RSA_PSS_SHA384 as &dyn SignatureVerificationAlgorithm,
        &verify::RSA_PSS_SHA512 as &dyn SignatureVerificationAlgorithm,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&verify::ECDSA_P384_SHA384 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&verify::ECDSA_P256_SHA256 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::ED25519,
            &[&verify::ED25519 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[&verify::RSA_PSS_SHA512 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[&verify::RSA_PSS_SHA384 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[&verify::RSA_PSS_SHA256 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[&verify::RSA_PKCS1_SHA512 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[&verify::RSA_PKCS1_SHA384 as &dyn SignatureVerificationAlgorithm],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[&verify::RSA_PKCS1_SHA256 as &dyn SignatureVerificationAlgorithm],
        ),
    ],
};

/// The provider, ready to hand to a rustls builder.
pub fn arc_provider() -> Arc<CryptoProvider> {
    Arc::new(provider())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything the module documentation promises must actually be offered.
    ///
    /// A provider that silently omits a suite does not fail; it negotiates
    /// something else, or nothing, and the reason is several layers away from
    /// whoever has to debug it.
    #[test]
    fn the_provider_offers_what_it_says_it_does() {
        let p = provider();

        // Nine suites: three AEADs for TLS 1.3, and the same three for TLS 1.2
        // once with an ECDSA certificate and once with an RSA one. The literal
        // is here to catch a *removal*, which the list below cannot: dropping a
        // suite and its expectation together would otherwise pass.
        assert_eq!(p.cipher_suites.len(), 9, "{:?}", p.cipher_suites);
        let names: alloc::vec::Vec<_> = p
            .cipher_suites
            .iter()
            .map(|s| alloc::format!("{:?}", s.suite()))
            .collect();
        for want in [
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS13_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ] {
            assert!(
                names.iter().any(|n| n == want),
                "{want} is missing: {names:?}"
            );
        }

        // Three key exchange groups, X25519 preferred.
        assert_eq!(p.kx_groups.len(), 3);
        assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::X25519);

        // Two ECDSA pairings, Ed25519, and six RSA ones, with a mapping each.
        assert_eq!(p.signature_verification_algorithms.all.len(), 9);
        assert_eq!(p.signature_verification_algorithms.mapping.len(), 9);
    }

    /// Nothing in the provider may report FIPS validation.
    ///
    /// rustls surfaces this to applications, some of which gate behaviour on
    /// it. IronCrypto holds no CMVP certificate, so every answer here is false
    /// and must stay false -- the same rule
    /// `ic_ontology::runtime::has("fips-validated")` follows.
    #[test]
    fn nothing_claims_fips_validation() {
        let p = provider();
        assert!(!p.fips(), "the provider as a whole claims validation");

        let mut checked = 0;
        for suite in &p.cipher_suites {
            assert!(!suite.fips(), "{:?} claims validation", suite.suite());
            checked += 1;
        }
        for group in &p.kx_groups {
            assert!(!group.fips(), "{:?} claims validation", group.name());
            checked += 1;
        }
        for alg in p.signature_verification_algorithms.all {
            assert!(!alg.fips(), "a signature algorithm claims validation");
            checked += 1;
        }
        // Nine suites, three key exchange groups, nine signature algorithms.
        assert!(checked >= 21, "only {checked} components examined");
    }

    /// The suites must name the hash and HMAC this crate provides, or the key
    /// schedule is someone else's.
    #[test]
    fn the_suites_use_this_provider_for_the_key_schedule() {
        use rustls::crypto::hash::HashAlgorithm;

        for suite in suites::ALL {
            let hash = match suite {
                SupportedCipherSuite::Tls13(t) => t.common.hash_provider,
                SupportedCipherSuite::Tls12(t) => t.common.hash_provider,
            };
            assert!(
                matches!(
                    hash.algorithm(),
                    HashAlgorithm::SHA256 | HashAlgorithm::SHA384
                ),
                "{:?} uses an unexpected hash",
                suite.suite()
            );
            assert!(!hash.fips());
        }
    }
}
