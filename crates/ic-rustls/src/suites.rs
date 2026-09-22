//! The cipher suites, assembled from the pieces in the other modules.

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{CipherSuiteCommon, KeyExchangeAlgorithm};
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite};

use crate::{aead, hash, hmac, quic};

/// Every suite this provider offers, strongest first.
pub static ALL: &[SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// TLS 1.3 with AES-256-GCM and SHA-384.
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            // RFC 8446 appendix B.4 and the AEAD limits draft: the number of
            // records that may be protected under one key before rekeying.
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::SHA384),
        aead_alg: &aead::TLS13_AES_256_GCM,
        quic: Some(&quic::AES_256_GCM),
    });

/// TLS 1.3 with AES-128-GCM and SHA-256.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::SHA256),
        aead_alg: &aead::TLS13_AES_128_GCM,
        quic: Some(&quic::AES_128_GCM),
    });

/// TLS 1.3 with ChaCha20-Poly1305 and SHA-256.
///
/// Listed after the AES suites rather than before because most hardware this
/// runs on has AES instructions, where AES-GCM is faster. On hardware without
/// them the position in this list is what stops the connection failing
/// outright, which is the case for offering it at all.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            // No limit. ChaCha20-Poly1305 is not a block cipher and has no
            // birthday bound on the ciphertext to respect, so the CFRG AEAD
            // limits draft section 5.2.1 sets no confidentiality limit for it;
            // rustls spells that u64::MAX, and its own provider does the same.
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::SHA256),
        aead_alg: &aead::TLS13_CHACHA20_POLY1305,
        quic: Some(&quic::CHACHA20_POLY1305),
    });

/// TLS 1.2 with ECDHE, ECDSA, AES-256-GCM and SHA-384.
///
/// ECDSA only: this provider verifies ECDSA signatures and not RSA ones, so
/// offering an RSA suite would advertise something it cannot complete.
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: 1 << 23,
        },
        prf_provider: &PrfUsingHmac(&hmac::SHA384),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &aead::TLS12_AES_256_GCM,
    });

/// TLS 1.2 with ECDHE, ECDSA, AES-128-GCM and SHA-256.
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 23,
        },
        prf_provider: &PrfUsingHmac(&hmac::SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &aead::TLS12_AES_128_GCM,
    });

/// TLS 1.2 with ECDHE, ECDSA, ChaCha20-Poly1305 and SHA-256.
///
/// RFC 7905. Note that this one is not framed like the AES-GCM suites above --
/// it sends no explicit nonce -- which `aead` handles and tests.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &PrfUsingHmac(&hmac::SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &aead::TLS12_CHACHA20_POLY1305,
    });

/// TLS 1.2 with ECDHE, RSA, AES-256-GCM and SHA-384.
///
/// The RSA suites exist because most certificate chains on the public web are
/// RSA. Without them the TLS 1.2 half of this provider can only talk to a
/// server holding an ECDSA certificate, which is a minority of them.
///
/// They are listed after the ECDSA suites: where a server offers both, ECDSA is
/// faster and smaller, and the order here is the order rustls proposes.
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: 1 << 23,
        },
        prf_provider: &PrfUsingHmac(&hmac::SHA384),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &aead::TLS12_AES_256_GCM,
    });

/// TLS 1.2 with ECDHE, RSA, AES-128-GCM and SHA-256.
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: 1 << 23,
        },
        prf_provider: &PrfUsingHmac(&hmac::SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &aead::TLS12_AES_128_GCM,
    });

/// TLS 1.2 with ECDHE, RSA, ChaCha20-Poly1305 and SHA-256.
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &PrfUsingHmac(&hmac::SHA256),
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &aead::TLS12_CHACHA20_POLY1305,
    });

/// The signature schemes a TLS 1.2 ECDSA suite may use.
///
/// These are exactly the pairings [`crate::verify`] implements. Listing one
/// that is not verifiable would let a handshake get as far as a certificate
/// this provider then cannot check.
/// Ed25519 belongs here rather than in a family of its own: RFC 8422 carries
/// it in the ECDHE_ECDSA suites, so a TLS 1.2 server holding an Ed25519
/// certificate negotiates one of these. rustls's own provider lists it first,
/// and this follows.
static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// The signature schemes a TLS 1.2 RSA suite may use, strongest first.
///
/// PSS ahead of PKCS#1 v1.5: both are verifiable here, and the ontology records
/// PSS as superseding v1.5. The older padding stays because a great many TLS
/// 1.2 servers sign the key exchange with it and will not offer anything else.
static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every signature scheme a TLS 1.2 suite advertises must be one the
    /// verifier actually implements.
    ///
    /// Advertising more than can be verified is worse than advertising less:
    /// the handshake proceeds, the peer picks the scheme, and it fails at
    /// certificate verification with no indication that the choice was ours.
    #[test]
    fn the_advertised_schemes_are_all_verifiable() {
        let mapped: alloc::vec::Vec<SignatureScheme> = crate::SUPPORTED_SIG_ALGS
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect();

        let mut checked = 0;
        for suite in ALL {
            let SupportedCipherSuite::Tls12(t) = suite else {
                continue;
            };
            for scheme in t.sign {
                assert!(
                    mapped.contains(scheme),
                    "{:?} advertises {scheme:?}, which nothing here verifies",
                    suite.suite()
                );
                checked += 1;
            }
        }
        // Three ECDSA suites at three schemes each, three RSA suites at six.
        assert!(checked >= 27, "only {checked} advertised schemes examined");
    }

    /// Each suite's hash must match the one its name promises, because the key
    /// schedule and the transcript both depend on it.
    #[test]
    fn each_suite_uses_the_hash_it_is_named_for() {
        use rustls::crypto::hash::HashAlgorithm;

        // `common()` is crate-private in rustls, so the variant is matched to
        // reach the public field on the concrete suite.
        for (suite, want) in [
            (&TLS13_AES_256_GCM_SHA384, HashAlgorithm::SHA384),
            (&TLS13_AES_128_GCM_SHA256, HashAlgorithm::SHA256),
            (
                &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                HashAlgorithm::SHA384,
            ),
            (
                &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                HashAlgorithm::SHA256,
            ),
            (&TLS13_CHACHA20_POLY1305_SHA256, HashAlgorithm::SHA256),
            (
                &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                HashAlgorithm::SHA256,
            ),
            (
                &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                HashAlgorithm::SHA384,
            ),
            (
                &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                HashAlgorithm::SHA256,
            ),
            (
                &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                HashAlgorithm::SHA256,
            ),
        ] {
            let got = match suite {
                SupportedCipherSuite::Tls13(t) => t.common.hash_provider.algorithm(),
                SupportedCipherSuite::Tls12(t) => t.common.hash_provider.algorithm(),
            };
            assert_eq!(got, want, "{:?} uses the wrong hash", suite.suite());
        }
    }

    /// The list must be ordered strongest first, since rustls offers it in
    /// order and the peer picks the first it accepts.
    #[test]
    fn the_suites_are_ordered_and_distinct() {
        let names: alloc::vec::Vec<CipherSuite> = ALL.iter().map(|s| s.suite()).collect();
        assert_eq!(names.len(), 9);
        for (i, a) in names.iter().enumerate() {
            assert!(!names[i + 1..].contains(a), "{a:?} is listed twice");
        }
        // TLS 1.3 before TLS 1.2, and 256 before 128 within each.
        assert_eq!(names[0], CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(names[1], CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(names[2], CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
        // Every TLS 1.3 suite before every TLS 1.2 one.
        let first_12 = ALL
            .iter()
            .position(|s| matches!(s, SupportedCipherSuite::Tls12(_)))
            .expect("there are TLS 1.2 suites");
        assert!(
            ALL[first_12..]
                .iter()
                .all(|s| matches!(s, SupportedCipherSuite::Tls12(_))),
            "the TLS 1.3 and TLS 1.2 suites are interleaved"
        );
    }
}
