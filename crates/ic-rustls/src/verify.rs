//! Signature verification, for certificate chains and for the handshake.
//!
//! This is the one place in the provider where the input is entirely chosen by
//! whoever is on the other end: a certificate from an unknown peer, a
//! `CertificateVerify` from a server not yet authenticated. Everything here has
//! to return rather than panic on any byte string at all, which `ic_ec`'s
//! verifiers do and the hostile-input suite in `iron-crypto` holds them to.
//!
//! The signature arrives as an X.509 `Ecdsa-Sig-Value` -- a DER SEQUENCE of two
//! INTEGERs -- while `ic_ec` verifies fixed-width `r || s`, so `ic_pkix`
//! decodes between them. A DER parser reading attacker input is exactly where a
//! signature-verification bug lives, which is why it is `ic_pkix`'s parser
//! rather than another one written here.
//!
//! # RSA
//!
//! Both paddings, over each of SHA-256, SHA-384 and SHA-512. This matters more
//! than its share of the code suggests: most certificate chains on the public
//! web are RSA, so without it the provider can speak TLS only to the minority
//! of servers that present an ECDSA certificate.
//!
//! TLS 1.3 requires PSS for the handshake signature and leaves PKCS#1 v1.5 for
//! certificates, so both are needed to authenticate one connection. The public
//! key algorithm is `rsaEncryption` in every case, including for PSS: that is
//! TLS's `rsa_pss_rsae_*`, a PSS signature made with an ordinary RSA key, which
//! is what deployments actually use.
//!
//! A modulus below 2048 bits is refused, by `ic_rsa` rather than by anything
//! here. That is a deliberate policy and a stricter one than webpki's default,
//! so a chain with a 1024-bit key fails against this provider and would pass
//! against some others. The ontology marks that constraint `critical`, which
//! settles the question: a sub-2048-bit chain is refused, not accommodated.
//!
//! # What is not here
//!
//! Only the matched ECDSA pairings are offered: P-256 with SHA-256 and P-384
//! with SHA-384. A certificate may legitimately carry a P-256 key signed with
//! SHA-384, or the reverse, and `ic_ec` has no such combination -- so rather
//! than assemble one here, out of sight of that crate's vectors, the pairing is
//! simply not advertised. rustls will decline a chain that needs it, which is
//! the honest failure: a verification this provider cannot do is better refused
//! than approximated.
//!
//! RSA is not bound to particular curves that way, so all six of its
//! combinations are offered.

use ic_core::traits::SignatureScheme as _;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};

/// ECDSA P-256 with SHA-256.
pub(crate) static ECDSA_P256_SHA256: Ecdsa = Ecdsa {
    curve: Curve::P256,
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scalar_len: 32,
};

/// ECDSA P-384 with SHA-384.
pub(crate) static ECDSA_P384_SHA384: Ecdsa = Ecdsa {
    curve: Curve::P384,
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scalar_len: 48,
};

#[derive(Debug, Clone, Copy)]
enum Curve {
    P256,
    P384,
}

#[derive(Debug)]
pub(crate) struct Ecdsa {
    curve: Curve,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    scalar_len: usize,
}

impl SignatureVerificationAlgorithm for Ecdsa {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // DER SEQUENCE { r INTEGER, s INTEGER } to fixed-width r || s. A
        // signature whose integers are negative, over-long, or not minimally
        // encoded is refused here rather than coerced into something that might
        // verify.
        let mut buf = [0u8; 96];
        let fixed = &mut buf[..self.scalar_len * 2];
        ic_pkix::ecdsa_signature::from_der(signature, fixed).map_err(|_| InvalidSignature)?;

        let verified = match self.curve {
            Curve::P256 => ic_ec::p256::EcdsaP256Sha256::verify(public_key, message, fixed),
            Curve::P384 => ic_ec::p384::EcdsaP384Sha384::verify(public_key, message, fixed),
        };
        verified.map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    /// Always false; see the note on the hash adapter.
    fn fips(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 with SHA-256, the padding certificate chains are made of.
pub(crate) static RSA_PKCS1_SHA256: Rsa = Rsa {
    scheme: RsaScheme::Pkcs1Sha256,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
};

/// RSASSA-PKCS1-v1_5 with SHA-384.
pub(crate) static RSA_PKCS1_SHA384: Rsa = Rsa {
    scheme: RsaScheme::Pkcs1Sha384,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
};

/// RSASSA-PKCS1-v1_5 with SHA-512.
pub(crate) static RSA_PKCS1_SHA512: Rsa = Rsa {
    scheme: RsaScheme::Pkcs1Sha512,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
};

/// RSASSA-PSS with SHA-256, over an `rsaEncryption` key: TLS's
/// `rsa_pss_rsae_sha256`.
pub(crate) static RSA_PSS_SHA256: Rsa = Rsa {
    scheme: RsaScheme::PssSha256,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
};

/// RSASSA-PSS with SHA-384.
pub(crate) static RSA_PSS_SHA384: Rsa = Rsa {
    scheme: RsaScheme::PssSha384,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
};

/// RSASSA-PSS with SHA-512.
pub(crate) static RSA_PSS_SHA512: Rsa = Rsa {
    scheme: RsaScheme::PssSha512,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
};

/// Which padding and hash, as data rather than a type parameter, so the six
/// statics above can be `static` and not generic instantiations.
#[derive(Debug, Clone, Copy, PartialEq)]
enum RsaScheme {
    Pkcs1Sha256,
    Pkcs1Sha384,
    Pkcs1Sha512,
    PssSha256,
    PssSha384,
    PssSha512,
}

/// An RSA signature verifier.
#[derive(Debug)]
pub(crate) struct Rsa {
    scheme: RsaScheme,
    signature_alg_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Rsa {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // `public_key` is the SubjectPublicKeyInfo's subjectPublicKey contents,
        // which for rsaEncryption is a DER PKCS#1 `RSAPublicKey`. It comes from
        // a certificate supplied by an unauthenticated peer, so it is parsed by
        // `ic_pkix` -- the same parser the rest of the workspace uses and the
        // hostile-input suite exercises -- rather than by anything written here.
        let (modulus, exponent) =
            ic_pkix::parse_rsa_public_key(public_key).map_err(|_| InvalidSignature)?;

        // Refuses a modulus below 2048 bits, among other things. That rejection
        // is policy, not an incapacity: see the module documentation.
        let key = ic_rsa::RsaPublicKey::from_components(modulus, exponent)
            .map_err(|_| InvalidSignature)?;

        let verified = match self.scheme {
            RsaScheme::Pkcs1Sha256 => ic_rsa::Pkcs1Sha256::verify(&key, message, signature),
            RsaScheme::Pkcs1Sha384 => ic_rsa::Pkcs1Sha384::verify(&key, message, signature),
            RsaScheme::Pkcs1Sha512 => ic_rsa::Pkcs1Sha512::verify(&key, message, signature),
            RsaScheme::PssSha256 => ic_rsa::PssSha256::verify(&key, message, signature),
            RsaScheme::PssSha384 => ic_rsa::PssSha384::verify(&key, message, signature),
            RsaScheme::PssSha512 => ic_rsa::PssSha512::verify(&key, message, signature),
        };
        verified.map_err(|_| InvalidSignature)
    }

    /// `rsaEncryption` for all six.
    ///
    /// Including the PSS ones: TLS's `rsa_pss_rsae_*` schemes are PSS
    /// signatures made with an ordinary RSA key, which is what certificates
    /// carry. A key whose algorithm is `RSASSA-PSS` proper is a different and
    /// much rarer thing, and is not claimed here.
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    /// Always false; see the note on the hash adapter.
    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One 2048-bit key, generated once and shared by the RSA tests.
    ///
    /// Generation is slow enough that doing it per test is worth avoiding, and
    /// the repository already generates rather than embedding a key: an RSA
    /// private key transcribed into source is a key anyone reading the source
    /// has, which is fine for a test and bad if it ever escapes into an example.
    fn rsa_key() -> &'static ic_rsa::RsaPrivateKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<ic_rsa::RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = ic_drbg::Rng::from_os().expect("os randomness");
            ic_rsa::generate(2048, &mut rng).expect("rsa key generation")
        })
    }

    /// The public key as a certificate carries it: a DER PKCS#1 `RSAPublicKey`,
    /// which is what rustls hands to `verify_signature`.
    fn rsa_spki_body(key: &ic_rsa::RsaPrivateKey) -> alloc::vec::Vec<u8> {
        let public = key.public_key();
        let mut modulus = alloc::vec![0u8; public.size()];
        public.modulus_bytes(&mut modulus).unwrap();

        let mut der = alloc::vec![0u8; 1024];
        let n = ic_pkix::write_rsa_public_key(&modulus, public.exponent(), &mut der).unwrap();
        der.truncate(n);
        der
    }

    /// An RSA signature must verify through the adapter, for every scheme.
    ///
    /// The signing side is `ic_rsa` called directly and the verifying side is
    /// the adapter, which parses the public key out of its certificate encoding
    /// and dispatches on the scheme. Those are the two things this module adds
    /// over `ic-rsa`, and both are exercised here rather than assumed.
    #[test]
    fn rsa_signatures_verify_through_the_adapter() {
        let key = rsa_key();
        let spki = rsa_spki_body(key);
        let message = b"the transcript a CertificateVerify covers";
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut sig = alloc::vec![0u8; key.public_key().size()];

        let mut checked = 0;
        for (name, alg) in [
            ("rsa-pkcs1-sha256", &RSA_PKCS1_SHA256),
            ("rsa-pkcs1-sha384", &RSA_PKCS1_SHA384),
            ("rsa-pkcs1-sha512", &RSA_PKCS1_SHA512),
            ("rsa-pss-sha256", &RSA_PSS_SHA256),
            ("rsa-pss-sha384", &RSA_PSS_SHA384),
            ("rsa-pss-sha512", &RSA_PSS_SHA512),
        ] {
            match alg.scheme {
                RsaScheme::Pkcs1Sha256 => ic_rsa::Pkcs1Sha256::sign(key, message, &mut sig),
                RsaScheme::Pkcs1Sha384 => ic_rsa::Pkcs1Sha384::sign(key, message, &mut sig),
                RsaScheme::Pkcs1Sha512 => ic_rsa::Pkcs1Sha512::sign(key, message, &mut sig),
                RsaScheme::PssSha256 => ic_rsa::PssSha256::sign(key, message, &mut rng, &mut sig),
                RsaScheme::PssSha384 => ic_rsa::PssSha384::sign(key, message, &mut rng, &mut sig),
                RsaScheme::PssSha512 => ic_rsa::PssSha512::sign(key, message, &mut rng, &mut sig),
            }
            .unwrap_or_else(|e| panic!("{name}: signing failed: {e}"));

            alg.verify_signature(&spki, message, &sig)
                .unwrap_or_else(|_| panic!("{name}: a signature ic_rsa made did not verify"));

            // A different message must not, or the check above is empty.
            assert!(
                alg.verify_signature(&spki, b"a different transcript", &sig)
                    .is_err(),
                "{name}: a signature verified against the wrong message"
            );

            // And no *other* scheme may accept it. This is what catches a
            // dispatch that collapses two arms onto one hash or one padding:
            // every signature would still verify under its own name, and only
            // the cross-checks would notice.
            for (other_name, other) in [
                ("rsa-pkcs1-sha256", &RSA_PKCS1_SHA256),
                ("rsa-pkcs1-sha384", &RSA_PKCS1_SHA384),
                ("rsa-pkcs1-sha512", &RSA_PKCS1_SHA512),
                ("rsa-pss-sha256", &RSA_PSS_SHA256),
                ("rsa-pss-sha384", &RSA_PSS_SHA384),
                ("rsa-pss-sha512", &RSA_PSS_SHA512),
            ] {
                if other.scheme == alg.scheme {
                    continue;
                }
                assert!(
                    other.verify_signature(&spki, message, &sig).is_err(),
                    "a {name} signature was accepted as {other_name}"
                );
            }
            checked += 1;
        }
        assert_eq!(checked, 6, "not every RSA scheme was exercised");
    }

    /// Every RSA scheme must name `rsaEncryption` as its public key algorithm,
    /// and a signature algorithm distinct from all the others.
    ///
    /// rustls matches a certificate's algorithm identifiers against these. Two
    /// schemes sharing a signature identifier would make the choice between
    /// them arbitrary.
    #[test]
    fn the_rsa_algorithm_identifiers_are_distinct_and_rsae() {
        let all = [
            &RSA_PKCS1_SHA256,
            &RSA_PKCS1_SHA384,
            &RSA_PKCS1_SHA512,
            &RSA_PSS_SHA256,
            &RSA_PSS_SHA384,
            &RSA_PSS_SHA512,
        ];
        for (i, a) in all.iter().enumerate() {
            assert_eq!(
                a.public_key_alg_id(),
                alg_id::RSA_ENCRYPTION,
                "TLS's rsa_pss_rsae_* and rsa_pkcs1_* both use rsaEncryption keys"
            );
            for b in &all[i + 1..] {
                assert_ne!(
                    a.signature_alg_id(),
                    b.signature_alg_id(),
                    "two RSA schemes share a signature algorithm identifier"
                );
            }
            assert!(!a.fips());
        }
    }

    /// A modulus below 2048 bits is refused.
    ///
    /// This is policy rather than incapacity: the ontology marks
    /// `rsa-modulus-at-least-2048-bits` critical, `ic_rsa` enforces it, and a
    /// chain carrying a 1024-bit key therefore fails against this provider
    /// where it would pass against some others. Pinning it here means the
    /// behaviour is a decision on record and not an accident that could be
    /// "fixed" by someone who met it as a mysterious handshake failure.
    #[test]
    fn a_short_modulus_is_refused_rather_than_verified() {
        // The policy itself, asserted where it lives. Going through
        // `verify_signature` alone would not establish this: any signature
        // supplied for a short key is necessarily wrong, so the call fails
        // either way and the test would pass with the size check deleted.
        assert_eq!(ic_rsa::MIN_MODULUS_BITS, 2048);
        let short = alloc::vec![0xc7u8; 128];
        assert!(
            ic_rsa::RsaPublicKey::from_components(&short, 65537).is_err(),
            "a 1024-bit modulus was accepted"
        );

        // The identical call at 2048 bits succeeds, so the refusal above is
        // about the size and not about these particular bytes.
        let long = alloc::vec![0xc7u8; 256];
        assert!(
            ic_rsa::RsaPublicKey::from_components(&long, 65537).is_ok(),
            "the control key was rejected for some other reason, so the \
             comparison says nothing about the modulus size"
        );

        // And the adapter surfaces the refusal rather than panicking on it.
        let mut der = alloc::vec![0u8; 512];
        let n = ic_pkix::write_rsa_public_key(&short, 65537, &mut der).unwrap();
        assert!(RSA_PKCS1_SHA256
            .verify_signature(&der[..n], b"anything", &[0u8; 128])
            .is_err());
    }

    /// Hostile public keys and signatures must return, not panic.
    ///
    /// Both arguments come from an unauthenticated peer. This is the same
    /// property the ECDSA path is held to below, applied to the RSA one.
    #[test]
    fn hostile_rsa_inputs_are_refused_rather_than_fatal() {
        let key = rsa_key();
        let spki = rsa_spki_body(key);

        let mut tried = 0;
        for bad_key in [
            alloc::vec![],
            alloc::vec![0x30],
            alloc::vec![0x30, 0x82, 0xff, 0xff],
            alloc::vec![0xffu8; 300],
            spki[..spki.len() / 2].to_vec(),
        ] {
            for bad_sig in [
                alloc::vec![],
                alloc::vec![0u8; 256],
                alloc::vec![0xffu8; 1000],
            ] {
                assert!(RSA_PKCS1_SHA256
                    .verify_signature(&bad_key, b"message", &bad_sig)
                    .is_err());
                assert!(RSA_PSS_SHA256
                    .verify_signature(&bad_key, b"message", &bad_sig)
                    .is_err());
                tried += 2;
            }
        }

        // A good key with a hostile signature, which reaches further in.
        for bad_sig in [
            alloc::vec![],
            alloc::vec![0u8; 255],
            alloc::vec![0u8; 256],
            alloc::vec![0xffu8; 256],
            alloc::vec![0xffu8; 257],
        ] {
            assert!(RSA_PKCS1_SHA256
                .verify_signature(&spki, b"message", &bad_sig)
                .is_err());
            assert!(RSA_PSS_SHA256
                .verify_signature(&spki, b"message", &bad_sig)
                .is_err());
            tried += 2;
        }
        assert!(tried >= 40, "only {tried} hostile inputs tried");
    }

    /// A signature this library produced must verify through the adapter.
    ///
    /// The path is not trivial: the signature is made in fixed-width form,
    /// encoded to DER the way a certificate carries it, and decoded back by the
    /// adapter. A mistake in either direction shows up here.
    #[test]
    fn a_real_signature_verifies_through_the_der_path() {
        let sk = [7u8; 32];
        let mut pk = [0u8; 65];
        ic_ec::p256::EcdsaP256Sha256::public_key(&sk, &mut pk).unwrap();

        let message = b"a message that was genuinely signed";
        let mut fixed = [0u8; 64];
        ic_ec::p256::EcdsaP256Sha256::sign(&sk, message, &mut fixed).unwrap();

        let mut der = [0u8; 80];
        let n = ic_pkix::ecdsa_signature::to_der(&fixed, &mut der).unwrap();

        ECDSA_P256_SHA256
            .verify_signature(&pk, message, &der[..n])
            .expect("a signature this library made must verify");

        // A different message must not.
        assert!(ECDSA_P256_SHA256
            .verify_signature(&pk, b"a different message", &der[..n])
            .is_err());
    }

    #[test]
    fn p384_verifies_through_the_der_path() {
        let sk = [9u8; 48];
        let mut pk = [0u8; 97];
        ic_ec::p384::EcdsaP384Sha384::public_key(&sk, &mut pk).unwrap();

        let message = b"a message that was genuinely signed";
        let mut fixed = [0u8; 96];
        ic_ec::p384::EcdsaP384Sha384::sign(&sk, message, &mut fixed).unwrap();

        let mut der = [0u8; 112];
        let n = ic_pkix::ecdsa_signature::to_der(&fixed, &mut der).unwrap();

        ECDSA_P384_SHA384
            .verify_signature(&pk, message, &der[..n])
            .expect("a signature this library made must verify");
        assert!(ECDSA_P384_SHA384
            .verify_signature(&pk, b"something else", &der[..n])
            .is_err());
    }

    /// Verification reads bytes an attacker chose, so it must return for all of
    /// them -- no panic, no index out of range.
    ///
    /// This is a smaller version of what `iron-crypto`'s hostile-input suite
    /// does to the verifiers underneath; it is here because the DER decode in
    /// front of them is part of this crate rather than part of theirs.
    #[test]
    fn hostile_signatures_are_refused_rather_than_fatal() {
        let sk = [7u8; 32];
        let mut pk = [0u8; 65];
        ic_ec::p256::EcdsaP256Sha256::public_key(&sk, &mut pk).unwrap();

        let mut refused = 0;
        for len in [0usize, 1, 8, 63, 64, 70, 71, 72, 200] {
            for fill in [0x00u8, 0xff, 0x30, 0x02, 0x80] {
                let sig = alloc::vec![fill; len];
                assert!(
                    ECDSA_P256_SHA256
                        .verify_signature(&pk, b"message", &sig)
                        .is_err(),
                    "a signature of {len} bytes of {fill:#04x} was accepted"
                );
                refused += 1;

                // A hostile public key must be refused too, not trusted.
                let bad_key = alloc::vec![fill; 65];
                assert!(ECDSA_P256_SHA256
                    .verify_signature(&bad_key, b"message", &sig)
                    .is_err());
                refused += 1;
            }
        }
        assert!(refused > 80, "only {refused} hostile inputs tried");
    }

    /// The identifiers decide which chains rustls will route here, so a wrong
    /// one sends signatures to the wrong verifier.
    #[test]
    fn the_algorithm_identifiers_are_the_expected_ones() {
        assert_eq!(ECDSA_P256_SHA256.public_key_alg_id(), alg_id::ECDSA_P256);
        assert_eq!(ECDSA_P256_SHA256.signature_alg_id(), alg_id::ECDSA_SHA256);
        assert_eq!(ECDSA_P384_SHA384.public_key_alg_id(), alg_id::ECDSA_P384);
        assert_eq!(ECDSA_P384_SHA384.signature_alg_id(), alg_id::ECDSA_SHA384);
    }

    #[test]
    fn neither_claims_fips_validation() {
        assert!(!ECDSA_P256_SHA256.fips());
        assert!(!ECDSA_P384_SHA384.fips());
    }
}
