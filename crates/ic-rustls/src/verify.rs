//! ECDSA signature verification, for certificate chains and for the handshake.
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
//! # What is not here
//!
//! Only the matched pairings are offered: P-256 with SHA-256 and P-384 with
//! SHA-384. A certificate may legitimately carry a P-256 key signed with
//! SHA-384, or the reverse, and `ic_ec` has no such combination -- so rather
//! than assemble one here, out of sight of that crate's vectors, the pairing is
//! simply not advertised. rustls will decline a chain that needs it, which is
//! the honest failure: a verification this provider cannot do is better refused
//! than approximated.

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

#[cfg(test)]
mod tests {
    use super::*;

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
