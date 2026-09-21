//! Signing, so the provider can present a certificate as well as check one.
//!
//! Without this the provider authenticates a peer and cannot prove anything
//! about itself: no server, no client certificate. rustls asks for a
//! [`KeyProvider`] that turns a DER private key into a [`SigningKey`], which
//! then picks a scheme from what the peer offered and produces signatures.
//!
//! # What is signed, and in what form
//!
//! rustls hands over the message unhashed and expects the digest implied by the
//! chosen scheme to be applied here. `ic_ec`'s signers hash internally, so the
//! message is passed through rather than pre-hashed -- passing a digest to a
//! function that digests would sign the hash of the hash, which verifies
//! against nothing.
//!
//! The signature goes back as an X.509 `Ecdsa-Sig-Value`, a DER SEQUENCE of two
//! INTEGERs, because that is what TLS carries for ECDSA. `ic_ec` produces
//! fixed-width `r || s`, so `ic_pkix` encodes between them -- the same crate
//! that decodes in the other direction for [`crate::verify`], which keeps one
//! implementation of that mapping rather than two that could disagree.
//!
//! # ECDSA only
//!
//! The scheme chosen must be one [`crate::verify`] can check. Offering to sign
//! with something this provider cannot verify would let a handshake proceed to
//! a point where the peer expects a signature nothing here can produce a
//! counterpart for. RSA keys and Ed25519 keys are refused by
//! [`KeyProvider::load_private_key`] with a message saying so.

use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ic_core::traits::SignatureScheme as _;
use ic_core::Zeroize;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

/// Turns a DER private key into something that can sign.
#[derive(Debug)]
pub struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        // PKCS#8 and bare SEC1 both appear in the wild -- the bodies of
        // `-----BEGIN PRIVATE KEY-----` and `-----BEGIN EC PRIVATE KEY-----`
        // respectively -- and rustls tells them apart, so both are read here
        // rather than making the caller convert. They are different grammars
        // with a parser each; passing one to the other's parser fails, so the
        // label has to be honoured rather than guessed at.
        let parsed = match &key {
            PrivateKeyDer::Pkcs8(k) => ic_pkix::PrivateKeyInfo::from_der(k.secret_pkcs8_der()),
            // `None`: a bare ECPrivateKey names its own curve, because there is
            // no enclosing AlgorithmIdentifier to name it.
            PrivateKeyDer::Sec1(k) => {
                ic_pkix::private_key::parse_ec_private_key(k.secret_sec1_der(), None)
            }
            PrivateKeyDer::Pkcs1(_) => {
                return Err(Error::General(
                    "ic-rustls signs with ECDSA; a PKCS#1 key is RSA, which crate::verify \
                     cannot check either, so offering to sign with it would advertise \
                     something this provider cannot complete"
                        .into(),
                ))
            }
            _ => return Err(Error::General("unrecognised private key format".into())),
        };
        let parsed = parsed.map_err(|e| {
            Error::General(format!(
                "could not parse the private key: {}",
                e.kind().id()
            ))
        })?;

        match parsed {
            ic_pkix::PrivateKeyInfo::Ec {
                algorithm,
                private_key,
                ..
            } => {
                let curve = Curve::from_algorithm(algorithm).ok_or_else(|| {
                    Error::General(format!(
                        "ic-rustls verifies ECDSA on P-256 and P-384; {} is not one of them",
                        algorithm.id()
                    ))
                })?;
                if private_key.len() != curve.scalar_len() {
                    return Err(Error::General(format!(
                        "a {} scalar is {} bytes, not {}",
                        algorithm.id(),
                        curve.scalar_len(),
                        private_key.len()
                    )));
                }
                Ok(Arc::new(EcdsaSigningKey {
                    curve,
                    secret: private_key.to_vec(),
                }))
            }
            other => Err(Error::General(format!(
                "ic-rustls signs with ECDSA; this key is {}, which crate::verify cannot check, \
                 so offering to sign with it would advertise something this provider cannot \
                 complete",
                other.algorithm().id()
            ))),
        }
    }

    /// Always false; see the crate documentation.
    fn fips(&self) -> bool {
        false
    }
}

/// The two curves this provider can both sign with and verify.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Curve {
    P256,
    P384,
}

impl Curve {
    fn from_algorithm(algorithm: ic_pkix::KeyAlgorithm) -> Option<Self> {
        match algorithm {
            ic_pkix::KeyAlgorithm::EcP256 => Some(Self::P256),
            ic_pkix::KeyAlgorithm::EcP384 => Some(Self::P384),
            _ => None,
        }
    }

    fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }

    /// The one scheme this curve is used with here.
    ///
    /// Deliberately one rather than several: `crate::verify` implements only
    /// the matched pairings, and a scheme offered for signing that cannot be
    /// verified is a handshake that fails later and further away.
    fn scheme(self) -> SignatureScheme {
        match self {
            Self::P256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            Self::P384 => SignatureScheme::ECDSA_NISTP384_SHA384,
        }
    }
}

/// An ECDSA key that has been parsed and is ready to sign.
#[derive(Debug)]
struct EcdsaSigningKey {
    curve: Curve,
    secret: Vec<u8>,
}

impl Drop for EcdsaSigningKey {
    /// The scalar is the private key of whoever this provider speaks for, and
    /// it lives as long as the configuration does.
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self.curve.scheme();
        offered.contains(&scheme).then(|| {
            Box::new(EcdsaSigner {
                curve: self.curve,
                secret: self.secret.clone(),
                scheme,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

/// One key bound to one scheme.
#[derive(Debug)]
struct EcdsaSigner {
    curve: Curve,
    secret: Vec<u8>,
    scheme: SignatureScheme,
}

impl Drop for EcdsaSigner {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // The message arrives unhashed and `ic_ec`'s signers hash it
        // themselves, so it is passed straight through. Hashing here first
        // would sign the digest of the digest.
        let mut fixed = [0u8; 96];
        let fixed = &mut fixed[..self.curve.scalar_len() * 2];

        let signed = match self.curve {
            Curve::P256 => ic_ec::p256::EcdsaP256Sha256::sign(&self.secret, message, fixed),
            Curve::P384 => ic_ec::p384::EcdsaP384Sha384::sign(&self.secret, message, fixed),
        };
        signed.map_err(|e| Error::General(format!("signing failed: {}", e.kind().id())))?;

        // TLS carries ECDSA signatures as an X.509 Ecdsa-Sig-Value. `ic_pkix`
        // owns both directions of this mapping, so the encoder here and the
        // decoder in `crate::verify` cannot disagree about it.
        let mut der = [0u8; 112];
        let n = ic_pkix::ecdsa_signature::to_der(fixed, &mut der).map_err(|e| {
            Error::General(format!("could not encode the signature: {}", e.kind().id()))
        })?;
        fixed.zeroize();
        Ok(der[..n].to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// A PKCS#8 P-256 key, built from a scalar this crate can also verify with.
    fn p256_pkcs8(scalar: &[u8; 32]) -> PrivateKeyDer<'static> {
        let mut point = [0u8; 65];
        ic_ec::p256::EcdsaP256Sha256::public_key(scalar, &mut point).unwrap();
        let mut der = [0u8; 256];
        let n = ic_pkix::PrivateKeyInfo::Ec {
            algorithm: ic_pkix::KeyAlgorithm::EcP256,
            private_key: scalar,
            public_key: Some(&point),
        }
        .to_der(&mut der)
        .unwrap();
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der[..n].to_vec()))
    }

    /// The signature a key produces must verify against the matching public
    /// key, through this crate's own verifier.
    ///
    /// That is the property that matters: signing and verification are separate
    /// code paths here -- different modules, different `ic_pkix` functions in
    /// opposite directions -- so agreeing is evidence rather than tautology.
    #[test]
    fn a_signature_verifies_through_this_providers_verifier() {
        use rustls::pki_types::SignatureVerificationAlgorithm;

        let scalar = [7u8; 32];
        let key = Keys.load_private_key(p256_pkcs8(&scalar)).unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);

        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("the scheme it names should be choosable");
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);

        let message = b"the transcript a CertificateVerify covers";
        let sig = signer.sign(message).expect("signing should work");

        let mut point = [0u8; 65];
        ic_ec::p256::EcdsaP256Sha256::public_key(&scalar, &mut point).unwrap();
        crate::verify::ECDSA_P256_SHA256
            .verify_signature(&point, message, &sig)
            .expect("a signature this provider made must verify through its own verifier");

        // And must not verify a different message, or the check above is empty.
        assert!(crate::verify::ECDSA_P256_SHA256
            .verify_signature(&point, b"a different transcript", &sig)
            .is_err());
    }

    /// The same property on P-384, which is not the same code path.
    ///
    /// The scalar is half again as long, the fixed-width signature is 96 bytes
    /// rather than 64, and the DER encoding is correspondingly larger -- so the
    /// two fixed-size buffers in `sign` are exercised near their capacity here
    /// and nowhere else. A buffer sized for P-256 alone passes every P-256 test.
    #[test]
    fn a_p384_signature_verifies_through_this_providers_verifier() {
        use rustls::pki_types::SignatureVerificationAlgorithm;

        let scalar = [0x5au8; 48];
        let mut point = [0u8; 97];
        ic_ec::p384::EcdsaP384Sha384::public_key(&scalar, &mut point).unwrap();

        let mut der = [0u8; 256];
        let n = ic_pkix::PrivateKeyInfo::Ec {
            algorithm: ic_pkix::KeyAlgorithm::EcP384,
            private_key: &scalar,
            public_key: Some(&point),
        }
        .to_der(&mut der)
        .unwrap();
        let key = Keys
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                der[..n].to_vec(),
            )))
            .unwrap();

        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
            .expect("a P-384 key should choose the P-384 scheme");
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP384_SHA384);

        let message = b"the transcript a CertificateVerify covers";
        let sig = signer.sign(message).expect("signing should work");

        crate::verify::ECDSA_P384_SHA384
            .verify_signature(&point, message, &sig)
            .expect("a signature this provider made must verify through its own verifier");
        assert!(crate::verify::ECDSA_P384_SHA384
            .verify_signature(&point, b"a different transcript", &sig)
            .is_err());
    }

    /// A key must not sign under the other curve's scheme.
    ///
    /// The scheme carries the digest, so a P-256 key answering a P-384 request
    /// would produce something the peer hashes differently and rejects. That is
    /// covered by `choose_scheme` above; this checks the pairing from the other
    /// side -- that each curve names the scheme `crate::verify` implements for
    /// it, and not the other one.
    #[test]
    fn each_curve_names_the_scheme_its_verifier_implements() {
        assert_eq!(Curve::P256.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
        assert_eq!(Curve::P384.scheme(), SignatureScheme::ECDSA_NISTP384_SHA384);
        assert_ne!(Curve::P256.scheme(), Curve::P384.scheme());

        // And both are schemes the provider actually advertises for verification.
        for c in [Curve::P256, Curve::P384] {
            assert!(
                crate::SUPPORTED_SIG_ALGS
                    .mapping
                    .iter()
                    .any(|(scheme, _)| *scheme == c.scheme()),
                "{:?} signs under a scheme the provider does not verify",
                c
            );
        }
    }

    /// A scheme that was not offered must not be chosen.
    ///
    /// Returning a signer for an unoffered scheme produces a signature the peer
    /// did not ask for and will reject, which is a confusing way to fail a
    /// handshake.
    #[test]
    fn only_an_offered_scheme_is_chosen() {
        let key = Keys.load_private_key(p256_pkcs8(&[9u8; 32])).unwrap();

        assert!(key.choose_scheme(&[]).is_none());
        assert!(key
            .choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::RSA_PSS_SHA256])
            .is_none());
        // A P-384 scheme is not this key's, even though the provider verifies it.
        assert!(key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
            .is_none());
        assert!(key
            .choose_scheme(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256
            ])
            .is_some());
    }

    /// Keys this provider cannot verify with are refused, with the reason.
    ///
    /// Loading one and signing with it would advertise a capability the
    /// verifier does not have, and the handshake would fail at the peer instead
    /// of here.
    #[test]
    fn a_key_this_provider_cannot_verify_with_is_refused() {
        // Ed25519: implemented in ic-ec, deliberately not offered here.
        let mut der = [0u8; 128];
        let n = ic_pkix::PrivateKeyInfo::Ed25519(&[3u8; 32])
            .to_der(&mut der)
            .unwrap();
        let ed = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der[..n].to_vec()));
        let err = Keys.load_private_key(ed).unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("ECDSA") && text.contains("cannot"),
            "the refusal should say why: {text}"
        );

        // Rubbish, which must be an error rather than a panic.
        for bad in [
            vec![],
            vec![0x30],
            vec![0xffu8; 64],
            vec![0x30, 0x82, 0xff, 0xff],
        ] {
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bad));
            assert!(Keys.load_private_key(key).is_err());
        }
    }

    #[test]
    fn the_key_provider_claims_no_fips_validation() {
        assert!(!Keys.fips());
    }
}
