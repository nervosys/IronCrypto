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
//! # ECDSA, Ed25519 and RSA
//!
//! The scheme chosen must be one [`crate::verify`] can check. Offering to sign
//! with something this provider cannot verify would let a handshake proceed to
//! a point where the peer expects a signature nothing here can produce a
//! counterpart for. An X25519 key is therefore refused by
//! [`KeyProvider::load_private_key`] with a message saying so: it is a key
//! agreement key, and no signature scheme uses it.
//!
//! RSA keys are built from their primes rather than from `n`, `e` and `d`.
//! `ic_rsa` then derives the CRT parameters itself instead of reading the
//! file's, so a file whose `dP`, `dQ` or `qInv` disagree with its primes cannot
//! produce the faulted half that leaks a factorization -- and the key signs on
//! the fast path, which the `n`/`e`/`d` form cannot. The modulus the file
//! states is checked against the one the primes produce, because a key that is
//! not the one the certificate names would sign things nothing verifies.

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
            // A bare PKCS#1 `RSAPrivateKey`, the body of a
            // `-----BEGIN RSA PRIVATE KEY-----` file.
            PrivateKeyDer::Pkcs1(k) => {
                ic_pkix::private_key::parse_rsa_private_key(k.secret_pkcs1_der())
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
            ic_pkix::PrivateKeyInfo::Rsa {
                modulus,
                public_exponent,
                private_exponent,
                prime1,
                prime2,
                ..
            } => {
                let key = rsa_key_from(modulus, public_exponent, private_exponent, prime1, prime2)?;
                Ok(Arc::new(RsaSigningKey { key: Arc::new(key) }))
            }
            ic_pkix::PrivateKeyInfo::Ed25519(seed) => {
                // `ic_pkix` already refuses any length but 32, in the parser as
                // well as the writer, so this cannot fire today. It is kept
                // because the cost is one comparison and the consequence of
                // that invariant being relaxed upstream would be a seed handed
                // to `ic_ec` for it to reject less informatively. No test
                // covers it, because no input reaches it.
                if seed.len() != 32 {
                    return Err(Error::General(format!(
                        "an ed25519 seed is 32 bytes, not {}",
                        seed.len()
                    )));
                }
                Ok(Arc::new(Ed25519SigningKey {
                    seed: seed.to_vec(),
                }))
            }
            other => Err(Error::General(format!(
                "ic-rustls signs with ECDSA, Ed25519 and RSA; this key is {}, which crate::verify \
                 cannot check, so offering to sign with it would advertise something this \
                 provider cannot complete",
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

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// An Ed25519 key.
///
/// The scheme fixes the hash and the curve together, so there is nothing to
/// choose: one key, one scheme, one 64-byte signature.
struct Ed25519SigningKey {
    /// The 32-byte seed. Not the expanded scalar -- `ic_ec` expands it per
    /// operation and wipes what it expanded.
    seed: Vec<u8>,
}

impl core::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519SigningKey(..)")
    }
}

impl Drop for Ed25519SigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ED25519).then(|| {
            Box::new(Ed25519Signer {
                seed: self.seed.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct Ed25519Signer {
    seed: Vec<u8>,
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519Signer(..)")
    }
}

impl Drop for Ed25519Signer {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // Ed25519 hashes the message itself, twice, as part of the scheme. As
        // everywhere else here, the message is passed through unhashed.
        let mut sig = [0u8; 64];
        ic_ec::Ed25519::sign(&self.seed, message, &mut sig)
            .map_err(|e| Error::General(format!("signing failed: {e}")))?;
        Ok(sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Build an RSA private key from the fields a PKCS#8 or PKCS#1 file carries.
///
/// Separate from [`Keys::load_private_key`] so its result can be inspected: the
/// two properties worth asserting -- that the key takes the CRT path, and that
/// a file whose primes contradict its modulus is refused -- are invisible
/// through the `SigningKey` trait object, and a test that could only go through
/// the trait would end up testing `ic_rsa`'s constructors instead of this
/// crate's choice between them.
fn rsa_key_from(
    modulus: &[u8],
    public_exponent: u64,
    private_exponent: &[u8],
    prime1: &[u8],
    prime2: &[u8],
) -> Result<ic_rsa::RsaPrivateKey, Error> {
    // Built from the primes, which does two things at once.
    //
    // `ic_rsa` derives `d` and the CRT parameters from `p` and `q` in one place
    // rather than reading the file's `dP`, `dQ` and `qInv`. A key whose stored
    // CRT values disagree with its primes computes a wrong half and, from the
    // signature, leaks the factorization -- the classic fault attack. Deriving
    // them means the file cannot express that disagreement.
    //
    // It is also the fast path: a key built from `n`, `e` and `d` alone carries
    // no primes, so signing cannot use the CRT. `ic-rsa`'s own measurement --
    // `key::tests::report_the_crt_speedup`, ignored by default and run with
    // `--release` -- puts a 2048-bit private operation at 1.84ms with the CRT
    // and 7.85ms without, a factor of 4.27 on that machine. So the fallback
    // exists for keys that genuinely lack primes, not as the ordinary case.
    //
    // Either way the 2048-bit floor applies on this side as well as the
    // verifying one. See `crate::verify`.
    let key = if prime1.is_empty() || prime2.is_empty() {
        ic_rsa::RsaPrivateKey::from_components(modulus, public_exponent, private_exponent)
    } else {
        ic_rsa::RsaPrivateKey::from_primes(prime1, prime2, public_exponent)
    }
    .map_err(|e| Error::General(format!("unusable RSA key: {e}")))?;

    // The primes must actually describe the modulus in the file. If they do
    // not, this is not the key the certificate names, and signing with it would
    // produce signatures nothing verifies.
    let mut derived = alloc::vec![0u8; key.public_key().size()];
    key.public_key()
        .modulus_bytes(&mut derived)
        .map_err(|e| Error::General(format!("unusable RSA key: {e}")))?;
    if derived != modulus {
        return Err(Error::General(
            "the RSA key's primes do not multiply to the modulus it carries".into(),
        ));
    }
    Ok(key)
}

/// The RSA schemes this provider will sign with, in preference order.
///
/// PSS ahead of PKCS#1 v1.5, and the stronger hash ahead of the weaker within
/// each. TLS 1.3 will only offer the PSS ones, so the v1.5 entries matter for
/// TLS 1.2 peers that offer nothing else -- and the peer's offer is what bounds
/// the choice, so listing them costs nothing against a modern peer.
///
/// Every entry is a scheme [`crate::verify`] can also check. That is the same
/// rule the ECDSA side follows and for the same reason.
const RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// An RSA key that has been parsed and is ready to sign.
///
/// The key is behind an `Arc` because `ic_rsa::RsaPrivateKey` is sized for a
/// 4096-bit modulus whether or not the key is one, and `choose_scheme` may be
/// called more than once. Sharing it beats copying several kilobytes per
/// signature.
struct RsaSigningKey {
    key: Arc<ic_rsa::RsaPrivateKey>,
}

/// Written out rather than derived: `Debug` on a type holding a private key
/// should not be able to print one, and a derive would print whatever the
/// fields grow into later.
impl core::fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RsaSigningKey(..)")
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // This crate's preference order decides, among what the peer allows.
        // Scanning `offered` instead would let the peer pick PKCS#1 v1.5 when
        // it would also have accepted PSS.
        let scheme = *RSA_SCHEMES.iter().find(|s| offered.contains(s))?;
        Some(Box::new(RsaSigner {
            key: Arc::clone(&self.key),
            scheme,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

/// One RSA key bound to one scheme.
struct RsaSigner {
    key: Arc<ic_rsa::RsaPrivateKey>,
    scheme: SignatureScheme,
}

impl core::fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RsaSigner(..)")
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // As on the ECDSA side, the message arrives unhashed and `ic_rsa`
        // hashes it, so it is passed through rather than pre-hashed.
        let mut sig = alloc::vec![0u8; self.key.public_key().size()];

        let signed = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => {
                ic_rsa::Pkcs1Sha256::sign(&self.key, message, &mut sig)
            }
            SignatureScheme::RSA_PKCS1_SHA384 => {
                ic_rsa::Pkcs1Sha384::sign(&self.key, message, &mut sig)
            }
            SignatureScheme::RSA_PKCS1_SHA512 => {
                ic_rsa::Pkcs1Sha512::sign(&self.key, message, &mut sig)
            }
            // PSS is randomized, so signing needs entropy where PKCS#1 v1.5
            // does not. A fresh generator per signature, as in `crate::random`.
            scheme @ (SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512) => {
                let mut rng = ic_drbg::Rng::from_os()
                    .map_err(|e| Error::General(format!("no randomness for PSS: {e}")))?;
                match scheme {
                    SignatureScheme::RSA_PSS_SHA256 => {
                        ic_rsa::PssSha256::sign(&self.key, message, &mut rng, &mut sig)
                    }
                    SignatureScheme::RSA_PSS_SHA384 => {
                        ic_rsa::PssSha384::sign(&self.key, message, &mut rng, &mut sig)
                    }
                    _ => ic_rsa::PssSha512::sign(&self.key, message, &mut rng, &mut sig),
                }
            }
            // Unreachable: `choose_scheme` only ever builds this with a scheme
            // from RSA_SCHEMES. Returned rather than panicked because a panic
            // here would be reachable from a handshake if that ever stopped
            // being true.
            other => {
                return Err(Error::General(format!(
                    "ic-rustls cannot sign with {other:?}"
                )))
            }
        };
        signed.map_err(|e| Error::General(format!("signing failed: {e}")))?;
        Ok(sig)
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
        // X25519: a key agreement key, not a signing key at all. `ic-ec`
        // implements it and no signature scheme uses it, so it is the case this
        // arm exists for.
        let mut der = [0u8; 128];
        let n = ic_pkix::PrivateKeyInfo::X25519(&[3u8; 32])
            .to_der(&mut der)
            .unwrap();
        let x = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der[..n].to_vec()));
        let err = Keys.load_private_key(x).unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("x25519") && text.contains("cannot"),
            "the refusal should name the key and say why: {text}"
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

    /// An Ed25519 signature must verify through this provider's own verifier.
    ///
    /// Ed25519 has no pairing to choose and no DER wrapper, so this is the
    /// simplest of the three round trips -- which is the reason to write it
    /// down rather than assume it: there is nothing here to go subtly wrong,
    /// so a failure would mean something plainly wrong, like a seed used where
    /// an expanded scalar was wanted.
    #[test]
    fn an_ed25519_signature_verifies_through_this_providers_verifier() {
        use rustls::pki_types::SignatureVerificationAlgorithm;

        let seed = [0x9du8; 32];
        let mut der = [0u8; 128];
        let n = ic_pkix::PrivateKeyInfo::Ed25519(&seed)
            .to_der(&mut der)
            .unwrap();
        let key = Keys
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                der[..n].to_vec(),
            )))
            .unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::ED25519);

        let signer = key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("an Ed25519 key should choose the Ed25519 scheme");
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);

        let message = b"the transcript a CertificateVerify covers";
        let sig = signer.sign(message).expect("signing should work");
        assert_eq!(sig.len(), 64, "an Ed25519 signature is 64 bytes");

        let mut public = [0u8; 32];
        ic_ec::Ed25519::public_key(&seed, &mut public).unwrap();
        crate::verify::ED25519
            .verify_signature(&public, message, &sig)
            .expect("a signature this provider made must verify through its own verifier");
        assert!(crate::verify::ED25519
            .verify_signature(&public, b"a different transcript", &sig)
            .is_err());

        // Deterministic, by RFC 8032: no nonce to repeat or leak.
        assert_eq!(signer.sign(message).unwrap(), sig);

        // And nothing but Ed25519 is offered by this key.
        assert!(key.choose_scheme(&[]).is_none());
        assert!(key
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256
            ])
            .is_none());

        // A seed of the wrong length cannot reach the loader at all: `ic_pkix`
        // refuses 31 bytes in both directions, so there is no PKCS#8 document
        // to hand over. Asserted here rather than left implicit, because the
        // first version of this test tried to build one, silently got nothing,
        // and skipped -- proving only that the encoder had declined.
        let mut short = [0u8; 128];
        assert!(
            ic_pkix::PrivateKeyInfo::Ed25519(&[1u8; 31])
                .to_der(&mut short)
                .is_err(),
            "the encoder accepted a 31-byte seed"
        );
    }

    /// One 2048-bit key, generated once and shared by the RSA tests.
    fn rsa_key() -> &'static ic_rsa::RsaPrivateKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<ic_rsa::RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = ic_drbg::Rng::from_os().expect("os randomness");
            ic_rsa::generate(2048, &mut rng).expect("rsa key generation")
        })
    }

    /// That key as a PKCS#8 `PrivateKeyInfo`, the way a file carries it.
    fn rsa_pkcs8(key: &ic_rsa::RsaPrivateKey) -> PrivateKeyDer<'static> {
        let half = key.size() / 2;
        let (mut modulus, mut d) = (alloc::vec![0u8; key.size()], alloc::vec![0u8; key.size()]);
        let (mut p, mut q) = (alloc::vec![0u8; half], alloc::vec![0u8; half]);
        let (mut dp, mut dq, mut qinv) = (
            alloc::vec![0u8; half],
            alloc::vec![0u8; half],
            alloc::vec![0u8; half],
        );
        key.public_key().modulus_bytes(&mut modulus).unwrap();
        key.exponent_bytes(&mut d).unwrap();
        key.prime_bytes(&mut p, &mut q).unwrap();
        key.crt_exponent_bytes(&mut dp, &mut dq, &mut qinv).unwrap();

        let mut der = alloc::vec![0u8; 4096];
        let n = ic_pkix::PrivateKeyInfo::Rsa {
            modulus: &modulus,
            public_exponent: key.public_key().exponent(),
            private_exponent: &d,
            prime1: &p,
            prime2: &q,
            exponent1: &dp,
            exponent2: &dq,
            coefficient: &qinv,
        }
        .to_der(&mut der)
        .unwrap();
        der.truncate(n);
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
    }

    /// An RSA signature must verify through this provider's own verifier, for
    /// every scheme the key will choose.
    ///
    /// Same shape as the ECDSA round trip: signing and verification are
    /// different modules reaching `ic_rsa` from opposite directions, so
    /// agreeing is evidence. The cross-check matters for the same reason it
    /// does in `crate::verify` -- it is what catches a scheme that signs under
    /// one hash and is named for another.
    #[test]
    fn rsa_signatures_verify_through_this_providers_verifier() {
        use rustls::pki_types::SignatureVerificationAlgorithm;

        let key = Keys.load_private_key(rsa_pkcs8(rsa_key())).unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);

        let mut spki = alloc::vec![0u8; rsa_key().size()];
        rsa_key().public_key().modulus_bytes(&mut spki).unwrap();
        let mut pk_der = alloc::vec![0u8; 1024];
        let n =
            ic_pkix::write_rsa_public_key(&spki, rsa_key().public_key().exponent(), &mut pk_der)
                .unwrap();
        let pk = &pk_der[..n];

        let message = b"the transcript a CertificateVerify covers";
        let mut checked = 0;
        for scheme in RSA_SCHEMES {
            let signer = key
                .choose_scheme(&[*scheme])
                .unwrap_or_else(|| panic!("{scheme:?} is listed but was not choosable"));
            assert_eq!(signer.scheme(), *scheme);

            let sig = signer.sign(message).expect("signing should work");

            let verifier: &dyn SignatureVerificationAlgorithm = match *scheme {
                SignatureScheme::RSA_PKCS1_SHA256 => &crate::verify::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384 => &crate::verify::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512 => &crate::verify::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PSS_SHA256 => &crate::verify::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384 => &crate::verify::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512 => &crate::verify::RSA_PSS_SHA512,
                other => panic!("{other:?} is in RSA_SCHEMES but has no verifier"),
            };
            verifier
                .verify_signature(pk, message, &sig)
                .unwrap_or_else(|_| {
                    panic!("{scheme:?}: a signature this provider made did not verify")
                });
            assert!(
                verifier
                    .verify_signature(pk, b"a different transcript", &sig)
                    .is_err(),
                "{scheme:?}: verified against the wrong message"
            );
            checked += 1;
        }
        assert_eq!(checked, 6, "not every RSA scheme was exercised");
    }

    /// The loaded key must use the CRT, and must be the key the file describes.
    ///
    /// Both are properties of how `load_private_key` builds the key rather than
    /// of `ic_rsa`. Building from `n`, `e` and `d` would still sign correctly
    /// and would silently cost several times as much per signature, so nothing
    /// else here would notice.
    #[test]
    fn a_loaded_rsa_key_takes_the_crt_path() {
        let key = rsa_key();
        let half = key.size() / 2;
        let (mut p, mut q) = (alloc::vec![0u8; half], alloc::vec![0u8; half]);
        let (mut d, mut modulus) = (alloc::vec![0u8; key.size()], alloc::vec![0u8; key.size()]);
        key.prime_bytes(&mut p, &mut q).unwrap();
        key.exponent_bytes(&mut d).unwrap();
        key.public_key().modulus_bytes(&mut modulus).unwrap();
        let e = key.public_key().exponent();

        // The loader's own result, given everything a PKCS#8 file carries.
        // Asserting on `ic_rsa`'s constructors instead would test that crate
        // rather than this one's choice between them, and would still pass if
        // the loader were switched back to the slow path.
        let loaded = rsa_key_from(&modulus, e, &d, &p, &q).unwrap();
        assert!(
            loaded.uses_crt(),
            "the loader built a key without CRT parameters, so every signature \
             it makes costs several times what it should"
        );

        // The contrast that makes the assertion above mean something: handed no
        // primes, the same function returns a key that cannot use the CRT, so
        // `uses_crt` distinguishes the two paths rather than always being true.
        let without_primes = rsa_key_from(&modulus, e, &d, &[], &[]).unwrap();
        assert!(
            !without_primes.uses_crt(),
            "the n/e/d fallback should not carry CRT parameters"
        );

        // And the two must sign identically, since the fallback is a real path
        // and not merely a slower wrong answer.
        let mut a = alloc::vec![0u8; loaded.size()];
        let mut b = alloc::vec![0u8; without_primes.size()];
        ic_rsa::Pkcs1Sha256::sign(&loaded, b"message", &mut a).unwrap();
        ic_rsa::Pkcs1Sha256::sign(&without_primes, b"message", &mut b).unwrap();
        assert_eq!(a, b, "the CRT and non-CRT paths disagreed");
    }

    /// A key whose primes do not match its stated modulus is refused.
    ///
    /// Such a file is not the key the certificate names. Loading it would give
    /// a signer whose signatures verify against nothing, and the failure would
    /// surface at the peer rather than here.
    #[test]
    fn an_rsa_key_whose_primes_contradict_its_modulus_is_refused() {
        let key = rsa_key();
        let half = key.size() / 2;
        let (mut p, mut q) = (alloc::vec![0u8; half], alloc::vec![0u8; half]);
        let (mut dp, mut dq, mut qinv) = (
            alloc::vec![0u8; half],
            alloc::vec![0u8; half],
            alloc::vec![0u8; half],
        );
        let (mut modulus, mut d) = (alloc::vec![0u8; key.size()], alloc::vec![0u8; key.size()]);
        key.prime_bytes(&mut p, &mut q).unwrap();
        key.crt_exponent_bytes(&mut dp, &mut dq, &mut qinv).unwrap();
        key.exponent_bytes(&mut d).unwrap();
        key.public_key().modulus_bytes(&mut modulus).unwrap();

        // A modulus from a *different* key, so the primes no longer describe it.
        let mut other = ic_drbg::Rng::from_os().unwrap();
        let other_key = ic_rsa::generate(2048, &mut other).unwrap();
        let mut other_modulus = alloc::vec![0u8; other_key.size()];
        other_key
            .public_key()
            .modulus_bytes(&mut other_modulus)
            .unwrap();

        let mut der = alloc::vec![0u8; 4096];
        let n = ic_pkix::PrivateKeyInfo::Rsa {
            modulus: &other_modulus,
            public_exponent: key.public_key().exponent(),
            private_exponent: &d,
            prime1: &p,
            prime2: &q,
            exponent1: &dp,
            exponent2: &dq,
            coefficient: &qinv,
        }
        .to_der(&mut der)
        .unwrap();
        der.truncate(n);

        let err = Keys
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
            .expect_err("a key whose primes contradict its modulus was accepted");
        let text = format!("{err}");
        assert!(
            text.contains("modulus"),
            "the refusal should say what was wrong: {text}"
        );

        // The same construction with the matching modulus loads, so the
        // rejection is about the mismatch and not about this encoding path.
        assert!(Keys.load_private_key(rsa_pkcs8(key)).is_ok());
    }

    /// An RSA key must not offer a scheme the peer did not, and an ECDSA-only
    /// offer must not be answered by an RSA key.
    #[test]
    fn an_rsa_key_only_chooses_an_offered_rsa_scheme() {
        let key = Keys.load_private_key(rsa_pkcs8(rsa_key())).unwrap();

        assert!(key.choose_scheme(&[]).is_none());
        assert!(key
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519
            ])
            .is_none());

        // Preference is this crate's, not the peer's order: offered both, PSS
        // wins over PKCS#1 v1.5.
        let signer = key
            .choose_scheme(&[
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
            ])
            .expect("one of the two should be chosen");
        assert_eq!(
            signer.scheme(),
            SignatureScheme::RSA_PSS_SHA256,
            "PKCS#1 v1.5 was chosen where PSS was also on offer"
        );
    }

    /// Two PSS signatures over one message must differ.
    ///
    /// PSS is randomized. Two identical signatures would mean the salt is not
    /// fresh, which is the failure that makes PSS no better than v1.5.
    #[test]
    fn pss_signatures_are_randomized() {
        let key = Keys.load_private_key(rsa_pkcs8(rsa_key())).unwrap();
        let signer = key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        let a = signer.sign(b"one message").unwrap();
        let b = signer.sign(b"one message").unwrap();
        assert_ne!(a, b, "two PSS signatures over one message were identical");

        // Whereas PKCS#1 v1.5 is deterministic, so this is a property of the
        // padding and not of the test happening to compare different things.
        let signer = key
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
            .unwrap();
        let a = signer.sign(b"one message").unwrap();
        let b = signer.sign(b"one message").unwrap();
        assert_eq!(a, b, "PKCS#1 v1.5 should be deterministic");
    }
}
