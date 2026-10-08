//! Signing through an interface, so a key need not be in memory.
//!
//! The signature schemes in this library take a private key as bytes. That is
//! the wrong shape for a key held in an HSM, a TPM or a cloud key service,
//! where the caller has a handle and the device does the arithmetic. [`Signer`]
//! is the shape both fit: name the algorithm, pass the message, get a
//! signature. A TLS handshake or a certificate issuer written against it does
//! not know or care where the key lives; [`Signer::custody`] is there for the
//! callers that must.
//!
//! This crate defines the interface and nothing that implements it. Software
//! keys and the hardware backends are other crates'; verification, which needs
//! no private key, is `ic_sig::verify`.
//!
//! # Encodings
//!
//! Public keys are DER `SubjectPublicKeyInfo`. Signatures are in the form
//! X.509 and TLS 1.3 both carry: an ASN.1 `Ecdsa-Sig-Value` for ECDSA, and the
//! algorithm's own bytes for Ed25519, RSA and ML-DSA. One encoding at the
//! interface means a signer written for certificates serves a handshake
//! unchanged.

use crate::traits::RandomSource;
use crate::Result;

/// A signature algorithm: the key type and everything that goes with it.
///
/// Each names one entry in the ontology, by [`SignatureAlgorithm::id`]. RSA
/// keys serve several of these; every other key serves exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA over P-384 with SHA-384.
    EcdsaP384Sha384,
    /// ECDSA over P-521 with SHA-512.
    EcdsaP521Sha512,
    /// Ed25519.
    Ed25519,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384, MGF1-SHA-384 and a 48-byte salt.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512, MGF1-SHA-512 and a 64-byte salt.
    RsaPssSha512,
    /// ML-DSA-44 (FIPS 204), pure, with an empty context.
    MlDsa44,
    /// ML-DSA-65 (FIPS 204), pure, with an empty context.
    MlDsa65,
    /// ML-DSA-87 (FIPS 204), pure, with an empty context.
    MlDsa87,
}

impl SignatureAlgorithm {
    /// Every algorithm, for callers that enumerate them.
    pub const ALL: &'static [SignatureAlgorithm] = &[
        Self::EcdsaP256Sha256,
        Self::EcdsaP384Sha384,
        Self::EcdsaP521Sha512,
        Self::Ed25519,
        Self::RsaPkcs1Sha256,
        Self::RsaPkcs1Sha384,
        Self::RsaPkcs1Sha512,
        Self::RsaPssSha256,
        Self::RsaPssSha384,
        Self::RsaPssSha512,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    /// The ontology identifier of the algorithm.
    pub const fn id(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Self::EcdsaP521Sha512 => "ecdsa-p521-sha512",
            Self::Ed25519 => "ed25519",
            Self::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
            Self::RsaPkcs1Sha384 => "rsa-pkcs1-sha384",
            Self::RsaPkcs1Sha512 => "rsa-pkcs1-sha512",
            Self::RsaPssSha256 => "rsa-pss-sha256",
            Self::RsaPssSha384 => "rsa-pss-sha384",
            Self::RsaPssSha512 => "rsa-pss-sha512",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }

    /// The algorithm an ontology identifier names, if it is one of these.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.id() == id)
    }

    /// The longest signature the algorithm produces, in the encoding this
    /// module's interface uses: a buffer this long always suffices.
    ///
    /// ECDSA is the DER `Ecdsa-Sig-Value`, whose length varies with the
    /// leading bits of `r` and `s`. RSA is for the largest modulus this
    /// library accepts, 4096 bits.
    pub const fn max_signature_len(self) -> usize {
        match self {
            // SEQUENCE { INTEGER, INTEGER }, each integer one byte longer
            // than the scalar when its top bit is set.
            Self::EcdsaP256Sha256 => 72,
            Self::EcdsaP384Sha384 => 104,
            Self::EcdsaP521Sha512 => 139,
            Self::Ed25519 => 64,
            Self::RsaPkcs1Sha256
            | Self::RsaPkcs1Sha384
            | Self::RsaPkcs1Sha512
            | Self::RsaPssSha256
            | Self::RsaPssSha384
            | Self::RsaPssSha512 => 512,
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// Where a private key lives, as far as its holder can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Custody {
    /// In this process's memory.
    Software,
    /// In a hardware device -- an HSM, a TPM, a smart card -- that performs the
    /// operation itself.
    Hardware,
    /// In a remote service that performs the operation, such as a cloud key
    /// management service.
    Service,
}

impl Custody {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Hardware => "hardware",
            Self::Service => "service",
        }
    }
}

/// A private key that can sign, wherever it is held.
///
/// Object-safe: protocols hold a `&dyn Signer` or box one.
///
/// # What an implementation promises
///
/// - [`sign`](Signer::sign) signs `message` itself, not a digest of it: the
///   algorithm names its own hash.
/// - It writes nothing past the length it returns, and allocates only if the
///   implementation must, so a software signer can serve a caller that may not
///   allocate.
/// - It refuses, rather than substitutes, an algorithm it did not list in
///   [`algorithms`](Signer::algorithms).
///
/// # Blocking
///
/// `sign` returns when the signature exists. For a key in a remote service that
/// is a network round trip made inside the call; a caller that cannot block
/// needs to run it elsewhere and is not served by this interface alone.
pub trait Signer {
    /// The algorithms this key signs with, in the holder's order of preference.
    fn algorithms(&self) -> &[SignatureAlgorithm];

    /// The public key, as a DER `SubjectPublicKeyInfo`.
    fn public_key(&self) -> &[u8];

    /// Where the private key lives.
    fn custody(&self) -> Custody;

    /// Sign `message` with `algorithm`, writing the signature to the front of
    /// `out` and returning its length.
    ///
    /// `rng` supplies randomness for the algorithms that use it; a device that
    /// draws its own ignores it. `out` shorter than the signature is refused
    /// with `InvalidLength`; [`SignatureAlgorithm::max_signature_len`] is
    /// always long enough.
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_round_trip() {
        for (i, a) in SignatureAlgorithm::ALL.iter().enumerate() {
            assert_eq!(SignatureAlgorithm::from_id(a.id()), Some(*a));
            assert!(SignatureAlgorithm::ALL[..i]
                .iter()
                .all(|b| b.id() != a.id()));
        }
        assert_eq!(SignatureAlgorithm::from_id("ecdsa-p256-sha1"), None);
    }

    /// The trait is object-safe, which is the property protocols rely on.
    #[test]
    fn a_signer_can_be_a_trait_object() {
        struct Fixed;
        impl Signer for Fixed {
            fn algorithms(&self) -> &[SignatureAlgorithm] {
                &[SignatureAlgorithm::Ed25519]
            }
            fn public_key(&self) -> &[u8] {
                &[]
            }
            fn custody(&self) -> Custody {
                Custody::Hardware
            }
            fn sign(
                &self,
                _: SignatureAlgorithm,
                _: &[u8],
                _: &mut dyn RandomSource,
                out: &mut [u8],
            ) -> Result<usize> {
                out[0] = 7;
                Ok(1)
            }
        }
        struct NoRng;
        impl RandomSource for NoRng {
            fn fill(&mut self, _: &mut [u8]) -> Result<()> {
                Ok(())
            }
        }
        let signer: &dyn Signer = &Fixed;
        let mut out = [0u8; 4];
        assert_eq!(
            signer
                .sign(SignatureAlgorithm::Ed25519, b"m", &mut NoRng, &mut out)
                .unwrap(),
            1
        );
        assert_eq!(signer.custody().id(), "hardware");
    }
}
