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
//! This crate defines the interface and nothing that implements it. A key
//! held in memory signs through `ic_sig::SoftwareSigner`; the hardware and
//! service backends are other crates'; verification, which needs no private
//! key, is `ic_sig::verify`.
//!
//! # Encodings
//!
//! Public keys are DER `SubjectPublicKeyInfo`. Signatures are in the form
//! X.509 and TLS 1.3 both carry: an ASN.1 `Ecdsa-Sig-Value` for ECDSA, and the
//! algorithm's own bytes for Ed25519, RSA, ML-DSA, SLH-DSA and HSS/LMS. One
//! encoding at the
//! interface means a signer written for certificates serves a handshake
//! unchanged.

use crate::traits::RandomSource;
use crate::Result;

/// A signature algorithm: the key type and everything that goes with it.
///
/// Each names one entry in the ontology, by [`SignatureAlgorithm::id`] --
/// except the twelve SLH-DSA parameter sets, which share the entry `slh-dsa`
/// and are named as its sets are. RSA keys serve several of these; every other
/// key serves exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
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
    /// HSS/LMS (RFC 8554, SP 800-208). The key names its own parameters, and
    /// the hash function with them.
    HssLms,
    /// SLH-DSA-SHA2-128s (FIPS 205), pure, with an empty context.
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f (FIPS 205), pure, with an empty context.
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s (FIPS 205), pure, with an empty context.
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f (FIPS 205), pure, with an empty context.
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s (FIPS 205), pure, with an empty context.
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f (FIPS 205), pure, with an empty context.
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-128s (FIPS 205), pure, with an empty context.
    SlhDsaShake_128s,
    /// SLH-DSA-SHAKE-128f (FIPS 205), pure, with an empty context.
    SlhDsaShake_128f,
    /// SLH-DSA-SHAKE-192s (FIPS 205), pure, with an empty context.
    SlhDsaShake_192s,
    /// SLH-DSA-SHAKE-192f (FIPS 205), pure, with an empty context.
    SlhDsaShake_192f,
    /// SLH-DSA-SHAKE-256s (FIPS 205), pure, with an empty context.
    SlhDsaShake_256s,
    /// SLH-DSA-SHAKE-256f (FIPS 205), pure, with an empty context.
    SlhDsaShake_256f,
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
        Self::HssLms,
        Self::SlhDsaSha2_128s,
        Self::SlhDsaSha2_128f,
        Self::SlhDsaSha2_192s,
        Self::SlhDsaSha2_192f,
        Self::SlhDsaSha2_256s,
        Self::SlhDsaSha2_256f,
        Self::SlhDsaShake_128s,
        Self::SlhDsaShake_128f,
        Self::SlhDsaShake_192s,
        Self::SlhDsaShake_192f,
        Self::SlhDsaShake_256s,
        Self::SlhDsaShake_256f,
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
            Self::HssLms => "hss-lms",
            Self::SlhDsaSha2_128s => "slh-dsa-sha2-128s",
            Self::SlhDsaSha2_128f => "slh-dsa-sha2-128f",
            Self::SlhDsaSha2_192s => "slh-dsa-sha2-192s",
            Self::SlhDsaSha2_192f => "slh-dsa-sha2-192f",
            Self::SlhDsaSha2_256s => "slh-dsa-sha2-256s",
            Self::SlhDsaSha2_256f => "slh-dsa-sha2-256f",
            Self::SlhDsaShake_128s => "slh-dsa-shake-128s",
            Self::SlhDsaShake_128f => "slh-dsa-shake-128f",
            Self::SlhDsaShake_192s => "slh-dsa-shake-192s",
            Self::SlhDsaShake_192f => "slh-dsa-shake-192f",
            Self::SlhDsaShake_256s => "slh-dsa-shake-256s",
            Self::SlhDsaShake_256f => "slh-dsa-shake-256f",
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
    /// library accepts, 4096 bits. HSS/LMS is for the largest parameters RFC
    /// 8554 allows -- eight levels, each a tree of height 25 at Winternitz
    /// width 1 with a 256-bit hash -- and most signatures are a small fraction
    /// of it.
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
            // u32(L - 1), then seven signed public keys of 56 bytes, then
            // eight LMS signatures of 12 + 32 + 265 * 32 + 25 * 32 bytes.
            Self::HssLms => 74988,
            // FIPS 205 table 2.
            Self::SlhDsaSha2_128s | Self::SlhDsaShake_128s => 7856,
            Self::SlhDsaSha2_128f | Self::SlhDsaShake_128f => 17088,
            Self::SlhDsaSha2_192s | Self::SlhDsaShake_192s => 16224,
            Self::SlhDsaSha2_192f | Self::SlhDsaShake_192f => 35664,
            Self::SlhDsaSha2_256s | Self::SlhDsaShake_256s => 29792,
            Self::SlhDsaSha2_256f | Self::SlhDsaShake_256f => 49856,
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
/// Object-safe, and `Send + Sync`: a server shares one key between the
/// connections it is serving at once, so a signer that could not cross threads
/// would be unusable exactly where a signer is most needed. Signing takes
/// `&self` for the same reason; a signer with state to change guards it itself.
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
pub trait Signer: Send + Sync {
    /// The algorithms this key signs with, most preferred first.
    ///
    /// The order is meaningful: a protocol negotiating an algorithm takes the
    /// first one here that its peer and its policy also allow. Listing an
    /// algorithm is a statement about the key, not about any protocol -- an
    /// RSA key may list PKCS#1 v1.5 for the certificates it signs, and a TLS
    /// 1.3 handshake still will not use it.
    fn algorithms(&self) -> &[SignatureAlgorithm];

    /// The public key, as a DER `SubjectPublicKeyInfo`.
    ///
    /// These must be the bytes the key's certificate carries, not a
    /// re-encoding of the same key: callers compare the two byte for byte to
    /// check that a certificate and a signer belong together. A signer for a
    /// remote key reads this once, when it is made.
    fn public_key(&self) -> &[u8];

    /// Where the private key lives.
    fn custody(&self) -> Custody;

    /// Sign `message` with `algorithm`, writing the signature to the front of
    /// `out` and returning its length.
    ///
    /// `rng` supplies randomness for the algorithms that use it; a device that
    /// draws its own ignores it. `out` shorter than the signature is refused
    /// with `InvalidLength`, with nothing written and nothing consumed;
    /// [`SignatureAlgorithm::max_signature_len`] is always long enough. An
    /// algorithm not in [`algorithms`](Signer::algorithms) is refused with
    /// `InvalidParameter`.
    ///
    /// A key held elsewhere fails in two ways a key in memory does not, and
    /// each has a kind: `ProviderUnavailable` when its holder could not be
    /// reached or could not answer, and `ProviderRefused` when it answered
    /// no. They differ in whether a retry is safe.
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
        // Shared across threads, as a server shares its key.
        fn shareable<T: Send + Sync + ?Sized>(_: &T) {}
        let signer: &dyn Signer = &Fixed;
        shareable(signer);
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
