//! Signature verification by algorithm, over the public keys certificates
//! carry.
//!
//! Each signature scheme in IronCrypto verifies through its own type, with its
//! own key and signature encodings. A protocol does not think that way: a
//! certificate or a TLS handshake names an algorithm and hands over a
//! `SubjectPublicKeyInfo`, a message and a signature. [`verify`] is that one
//! call, for every algorithm in [`SignatureAlgorithm`].
//!
//! ```
//! # fn main() -> ic_core::Result<()> {
//! use ic_core::sig::SignatureAlgorithm;
//! use ic_core::traits::SignatureScheme;
//! use ic_sig::PublicKey;
//!
//! // An Ed25519 key and signature, made here for the example.
//! let seed = [7u8; 32];
//! let mut raw_public = [0u8; 32];
//! ic_ec::Ed25519::public_key(&seed, &mut raw_public)?;
//! let mut signature = [0u8; 64];
//! ic_ec::Ed25519::sign(&seed, b"message", &mut signature)?;
//!
//! // What a certificate carries: the key as a SubjectPublicKeyInfo.
//! let mut spki = [0u8; 64];
//! let n = ic_pkix::PublicKeyInfo::Ed25519(&raw_public).to_der(&mut spki)?;
//!
//! let key = PublicKey::from_spki(&spki[..n])?;
//! ic_sig::verify(SignatureAlgorithm::Ed25519, &key, b"message", &signature)?;
//! assert!(ic_sig::verify(SignatureAlgorithm::Ed25519, &key, b"other", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Encodings
//!
//! Signatures are in the form X.509 and TLS 1.3 carry: a DER
//! `Ecdsa-Sig-Value` for ECDSA, and the algorithm's own bytes for Ed25519,
//! RSA, ML-DSA, SLH-DSA and HSS/LMS. ML-DSA and SLH-DSA are the pure variants
//! with an empty context, as RFC 9881 and RFC 9909 specify for certificates.
//!
//! # Hash-based signatures
//!
//! An HSS/LMS key is read per RFC 9708 and an SLH-DSA key per RFC 9909. Two
//! things about them differ from every other key here. An HSS/LMS key names
//! its own parameter set, so one algorithm covers them all and
//! [`PublicKey::classical_bits`] reads the strength from the key. And RFC
//! 9909's twelve pre-hash key types, `id-hash-slh-dsa-*`, are not read: a key
//! of one is `Unsupported`. `ic_slhdsa::hash_verify` verifies such a
//! signature for a caller that has the key bytes.
//!
//! # What the result tells an attacker
//!
//! A signature that does not verify is `AuthenticationFailed`, whether it was
//! malformed, the wrong length or simply wrong: the three are not
//! distinguished, since the signature is the attacker's to choose. A key that
//! cannot be used with the algorithm named is `InvalidParameter`, which is a
//! fact about the caller's request and is reported as one.
//!
//! # Policy this does not hold
//!
//! Which algorithms a protocol accepts where -- TLS 1.3 allows PKCS#1 v1.5 on
//! certificates and refuses it in a handshake -- is the protocol's rule, not
//! this crate's. It verifies what it is asked to.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use ic_core::sig::SignatureAlgorithm;
use ic_core::traits::SignatureScheme;
use ic_core::{ensure, err, Result};
use ic_pkix::der::Reader;
use ic_pkix::{oid, KeyAlgorithm, PublicKeyInfo};

/// The largest RSA public exponent accepted, `2^32 - 1`.
///
/// Verification costs a modular exponentiation whose length is the peer's to
/// choose: an exponent of `2^64 - 1` costs several times what 65537 does.
/// Certificates use 65537, so nothing legitimate is refused by this.
pub const MAX_RSA_EXPONENT: u64 = u32::MAX as u64;

/// A public key parsed from a `SubjectPublicKeyInfo`, borrowing from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKey<'a> {
    /// P-256, SEC1 uncompressed, 65 bytes.
    EcP256(&'a [u8]),
    /// P-384, SEC1 uncompressed, 97 bytes.
    EcP384(&'a [u8]),
    /// P-521, SEC1 uncompressed, 133 bytes.
    EcP521(&'a [u8]),
    /// Ed25519, 32 bytes.
    Ed25519(&'a [u8]),
    /// RSA: the modulus, big-endian, and the exponent.
    Rsa {
        /// Big-endian modulus.
        modulus: &'a [u8],
        /// Public exponent.
        exponent: u64,
    },
    /// ML-DSA-44, 1312 bytes.
    MlDsa44(&'a [u8]),
    /// ML-DSA-65, 1952 bytes.
    MlDsa65(&'a [u8]),
    /// ML-DSA-87, 2592 bytes.
    MlDsa87(&'a [u8]),
    /// HSS/LMS: `u32(L) || lms_public_key`, 52 or 60 bytes.
    HssLms(&'a [u8]),
    /// SLH-DSA: the parameter set, and `PK.seed || PK.root`, 32 to 64 bytes.
    SlhDsa(ic_slhdsa::ParameterSet, &'a [u8]),
}

/// The SLH-DSA parameter set an algorithm names, if it names one.
const fn slh_dsa_set(algorithm: SignatureAlgorithm) -> Option<ic_slhdsa::ParameterSet> {
    use ic_slhdsa::ParameterSet as P;
    use SignatureAlgorithm as A;
    Some(match algorithm {
        A::SlhDsaSha2_128s => P::Sha2_128s,
        A::SlhDsaSha2_128f => P::Sha2_128f,
        A::SlhDsaSha2_192s => P::Sha2_192s,
        A::SlhDsaSha2_192f => P::Sha2_192f,
        A::SlhDsaSha2_256s => P::Sha2_256s,
        A::SlhDsaSha2_256f => P::Sha2_256f,
        A::SlhDsaShake_128s => P::Shake_128s,
        A::SlhDsaShake_128f => P::Shake_128f,
        A::SlhDsaShake_192s => P::Shake_192s,
        A::SlhDsaShake_192f => P::Shake_192f,
        A::SlhDsaShake_256s => P::Shake_256s,
        A::SlhDsaShake_256f => P::Shake_256f,
        _ => return None,
    })
}

/// The SLH-DSA parameter set an object identifier names: RFC 9909 section 3.
fn slh_dsa_set_of_oid(id: &[u8]) -> Option<ic_slhdsa::ParameterSet> {
    use ic_slhdsa::ParameterSet as P;
    const TABLE: [(&[u8], P); 12] = [
        (oid::SLH_DSA_SHA2_128S, P::Sha2_128s),
        (oid::SLH_DSA_SHA2_128F, P::Sha2_128f),
        (oid::SLH_DSA_SHA2_192S, P::Sha2_192s),
        (oid::SLH_DSA_SHA2_192F, P::Sha2_192f),
        (oid::SLH_DSA_SHA2_256S, P::Sha2_256s),
        (oid::SLH_DSA_SHA2_256F, P::Sha2_256f),
        (oid::SLH_DSA_SHAKE_128S, P::Shake_128s),
        (oid::SLH_DSA_SHAKE_128F, P::Shake_128f),
        (oid::SLH_DSA_SHAKE_192S, P::Shake_192s),
        (oid::SLH_DSA_SHAKE_192F, P::Shake_192f),
        (oid::SLH_DSA_SHAKE_256S, P::Shake_256s),
        (oid::SLH_DSA_SHAKE_256F, P::Shake_256f),
    ];
    TABLE.iter().find(|(o, _)| *o == id).map(|(_, set)| *set)
}

impl<'a> PublicKey<'a> {
    /// Parse a DER `SubjectPublicKeyInfo`.
    ///
    /// The classical algorithms are read by `ic_pkix`, with its checks: RSA's
    /// parameters present and `NULL`, an EC point uncompressed and of its
    /// curve's length. ML-DSA, which `ic_pkix::PublicKeyInfo` does not name,
    /// is read here per RFC 9881: no parameters, and a key of exactly the
    /// parameter set's length. SLH-DSA is read per RFC 9909 the same way, and
    /// HSS/LMS per RFC 9708: no parameters, and a key whose own typecodes
    /// `ic_lms` knows. A key `ic_pkix` refuses is not given a second reading.
    ///
    /// Two failures, kept apart because a protocol answers them differently: a
    /// structure that is not a valid `SubjectPublicKeyInfo` is
    /// `MalformedEncoding`, and a well-formed one this library cannot verify
    /// with -- an X25519 key, an unimplemented algorithm or curve, a compressed
    /// EC point -- is `Unsupported`.
    pub fn from_spki(spki: &'a [u8]) -> Result<Self> {
        match PublicKeyInfo::from_der(spki)? {
            PublicKeyInfo::Rsa { modulus, exponent } => Ok(Self::Rsa { modulus, exponent }),
            PublicKeyInfo::Ec { algorithm, point } => match algorithm {
                KeyAlgorithm::EcP256 => Ok(Self::EcP256(point)),
                KeyAlgorithm::EcP384 => Ok(Self::EcP384(point)),
                KeyAlgorithm::EcP521 => Ok(Self::EcP521(point)),
                _ => Err(err!(Unsupported, "public key on an unsupported curve")),
            },
            PublicKeyInfo::Ed25519(key) => Ok(Self::Ed25519(key)),
            PublicKeyInfo::Unsupported { .. } => Self::post_quantum_from_spki(spki),
            _ => Err(err!(Unsupported, "not a signature verification key")),
        }
    }

    /// The ML-DSA, SLH-DSA or HSS/LMS reading of a `SubjectPublicKeyInfo`
    /// `ic_pkix` did not name.
    fn post_quantum_from_spki(spki: &'a [u8]) -> Result<Self> {
        let mut outer = Reader::new(spki);
        let mut body = outer.sequence()?;
        outer.finish()?;
        let mut algorithm = body.sequence()?;
        let id = algorithm.oid()?;
        // RFC 9881 section 2, RFC 9909 section 3 and RFC 9708 section 4: the
        // parameters field is absent.
        let parameters_absent = algorithm.finish().is_ok();
        let key = body.bit_string()?;
        body.finish()?;

        if let Some(set) = slh_dsa_set_of_oid(id) {
            ensure!(
                parameters_absent,
                MalformedEncoding,
                "slh-dsa public key with parameters"
            );
            ensure!(
                key.len() == set.public_key_len(),
                MalformedEncoding,
                "slh-dsa public key length"
            );
            return Ok(Self::SlhDsa(set, key));
        }
        if id == oid::HSS_LMS {
            ensure!(
                parameters_absent,
                MalformedEncoding,
                "hss/lms public key with parameters"
            );
            // Malformed, or of a parameter set that is not implemented: each
            // is reported as `ic_lms` reports it.
            ic_lms::parameters(key)?;
            return Ok(Self::HssLms(key));
        }

        let (len, make): (usize, fn(&'a [u8]) -> Self) = if id == oid::ML_DSA_44 {
            (ic_mldsa::sign44::PUBLIC_KEY_LEN, Self::MlDsa44)
        } else if id == oid::ML_DSA_65 {
            (ic_mldsa::sign::PUBLIC_KEY_LEN, Self::MlDsa65)
        } else if id == oid::ML_DSA_87 {
            (ic_mldsa::sign87::PUBLIC_KEY_LEN, Self::MlDsa87)
        } else {
            return Err(err!(Unsupported, "public key algorithm not implemented"));
        };
        ensure!(
            parameters_absent,
            MalformedEncoding,
            "ml-dsa public key with parameters"
        );
        ensure!(
            key.len() == len,
            MalformedEncoding,
            "ml-dsa public key length"
        );
        Ok(make(key))
    }

    /// The kind of key: `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`,
    /// `rsa`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `hss-lms`, or an SLH-DSA
    /// parameter set such as `slh-dsa-sha2-128s`. For reports.
    #[must_use = "the key's kind; discarding it reports nothing"]
    pub const fn kind_id(&self) -> &'static str {
        match self {
            Self::EcP256(_) => "ecdsa-p256",
            Self::EcP384(_) => "ecdsa-p384",
            Self::EcP521(_) => "ecdsa-p521",
            Self::Ed25519(_) => "ed25519",
            Self::Rsa { .. } => "rsa",
            Self::MlDsa44(_) => "ml-dsa-44",
            Self::MlDsa65(_) => "ml-dsa-65",
            Self::MlDsa87(_) => "ml-dsa-87",
            Self::HssLms(_) => "hss-lms",
            Self::SlhDsa(set, _) => set.id(),
        }
    }

    /// The size of an RSA modulus in bits, leading zero bytes and bits not
    /// counted; `None` for every other key.
    #[must_use = "the modulus size; discarding it checks nothing"]
    pub fn rsa_bits(&self) -> Option<usize> {
        let Self::Rsa { modulus, .. } = self else {
            return None;
        };
        let significant = modulus.iter().position(|b| *b != 0)?;
        let top = modulus[significant];
        Some((modulus.len() - significant) * 8 - top.leading_zeros() as usize)
    }

    /// Security strength against a classical adversary, in bits, as the
    /// ontology records it for the key's algorithms.
    ///
    /// RSA's depends on the modulus, by SP 800-57 Part 1 table 2: 112 from
    /// 2048 bits, 128 from 3072, 192 from 7680, 256 from 15360, and 0 below
    /// 2048, which nothing here verifies with. SLH-DSA's is its parameter
    /// set's category, and HSS/LMS's the output length of the hash its key
    /// names -- 192 or 256 -- or 0 for a key `ic_lms` cannot read.
    #[must_use = "the key's strength; discarding it enforces no minimum"]
    pub fn classical_bits(&self) -> u16 {
        match self {
            Self::EcP256(_) | Self::Ed25519(_) | Self::MlDsa44(_) => 128,
            Self::EcP384(_) | Self::MlDsa65(_) => 192,
            Self::EcP521(_) | Self::MlDsa87(_) => 256,
            Self::SlhDsa(set, _) => match set.category() {
                1 => 128,
                3 => 192,
                _ => 256,
            },
            Self::HssLms(key) => match ic_lms::parameters(key) {
                Ok(p) => 8 * p.hash.output_len() as u16,
                Err(_) => 0,
            },
            Self::Rsa { .. } => match self.rsa_bits().unwrap_or(0) {
                0..=2047 => 0,
                2048..=3071 => 112,
                3072..=7679 => 128,
                7680..=15359 => 192,
                _ => 256,
            },
        }
    }

    /// Whether this key can verify a signature made with `algorithm`.
    ///
    /// An RSA key serves all six RSA algorithms; every other key serves the
    /// one algorithm of its type, and an SLH-DSA key that of its parameter
    /// set.
    #[must_use = "whether the key serves the algorithm; discarding it checks nothing"]
    pub fn supports(&self, algorithm: SignatureAlgorithm) -> bool {
        use SignatureAlgorithm as A;
        if let Self::SlhDsa(set, _) = self {
            return slh_dsa_set(algorithm) == Some(*set);
        }
        matches!(
            (self, algorithm),
            (Self::EcP256(_), A::EcdsaP256Sha256)
                | (Self::EcP384(_), A::EcdsaP384Sha384)
                | (Self::EcP521(_), A::EcdsaP521Sha512)
                | (Self::Ed25519(_), A::Ed25519)
                | (Self::MlDsa44(_), A::MlDsa44)
                | (Self::MlDsa65(_), A::MlDsa65)
                | (Self::MlDsa87(_), A::MlDsa87)
                | (Self::HssLms(_), A::HssLms)
                | (
                    Self::Rsa { .. },
                    A::RsaPkcs1Sha256
                        | A::RsaPkcs1Sha384
                        | A::RsaPkcs1Sha512
                        | A::RsaPssSha256
                        | A::RsaPssSha384
                        | A::RsaPssSha512
                )
        )
    }
}

/// Verify `signature` over `message` with `key` under `algorithm`.
///
/// `Ok(())` means the signature is valid. `AuthenticationFailed` means it is
/// not, for any reason to do with the signature. `InvalidParameter` means
/// `key` is not a key for `algorithm`, and `Unsupported` that an RSA key is
/// one this library does not accept -- outside its sizes, or with an exponent
/// above [`MAX_RSA_EXPONENT`] -- or an HSS/LMS key of a parameter set it does
/// not implement.
pub fn verify(
    algorithm: SignatureAlgorithm,
    key: &PublicKey<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use SignatureAlgorithm as A;
    ensure!(
        key.supports(algorithm),
        InvalidParameter,
        "signature algorithm does not match the key"
    );
    // Each family verifies in its own out-of-line function, so this frame
    // reserves none of their state: with every verifier inlined, a small
    // target pays for the largest of them on every call.
    match (*key, algorithm) {
        (PublicKey::EcP256(pk), _) => verify_p256(pk, message, signature),
        (PublicKey::EcP384(pk), _) => verify_p384(pk, message, signature),
        (PublicKey::EcP521(pk), _) => verify_p521(pk, message, signature),
        (PublicKey::Ed25519(pk), _) => verify_ed25519(pk, message, signature),
        (PublicKey::MlDsa44(pk), _) => verify_ml_dsa_44(pk, message, signature),
        (PublicKey::MlDsa65(pk), _) => verify_ml_dsa_65(pk, message, signature),
        (PublicKey::MlDsa87(pk), _) => verify_ml_dsa_87(pk, message, signature),
        (PublicKey::HssLms(pk), _) => verify_hss_lms(pk, message, signature),
        (PublicKey::SlhDsa(set, pk), _) => verify_slh_dsa(set, pk, message, signature),
        (PublicKey::Rsa { modulus, exponent }, a) => {
            debug_assert!(matches!(
                a,
                A::RsaPkcs1Sha256
                    | A::RsaPkcs1Sha384
                    | A::RsaPkcs1Sha512
                    | A::RsaPssSha256
                    | A::RsaPssSha384
                    | A::RsaPssSha512
            ));
            verify_rsa(a, modulus, exponent, message, signature)
        }
    }
}

/// [`verify`] for a key still in its `SubjectPublicKeyInfo`.
pub fn verify_spki(
    algorithm: SignatureAlgorithm,
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify(algorithm, &PublicKey::from_spki(spki)?, message, signature)
}

/// Any failure to do with the signature is the same failure.
fn rejected<T>(result: Result<T>) -> Result<T> {
    result.map_err(|_| err!(AuthenticationFailed, "signature did not verify"))
}

#[inline(never)]
fn verify_p256(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let mut fixed = [0u8; 64];
    rejected(ic_pkix::ecdsa_signature::from_der(signature, &mut fixed))?;
    rejected(ic_ec::p256::EcdsaP256Sha256::verify(pk, message, &fixed))
}

#[inline(never)]
fn verify_p384(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let mut fixed = [0u8; 96];
    rejected(ic_pkix::ecdsa_signature::from_der(signature, &mut fixed))?;
    rejected(ic_ec::p384::EcdsaP384Sha384::verify(pk, message, &fixed))
}

#[inline(never)]
fn verify_p521(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let mut fixed = [0u8; 132];
    rejected(ic_pkix::ecdsa_signature::from_der(signature, &mut fixed))?;
    rejected(ic_ec::p521::EcdsaP521Sha512::verify(pk, message, &fixed))
}

#[inline(never)]
fn verify_ed25519(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    rejected(ic_ec::Ed25519::verify(pk, message, signature))
}

macro_rules! ml_dsa_verifier {
    ($name:ident, $set:ident) => {
        #[inline(never)]
        fn $name(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
            use ic_mldsa::$set as set;
            // The key's length was checked when it was parsed; a mismatch
            // here would be this crate's error, not the peer's.
            let pk: &[u8; set::PUBLIC_KEY_LEN] = pk
                .try_into()
                .map_err(|_| err!(Internal, "ml-dsa public key length"))?;
            let signature: &[u8; set::SIGNATURE_LEN] =
                rejected(signature.try_into().map_err(|_| err!(InvalidLength, "")))?;
            // Pure ML-DSA with an empty context: RFC 9881, and TLS 1.3's use.
            ensure!(
                set::verify(pk, message, b"", signature),
                AuthenticationFailed,
                "signature did not verify"
            );
            Ok(())
        }
    };
}

ml_dsa_verifier!(verify_ml_dsa_44, sign44);
ml_dsa_verifier!(verify_ml_dsa_65, sign);
ml_dsa_verifier!(verify_ml_dsa_87, sign87);

#[inline(never)]
fn verify_hss_lms(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    // What is wrong with the key is the key's fault and is reported as
    // `ic_lms` reports it; everything after that is the signature's.
    ic_lms::parameters(pk)?;
    rejected(ic_lms::verify(pk, message, signature))
}

#[inline(never)]
fn verify_slh_dsa(
    set: ic_slhdsa::ParameterSet,
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    // The key's length was checked when it was parsed; a mismatch here would
    // be this crate's error, not the peer's.
    ensure!(
        pk.len() == set.public_key_len(),
        Internal,
        "slh-dsa public key length"
    );
    // Pure SLH-DSA with an empty context: RFC 9909 section 1.
    rejected(ic_slhdsa::verify(set, pk, message, b"", signature))
}

#[inline(never)]
fn verify_rsa(
    algorithm: SignatureAlgorithm,
    modulus: &[u8],
    exponent: u64,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use SignatureAlgorithm as A;
    ensure!(
        exponent <= MAX_RSA_EXPONENT,
        Unsupported,
        "rsa public exponent above 2^32"
    );
    // Whatever the RSA implementation will not load -- a modulus outside its
    // sizes, an even one, an exponent it refuses -- is the key's fault, not the
    // signature's, and is reported as the key's.
    let key = ic_rsa::RsaPublicKey::from_components(modulus, exponent).map_err(|_| {
        err!(
            Unsupported,
            "rsa public key is not one this library accepts"
        )
    })?;
    rejected(match algorithm {
        A::RsaPkcs1Sha256 => ic_rsa::Pkcs1Sha256::verify(&key, message, signature),
        A::RsaPkcs1Sha384 => ic_rsa::Pkcs1Sha384::verify(&key, message, signature),
        A::RsaPkcs1Sha512 => ic_rsa::Pkcs1Sha512::verify(&key, message, signature),
        A::RsaPssSha256 => ic_rsa::PssSha256::verify(&key, message, signature),
        A::RsaPssSha384 => ic_rsa::PssSha384::verify(&key, message, signature),
        A::RsaPssSha512 => ic_rsa::PssSha512::verify(&key, message, signature),
        _ => return Err(err!(InvalidParameter, "not an rsa signature algorithm")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::ErrorKind;
    use ic_pkix::cert::{write_ml_dsa_public_key, SignatureAlgorithm as CertAlgorithm};
    use ic_pkix::der::Writer;

    fn kind<T: core::fmt::Debug>(r: Result<T>) -> ErrorKind {
        r.expect_err("must be refused").kind()
    }

    /// ML-DSA at every parameter set, through its `SubjectPublicKeyInfo`.
    /// OpenSSL's ML-DSA-65 and -87 signatures are checked in
    /// `ironcrypto/tests/sig.rs`; nothing there covers ML-DSA-44.
    #[test]
    fn ml_dsa_verifies_at_every_parameter_set() {
        macro_rules! case {
            ($set:ident, $alg:ident, $cert:ident) => {{
                use ic_mldsa::$set as set;
                let mut pk = [0u8; set::PUBLIC_KEY_LEN];
                let mut sk = [0u8; set::SECRET_KEY_LEN];
                assert!(set::keygen(&[3u8; 32], &mut pk, &mut sk));
                let mut sig = [0u8; set::SIGNATURE_LEN];
                assert!(set::sign(&sk, b"message", b"", &[0u8; 32], &mut sig));
                assert_eq!(
                    SignatureAlgorithm::$alg.max_signature_len(),
                    set::SIGNATURE_LEN
                );

                let mut spki = [0u8; 2700];
                let n = write_ml_dsa_public_key(CertAlgorithm::$cert, &pk, &mut spki).unwrap();
                let key = PublicKey::from_spki(&spki[..n]).unwrap();
                verify(SignatureAlgorithm::$alg, &key, b"message", &sig).unwrap();
                assert_eq!(
                    kind(verify(SignatureAlgorithm::$alg, &key, b"massage", &sig)),
                    ErrorKind::AuthenticationFailed
                );
                assert_eq!(
                    kind(verify(
                        SignatureAlgorithm::$alg,
                        &key,
                        b"message",
                        &sig[1..]
                    )),
                    ErrorKind::AuthenticationFailed
                );
                // A signature under a context is not one under none.
                assert!(set::sign(&sk, b"message", b"ctx", &[0u8; 32], &mut sig));
                assert_eq!(
                    kind(verify(SignatureAlgorithm::$alg, &key, b"message", &sig)),
                    ErrorKind::AuthenticationFailed
                );
            }};
        }
        case!(sign44, MlDsa44, MlDsa44);
        case!(sign, MlDsa65, MlDsa65);
        case!(sign87, MlDsa87, MlDsa87);
    }

    /// A `SubjectPublicKeyInfo` built by hand: the algorithm, then the key.
    fn spki(algorithm: &[u8], null_parameters: bool, key: &[u8], out: &mut [u8]) -> usize {
        let mut w = Writer::new(out);
        w.push_bit_string(key).unwrap();
        let start = w.len();
        if null_parameters {
            w.push_null().unwrap();
        }
        w.push_oid(algorithm).unwrap();
        w.push_wrapper(ic_pkix::der::SEQUENCE, start).unwrap();
        w.push_wrapper(ic_pkix::der::SEQUENCE, 0).unwrap();
        w.finish()
    }

    /// SLH-DSA through its `SubjectPublicKeyInfo`, for the six sets that sign
    /// quickly. OpenSSL's signatures for all twelve are checked in
    /// `ironcrypto/tests/sig.rs`.
    #[test]
    fn slh_dsa_verifies_through_its_spki() {
        use ic_slhdsa::ParameterSet as P;
        let fast = [
            (P::Sha2_128f, oid::SLH_DSA_SHA2_128F),
            (P::Sha2_192f, oid::SLH_DSA_SHA2_192F),
            (P::Sha2_256f, oid::SLH_DSA_SHA2_256F),
            (P::Shake_128f, oid::SLH_DSA_SHAKE_128F),
            (P::Shake_192f, oid::SLH_DSA_SHAKE_192F),
            (P::Shake_256f, oid::SLH_DSA_SHAKE_256F),
        ];
        for (set, id) in fast {
            let n = set.n();
            let seed = [5u8; 32];
            let (mut sk, mut pk) = ([0u8; 128], [0u8; 64]);
            let (sk, pk) = (&mut sk[..4 * n], &mut pk[..2 * n]);
            ic_slhdsa::keygen_internal(set, &seed[..n], &seed[..n], &seed[..n], sk, pk).unwrap();
            let mut sig = vec![0u8; set.signature_len()];
            ic_slhdsa::sign_deterministic(set, sk, b"message", b"", &mut sig).unwrap();

            let alg = SignatureAlgorithm::from_id(set.id()).unwrap();
            let mut buf = [0u8; 128];
            let len = spki(id, false, pk, &mut buf);
            let key = PublicKey::from_spki(&buf[..len]).unwrap();
            assert_eq!(key, PublicKey::SlhDsa(set, pk));
            verify(alg, &key, b"message", &sig).unwrap();
            assert_eq!(
                kind(verify(alg, &key, b"massage", &sig)),
                ErrorKind::AuthenticationFailed
            );
            assert_eq!(
                kind(verify(alg, &key, b"message", &sig[1..])),
                ErrorKind::AuthenticationFailed
            );
            // A signature under a context is not one under none, and a
            // pre-hash signature is not a pure one.
            ic_slhdsa::sign_deterministic(set, sk, b"message", b"ctx", &mut sig).unwrap();
            assert_eq!(
                kind(verify(alg, &key, b"message", &sig)),
                ErrorKind::AuthenticationFailed
            );
            ic_slhdsa::hash_sign_deterministic(
                set,
                sk,
                b"message",
                b"",
                ic_slhdsa::PreHash::Sha512,
                &mut sig,
            )
            .unwrap();
            assert_eq!(
                kind(verify(alg, &key, b"message", &sig)),
                ErrorKind::AuthenticationFailed
            );

            // RFC 9909 section 3: parameters are absent, and the key is the
            // set's length.
            let len = spki(id, true, pk, &mut buf);
            assert_eq!(
                kind(PublicKey::from_spki(&buf[..len])),
                ErrorKind::MalformedEncoding
            );
            let len = spki(id, false, &pk[1..], &mut buf);
            assert_eq!(
                kind(PublicKey::from_spki(&buf[..len])),
                ErrorKind::MalformedEncoding
            );
            // A key made by hand at the wrong length is not the peer's error.
            assert_eq!(
                kind(verify(alg, &PublicKey::SlhDsa(set, &pk[1..]), b"m", &sig)),
                ErrorKind::Internal
            );
        }
        // RFC 9909's pre-hash key types are not read.
        let id = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 35];
        let mut buf = [0u8; 128];
        let len = spki(&id, false, &[0u8; 32], &mut buf);
        assert_eq!(
            kind(PublicKey::from_spki(&buf[..len])),
            ErrorKind::Unsupported
        );
    }

    /// HSS/LMS through its `SubjectPublicKeyInfo`, with RFC 9858's A.1 case.
    #[test]
    fn hss_lms_verifies_through_its_spki() {
        let (pk, message, signature) = ic_lms::example();
        let alg = SignatureAlgorithm::HssLms;
        let mut buf = [0u8; 128];
        let len = spki(oid::HSS_LMS, false, &pk, &mut buf);
        let key = PublicKey::from_spki(&buf[..len]).unwrap();
        assert_eq!(key, PublicKey::HssLms(&pk));
        verify(alg, &key, &message, &signature).unwrap();
        assert!(signature.len() <= alg.max_signature_len());
        assert_eq!(
            kind(verify(alg, &key, &message[1..], &signature)),
            ErrorKind::AuthenticationFailed
        );
        for len in [0, 3, signature.len() - 1] {
            assert_eq!(
                kind(verify(alg, &key, &message, &signature[..len])),
                ErrorKind::AuthenticationFailed
            );
        }
        // The longest signature RFC 8554 allows: u32(L - 1), seven signed
        // public keys, and eight LMS signatures at height 25, width 1 and a
        // 256-bit hash.
        let lms_signature = 4 + (4 + 32 + 265 * 32) + 4 + 25 * 32;
        let lms_public_key = 4 + 4 + 16 + 32;
        assert_eq!(
            alg.max_signature_len(),
            4 + 7 * (lms_signature + lms_public_key) + lms_signature
        );

        // RFC 9708 section 4: parameters are absent.
        let len = spki(oid::HSS_LMS, true, &pk, &mut buf);
        assert_eq!(
            kind(PublicKey::from_spki(&buf[..len])),
            ErrorKind::MalformedEncoding
        );
        // A key that is not an HSS key is refused when it is read, and one
        // made by hand is refused as a key, not as a signature.
        let len = spki(oid::HSS_LMS, false, &pk[1..], &mut buf);
        assert!(PublicKey::from_spki(&buf[..len]).is_err());
        assert_ne!(
            kind(verify(
                alg,
                &PublicKey::HssLms(&pk[1..]),
                &message,
                &signature
            )),
            ErrorKind::AuthenticationFailed
        );
    }

    #[test]
    fn keys_that_cannot_verify_are_refused_as_what_they_are() {
        let mut buf = [0u8; 2700];
        // X25519 is a well-formed key that signs nothing.
        let n = PublicKeyInfo::X25519(&[9u8; 32]).to_der(&mut buf).unwrap();
        assert_eq!(
            kind(PublicKey::from_spki(&buf[..n])),
            ErrorKind::Unsupported
        );
        // An algorithm nobody here implements.
        let n = spki(&[0x2a, 0x03, 0x04], false, &[1, 2, 3], &mut buf);
        assert_eq!(
            kind(PublicKey::from_spki(&buf[..n])),
            ErrorKind::Unsupported
        );
        // ML-DSA with a NULL where RFC 9881 has nothing.
        let key = [0u8; ic_mldsa::sign::PUBLIC_KEY_LEN];
        let n = spki(oid::ML_DSA_65, true, &key, &mut buf);
        assert_eq!(
            kind(PublicKey::from_spki(&buf[..n])),
            ErrorKind::MalformedEncoding
        );
        // ML-DSA-65's identifier on a key of ML-DSA-44's length.
        let n = spki(
            oid::ML_DSA_65,
            false,
            &key[..ic_mldsa::sign44::PUBLIC_KEY_LEN],
            &mut buf,
        );
        assert_eq!(
            kind(PublicKey::from_spki(&buf[..n])),
            ErrorKind::MalformedEncoding
        );
        // And the same key, well-formed, is accepted.
        let n = spki(oid::ML_DSA_65, false, &key, &mut buf);
        assert!(matches!(
            PublicKey::from_spki(&buf[..n]),
            Ok(PublicKey::MlDsa65(_))
        ));
        // Trailing bytes after the structure, a truncated one, and nothing at
        // all: malformed, which is a different answer from unsupported.
        buf[n] = 0;
        for bad in [&buf[..n + 1], &buf[..n - 1], &buf[..0]] {
            assert_eq!(
                kind(PublicKey::from_spki(bad)),
                ErrorKind::MalformedEncoding
            );
        }
    }

    #[test]
    fn a_key_serves_only_its_own_algorithms() {
        let rsa = PublicKey::Rsa {
            modulus: &[],
            exponent: 65537,
        };
        let served = |k: &PublicKey| {
            SignatureAlgorithm::ALL
                .iter()
                .filter(|a| k.supports(**a))
                .count()
        };
        assert_eq!(served(&rsa), 6);
        for key in [
            PublicKey::EcP256(&[]),
            PublicKey::EcP384(&[]),
            PublicKey::EcP521(&[]),
            PublicKey::Ed25519(&[]),
            PublicKey::MlDsa44(&[]),
            PublicKey::MlDsa65(&[]),
            PublicKey::MlDsa87(&[]),
            PublicKey::HssLms(&[]),
        ] {
            assert_eq!(served(&key), 1, "{key:?}");
        }
        // Each SLH-DSA set serves its own algorithm and no other set's, and
        // every SLH-DSA algorithm is some set's.
        for &set in ic_slhdsa::ParameterSet::ALL {
            let key = PublicKey::SlhDsa(set, &[]);
            assert_eq!(served(&key), 1, "{key:?}");
            let alg = SignatureAlgorithm::from_id(set.id()).expect("an algorithm per set");
            assert!(key.supports(alg));
            assert_eq!(key.kind_id(), alg.id());
            assert_eq!(alg.max_signature_len(), set.signature_len());
        }
        assert_eq!(
            SignatureAlgorithm::ALL
                .iter()
                .filter(|a| slh_dsa_set(**a).is_some())
                .count(),
            12
        );
        assert_eq!(
            kind(verify(
                SignatureAlgorithm::Ed25519,
                &PublicKey::EcP256(&[4; 65]),
                b"m",
                &[0; 64]
            )),
            ErrorKind::InvalidParameter
        );
    }

    /// What a key reports about itself agrees with the ontology's entry for
    /// its algorithm, and RSA's strength follows its modulus.
    #[test]
    fn key_metadata_agrees_with_the_ontology() {
        let cases: [(PublicKey, &str, &str); 7] = [
            (PublicKey::EcP256(&[]), "ecdsa-p256", "ecdsa-p256-sha256"),
            (PublicKey::EcP384(&[]), "ecdsa-p384", "ecdsa-p384-sha384"),
            (PublicKey::EcP521(&[]), "ecdsa-p521", "ecdsa-p521-sha512"),
            (PublicKey::Ed25519(&[]), "ed25519", "ed25519"),
            (PublicKey::MlDsa44(&[]), "ml-dsa-44", "ml-dsa-44"),
            (PublicKey::MlDsa65(&[]), "ml-dsa-65", "ml-dsa-65"),
            (PublicKey::MlDsa87(&[]), "ml-dsa-87", "ml-dsa-87"),
        ];
        for (key, kind_id, entry) in cases {
            assert_eq!(key.kind_id(), kind_id);
            assert_eq!(key.rsa_bits(), None);
            let strength = ic_ontology::get(entry).expect("registered").strength;
            assert_eq!(key.classical_bits(), strength.classical, "{entry}");
        }

        // SLH-DSA's entry quotes the floor of its sets, which are category 1,
        // 3 and 5.
        let floor = ic_ontology::get("slh-dsa").unwrap().strength.classical;
        let strengths: Vec<u16> = ic_slhdsa::ParameterSet::ALL
            .iter()
            .map(|set| PublicKey::SlhDsa(*set, &[]).classical_bits())
            .collect();
        assert_eq!(strengths.iter().min(), Some(&floor));
        for (set, bits) in ic_slhdsa::ParameterSet::ALL.iter().zip(&strengths) {
            // A set's name carries its strength: `slh-dsa-shake-192f`.
            assert!(set.id().contains(&bits.to_string()), "{}", set.id());
        }
        // HSS/LMS's is its hash's output, read from the key; the entry quotes
        // the smaller of the two, and a key that cannot be read has none.
        let (lms_key, _, _) = ic_lms::example();
        assert_eq!(ic_lms::parameters(&lms_key).unwrap().hash.output_len(), 24);
        assert_eq!(PublicKey::HssLms(&lms_key).classical_bits(), 192);
        assert_eq!(ic_ontology::get("hss-lms").unwrap().strength.classical, 192);
        assert_eq!(PublicKey::HssLms(&[]).classical_bits(), 0);
        assert_eq!(PublicKey::HssLms(&lms_key).kind_id(), "hss-lms");

        let rsa = |modulus: &'static [u8]| PublicKey::Rsa {
            modulus,
            exponent: 65537,
        };
        let top = |bits: usize| -> &'static [u8] {
            let mut m = vec![0u8; bits.div_ceil(8)];
            m[0] = 1 << ((bits - 1) % 8);
            m.leak()
        };
        for (bits, strength) in [
            (2047, 0),
            (2048, 112),
            (3071, 112),
            (3072, 128),
            (4096, 128),
            (7680, 192),
            (15360, 256),
        ] {
            let key = rsa(top(bits));
            assert_eq!(key.rsa_bits(), Some(bits));
            assert_eq!(key.classical_bits(), strength, "{bits} bits");
        }
        assert_eq!(rsa(top(2048)).kind_id(), "rsa");
        // Leading zero bytes are not key size.
        let mut padded = vec![0u8; 4];
        padded.extend_from_slice(top(2048));
        assert_eq!(rsa(padded.leak()).rsa_bits(), Some(2048));
        assert_eq!(rsa(&[0, 0]).rsa_bits(), None);
        // 2048-bit RSA is the ontology's 112.
        assert_eq!(
            ic_ontology::get("rsa-pss-sha256")
                .unwrap()
                .strength
                .classical,
            112
        );
    }

    /// The exponent bound is a rule about cost, so it is tested as a rule: a
    /// 2048-bit modulus with the next odd exponent past the limit is refused
    /// before any arithmetic, and at the limit it is not refused for its
    /// exponent. Odd, because `ic_rsa` refuses an even exponent itself and an
    /// even one here would pass with the bound removed -- which it did.
    #[test]
    fn an_rsa_exponent_above_the_bound_is_refused() {
        let mut modulus = [0xffu8; 256];
        modulus[255] = 0xfd;
        let key = |exponent| PublicKey::Rsa {
            modulus: &modulus,
            exponent,
        };
        let sig = [0u8; 256];
        assert_eq!(
            kind(verify(
                SignatureAlgorithm::RsaPssSha256,
                &key(MAX_RSA_EXPONENT + 2),
                b"m",
                &sig
            )),
            ErrorKind::Unsupported
        );
        assert_eq!(
            kind(verify(
                SignatureAlgorithm::RsaPssSha256,
                &key(MAX_RSA_EXPONENT),
                b"m",
                &sig
            )),
            ErrorKind::AuthenticationFailed
        );
        // A modulus below the minimum size is the key's fault.
        assert_eq!(
            kind(verify(
                SignatureAlgorithm::RsaPssSha256,
                &PublicKey::Rsa {
                    modulus: &modulus[..128],
                    exponent: 65537
                },
                b"m",
                &sig[..128]
            )),
            ErrorKind::Unsupported
        );
    }
}
