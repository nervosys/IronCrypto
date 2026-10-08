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
//! `Ecdsa-Sig-Value` for ECDSA, and the algorithm's own bytes for Ed25519, RSA
//! and ML-DSA. ML-DSA is the pure variant with an empty context, as RFC 9881
//! specifies for certificates.
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
}

impl<'a> PublicKey<'a> {
    /// Parse a DER `SubjectPublicKeyInfo`.
    ///
    /// The classical algorithms are read by `ic_pkix`, with its checks: RSA's
    /// parameters present and `NULL`, an EC point uncompressed and of its
    /// curve's length. ML-DSA, which `ic_pkix::PublicKeyInfo` does not name,
    /// is read here per RFC 9881: no parameters, and a key of exactly the
    /// parameter set's length. A key `ic_pkix` refuses is not given a second
    /// reading. X25519 keys and algorithms this library does not implement are
    /// `Unsupported`: they are well-formed and cannot verify a signature.
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
            PublicKeyInfo::Unsupported { .. } => Self::ml_dsa_from_spki(spki),
            _ => Err(err!(Unsupported, "not a signature verification key")),
        }
    }

    /// The ML-DSA reading of a `SubjectPublicKeyInfo` `ic_pkix` did not name.
    fn ml_dsa_from_spki(spki: &'a [u8]) -> Result<Self> {
        let mut outer = Reader::new(spki);
        let mut body = outer.sequence()?;
        outer.finish()?;
        let mut algorithm = body.sequence()?;
        let id = algorithm.oid()?;
        // RFC 9881 section 2: the parameters field is absent.
        let parameters_absent = algorithm.finish().is_ok();
        let key = body.bit_string()?;
        body.finish()?;

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

    /// Whether this key can verify a signature made with `algorithm`.
    ///
    /// An RSA key serves all six RSA algorithms; every other key serves the
    /// one algorithm of its type.
    #[must_use = "whether the key serves the algorithm; discarding it checks nothing"]
    pub fn supports(&self, algorithm: SignatureAlgorithm) -> bool {
        use SignatureAlgorithm as A;
        matches!(
            (self, algorithm),
            (Self::EcP256(_), A::EcdsaP256Sha256)
                | (Self::EcP384(_), A::EcdsaP384Sha384)
                | (Self::EcP521(_), A::EcdsaP521Sha512)
                | (Self::Ed25519(_), A::Ed25519)
                | (Self::MlDsa44(_), A::MlDsa44)
                | (Self::MlDsa65(_), A::MlDsa65)
                | (Self::MlDsa87(_), A::MlDsa87)
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
/// above [`MAX_RSA_EXPONENT`].
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
        // Trailing bytes after the structure.
        buf[n] = 0;
        assert!(PublicKey::from_spki(&buf[..n + 1]).is_err());
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
        ] {
            assert_eq!(served(&key), 1, "{key:?}");
        }
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
