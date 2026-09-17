//! `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7) and PKCS#1 `RSAPublicKey`.
//!
//! This is the shape a public key arrives in: inside a certificate, in a
//! `-----BEGIN PUBLIC KEY-----` file, in a JWK's `x5c`. Parsing returns
//! borrowed slices, so nothing is copied and nothing is allocated; the caller
//! hands them straight to `ic_rsa::RsaPublicKey::from_components` or to an
//! elliptic-curve verifier.
//!
//! ```text
//! SubjectPublicKeyInfo ::= SEQUENCE {
//!     algorithm         AlgorithmIdentifier,
//!     subjectPublicKey  BIT STRING }
//!
//! AlgorithmIdentifier ::= SEQUENCE {
//!     algorithm   OBJECT IDENTIFIER,
//!     parameters  ANY DEFINED BY algorithm OPTIONAL }
//! ```
//!
//! The `parameters` field is where the three families differ, and each
//! difference is load-bearing:
//!
//! | family | parameters |
//! |---|---|
//! | RSA | `NULL`, and it must be present (RFC 4055 §2.1) |
//! | EC | the named-curve OID; a key without one is not usable |
//! | Ed25519, X25519 | absent entirely (RFC 8410 §3), not `NULL` |

use crate::der::{self, Reader, Writer};
use crate::oid::{self, KeyAlgorithm};
use ic_core::{ensure, Result};

/// A parsed public key, borrowing from the DER it was read out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyInfo<'a> {
    /// An RSA key: the modulus, big-endian and minimal, plus the exponent.
    Rsa {
        /// Modulus, big-endian, with no leading zero byte.
        modulus: &'a [u8],
        /// Public exponent.
        exponent: u64,
    },
    /// An elliptic-curve key in SEC1 form, `0x04 || X || Y` uncompressed or
    /// `0x02`/`0x03` prefixed when compressed.
    Ec {
        /// Which curve.
        algorithm: KeyAlgorithm,
        /// The encoded point, exactly as it appeared.
        point: &'a [u8],
    },
    /// An Ed25519 public key, 32 bytes.
    Ed25519(&'a [u8]),
    /// An X25519 public key, 32 bytes.
    X25519(&'a [u8]),
    /// A key whose algorithm this build does not implement.
    ///
    /// Reported rather than refused, so a caller can say *which* algorithm it
    /// found. Nothing here will operate on it.
    Unsupported {
        /// The algorithm OID's content bytes.
        oid: &'a [u8],
    },
}

impl<'a> PublicKeyInfo<'a> {
    /// Which algorithm this key is for.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Rsa { .. } => KeyAlgorithm::Rsa,
            Self::Ec { algorithm, .. } => *algorithm,
            Self::Ed25519(_) => KeyAlgorithm::Ed25519,
            Self::X25519(_) => KeyAlgorithm::X25519,
            Self::Unsupported { .. } => KeyAlgorithm::Unknown,
        }
    }

    /// Parse a `SubjectPublicKeyInfo`.
    ///
    /// Rejects trailing data, so a caller cannot be handed a key with extra
    /// bytes that a different parser would read differently.
    pub fn from_der(input: &'a [u8]) -> Result<Self> {
        let mut outer = Reader::new(input);
        let mut spki = outer.sequence()?;
        outer.finish()?;

        let mut alg = spki.sequence()?;
        let algorithm_oid = alg.oid()?;
        let key_bits = spki.bit_string()?;
        spki.finish()?;

        if algorithm_oid == oid::RSA_ENCRYPTION {
            // RFC 4055 §2.1: the parameters field must be present and NULL.
            alg.null()?;
            alg.finish()?;
            let (modulus, exponent) = parse_rsa_public_key(key_bits)?;
            return Ok(PublicKeyInfo::Rsa { modulus, exponent });
        }

        if algorithm_oid == oid::EC_PUBLIC_KEY {
            let curve = alg.oid()?;
            alg.finish()?;
            let algorithm = oid::curve_from_oid(curve);
            ensure!(
                algorithm != KeyAlgorithm::Unknown,
                Unsupported,
                "unsupported named curve"
            );
            ensure!(!key_bits.is_empty(), MalformedEncoding, "empty ec point");
            // Only the uncompressed form is accepted on input. Compressed
            // points need a square root in the field, which belongs in the
            // curve implementation, not in a parser.
            ensure!(key_bits[0] == 0x04, Unsupported, "compressed ec point");
            ensure!(
                Some(key_bits.len()) == algorithm.public_key_len(),
                MalformedEncoding,
                "ec point has the wrong length for its curve"
            );
            return Ok(PublicKeyInfo::Ec {
                algorithm,
                point: key_bits,
            });
        }

        if algorithm_oid == oid::ED25519 || algorithm_oid == oid::X25519 {
            // RFC 8410 §3: parameters are absent, not NULL.
            alg.finish()?;
            ensure!(
                key_bits.len() == 32,
                MalformedEncoding,
                "curve25519 key length"
            );
            return Ok(if algorithm_oid == oid::ED25519 {
                PublicKeyInfo::Ed25519(key_bits)
            } else {
                PublicKeyInfo::X25519(key_bits)
            });
        }

        Ok(PublicKeyInfo::Unsupported { oid: algorithm_oid })
    }

    /// Serialize as a `SubjectPublicKeyInfo`, returning the length written.
    ///
    /// Refuses [`PublicKeyInfo::Unsupported`]: re-emitting a key whose
    /// structure was never validated would turn this crate into a laundering
    /// step for malformed input.
    pub fn to_der(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        let start = w.len();

        match self {
            Self::Rsa { modulus, exponent } => {
                let key_start = w.len();
                w.push_unsigned_u64(*exponent)?;
                w.push_unsigned_integer(modulus)?;
                w.push_wrapper(der::SEQUENCE, key_start)?;
                // Wrap the RSAPublicKey DER in the BIT STRING. The writer runs
                // backwards, so the content is already in place and only the
                // header is missing.
                let key_len = w.len() - key_start;
                w.push(&[0])?;
                w.push_header(der::BIT_STRING, key_len + 1)?;

                let alg_start = w.len();
                w.push_null()?;
                w.push_oid(oid::RSA_ENCRYPTION)?;
                w.push_wrapper(der::SEQUENCE, alg_start)?;
            }
            Self::Ec { algorithm, point } => {
                let curve = oid::curve_oid(*algorithm)
                    .ok_or(ic_core::err!(Unsupported, "not a named curve"))?;
                w.push_bit_string(point)?;
                let alg_start = w.len();
                w.push_oid(curve)?;
                w.push_oid(oid::EC_PUBLIC_KEY)?;
                w.push_wrapper(der::SEQUENCE, alg_start)?;
            }
            Self::Ed25519(key) | Self::X25519(key) => {
                ensure!(key.len() == 32, InvalidLength, "curve25519 key length");
                w.push_bit_string(key)?;
                let alg_start = w.len();
                w.push_oid(if matches!(self, Self::Ed25519(_)) {
                    oid::ED25519
                } else {
                    oid::X25519
                })?;
                w.push_wrapper(der::SEQUENCE, alg_start)?;
            }
            Self::Unsupported { .. } => {
                return Err(ic_core::err!(
                    Unsupported,
                    "cannot re-serialize an unrecognized key"
                ))
            }
        }

        w.push_wrapper(der::SEQUENCE, start)?;
        Ok(w.finish())
    }
}

/// Parse a bare PKCS#1 `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
/// publicExponent INTEGER }`.
///
/// This is what lives inside an SPKI's `BIT STRING`, and also what a
/// `-----BEGIN RSA PUBLIC KEY-----` file contains on its own.
pub fn parse_rsa_public_key(input: &[u8]) -> Result<(&[u8], u64)> {
    let mut outer = Reader::new(input);
    let mut seq = outer.sequence()?;
    outer.finish()?;
    let modulus = seq.unsigned_integer()?;
    let exponent = seq.unsigned_integer_u64()?;
    seq.finish()?;
    ensure!(!modulus.is_empty(), MalformedEncoding, "empty rsa modulus");
    Ok((modulus, exponent))
}

/// Serialize a bare PKCS#1 `RSAPublicKey`.
pub fn write_rsa_public_key(modulus: &[u8], exponent: u64, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out);
    let start = w.len();
    w.push_unsigned_u64(exponent)?;
    w.push_unsigned_integer(modulus)?;
    w.push_wrapper(der::SEQUENCE, start)?;
    Ok(w.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny RSA key. Small enough that the expected DER can be written out
    /// by hand below, which is the point: the encoder is checked against bytes
    /// derived from the ASN.1 grammar, not against itself.
    const SMALL_N: &[u8] = &[0xc0, 0xff, 0xee, 0x01];
    const SMALL_E: u64 = 65537;

    #[test]
    fn rsa_public_key_matches_a_hand_built_encoding() {
        // RSAPublicKey ::= SEQUENCE {
        //   modulus        INTEGER (0x00 c0 ff ee 01 — sign byte, top bit set)
        //   publicExponent INTEGER (0x01 00 01) }
        let want: &[u8] = &[
            0x30, 0x0c, // SEQUENCE, 12 bytes
            0x02, 0x05, 0x00, 0xc0, 0xff, 0xee, 0x01, // INTEGER modulus
            0x02, 0x03, 0x01, 0x00, 0x01, // INTEGER 65537
        ];
        let mut out = [0u8; 64];
        let n = write_rsa_public_key(SMALL_N, SMALL_E, &mut out).unwrap();
        assert_eq!(&out[..n], want);

        let (modulus, exponent) = parse_rsa_public_key(&out[..n]).unwrap();
        assert_eq!(modulus, SMALL_N);
        assert_eq!(exponent, SMALL_E);
    }

    #[test]
    fn rsa_spki_matches_a_hand_built_encoding() {
        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm SEQUENCE { OID rsaEncryption, NULL }
        //   subjectPublicKey BIT STRING { RSAPublicKey } }
        let want: &[u8] = &[
            0x30, 0x20, // SEQUENCE, 32 bytes = 15 (algorithm) + 17 (key)
            0x30, 0x0d, // AlgorithmIdentifier, 13 bytes
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, // OID 1.2.840.113549.1.1.1
            0x05, 0x00, // NULL
            0x03, 0x0f, 0x00, // BIT STRING, 15 bytes, 0 unused
            0x30, 0x0c, // RSAPublicKey
            0x02, 0x05, 0x00, 0xc0, 0xff, 0xee, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        let key = PublicKeyInfo::Rsa {
            modulus: SMALL_N,
            exponent: SMALL_E,
        };
        let mut out = [0u8; 128];
        let n = key.to_der(&mut out).unwrap();
        assert_eq!(&out[..n], want);
        assert_eq!(PublicKeyInfo::from_der(&out[..n]).unwrap(), key);
    }

    #[test]
    fn rsa_spki_round_trips_at_realistic_sizes() {
        for bytes in [256usize, 384, 512] {
            let mut modulus = std::vec![0xa5u8; bytes];
            modulus[0] = 0xd7; // top bit set, so a sign byte is required
            let key = PublicKeyInfo::Rsa {
                modulus: &modulus,
                exponent: 65537,
            };
            let mut out = [0u8; 1024];
            let n = key.to_der(&mut out).unwrap();
            // The long-form length header kicks in well before this size.
            assert!(n > bytes);
            assert_eq!(
                PublicKeyInfo::from_der(&out[..n]).unwrap(),
                key,
                "{bytes} bytes"
            );
        }
    }

    #[test]
    fn ec_spki_matches_a_hand_built_encoding() {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        for (i, b) in point[1..].iter_mut().enumerate() {
            *b = i as u8;
        }

        let key = PublicKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP256,
            point: &point,
        };
        let mut out = [0u8; 256];
        let n = key.to_der(&mut out).unwrap();

        // SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING }
        let mut want = std::vec::Vec::new();
        let alg: &[u8] = &[
            0x30, 0x13, // AlgorithmIdentifier, 19 bytes
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        ];
        let mut body = alg.to_vec();
        body.extend_from_slice(&[0x03, 0x42, 0x00]); // BIT STRING, 66 bytes
        body.extend_from_slice(&point);
        want.extend_from_slice(&[0x30, body.len() as u8]);
        want.extend_from_slice(&body);

        assert_eq!(&out[..n], &want[..]);
        assert_eq!(PublicKeyInfo::from_der(&out[..n]).unwrap(), key);
    }

    #[test]
    fn ed25519_spki_matches_a_hand_built_encoding() {
        let raw = [0x42u8; 32];
        let key = PublicKeyInfo::Ed25519(&raw);
        let mut out = [0u8; 128];
        let n = key.to_der(&mut out).unwrap();

        // RFC 8410 §3: no parameters at all.
        let mut want = std::vec![
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, // AlgorithmIdentifier, 5 bytes — note: no NULL
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused
        ];
        want.extend_from_slice(&raw);
        assert_eq!(&out[..n], &want[..]);
        assert_eq!(PublicKeyInfo::from_der(&out[..n]).unwrap(), key);
    }

    #[test]
    fn x25519_and_p384_round_trip() {
        let raw = [0x11u8; 32];
        let x = PublicKeyInfo::X25519(&raw);
        let mut out = [0u8; 128];
        let n = x.to_der(&mut out).unwrap();
        assert_eq!(PublicKeyInfo::from_der(&out[..n]).unwrap(), x);
        assert_eq!(x.algorithm(), KeyAlgorithm::X25519);

        let mut point = [0u8; 97];
        point[0] = 0x04;
        let p384 = PublicKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP384,
            point: &point,
        };
        let mut out = [0u8; 256];
        let n = p384.to_der(&mut out).unwrap();
        assert_eq!(PublicKeyInfo::from_der(&out[..n]).unwrap(), p384);
    }

    /// RFC 4055 §2.1 requires the NULL for RSA. Ed25519 forbids parameters
    /// entirely. Confusing the two is a common interoperability bug, so both
    /// directions are checked.
    #[test]
    fn algorithm_parameters_are_enforced_per_family() {
        // RSA with the NULL removed: AlgorithmIdentifier shrinks to 11 bytes.
        let bad_rsa: &[u8] = &[
            0x30, 0x20, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, 0x03, 0x0f, 0x00, 0x30, 0x0c, 0x02, 0x05, 0x00, 0xc0, 0xff, 0xee, 0x01, 0x02,
            0x03, 0x01, 0x00, 0x01,
        ];
        assert!(
            PublicKeyInfo::from_der(bad_rsa).is_err(),
            "rsa needs its NULL"
        );

        // Ed25519 with a NULL added: AlgorithmIdentifier grows to 7 bytes.
        let mut bad_ed = std::vec![
            0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x21, 0x00,
        ];
        bad_ed.extend_from_slice(&[0x42u8; 32]);
        assert!(
            PublicKeyInfo::from_der(&bad_ed).is_err(),
            "ed25519 takes no parameters"
        );
    }

    #[test]
    fn an_unknown_algorithm_is_reported_not_guessed() {
        // A DSA OID (1.2.840.10040.4.1), which this build does not implement.
        let dsa: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];
        let spki: &[u8] = &[
            0x30, 0x10, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01, 0x03,
            0x03, 0x00, 0x01, 0x02,
        ];
        let parsed = PublicKeyInfo::from_der(spki).unwrap();
        assert_eq!(parsed, PublicKeyInfo::Unsupported { oid: dsa });
        assert_eq!(parsed.algorithm(), KeyAlgorithm::Unknown);

        // And it will not be re-emitted.
        let mut out = [0u8; 64];
        assert!(parsed.to_der(&mut out).is_err());
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let key = PublicKeyInfo::Rsa {
            modulus: SMALL_N,
            exponent: SMALL_E,
        };
        let mut out = [0u8; 128];
        let n = key.to_der(&mut out).unwrap();

        // Trailing byte.
        let mut extra = out[..n].to_vec();
        extra.push(0x00);
        assert!(PublicKeyInfo::from_der(&extra).is_err(), "trailing data");

        // Truncated.
        assert!(PublicKeyInfo::from_der(&out[..n - 1]).is_err(), "truncated");

        // Empty.
        assert!(PublicKeyInfo::from_der(&[]).is_err(), "empty");
    }

    #[test]
    fn an_ec_point_of_the_wrong_length_is_rejected() {
        // A P-256 key carrying a 97-byte P-384 point.
        let mut point = [0u8; 97];
        point[0] = 0x04;
        let mut out = [0u8; 256];
        let n = PublicKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP384,
            point: &point,
        }
        .to_der(&mut out)
        .unwrap();

        // Rewrite the curve OID in place to say P-256 instead of P-384.
        let at = out[..n]
            .windows(oid::P384.len())
            .position(|w| w == oid::P384)
            .expect("the p-384 oid is in there");
        let mut tampered = out[..n].to_vec();
        // P-256's OID is one byte longer, so splice rather than overwrite.
        tampered.splice(at - 2..at + oid::P384.len(), {
            let mut v = std::vec![0x06, oid::P256.len() as u8];
            v.extend_from_slice(oid::P256);
            v
        });
        // Fix up the two enclosing lengths by hand.
        tampered[1] += 1;
        tampered[3] += 1;
        assert!(
            PublicKeyInfo::from_der(&tampered).is_err(),
            "a p-384 point must not pass as p-256"
        );
    }

    #[test]
    fn a_compressed_point_is_refused_rather_than_mishandled() {
        let mut point = [0u8; 33];
        point[0] = 0x02;
        // Build the SPKI by hand, since to_der only emits what it parsed.
        let mut body = std::vec![
            0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        body.extend_from_slice(&[0x03, 0x22, 0x00]);
        body.extend_from_slice(&point);
        let mut spki = std::vec![0x30, body.len() as u8];
        spki.extend_from_slice(&body);
        assert!(PublicKeyInfo::from_der(&spki).is_err());
    }

    #[test]
    fn a_small_buffer_is_an_error_not_a_panic() {
        let key = PublicKeyInfo::Rsa {
            modulus: SMALL_N,
            exponent: SMALL_E,
        };
        let mut out = [0u8; 8];
        assert!(key.to_der(&mut out).is_err());
    }
}
