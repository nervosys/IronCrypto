//! PKCS#8 `PrivateKeyInfo` (RFC 5208 / RFC 5958) and SEC1 `ECPrivateKey`.
//!
//! ```text
//! PrivateKeyInfo ::= SEQUENCE {
//!     version              INTEGER,            -- 0
//!     privateKeyAlgorithm  AlgorithmIdentifier,
//!     privateKey           OCTET STRING,
//!     attributes       [0] IMPLICIT Attributes OPTIONAL }
//! ```
//!
//! The `privateKey` octet string holds another DER structure, different for
//! each family. The Curve25519 case is the one that trips people up: RFC 8410
//! §7 defines `CurvePrivateKey ::= OCTET STRING`, so the 32 raw bytes sit
//! inside *two* nested octet strings, and a key written with only one is a
//! common and silently wrong output.
//!
//! # Secrets and buffers
//!
//! Parsing borrows from the input, so a parsed private key is a view onto the
//! caller's buffer and carries no copy of its own. That also means the caller
//! owns the erasure: wrap the DER in [`ic_core::Zeroizing`] or call
//! [`ic_core::Zeroize::zeroize`] on it once the key material has been moved
//! into a key type.
//!
//! # RSA carries eight integers
//!
//! `RSAPrivateKey` holds `n`, `e`, `d`, the two primes, and the three CRT
//! parameters. All eight are parsed and all eight are kept, because
//! `ic_rsa::RsaPrivateKey` uses the CRT and can supply them. A key that
//! reaches here without them is malformed, not merely inconvenient: the
//! structure has no optional fields before `otherPrimeInfos`.

use crate::der::{self, Reader, Writer};
use crate::oid::{self, KeyAlgorithm};
use ic_core::{ensure, Result};

/// A parsed private key, borrowing from the DER it was read out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyInfo<'a> {
    /// An RSA private key, with every field PKCS#1 defines for the two-prime
    /// case.
    Rsa {
        /// Modulus, big-endian and minimal.
        modulus: &'a [u8],
        /// Public exponent.
        public_exponent: u64,
        /// Private exponent, big-endian and minimal.
        private_exponent: &'a [u8],
        /// First prime factor, conventionally the larger.
        prime1: &'a [u8],
        /// Second prime factor.
        prime2: &'a [u8],
        /// `d mod (p - 1)`.
        exponent1: &'a [u8],
        /// `d mod (q - 1)`.
        exponent2: &'a [u8],
        /// `q^-1 mod p`.
        coefficient: &'a [u8],
    },
    /// An elliptic-curve private key, with the public key when the encoding
    /// carried one.
    Ec {
        /// Which curve.
        algorithm: KeyAlgorithm,
        /// The scalar, fixed width for the curve.
        private_key: &'a [u8],
        /// The SEC1 point, if present.
        public_key: Option<&'a [u8]>,
    },
    /// An Ed25519 seed, 32 bytes.
    Ed25519(&'a [u8]),
    /// An X25519 scalar, 32 bytes.
    X25519(&'a [u8]),
    /// A key whose algorithm this build does not implement.
    Unsupported {
        /// The algorithm OID's content bytes -- or, for an elliptic-curve key
        /// on a curve this build does not implement, the named curve's. See
        /// [`crate::PublicKeyInfo::Unsupported`].
        oid: &'a [u8],
    },
}

impl<'a> PrivateKeyInfo<'a> {
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

    /// Parse a PKCS#8 `PrivateKeyInfo`.
    pub fn from_der(input: &'a [u8]) -> Result<Self> {
        let mut outer = Reader::new(input);
        let mut pki = outer.sequence()?;
        outer.finish()?;

        // Version 0 is PKCS#8 v1. Version 1 (RFC 5958 "OneAsymmetricKey") adds
        // an optional public key field that this parser does not read, so it is
        // refused rather than half-understood.
        pki.expect_version(0)?;

        let mut alg = pki.sequence()?;
        let algorithm_oid = alg.oid()?;
        let inner = pki.octet_string()?;
        // RFC 5208's optional [0] attributes set is refused rather than
        // skipped. Skipping it would mean this parser accepts a document it
        // cannot re-emit: the attributes would vanish on the way out, and a
        // caller who read a key and wrote it back would get different bytes
        // than it started with. That is the encoding ambiguity this crate
        // exists to avoid, so a document carrying attributes is rejected and
        // said so, rather than silently normalized. Key-file tooling does not
        // produce them; they belong to PKCS#12.
        ensure!(
            pki.peek_tag() != Some(der::context(0)),
            Unsupported,
            "pkcs#8 attributes are not supported, and are refused rather than dropped"
        );
        pki.finish()?;

        if algorithm_oid == oid::RSA_ENCRYPTION {
            alg.null()?;
            alg.finish()?;
            return parse_rsa_private_key(inner);
        }

        if algorithm_oid == oid::EC_PUBLIC_KEY {
            let curve = alg.oid()?;
            alg.finish()?;
            let algorithm = oid::curve_from_oid(curve);
            if algorithm == KeyAlgorithm::Unknown {
                // Reported, not refused; see `PublicKeyInfo::Unsupported`.
                return Ok(PrivateKeyInfo::Unsupported { oid: curve });
            }
            return parse_ec_private_key(inner, Some(algorithm));
        }

        if algorithm_oid == oid::ED25519 || algorithm_oid == oid::X25519 {
            alg.finish()?;
            // RFC 8410 §7: the inner value is itself an OCTET STRING.
            let mut curve_key = Reader::new(inner);
            let raw = curve_key.octet_string()?;
            curve_key.finish()?;
            ensure!(raw.len() == 32, MalformedEncoding, "curve25519 key length");
            return Ok(if algorithm_oid == oid::ED25519 {
                PrivateKeyInfo::Ed25519(raw)
            } else {
                PrivateKeyInfo::X25519(raw)
            });
        }

        Ok(PrivateKeyInfo::Unsupported { oid: algorithm_oid })
    }

    /// Serialize as a PKCS#8 `PrivateKeyInfo`, returning the length written.
    ///
    /// RSA is refused; see the module docs.
    pub fn to_der(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer::new(out);
        let start = w.len();

        match self {
            Self::Rsa {
                modulus,
                public_exponent,
                private_exponent,
                prime1,
                prime2,
                exponent1,
                exponent2,
                coefficient,
            } => {
                // RSAPrivateKey, innermost first because the writer runs
                // backwards. The field order is RFC 8017 A.1.2 read upwards.
                let inner_start = w.len();
                w.push_unsigned_integer(coefficient)?;
                w.push_unsigned_integer(exponent2)?;
                w.push_unsigned_integer(exponent1)?;
                w.push_unsigned_integer(prime2)?;
                w.push_unsigned_integer(prime1)?;
                w.push_unsigned_integer(private_exponent)?;
                w.push_unsigned_u64(*public_exponent)?;
                w.push_unsigned_integer(modulus)?;
                w.push_unsigned_u64(0)?; // two-prime version
                w.push_wrapper(der::SEQUENCE, inner_start)?;
                w.push_wrapper(der::OCTET_STRING, inner_start)?;

                let alg_start = w.len();
                w.push_null()?;
                w.push_oid(oid::RSA_ENCRYPTION)?;
                w.push_wrapper(der::SEQUENCE, alg_start)?;
            }
            Self::Ec {
                algorithm,
                private_key,
                public_key,
            } => {
                let curve = oid::curve_oid(*algorithm)
                    .ok_or(ic_core::err!(Unsupported, "not a named curve"))?;
                ensure!(
                    Some(private_key.len()) == algorithm.private_key_len(),
                    InvalidLength,
                    "ec private key length"
                );

                let inner_start = w.len();
                if let Some(point) = public_key {
                    let point_start = w.len();
                    w.push_bit_string(point)?;
                    w.push_wrapper(der::context(1), point_start)?;
                }
                w.push_octet_string(private_key)?;
                w.push_unsigned_u64(1)?; // ECPrivateKey version
                w.push_wrapper(der::SEQUENCE, inner_start)?;
                w.push_wrapper(der::OCTET_STRING, inner_start)?;

                let alg_start = w.len();
                w.push_oid(curve)?;
                w.push_oid(oid::EC_PUBLIC_KEY)?;
                w.push_wrapper(der::SEQUENCE, alg_start)?;
            }
            Self::Ed25519(key) | Self::X25519(key) => {
                ensure!(key.len() == 32, InvalidLength, "curve25519 key length");
                // Two nested OCTET STRINGs: CurvePrivateKey inside privateKey.
                w.push_octet_string(key)?;
                w.push_header(der::OCTET_STRING, key.len() + 2)?;

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

        w.push_unsigned_u64(0)?; // PrivateKeyInfo version
        w.push_wrapper(der::SEQUENCE, start)?;
        Ok(w.finish())
    }
}

/// Parse a PKCS#1 `RSAPrivateKey`.
///
/// This is the body of a `-----BEGIN RSA PRIVATE KEY-----` file, and also what
/// a PKCS#8 `PrivateKeyInfo` wraps for an RSA key. Public for the first case:
/// a caller handed a bare `RSAPrivateKey` has no PKCS#8 envelope to go through,
/// exactly as with [`parse_ec_private_key`].
pub fn parse_rsa_private_key(input: &[u8]) -> Result<PrivateKeyInfo<'_>> {
    let mut outer = Reader::new(input);
    let mut seq = outer.sequence()?;
    outer.finish()?;

    // Version 0 is the two-prime form. Version 1 carries otherPrimeInfos for
    // multi-prime RSA, which nothing here supports.
    seq.expect_version(0)?;
    let modulus = seq.unsigned_integer()?;
    let public_exponent = seq.unsigned_integer_u64()?;
    let private_exponent = seq.unsigned_integer()?;
    let prime1 = seq.unsigned_integer()?;
    let prime2 = seq.unsigned_integer()?;
    let exponent1 = seq.unsigned_integer()?;
    let exponent2 = seq.unsigned_integer()?;
    let coefficient = seq.unsigned_integer()?;
    seq.finish()?;

    ensure!(!modulus.is_empty(), MalformedEncoding, "empty rsa modulus");
    Ok(PrivateKeyInfo::Rsa {
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
    })
}

/// Parse a SEC1 `ECPrivateKey` (RFC 5915).
///
/// `expected` is the curve from the enclosing PKCS#8 `AlgorithmIdentifier`,
/// when there is one. A bare `ECPrivateKey` — the body of a
/// `-----BEGIN EC PRIVATE KEY-----` file — carries the curve in its own
/// `[0] parameters` field instead, so pass `None` there.
pub fn parse_ec_private_key(
    input: &[u8],
    expected: Option<KeyAlgorithm>,
) -> Result<PrivateKeyInfo<'_>> {
    let mut outer = Reader::new(input);
    let mut seq = outer.sequence()?;
    outer.finish()?;

    seq.expect_version(1)?;
    let private_key = seq.octet_string()?;

    let mut algorithm = expected.unwrap_or(KeyAlgorithm::Unknown);
    if seq.peek_tag() == Some(der::context(0)) {
        // RFC 5915 section 3: inside a PKCS#8 PrivateKeyInfo the parameters
        // field is omitted, because the container's AlgorithmIdentifier already
        // names the curve. A key that carries it in both places is refused
        // rather than accepted and re-emitted without it — that asymmetry means
        // reading a key and writing it back produces different bytes, which is
        // the ambiguity this crate exists to avoid. A *bare* ECPrivateKey is
        // the opposite case: there the field is the only statement of which
        // curve the key is on, and it is required.
        ensure!(
            expected.is_none(),
            MalformedEncoding,
            "ec private key repeats its curve inside a pkcs#8 container, where rfc 5915 omits it"
        );
        let mut params = seq.expect_nested(der::context(0))?;
        let curve = params.oid()?;
        params.finish()?;
        let named = oid::curve_from_oid(curve);
        if named == KeyAlgorithm::Unknown {
            // Reported, not refused; see `PublicKeyInfo::Unsupported`.
            return Ok(PrivateKeyInfo::Unsupported { oid: curve });
        }
        algorithm = named;
    }
    ensure!(
        algorithm != KeyAlgorithm::Unknown,
        MalformedEncoding,
        "ec private key does not say which curve it is on"
    );

    let mut public_key = None;
    if seq.peek_tag() == Some(der::context(1)) {
        let mut wrapper = seq.expect_nested(der::context(1))?;
        let point = wrapper.bit_string()?;
        wrapper.finish()?;
        ensure!(
            Some(point.len()) == algorithm.public_key_len(),
            MalformedEncoding,
            "ec public key has the wrong length for its curve"
        );
        ensure!(point[0] == 0x04, Unsupported, "compressed ec point");
        public_key = Some(point);
    }
    seq.finish()?;

    ensure!(
        Some(private_key.len()) == algorithm.private_key_len(),
        MalformedEncoding,
        "ec private key has the wrong length for its curve"
    );

    Ok(PrivateKeyInfo::Ec {
        algorithm,
        private_key,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `content` in a DER header with a correctly computed length.
    ///
    /// Parser fixtures below are written as explicit field bytes; only the
    /// enclosing lengths are computed, because hand-counting them adds an
    /// arithmetic slip to every test without adding any coverage. The encoder
    /// tests compare against fully hand-written bytes, which is where checking
    /// the length arithmetic actually belongs.
    fn wrap(tag: u8, content: &[u8]) -> std::vec::Vec<u8> {
        assert!(content.len() < 128, "fixtures stay in the short form");
        let mut out = std::vec![tag, content.len() as u8];
        out.extend_from_slice(content);
        out
    }

    fn seq(content: &[u8]) -> std::vec::Vec<u8> {
        wrap(crate::der::SEQUENCE, content)
    }

    #[test]
    fn ed25519_pkcs8_matches_a_hand_built_encoding() {
        let seed = [0x9du8; 32];
        let key = PrivateKeyInfo::Ed25519(&seed);
        let mut out = [0u8; 128];
        let n = key.to_der(&mut out).unwrap();

        // PrivateKeyInfo ::= SEQUENCE {
        //   version 0,
        //   algorithm SEQUENCE { OID 1.3.101.112 },
        //   privateKey OCTET STRING { OCTET STRING { 32 bytes } } }
        let mut want = std::vec![
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // version 0
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier
            0x04, 0x22, // privateKey OCTET STRING, 34 bytes
            0x04, 0x20, // CurvePrivateKey OCTET STRING, 32 bytes
        ];
        want.extend_from_slice(&seed);
        assert_eq!(&out[..n], &want[..], "the double octet-string wrapping");
        assert_eq!(PrivateKeyInfo::from_der(&out[..n]).unwrap(), key);
    }

    /// The single-wrapped form is what an implementation produces when it
    /// misses RFC 8410 §7. It must not parse, or this library would accept a
    /// key it cannot round-trip.
    #[test]
    fn a_singly_wrapped_curve25519_key_is_rejected() {
        let seed = [0x9du8; 32];
        let mut bad = std::vec![
            0x30, 0x2c, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
            0x20, // privateKey OCTET STRING holding the seed directly
        ];
        bad.extend_from_slice(&seed);
        assert!(PrivateKeyInfo::from_der(&bad).is_err());
    }

    #[test]
    fn x25519_pkcs8_round_trips() {
        let scalar = [0x07u8; 32];
        let key = PrivateKeyInfo::X25519(&scalar);
        let mut out = [0u8; 128];
        let n = key.to_der(&mut out).unwrap();
        assert_eq!(PrivateKeyInfo::from_der(&out[..n]).unwrap(), key);
        assert_eq!(key.algorithm(), KeyAlgorithm::X25519);
    }

    #[test]
    fn ec_pkcs8_round_trips_with_and_without_the_public_key() {
        for (algorithm, scalar_len, point_len) in [
            (KeyAlgorithm::EcP256, 32usize, 65usize),
            (KeyAlgorithm::EcP384, 48, 97),
        ] {
            let scalar = std::vec![0x33u8; scalar_len];
            let mut point = std::vec![0u8; point_len];
            point[0] = 0x04;

            for public_key in [None, Some(&point[..])] {
                let key = PrivateKeyInfo::Ec {
                    algorithm,
                    private_key: &scalar,
                    public_key,
                };
                let mut out = [0u8; 512];
                let n = key.to_der(&mut out).unwrap();
                assert_eq!(
                    PrivateKeyInfo::from_der(&out[..n]).unwrap(),
                    key,
                    "{algorithm:?} with public key: {}",
                    public_key.is_some()
                );
            }
        }
    }

    #[test]
    fn ec_key_lengths_are_checked_against_the_curve() {
        // A 48-byte scalar labelled P-256.
        let scalar = [0x33u8; 48];
        let key = PrivateKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP256,
            private_key: &scalar,
            public_key: None,
        };
        let mut out = [0u8; 256];
        assert!(key.to_der(&mut out).is_err());

        // And on the way in: build a P-256 container around a P-384 scalar.
        let good = PrivateKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP384,
            private_key: &scalar,
            public_key: None,
        };
        let n = good.to_der(&mut out).unwrap();
        let mut tampered = out[..n].to_vec();
        let at = tampered
            .windows(oid::P384.len())
            .position(|w| w == oid::P384)
            .unwrap();
        tampered.splice(at - 2..at + oid::P384.len(), {
            let mut v = std::vec![0x06, oid::P256.len() as u8];
            v.extend_from_slice(oid::P256);
            v
        });
        tampered[1] += 1;
        tampered[6] += 1;
        assert!(PrivateKeyInfo::from_der(&tampered).is_err());
    }

    /// A bare `ECPrivateKey`, as found in a `-----BEGIN EC PRIVATE KEY-----`
    /// file, carries the curve in its own `[0]` field.
    #[test]
    fn a_bare_ec_private_key_carries_its_own_curve() {
        let scalar = [0x44u8; 32];
        let mut fields = std::vec![0x02, 0x01, 0x01]; // version 1
        fields.extend_from_slice(&[0x04, 0x20]); // privateKey OCTET STRING
        fields.extend_from_slice(&scalar);
        fields.extend_from_slice(&[
            0xa0, 0x0a, // [0] parameters
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        ]);
        let inner = seq(&fields);

        let parsed = parse_ec_private_key(&inner, None).unwrap();
        assert_eq!(
            parsed,
            PrivateKeyInfo::Ec {
                algorithm: KeyAlgorithm::EcP256,
                private_key: &scalar,
                public_key: None,
            }
        );

        // Without the parameters and without a container, the curve is unknown
        // and the key is unusable rather than assumed to be P-256.
        let mut bare = std::vec![0x02, 0x01, 0x01, 0x04, 0x20];
        bare.extend_from_slice(&scalar);
        assert!(parse_ec_private_key(&seq(&bare), None).is_err());
    }

    /// Inside a PKCS#8 container the inner parameters field must be absent, so
    /// a key that states its curve twice is refused. Bare, the same bytes are
    /// the only statement of the curve and are required.
    #[test]
    fn inner_ec_parameters_are_refused_inside_a_container() {
        let scalar = [0x44u8; 32];
        let mut fields = std::vec![0x02, 0x01, 0x01, 0x04, 0x20];
        fields.extend_from_slice(&scalar);
        fields.extend_from_slice(&[
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        let inner = seq(&fields);

        assert!(
            parse_ec_private_key(&inner, Some(KeyAlgorithm::EcP256)).is_err(),
            "a container already names the curve"
        );
        assert!(
            parse_ec_private_key(&inner, Some(KeyAlgorithm::EcP384)).is_err(),
            "and disagreeing about it is no better"
        );
        assert!(
            parse_ec_private_key(&inner, None).is_ok(),
            "bare, the field is what names the curve"
        );
    }

    /// An RSA private key parses, including its CRT fields, and does not
    /// re-serialize.
    #[test]
    fn rsa_private_keys_round_trip() {
        // A miniature RSAPrivateKey: p = 61, q = 53, n = 3233, e = 17, d = 413,
        // dP = 53, dQ = 49, qInv = 38. The textbook worked example, chosen so
        // the whole structure fits in a readable literal.
        let rsa_fields: &[u8] = &[
            0x02, 0x01, 0x00, // version 0
            0x02, 0x02, 0x0c, 0xa1, // n = 3233
            0x02, 0x01, 0x11, // e = 17
            0x02, 0x02, 0x01, 0x9d, // d = 413
            0x02, 0x01, 0x3d, // p = 61
            0x02, 0x01, 0x35, // q = 53
            0x02, 0x01, 0x35, // dP = 53 = 413 mod 60
            0x02, 0x01, 0x31, // dQ = 49 = 413 mod 52
            0x02, 0x01, 0x26, // qInv = 38, since 53 * 38 = 1 mod 61
        ];
        let inner = seq(rsa_fields);

        let mut outer_fields = std::vec![
            0x02, 0x01, 0x00, // version 0
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, // rsaEncryption, NULL
        ];
        outer_fields.extend_from_slice(&wrap(crate::der::OCTET_STRING, &inner));
        let pkcs8 = seq(&outer_fields);

        let parsed = PrivateKeyInfo::from_der(&pkcs8).unwrap();
        assert_eq!(
            parsed,
            PrivateKeyInfo::Rsa {
                modulus: &[0x0c, 0xa1],
                public_exponent: 17,
                private_exponent: &[0x01, 0x9d],
                prime1: &[0x3d],
                prime2: &[0x35],
                exponent1: &[0x35],
                exponent2: &[0x31],
                coefficient: &[0x26],
            }
        );
        assert_eq!(parsed.algorithm(), KeyAlgorithm::Rsa);

        // And it re-serializes to exactly the bytes it came from, which is the
        // property a parser and an encoder written separately can most easily
        // fail to have.
        let mut out = [0u8; 256];
        let n = parsed.to_der(&mut out).unwrap();
        assert_eq!(&out[..n], &pkcs8[..], "round trip is byte-identical");

        // Dropping the last CRT field must fail rather than silently produce a
        // key from the fields it did manage to read.
        let short_inner = seq(&rsa_fields[..rsa_fields.len() - 3]);
        let mut short_outer = std::vec![
            0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x01, 0x01, 0x05, 0x00,
        ];
        short_outer.extend_from_slice(&wrap(crate::der::OCTET_STRING, &short_inner));
        assert!(PrivateKeyInfo::from_der(&seq(&short_outer)).is_err());
    }

    #[test]
    fn an_unknown_algorithm_is_reported_not_guessed() {
        let dsa: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];
        let pkcs8: &[u8] = &[
            0x30, 0x13, 0x02, 0x01, 0x00, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38,
            0x04, 0x01, 0x04, 0x03, 0x01, 0x02, 0x03,
        ];
        let parsed = PrivateKeyInfo::from_der(pkcs8).unwrap();
        assert_eq!(parsed, PrivateKeyInfo::Unsupported { oid: dsa });
        let mut out = [0u8; 64];
        assert!(parsed.to_der(&mut out).is_err());
    }

    #[test]
    fn a_wrong_version_is_refused() {
        let seed = [0x9du8; 32];
        let key = PrivateKeyInfo::Ed25519(&seed);
        let mut out = [0u8; 128];
        let n = key.to_der(&mut out).unwrap();

        // Byte 4 is the PrivateKeyInfo version. RFC 5958 version 1 adds a field
        // this parser does not read, so it is refused rather than half-read.
        let mut v1 = out[..n].to_vec();
        assert_eq!(v1[4], 0);
        v1[4] = 1;
        assert!(PrivateKeyInfo::from_der(&v1).is_err());
    }

    #[test]
    fn trailing_data_is_rejected() {
        let seed = [0x9du8; 32];
        let mut out = [0u8; 128];
        let n = PrivateKeyInfo::Ed25519(&seed).to_der(&mut out).unwrap();
        let mut extra = out[..n].to_vec();
        extra.push(0);
        assert!(PrivateKeyInfo::from_der(&extra).is_err());
    }

    #[test]
    fn a_small_buffer_is_an_error_not_a_panic() {
        let seed = [0x9du8; 32];
        let mut out = [0u8; 8];
        assert!(PrivateKeyInfo::Ed25519(&seed).to_der(&mut out).is_err());
    }

    // Keys produced by OpenSSL 3.5.7, an implementation independent of this
    // one, so that parsing them and writing them back tests against someone
    // else's encoder rather than against this crate's own output:
    //
    //   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:<curve>     //       -pkeyopt ec_param_enc:named_curve -outform DER      # bare SEC1
    //   openssl pkcs8 -topk8 -nocrypt -inform DER -outform DER  # PKCS#8
    //   openssl pkey -inform DER -pubout -outform DER           # SPKI
    //
    // P-521 is the useful curve for the writer as well as the parser: its
    // structures are large enough that every one of them needs long-form DER
    // lengths (30 81 9b, 03 81 86, 04 81 d6), which P-256 keys barely touch.
    // secp256k1 is a real curve this build does not implement.
    const OPENSSL_P521_PKCS8: &str = concat!(
        "3081ee020100301006072a8648ce3d020106052b810400230481d63081d30201",
        "01044201561e70ddafc182c8543600963cd72f2f99905eaf3e004bbcce708b39",
        "b6b38ed346c8416f34e26d9fbbfe8a19a6031b6158ac620e26df07ee2b5f2a2b",
        "b56eecbb67a18189038186000401d5a6010c58847c997e57aa3e006dc546ddfd",
        "953492fd28ec42c66499f223c4c27544b4f749ba345a45d0ea3f86e5756886ec",
        "4775aa7bf505495da5b71cfe9bf1fe0178fe7a00a59e3965a5af25d7c3117750",
        "e3b969f26d5987d7879977ea16bc083f2774585c4f48a5567da7f399d873d21b",
        "fe5e8fc0f464db21ce39b8269ef39e1e9f",
    );
    const OPENSSL_P521_SEC1: &str = concat!(
        "3081dc020101044201561e70ddafc182c8543600963cd72f2f99905eaf3e004b",
        "bcce708b39b6b38ed346c8416f34e26d9fbbfe8a19a6031b6158ac620e26df07",
        "ee2b5f2a2bb56eecbb67a00706052b81040023a18189038186000401d5a6010c",
        "58847c997e57aa3e006dc546ddfd953492fd28ec42c66499f223c4c27544b4f7",
        "49ba345a45d0ea3f86e5756886ec4775aa7bf505495da5b71cfe9bf1fe0178fe",
        "7a00a59e3965a5af25d7c3117750e3b969f26d5987d7879977ea16bc083f2774",
        "585c4f48a5567da7f399d873d21bfe5e8fc0f464db21ce39b8269ef39e1e9f",
    );
    const OPENSSL_SECP256K1_PKCS8: &str = concat!(
        "308184020100301006072a8648ce3d020106052b8104000a046d306b02010104",
        "2078f8ec5a553f99122757b815556294c979b5e478fe6e565313ea8d35f7d241",
        "84a14403420004b3220f31f48114130af06f8b7c2aad8bde7161e73da1f4af75",
        "2778a51b8ae87293c7d0fbfc1ba665d567a7766861011baa8924b6cd172bdc21",
        "a4fb6eef6a8300",
    );
    const OPENSSL_SECP256K1_SEC1: &str = concat!(
        "3074020101042078f8ec5a553f99122757b815556294c979b5e478fe6e565313",
        "ea8d35f7d24184a00706052b8104000aa14403420004b3220f31f48114130af0",
        "6f8b7c2aad8bde7161e73da1f4af752778a51b8ae87293c7d0fbfc1ba665d567",
        "a7766861011baa8924b6cd172bdc21a4fb6eef6a8300",
    );

    fn unhex(s: &str) -> std::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `secp256k1`, 1.3.132.0.10.
    const SECP256K1_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

    /// A P-521 PKCS#8 key parses, and writes back byte for byte.
    #[test]
    fn an_openssl_p521_pkcs8_key_parses_and_writes_back_identically() {
        let der = unhex(OPENSSL_P521_PKCS8);
        let key = PrivateKeyInfo::from_der(&der).unwrap();
        let PrivateKeyInfo::Ec {
            algorithm,
            private_key,
            public_key,
        } = key
        else {
            panic!("expected an EC key, got {key:?}");
        };
        assert_eq!(algorithm, KeyAlgorithm::EcP521);
        assert_eq!(private_key.len(), 66);
        assert_eq!(public_key.map(<[u8]>::len), Some(133));

        let mut out = [0u8; 512];
        let n = key.to_der(&mut out).unwrap();
        assert_eq!(&out[..n], &der[..], "re-encoding differs from OpenSSL's");
    }

    /// The bare SEC1 form, which names its curve inside itself, parses to the
    /// same key as the PKCS#8 container around it.
    #[test]
    fn an_openssl_p521_bare_key_names_its_own_curve() {
        let bare = unhex(OPENSSL_P521_SEC1);
        let wrapped = unhex(OPENSSL_P521_PKCS8);
        let parsed = parse_ec_private_key(&bare, None).unwrap();
        // Checked directly, not only against the wrapped form. With P-521
        // unrecognised both would come back as the same `Unsupported`, and an
        // equality check alone would pass on exactly the bug this is for.
        assert_eq!(parsed.algorithm(), KeyAlgorithm::EcP521);
        assert_eq!(parsed, PrivateKeyInfo::from_der(&wrapped).unwrap());
    }

    /// Both private formats report an unimplemented curve rather than refuse
    /// it. The bare form reaches the curve by a different path -- from inside
    /// the key rather than from the container around it -- and both used to
    /// be errors.
    #[test]
    fn both_private_formats_report_an_unimplemented_curve() {
        let wrapped = unhex(OPENSSL_SECP256K1_PKCS8);
        assert_eq!(
            PrivateKeyInfo::from_der(&wrapped).unwrap(),
            PrivateKeyInfo::Unsupported { oid: SECP256K1_OID }
        );
        let bare = unhex(OPENSSL_SECP256K1_SEC1);
        assert_eq!(
            parse_ec_private_key(&bare, None).unwrap(),
            PrivateKeyInfo::Unsupported { oid: SECP256K1_OID }
        );
    }
}
