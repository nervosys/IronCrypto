//! Object identifiers, as DER content bytes.
//!
//! # Derived, not pasted
//!
//! Each constant below is accompanied by the dotted arc it encodes, and
//! `tests::every_oid_matches_its_dotted_form` re-encodes that arc with an
//! independent encoder written from X.690 §8.19 and compares. A mistyped byte
//! here would otherwise be invisible: the wrong OID parses cleanly, matches
//! nothing, and turns into "unsupported algorithm" at some distance from the
//! cause.

/// `rsaEncryption`, 1.2.840.113549.1.1.1 (PKCS#1).
pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// `id-RSASSA-PSS`, 1.2.840.113549.1.1.10.
pub const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];

/// `id-ecPublicKey`, 1.2.840.10045.2.1 (SEC1 / RFC 5480).
pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// `prime256v1` (P-256, secp256r1), 1.2.840.10045.3.1.7.
pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// `secp384r1` (P-384), 1.3.132.0.34.
pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// `id-Ed25519`, 1.3.101.112 (RFC 8410).
pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// `id-X25519`, 1.3.101.110 (RFC 8410).
pub const X25519: &[u8] = &[0x2b, 0x65, 0x6e];

/// The algorithm an object identifier names, for the key formats this crate
/// understands.
///
/// A closed vocabulary rather than a raw OID slice: an unknown OID becomes
/// [`KeyAlgorithm::Unknown`] at the parse boundary, so downstream code matches
/// exhaustively instead of comparing byte strings at each use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA, any padding. The key itself does not fix the padding.
    Rsa,
    /// ECDSA or ECDH over P-256.
    EcP256,
    /// ECDSA or ECDH over P-384.
    EcP384,
    /// Ed25519 signatures.
    Ed25519,
    /// X25519 key agreement.
    X25519,
    /// An algorithm this build does not implement.
    ///
    /// Carried rather than rejected so a caller can report *which* algorithm a
    /// key uses. Nothing here will operate on it.
    Unknown,
}

impl KeyAlgorithm {
    /// Stable identifier, matching the ontology where one exists.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::EcP256 => "p256",
            Self::EcP384 => "p384",
            Self::Ed25519 => "ed25519",
            Self::X25519 => "x25519",
            Self::Unknown => "unknown",
        }
    }

    /// The uncompressed public-key length for the elliptic-curve algorithms.
    pub const fn public_key_len(self) -> Option<usize> {
        match self {
            Self::EcP256 => Some(65),
            Self::EcP384 => Some(97),
            Self::Ed25519 | Self::X25519 => Some(32),
            Self::Rsa | Self::Unknown => None,
        }
    }

    /// The private-key length for the algorithms with a fixed one.
    pub const fn private_key_len(self) -> Option<usize> {
        match self {
            Self::EcP256 => Some(32),
            Self::EcP384 => Some(48),
            Self::Ed25519 | Self::X25519 => Some(32),
            Self::Rsa | Self::Unknown => None,
        }
    }
}

/// Resolve a named curve OID to its algorithm.
pub(crate) fn curve_from_oid(oid: &[u8]) -> KeyAlgorithm {
    if oid == P256 {
        KeyAlgorithm::EcP256
    } else if oid == P384 {
        KeyAlgorithm::EcP384
    } else {
        KeyAlgorithm::Unknown
    }
}

/// The named-curve OID for an elliptic-curve algorithm.
pub(crate) fn curve_oid(alg: KeyAlgorithm) -> Option<&'static [u8]> {
    match alg {
        KeyAlgorithm::EcP256 => Some(P256),
        KeyAlgorithm::EcP384 => Some(P384),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a dotted OID from X.690 §8.19: the first two arcs collapse into
    /// `40 * a + b`, and every arc after that is base-128, big-endian, with the
    /// high bit set on all but the final byte.
    fn encode_oid(arcs: &[u32]) -> std::vec::Vec<u8> {
        assert!(arcs.len() >= 2, "an oid has at least two arcs");
        assert!(arcs[0] <= 2, "the first arc is 0, 1, or 2");
        let mut out = std::vec::Vec::new();
        let emit = |mut v: u32, out: &mut std::vec::Vec<u8>| {
            let mut stack = [0u8; 5];
            let mut n = 0;
            loop {
                stack[n] = (v & 0x7f) as u8;
                n += 1;
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            for i in (0..n).rev() {
                let last = i == 0;
                out.push(if last { stack[i] } else { stack[i] | 0x80 });
            }
        };
        emit(arcs[0] * 40 + arcs[1], &mut out);
        for arc in &arcs[2..] {
            emit(*arc, &mut out);
        }
        out
    }

    #[test]
    fn the_reference_encoder_matches_the_textbook_example() {
        // X.690's own example: 2.999.3 encodes as 88 37 03.
        assert_eq!(encode_oid(&[2, 999, 3]), std::vec![0x88, 0x37, 0x03]);
        // 1.2.840 -> 2a 86 48, the prefix of every PKCS OID.
        assert_eq!(encode_oid(&[1, 2, 840]), std::vec![0x2a, 0x86, 0x48]);
    }

    #[test]
    fn every_oid_matches_its_dotted_form() {
        let cases: &[(&[u8], &[u32], &str)] = &[
            (
                RSA_ENCRYPTION,
                &[1, 2, 840, 113549, 1, 1, 1],
                "rsaEncryption",
            ),
            (RSASSA_PSS, &[1, 2, 840, 113549, 1, 1, 10], "id-RSASSA-PSS"),
            (EC_PUBLIC_KEY, &[1, 2, 840, 10045, 2, 1], "id-ecPublicKey"),
            (P256, &[1, 2, 840, 10045, 3, 1, 7], "prime256v1"),
            (P384, &[1, 3, 132, 0, 34], "secp384r1"),
            (ED25519, &[1, 3, 101, 112], "id-Ed25519"),
            (X25519, &[1, 3, 101, 110], "id-X25519"),
        ];
        for (constant, arcs, name) in cases {
            assert_eq!(*constant, &encode_oid(arcs)[..], "{name}");
        }
    }

    #[test]
    fn oids_are_distinct() {
        let all = [
            RSA_ENCRYPTION,
            RSASSA_PSS,
            EC_PUBLIC_KEY,
            P256,
            P384,
            ED25519,
            X25519,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two oids collide");
            }
        }
    }

    #[test]
    fn curve_lookup_round_trips() {
        for alg in [KeyAlgorithm::EcP256, KeyAlgorithm::EcP384] {
            let oid = curve_oid(alg).unwrap();
            assert_eq!(curve_from_oid(oid), alg);
        }
        assert_eq!(curve_from_oid(ED25519), KeyAlgorithm::Unknown);
        assert_eq!(curve_oid(KeyAlgorithm::Rsa), None);
    }

    #[test]
    fn key_lengths_match_the_curves() {
        // Uncompressed SEC1 is 0x04 plus two field elements.
        assert_eq!(KeyAlgorithm::EcP256.public_key_len(), Some(1 + 32 + 32));
        assert_eq!(KeyAlgorithm::EcP384.public_key_len(), Some(1 + 48 + 48));
        // RSA public keys have no fixed length.
        assert_eq!(KeyAlgorithm::Rsa.public_key_len(), None);
    }
}
