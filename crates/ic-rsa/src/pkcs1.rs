//! RSASSA-PKCS1-v1_5 signatures (RFC 8017 §8.2).
//!
//! # Why the DigestInfo prefix is built, not pasted
//!
//! Every RSA implementation carries a table of hard-coded DigestInfo prefixes —
//! `3031300d060960864801650304020105000420` for SHA-256, and so on. They are
//! easy to copy and impossible to eyeball. This module instead encodes the
//! structure from RFC 8017 §9.2 note 1 at run time out of the algorithm OID:
//!
//! ```text
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm AlgorithmIdentifier,   -- SEQUENCE { OID, NULL }
//!     digest          OCTET STRING
//! }
//! ```
//!
//! A test then checks the result against the published constants, so the two
//! derivations have to agree.
//!
//! # Verification is by re-encoding
//!
//! Verification computes the expected encoded message and compares it against
//! `s^e mod n` in constant time. It never *parses* the recovered block. Parsing
//! is what produced the Bleichenbacher 2006 signature forgeries, where a lax
//! parser accepted trailing garbage after the DigestInfo and let anyone forge
//! signatures under a small public exponent with no private key at all.

use crate::key::{RsaPrivateKey, RsaPublicKey};
use crate::uint::MAX_BYTES;
use ic_core::traits::Digest;
use ic_core::{ct, ensure, Result};

/// The smallest block this will produce: RFC 8017 requires at least 8 padding
/// bytes, plus the leading `00 01` and the `00` separator.
const MIN_PADDING: usize = 8;

/// Write a DER length. Every length here is under 128, so a single byte.
fn der_len(out: &mut [u8], at: usize, len: usize) -> Result<usize> {
    ensure!(len < 128, Internal, "digestinfo length needs long-form der");
    out[at] = len as u8;
    Ok(at + 1)
}

/// Encode `DigestInfo` for `oid` over `digest` into `out`, returning its length.
///
/// Built from the ASN.1 structure rather than transcribed. See the module docs.
fn digest_info(oid: &[u8], digest: &[u8], out: &mut [u8]) -> Result<usize> {
    // Lengths, innermost first. `_content` is the length of what sits inside a
    // SEQUENCE; `_tlv` adds the two-byte tag-and-length header.
    //
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
    //                                    parameters NULL }
    let oid_tlv = 2 + oid.len();
    let null_tlv = 2;
    let alg_content = oid_tlv + null_tlv;
    let alg_tlv = 2 + alg_content;
    // DigestInfo ::= SEQUENCE { digestAlgorithm, digest OCTET STRING }
    let octet_tlv = 2 + digest.len();
    let info_content = alg_tlv + octet_tlv;
    let total = 2 + info_content;
    ensure!(out.len() >= total, InvalidLength, "digestinfo buffer");

    let mut i = 0;
    out[i] = 0x30; // SEQUENCE (DigestInfo)
    i = der_len(out, i + 1, info_content)?;

    out[i] = 0x30; // SEQUENCE (AlgorithmIdentifier)
    i = der_len(out, i + 1, alg_content)?;

    out[i] = 0x06; // OBJECT IDENTIFIER
    i = der_len(out, i + 1, oid.len())?;
    out[i..i + oid.len()].copy_from_slice(oid);
    i += oid.len();

    out[i] = 0x05; // NULL
    out[i + 1] = 0x00;
    i += 2;

    out[i] = 0x04; // OCTET STRING
    i = der_len(out, i + 1, digest.len())?;
    out[i..i + digest.len()].copy_from_slice(digest);
    i += digest.len();

    debug_assert_eq!(i, total);
    Ok(total)
}

/// EMSA-PKCS1-v1_5 encoding: `00 01 FF..FF 00 || DigestInfo`.
fn encode(oid: &[u8], digest: &[u8], em: &mut [u8]) -> Result<()> {
    let mut info = [0u8; 128];
    let info_len = digest_info(oid, digest, &mut info)?;
    ensure!(
        em.len() >= info_len + MIN_PADDING + 3,
        InvalidParameter,
        "rsa modulus too small for this digest"
    );

    em[0] = 0x00;
    em[1] = 0x01;
    let separator = em.len() - info_len - 1;
    for slot in &mut em[2..separator] {
        *slot = 0xff;
    }
    em[separator] = 0x00;
    em[separator + 1..].copy_from_slice(&info[..info_len]);
    Ok(())
}

/// A hash paired with its ASN.1 object identifier, as PKCS#1 requires.
pub trait Pkcs1Hash {
    /// The hash function.
    type Hash: Digest;
    /// The DER *contents* of the algorithm's OBJECT IDENTIFIER — the bytes
    /// after the `06 len` header.
    const OID: &'static [u8];
    /// Ontology identifier for the resulting signature scheme.
    const SCHEME_ID: &'static str;
}

/// Sign `message` with `key`, writing a signature of `key.size()` bytes.
pub fn sign<S: Pkcs1Hash>(key: &RsaPrivateKey, message: &[u8], signature: &mut [u8]) -> Result<()> {
    ensure!(
        signature.len() == key.size(),
        InvalidLength,
        "rsa signature buffer"
    );
    let digest = S::Hash::digest(message);
    let mut em = [0u8; MAX_BYTES];
    let size = key.size();
    encode(S::OID, digest.as_ref(), &mut em[..size])?;
    key.raw_private(&em[..size], signature)
}

/// Verify `signature` over `message`.
///
/// Returns `Err(AuthenticationFailed)` on any mismatch, with no detail about
/// which part failed.
pub fn verify<S: Pkcs1Hash>(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    let size = key.size();
    ensure!(
        signature.len() == size,
        AuthenticationFailed,
        "rsa signature length"
    );

    let digest = S::Hash::digest(message);
    let mut expected = [0u8; MAX_BYTES];
    encode(S::OID, digest.as_ref(), &mut expected[..size])?;

    let mut recovered = [0u8; MAX_BYTES];
    // A signature numerically >= n is invalid rather than an error worth
    // distinguishing, so fold that case into the failure.
    if key.raw_public(signature, &mut recovered[..size]).is_err() {
        return Err(ic_core::err!(AuthenticationFailed, "rsa signature"));
    }

    ensure!(
        ct::verify(&expected[..size], &recovered[..size]),
        AuthenticationFailed,
        "rsa signature"
    );
    Ok(())
}

/// Declare a PKCS#1 v1.5 scheme over one hash.
macro_rules! pkcs1_scheme {
    ($name:ident, $hash:ty, $oid:expr, $id:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl Pkcs1Hash for $name {
            type Hash = $hash;
            const OID: &'static [u8] = &$oid;
            const SCHEME_ID: &'static str = $id;
        }

        impl $name {
            /// Ontology identifier for this scheme.
            pub const ID: &'static str = $id;

            /// Sign `message`, writing `key.size()` bytes into `signature`.
            pub fn sign(key: &RsaPrivateKey, message: &[u8], signature: &mut [u8]) -> Result<()> {
                sign::<$name>(key, message, signature)
            }

            /// Verify `signature` over `message`.
            pub fn verify(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
                verify::<$name>(key, message, signature)
            }
        }
    };
}

// The NIST hash OID arc is 2.16.840.1.101.3.4.2.n:
//   2.16     -> 2*40 + 16 = 0x60
//   840      -> 0x86 0x48   (base-128, high bit set on all but the last byte)
//   1.101    -> 0x01 0x65
//   3.4.2    -> 0x03 0x04 0x02
//   n        -> SHA-256 = 1, SHA-384 = 2, SHA-512 = 3
pkcs1_scheme!(
    Pkcs1Sha256,
    ic_hash::Sha256,
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    "rsa-pkcs1-sha256",
    "RSASSA-PKCS1-v1_5 with SHA-256."
);
pkcs1_scheme!(
    Pkcs1Sha384,
    ic_hash::Sha384,
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
    "rsa-pkcs1-sha384",
    "RSASSA-PKCS1-v1_5 with SHA-384."
);
pkcs1_scheme!(
    Pkcs1Sha512,
    ic_hash::Sha512,
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    "rsa-pkcs1-sha512",
    "RSASSA-PKCS1-v1_5 with SHA-512."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkey::{test_private_key, test_public_key};

    /// The DigestInfo prefixes published in RFC 8017 §9.2 note 1. If the
    /// encoder and these disagree, one of them is wrong — and they were arrived
    /// at independently, the encoder from the ASN.1 grammar and these from the
    /// RFC.
    const SHA256_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_PREFIX: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512_PREFIX: [u8; 19] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    #[test]
    fn digest_info_matches_the_published_prefixes() {
        for (oid, digest_len, want) in [
            (Pkcs1Sha256::OID, 32usize, &SHA256_PREFIX),
            (Pkcs1Sha384::OID, 48, &SHA384_PREFIX),
            (Pkcs1Sha512::OID, 64, &SHA512_PREFIX),
        ] {
            let digest = vec![0xabu8; digest_len];
            let mut out = [0u8; 128];
            let len = digest_info(oid, &digest, &mut out).unwrap();
            assert_eq!(len, 19 + digest_len);
            assert_eq!(
                &out[..19],
                &want[..],
                "prefix for a {digest_len}-byte digest"
            );
            assert_eq!(&out[19..len], &digest[..], "digest follows the prefix");
        }
    }

    /// EMSA-PKCS1-v1_5 rebuilt straight from RFC 8017 §9.2, independently of the
    /// implementation, and compared byte for byte.
    #[test]
    fn encoding_matches_an_independent_construction() {
        let message = b"the quick brown fox";
        let digest = ic_hash::Sha256::digest(message);

        let mut want = vec![0u8; 256];
        want[0] = 0x00;
        want[1] = 0x01;
        // T is the prefix plus the hash: 19 + 32 = 51 bytes. PS runs from index
        // 2 up to the 0x00 separator.
        let t_start = 256 - 51;
        for slot in want.iter_mut().take(t_start - 1).skip(2) {
            *slot = 0xff;
        }
        want[t_start - 1] = 0x00;
        want[t_start..t_start + 19].copy_from_slice(&SHA256_PREFIX);
        want[t_start + 19..].copy_from_slice(digest.as_ref());
        assert!(t_start - 3 >= 8, "at least 8 padding bytes");

        let mut got = vec![0u8; 256];
        encode(Pkcs1Sha256::OID, digest.as_ref(), &mut got).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = test_private_key();
        let public = test_public_key();
        let mut sig = [0u8; 256];

        for message in [&b""[..], b"a", b"the quick brown fox", &[0x5au8; 1000][..]] {
            Pkcs1Sha256::sign(&key, message, &mut sig).unwrap();
            Pkcs1Sha256::verify(&public, message, &sig).unwrap();

            Pkcs1Sha384::sign(&key, message, &mut sig).unwrap();
            Pkcs1Sha384::verify(&public, message, &sig).unwrap();

            Pkcs1Sha512::sign(&key, message, &mut sig).unwrap();
            Pkcs1Sha512::verify(&public, message, &sig).unwrap();
        }
    }

    #[test]
    fn signatures_are_deterministic() {
        let key = test_private_key();
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        Pkcs1Sha256::sign(&key, b"determinism", &mut a).unwrap();
        Pkcs1Sha256::sign(&key, b"determinism", &mut b).unwrap();
        assert_eq!(a, b, "PKCS#1 v1.5 has no randomness");
    }

    #[test]
    fn verification_rejects_tampering() {
        let key = test_private_key();
        let public = test_public_key();
        let mut sig = [0u8; 256];
        Pkcs1Sha256::sign(&key, b"message", &mut sig).unwrap();

        assert!(
            Pkcs1Sha256::verify(&public, b"messagf", &sig).is_err(),
            "wrong message"
        );
        assert!(
            Pkcs1Sha384::verify(&public, b"message", &sig).is_err(),
            "wrong hash for this signature"
        );

        for bit in [0usize, 7, 128, 1024, 2047] {
            let mut bad = sig;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(
                Pkcs1Sha256::verify(&public, b"message", &bad).is_err(),
                "flipped signature bit {bit}"
            );
        }

        assert!(
            Pkcs1Sha256::verify(&public, b"message", &sig[..255]).is_err(),
            "truncated signature"
        );
    }

    /// The failure mode this design exists to prevent: a block with the right
    /// DigestInfo but short padding, which a lax *parser* would accept. The
    /// re-encoding comparison rejects it because the expected block always uses
    /// full-length padding.
    #[test]
    fn short_padding_does_not_match_the_expected_encoding() {
        let digest = ic_hash::Sha256::digest(b"message");

        let mut forged = [0u8; 256];
        forged[0] = 0x00;
        forged[1] = 0x01;
        forged[2] = 0xff;
        forged[3] = 0x00;
        forged[4..23].copy_from_slice(&SHA256_PREFIX);
        forged[23..55].copy_from_slice(digest.as_ref());
        for (i, slot) in forged[55..].iter_mut().enumerate() {
            *slot = i as u8;
        }

        let mut expected = [0u8; 256];
        encode(Pkcs1Sha256::OID, digest.as_ref(), &mut expected).unwrap();
        assert_ne!(
            expected, forged,
            "the re-encoded block must differ from the short-padded one"
        );
    }

    #[test]
    fn oversized_digests_are_refused_for_small_moduli() {
        // A 2048-bit modulus has room for SHA-512; a 256-bit one would not.
        // Exercise the guard directly.
        let digest = [0u8; 64];
        let mut em = [0u8; 32];
        assert!(encode(Pkcs1Sha512::OID, &digest, &mut em).is_err());
    }
}
