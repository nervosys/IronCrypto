//! RSASSA-PSS signatures (RFC 8017 §8.1).
//!
//! PSS is the padding to prefer for new RSA signatures: it has a security proof
//! reducing forgery to the RSA problem, which PKCS#1 v1.5 does not, and its
//! randomized salt means two signatures over the same message differ. PKCS#1
//! v1.5 remains here because certificates in the wild use it.
//!
//! The salt length is always the hash length, which is what FIPS 186-5 and
//! essentially every deployment use.
//!
//! # `emBits = modBits - 1`
//!
//! RFC 8017 specifies the encoded message as one bit shorter than the modulus,
//! with that top bit cleared. That is what guarantees `EM < n`, so the private
//! operation always has a valid input — no rejection sampling, no retry loop.

use crate::key::{RsaPrivateKey, RsaPublicKey};
use crate::uint::MAX_BYTES;
use ic_core::traits::{Digest, RandomSource};
use ic_core::{ct, ensure, Result};

/// Largest digest this module handles, which bounds the stack buffers.
const MAX_HASH: usize = 64;

/// MGF1 (RFC 8017 B.2.1): `Hash(seed || counter)` concatenated until `out` is
/// full, with the counter a four-byte big-endian integer.
fn mgf1<H: Digest>(seed: &[u8], out: &mut [u8]) {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(H::OUTPUT_LEN)) {
        let mut h = H::new();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        let block = h.finalize();
        chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
    }
}

/// `H = Hash(00 00 00 00 00 00 00 00 || mHash || salt)`, the M' of RFC 8017 §9.1.
fn hash_m_prime<H: Digest>(m_hash: &[u8], salt: &[u8]) -> H::Output {
    let mut h = H::new();
    h.update(&[0u8; 8]);
    h.update(m_hash);
    h.update(salt);
    h.finalize()
}

/// EMSA-PSS-ENCODE over an already-computed message hash.
fn encode<H: Digest>(m_hash: &[u8], salt: &[u8], em_bits: usize, em: &mut [u8]) -> Result<()> {
    let h_len = H::OUTPUT_LEN;
    let s_len = salt.len();
    let em_len = em.len();
    ensure!(
        em_len >= h_len + s_len + 2,
        InvalidParameter,
        "rsa modulus too small for this hash and salt"
    );

    let h = hash_m_prime::<H>(m_hash, salt);
    let h = h.as_ref();

    // DB = PS || 0x01 || salt, the same length as the masked half.
    let db_len = em_len - h_len - 1;
    let (masked_db, tail) = em.split_at_mut(db_len);
    for slot in masked_db.iter_mut() {
        *slot = 0;
    }
    masked_db[db_len - s_len - 1] = 0x01;
    masked_db[db_len - s_len..].copy_from_slice(salt);

    let mut mask = [0u8; MAX_BYTES];
    mgf1::<H>(h, &mut mask[..db_len]);
    for (slot, m) in masked_db.iter_mut().zip(&mask[..db_len]) {
        *slot ^= m;
    }

    // Clear the leftmost 8*emLen - emBits bits, which is what keeps EM < n.
    let spare = 8 * em_len - em_bits;
    if spare > 0 {
        masked_db[0] &= 0xff >> spare;
    }

    tail[..h_len].copy_from_slice(h);
    tail[h_len] = 0xbc;
    Ok(())
}

/// EMSA-PSS-VERIFY. Returns whether `em` is a valid encoding of `m_hash`.
fn verify_encoding<H: Digest>(m_hash: &[u8], s_len: usize, em_bits: usize, em: &[u8]) -> bool {
    let h_len = H::OUTPUT_LEN;
    let em_len = em.len();
    if em_len < h_len + s_len + 2 {
        return false;
    }
    if em[em_len - 1] != 0xbc {
        return false;
    }

    let db_len = em_len - h_len - 1;
    let spare = 8 * em_len - em_bits;
    if spare > 0 && em[0] & !(0xff >> spare) != 0 {
        return false;
    }

    let h = &em[db_len..db_len + h_len];
    let mut db = [0u8; MAX_BYTES];
    let db = &mut db[..db_len];
    db.copy_from_slice(&em[..db_len]);

    let mut mask = [0u8; MAX_BYTES];
    mgf1::<H>(h, &mut mask[..db_len]);
    for (slot, m) in db.iter_mut().zip(&mask[..db_len]) {
        *slot ^= m;
    }
    if spare > 0 {
        db[0] &= 0xff >> spare;
    }

    // DB must be PS(zeros) || 0x01 || salt.
    let separator = db_len - s_len - 1;
    if db[..separator].iter().any(|b| *b != 0) || db[separator] != 0x01 {
        return false;
    }

    let recomputed = hash_m_prime::<H>(m_hash, &db[separator + 1..]);
    ct::verify(recomputed.as_ref(), h)
}

/// Sign `message` with a fresh random salt of the hash's length.
pub fn sign<H: Digest, R: RandomSource + ?Sized>(
    key: &RsaPrivateKey,
    message: &[u8],
    rng: &mut R,
    signature: &mut [u8],
) -> Result<()> {
    let mut salt = [0u8; MAX_HASH];
    let salt = &mut salt[..H::OUTPUT_LEN];
    rng.fill(salt)?;
    sign_with_salt::<H>(key, message, salt, signature)
}

/// Sign with a caller-supplied salt.
///
/// Internal, and internal it stays: a repeated salt forfeits the randomization
/// the PSS security proof relies on. It exists so the known-answer test has a
/// deterministic signature to compare against.
pub(crate) fn sign_with_salt<H: Digest>(
    key: &RsaPrivateKey,
    message: &[u8],
    salt: &[u8],
    signature: &mut [u8],
) -> Result<()> {
    let size = key.size();
    ensure!(
        signature.len() == size,
        InvalidLength,
        "rsa signature buffer"
    );

    let m_hash = H::digest(message);

    // emBits is one less than the modulus bit length, so EM < n by construction.
    let em_bits = key.public_key().bits() - 1;
    let em_len = em_bits.div_ceil(8);
    let mut block = [0u8; MAX_BYTES];
    encode::<H>(m_hash.as_ref(), salt, em_bits, &mut block[..em_len])?;

    // Right-align the encoding in a full-width block when emLen < modulus size,
    // which happens when the modulus bit length is one more than a multiple of
    // eight.
    let mut input = [0u8; MAX_BYTES];
    input[size - em_len..size].copy_from_slice(&block[..em_len]);
    key.raw_private(&input[..size], signature)
}

/// Verify a PSS signature over `message`.
pub fn verify<H: Digest>(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    let size = key.size();
    ensure!(
        signature.len() == size,
        AuthenticationFailed,
        "rsa signature length"
    );

    let mut recovered = [0u8; MAX_BYTES];
    if key.raw_public(signature, &mut recovered[..size]).is_err() {
        return Err(ic_core::err!(AuthenticationFailed, "rsa signature"));
    }

    let em_bits = key.bits() - 1;
    let em_len = em_bits.div_ceil(8);
    // Any bytes to the left of the encoding must be zero.
    if recovered[..size - em_len].iter().any(|b| *b != 0) {
        return Err(ic_core::err!(AuthenticationFailed, "rsa signature"));
    }

    let m_hash = H::digest(message);
    ensure!(
        verify_encoding::<H>(
            m_hash.as_ref(),
            H::OUTPUT_LEN,
            em_bits,
            &recovered[size - em_len..size]
        ),
        AuthenticationFailed,
        "rsa signature"
    );
    Ok(())
}

/// Declare a PSS scheme over one hash.
macro_rules! pss_scheme {
    ($name:ident, $hash:ty, $id:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl $name {
            /// Ontology identifier for this scheme.
            pub const ID: &'static str = $id;

            /// Sign `message` with a fresh random salt.
            pub fn sign<R: RandomSource + ?Sized>(
                key: &RsaPrivateKey,
                message: &[u8],
                rng: &mut R,
                signature: &mut [u8],
            ) -> Result<()> {
                sign::<$hash, R>(key, message, rng, signature)
            }

            /// Verify `signature` over `message`.
            pub fn verify(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
                verify::<$hash>(key, message, signature)
            }
        }
    };
}

pss_scheme!(
    PssSha256,
    ic_hash::Sha256,
    "rsa-pss-sha256",
    "RSASSA-PSS with SHA-256 and a 32-byte salt."
);
pss_scheme!(
    PssSha384,
    ic_hash::Sha384,
    "rsa-pss-sha384",
    "RSASSA-PSS with SHA-384 and a 48-byte salt."
);
pss_scheme!(
    PssSha512,
    ic_hash::Sha512,
    "rsa-pss-sha512",
    "RSASSA-PSS with SHA-512 and a 64-byte salt."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkey::{test_private_key, test_public_key};
    use ic_hash::Sha256;

    fn rng(label: &[u8]) -> ic_drbg::Rng {
        ic_drbg::Rng::from_entropy(&[0x42u8; 32], label).unwrap()
    }

    /// MGF1 is a counter-mode hash, which is simple enough to rebuild in the
    /// test from RFC 8017 B.2.1 and compare against.
    #[test]
    fn mgf1_matches_an_independent_construction() {
        for len in [1usize, 20, 32, 33, 64, 100, 255] {
            let mut got = vec![0u8; len];
            mgf1::<Sha256>(b"seed", &mut got);

            let mut want = Vec::new();
            let mut counter = 0u32;
            while want.len() < len {
                let mut h = Sha256::new();
                h.update(b"seed");
                h.update(&counter.to_be_bytes());
                want.extend_from_slice(h.finalize().as_ref());
                counter += 1;
            }
            want.truncate(len);
            assert_eq!(got, want, "mgf1 output of {len} bytes");
        }
    }

    /// The encoder and the verifier are separate code paths reading the same
    /// spec; every well-formed encoding must satisfy the verifier.
    #[test]
    fn encoding_verifies() {
        let m_hash = Sha256::digest(b"message");
        for em_bits in [2047usize, 3071, 4095] {
            let em_len = em_bits.div_ceil(8);
            let mut em = vec![0u8; em_len];
            let salt = [0x11u8; 32];
            encode::<Sha256>(m_hash.as_ref(), &salt, em_bits, &mut em).unwrap();

            assert_eq!(em[em_len - 1], 0xbc, "trailer");
            assert_eq!(em[0] & 0x80, 0, "top bit cleared so EM < n");
            assert!(verify_encoding::<Sha256>(m_hash.as_ref(), 32, em_bits, &em));

            // A different message must not verify against this encoding.
            let other = Sha256::digest(b"other");
            assert!(!verify_encoding::<Sha256>(other.as_ref(), 32, em_bits, &em));
        }
    }

    #[test]
    fn encoding_rejects_a_corrupted_block() {
        let m_hash = Sha256::digest(b"message");
        let em_bits = 2047;
        let mut em = vec![0u8; 256];
        encode::<Sha256>(m_hash.as_ref(), &[0x11u8; 32], em_bits, &mut em).unwrap();

        for index in [0usize, 1, 100, 223, 224, 254, 255] {
            let mut bad = em.clone();
            bad[index] ^= 0x01;
            assert!(
                !verify_encoding::<Sha256>(m_hash.as_ref(), 32, em_bits, &bad),
                "flipped byte {index}"
            );
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = test_private_key();
        let public = test_public_key();
        let mut r = rng(b"pss-round-trip");
        let mut sig = [0u8; 256];

        for message in [&b""[..], b"a", b"the quick brown fox", &[0x5au8; 1000][..]] {
            PssSha256::sign(&key, message, &mut r, &mut sig).unwrap();
            PssSha256::verify(&public, message, &sig).unwrap();

            PssSha384::sign(&key, message, &mut r, &mut sig).unwrap();
            PssSha384::verify(&public, message, &sig).unwrap();

            PssSha512::sign(&key, message, &mut r, &mut sig).unwrap();
            PssSha512::verify(&public, message, &sig).unwrap();
        }
    }

    /// The salt is what makes PSS randomized; two signatures over one message
    /// must differ, and both must verify.
    #[test]
    fn signatures_are_randomized() {
        let key = test_private_key();
        let public = test_public_key();
        let mut r = rng(b"pss-randomized");
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        PssSha256::sign(&key, b"message", &mut r, &mut a).unwrap();
        PssSha256::sign(&key, b"message", &mut r, &mut b).unwrap();
        assert_ne!(a, b, "the salt differs between signatures");
        PssSha256::verify(&public, b"message", &a).unwrap();
        PssSha256::verify(&public, b"message", &b).unwrap();
    }

    #[test]
    fn verification_rejects_tampering() {
        let key = test_private_key();
        let public = test_public_key();
        let mut r = rng(b"pss-tamper");
        let mut sig = [0u8; 256];
        PssSha256::sign(&key, b"message", &mut r, &mut sig).unwrap();

        assert!(
            PssSha256::verify(&public, b"messagf", &sig).is_err(),
            "wrong message"
        );
        assert!(
            PssSha384::verify(&public, b"message", &sig).is_err(),
            "wrong hash"
        );
        assert!(
            PssSha256::verify(&public, b"message", &sig[..255]).is_err(),
            "truncated"
        );

        for bit in [0usize, 7, 128, 1024, 2047] {
            let mut bad = sig;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(
                PssSha256::verify(&public, b"message", &bad).is_err(),
                "flipped signature bit {bit}"
            );
        }
    }

    /// A PKCS#1 v1.5 signature must not verify as PSS, and vice versa. The two
    /// paddings are incompatible by design, and confusing them has been a real
    /// source of vulnerabilities.
    #[test]
    fn the_two_paddings_do_not_cross_verify() {
        let key = test_private_key();
        let public = test_public_key();
        let mut r = rng(b"pss-cross");
        let mut pss_sig = [0u8; 256];
        let mut v15_sig = [0u8; 256];
        PssSha256::sign(&key, b"message", &mut r, &mut pss_sig).unwrap();
        crate::Pkcs1Sha256::sign(&key, b"message", &mut v15_sig).unwrap();

        assert!(crate::Pkcs1Sha256::verify(&public, b"message", &pss_sig).is_err());
        assert!(PssSha256::verify(&public, b"message", &v15_sig).is_err());
    }
}
