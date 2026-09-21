//! AES-GCM-SIV (RFC 8452): authenticated encryption that survives nonce reuse.
//!
//! # What this is for
//!
//! GCM fails catastrophically when a nonce repeats. Two messages under the same
//! key and nonce share a keystream, so their XOR is the XOR of the plaintexts,
//! and the authentication key falls out of the pair — every message under that
//! key becomes forgeable, not just the two that collided. That is not a
//! theoretical concern; it is the most common way GCM deployments fail.
//!
//! GCM-SIV derives its keystream from the tag, and the tag from the plaintext.
//! Repeat a nonce and the worst an attacker learns is whether two plaintexts
//! were equal. Everything else holds. The price is that encryption needs two
//! passes over the plaintext, so it cannot be streamed.
//!
//! Reach for it when nonces come from anywhere you do not fully control: a
//! distributed system without a shared counter, a device that might be restored
//! from a snapshot, a protocol where the peer picks the nonce.
//!
//! # Verification status — read this before using it
//!
//! **This implementation is not interoperability-tested.** It is registered in
//! the ontology as [`Experimental`][ic_ontology_status], not `Available`, and
//! it is excluded from the FIPS approved mode. AES-GCM-SIV is an IETF RFC
//! rather than a NIST standard, so it is not FIPS-approved in any case.
//!
//! What *is* verified:
//!
//! - [`crate::polyval`] is checked against the GHASH construction of RFC 8452
//!   Appendix A, over a GHASH that published GCM vectors validate. That is a
//!   genuine independent oracle for the hardest component.
//! - AES beneath it is validated against FIPS 197 and SP 800-38A.
//! - The structural properties below: determinism, nonce-misuse behaviour that
//!   differs from CTR mode, and tamper rejection.
//!
//! What is **not** verified: that the assembly of those pieces — the key
//! derivation, the length block, the tag and counter bit-twiddling — matches
//! what other implementations compute. No published RFC 8452 vector is wired
//! in. An implementation can pass every test here and still interoperate with
//! nothing, which is exactly the failure this project takes seriously enough to
//! label rather than gloss. Wire in a vector from RFC 8452 Appendix C before
//! trusting this against another party.
//!
//! [ic_ontology_status]: https://docs.rs/ic-ontology

use crate::polyval::Polyval;
use ic_core::traits::{Aead, Algorithm, BlockCipher, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// Nonce width. RFC 8452 fixes this at 96 bits.
pub const NONCE_LEN: usize = 12;
/// Tag width.
pub const TAG_LEN: usize = 16;
const BLOCK_LEN: usize = 16;

/// Derive the per-nonce message keys (RFC 8452 section 4).
///
/// Each 16-byte derivation block is a little-endian 32-bit counter followed by
/// the nonce, and only the first eight bytes of each AES output are used. The
/// discarded half is what stops the derived keys from being a permutation of
/// the key itself.
fn derive_keys<C: BlockCipher>(
    key_cipher: &C,
    nonce: &[u8],
    auth_key: &mut [u8; 16],
    enc_key: &mut [u8],
) -> Result<()> {
    let mut block = [0u8; BLOCK_LEN];
    block[4..].copy_from_slice(nonce);

    let mut take = |counter: u32, out: &mut [u8]| -> Result<()> {
        block[0..4].copy_from_slice(&counter.to_le_bytes());
        let mut b = block;
        key_cipher.encrypt_block(&mut b)?;
        out.copy_from_slice(&b[..8]);
        b.zeroize();
        Ok(())
    };

    take(0, &mut auth_key[0..8])?;
    take(1, &mut auth_key[8..16])?;
    for (i, chunk) in enc_key.chunks_mut(8).enumerate() {
        take(2 + i as u32, chunk)?;
    }
    block.zeroize();
    Ok(())
}

/// POLYVAL over the padded AAD, the padded message, and the length block.
fn authenticate(auth_key: [u8; 16], aad: &[u8], message: &[u8]) -> [u8; 16] {
    let mut p = Polyval::new(auth_key);
    p.update_padded(aad);
    p.update_padded(message);

    // The length block is bit counts, little-endian, AAD first. Including it is
    // what stops an attacker moving bytes between the AAD and the message.
    let mut lengths = [0u8; BLOCK_LEN];
    lengths[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
    lengths[8..16].copy_from_slice(&((message.len() as u64) * 8).to_le_bytes());
    p.update_block(&lengths);
    p.finish()
}

/// CTR mode as RFC 8452 defines it: a little-endian 32-bit counter in the first
/// four bytes, the rest of the block fixed.
///
/// Note this is *not* the big-endian counter GCM uses. Same idea, different
/// byte order, and getting it wrong produces a cipher that decrypts its own
/// output and nobody else's.
fn ctr_xor<C: BlockCipher>(cipher: &C, counter_block: &[u8; 16], in_out: &mut [u8]) -> Result<()> {
    let mut block = *counter_block;
    for chunk in in_out.chunks_mut(BLOCK_LEN) {
        let mut keystream = block;
        cipher.encrypt_block(&mut keystream)?;
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
            *b ^= *k;
        }
        keystream.zeroize();

        let counter = u32::from_le_bytes(block[0..4].try_into().unwrap());
        block[0..4].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
    }
    block.zeroize();
    Ok(())
}

/// Declare an AES-GCM-SIV over one AES key size.
macro_rules! gcm_siv {
    ($name:ident, $cipher:ty, $key_len:literal, $id:literal, $disp:literal,
     $kat_ct:literal, $kat_tag:literal) => {
        #[doc = concat!("RFC 8452 ", $disp, ". See the module docs on verification status.")]
        pub struct $name {
            key: [u8; $key_len],
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.key.zeroize();
            }
        }

        impl Aead for $name {
            const KEY_LEN: usize = $key_len;
            const NONCE_LEN: usize = NONCE_LEN;
            const TAG_LEN: usize = TAG_LEN;

            fn new(key: &[u8]) -> Result<Self> {
                ensure!(key.len() == $key_len, InvalidLength, "aes-gcm-siv key");
                let mut k = [0u8; $key_len];
                k.copy_from_slice(key);
                Ok(Self { key: k })
            }

            fn seal_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &mut [u8],
            ) -> Result<()> {
                ensure!(nonce.len() == NONCE_LEN, InvalidLength, "aes-gcm-siv nonce");
                ensure!(tag.len() == TAG_LEN, InvalidLength, "aes-gcm-siv tag");

                let key_cipher = <$cipher>::new(&self.key)?;
                let mut auth_key = [0u8; 16];
                let mut enc_key = [0u8; $key_len];
                derive_keys(&key_cipher, nonce, &mut auth_key, &mut enc_key)?;
                let message_cipher = <$cipher>::new(&enc_key)?;
                enc_key.zeroize();

                // The tag is computed over the *plaintext*, which is what makes
                // the keystream depend on it and the whole thing misuse
                // resistant. It is also why this cannot be streamed.
                let mut s = authenticate(auth_key, aad, in_out);
                auth_key.zeroize();
                for (b, n) in s.iter_mut().zip(nonce.iter()) {
                    *b ^= *n;
                }
                s[15] &= 0x7f;
                message_cipher.encrypt_block(&mut s)?;
                tag.copy_from_slice(&s);

                let mut counter_block = s;
                counter_block[15] |= 0x80;
                ctr_xor(&message_cipher, &counter_block, in_out)?;
                counter_block.zeroize();
                s.zeroize();
                Ok(())
            }

            fn open_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &[u8],
            ) -> Result<()> {
                ensure!(nonce.len() == NONCE_LEN, InvalidLength, "aes-gcm-siv nonce");
                ensure!(tag.len() == TAG_LEN, InvalidLength, "aes-gcm-siv tag");

                let key_cipher = <$cipher>::new(&self.key)?;
                let mut auth_key = [0u8; 16];
                let mut enc_key = [0u8; $key_len];
                derive_keys(&key_cipher, nonce, &mut auth_key, &mut enc_key)?;
                let message_cipher = <$cipher>::new(&enc_key)?;
                enc_key.zeroize();

                let mut counter_block = [0u8; BLOCK_LEN];
                counter_block.copy_from_slice(tag);
                counter_block[15] |= 0x80;
                ctr_xor(&message_cipher, &counter_block, in_out)?;
                counter_block.zeroize();

                let mut s = authenticate(auth_key, aad, in_out);
                auth_key.zeroize();
                for (b, n) in s.iter_mut().zip(nonce.iter()) {
                    *b ^= *n;
                }
                s[15] &= 0x7f;
                message_cipher.encrypt_block(&mut s)?;

                let ok = ic_core::ct::verify(&s, tag);
                s.zeroize();
                if !ok {
                    // Never hand back unauthenticated plaintext.
                    in_out.zeroize();
                    return Err(ic_core::err!(AuthenticationFailed, $id));
                }
                Ok(())
            }
        }

        impl SelfTest for $name {
            /// RFC 8452 appendix C, plus the structural properties a vector
            /// cannot express.
            ///
            /// The vector is the part that says this computes AES-GCM-SIV
            /// rather than something self-consistent. The checks after it cover
            /// what no vector does: that a tampered tag is refused, that
            /// changed associated data is refused, and that a failed open
            /// clears the buffer instead of releasing unauthenticated
            /// plaintext.
            ///
            /// All 50 published cases run in
            /// `crates/iron-crypto/tests/vectors.rs`; this is the one the module
            /// checks at startup, where FIPS 140-3 wants a known-answer test and
            /// not a test suite.
            fn self_test() -> Result<()> {
                // Key, nonce and associated data are shared between the two
                // published cases; only the key length and the answer differ.
                let mut key = [0u8; $key_len];
                key[0] = 0x01;
                let kat = <Self as Aead>::new(&key)?;

                let mut nonce_kat = [0u8; NONCE_LEN];
                nonce_kat[0] = 0x03;

                let mut buf = [0x02u8, 0, 0, 0, 0, 0, 0, 0];
                let mut tag = [0u8; TAG_LEN];
                kat.seal_detached(&nonce_kat, &[0x01], &mut buf, &mut tag)?;

                let mut want_ct = [0u8; 8];
                let mut want_tag = [0u8; TAG_LEN];
                ic_core::codec::hex_decode($kat_ct, &mut want_ct)?;
                ic_core::codec::hex_decode($kat_tag, &mut want_tag)?;
                ensure!(
                    ic_core::ct::verify(&want_ct, &buf) && ic_core::ct::verify(&want_tag, &tag),
                    SelfTestFailed,
                    $id
                );

                let cipher = <Self as Aead>::new(&[0x42u8; $key_len])?;
                let nonce = [0x24u8; NONCE_LEN];

                let mut a = *b"self-test message";
                let mut tag_a = [0u8; TAG_LEN];
                cipher.seal_detached(&nonce, b"aad", &mut a, &mut tag_a)?;

                // Deterministic: the same inputs give the same output.
                let mut b = *b"self-test message";
                let mut tag_b = [0u8; TAG_LEN];
                cipher.seal_detached(&nonce, b"aad", &mut b, &mut tag_b)?;
                ensure!(a == b && tag_a == tag_b, SelfTestFailed, $id);

                // Round trip.
                cipher.open_detached(&nonce, b"aad", &mut a, &tag_a)?;
                ensure!(&a == b"self-test message", SelfTestFailed, $id);

                // A tampered tag is rejected and the buffer is cleared.
                let mut bad = tag_a;
                bad[0] ^= 1;
                ensure!(
                    cipher.open_detached(&nonce, b"aad", &mut b, &bad).is_err(),
                    SelfTestFailed,
                    $id
                );
                // Changing the AAD must also fail.
                let mut c = *b"self-test message";
                let mut tag_c = [0u8; TAG_LEN];
                cipher.seal_detached(&nonce, b"aad", &mut c, &mut tag_c)?;
                ensure!(
                    cipher
                        .open_detached(&nonce, b"other", &mut c, &tag_c)
                        .is_err(),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

gcm_siv!(
    Aes128GcmSiv,
    crate::Aes128,
    16,
    "aes-128-gcm-siv",
    "AES-128-GCM-SIV",
    // RFC 8452 appendix C.1: an 8-byte plaintext with one byte of associated
    // data. Result = 1e6daba35669f427 3b0a1a2560969cdf790d99759abd1508,
    // split here into the ciphertext and the tag the API returns separately.
    b"1e6daba35669f427",
    b"3b0a1a2560969cdf790d99759abd1508"
);
gcm_siv!(
    Aes256GcmSiv,
    crate::Aes256,
    32,
    "aes-256-gcm-siv",
    "AES-256-GCM-SIV",
    // RFC 8452 appendix C.2, the same inputs at the larger key length.
    // Result = 1de22967237a8132 91213f267e3b452f02d01ae33e4ec854.
    b"1de22967237a8132",
    b"91213f267e3b452f02d01ae33e4ec854"
);

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(cipher: &Aes256GcmSiv, nonce: &[u8], aad: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut buf = pt.to_vec();
        let mut tag = [0u8; TAG_LEN];
        cipher
            .seal_detached(nonce, aad, &mut buf, &mut tag)
            .unwrap();
        (buf, tag)
    }

    #[test]
    fn round_trips_at_every_length_boundary() {
        let cipher = Aes256GcmSiv::new(&[0x11u8; 32]).unwrap();
        let nonce = [0x22u8; NONCE_LEN];

        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 255, 256] {
            let pt = vec![0x5au8; len];
            let (mut ct, tag) = seal(&cipher, &nonce, b"aad", &pt);
            assert_eq!(ct.len(), len, "length is preserved");
            if len > 0 {
                assert_ne!(ct, pt, "and the plaintext is not passed through");
            }
            cipher.open_detached(&nonce, b"aad", &mut ct, &tag).unwrap();
            assert_eq!(ct, pt, "round trip at {len} bytes");
        }
    }

    /// The defining property. Under a repeated nonce, GCM-SIV must *not* behave
    /// like CTR mode: for CTR, `C1 ^ C2 == P1 ^ P2` exactly, which is what makes
    /// GCM's nonce reuse fatal. Here the keystream depends on the plaintext
    /// through the tag, so that relation must fail.
    #[test]
    fn nonce_reuse_does_not_leak_the_plaintext_xor() {
        let cipher = Aes256GcmSiv::new(&[0x33u8; 32]).unwrap();
        let nonce = [0x44u8; NONCE_LEN];

        let p1 = vec![0xaau8; 64];
        let mut p2 = vec![0xaau8; 64];
        p2[0] ^= 0x01; // differ in a single bit

        let (c1, _) = seal(&cipher, &nonce, b"", &p1);
        let (c2, _) = seal(&cipher, &nonce, b"", &p2);

        let cipher_xor: Vec<u8> = c1.iter().zip(c2.iter()).map(|(a, b)| a ^ b).collect();
        let plain_xor: Vec<u8> = p1.iter().zip(p2.iter()).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            cipher_xor, plain_xor,
            "a one-bit plaintext change must change the whole keystream"
        );

        // And almost every byte should differ, not just the one that changed.
        let differing = cipher_xor.iter().filter(|b| **b != 0).count();
        assert!(
            differing > 48,
            "only {differing} of 64 ciphertext bytes changed; the keystream is \
             not depending on the plaintext"
        );
    }

    /// Encryption is deterministic, which is the trade GCM-SIV makes: equal
    /// plaintexts under one nonce are visibly equal, and nothing worse.
    #[test]
    fn encryption_is_deterministic() {
        let cipher = Aes256GcmSiv::new(&[0x55u8; 32]).unwrap();
        let nonce = [0x66u8; NONCE_LEN];
        let (a, ta) = seal(&cipher, &nonce, b"aad", b"same message");
        let (b, tb) = seal(&cipher, &nonce, b"aad", b"same message");
        assert_eq!((a, ta), (b, tb));
    }

    #[test]
    fn every_input_is_authenticated() {
        let cipher = Aes256GcmSiv::new(&[0x77u8; 32]).unwrap();
        let nonce = [0x88u8; NONCE_LEN];
        let (ct, tag) = seal(&cipher, &nonce, b"aad", b"message");

        // Wrong nonce.
        let mut buf = ct.clone();
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert!(cipher
            .open_detached(&other_nonce, b"aad", &mut buf, &tag)
            .is_err());

        // Wrong AAD.
        let mut buf = ct.clone();
        assert!(cipher
            .open_detached(&nonce, b"aae", &mut buf, &tag)
            .is_err());

        // Tampered ciphertext.
        let mut buf = ct.clone();
        buf[0] ^= 1;
        assert!(cipher
            .open_detached(&nonce, b"aad", &mut buf, &tag)
            .is_err());

        // Tampered tag.
        let mut buf = ct.clone();
        let mut bad = tag;
        bad[15] ^= 1;
        assert!(cipher
            .open_detached(&nonce, b"aad", &mut buf, &bad)
            .is_err());
    }

    /// A failed open must not leave plaintext in the caller's buffer.
    #[test]
    fn a_failed_open_clears_the_buffer() {
        let cipher = Aes256GcmSiv::new(&[0x99u8; 32]).unwrap();
        let nonce = [0xaau8; NONCE_LEN];
        let (ct, tag) = seal(&cipher, &nonce, b"", b"secret plaintext");

        let mut buf = ct;
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(cipher.open_detached(&nonce, b"", &mut buf, &bad).is_err());
        assert!(
            buf.iter().all(|b| *b == 0),
            "the buffer still held data after a failed open"
        );
    }

    /// AAD and message must not be interchangeable: moving a byte across the
    /// boundary has to change the tag. That is what the length block is for.
    #[test]
    fn the_aad_boundary_is_authenticated() {
        let cipher = Aes256GcmSiv::new(&[0xbbu8; 32]).unwrap();
        let nonce = [0xccu8; NONCE_LEN];
        let (_, tag_a) = seal(&cipher, &nonce, b"abc", b"def");
        let (_, tag_b) = seal(&cipher, &nonce, b"ab", b"cdef");
        assert_ne!(tag_a, tag_b, "the aad/message split must be bound in");
    }

    #[test]
    fn key_sizes_and_lengths_are_checked() {
        assert!(Aes128GcmSiv::new(&[0u8; 16]).is_ok());
        assert!(Aes128GcmSiv::new(&[0u8; 32]).is_err());
        assert!(Aes256GcmSiv::new(&[0u8; 16]).is_err());

        let cipher = Aes128GcmSiv::new(&[0u8; 16]).unwrap();
        let mut buf = [0u8; 8];
        let mut tag = [0u8; TAG_LEN];
        assert!(cipher
            .seal_detached(&[0u8; 11], b"", &mut buf, &mut tag)
            .is_err());
        assert!(cipher
            .seal_detached(&[0u8; 12], b"", &mut buf, &mut [0u8; 15])
            .is_err());
    }

    #[test]
    fn both_self_tests_pass() {
        Aes128GcmSiv::self_test().unwrap();
        Aes256GcmSiv::self_test().unwrap();
    }

    /// The two key sizes must not agree — a build where AES-256-GCM-SIV
    /// silently used only 16 bytes of key would pass everything above.
    #[test]
    fn the_two_key_sizes_are_distinct() {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&[0x5au8; 16]);
        let small = Aes128GcmSiv::new(&key[..16]).unwrap();
        let large = Aes256GcmSiv::new(&key).unwrap();

        let nonce = [0u8; NONCE_LEN];
        let mut a = *b"message";
        let mut b = *b"message";
        let mut ta = [0u8; TAG_LEN];
        let mut tb = [0u8; TAG_LEN];
        small.seal_detached(&nonce, b"", &mut a, &mut ta).unwrap();
        large.seal_detached(&nonce, b"", &mut b, &mut tb).unwrap();
        assert_ne!((a, ta), (b, tb));
    }
}
