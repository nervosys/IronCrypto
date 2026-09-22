//! QUIC packet and header protection, RFC 9001.
//!
//! QUIC protects a packet twice. The payload is sealed with the same AEAD the
//! TLS record layer uses, keyed and nonced differently; then a few bytes of the
//! *header* -- the reserved and packet-number-length bits, and the packet
//! number itself -- are masked with a keystream derived from a sample of the
//! ciphertext that was just produced. The second step is what stops a passive
//! observer following a connection across a path change.
//!
//! # The two header protection constructions
//!
//! They share nothing but their output length.
//!
//! - **AES** (RFC 9001 section 5.4.3) encrypts the 16-byte sample as a single
//!   ECB block and takes the first five bytes. This is the one place in the
//!   workspace a bare block cipher call is the specification rather than a
//!   mistake: there is no chaining, no IV and no authentication because the
//!   input is a single block used once as a PRF.
//! - **ChaCha20** (RFC 9001 section 5.4.4) reads the sample as a 32-bit
//!   little-endian counter followed by a 12-byte nonce, and runs the raw block
//!   function over five zero bytes.
//!
//! Both then apply the mask the same way: the low bits of the first byte, and
//! the packet number. How many bits of the first byte depends on the header
//! form, and the bit that says which form it is lies outside the mask -- which
//! is why protecting and unprotecting are the same operation, and why this
//! module has one function for both directions rather than two that must agree.
//!
//! # What is not here
//!
//! Multipath QUIC. `PacketKey` has `encrypt_in_place_for_path` and its
//! decrypting twin, which rustls defaults to an error, and that default is kept
//! rather than implemented against a draft.

use alloc::boxed::Box;

use ic_core::traits::BlockCipher as _;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};
use rustls::Error;

use crate::aead::{Cipher, Suite};

/// The tag on every QUIC packet, for all three AEADs.
const TAG_LEN: usize = 16;

/// RFC 9001 section 5.4.2: header protection always samples sixteen bytes.
const SAMPLE_LEN: usize = 16;

/// The mask covers the first byte and up to four packet number bytes.
const MASK_LEN: usize = 5;

/// AES-128-GCM.
///
/// Limits from RFC 9001: section B.1.1 for confidentiality, B.1.2 for
/// integrity. They are the AEAD's, not the suite's, so both AES suites share
/// them.
pub(crate) static AES_128_GCM: IcQuic = IcQuic {
    suite: Suite::Aes128,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// AES-256-GCM.
pub(crate) static AES_256_GCM: IcQuic = IcQuic {
    suite: Suite::Aes256,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// ChaCha20-Poly1305.
///
/// RFC 9001 section 6.6: the confidentiality limit exceeds the number of
/// packets a connection can carry, so there is nothing to enforce and rustls
/// spells that `u64::MAX`. The integrity limit is real.
pub(crate) static CHACHA20_POLY1305: IcQuic = IcQuic {
    suite: Suite::ChaCha20,
    confidentiality_limit: u64::MAX,
    integrity_limit: 1 << 36,
};

/// One AEAD, as QUIC uses it.
#[derive(Debug)]
pub(crate) struct IcQuic {
    suite: Suite,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl Algorithm for IcQuic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(IcPacketKey {
            // As in `crate::aead`: the trait gives nowhere to report a failure,
            // and rustls sizes the key from the suite this algorithm belongs
            // to. `the_key_lengths_match_the_suites` pins that.
            cipher: self
                .suite
                .cipher(key.as_ref())
                .expect("rustls supplied a key this suite does not use"),
            iv,
            confidentiality_limit: self.confidentiality_limit,
            integrity_limit: self.integrity_limit,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(IcHeaderKey::new(self.suite, key.as_ref()))
    }

    fn aead_key_len(&self) -> usize {
        self.suite.key_len()
    }

    /// Always false; see the note on the hash adapter.
    fn fips(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Packet protection
// ---------------------------------------------------------------------------

struct IcPacketKey {
    cipher: Cipher,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl PacketKey for IcPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        // RFC 9001 section 5.3: the nonce is the IV xored with the packet
        // number, left-padded -- the same construction TLS 1.3 uses with the
        // sequence number, so it is rustls's `Nonce` rather than one built here.
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let mut tag = [0u8; TAG_LEN];
        self.cipher
            .seal(&nonce, header, payload, &mut tag)
            .map_err(|_| Error::EncryptError)?;
        Ok(Tag::from(&tag[..]))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, packet_number).0;

        let plain_len = payload.len() - TAG_LEN;
        let (body, tag) = payload.split_at_mut(plain_len);
        let tag: [u8; TAG_LEN] = tag.try_into().expect("split at exactly the tag length");

        self.cipher
            .open(&nonce, header, body, &tag)
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..plain_len])
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

// ---------------------------------------------------------------------------
// Header protection
// ---------------------------------------------------------------------------

/// The header protection key, which is a keyed mask generator and not an AEAD.
enum IcHeaderKey {
    /// AES-ECB over the sample, one block. RFC 9001 section 5.4.3.
    Aes128(ic_cipher::Aes128),
    /// As above with a 256-bit key.
    Aes256(ic_cipher::Aes256),
    /// The raw ChaCha20 block function. RFC 9001 section 5.4.4.
    ChaCha20([u8; 32]),
}

impl IcHeaderKey {
    fn new(suite: Suite, key: &[u8]) -> Self {
        // The lengths come from the suite, as with the packet key.
        match suite {
            Suite::Aes128 => Self::Aes128(
                ic_cipher::Aes128::new(key).expect("rustls supplied a key this suite does not use"),
            ),
            Suite::Aes256 => Self::Aes256(
                ic_cipher::Aes256::new(key).expect("rustls supplied a key this suite does not use"),
            ),
            Suite::ChaCha20 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Self::ChaCha20(k)
            }
        }
    }

    /// The five mask bytes for one sample.
    fn mask(&self, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::General(alloc::format!(
                "a header protection sample is {SAMPLE_LEN} bytes, not {}",
                sample.len()
            )));
        }
        let mut mask = [0u8; MASK_LEN];

        match self {
            Self::Aes128(_) | Self::Aes256(_) => {
                // One ECB block. Unauthenticated and unchained on purpose: the
                // sample is a single block used once, as a pseudorandom
                // function, which is what section 5.4.3 specifies.
                let mut block = [0u8; 16];
                block.copy_from_slice(sample);
                match self {
                    Self::Aes128(c) => c.encrypt_block(&mut block),
                    Self::Aes256(c) => c.encrypt_block(&mut block),
                    Self::ChaCha20(_) => unreachable!("matched on AES above"),
                }
                .map_err(|_| Error::General("header protection block failed".into()))?;
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            Self::ChaCha20(key) => {
                // Section 5.4.4: the first four bytes are the block counter,
                // little-endian, and the remaining twelve are the nonce. The
                // keystream is then taken over five zero bytes.
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                ic_cipher::chacha20_xor(key, &sample[4..], counter, &mut mask)
                    .map_err(|_| Error::General("header protection keystream failed".into()))?;
            }
        }
        Ok(mask)
    }

    /// Apply the mask, which is the same operation in both directions.
    ///
    /// RFC 9001 section 5.4.1. The number of protected bits in the first byte
    /// depends on the header form, and the form bit -- the top bit -- is not
    /// itself protected. So a receiver reads the form from the byte it has,
    /// masked or not, and gets the same answer as the sender did. That is why
    /// this is one function: two would be two chances to disagree.
    fn apply(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<(), Error> {
        if packet_number.len() > 4 {
            return Err(Error::General(alloc::format!(
                "a QUIC packet number is at most 4 bytes, not {}",
                packet_number.len()
            )));
        }
        // Computed before anything is written, so a bad sample leaves the
        // header untouched -- which the trait requires.
        let mask = self.mask(sample)?;

        // Long headers protect four bits, short headers five. RFC 9001 5.4.1.
        let long = *first & 0x80 == 0x80;
        *first ^= mask[0] & if long { 0x0f } else { 0x1f };

        for (byte, m) in packet_number.iter_mut().zip(&mask[1..]) {
            *byte ^= m;
        }
        Ok(())
    }
}

impl HeaderProtectionKey for IcHeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.apply(sample, first, packet_number)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.apply(sample, first, packet_number)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 appendix A.2: the client Initial packet's header protection.
    ///
    /// A published vector, and the reason this module can claim to interoperate
    /// rather than merely to round-trip against itself. The sample and the key
    /// are the specification's; so is the resulting first byte and packet
    /// number.
    #[test]
    fn the_client_initial_header_matches_rfc9001() {
        // A.2: "hp" for the client Initial keys.
        let key = hex("9f50449e04a0e810283a1e9933adedd2");
        let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");

        let hp = IcHeaderKey::new(Suite::Aes128, &key);
        // The unprotected first byte and packet number from A.2.
        let mut first = 0xc3u8;
        let mut pn = hex("00000002");

        hp.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(first, 0xc0, "protected first byte");
        assert_eq!(pn, hex("7b9aec34"), "protected packet number");

        // And back again, since the two directions are one operation.
        hp.decrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(first, 0xc3);
        assert_eq!(pn, hex("00000002"));
    }

    /// RFC 9001 appendix A.3: the server Initial packet.
    ///
    /// A second AES vector with a short packet number, so the mask is not
    /// consumed to its full width and the zip in `apply` is exercised at a
    /// length other than four.
    #[test]
    fn the_server_initial_header_matches_rfc9001() {
        let key = hex("c206b8d9b9f0f37644430b490eeaa314");
        let sample = hex("2cd0991cd25b0aac406a5816b6394100");

        let hp = IcHeaderKey::new(Suite::Aes128, &key);
        let mut first = 0xc1u8;
        let mut pn = hex("0001");

        hp.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(first, 0xcf);
        assert_eq!(pn, hex("c0d9"));
    }

    /// RFC 9001 appendix A.5: the ChaCha20-Poly1305 short header packet.
    ///
    /// The other construction entirely -- a counter and nonce read out of the
    /// sample rather than a block encryption -- and a short header, so the
    /// five-bit mask applies rather than the four-bit one. Nothing in the AES
    /// vectors above would catch either being wrong.
    #[test]
    fn the_chacha20_short_header_matches_rfc9001() {
        let key = hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let sample = hex("5e5cd55c41f69080575d7999c25a5bfb");

        let hp = IcHeaderKey::new(Suite::ChaCha20, &key);
        let mut first = 0x42u8;
        let mut pn = hex("00bff4");

        hp.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        // A.5 gives the protected header as 4cfe4189: first byte 0x4c and the
        // three packet number bytes fe4189.
        assert_eq!(first, 0x4c, "protected first byte");
        assert_eq!(pn, hex("fe4189"), "protected packet number");

        hp.decrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(first, 0x42);
        assert_eq!(pn, hex("00bff4"));
    }

    /// The long and short header forms must mask different numbers of bits.
    ///
    /// RFC 9001 section 5.4.1: a long header protects the four low bits of the
    /// first byte, a short header five. No vector above catches the difference,
    /// and that is a property of the published vectors rather than a poor
    /// choice among them -- in A.2, A.3 and A.5 alike, bit 0x10 of the mask's
    /// first byte happens to be zero (0x43, 0x2e, 0xae), so `& 0x0f` and
    /// `& 0x1f` give the same answer. Swapping the two widths leaves every RFC
    /// vector in this file passing; that was confirmed by doing it, which is
    /// why this test exists.
    ///
    /// So the rule is checked directly, against a sample chosen so the bit in
    /// question is set. `mask` supplies what the mask is -- pinned independently
    /// by the vectors above -- and what is under test here is how `apply` uses
    /// it, which is separate code.
    #[test]
    fn the_header_form_decides_how_many_bits_are_masked() {
        let hp = IcHeaderKey::new(Suite::Aes128, &[0x11u8; 16]);

        // Roughly half of all samples set the bit; 256 tries is ample.
        let sample = (0u8..=255)
            .map(|i| alloc::vec![i; SAMPLE_LEN])
            .find(|s| hp.mask(s).unwrap()[0] & 0x10 != 0)
            .expect("no sample set the fifth mask bit");
        let mask0 = hp.mask(&sample).unwrap()[0];

        // Long header: top bit set. Bit 0x10 must survive untouched.
        let mut first = 0xc3u8;
        let mut pn = alloc::vec![0u8; 1];
        hp.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_eq!(
            first & 0x10,
            0xc3 & 0x10,
            "a long header masked the fifth bit, which belongs to the packet type"
        );
        assert_eq!(first ^ 0xc3, mask0 & 0x0f);

        // Short header: top bit clear. Bit 0x10 must flip.
        let mut first = 0x42u8;
        let mut pn = alloc::vec![0u8; 1];
        hp.encrypt_in_place(&sample, &mut first, &mut pn).unwrap();
        assert_ne!(
            first & 0x10,
            0x42 & 0x10,
            "a short header left the fifth bit alone, so it protects too little"
        );
        assert_eq!(first ^ 0x42, mask0 & 0x1f);
    }

    /// A sample of the wrong length is refused, and leaves the header alone.
    ///
    /// The trait requires that: a caller that ignores the error must not find a
    /// half-masked header.
    #[test]
    fn a_bad_sample_is_refused_without_touching_the_header() {
        let hp = IcHeaderKey::new(Suite::Aes128, &[0x11u8; 16]);

        for bad in [alloc::vec![], alloc::vec![0u8; 15], alloc::vec![0u8; 17]] {
            let mut first = 0xc3u8;
            let mut pn = alloc::vec![1u8, 2, 3, 4];
            assert!(hp.encrypt_in_place(&bad, &mut first, &mut pn).is_err());
            assert_eq!(first, 0xc3, "the first byte was modified anyway");
            assert_eq!(pn, [1, 2, 3, 4], "the packet number was modified anyway");
        }

        // And an over-long packet number, for the same reason.
        let mut first = 0xc3u8;
        let mut pn = alloc::vec![1u8, 2, 3, 4, 5];
        assert!(hp
            .encrypt_in_place(&[0u8; SAMPLE_LEN], &mut first, &mut pn)
            .is_err());
        assert_eq!(first, 0xc3);
    }

    /// A packet survives the round trip, and is bound to its number and header.
    ///
    /// AES-128 is absent for the same reason it is absent from the record layer
    /// tests: `AeadKey` converts only from a 32-byte array, so no test outside
    /// rustls can build the 16-byte key it takes. Its header protection *is*
    /// covered, by the RFC 9001 vectors above, which reach `IcHeaderKey`
    /// directly rather than through `AeadKey`.
    #[test]
    fn a_packet_round_trips_and_is_bound_to_its_context() {
        let mut checked = 0;
        for alg in [&AES_256_GCM, &CHACHA20_POLY1305] {
            assert_eq!(alg.aead_key_len(), 32, "only the 32-byte suites fit here");
            let pk = alg.packet_key(AeadKey::from([0x3au8; 32]), Iv::copy(&[0x5cu8; 12]));

            let header = b"@";
            let mut buf = alloc::vec![0u8; 32 + TAG_LEN];
            buf[..32].copy_from_slice(&[0x7eu8; 32]);

            let tag = pk.encrypt_in_place(7, header, &mut buf[..32]).unwrap();
            buf[32..].copy_from_slice(tag.as_ref());
            assert_ne!(&buf[..32], &[0x7eu8; 32][..], "the payload was not sealed");

            // The wrong packet number must fail: the nonce differs.
            let mut wrong = buf.clone();
            assert!(pk.decrypt_in_place(8, header, &mut wrong).is_err());

            // So must the wrong header, which is the additional data.
            let mut wrong = buf.clone();
            assert!(pk.decrypt_in_place(7, b"@", &mut wrong).is_err());

            // And a packet shorter than its own tag, rather than a panic.
            let mut short = alloc::vec![0u8; TAG_LEN - 1];
            assert!(pk.decrypt_in_place(7, header, &mut short).is_err());

            let opened = pk.decrypt_in_place(7, header, &mut buf).unwrap();
            assert_eq!(opened, &[0x7eu8; 32][..]);
            checked += 1;
        }
        assert_eq!(checked, 2);
    }

    /// Each algorithm's key length must be the one its ciphers accept.
    ///
    /// `packet_key` and `header_protection_key` both panic on a mismatch,
    /// because the traits return the key directly. That is only safe if rustls
    /// cannot hand over the wrong length, and `aead_key_len` is what tells it.
    #[test]
    fn the_key_lengths_match_the_suites() {
        assert_eq!(AES_128_GCM.aead_key_len(), 16);
        assert_eq!(AES_256_GCM.aead_key_len(), 32);
        assert_eq!(CHACHA20_POLY1305.aead_key_len(), 32);

        // The header protection key is built from a raw slice, so every suite
        // including AES-128 can be constructed here. None of these may panic.
        for suite in [Suite::Aes128, Suite::Aes256, Suite::ChaCha20] {
            let _ = IcHeaderKey::new(suite, &alloc::vec![0u8; suite.key_len()]);
        }

        for alg in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
            assert!(!alg.fips());
        }
    }

    /// The published limits, as the specification states them.
    ///
    /// AES-256 stands in for both AES suites: the limits are the AEAD's, and
    /// the two share them by construction above.
    #[test]
    fn the_aead_limits_are_the_published_ones() {
        let pk = AES_256_GCM.packet_key(AeadKey::from([0u8; 32]), Iv::copy(&[0u8; 12]));
        assert_eq!(pk.confidentiality_limit(), 1 << 23, "RFC 9001 B.1.1");
        assert_eq!(pk.integrity_limit(), 1 << 52, "RFC 9001 B.1.2");
        assert_eq!(pk.tag_len(), 16);
        assert_eq!(AES_128_GCM.confidentiality_limit, 1 << 23);
        assert_eq!(AES_128_GCM.integrity_limit, 1 << 52);

        let pk = CHACHA20_POLY1305.packet_key(AeadKey::from([0u8; 32]), Iv::copy(&[0u8; 12]));
        assert_eq!(pk.confidentiality_limit(), u64::MAX, "RFC 9001 6.6");
        assert_eq!(pk.integrity_limit(), 1 << 36, "RFC 9001 6.6");

        // The two AEADs must not have been given the same limits by accident.
        assert_ne!(
            AES_256_GCM.integrity_limit,
            CHACHA20_POLY1305.integrity_limit
        );
    }
}
