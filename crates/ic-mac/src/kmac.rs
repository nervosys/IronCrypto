//! SP 800-185 KMAC: a MAC built on cSHAKE.
//!
//! KMAC is the SHA-3 family's answer to HMAC, and a simpler one. HMAC exists
//! because the Merkle-Damgard hashes it wraps are vulnerable to length
//! extension, so it needs two passes with an inner and an outer key. A sponge
//! has no such weakness, so KMAC just absorbs the key first:
//!
//! ```text
//! KMAC128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168)
//!                                 || X || right_encode(L),
//!                                 L, "KMAC", S)
//! ```
//!
//! # The output length is authenticated
//!
//! `right_encode(L)` at the end is the part worth understanding. It binds the
//! requested output length into the input, so a 32-byte tag is not a prefix of
//! a 64-byte tag over the same key and message. Without it, anyone who saw a
//! long tag could truncate it into a valid short one.
//!
//! That is also why [`Kmac128::finalize`] and [`Kmac128::finalize_xof`] differ
//! for the same length: the XOF variant encodes zero, which is precisely what
//! makes its output a stream that can be extended without changing its prefix.
//!
//! # Customization separates domains
//!
//! Two subsystems sharing a key should pass different `custom` strings. Then a
//! tag from one cannot be replayed into the other, and neither has to trust the
//! other's message framing.

use ic_core::traits::{Algorithm, SelfTest};
use ic_core::{ensure, Result};
use ic_hash::sp800_185::{right_encode, MAX_ENCODE};

/// The widest tag the fixed-length helpers handle.
const MAX_TAG: usize = 64;

/// Declare a KMAC over one cSHAKE parameter set.
macro_rules! kmac {
    ($name:ident, $cshake:ty, $id:literal, $disp:literal, $bits:literal) => {
        #[doc = concat!("SP 800-185 ", $disp, ", offering ", $bits, "-bit security.")]
        #[derive(Clone)]
        pub struct $name {
            inner: $cshake,
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl $name {
            /// Start a KMAC with `key` and a customization string.
            ///
            /// Pass an empty `custom` when the key has only one use.
            pub fn new(key: &[u8], custom: &[u8]) -> Self {
                let mut inner = <$cshake>::new(b"KMAC", custom);
                inner.absorb_bytepadded_string(key);
                Self { inner }
            }

            /// Absorb more of the message.
            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            /// Produce a tag of exactly `out.len()` bytes.
            ///
            /// The length is bound into the computation, so tags of different
            /// lengths over the same input are unrelated.
            pub fn finalize(mut self, out: &mut [u8]) {
                let mut buf = [0u8; MAX_ENCODE];
                let used = right_encode((out.len() as u64) * 8, &mut buf);
                self.inner.update(&buf[..used]);
                self.inner.finalize_xof(out);
            }

            /// Produce an arbitrary-length stream instead of a fixed tag.
            ///
            /// Encodes a length of zero, per SP 800-185 section 4.3.1.
            pub fn finalize_xof(mut self, out: &mut [u8]) {
                let mut buf = [0u8; MAX_ENCODE];
                let used = right_encode(0, &mut buf);
                self.inner.update(&buf[..used]);
                self.inner.finalize_xof(out);
            }

            /// One-shot fixed-length tag.
            pub fn mac(key: &[u8], custom: &[u8], data: &[u8], out: &mut [u8]) {
                let mut k = Self::new(key, custom);
                k.update(data);
                k.finalize(out);
            }

            /// One-shot XOF mode.
            pub fn mac_xof(key: &[u8], custom: &[u8], data: &[u8], out: &mut [u8]) {
                let mut k = Self::new(key, custom);
                k.update(data);
                k.finalize_xof(out);
            }

            /// Verify a tag in constant time.
            ///
            /// Compare with this rather than `==`. An early-exit comparison
            /// leaks how many leading bytes matched, which is enough to recover
            /// a valid tag one byte at a time.
            pub fn verify(key: &[u8], custom: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
                ensure!(
                    !tag.is_empty() && tag.len() <= MAX_TAG,
                    InvalidLength,
                    "kmac tag length"
                );
                let mut expected = [0u8; MAX_TAG];
                Self::mac(key, custom, data, &mut expected[..tag.len()]);
                ensure!(
                    ic_core::ct::verify(&expected[..tag.len()], tag),
                    AuthenticationFailed,
                    $id
                );
                Ok(())
            }
        }

        impl SelfTest for $name {
            /// # Provenance
            ///
            /// No pinned vector. The unit tests check KMAC against an
            /// independent construction from SP 800-185's own definition —
            /// stronger evidence than a value this code produced — and cSHAKE
            /// beneath it is checked against a Keccak written from FIPS 202.
            /// docs/FIPS.md records that. What this adds at startup is that the
            /// code still computes what it computed when those tests last ran,
            /// and that its structural properties hold.
            fn self_test() -> Result<()> {
                let key = [0x40u8; 32];
                let mut short = [0u8; 32];
                let mut long = [0u8; 64];
                Self::mac(&key, b"self-test", b"message", &mut short);
                Self::mac(&key, b"self-test", b"message", &mut long);

                // The output length is bound in, so the short tag is not a
                // prefix of the long one. Drop right_encode(L) and it would be.
                ensure!(short[..] != long[..32], SelfTestFailed, $id);

                let mut again = [0u8; 32];
                Self::mac(&key, b"self-test", b"message", &mut again);
                ensure!(ic_core::ct::verify(&short, &again), SelfTestFailed, $id);
                Self::verify(&key, b"self-test", b"message", &short)?;

                let mut tampered = short;
                tampered[0] ^= 1;
                ensure!(
                    Self::verify(&key, b"self-test", b"message", &tampered).is_err(),
                    SelfTestFailed,
                    $id
                );
                // Customization must separate domains.
                ensure!(
                    Self::verify(&key, b"other", b"message", &short).is_err(),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

kmac!(Kmac128, ic_hash::CShake128, "kmac128", "KMAC128", "128");
kmac!(Kmac256, ic_hash::CShake256, "kmac256", "KMAC256", "256");

#[cfg(test)]
mod tests {
    use super::*;
    use ic_hash::sp800_185::{left_encode, CShake128, CShake256};

    /// SP 800-185's definition, assembled literally, with no shared code.
    ///
    /// `KMAC(K, X, L, S) = cSHAKE(bytepad(encode_string(K), rate)
    ///                            || X || right_encode(L), L, "KMAC", S)`
    ///
    /// cSHAKE is trusted here because its own tests check it against a Keccak
    /// written from FIPS 202 and anchored to a published SHA-3 vector. So this
    /// checks the layer KMAC actually adds: the key encoding, the padding
    /// width, and the trailing length.
    fn reference_kmac(
        rate: usize,
        key: &[u8],
        custom: &[u8],
        data: &[u8],
        out: &mut [u8],
        xof: bool,
    ) {
        fn enc(x: u64) -> Vec<u8> {
            let mut bytes = x.to_be_bytes().to_vec();
            while bytes.len() > 1 && bytes[0] == 0 {
                bytes.remove(0);
            }
            let mut v = vec![bytes.len() as u8];
            v.extend_from_slice(&bytes);
            v
        }
        fn renc(x: u64) -> Vec<u8> {
            let mut bytes = x.to_be_bytes().to_vec();
            while bytes.len() > 1 && bytes[0] == 0 {
                bytes.remove(0);
            }
            let n = bytes.len() as u8;
            bytes.push(n);
            bytes
        }

        // bytepad(encode_string(K), rate)
        let mut message = enc(rate as u64);
        message.extend_from_slice(&enc((key.len() as u64) * 8));
        message.extend_from_slice(key);
        while message.len() % rate != 0 {
            message.push(0);
        }
        message.extend_from_slice(data);
        message.extend_from_slice(&renc(if xof { 0 } else { (out.len() as u64) * 8 }));

        if rate == 168 {
            CShake128::xof(b"KMAC", custom, &message, out);
        } else {
            CShake256::xof(b"KMAC", custom, &message, out);
        }
    }

    #[test]
    fn kmac_matches_an_independent_construction() {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (&[0x40u8; 32], b"", b""),
            (&[0x40u8; 32], b"My Tagged Application", b"\x00\x01\x02\x03"),
            (b"short key", b"S", &[0xa5u8; 500]),
            (&[0x11u8; 200], b"", b"key longer than the rate"),
        ];

        for (key, custom, data) in cases {
            for len in [16usize, 32, 64] {
                let mut want = vec![0u8; len];
                let mut got = vec![0u8; len];

                reference_kmac(168, key, custom, data, &mut want, false);
                Kmac128::mac(key, custom, data, &mut got);
                assert_eq!(got, want, "KMAC128 fixed, {len} bytes");

                reference_kmac(136, key, custom, data, &mut want, false);
                Kmac256::mac(key, custom, data, &mut got);
                assert_eq!(got, want, "KMAC256 fixed, {len} bytes");

                reference_kmac(168, key, custom, data, &mut want, true);
                Kmac128::mac_xof(key, custom, data, &mut got);
                assert_eq!(got, want, "KMAC128 xof, {len} bytes");

                reference_kmac(136, key, custom, data, &mut want, true);
                Kmac256::mac_xof(key, custom, data, &mut got);
                assert_eq!(got, want, "KMAC256 xof, {len} bytes");
            }
        }
    }

    /// The property `right_encode(L)` exists to provide: a short tag is not a
    /// truncation of a long one.
    #[test]
    fn tag_length_is_bound_into_the_tag() {
        let key = [0x7fu8; 32];
        let mut short = [0u8; 32];
        let mut long = [0u8; 64];
        Kmac128::mac(&key, b"", b"message", &mut short);
        Kmac128::mac(&key, b"", b"message", &mut long);
        assert_ne!(short[..], long[..32], "truncation must not forge");
    }

    /// The XOF variant, by contrast, *is* a stream: a longer output extends a
    /// shorter one.
    #[test]
    fn the_xof_variant_extends_rather_than_changes() {
        let key = [0x7fu8; 32];
        let mut short = [0u8; 32];
        let mut long = [0u8; 64];
        Kmac128::mac_xof(&key, b"", b"message", &mut short);
        Kmac128::mac_xof(&key, b"", b"message", &mut long);
        assert_eq!(short[..], long[..32], "the xof output is a prefix");
    }

    #[test]
    fn streaming_matches_the_one_shot() {
        let key = [0x31u8; 32];
        let data = [0x62u8; 777];
        let mut one = [0u8; 32];
        Kmac256::mac(&key, b"S", &data, &mut one);

        let mut k = Kmac256::new(&key, b"S");
        for chunk in data.chunks(13) {
            k.update(chunk);
        }
        let mut streamed = [0u8; 32];
        k.finalize(&mut streamed);
        assert_eq!(one, streamed);
    }

    #[test]
    fn keys_and_customization_both_change_the_tag() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Kmac128::mac(&[1u8; 32], b"S", b"m", &mut a);
        Kmac128::mac(&[2u8; 32], b"S", b"m", &mut b);
        assert_ne!(a, b, "the key matters");
        Kmac128::mac(&[1u8; 32], b"T", b"m", &mut b);
        assert_ne!(a, b, "the customization matters");
    }

    #[test]
    fn verification_rejects_tampering_and_bad_lengths() {
        let key = [0x55u8; 32];
        let mut tag = [0u8; 32];
        Kmac128::mac(&key, b"S", b"message", &mut tag);
        Kmac128::verify(&key, b"S", b"message", &tag).unwrap();

        for bit in [0usize, 7, 128, 255] {
            let mut bad = tag;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(Kmac128::verify(&key, b"S", b"message", &bad).is_err());
        }
        assert!(Kmac128::verify(&key, b"S", b"messagf", &tag).is_err());
        assert!(Kmac128::verify(&[0u8; 32], b"S", b"message", &tag).is_err());
        assert!(
            Kmac128::verify(&key, b"S", b"message", &[]).is_err(),
            "empty tag"
        );
        assert!(
            Kmac128::verify(&key, b"S", b"message", &[0u8; 65]).is_err(),
            "over-long tag"
        );
    }

    #[test]
    fn both_self_tests_pass() {
        Kmac128::self_test().unwrap();
        Kmac256::self_test().unwrap();
    }

    /// `left_encode` is re-exported through `ic_hash`; make sure the path the
    /// docs point at actually resolves.
    #[test]
    fn the_encoding_helpers_are_reachable() {
        let mut buf = [0u8; MAX_ENCODE];
        assert_eq!(left_encode(168, &mut buf), 2);
        assert_eq!(&buf[..2], &[0x01, 0xa8]);
    }
}
