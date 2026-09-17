//! HMAC for rustls, which is also where HKDF comes from.
//!
//! rustls builds its TLS 1.3 key schedule with `HkdfUsingHmac`, a generic
//! HKDF over any `Hmac` implementation. So supplying HMAC here supplies HKDF
//! too, and the derivation is RFC 5869 extract-and-expand as rustls implements
//! it, over IronCrypto's HMAC. That is the right split: HKDF is a construction,
//! HMAC is the primitive, and only the primitive is ours to provide.
//!
//! HMAC-SHA256 and HMAC-SHA384 are what the TLS 1.3 suites name.

use alloc::boxed::Box;

use ic_core::traits::Mac;
use rustls::crypto::hmac;

pub(crate) static SHA256: Hmac<ic_mac::HmacSha256> = Hmac::new();
pub(crate) static SHA384: Hmac<ic_mac::HmacSha384> = Hmac::new();

/// One of IronCrypto's MACs, presented as a rustls HMAC.
pub(crate) struct Hmac<M: Mac> {
    _mac: core::marker::PhantomData<fn() -> M>,
}

impl<M: Mac> Hmac<M> {
    const fn new() -> Self {
        Self {
            _mac: core::marker::PhantomData,
        }
    }
}

impl<M: Mac + Send + Sync + 'static> hmac::Hmac for Hmac<M> {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(Key::<M> {
            key: key.to_vec(),
            _mac: core::marker::PhantomData,
        })
    }

    fn hash_output_len(&self) -> usize {
        M::TAG_LEN
    }

    /// Always false; see the note on the hash adapter.
    fn fips(&self) -> bool {
        false
    }
}

/// A key bound to a MAC.
///
/// The key is held rather than a keyed MAC instance, because rustls signs many
/// independent messages with one key and each needs a fresh computation.
struct Key<M: Mac> {
    key: alloc::vec::Vec<u8>,
    _mac: core::marker::PhantomData<fn() -> M>,
}

impl<M: Mac> Drop for Key<M> {
    /// The key is HMAC key material -- in TLS 1.3 it is a traffic secret or a
    /// `finished` key -- so it does not outlive the connection in memory.
    fn drop(&mut self) {
        use ic_core::Zeroize;
        self.key.zeroize();
    }
}

impl<M: Mac + Send + Sync + 'static> hmac::Key for Key<M> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        // The pieces are fed in order rather than concatenated into a buffer:
        // the input is a traffic secret and a transcript, and copying them to
        // join them would leave a second copy to clear.
        let mut mac = M::new(&self.key).expect("the key length was accepted by with_key");
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        hmac::Tag::new(mac.finalize().as_ref())
    }

    fn tag_len(&self) -> usize {
        M::TAG_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hmac::Hmac as _;

    /// RFC 4231 test case 2, which uses the key "Jefe" and the message
    /// "what do ya want for nothing?".
    ///
    /// Checked against the published value rather than against `ic_mac`, so
    /// this says the adapter computes HMAC rather than that it agrees with the
    /// thing it wraps.
    #[test]
    fn the_adapter_computes_rfc4231_hmac() {
        let key = SHA256.with_key(b"Jefe");
        let tag = key.sign(&[b"what do ya want for nothing?"]);
        assert_eq!(
            ic_core::codec::hex(tag.as_ref()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        let key = SHA384.with_key(b"Jefe");
        let tag = key.sign(&[b"what do ya want for nothing?"]);
        assert_eq!(
            ic_core::codec::hex(tag.as_ref()),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );
    }

    /// The pieces must join in order, or a transcript would authenticate
    /// differently from the bytes that were sent.
    #[test]
    fn splitting_the_input_does_not_change_the_tag() {
        let key = SHA256.with_key(b"Jefe");
        let whole = key.sign(&[b"what do ya want for nothing?"]);

        let split = key.sign(&[b"what do ya ", b"want for ", b"nothing?"]);
        assert_eq!(whole.as_ref(), split.as_ref());

        let concat = key.sign_concat(b"what do ya ", &[b"want for "], b"nothing?");
        assert_eq!(whole.as_ref(), concat.as_ref());

        // And order has to matter, or the check above proves nothing.
        let reordered = key.sign(&[b"want for ", b"what do ya ", b"nothing?"]);
        assert_ne!(whole.as_ref(), reordered.as_ref());
    }

    /// rustls derives the whole TLS 1.3 key schedule through this, so the
    /// construction it builds has to produce RFC 5869's answers.
    ///
    /// Test case 1 from RFC 5869 appendix A: SHA-256, a 22-byte IKM of 0x0b, a
    /// 13-byte salt, a 10-byte info, and 42 bytes of output.
    #[test]
    fn hkdf_over_this_hmac_matches_rfc5869() {
        use rustls::crypto::tls13::{Hkdf, HkdfUsingHmac};

        let hkdf = HkdfUsingHmac(&SHA256);
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ikm = [0x0bu8; 22];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);
        let mut out = [0u8; 42];
        expander
            .expand_slice(&[&info], &mut out)
            .expect("42 bytes is within the HKDF output limit");

        assert_eq!(
            ic_core::codec::hex(&out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    #[test]
    fn the_declared_lengths_are_right() {
        assert_eq!(SHA256.hash_output_len(), 32);
        assert_eq!(SHA384.hash_output_len(), 48);
        assert_eq!(SHA256.with_key(b"k").tag_len(), 32);
        assert_eq!(SHA384.with_key(b"k").tag_len(), 48);
    }

    #[test]
    fn neither_claims_fips_validation() {
        assert!(!SHA256.fips());
        assert!(!SHA384.fips());
    }
}
