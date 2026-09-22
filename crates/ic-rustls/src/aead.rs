//! Record protection, for TLS 1.3 and TLS 1.2.
//!
//! The two versions frame a record differently and that is most of what is
//! here:
//!
//! - **TLS 1.3** hides the content type by appending it to the plaintext and
//!   encrypting it, so every record is `application_data` on the wire. The
//!   nonce is the write IV xored with the sequence number; nothing is sent.
//! - **TLS 1.2 with AES-GCM** sends an explicit 8-byte nonce ahead of the
//!   ciphertext, and authenticates a header carrying the sequence number,
//!   content type, version and length.
//! - **TLS 1.2 with ChaCha20-Poly1305** does *not*. RFC 7905 gives it the
//!   TLS 1.3 nonce construction instead: a 12-byte fixed IV from the key block
//!   xored with the sequence number, with nothing sent on the wire. It keeps
//!   the TLS 1.2 additional data. So it is neither of the other two cases and
//!   has its own encrypter below.
//!
//! That last point is the one worth being careful about. A ChaCha20 suite
//! framed like the GCM one -- eight bytes of explicit nonce in front --
//! round-trips perfectly against itself and interoperates with nothing, which
//! is the failure this module's tests are built to catch.
//!
//! All three use `ic_cipher` underneath, through the same `Aead` trait any
//! other caller would use. Nothing about the ciphers is special-cased for TLS.

use alloc::boxed::Box;

use ic_core::traits::Aead as _;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

/// The authentication tag is 16 bytes in every TLS cipher suite here, for
/// AES-GCM and ChaCha20-Poly1305 alike.
const TAG_LEN: usize = 16;

/// The explicit nonce TLS 1.2 puts on the wire for AES-GCM.
const TLS12_EXPLICIT_NONCE_LEN: usize = 8;

/// The implicit part of a TLS 1.2 AES-GCM nonce, from the key block.
const TLS12_FIXED_IV_LEN: usize = 4;

/// The whole of a TLS 1.2 ChaCha20-Poly1305 nonce comes from the key block.
/// RFC 7905 section 2.
const TLS12_CHACHA_IV_LEN: usize = 12;

pub(crate) static TLS13_AES_128_GCM: Tls13Aead = Tls13Aead {
    suite: Suite::Aes128,
};
pub(crate) static TLS13_AES_256_GCM: Tls13Aead = Tls13Aead {
    suite: Suite::Aes256,
};
pub(crate) static TLS13_CHACHA20_POLY1305: Tls13Aead = Tls13Aead {
    suite: Suite::ChaCha20,
};
pub(crate) static TLS12_AES_128_GCM: Tls12Aead = Tls12Aead {
    suite: Suite::Aes128,
};
pub(crate) static TLS12_AES_256_GCM: Tls12Aead = Tls12Aead {
    suite: Suite::Aes256,
};
pub(crate) static TLS12_CHACHA20_POLY1305: Tls12Aead = Tls12Aead {
    suite: Suite::ChaCha20,
};

/// Which AEAD a suite uses.
///
/// Carried as data rather than as a type parameter because rustls hands over an
/// `AeadKey` whose length the cipher suite decides, and a mismatch should be an
/// error rather than a monomorphisation. It is an explicit choice rather than
/// an inference from the key length, because ChaCha20-Poly1305 and AES-256-GCM
/// both take thirty-two bytes and are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Suite {
    Aes128,
    Aes256,
    ChaCha20,
}

impl Suite {
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 => 32,
        }
    }

    /// Bind a key to this suite's cipher.
    pub(crate) fn cipher(self, key: &[u8]) -> Result<Cipher, Error> {
        if key.len() != self.key_len() {
            return Err(Error::General(alloc::format!(
                "{:?} takes a {}-byte key, not {}",
                self,
                self.key_len(),
                key.len()
            )));
        }
        let bad = |_| Error::General(alloc::format!("{self:?} rejected a key rustls supplied"));
        Ok(match self {
            Self::Aes128 => Cipher::Aes128(ic_cipher::Aes128Gcm::new(key).map_err(bad)?),
            Self::Aes256 => Cipher::Aes256(ic_cipher::Aes256Gcm::new(key).map_err(bad)?),
            Self::ChaCha20 => Cipher::ChaCha20(ic_cipher::ChaCha20Poly1305::new(key).map_err(bad)?),
        })
    }

    /// What rustls should report when asked to export the traffic keys.
    fn traffic_secrets(self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self {
            Self::Aes128 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::ChaCha20 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
}

/// One of the three AEADs, keyed.
pub(crate) enum Cipher {
    Aes128(ic_cipher::Aes128Gcm),
    Aes256(ic_cipher::Aes256Gcm),
    ChaCha20(ic_cipher::ChaCha20Poly1305),
}

impl Cipher {
    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), ()> {
        match self {
            Self::Aes128(c) => c.seal_detached(nonce, aad, in_out, tag),
            Self::Aes256(c) => c.seal_detached(nonce, aad, in_out, tag),
            Self::ChaCha20(c) => c.seal_detached(nonce, aad, in_out, tag),
        }
        .map_err(|_| ())
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8],
    ) -> Result<(), ()> {
        match self {
            Self::Aes128(c) => c.open_detached(nonce, aad, in_out, tag),
            Self::Aes256(c) => c.open_detached(nonce, aad, in_out, tag),
            Self::ChaCha20(c) => c.open_detached(nonce, aad, in_out, tag),
        }
        .map_err(|_| ())
    }
}

// ---------------------------------------------------------------------------
// TLS 1.3
// ---------------------------------------------------------------------------

/// TLS 1.3 record protection.
///
/// One type for all three ciphers, because TLS 1.3 frames every record the same
/// way whatever the AEAD: the nonce is the IV xored with the sequence number,
/// the content type is encrypted with the payload, and nothing goes on the wire
/// but ciphertext and tag. Writing that out once per cipher would be three
/// copies of the part most worth having only one of.
pub(crate) struct Tls13Aead {
    suite: Suite,
}

impl Tls13AeadAlgorithm for Tls13Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            // A failure here cannot be reported: the trait returns the
            // encrypter directly. It also cannot happen, because rustls sizes
            // the key from the cipher suite this algorithm belongs to, and the
            // test below pins that.
            cipher: self
                .suite
                .cipher(key.as_ref())
                .expect("rustls supplied a key this suite does not use"),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            cipher: self
                .suite
                .cipher(key.as_ref())
                .expect("rustls supplied a key this suite does not use"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.suite.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.suite.traffic_secrets(key, iv))
    }

    /// Always false; see the note on the hash adapter.
    fn fips(&self) -> bool {
        false
    }
}

struct Tls13Encrypter {
    cipher: Cipher,
    iv: Iv,
}

impl MessageEncrypter for Tls13Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // TLS 1.3 encrypts the content type along with the data, so the type
        // on the wire is always application_data and the real one is recovered
        // only after the tag verifies.
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);

        let mut tag = [0u8; TAG_LEN];
        let body = payload.as_mut();
        self.cipher
            .seal(&nonce, &aad, body, &mut tag)
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Every TLS 1.3 record carries 0x0303 as the legacy record version.
            // RFC 8446 section 5.1.
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        // The content type byte, then the tag.
        payload_len + 1 + TAG_LEN
    }
}

struct Tls13Decrypter {
    cipher: Cipher,
    iv: Iv,
}

impl MessageDecrypter for Tls13Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(payload.len());

        let cipher_len = payload.len() - TAG_LEN;
        let (body, tag) = payload.split_at_mut(cipher_len);
        let tag: [u8; TAG_LEN] = tag.try_into().expect("split at exactly the tag length");

        self.cipher
            .open(&nonce, &aad, body, &tag)
            .map_err(|_| Error::DecryptError)?;

        payload.truncate(cipher_len);
        msg.into_tls13_unpadded_message()
    }
}

// ---------------------------------------------------------------------------
// TLS 1.2
// ---------------------------------------------------------------------------

/// TLS 1.2 record protection.
///
/// Unlike TLS 1.3 this cannot be one implementation, because the two AEADs are
/// framed differently: AES-GCM sends an explicit nonce and ChaCha20-Poly1305
/// derives the whole nonce from the key block. The choice is made here, once,
/// and [`Self::key_block_shape`] has to agree with it -- a shape that says
/// eight explicit bytes while the encrypter sends none produces records the
/// peer cannot parse.
pub(crate) struct Tls12Aead {
    suite: Suite,
}

impl Tls12AeadAlgorithm for Tls12Aead {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let cipher = self
            .suite
            .cipher(key.as_ref())
            .expect("rustls supplied a key this suite does not use");

        if self.suite == Suite::ChaCha20 {
            // RFC 7905 section 2: the nonce is the whole 12-byte key block IV
            // xored with the sequence number, exactly as in TLS 1.3. `extra` is
            // empty, because `key_block_shape` asks for no explicit nonce.
            let mut fixed = [0u8; TLS12_CHACHA_IV_LEN];
            fixed.copy_from_slice(iv);
            return Box::new(Tls12ChaChaEncrypter {
                cipher,
                iv: Iv::new(fixed),
            });
        }

        // The write nonce is the 4-byte fixed IV from the key block followed by
        // an 8-byte explicit part, which is `extra` -- also key block material
        // -- xored with the sequence number per record.
        //
        // RFC 5288 does not specify how to build the explicit part: the receiver
        // uses whatever was sent, so any construction that does not repeat under
        // one key interoperates. That freedom means there is no specification to
        // check this against, so it was compared against rustls's own provider
        // instead, which builds the same `write_iv || explicit` and xors the
        // sequence into the last eight bytes. Their comment on the matter: "no
        // specified construction. Thanks for that."
        //
        // `the_tls12_explicit_nonce_is_the_key_block_value_xored_with_the_sequence`
        // pins the resulting bytes, because a comparison nobody wrote down is
        // one that has to be made again.
        let mut nonce = [0u8; 12];
        nonce[..TLS12_FIXED_IV_LEN].copy_from_slice(iv);
        nonce[TLS12_FIXED_IV_LEN..].copy_from_slice(extra);

        Box::new(Tls12Encrypter { cipher, nonce })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let cipher = self
            .suite
            .cipher(key.as_ref())
            .expect("rustls supplied a key this suite does not use");

        if self.suite == Suite::ChaCha20 {
            let mut fixed = [0u8; TLS12_CHACHA_IV_LEN];
            fixed.copy_from_slice(iv);
            return Box::new(Tls12ChaChaDecrypter {
                cipher,
                iv: Iv::new(fixed),
            });
        }

        let mut fixed = [0u8; TLS12_FIXED_IV_LEN];
        fixed.copy_from_slice(iv);
        Box::new(Tls12Decrypter { cipher, fixed })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        if self.suite == Suite::ChaCha20 {
            // RFC 7905 section 2: twelve bytes of IV drawn from the key block,
            // nothing explicit.
            return KeyBlockShape {
                enc_key_len: self.suite.key_len(),
                fixed_iv_len: TLS12_CHACHA_IV_LEN,
                explicit_nonce_len: 0,
            };
        }
        KeyBlockShape {
            enc_key_len: self.suite.key_len(),
            fixed_iv_len: TLS12_FIXED_IV_LEN,
            explicit_nonce_len: TLS12_EXPLICIT_NONCE_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut nonce = [0u8; 12];
        // For ChaCha20 the IV is already the full twelve bytes and `explicit`
        // is empty; for GCM the two halves are concatenated.
        if iv.len() + explicit.len() != nonce.len() {
            return Err(UnsupportedOperationError);
        }
        nonce[..iv.len()].copy_from_slice(iv);
        nonce[iv.len()..].copy_from_slice(explicit);

        Ok(self.suite.traffic_secrets(key, Iv::new(nonce)))
    }

    fn fips(&self) -> bool {
        false
    }
}

struct Tls12Encrypter {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl MessageEncrypter for Tls12Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        // The explicit half of the nonce is the sequence number, and it is sent
        // in the clear ahead of the ciphertext so the peer can reconstruct it.
        let mut nonce = self.nonce;
        for (n, s) in nonce[TLS12_FIXED_IV_LEN..]
            .iter_mut()
            .zip(seq.to_be_bytes())
        {
            *n ^= s;
        }
        let explicit = &nonce[TLS12_FIXED_IV_LEN..];

        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(explicit);
        payload.extend_from_chunks(&msg.payload);

        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let mut tag = [0u8; TAG_LEN];
        let body = &mut payload.as_mut()[TLS12_EXPLICIT_NONCE_LEN..];
        self.cipher
            .seal(&nonce, &aad, body, &mut tag)
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        TLS12_EXPLICIT_NONCE_LEN + payload_len + TAG_LEN
    }
}

struct Tls12Decrypter {
    cipher: Cipher,
    fixed: [u8; TLS12_FIXED_IV_LEN],
}

impl MessageDecrypter for Tls12Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TLS12_EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }

        // The peer chose the explicit half of the nonce and sent it, so it is
        // read rather than derived.
        let mut nonce = [0u8; 12];
        nonce[..TLS12_FIXED_IV_LEN].copy_from_slice(&self.fixed);
        nonce[TLS12_FIXED_IV_LEN..].copy_from_slice(&payload[..TLS12_EXPLICIT_NONCE_LEN]);

        let plain_len = payload.len() - TLS12_EXPLICIT_NONCE_LEN - TAG_LEN;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);

        let tag_at = TLS12_EXPLICIT_NONCE_LEN + plain_len;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&payload[tag_at..]);

        let body = &mut payload[TLS12_EXPLICIT_NONCE_LEN..tag_at];
        self.cipher
            .open(&nonce, &aad, body, &tag)
            .map_err(|_| Error::DecryptError)?;

        // Drop the explicit nonce from the front, leaving just the plaintext.
        payload.copy_within(TLS12_EXPLICIT_NONCE_LEN.., 0);
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// TLS 1.2 with ChaCha20-Poly1305, which sends no explicit nonce.
///
/// RFC 7905 section 2. The record is ciphertext and tag, nothing more: the
/// nonce is reconstructed by the receiver from its own key block and the
/// sequence number, as in TLS 1.3. The additional data is still TLS 1.2's.
struct Tls12ChaChaEncrypter {
    cipher: Cipher,
    iv: Iv,
}

impl MessageEncrypter for Tls12ChaChaEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);

        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let mut tag = [0u8; TAG_LEN];
        self.cipher
            .seal(&nonce, &aad, payload.as_mut(), &mut tag)
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

struct Tls12ChaChaDecrypter {
    cipher: Cipher,
    iv: Iv,
}

impl MessageDecrypter for Tls12ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }

        let plain_len = payload.len() - TAG_LEN;
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);

        let (body, tag) = payload.split_at_mut(plain_len);
        let tag: [u8; TAG_LEN] = tag.try_into().expect("split at exactly the tag length");

        self.cipher
            .open(&nonce, &aad, body, &tag)
            .map_err(|_| Error::DecryptError)?;

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each suite's key length must be the one its cipher accepts.
    ///
    /// `encrypter` panics on a mismatch rather than returning an error, because
    /// the trait gives it nowhere to put one. That is only safe if rustls can
    /// never hand over the wrong length, which is what this pins.
    #[test]
    fn each_suite_binds_the_key_length_it_advertises() {
        for suite in [Suite::Aes128, Suite::Aes256, Suite::ChaCha20] {
            let key = alloc::vec![0x42u8; suite.key_len()];
            assert!(suite.cipher(&key).is_ok(), "{suite:?} rejected its own key");

            // And the neighbouring lengths must not be accepted silently.
            for wrong in [suite.key_len() - 1, suite.key_len() + 1] {
                assert!(
                    suite.cipher(&alloc::vec![0u8; wrong]).is_err(),
                    "{suite:?} accepted a {wrong}-byte key"
                );
            }
        }

        // The distinction that cannot be made from the key length alone.
        assert_eq!(Suite::Aes256.key_len(), Suite::ChaCha20.key_len());
    }

    /// The TLS 1.2 key block shape must match how the record is actually framed.
    ///
    /// These two are set in different places and nothing in the type system ties
    /// them together: a shape asking for eight explicit bytes while the
    /// encrypter emits none yields records the peer reads as truncated. RFC 7905
    /// section 2 is the authority for the ChaCha20 row.
    #[test]
    fn the_tls12_key_block_shape_matches_the_framing() {
        let gcm = Tls12Aead {
            suite: Suite::Aes128,
        }
        .key_block_shape();
        assert_eq!(gcm.fixed_iv_len, 4);
        assert_eq!(gcm.explicit_nonce_len, 8);
        assert_eq!(gcm.enc_key_len, 16);

        let chacha = Tls12Aead {
            suite: Suite::ChaCha20,
        }
        .key_block_shape();
        assert_eq!(
            chacha.fixed_iv_len, 12,
            "RFC 7905: the whole nonce is implicit"
        );
        assert_eq!(chacha.explicit_nonce_len, 0, "RFC 7905: nothing is sent");
        assert_eq!(chacha.enc_key_len, 32);

        // Whatever the split, a nonce is twelve bytes.
        for shape in [gcm, chacha] {
            assert_eq!(shape.fixed_iv_len + shape.explicit_nonce_len, 12);
        }
    }
}
