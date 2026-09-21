//! AES-GCM record protection, for TLS 1.3 and TLS 1.2.
//!
//! The two versions frame a record differently and that is most of what is
//! here:
//!
//! - **TLS 1.3** hides the content type by appending it to the plaintext and
//!   encrypting it, so every record is `application_data` on the wire. The
//!   nonce is the write IV xored with the sequence number; nothing is sent.
//! - **TLS 1.2** sends an explicit 8-byte nonce ahead of the ciphertext, and
//!   authenticates a header carrying the sequence number, content type,
//!   version and length.
//!
//! Both use `ic_cipher`'s AES-GCM underneath, through the same `Aead` trait any
//! other caller would use. Nothing about the cipher is special-cased for TLS.

use alloc::boxed::Box;

use ic_core::traits::Aead as _;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

/// AES-GCM's authentication tag is 16 bytes in every TLS cipher suite.
const TAG_LEN: usize = 16;

/// The explicit nonce TLS 1.2 puts on the wire, in bytes.
const TLS12_EXPLICIT_NONCE_LEN: usize = 8;

/// The implicit part of a TLS 1.2 GCM nonce, from the key block.
const TLS12_FIXED_IV_LEN: usize = 4;

pub(crate) static TLS13_AES_128_GCM: Tls13Gcm = Tls13Gcm { key_len: 16 };
pub(crate) static TLS13_AES_256_GCM: Tls13Gcm = Tls13Gcm { key_len: 32 };
pub(crate) static TLS12_AES_128_GCM: Tls12Gcm = Tls12Gcm { key_len: 16 };
pub(crate) static TLS12_AES_256_GCM: Tls12Gcm = Tls12Gcm { key_len: 32 };

/// Bind a key of whichever length to the matching AES-GCM.
///
/// The key length is carried as data rather than as a type parameter because
/// rustls hands over an `AeadKey` whose length is decided by the cipher suite,
/// and a mismatch here should be an error rather than a monomorphisation.
fn gcm(key: &[u8]) -> Result<Gcm, Error> {
    Ok(match key.len() {
        16 => Gcm::Aes128(
            ic_cipher::Aes128Gcm::new(key)
                .map_err(|_| Error::General("aes-128-gcm rejected a key rustls supplied".into()))?,
        ),
        32 => Gcm::Aes256(
            ic_cipher::Aes256Gcm::new(key)
                .map_err(|_| Error::General("aes-256-gcm rejected a key rustls supplied".into()))?,
        ),
        n => {
            return Err(Error::General(alloc::format!(
                "no aes-gcm variant takes a {n}-byte key"
            )))
        }
    })
}

/// AES-GCM at one of the two key lengths TLS uses.
enum Gcm {
    Aes128(ic_cipher::Aes128Gcm),
    Aes256(ic_cipher::Aes256Gcm),
}

impl Gcm {
    fn seal(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &mut [u8]) -> Result<(), ()> {
        match self {
            Self::Aes128(c) => c.seal_detached(nonce, aad, in_out, tag),
            Self::Aes256(c) => c.seal_detached(nonce, aad, in_out, tag),
        }
        .map_err(|_| ())
    }

    fn open(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<(), ()> {
        match self {
            Self::Aes128(c) => c.open_detached(nonce, aad, in_out, tag),
            Self::Aes256(c) => c.open_detached(nonce, aad, in_out, tag),
        }
        .map_err(|_| ())
    }
}

// ---------------------------------------------------------------------------
// TLS 1.3
// ---------------------------------------------------------------------------

pub(crate) struct Tls13Gcm {
    key_len: usize,
}

impl Tls13AeadAlgorithm for Tls13Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            // A failure here cannot be reported: the trait returns the
            // encrypter directly. It also cannot happen, because rustls sizes
            // the key from the cipher suite this algorithm belongs to, and the
            // test below pins that.
            cipher: gcm(key.as_ref()).expect("rustls supplied a key this suite does not use"),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            cipher: gcm(key.as_ref()).expect("rustls supplied a key this suite does not use"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.key_len
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.key_len {
            16 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            32 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            _ => return Err(UnsupportedOperationError),
        })
    }

    /// Always false; see the note on the hash adapter.
    fn fips(&self) -> bool {
        false
    }
}

struct Tls13Encrypter {
    cipher: Gcm,
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
    cipher: Gcm,
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

pub(crate) struct Tls12Gcm {
    key_len: usize,
}

impl Tls12AeadAlgorithm for Tls12Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
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

        Box::new(Tls12Encrypter {
            cipher: gcm(key.as_ref()).expect("rustls supplied a key this suite does not use"),
            nonce,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut fixed = [0u8; TLS12_FIXED_IV_LEN];
        fixed.copy_from_slice(iv);
        Box::new(Tls12Decrypter {
            cipher: gcm(key.as_ref()).expect("rustls supplied a key this suite does not use"),
            fixed,
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.key_len,
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
        nonce[..TLS12_FIXED_IV_LEN].copy_from_slice(iv);
        nonce[TLS12_FIXED_IV_LEN..].copy_from_slice(explicit);
        let iv = Iv::new(nonce);

        Ok(match self.key_len {
            16 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            32 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            _ => return Err(UnsupportedOperationError),
        })
    }

    fn fips(&self) -> bool {
        false
    }
}

struct Tls12Encrypter {
    cipher: Gcm,
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
    cipher: Gcm,
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
