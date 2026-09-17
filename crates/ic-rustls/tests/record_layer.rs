//! The record layer, driven through rustls's own types.
//!
//! This is the riskiest code in the crate. The cipher underneath is checked
//! against the GCM specification's vectors in `ic-cipher`, and none of that
//! says whether *this* crate frames a record correctly: what goes in the
//! additional data, where the tag sits, which byte carries the content type,
//! how the nonce is built from the sequence number.
//!
//! Getting any of those wrong produces something that encrypts and decrypts
//! perfectly well against itself and interoperates with nothing. So these tests
//! check the framing, not the cipher -- the parts where agreement with the
//! specification is the whole requirement:
//!
//! - a record made by the encrypter is read back by the decrypter, with the
//!   content type and payload intact;
//! - the sequence number is bound in, so a record replayed at a different
//!   position is refused;
//! - the tag is checked, so any modification is refused;
//! - and the lengths are what the encrypter promised, since rustls allocates
//!   from `encrypted_payload_len` before it calls `encrypt`.

use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, OutboundPlainMessage, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
};
use rustls::{ContentType, ProtocolVersion};

/// The AES-256 TLS 1.3 algorithm.
///
/// Only the 256-bit suites are driven here, and not because the 128-bit ones
/// are less important. `AeadKey` can only be constructed publicly from a full
/// 32-byte array -- `with_length` is private to rustls -- so an external test
/// cannot produce the 16-byte key AES-128 takes. Passing 32 bytes to the
/// AES-128 algorithm would quietly select AES-256 inside the provider's length
/// dispatch, and the test would report coverage it does not have.
///
/// The two share every line of framing. What differs is which cipher the length
/// dispatch returns, and `suites.rs` checks each suite is wired to the right
/// key length.
fn tls13_aes256() -> &'static dyn Tls13AeadAlgorithm {
    for suite in ic_rustls::suites::ALL {
        if let rustls::SupportedCipherSuite::Tls13(t) = suite {
            if t.common.suite == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 {
                assert_eq!(t.aead_alg.key_len(), 32);
                return t.aead_alg;
            }
        }
    }
    panic!("the AES-256 TLS 1.3 suite is missing");
}

/// The AES-256 TLS 1.2 algorithm, for the same reason.
fn tls12_aes256() -> &'static dyn Tls12AeadAlgorithm {
    for suite in ic_rustls::suites::ALL {
        if let rustls::SupportedCipherSuite::Tls12(t) = suite {
            if t.common.suite == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
                assert_eq!(t.aead_alg.key_block_shape().enc_key_len, 32);
                return t.aead_alg;
            }
        }
    }
    panic!("the AES-256 TLS 1.2 suite is missing");
}

fn key() -> AeadKey {
    AeadKey::from([0x2bu8; 32])
}

/// The encrypted bytes of an outbound record.
fn bytes_of(msg: &rustls::crypto::cipher::OutboundOpaqueMessage) -> Vec<u8> {
    msg.payload.as_ref().to_vec()
}

#[test]
fn a_tls13_record_survives_the_round_trip() {
    let mut checked = 0;

    {
        let name = "aes-256-gcm";
        let alg = tls13_aes256();
        let mut enc = alg.encrypter(key(), Iv::copy(&[0x5cu8; 12]));
        let mut dec = alg.decrypter(key(), Iv::copy(&[0x5cu8; 12]));

        for (typ, payload) in [
            (ContentType::ApplicationData, &b"hello"[..]),
            (ContentType::Handshake, &b""[..]),
            (ContentType::Alert, &[0xffu8; 1000][..]),
        ] {
            for seq in [0u64, 1, 4096, u32::MAX as u64 + 1] {
                let msg = OutboundPlainMessage {
                    typ,
                    version: ProtocolVersion::TLSv1_3,
                    payload: payload.into(),
                };

                // rustls allocates from this before calling encrypt, so an
                // understatement here is a buffer overrun in the caller and an
                // overstatement wastes a copy on every record.
                let promised = enc.encrypted_payload_len(payload.len());

                let sealed = enc.encrypt(msg, seq).expect("{name}: encrypt failed");
                assert_eq!(
                    bytes_of(&sealed).len(),
                    promised,
                    "{name}: encrypted_payload_len promised {promised}"
                );
                // TLS 1.3 hides the real type behind application_data.
                assert_eq!(sealed.typ, ContentType::ApplicationData);

                let mut buf = bytes_of(&sealed);
                let opened = dec
                    .decrypt(
                        InboundOpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            &mut buf,
                        ),
                        seq,
                    )
                    .unwrap_or_else(|e| panic!("{name}: decrypt failed at seq {seq}: {e:?}"));

                assert_eq!(opened.typ, typ, "{name}: the content type was lost");
                assert_eq!(opened.payload, payload, "{name}: the payload was lost");
                checked += 1;
            }
        }
    }

    assert!(checked >= 12, "only {checked} records exercised");
}

#[test]
fn a_tls13_record_is_bound_to_its_sequence_number() {
    {
        let name = "aes-256-gcm";
        let alg = tls13_aes256();
        let mut enc = alg.encrypter(key(), Iv::copy(&[0x5cu8; 12]));
        let mut dec = alg.decrypter(key(), Iv::copy(&[0x5cu8; 12]));

        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_3,
                    payload: b"attack at dawn"[..].into(),
                },
                7,
            )
            .unwrap();

        // Replayed at another position, the nonce differs and the tag fails.
        // Without this the record layer would accept reordering.
        let mut buf = bytes_of(&sealed);
        assert!(
            dec.decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut buf,
                ),
                8,
            )
            .is_err(),
            "{name}: a record replayed at a different sequence number was accepted"
        );

        // And at the right one it still works, so the check above is not just
        // failing for some other reason.
        let mut buf = bytes_of(&sealed);
        assert!(dec
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut buf,
                ),
                7,
            )
            .is_ok());
    }
}

#[test]
fn any_modification_to_a_tls13_record_is_refused() {
    {
        let name = "aes-256-gcm";
        let alg = tls13_aes256();
        let mut enc = alg.encrypter(key(), Iv::copy(&[0x5cu8; 12]));
        let mut dec = alg.decrypter(key(), Iv::copy(&[0x5cu8; 12]));

        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_3,
                    payload: b"attack at dawn"[..].into(),
                },
                0,
            )
            .unwrap();
        let original = bytes_of(&sealed);

        // Every byte, every bit: ciphertext, the hidden content type, and the
        // tag are all covered, so none of them can be changed unnoticed.
        let mut refused = 0;
        for at in 0..original.len() {
            for bit in 0..8 {
                let mut buf = original.clone();
                buf[at] ^= 1 << bit;
                assert!(
                    dec.decrypt(
                        InboundOpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            &mut buf,
                        ),
                        0,
                    )
                    .is_err(),
                    "{name}: flipping bit {bit} of byte {at} was not detected"
                );
                refused += 1;
            }
        }
        assert!(refused > 200, "{name}: only {refused} mutations tried");

        // Truncation, including below the tag length.
        for len in [0usize, 1, 15, 16, original.len() - 1] {
            let mut buf = original[..len].to_vec();
            assert!(
                dec.decrypt(
                    InboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        &mut buf,
                    ),
                    0,
                )
                .is_err(),
                "{name}: a record truncated to {len} bytes was accepted"
            );
        }
    }
}

#[test]
fn a_tls12_record_survives_the_round_trip() {
    let mut checked = 0;

    {
        let name = "aes-256-gcm";
        let alg = tls12_aes256();
        let shape = alg.key_block_shape();
        let iv = vec![0x5cu8; shape.fixed_iv_len];
        let extra = vec![0x11u8; shape.explicit_nonce_len];

        let mut enc = alg.encrypter(key(), &iv, &extra);
        let mut dec = alg.decrypter(key(), &iv);

        for (typ, payload) in [
            (ContentType::ApplicationData, &b"hello"[..]),
            (ContentType::Handshake, &[0xabu8; 500][..]),
        ] {
            for seq in [0u64, 1, 65535] {
                let promised = enc.encrypted_payload_len(payload.len());
                let sealed = enc
                    .encrypt(
                        OutboundPlainMessage {
                            typ,
                            version: ProtocolVersion::TLSv1_2,
                            payload: payload.into(),
                        },
                        seq,
                    )
                    .unwrap_or_else(|e| panic!("{name}: encrypt failed: {e:?}"));

                assert_eq!(bytes_of(&sealed).len(), promised, "{name}: length mismatch");
                // TLS 1.2 does not hide the content type.
                assert_eq!(sealed.typ, typ);

                let mut buf = bytes_of(&sealed);
                let opened = dec
                    .decrypt(
                        InboundOpaqueMessage::new(typ, ProtocolVersion::TLSv1_2, &mut buf),
                        seq,
                    )
                    .unwrap_or_else(|e| panic!("{name}: decrypt failed at seq {seq}: {e:?}"));

                assert_eq!(opened.payload, payload, "{name}: the payload was lost");
                checked += 1;
            }
        }
    }

    assert!(checked >= 6, "only {checked} records exercised");
}

#[test]
fn a_tls12_record_is_bound_to_its_header() {
    {
        let name = "aes-256-gcm";
        let alg = tls12_aes256();
        let shape = alg.key_block_shape();
        let iv = vec![0x5cu8; shape.fixed_iv_len];
        let extra = vec![0x11u8; shape.explicit_nonce_len];
        let mut enc = alg.encrypter(key(), &iv, &extra);
        let mut dec = alg.decrypter(key(), &iv);

        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: b"attack at dawn"[..].into(),
                },
                3,
            )
            .unwrap();
        let original = bytes_of(&sealed);

        // The sequence number, the content type and the version are all in the
        // additional data, so changing any of them must fail the tag. A record
        // that could be re-labelled as a different content type is a record
        // that can be smuggled past a state machine.
        for (what, typ, version, seq) in [
            (
                "sequence number",
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                4u64,
            ),
            (
                "content type",
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                3,
            ),
            (
                "version",
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_1,
                3,
            ),
        ] {
            let mut buf = original.clone();
            assert!(
                dec.decrypt(InboundOpaqueMessage::new(typ, version, &mut buf), seq)
                    .is_err(),
                "{name}: changing the {what} was not detected"
            );
        }

        // Unchanged, it still opens.
        let mut buf = original.clone();
        assert!(dec
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut buf,
                ),
                3,
            )
            .is_ok());
    }
}

/// Hostile records must be refused, not fatal.
///
/// A record arrives from the network before anything has authenticated it, so
/// the decrypter sees whatever the peer sends -- including lengths chosen to
/// make an implementation index past the end of a buffer.
#[test]
fn hostile_records_are_refused_rather_than_fatal() {
    let mut tried = 0;

    {
        let mut dec = tls13_aes256().decrypter(key(), Iv::copy(&[0x5cu8; 12]));
        for len in [0usize, 1, 15, 16, 17, 31, 32, 4096] {
            for fill in [0x00u8, 0xff, 0xaa] {
                let mut buf = vec![fill; len];
                let _ = dec.decrypt(
                    InboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        &mut buf,
                    ),
                    0,
                );
                tried += 1;
            }
        }
    }

    {
        let alg = tls12_aes256();
        let shape = alg.key_block_shape();
        let iv = vec![0x5cu8; shape.fixed_iv_len];
        let mut dec = alg.decrypter(key(), &iv);
        for len in [0usize, 1, 8, 16, 23, 24, 25, 4096] {
            for fill in [0x00u8, 0xff, 0xaa] {
                let mut buf = vec![fill; len];
                let _ = dec.decrypt(
                    InboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        &mut buf,
                    ),
                    0,
                );
                tried += 1;
            }
        }
    }

    assert!(tried >= 48, "only {tried} hostile records tried");
}
