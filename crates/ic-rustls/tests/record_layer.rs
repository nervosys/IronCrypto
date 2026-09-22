//! The record layer, driven through rustls's own types.
//!
//! This is the riskiest code in the crate. The ciphers underneath are checked
//! against their specifications' vectors in `ic-cipher`, and none of that says
//! whether *this* crate frames a record correctly: what goes in the additional
//! data, where the tag sits, which byte carries the content type, how the nonce
//! is built from the sequence number.
//!
//! Each test runs over both 32-byte algorithms -- AES-256-GCM and
//! ChaCha20-Poly1305 -- rather than over one with the other assumed to follow.
//! Under TLS 1.3 they are framed identically and share an implementation, so
//! that is cheap. Under TLS 1.2 they are *not*: RFC 7905 sends no explicit
//! nonce where RFC 5288 sends eight bytes of one, and
//! `a_tls12_chacha_record_carries_no_explicit_nonce` is there because every
//! other test in this file passes just as happily on the wrong framing.
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

/// The TLS 1.3 ChaCha20-Poly1305 algorithm.
///
/// Its key is thirty-two bytes, the same as AES-256, so unlike the AES-128
/// suites it can be driven from an external test through the public `AeadKey`
/// constructor. That is why both of the algorithms exercised below are the
/// 32-byte ones.
fn tls13_chacha() -> &'static dyn Tls13AeadAlgorithm {
    for suite in ic_rustls::suites::ALL {
        if let rustls::SupportedCipherSuite::Tls13(t) = suite {
            if t.common.suite == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 {
                assert_eq!(t.aead_alg.key_len(), 32);
                return t.aead_alg;
            }
        }
    }
    panic!("the ChaCha20-Poly1305 TLS 1.3 suite is missing");
}

/// The TLS 1.2 ChaCha20-Poly1305 algorithm.
fn tls12_chacha() -> &'static dyn Tls12AeadAlgorithm {
    for suite in ic_rustls::suites::ALL {
        if let rustls::SupportedCipherSuite::Tls12(t) = suite {
            if t.common.suite == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            {
                assert_eq!(t.aead_alg.key_block_shape().enc_key_len, 32);
                return t.aead_alg;
            }
        }
    }
    panic!("the ChaCha20-Poly1305 TLS 1.2 suite is missing");
}

/// The two TLS 1.3 algorithms, so every framing test below covers both.
fn tls13_algorithms() -> [(&'static str, &'static dyn Tls13AeadAlgorithm); 2] {
    [
        ("aes-256-gcm", tls13_aes256()),
        ("chacha20-poly1305", tls13_chacha()),
    ]
}

/// The two TLS 1.2 algorithms. These are *not* framed alike -- ChaCha20 sends
/// no explicit nonce -- so running the same tests over both is the point.
fn tls12_algorithms() -> [(&'static str, &'static dyn Tls12AeadAlgorithm); 2] {
    [
        ("aes-256-gcm", tls12_aes256()),
        ("chacha20-poly1305", tls12_chacha()),
    ]
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

    for (name, alg) in tls13_algorithms() {
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

    assert!(checked >= 24, "only {checked} records exercised");
}

#[test]
fn a_tls13_record_is_bound_to_its_sequence_number() {
    for (name, alg) in tls13_algorithms() {
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
    for (name, alg) in tls13_algorithms() {
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

    for (name, alg) in tls12_algorithms() {
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

    assert!(checked >= 12, "only {checked} records exercised");
}

/// The explicit nonce on the wire must be the fixed IV's partner xored with the
/// sequence number.
///
/// Everything else in this file encrypts with this crate and decrypts with this
/// crate, which establishes self-consistency and nothing about interoperability.
/// This pins the actual bytes a peer would read.
///
/// RFC 5288 leaves the construction of the 8-byte explicit part open -- the
/// receiver uses whatever was sent -- so there is no specification to check
/// against and a change here would otherwise be invisible. The construction
/// matches rustls's own provider, which builds `write_iv || explicit` and xors
/// the sequence number into the last eight bytes; this records that as bytes so
/// it outlives anyone remembering to compare.
#[test]
fn the_tls12_explicit_nonce_is_the_key_block_value_xored_with_the_sequence() {
    let alg = tls12_aes256();
    let shape = alg.key_block_shape();
    assert_eq!(shape.fixed_iv_len, 4);
    assert_eq!(shape.explicit_nonce_len, 8);

    let iv = vec![0x5cu8; shape.fixed_iv_len];
    let extra = vec![0x11u8; shape.explicit_nonce_len];
    let mut enc = alg.encrypter(key(), &iv, &extra);

    for (seq, want) in [
        // 0x1111111111111111 xor the sequence number, big-endian.
        (0u64, "1111111111111111"),
        (1, "1111111111111110"),
        (3, "1111111111111112"),
        (0xff, "11111111111111ee"),
        (0x0102030405060708, "1013121514171619"),
    ] {
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: b"x"[..].into(),
                },
                seq,
            )
            .unwrap();

        let on_the_wire = &bytes_of(&sealed)[..8];
        let got: String = on_the_wire.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want, "explicit nonce at sequence {seq}");
    }
}

/// TLS 1.2 with ChaCha20-Poly1305 must put nothing on the wire but ciphertext
/// and tag.
///
/// RFC 7905 section 2 gives it the TLS 1.3 nonce construction: the whole
/// 12-byte nonce comes from the key block and is xored with the sequence
/// number, so there is no explicit part to send. Framing it like the AES-GCM
/// suites -- eight bytes of nonce in front -- produces records that round-trip
/// against this crate perfectly and that no other implementation can read,
/// which is precisely the failure every other test in this file would miss.
///
/// So this checks the length against the plaintext rather than against the
/// encrypter's own promise, and checks the two suites differ by exactly the
/// eight bytes that distinguish them.
#[test]
fn a_tls12_chacha_record_carries_no_explicit_nonce() {
    let chacha = tls12_chacha();
    let shape = chacha.key_block_shape();
    assert_eq!(shape.explicit_nonce_len, 0, "RFC 7905: nothing is explicit");
    assert_eq!(
        shape.fixed_iv_len, 12,
        "RFC 7905: the whole nonce is implicit"
    );

    let iv = vec![0x5cu8; shape.fixed_iv_len];
    let mut enc = chacha.encrypter(key(), &iv, &[]);

    let gcm = tls12_aes256();
    let gcm_shape = gcm.key_block_shape();
    let mut gcm_enc = gcm.encrypter(
        key(),
        &vec![0x5cu8; gcm_shape.fixed_iv_len],
        &vec![0x11u8; gcm_shape.explicit_nonce_len],
    );

    let mut checked = 0;
    for payload in [&b""[..], &b"hello"[..], &[0x7eu8; 700][..]] {
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: payload.into(),
                },
                5,
            )
            .unwrap();

        // The plaintext, the tag, and not one byte more.
        assert_eq!(
            bytes_of(&sealed).len(),
            payload.len() + 16,
            "a {}-byte payload produced a record of {} bytes; anything longer \
             means something was prepended",
            payload.len(),
            bytes_of(&sealed).len()
        );

        // And the AES-GCM suite, framed the other way, is longer by exactly the
        // explicit nonce -- so the comparison above is measuring the difference
        // that matters and not some constant both share.
        let gcm_sealed = gcm_enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: payload.into(),
                },
                5,
            )
            .unwrap();
        assert_eq!(
            bytes_of(&gcm_sealed).len() - bytes_of(&sealed).len(),
            8,
            "the two TLS 1.2 framings should differ by the explicit nonce alone"
        );
        checked += 1;
    }
    assert_eq!(checked, 3);

    // The implicit IV must actually reach the nonce: a receiver holding a
    // different key block cannot read the record. Without this the test above
    // would pass just as well on an encrypter that ignored `iv` entirely.
    let mut wrong = chacha.decrypter(key(), &vec![0x5du8; shape.fixed_iv_len]);
    let sealed = enc
        .encrypt(
            OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: b"attack at dawn"[..].into(),
            },
            5,
        )
        .unwrap();
    let mut buf = bytes_of(&sealed);
    assert!(
        wrong
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut buf,
                ),
                5,
            )
            .is_err(),
        "a record decrypted under a different implicit IV, so the IV is unused"
    );

    let mut right = chacha.decrypter(key(), &iv);
    let mut buf = bytes_of(&sealed);
    assert!(
        right
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut buf,
                ),
                5,
            )
            .is_ok(),
        "the matching IV should read it, or the check above proves nothing"
    );
}

#[test]
fn a_tls12_record_is_bound_to_its_header() {
    for (name, alg) in tls12_algorithms() {
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
