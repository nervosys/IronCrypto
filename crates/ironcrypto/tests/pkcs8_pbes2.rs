//! `ic_pkix::pbes2` against keys OpenSSL encrypted.
//!
//! `testvectors/openssl-pkcs8-pbes2.json`, from
//! `scripts/gen_pkcs8_pbes2_vectors.py`: PKCS#8 keys OpenSSL encrypted under
//! PBES2, each with the plaintext key OpenSSL decrypts it back to. For each
//! case OpenSSL accepts and this library should too:
//!
//! - it decrypts to OpenSSL's plaintext, and parses;
//! - encrypting that plaintext again, with OpenSSL's salt and IV replayed as
//!   the random draws, gives OpenSSL's encoding byte for byte. That checks the
//!   layout this library writes, not only the one it reads;
//! - a wrong passphrase, or a flipped ciphertext bit, is refused.
//!
//! The rest are refused for what they are: an iteration count under the floor
//! (OpenSSL's default of 2048), the default PRF HMAC-SHA-1, and AES-128-CBC.

use ic_core::traits::RandomSource;
use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::pkix::{pbes2, pem, PrivateKeyInfo};
use std::collections::BTreeMap;

/// Replays fixed bytes as the random draws: salt, then IV.
struct Replay(Vec<u8>);

impl RandomSource for Replay {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        assert!(
            out.len() <= self.0.len(),
            "more random bytes drawn than replayed"
        );
        out.copy_from_slice(&self.0[..out.len()]);
        self.0.drain(..out.len());
        Ok(())
    }
}

fn text(case: &BTreeMap<String, String>, field: &str) -> String {
    String::from_utf8(hex_field(case, field)).unwrap()
}

#[test]
fn keys_openssl_encrypted_decrypt_and_reencrypt_to_the_same_bytes() {
    let Some(file) = VectorFile::load_or_report("openssl-pkcs8-pbes2") else {
        return;
    };
    let mut accepted = 0;
    let mut refused = 0;
    for case in &file.cases {
        let name = text(case, "name");
        let expect = text(case, "expect");
        let pw = hex_field(case, "passphrase");
        let encrypted = hex_field(case, "encrypted");
        let plaintext = hex_field(case, "plaintext");
        let mut out = vec![0u8; encrypted.len()];

        let want = match expect.as_str() {
            "accept" => None,
            "refuse-iterations" => Some(ErrorKind::InvalidParameter),
            "refuse-prf" | "refuse-cipher" => Some(ErrorKind::Unsupported),
            other => panic!("{name}: unknown expectation {other}"),
        };
        if let Some(kind) = want {
            let err = pbes2::decrypt(&encrypted, &pw, &mut out).unwrap_err();
            assert_eq!(err.kind(), kind, "{name}");
            assert!(out.iter().all(|b| *b == 0), "{name}: output written");
            refused += 1;
            continue;
        }

        let n = pbes2::decrypt(&encrypted, &pw, &mut out).unwrap();
        assert_eq!(&out[..n], &plaintext[..], "{name}: plaintext");
        let mut buf = vec![0u8; encrypted.len()];
        let key = PrivateKeyInfo::from_encrypted_der(&encrypted, &pw, &mut buf).unwrap();
        assert_eq!(key, PrivateKeyInfo::from_der(&plaintext).unwrap(), "{name}");

        let iterations = u32::from_be_bytes(hex_field(case, "iterations").try_into().unwrap());
        let mut draws = hex_field(case, "salt");
        draws.extend(hex_field(case, "iv"));
        let mut again = vec![0u8; pbes2::encrypted_len(plaintext.len())];
        let m =
            pbes2::encrypt(&plaintext, &pw, iterations, &mut Replay(draws), &mut again).unwrap();
        assert_eq!(
            &again[..m],
            &encrypted[..],
            "{name}: not OpenSSL's encoding"
        );

        let mut wrong = pw.clone();
        wrong.push(b'!');
        let mut buf = vec![0u8; encrypted.len()];
        assert!(
            PrivateKeyInfo::from_encrypted_der(&encrypted, &wrong, &mut buf).is_err(),
            "{name}: wrong passphrase accepted"
        );
        assert!(
            buf.iter().all(|b| *b == 0),
            "{name}: plaintext left after refusal"
        );
        accepted += 1;
    }
    assert_eq!((accepted, refused), (4, 3));
}

#[test]
fn a_flipped_ciphertext_bit_is_refused() {
    let Some(file) = VectorFile::load_or_report("openssl-pkcs8-pbes2") else {
        return;
    };
    let case = &file.cases[0];
    assert_eq!(text(case, "name"), "p256");
    let pw = hex_field(case, "passphrase");
    let mut encrypted = hex_field(case, "encrypted");
    // The last byte of the second-last block: CBC carries the flip into the
    // padding byte of the last.
    let at = encrypted.len() - 17;
    encrypted[at] ^= 1;
    let mut out = vec![0u8; encrypted.len()];
    assert!(PrivateKeyInfo::from_encrypted_der(&encrypted, &pw, &mut out).is_err());
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn an_encrypted_key_round_trips_through_pem() {
    let Some(file) = VectorFile::load_or_report("openssl-pkcs8-pbes2") else {
        return;
    };
    let encrypted = hex_field(&file.cases[0], "encrypted");
    let mut text = vec![0u8; pem::encoded_len(pem::ENCRYPTED_PRIVATE_KEY, encrypted.len())];
    let n = pem::encode(pem::ENCRYPTED_PRIVATE_KEY, &encrypted, &mut text).unwrap();
    assert!(text.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    let mut back = vec![0u8; encrypted.len()];
    let m = pem::decode(pem::ENCRYPTED_PRIVATE_KEY, &text[..n], &mut back).unwrap();
    assert_eq!(&back[..m], &encrypted[..]);
}
