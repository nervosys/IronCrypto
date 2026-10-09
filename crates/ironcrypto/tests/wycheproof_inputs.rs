//! Signatures, key agreement, AEADs, MACs, HKDF and key wrap against Project
//! Wycheproof.
//!
//! The algorithms here already have published known answers. What Wycheproof
//! adds is the other half: inputs made wrong on purpose, which a known-answer
//! vector never contains. A DER signature with its length written the long
//! way, a tag with one bit changed, a point of low order, a wrapped key of
//! the wrong size. `scripts/gen_wycheproof_vectors.py` says which files.
//!
//! The rule for each case is the one in `wycheproof.rs`: `valid` is accepted
//! and matches, `invalid` is refused, `acceptable` may go either way and is
//! counted. Where this library takes fewer shapes of input than the test
//! file offers -- a tag that is not sixteen bytes, a ChaCha20-Poly1305 nonce
//! that is not twelve -- the case must be refused whatever its verdict, and
//! is counted as refused by that rule.

use std::collections::BTreeMap;

use ic_core::sig::SignatureAlgorithm;
use ic_core::traits::{Aead, Kdf, KeyAgreement, Mac, SignatureScheme};
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::cipher::{
    Aes128Gcm, Aes128GcmSiv, Aes128Kw, Aes128Kwp, Aes192Gcm, Aes192Kw, Aes192Kwp, Aes256Gcm,
    Aes256GcmSiv, Aes256Kw, Aes256Kwp, ChaCha20Poly1305,
};
use ironcrypto::kdf::Hkdf;
use ironcrypto::mac::{CmacAes128, CmacAes192, CmacAes256, HmacSha256, HmacSha384, HmacSha512};
use ironcrypto::sig::{verify, PublicKey};

type Case = BTreeMap<String, String>;
type Tally = BTreeMap<String, usize>;

fn what(case: &Case) -> String {
    format!("{} [{}]", case["comment"], case["flags"])
}

/// Count one outcome, and fail on one the verdict does not allow.
fn judge(tally: &mut Tally, label: &str, case: &Case, accepted: bool) {
    match case["result"].as_str() {
        "valid" => assert!(accepted, "{label}: valid and refused: {}", what(case)),
        "invalid" => assert!(!accepted, "{label}: invalid and accepted: {}", what(case)),
        "acceptable" => {}
        other => panic!("unknown verdict {other}"),
    }
    let outcome = if accepted { "accepted" } else { "refused" };
    *tally
        .entry(format!("{label} {} {outcome}", case["result"]))
        .or_insert(0) += 1;
}

fn count(tally: &mut Tally, key: String) {
    *tally.entry(key).or_insert(0) += 1;
}

#[test]
fn ecdsa_der_verification_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-ecdsa") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let algorithm = SignatureAlgorithm::from_id(&case["algorithm"]).expect("an algorithm here");
        let (spki, message, signature) = (
            hex_field(case, "spki"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let key = PublicKey::from_spki(&spki).expect("every key in this file is sound");
        let result = verify(algorithm, &key, &message, &signature);
        // However a signature is wrong, it is one failure.
        if let Err(e) = &result {
            assert_eq!(e.kind(), ErrorKind::AuthenticationFailed, "{}", what(case));
        }
        judge(&mut tally, &case["algorithm"], case, result.is_ok());
    }
    println!("{tally:#?}");
    for (algorithm, valid) in [
        ("ecdsa-p256-sha256", 174),
        ("ecdsa-p384-sha384", 194),
        ("ecdsa-p521-sha512", 232),
    ] {
        assert_eq!(tally[&format!("{algorithm} valid accepted")], valid);
        assert_eq!(tally[&format!("{algorithm} invalid refused")], 310);
    }
}

#[test]
fn ed25519_verification_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-eddsa") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let (public_key, message, signature) = (
            hex_field(case, "public_key"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let result = ironcrypto::ec::Ed25519::verify(&public_key, &message, &signature);
        judge(&mut tally, "ed25519", case, result.is_ok());
    }
    println!("{tally:#?}");
    assert_eq!(tally["ed25519 valid accepted"], 88);
    assert_eq!(tally["ed25519 invalid refused"], 63);
}

#[test]
fn x25519_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-x25519") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let (public, private) = (hex_field(case, "public"), hex_field(case, "private"));
        let mut out = [0u8; 32];
        let result = ironcrypto::ec::X25519::agree(&private, &public, &mut out);
        // Whatever is accepted gives the shared secret Wycheproof gives.
        if result.is_ok() {
            assert_eq!(hex(&out), case["shared"], "{}", what(case));
        }
        judge(&mut tally, "x25519", case, result.is_ok());
        // What the acceptable cases are, and what becomes of each kind.
        if case["result"] == "acceptable" {
            let outcome = if result.is_ok() {
                "accepted"
            } else {
                "refused"
            };
            count(
                &mut tally,
                format!("  acceptable [{}] {outcome}", case["flags"]),
            );
        }
    }
    println!("{tally:#?}");
    assert_eq!(tally["x25519 valid accepted"], 264);
}

#[test]
fn the_aeads_match_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-aead") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let (key, nonce, aad, plaintext, ciphertext, tag) = (
            hex_field(case, "key"),
            hex_field(case, "nonce"),
            hex_field(case, "aad"),
            hex_field(case, "plaintext"),
            hex_field(case, "ciphertext"),
            hex_field(case, "tag"),
        );
        let cipher = case["cipher"].as_str();
        // Seal the plaintext and open the ciphertext, with whichever type
        // the cipher and key length name.
        macro_rules! run {
            ($ty:ty) => {{
                let aead = <$ty>::new(&key).expect("a key of this cipher's length");
                let mut sealed = plaintext.clone();
                let mut made_tag = [0u8; 16];
                let seal = aead.seal_detached(&nonce, &aad, &mut sealed, &mut made_tag);
                let mut opened = ciphertext.clone();
                let open = aead.open_detached(&nonce, &aad, &mut opened, &tag);
                (seal.map(|()| (sealed, made_tag)), open.map(|()| opened))
            }};
        }
        let (seal, open) = match (cipher, key.len()) {
            ("aes-gcm", 16) => run!(Aes128Gcm),
            ("aes-gcm", 24) => run!(Aes192Gcm),
            ("aes-gcm", 32) => run!(Aes256Gcm),
            ("chacha20-poly1305", 32) => run!(ChaCha20Poly1305),
            ("aes-gcm-siv", 16) => run!(Aes128GcmSiv),
            ("aes-gcm-siv", 32) => run!(Aes256GcmSiv),
            // A key length this library has no type for.
            (_, bits) => {
                count(
                    &mut tally,
                    format!("{cipher} {}-bit key: no such type", bits * 8),
                );
                continue;
            }
        };
        // The tag is sixteen bytes and nothing else. ChaCha20-Poly1305 and
        // AES-GCM-SIV take a twelve-byte nonce and nothing else; AES-GCM
        // takes any that is not empty, as SP 800-38D allows, so its cases
        // with other nonce lengths are judged like the rest. A shape that
        // is not taken is refused in both directions, whatever its verdict.
        let nonce_taken = if cipher == "aes-gcm" {
            !nonce.is_empty()
        } else {
            nonce.len() == 12
        };
        if !nonce_taken || tag.len() != 16 {
            assert!(open.is_err(), "{cipher}: {}", what(case));
            assert!(seal.is_err() || tag.len() != 16, "{cipher}: {}", what(case));
            count(
                &mut tally,
                format!(
                    "{cipher} refused by rule: {}-byte nonce, {}-byte tag",
                    nonce.len(),
                    tag.len()
                ),
            );
            continue;
        }
        if case["result"] == "valid" {
            let (sealed, made_tag) = seal.expect("sealing a valid case");
            assert_eq!(hex(&sealed), case["ciphertext"], "{cipher}: {}", what(case));
            assert_eq!(hex(&made_tag), case["tag"], "{cipher}: {}", what(case));
        }
        if let Ok(opened) = &open {
            assert_eq!(hex(opened), case["plaintext"], "{cipher}: {}", what(case));
        } else if let Err(e) = &open {
            assert_eq!(e.kind(), ErrorKind::AuthenticationFailed, "{}", what(case));
        }
        judge(&mut tally, cipher, case, open.is_ok());
    }
    println!("{tally:#?}");
    for cipher in ["aes-gcm", "chacha20-poly1305", "aes-gcm-siv"] {
        assert!(tally[&format!("{cipher} valid accepted")] > 50, "{cipher}");
        assert!(tally[&format!("{cipher} invalid refused")] > 20, "{cipher}");
    }
}

#[test]
fn the_macs_match_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-mac") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let (key, message, tag) = (
            hex_field(case, "key"),
            hex_field(case, "message"),
            hex_field(case, "tag"),
        );
        let name = case["mac"].as_str();
        // The full tag, or the reason there is none.
        let full: Result<Vec<u8>, ErrorKind> = match (name, key.len()) {
            ("hmac-sha2-256", _) => HmacSha256::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            ("hmac-sha2-384", _) => HmacSha384::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            ("hmac-sha2-512", _) => HmacSha512::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            ("aes-cmac", 16) => CmacAes128::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            ("aes-cmac", 24) => CmacAes192::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            ("aes-cmac", 32) => CmacAes256::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            // Not an AES key: every type refuses it.
            ("aes-cmac", _) => CmacAes128::mac(&key, &message).map(|t| t.as_ref().to_vec()),
            other => panic!("no such mac here: {other:?}"),
        }
        .map_err(|e| e.kind());
        // A tag may be a truncation; it is right if it is the front of the
        // full one.
        let accepted = match &full {
            Ok(full) => tag.len() <= full.len() && full[..tag.len()] == tag[..],
            Err(_) => false,
        };
        judge(&mut tally, name, case, accepted);
        if let Err(kind) = full {
            count(&mut tally, format!("  {name} refused the key: {kind:?}"));
        }
    }
    println!("{tally:#?}");
    for name in ["hmac-sha2-256", "hmac-sha2-384", "hmac-sha2-512"] {
        assert_eq!(tally[&format!("{name} valid accepted")], 66);
        assert_eq!(tally[&format!("{name} invalid refused")], 108);
    }
    assert_eq!(tally["aes-cmac valid accepted"], 63);
    assert_eq!(tally["aes-cmac invalid refused"], 248);
}

#[test]
fn hkdf_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-hkdf") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let (ikm, salt, info) = (
            hex_field(case, "ikm"),
            hex_field(case, "salt"),
            hex_field(case, "info"),
        );
        let size: usize = case["size"].parse().expect("size");
        let mut out = vec![0u8; size];
        let result = match case["hash"].as_str() {
            "sha2-256" => Hkdf::<HmacSha256>::derive(&ikm, &salt, &info, &mut out),
            "sha2-384" => Hkdf::<HmacSha384>::derive(&ikm, &salt, &info, &mut out),
            "sha2-512" => Hkdf::<HmacSha512>::derive(&ikm, &salt, &info, &mut out),
            other => panic!("no such hash here: {other}"),
        };
        if result.is_ok() {
            assert_eq!(hex(&out), case["okm"], "{}", what(case));
        }
        judge(&mut tally, &case["hash"], case, result.is_ok());
    }
    println!("{tally:#?}");
    for (hash, valid) in [("sha2-256", 83), ("sha2-384", 80), ("sha2-512", 80)] {
        assert_eq!(tally[&format!("{hash} valid accepted")], valid);
        assert_eq!(tally[&format!("{hash} invalid refused")], 3);
    }
}

#[test]
fn key_wrap_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-keywrap") else {
        return;
    };
    let mut tally = Tally::new();
    for case in &file.cases {
        let (key, plaintext, ciphertext) = (
            hex_field(case, "key"),
            hex_field(case, "plaintext"),
            hex_field(case, "ciphertext"),
        );
        let mode = case["mode"].as_str();
        // Wrap the plaintext and unwrap the ciphertext. `None` where there
        // is no type for the key length.
        macro_rules! kw {
            ($ty:ty) => {{
                let mut wrapped = vec![0u8; plaintext.len() + 8];
                let wrap = <$ty>::wrap(&key, &plaintext, &mut wrapped).map(|()| wrapped);
                let mut unwrapped = vec![0u8; ciphertext.len().saturating_sub(8)];
                let unwrap = <$ty>::unwrap(&key, &ciphertext, &mut unwrapped).map(|()| unwrapped);
                Some((wrap.ok(), unwrap.ok()))
            }};
        }
        macro_rules! kwp {
            ($ty:ty) => {{
                let mut wrapped = vec![0u8; <$ty>::wrapped_len(plaintext.len())];
                let wrap = <$ty>::wrap(&key, &plaintext, &mut wrapped).map(|()| wrapped);
                let mut unwrapped = vec![0u8; ciphertext.len()];
                let unwrap = <$ty>::unwrap(&key, &ciphertext, &mut unwrapped).map(|n| {
                    unwrapped.truncate(n);
                    unwrapped
                });
                Some((wrap.ok(), unwrap.ok()))
            }};
        }
        let ran = match (mode, key.len()) {
            ("kw", 16) => kw!(Aes128Kw),
            ("kw", 24) => kw!(Aes192Kw),
            ("kw", 32) => kw!(Aes256Kw),
            ("kwp", 16) => kwp!(Aes128Kwp),
            ("kwp", 24) => kwp!(Aes192Kwp),
            ("kwp", 32) => kwp!(Aes256Kwp),
            _ => None,
        };
        let Some((wrap, unwrap)) = ran else {
            assert_ne!(
                case["result"],
                "valid",
                "no type for a valid case: {}",
                what(case)
            );
            count(
                &mut tally,
                format!("{mode} {}-bit key: no such type", key.len() * 8),
            );
            continue;
        };
        if case["result"] == "valid" {
            assert_eq!(
                wrap.as_deref().map(hex),
                Some(case["ciphertext"].clone()),
                "{mode}: {}",
                what(case)
            );
        }
        if let Some(unwrapped) = &unwrap {
            assert_eq!(hex(unwrapped), case["plaintext"], "{mode}: {}", what(case));
        }
        judge(&mut tally, mode, case, unwrap.is_some());
    }
    println!("{tally:#?}");
    assert_eq!(tally["kw valid accepted"], 36);
    assert_eq!(tally["kwp valid accepted"], 77);
    assert!(tally["kw invalid refused"] > 100);
    assert!(tally["kwp invalid refused"] > 100);
}
