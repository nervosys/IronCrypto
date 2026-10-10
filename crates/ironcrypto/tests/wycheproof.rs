//! RSA verification, ECDH, KMAC and PBKDF2 against Project Wycheproof.
//!
//! `scripts/gen_wycheproof_vectors.py` converts the files and says which.
//! Wycheproof is not a standard: it is a collection of cases built to catch
//! implementation mistakes, each marked `valid`, `invalid` or `acceptable`.
//! It is here for what NIST's sample vectors do not reach in this library --
//! RSA-PSS, PBKDF2, KMAC256, ECDH on P-384 and P-521 -- and for the forged
//! and malformed inputs no known-answer vector contains.
//!
//! The rule for each case:
//!
//! - `valid`: accepted, and where there is an output, the output matches.
//! - `invalid`: refused.
//! - `acceptable`: either, and counted, so that what this library does with
//!   them is on the record.
//!
//! Where this library refuses an input on a rule of its own -- PBKDF2 below
//! 1000 iterations or with a salt under 16 bytes -- the case is checked
//! against that rule instead, and counted separately.

use std::collections::BTreeMap;

use ic_core::traits::KeyAgreement;
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::ec::p256::EcdhP256;
use ironcrypto::ec::p384::EcdhP384;
use ironcrypto::ec::p521::EcdhP521;
use ironcrypto::mac::{HmacSha256, HmacSha512, Kmac128, Kmac256};
use ironcrypto::rsa::{
    Pkcs1Sha256, Pkcs1Sha384, Pkcs1Sha512, PssSha256, PssSha384, PssSha512, RsaPrivateKey,
    RsaPublicKey,
};

/// Count one outcome, and fail on one the verdict does not allow.
fn judge(
    tally: &mut BTreeMap<String, usize>,
    label: &str,
    result: &str,
    accepted: bool,
    what: &str,
) {
    match result {
        "valid" => assert!(accepted, "{label}: valid and refused: {what}"),
        "invalid" => assert!(!accepted, "{label}: invalid and accepted: {what}"),
        "acceptable" => {}
        other => panic!("unknown verdict {other}"),
    }
    let outcome = if accepted { "accepted" } else { "refused" };
    *tally
        .entry(format!("{label} {result} {outcome}"))
        .or_insert(0) += 1;
}

/// Big-endian hex, as an integer of at most eight bytes.
fn small_integer(bytes: &[u8]) -> u64 {
    let significant: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    assert!(significant.len() <= 8, "exponent too wide");
    significant.iter().fold(0, |acc, b| (acc << 8) | *b as u64)
}

#[test]
fn rsa_verification_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-rsa") else {
        return;
    };
    let mut keys = BTreeMap::new();
    let mut tally = BTreeMap::new();
    for case in &file.cases {
        if case["kind"] == "key" {
            let n = hex_field(case, "n");
            // The modulus may carry a sign byte, which is not part of it.
            let n: Vec<u8> = n.iter().copied().skip_while(|b| *b == 0).collect();
            let key = RsaPublicKey::from_components(&n, small_integer(&hex_field(case, "e")))
                .unwrap_or_else(|e| panic!("{}: key refused: {e:?}", case["key"]));
            keys.insert(case["key"].clone(), key);
            continue;
        }
        let key = &keys[&case["key"]];
        let (message, signature) = (hex_field(case, "message"), hex_field(case, "signature"));
        let result = match (case["scheme"].as_str(), case["hash"].as_str()) {
            ("pss", "sha256") => PssSha256::verify(key, &message, &signature),
            ("pss", "sha384") => PssSha384::verify(key, &message, &signature),
            ("pss", "sha512") => PssSha512::verify(key, &message, &signature),
            ("pkcs1", "sha256") => Pkcs1Sha256::verify(key, &message, &signature),
            ("pkcs1", "sha384") => Pkcs1Sha384::verify(key, &message, &signature),
            ("pkcs1", "sha512") => Pkcs1Sha512::verify(key, &message, &signature),
            other => panic!("no such scheme here: {other:?}"),
        };
        // A refusal is a failed signature and nothing else: a malformed one
        // must not surface as a different kind of error.
        if let Err(e) = &result {
            assert_eq!(
                e.kind(),
                ErrorKind::AuthenticationFailed,
                "{} {}: {}",
                case["scheme"],
                case["hash"],
                case["comment"]
            );
        }
        judge(
            &mut tally,
            &format!("{} {}", case["scheme"], case["hash"]),
            &case["result"],
            result.is_ok(),
            &format!("{} [{}]", case["comment"], case["flags"]),
        );
    }
    println!("{tally:#?}");
    // One key a group: some files have more than one group.
    assert_eq!(keys.len(), 15);
    let total = |needle: &str| -> usize {
        tally
            .iter()
            .filter(|(k, _)| k.contains(needle))
            .map(|(_, n)| *n)
            .sum()
    };
    // Every PSS file and every PKCS#1 v1.5 file ran, valid and invalid.
    assert_eq!(total("pss "), 785);
    assert_eq!(total("pkcs1 "), 1293);
    assert!(total("pss sha512 valid accepted") > 100);
    assert!(total("pss sha256 invalid refused") > 100);
    assert!(total("pkcs1 sha384 invalid refused") > 200);
}

/// PKCS#1 v1.5 signing is deterministic, so a private key and a message have
/// one signature, and Wycheproof publishes it.
///
/// They reach the private-key operation without the CRT, since Wycheproof
/// gives exponents and no primes; the CRT path is held to this one by the
/// library's own tests, and by OpenSSL's signatures in `signer.rs`. PSS
/// signing is randomized and has no case here; `cavp_rsa_pss.rs` has the
/// ones NIST published with their salts.
#[test]
fn rsa_pkcs1_signing_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-rsa-sign") else {
        return;
    };
    let strip = |bytes: Vec<u8>| -> Vec<u8> { bytes.into_iter().skip_while(|b| *b == 0).collect() };
    let mut keys = BTreeMap::new();
    let mut tally = BTreeMap::new();
    for case in &file.cases {
        if case["kind"] == "key" {
            // A key this library will not load -- an exponent of 3 is not
            // refused, but a modulus it cannot hold would be -- is recorded
            // and its cases counted as such.
            let key = RsaPrivateKey::from_components(
                &strip(hex_field(case, "n")),
                small_integer(&hex_field(case, "e")),
                &strip(hex_field(case, "d")),
            );
            keys.insert(
                case["key"].clone(),
                (key, small_integer(&hex_field(case, "e"))),
            );
            continue;
        }
        let (key, exponent) = &keys[&case["key"]];
        let label = format!("{} e={exponent} {}", case["hash"], case["result"]);
        let key = match key {
            Ok(key) => key,
            Err(e) => {
                assert_ne!(
                    case["result"], "valid",
                    "a key for a valid case was refused: {e:?}"
                );
                *tally
                    .entry(format!("{label}: key refused"))
                    .or_insert(0usize) += 1;
                continue;
            }
        };
        let (message, expected) = (hex_field(case, "message"), hex_field(case, "signature"));
        let mut signature = vec![0u8; key.size()];
        match case["hash"].as_str() {
            "sha256" => Pkcs1Sha256::sign(key, &message, &mut signature),
            "sha384" => Pkcs1Sha384::sign(key, &message, &mut signature),
            "sha512" => Pkcs1Sha512::sign(key, &message, &mut signature),
            other => panic!("no such hash here: {other}"),
        }
        .unwrap_or_else(|e| panic!("{label}: {} : {e:?}", case["comment"]));
        // The signature is the modulus's length, with leading zeros kept.
        assert_eq!(
            hex(&signature),
            case["signature"],
            "{label}: {}",
            case["comment"]
        );
        assert_eq!(expected.len(), key.size());
        // And what was signed verifies, under the public half.
        let verified = match case["hash"].as_str() {
            "sha256" => Pkcs1Sha256::verify(key.public_key(), &message, &signature),
            "sha384" => Pkcs1Sha384::verify(key.public_key(), &message, &signature),
            _ => Pkcs1Sha512::verify(key.public_key(), &message, &signature),
        };
        verified.unwrap();
        *tally.entry(format!("{label}: matched")).or_insert(0usize) += 1;
    }
    println!("{tally:#?}");
    let matched: usize = tally
        .iter()
        .filter(|(k, _)| k.ends_with("matched"))
        .map(|(_, n)| *n)
        .sum();
    // Eight messages for each hash at each of three sizes are marked valid.
    assert!(matched >= 72, "{tally:?}");
}

#[test]
fn ecdh_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-ecdh") else {
        return;
    };
    let mut tally = BTreeMap::new();
    for case in &file.cases {
        let (public, private, shared) = (
            hex_field(case, "public"),
            hex_field(case, "private"),
            hex_field(case, "shared"),
        );
        let size = match case["curve"].as_str() {
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            other => panic!("no such curve here: {other}"),
        };
        // The private key is an integer: strip a sign byte, pad a short one.
        let significant: Vec<u8> = private.iter().copied().skip_while(|b| *b == 0).collect();
        assert!(significant.len() <= size, "private key too wide");
        let mut d = vec![0u8; size - significant.len()];
        d.extend_from_slice(&significant);

        let mut out = vec![0u8; size];
        let result = match size {
            32 => EcdhP256::agree(&d, &public, &mut out),
            48 => EcdhP384::agree(&d, &public, &mut out),
            _ => EcdhP521::agree(&d, &public, &mut out),
        };
        let what = format!("{} [{}]", case["comment"], case["flags"]);
        if result.is_ok() && case["result"] != "invalid" {
            assert_eq!(hex(&out), case["shared"], "{}: {what}", case["curve"]);
            assert_eq!(shared.len(), size);
        }
        judge(
            &mut tally,
            &case["curve"],
            &case["result"],
            result.is_ok(),
            &what,
        );
    }
    println!("{tally:#?}");
    for (curve, valid, invalid) in [("P-256", 330, 24), ("P-384", 771, 18), ("P-521", 632, 28)] {
        assert_eq!(tally[&format!("{curve} valid accepted")], valid);
        assert_eq!(tally[&format!("{curve} invalid refused")], invalid);
    }
}

#[test]
fn kmac_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-kmac") else {
        return;
    };
    let mut tally = BTreeMap::new();
    for case in &file.cases {
        let (key, message, tag) = (
            hex_field(case, "key"),
            hex_field(case, "message"),
            hex_field(case, "tag"),
        );
        let mut made = vec![0u8; tag.len()];
        let verified = match case["function"].as_str() {
            "kmac128" => {
                Kmac128::mac(&key, b"", &message, &mut made);
                Kmac128::verify(&key, b"", &message, &tag)
            }
            "kmac256" => {
                Kmac256::mac(&key, b"", &message, &mut made);
                Kmac256::verify(&key, b"", &message, &tag)
            }
            other => panic!("no such function here: {other}"),
        };
        // Computing and verifying agree with each other, and with the verdict.
        assert_eq!(made == tag, verified.is_ok(), "{}", case["comment"]);
        judge(
            &mut tally,
            &case["function"],
            &case["result"],
            verified.is_ok(),
            &format!("{} [{}]", case["comment"], case["flags"]),
        );
    }
    println!("{tally:#?}");
    assert_eq!(tally["kmac128 valid accepted"], 66);
    assert_eq!(tally["kmac128 invalid refused"], 108);
    assert_eq!(tally["kmac256 valid accepted"], 99);
    assert_eq!(tally["kmac256 invalid refused"], 162);
}

#[test]
fn pbkdf2_matches_wycheproof() {
    let Some(file) = VectorFile::load_or_report("wycheproof-pbkdf2") else {
        return;
    };
    let mut tally = BTreeMap::new();
    for case in &file.cases {
        let (password, salt, derived) = (
            hex_field(case, "password"),
            hex_field(case, "salt"),
            hex_field(case, "derived"),
        );
        let iterations: u32 = case["iterations"].parse().expect("iterations");
        let mut out = vec![0u8; derived.len()];
        let result = match case["prf"].as_str() {
            "hmac-sha2-256" => {
                ironcrypto::kdf::pbkdf2::<HmacSha256>(&password, &salt, iterations, &mut out)
            }
            "hmac-sha2-512" => {
                ironcrypto::kdf::pbkdf2::<HmacSha512>(&password, &salt, iterations, &mut out)
            }
            other => panic!("no such prf here: {other}"),
        };
        assert_eq!(case["result"], "valid");
        // This library refuses what SP 800-132 says is too weak to use, so
        // those cases test the refusal and not the value.
        let too_weak = iterations < 1000 || salt.len() < 16;
        let outcome = if too_weak {
            assert_eq!(
                result.unwrap_err().kind(),
                ErrorKind::InvalidParameter,
                "{}: {} iterations, {}-byte salt",
                case["comment"],
                iterations,
                salt.len()
            );
            "refused by rule"
        } else {
            result.unwrap_or_else(|e| panic!("{}: {e:?}", case["comment"]));
            assert_eq!(hex(&out), case["derived"], "{}", case["comment"]);
            "matched"
        };
        *tally
            .entry(format!("{} {outcome}", case["prf"]))
            .or_insert(0usize) += 1;
    }
    println!("{tally:#?}");
    // How many cases reach the arithmetic is the thing to know about this
    // file; it is asserted so that it cannot quietly become none.
    assert!(
        tally.get("hmac-sha2-256 matched").copied().unwrap_or(0) > 0,
        "{tally:?}"
    );
    assert!(
        tally.get("hmac-sha2-512 matched").copied().unwrap_or(0) > 0,
        "{tally:?}"
    );
}
