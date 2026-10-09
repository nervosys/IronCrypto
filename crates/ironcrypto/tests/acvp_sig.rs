//! ECDSA, RSA PKCS#1 v1.5 verification and cSHAKE against NIST's ACVP vectors.
//!
//! `scripts/gen_acvp_sig_vectors.py` converts NIST's files and says what is
//! kept and what is dropped. In short: ECDSA over the three curves here under
//! every hash wide enough for the curve, signing and verification; RSA
//! PKCS#1 v1.5 verification with SHA-256 at three modulus sizes; and the few
//! cSHAKE cases that are whole bytes. Nothing here covers RSA-PSS.
//!
//! For ECDSA these are the first published values P-521 has been held to, and
//! the first time any curve's signer has been held to NIST's deterministic
//! ECDSA rather than to RFC 6979's own examples.

use ic_core::traits::{Digest, SignatureScheme};
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::ec::p256::EcdsaP256Sha256;
use ironcrypto::ec::p384::EcdsaP384Sha384;
use ironcrypto::ec::p521::EcdsaP521Sha512;
use ironcrypto::hash;
use ironcrypto::rsa::{Pkcs1Sha256, RsaPublicKey};

fn digest(name: &str, message: &[u8]) -> Vec<u8> {
    match name {
        "SHA2-256" => hash::Sha256::digest(message).as_ref().to_vec(),
        "SHA2-384" => hash::Sha384::digest(message).as_ref().to_vec(),
        "SHA2-512" => hash::Sha512::digest(message).as_ref().to_vec(),
        "SHA2-512/256" => hash::Sha512_256::digest(message).as_ref().to_vec(),
        "SHA3-256" => hash::Sha3_256::digest(message).as_ref().to_vec(),
        "SHA3-384" => hash::Sha3_384::digest(message).as_ref().to_vec(),
        "SHA3-512" => hash::Sha3_512::digest(message).as_ref().to_vec(),
        other => panic!("no such hash here: {other}"),
    }
}

#[test]
fn ecdsa_matches_every_acvp_case() {
    let Some(file) = VectorFile::load_or_report("acvp-ecdsa") else {
        return;
    };
    let mut ran = std::collections::BTreeMap::new();
    for case in &file.cases {
        let (public_key, message, signature) = (
            hex_field(case, "public_key"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let (curve, hash_name) = (case["curve"].as_str(), case["hash"].as_str());
        let native = case["native"] == "true";
        let label = format!("{} {curve} {hash_name} ({})", case["kind"], case["reason"]);

        // Signing, where the hash is the scheme's own: the public key from
        // the private one, and the signature NIST's deterministic ECDSA makes.
        if case["kind"] == "sign" && native {
            let d = hex_field(case, "d");
            let mut made = vec![0u8; signature.len()];
            let mut derived = vec![0u8; public_key.len()];
            match curve {
                "P-256" => {
                    EcdsaP256Sha256::public_key(&d, &mut derived).unwrap();
                    EcdsaP256Sha256::sign(&d, &message, &mut made).unwrap();
                }
                "P-384" => {
                    EcdsaP384Sha384::public_key(&d, &mut derived).unwrap();
                    EcdsaP384Sha384::sign(&d, &message, &mut made).unwrap();
                }
                "P-521" => {
                    EcdsaP521Sha512::public_key(&d, &mut derived).unwrap();
                    EcdsaP521Sha512::sign(&d, &message, &mut made).unwrap();
                }
                other => panic!("no such curve here: {other}"),
            }
            assert_eq!(hex(&derived), case["public_key"], "{label}: public key");
            assert_eq!(hex(&made), case["signature"], "{label}: signature");
        }

        // Verification, through the digest interface for every hash and
        // through the scheme's own where the hash is its own.
        let expected = case["valid"] == "true";
        let prehash = digest(hash_name, &message);
        let (by_digest, by_message) = match curve {
            "P-256" => (
                EcdsaP256Sha256::verify_prehash(&public_key, &prehash, &signature),
                EcdsaP256Sha256::verify(&public_key, &message, &signature),
            ),
            "P-384" => (
                EcdsaP384Sha384::verify_prehash(&public_key, &prehash, &signature),
                EcdsaP384Sha384::verify(&public_key, &message, &signature),
            ),
            "P-521" => (
                EcdsaP521Sha512::verify_prehash(&public_key, &prehash, &signature),
                EcdsaP521Sha512::verify(&public_key, &message, &signature),
            ),
            other => panic!("no such curve here: {other}"),
        };
        assert_eq!(by_digest.is_ok(), expected, "{label}: {by_digest:?}");
        if native {
            assert_eq!(by_message.is_ok(), expected, "{label}: {by_message:?}");
        }
        *ran.entry((case["kind"].clone(), curve.to_string(), native, expected))
            .or_insert(0usize) += 1;
    }
    println!("{ran:?}");
    // Each curve signs its own hash's cases and verifies NIST's invalid ones.
    for curve in ["P-256", "P-384", "P-521"] {
        let count = |kind: &str, native, valid| {
            ran.get(&(kind.to_string(), curve.to_string(), native, valid))
                .copied()
                .unwrap_or(0)
        };
        assert_eq!(count("sign", true, true), 11, "{curve} signing");
        assert!(count("sign", false, true) >= 11, "{curve} other hashes");
        assert!(count("verify", true, false) + count("verify", false, false) >= 12);
        assert!(count("verify", true, true) + count("verify", false, true) >= 2);
    }
    assert_eq!(file.cases.len(), 206);
}

/// A zero in a signature is refused, in every position and both at once.
///
/// NIST's cases zero `r` or `s`, one at a time. Both zero is the case that
/// matters most -- `s = 0` has no inverse, the point computed from it is the
/// point at infinity, and a verifier that read that point's x-coordinate as
/// zero would accept `(0, 0)` for every message under every key -- so it is
/// tested here against the rule, on keys and messages NIST says are
/// otherwise valid.
///
/// What this does not show is that the verifier's explicit zero check is
/// what refuses them. It is not, alone: with that check removed every case
/// here is still refused, by the arithmetic after it. The test holds the
/// rule; the check is a second line that nothing can be made to exercise.
#[test]
fn ecdsa_refuses_a_zero_r_or_s_for_every_curve() {
    let Some(file) = VectorFile::load_or_report("acvp-ecdsa") else {
        return;
    };
    let mut curves = std::collections::BTreeSet::new();
    for case in file
        .cases
        .iter()
        .filter(|c| c["kind"] == "verify" && c["valid"] == "true" && c["native"] == "true")
    {
        let (public_key, message, signature) = (
            hex_field(case, "public_key"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let half = signature.len() / 2;
        let prehash = digest(&case["hash"], &message);
        let verify = |sig: &[u8]| match case["curve"].as_str() {
            "P-256" => (
                EcdsaP256Sha256::verify(&public_key, &message, sig).is_ok(),
                EcdsaP256Sha256::verify_prehash(&public_key, &prehash, sig).is_ok(),
            ),
            "P-521" => (
                EcdsaP521Sha512::verify(&public_key, &message, sig).is_ok(),
                EcdsaP521Sha512::verify_prehash(&public_key, &prehash, sig).is_ok(),
            ),
            other => panic!("no native verification case for {other}"),
        };
        assert_eq!(verify(&signature), (true, true), "the base case is valid");
        let mut zero_r = signature.clone();
        zero_r[..half].fill(0);
        let mut zero_s = signature.clone();
        zero_s[half..].fill(0);
        let both = vec![0u8; signature.len()];
        for (what, sig) in [("r", &zero_r), ("s", &zero_s), ("r and s", &both)] {
            assert_eq!(
                verify(sig),
                (false, false),
                "{}: zero {what} accepted",
                case["curve"]
            );
        }
        curves.insert(case["curve"].clone());
    }
    // P-384 has no verification case under its own hash in NIST's sample, so
    // it is run from a signing case, which is as valid.
    let p384 = file
        .cases
        .iter()
        .find(|c| c["kind"] == "sign" && c["curve"] == "P-384" && c["native"] == "true")
        .expect("a P-384 signing case");
    let (public_key, message, signature) = (
        hex_field(p384, "public_key"),
        hex_field(p384, "message"),
        hex_field(p384, "signature"),
    );
    EcdsaP384Sha384::verify(&public_key, &message, &signature).unwrap();
    let mut zero_r = signature.clone();
    zero_r[..48].fill(0);
    let mut zero_s = signature.clone();
    zero_s[48..].fill(0);
    for sig in [zero_r, zero_s, vec![0u8; 96]] {
        assert!(EcdsaP384Sha384::verify(&public_key, &message, &sig).is_err());
    }
    assert_eq!(curves.len(), 2, "{curves:?}");
}

#[test]
fn rsa_pkcs1_verification_matches_every_acvp_case() {
    let Some(file) = VectorFile::load_or_report("acvp-rsa-sigver") else {
        return;
    };
    let mut ran = std::collections::BTreeMap::new();
    for case in &file.cases {
        let (n, e, message, signature) = (
            hex_field(case, "n"),
            hex_field(case, "e"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let exponent = u64::from_be_bytes(e.try_into().expect("eight bytes"));
        let expected = case["valid"] == "true";
        let label = format!("{} bits, {}", case["modulus_bits"], case["reason"]);
        // The modulus and exponent are the group's and are sound; NIST's
        // "key modified" cases change the key the signature was made with,
        // not the one given here.
        let key = RsaPublicKey::from_components(&n, exponent)
            .unwrap_or_else(|err| panic!("{label}: key refused: {err:?}"));
        let result = Pkcs1Sha256::verify(&key, &message, &signature);
        assert_eq!(result.is_ok(), expected, "{label}: {result:?}");
        *ran.entry((case["modulus_bits"].clone(), expected))
            .or_insert(0usize) += 1;
    }
    println!("{ran:?}");
    for bits in ["2048", "3072", "4096"] {
        assert_eq!(ran[&(bits.to_string(), true)], 6, "{bits}");
        assert_eq!(ran[&(bits.to_string(), false)], 30, "{bits}");
    }
}

#[test]
fn cshake_matches_the_byte_aligned_acvp_cases() {
    let Some(file) = VectorFile::load_or_report("acvp-cshake") else {
        return;
    };
    let mut seen = std::collections::BTreeSet::new();
    for case in &file.cases {
        let (message, name, custom) = (
            hex_field(case, "message"),
            hex_field(case, "function_name"),
            hex_field(case, "customization"),
        );
        let mut out = vec![0u8; case["output"].len() / 2];
        match case["algorithm"].as_str() {
            "cshake128" => {
                let mut h = hash::CShake128::new(&name, &custom);
                h.update(&message);
                h.finalize_xof(&mut out);
            }
            "cshake256" => {
                let mut h = hash::CShake256::new(&name, &custom);
                h.update(&message);
                h.finalize_xof(&mut out);
            }
            other => panic!("unknown algorithm {other}"),
        }
        assert_eq!(hex(&out), case["output"], "{}", case["algorithm"]);
        seen.insert(case["algorithm"].clone());
    }
    // Five cases is what NIST's sample has in whole bytes; both functions
    // are among them, each with a function name and a customization.
    assert_eq!(file.cases.len(), 5);
    assert_eq!(seen.len(), 2);
}
