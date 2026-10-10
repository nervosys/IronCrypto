//! RSA-PSS signing against NIST's CAVP examples.
//!
//! A PSS signature is randomized, so a published signature holds a signer to
//! nothing unless the salt is published with it. NIST's `SigGenPSS_186-3.txt`
//! is the one file that does: it gives the private exponent and the salt, and
//! with those the signature is determined. `scripts/gen_cavp_rsa_pss_vectors.py`
//! converts it and says what is left out.
//!
//! The salt reaches the signer the way it does in use, through the
//! `RandomSource` the caller passes, so what is tested is the public `sign`
//! and not an internal with the salt as an argument.
//!
//! NIST mostly chose salts that are not the hash's length. This library makes
//! and accepts one PSS, with a salt as long as the hash, so those cases cannot
//! be signed here. They are kept for the other half of that rule: each is a
//! valid signature of a PSS this library does not have, and the verifier must
//! refuse it.
//!
//! NIST gives no primes, so these reach the private-key operation without the
//! CRT. The CRT path is held to this one by the library's own tests.

use std::collections::BTreeMap;

use ic_core::traits::RandomSource;
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::rsa::{PssSha256, PssSha384, PssSha512, RsaPrivateKey};

/// Hands out one salt, once, and nothing else.
struct GivenSalt {
    salt: Vec<u8>,
    asked: usize,
}

impl RandomSource for GivenSalt {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        // The signer asks for exactly a salt. Anything else would mean the
        // bytes below are not being used as one.
        assert_eq!(out.len(), self.salt.len(), "asked for something not a salt");
        out.copy_from_slice(&self.salt);
        self.asked += 1;
        Ok(())
    }
}

/// Big-endian hex, as an integer of at most eight bytes.
fn small_integer(bytes: &[u8]) -> u64 {
    assert!(bytes.len() <= 8, "exponent too wide");
    bytes.iter().fold(0, |acc, b| (acc << 8) | *b as u64)
}

#[test]
fn rsa_pss_signing_matches_cavp() {
    let Some(file) = VectorFile::load_or_report("cavp-rsa-pss-sign") else {
        return;
    };
    let mut keys = BTreeMap::new();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for case in &file.cases {
        if case["kind"] == "key" {
            let key = RsaPrivateKey::from_components(
                &hex_field(case, "n"),
                small_integer(&hex_field(case, "e")),
                &hex_field(case, "d"),
            )
            .unwrap();
            keys.insert(case["key"].clone(), key);
            continue;
        }
        let key = &keys[&case["key"]];
        let label = format!("{} {} {}", case["key"], case["hash"], case["kind"]);
        let (message, salt) = (hex_field(case, "message"), hex_field(case, "salt"));
        let expected = hex_field(case, "signature");
        assert_eq!(expected.len(), key.size());

        let verify = |signature: &[u8]| match case["hash"].as_str() {
            "sha256" => PssSha256::verify(key.public_key(), &message, signature),
            "sha384" => PssSha384::verify(key.public_key(), &message, signature),
            "sha512" => PssSha512::verify(key.public_key(), &message, signature),
            other => panic!("no such hash here: {other}"),
        };

        match case["kind"].as_str() {
            "sign" => {
                let mut rng = GivenSalt { salt, asked: 0 };
                let mut signature = vec![0u8; key.size()];
                match case["hash"].as_str() {
                    "sha256" => PssSha256::sign(key, &message, &mut rng, &mut signature),
                    "sha384" => PssSha384::sign(key, &message, &mut rng, &mut signature),
                    "sha512" => PssSha512::sign(key, &message, &mut rng, &mut signature),
                    other => panic!("no such hash here: {other}"),
                }
                .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                assert_eq!(rng.asked, 1, "{label}: one salt for one signature");
                assert_eq!(hex(&signature), case["signature"], "{label}");
                verify(&signature).unwrap();
            }
            "refuse" => {
                // Valid under a salt of another length, which is not a PSS
                // this library has.
                let err = verify(&expected).expect_err(&label);
                assert_eq!(err.kind(), ErrorKind::AuthenticationFailed, "{label}");
            }
            other => panic!("unknown kind {other}"),
        }
        *tally.entry(label).or_insert(0) += 1;
    }
    println!("{tally:#?}");
    let count = |kind: &str| -> usize {
        tally
            .iter()
            .filter(|(k, _)| k.ends_with(kind))
            .map(|(_, n)| *n)
            .sum()
    };
    // Ten messages for SHA-256 and for SHA-384 at 3072 bits carry a salt as
    // long as the hash; the other four groups do not.
    assert_eq!(count("sign"), 20, "{tally:?}");
    assert_eq!(count("refuse"), 40, "{tally:?}");
}
