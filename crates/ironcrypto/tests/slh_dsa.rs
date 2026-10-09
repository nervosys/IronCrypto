//! SLH-DSA against NIST's ACVP vectors for FIPS 205.
//!
//! `scripts/gen_slh_dsa_vectors.py` converts NIST's files and says which
//! cases are bundled: every key-generation case; signing cases for each
//! parameter set, interface (pure, pre-hash, internal) and variant, with the
//! expected signature as its SHA-256; and verification cases -- passing and
//! failing -- for the sets with the smallest signatures. The pre-hash cases
//! cover all twelve hash functions, in signing and in verification.
//!
//! Signing with an `s` parameter set takes a few million hash calls, which is
//! seconds per signature in an unoptimised test build, and generating an `s`
//! key is hundreds of thousands. So by default the `s` sets run two of their
//! ten key-generation cases and none of their twenty-four signing cases; the
//! `f` sets, which exercise the same code at other parameters, always run in
//! full, and NIST's `s`-set signatures are still verified. `IC_SLOW_SLH_DSA`
//! runs everything bundled. `IC_SLH_DSA_FULL`
//! names a directory holding the full conversion, every case of all three
//! interfaces, which is run as well when it is present.

use ic_core::traits::Digest;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::slhdsa::{self, ParameterSet};

type Case = std::collections::BTreeMap<String, String>;

fn set_of(case: &Case) -> ParameterSet {
    ParameterSet::from_id(&case["parameter_set"])
        .unwrap_or_else(|| panic!("unknown parameter set {}", case["parameter_set"]))
}

fn pre_hash_of(case: &Case) -> slhdsa::PreHash {
    slhdsa::PreHash::from_id(&case["hash"])
        .unwrap_or_else(|| panic!("unknown pre-hash {}", case["hash"]))
}

fn is_small_signature_set(set: ParameterSet) -> bool {
    set.id().ends_with('s')
}

/// The bundled file, and the full one when `IC_SLH_DSA_FULL` points at it.
fn files(name: &str) -> Vec<VectorFile> {
    let mut out = Vec::new();
    out.extend(VectorFile::load_or_report(name));
    if let Some(dir) = std::env::var_os("IC_SLH_DSA_FULL") {
        let full = VectorFile::load_from(std::path::Path::new(&dir), &format!("{name}-full"))
            .unwrap_or_else(|| panic!("IC_SLH_DSA_FULL is set and {name}-full.json is not there"));
        println!(
            "{}: {} cases from the full ACVP conversion",
            name,
            full.cases.len()
        );
        out.push(full);
    }
    out
}

#[test]
fn key_generation_matches_every_acvp_case() {
    let slow = std::env::var_os("IC_SLOW_SLH_DSA").is_some()
        || std::env::var_os("IC_SLH_DSA_FULL").is_some();
    let mut per_set = std::collections::BTreeMap::new();
    for file in files("slh-dsa-keygen").iter().take(1) {
        for case in &file.cases {
            let set = set_of(case);
            // An s set's top tree has up to 512 one-time keys to generate.
            // Two cases of each run by default, and all ten when asked.
            let seen = per_set.get(set.id()).copied().unwrap_or(0);
            if is_small_signature_set(set) && seen >= 2 && !slow {
                continue;
            }
            let mut sk = vec![0u8; set.secret_key_len()];
            let mut pk = vec![0u8; set.public_key_len()];
            slhdsa::keygen_internal(
                set,
                &hex_field(case, "sk_seed"),
                &hex_field(case, "sk_prf"),
                &hex_field(case, "pk_seed"),
                &mut sk,
                &mut pk,
            )
            .unwrap();
            assert_eq!(hex(&pk), case["pk"], "{} public key", set.id());
            assert_eq!(hex(&sk), case["sk"], "{} secret key", set.id());
            *per_set.entry(set.id()).or_insert(0) += 1;
        }
    }
    if !per_set.is_empty() {
        assert_eq!(per_set.len(), 12, "every parameter set");
        for (id, n) in &per_set {
            let want = if id.ends_with('s') && !slow { 2 } else { 10 };
            assert_eq!(*n, want, "{id}");
        }
    }
}

#[test]
fn signatures_match_the_acvp_cases() {
    let slow = std::env::var_os("IC_SLOW_SLH_DSA").is_some()
        || std::env::var_os("IC_SLH_DSA_FULL").is_some();
    let (mut ran, mut skipped) = (std::collections::BTreeSet::new(), 0);
    let mut hashes = std::collections::BTreeSet::new();
    for file in files("slh-dsa-siggen") {
        for case in &file.cases {
            let set = set_of(case);
            if is_small_signature_set(set) && !slow {
                skipped += 1;
                continue;
            }
            let (sk, message, context) = (
                hex_field(case, "sk"),
                hex_field(case, "message"),
                hex_field(case, "context"),
            );
            let randomness = hex_field(case, "additional_randomness");
            let deterministic = case["deterministic"] == "true";
            assert_eq!(deterministic, randomness.is_empty());
            let mut signature = vec![0u8; set.signature_len()];
            let written = match (case["interface"].as_str(), deterministic) {
                ("external", true) => {
                    slhdsa::sign_deterministic(set, &sk, &message, &context, &mut signature)
                }
                ("external", false) => slhdsa::sign_with_randomness(
                    set,
                    &sk,
                    &message,
                    &context,
                    &randomness,
                    &mut signature,
                ),
                ("internal", true) => {
                    slhdsa::sign_internal(set, &sk, &message, None, &mut signature)
                }
                ("internal", false) => {
                    slhdsa::sign_internal(set, &sk, &message, Some(&randomness), &mut signature)
                }
                ("prehash", true) => slhdsa::hash_sign_deterministic(
                    set,
                    &sk,
                    &message,
                    &context,
                    pre_hash_of(case),
                    &mut signature,
                ),
                ("prehash", false) => slhdsa::hash_sign_with_randomness(
                    set,
                    &sk,
                    &message,
                    &context,
                    pre_hash_of(case),
                    &randomness,
                    &mut signature,
                ),
                (other, _) => panic!("unknown interface {other}"),
            }
            .unwrap();
            let label = format!(
                "{} {} {}",
                set.id(),
                case["interface"],
                if deterministic {
                    "deterministic"
                } else {
                    "hedged"
                }
            );
            assert_eq!(
                written.to_string(),
                case["signature_len"],
                "{label}: length"
            );
            assert_eq!(
                hex(ic_hash::Sha256::digest(&signature).as_ref()),
                case["signature_sha256"],
                "{label}: signature"
            );
            if let Some(full) = case.get("signature") {
                assert_eq!(&hex(&signature), full, "{label}: signature bytes");
            }
            // What was signed verifies under the key's public half, the last
            // 2n bytes of the secret key, through the matching interface.
            let pk = &sk[sk.len() / 2..];
            match case["interface"].as_str() {
                "external" => slhdsa::verify(set, pk, &message, &context, &signature),
                "prehash" => {
                    hashes.insert(case["hash"].clone());
                    slhdsa::hash_verify(set, pk, &message, &context, pre_hash_of(case), &signature)
                }
                _ => slhdsa::verify_internal(set, pk, &message, &signature),
            }
            .unwrap_or_else(|e| panic!("{label}: its own signature did not verify: {e:?}"));
            ran.insert(label);
        }
    }
    if ran.is_empty() && skipped == 0 {
        return;
    }
    // Six f sets, three interfaces, two variants; and the s sets when asked.
    assert_eq!(ran.len(), if slow { 72 } else { 36 }, "{ran:?}");
    // The f sets alone sign under every pre-hash function.
    assert_eq!(hashes.len(), 12, "{hashes:?}");
    if !slow {
        println!("{skipped} s-set signing cases skipped; set IC_SLOW_SLH_DSA to run them");
    }
}

#[test]
fn verification_matches_the_acvp_cases() {
    let (mut valid, mut invalid) = (0, 0);
    let mut sets = std::collections::BTreeSet::new();
    let mut hashes = std::collections::BTreeSet::new();
    for file in files("slh-dsa-sigver") {
        for case in &file.cases {
            let set = set_of(case);
            let (pk, message, context, signature) = (
                hex_field(case, "pk"),
                hex_field(case, "message"),
                hex_field(case, "context"),
                hex_field(case, "signature"),
            );
            let result = match case["interface"].as_str() {
                "external" => slhdsa::verify(set, &pk, &message, &context, &signature),
                "internal" => slhdsa::verify_internal(set, &pk, &message, &signature),
                "prehash" => {
                    hashes.insert(case["hash"].clone());
                    slhdsa::hash_verify(set, &pk, &message, &context, pre_hash_of(case), &signature)
                }
                other => panic!("unknown interface {other}"),
            };
            let expected = case["valid"] == "true";
            assert_eq!(
                result.is_ok(),
                expected,
                "{} {}: NIST says {}, got {result:?}",
                set.id(),
                case["interface"],
                if expected { "valid" } else { "invalid" }
            );
            if expected {
                valid += 1;
            } else {
                invalid += 1;
            }
            sets.insert(set.id());
        }
    }
    if valid + invalid > 0 {
        assert!(
            valid >= 12 && invalid >= 18,
            "{valid} valid, {invalid} invalid"
        );
        assert!(sets.len() >= 6, "{sets:?}");
        assert_eq!(hashes.len(), 12, "{hashes:?}");
    }
}
