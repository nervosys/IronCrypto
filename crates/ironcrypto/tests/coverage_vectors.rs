//! The suites Graviola runs that this repository did not, run here.
//!
//! `scripts/gen_coverage_vectors.py` converts them, from NIST CAVP's response
//! files and Project Wycheproof at the commit the other Wycheproof files use,
//! each source pinned by SHA-256 in that script:
//!
//! - every SHA-2, SHA-3 and SHAKE ShortMsg, LongMsg, VariableOut and Monte
//!   case, and every HMAC case for the hashes this library has;
//! - Wycheproof's ML-KEM key generation, encapsulation and decapsulation for
//!   all three parameter sets, Graviola runs ML-KEM-768 only;
//! - ECDSA with IEEE P1363 signatures, and the curve and hash pairs
//!   `wycheproof-ecdsa.json` lacks;
//! - AES-GMAC;
//! - Wycheproof's primality cases, against ic-rsa's Miller-Rabin test with
//!   random bases from a seeded RNG. Every case must agree; none is listed.
//!
//! Each test tallies what it saw and asserts a floor, so a file that loses
//! cases, or a parser that silently matches none, fails rather than passes.

// Hashes, HMAC, AES-GCM, ECDSA and ML-KEM are all approved, so nothing here
// is outside the --cfg ic_approved_only build.

use std::collections::BTreeMap;

use ic_core::traits::{Aead, Digest, Mac};
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::{cipher, ec, hash, mac, mlkem};

type Case = BTreeMap<String, String>;

fn digest(alg: &str, data: &[u8]) -> Vec<u8> {
    macro_rules! d {
        ($ty:ty) => {
            <$ty as Digest>::digest(data).unwrap().as_ref().to_vec()
        };
    }
    match alg {
        "sha2-224" => d!(hash::Sha224),
        "sha2-256" => d!(hash::Sha256),
        "sha2-384" => d!(hash::Sha384),
        "sha2-512" => d!(hash::Sha512),
        "sha2-512-224" => d!(hash::Sha512_224),
        "sha2-512-256" => d!(hash::Sha512_256),
        "sha3-224" => d!(hash::Sha3_224),
        "sha3-256" => d!(hash::Sha3_256),
        "sha3-384" => d!(hash::Sha3_384),
        "sha3-512" => d!(hash::Sha3_512),
        other => panic!("no digest {other}"),
    }
}

fn shake(alg: &str, data: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    match alg {
        "shake128" => hash::Shake128::xof(data, &mut out).unwrap(),
        "shake256" => hash::Shake256::xof(data, &mut out).unwrap(),
        other => panic!("no xof {other}"),
    }
    out
}

/// SHA-2's Monte Carlo chain, SHAVS section 6.4: three running digests fed
/// back in, 1000 rounds per checkpoint.
fn sha2_monte(alg: &str, seed: &[u8]) -> Vec<u8> {
    let (mut a, mut b, mut c) = (seed.to_vec(), seed.to_vec(), seed.to_vec());
    for _ in 3..1003 {
        let mut m = a.clone();
        m.extend_from_slice(&b);
        m.extend_from_slice(&c);
        let next = digest(alg, &m);
        a = b;
        b = c;
        c = next;
    }
    c
}

/// SHA-3's Monte Carlo chain, SHA3VS section 6.2.3: each digest is the next
/// message, 1000 rounds per checkpoint.
fn sha3_monte(alg: &str, seed: &[u8]) -> Vec<u8> {
    let mut md = seed.to_vec();
    for _ in 0..1000 {
        md = digest(alg, &md);
    }
    md
}

/// SHAKE's Monte Carlo chain, SHA3VS section 6.2.3: the next message is the
/// leftmost 128 bits of the last output, and the next output length is
/// taken from its rightmost 16 bits, within [min, max] bytes.
fn shake_monte(alg: &str, seed: &[u8], min: usize, max: usize, out_len: &mut usize) -> Vec<u8> {
    let mut output = seed.to_vec();
    for _ in 0..1000 {
        let mut msg = [0u8; 16];
        let take = output.len().min(16);
        msg[..take].copy_from_slice(&output[..take]);
        output = shake(alg, &msg, *out_len);
        let right = u16::from_be_bytes([output[output.len() - 2], output[output.len() - 1]]);
        let range = max - min + 1;
        *out_len = min + usize::from(right) % range;
    }
    output
}

#[test]
fn cavp_sha2_and_sha3_every_case() {
    for name in ["cavp-sha2", "cavp-sha3"] {
        let Some(file) = VectorFile::load_or_report(name) else {
            continue;
        };
        let mut tally = BTreeMap::<String, usize>::new();
        // Monte checkpoints arrive in order; each continues from the last.
        let mut chain: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut shake_len: BTreeMap<String, usize> = BTreeMap::new();
        for case in &file.cases {
            let alg = case["hash"].as_str();
            let want = hex_field(case, "md");
            let got = match case["kind"].as_str() {
                "msg" if alg.starts_with("shake") => {
                    shake(alg, &hex_field(case, "msg"), want.len())
                }
                "msg" => digest(alg, &hex_field(case, "msg")),
                "monte" => {
                    let start = if case["count"] == "0" {
                        hex_field(case, "seed")
                    } else {
                        chain[alg].clone()
                    };
                    let md = if alg.starts_with("sha3") {
                        sha3_monte(alg, &start)
                    } else {
                        sha2_monte(alg, &start)
                    };
                    chain.insert(alg.to_string(), md.clone());
                    md
                }
                "shake-monte" => {
                    let min = case["min_bits"].parse::<usize>().unwrap() / 8;
                    let max = case["max_bits"].parse::<usize>().unwrap() / 8;
                    let start = if case["count"] == "0" {
                        shake_len.insert(alg.to_string(), max);
                        hex_field(case, "seed")
                    } else {
                        chain[alg].clone()
                    };
                    let mut len = shake_len[alg];
                    let out = shake_monte(alg, &start, min, max, &mut len);
                    assert_eq!(
                        out.len() * 8,
                        case["outlen"].parse::<usize>().unwrap(),
                        "{alg} monte {}: output length",
                        case["count"]
                    );
                    shake_len.insert(alg.to_string(), len);
                    chain.insert(alg.to_string(), out.clone());
                    out
                }
                other => panic!("unknown kind {other}"),
            };
            assert_eq!(hex(&got), hex(&want), "{name} {alg} {}", case["kind"]);
            *tally.entry(format!("{alg} {}", case["kind"])).or_default() += 1;
        }
        println!("{name}: {tally:#?}");
        for (key, n) in &tally {
            assert!(*n >= 100, "{name}: only {n} cases of {key}");
        }
        let algorithms = tally
            .keys()
            .map(|k| k.split(' ').next().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        // Six either way: the six SHA-2 functions, or four SHA-3 and two SHAKE.
        assert_eq!(algorithms.len(), 6, "{name}: {algorithms:?}");
    }
}

#[test]
fn cavp_hmac_every_case_with_its_truncation() {
    let Some(file) = VectorFile::load_or_report("cavp-hmac") else {
        return;
    };
    let mut tally = BTreeMap::<String, usize>::new();
    for case in &file.cases {
        let (key, msg, tag) = (
            hex_field(case, "key"),
            hex_field(case, "msg"),
            hex_field(case, "tag"),
        );
        let tlen: usize = case["tlen"].parse().unwrap();
        assert_eq!(tag.len(), tlen);
        let full = match case["hash"].as_str() {
            "sha2-256" => mac::HmacSha256::mac(&key, &msg).unwrap().as_ref().to_vec(),
            "sha2-384" => mac::HmacSha384::mac(&key, &msg).unwrap().as_ref().to_vec(),
            "sha2-512" => mac::HmacSha512::mac(&key, &msg).unwrap().as_ref().to_vec(),
            other => panic!("no hmac {other}"),
        };
        assert!(
            ic_core::ct::verify(&full[..tlen], &tag),
            "hmac-{} key {} bytes tlen {tlen}",
            case["hash"],
            key.len()
        );
        *tally.entry(case["hash"].clone()).or_default() += 1;
    }
    println!("{tally:#?}");
    assert_eq!(tally.len(), 3);
    assert!(tally.values().all(|n| *n >= 200), "{tally:?}");
}

macro_rules! mlkem_case {
    ($set:ident, $ty:ident, $case:expr, $tally:expr) => {{
        use mlkem::$set as m;
        let case: &Case = $case;
        let valid = case["result"] == "valid";
        let file = case["file"].as_str();
        let fixed = |name: &str, len: usize| -> Option<Vec<u8>> {
            let bytes = hex_field(case, name);
            (bytes.len() == len).then_some(bytes)
        };
        let outcome: Result<(), String> = (|| match file {
            "keygen_seed_test" | "test" => {
                let Some(seed) = fixed("seed", 64) else {
                    return Err("seed length".into());
                };
                let mut ek = [0u8; m::ENCAPS_KEY_LEN];
                let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
                mlkem::$ty::keygen_deterministic(
                    seed[..32].try_into().unwrap(),
                    seed[32..].try_into().unwrap(),
                    &mut ek,
                    &mut dk,
                )
                .map_err(|e| format!("{e:?}"))?;
                if case.contains_key("ek") {
                    assert_eq!(hex(&ek), case["ek"], "{} ek", case["tcId"]);
                }
                if file == "keygen_seed_test" {
                    assert_eq!(hex(&dk[..]), case["dk"], "{} dk", case["tcId"]);
                    return Ok(());
                }
                let Some(c) = fixed("c", m::CIPHERTEXT_LEN) else {
                    return Err("ciphertext length".into());
                };
                let mut k = [0u8; m::SHARED_SECRET_LEN];
                mlkem::$ty::decapsulate(&dk, c[..].try_into().unwrap(), &mut k)
                    .map_err(|e| format!("{e:?}"))?;
                // The prepared key must agree, case by case, valid or not.
                let mut k_prepared = [0u8; m::SHARED_SECRET_LEN];
                m::PreparedDecapsulationKey::new(&dk)
                    .map_err(|e| format!("{e:?}"))?
                    .decapsulate(c[..].try_into().unwrap(), &mut k_prepared)
                    .map_err(|e| format!("{e:?}"))?;
                assert_eq!(k, k_prepared, "{} prepared decapsulation", case["tcId"]);
                (hex(&k) == case["K"])
                    .then_some(())
                    .ok_or("shared secret".into())
            }
            "encaps_test" => {
                let Some(ek) = fixed("ek", m::ENCAPS_KEY_LEN) else {
                    return Err("key length".into());
                };
                let ek: [u8; m::ENCAPS_KEY_LEN] = ek[..].try_into().unwrap();
                // The prepared key's constructor must refuse exactly what the
                // validator refuses.
                let prepared = m::PreparedEncapsulationKey::new(&ek);
                let validated = mlkem::$ty::validate_encapsulation_key(&ek);
                assert_eq!(
                    prepared.is_ok(),
                    validated.is_ok(),
                    "{} prepared key and validator disagree",
                    case["tcId"]
                );
                validated.map_err(|e| format!("{e:?}"))?;
                let prepared = prepared.map_err(|e| format!("{e:?}"))?;
                let msg: [u8; 32] = hex_field(case, "m")[..].try_into().unwrap();
                let mut c = [0u8; m::CIPHERTEXT_LEN];
                let mut k = [0u8; m::SHARED_SECRET_LEN];
                mlkem::$ty::encapsulate_deterministic(&msg, &ek, &mut c, &mut k)
                    .map_err(|e| format!("{e:?}"))?;
                assert_eq!(hex(&c), case["c"], "{} c", case["tcId"]);
                let mut c_prepared = [0u8; m::CIPHERTEXT_LEN];
                let mut k_prepared = [0u8; m::SHARED_SECRET_LEN];
                prepared
                    .encapsulate_deterministic(&msg, &mut c_prepared, &mut k_prepared)
                    .map_err(|e| format!("{e:?}"))?;
                assert_eq!(hex(&c_prepared), case["c"], "{} prepared c", case["tcId"]);
                assert_eq!(k, k_prepared, "{} prepared K", case["tcId"]);
                (hex(&k) == case["K"])
                    .then_some(())
                    .ok_or("shared secret".into())
            }
            other => panic!("unknown file {other}"),
        })();
        // A key with a coefficient at or above q is refused when the prepared
        // key is built, not later.
        if file == "encaps_test" && case["flags"] == "ModulusOverflow" {
            let ek: [u8; m::ENCAPS_KEY_LEN] = hex_field(case, "ek")[..].try_into().unwrap();
            let refused = m::PreparedEncapsulationKey::new(&ek).unwrap_err();
            assert_eq!(
                refused.kind(),
                ErrorKind::MalformedEncoding,
                "{}",
                case["tcId"]
            );
            *$tally
                .entry(format!("{} prepared modulus overflow refused", case["set"]))
                .or_default() += 1;
        }
        match (valid, outcome) {
            (true, Ok(())) => {
                *$tally
                    .entry(format!("{} {file} valid accepted", case["set"]))
                    .or_default() += 1
            }
            (false, Err(_)) => {
                *$tally
                    .entry(format!("{} {file} invalid refused", case["set"]))
                    .or_default() += 1
            }
            (true, Err(e)) => panic!(
                "{} {file} {}: valid case refused: {e}",
                case["set"], case["tcId"]
            ),
            (false, Ok(())) => panic!(
                "{} {file} {}: invalid case accepted",
                case["set"], case["tcId"]
            ),
        }
    }};
}

#[test]
fn wycheproof_ml_kem_all_parameter_sets() {
    let Some(file) = VectorFile::load_or_report("wycheproof-mlkem") else {
        return;
    };
    let mut tally = BTreeMap::<String, usize>::new();
    for case in &file.cases {
        match case["set"].as_str() {
            "ML-KEM-512" => mlkem_case!(kem512, MlKem512, case, tally),
            "ML-KEM-768" => mlkem_case!(kem, MlKem768, case, tally),
            "ML-KEM-1024" => mlkem_case!(kem1024, MlKem1024, case, tally),
            other => panic!("unknown set {other}"),
        }
    }
    println!("{tally:#?}");
    for set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        for (file, floor) in [("keygen_seed_test", 50), ("test", 100), ("encaps_test", 50)] {
            assert!(
                tally
                    .get(&format!("{set} {file} valid accepted"))
                    .copied()
                    .unwrap_or(0)
                    >= floor,
                "{set} {file}: {tally:?}"
            );
        }
        // Wycheproof has 4k modulus-overflow keys per set, each refused by
        // the prepared key's constructor.
        let overflows = match set {
            "ML-KEM-512" => 8,
            "ML-KEM-768" => 12,
            _ => 16,
        };
        assert_eq!(
            tally
                .get(&format!("{set} prepared modulus overflow refused"))
                .copied(),
            Some(overflows),
            "{set}: {tally:?}"
        );
        // The modulus check and the length checks were each reached.
        assert!(
            tally
                .get(&format!("{set} encaps_test invalid refused"))
                .copied()
                .unwrap_or(0)
                >= 10
        );
        assert!(
            tally
                .get(&format!("{set} test invalid refused"))
                .copied()
                .unwrap_or(0)
                >= 10
        );
    }
}

#[test]
fn wycheproof_ecdsa_p1363_and_other_hashes() {
    let Some(file) = VectorFile::load_or_report("wycheproof-ecdsa-extra") else {
        return;
    };
    let mut tally = BTreeMap::<String, usize>::new();
    for case in &file.cases {
        let (key, msg, sig) = (
            hex_field(case, "key"),
            hex_field(case, "msg"),
            hex_field(case, "sig"),
        );
        let curve = case["curve"].as_str();
        let width = match curve {
            "p256" => 32,
            "p384" => 48,
            "p521" => 66,
            other => panic!("curve {other}"),
        };
        // Both encodings come down to fixed-width r || s; DER that does not
        // decode, or P1363 of the wrong length, is a refusal.
        let fixed: Option<Vec<u8>> = if case["encoding"] == "der" {
            let mut out = vec![0u8; 2 * width];
            ironcrypto::pkix::ecdsa_signature::from_der(&sig, &mut out)
                .ok()
                .map(|_| out)
        } else {
            (sig.len() == 2 * width).then_some(sig.clone())
        };
        let digest = digest(&format!("sha2-{}", &case["hash"][3..]), &msg);
        let result = match fixed {
            None => Err(ErrorKind::MalformedEncoding),
            Some(rs) => match curve {
                "p256" => ec::p256::EcdsaP256Sha256::verify_prehash(&key, &digest, &rs),
                "p384" => ec::p384::EcdsaP384Sha384::verify_prehash(&key, &digest, &rs),
                _ => ec::p521::EcdsaP521Sha512::verify_prehash(&key, &digest, &rs),
            }
            .map_err(|e| e.kind()),
        };
        let label = format!("{curve} {} {}", case["hash"], case["encoding"]);
        // P-384 under SHA-256 is refused by rule, before any arithmetic: a
        // digest narrower than the curve's strength. Graviola accepts it;
        // this library's verify_prehash does not, by design.
        if curve == "p384" && case["hash"] == "sha256" {
            assert!(
                result.is_err(),
                "{label} {}: a 32-byte digest on P-384 was taken",
                case["tcId"]
            );
            *tally.entry(format!("{label} refused by rule")).or_default() += 1;
            continue;
        }
        match (case["result"].as_str(), result) {
            ("valid", Ok(())) => *tally.entry(format!("{label} valid accepted")).or_default() += 1,
            ("invalid", Err(_)) => {
                *tally.entry(format!("{label} invalid refused")).or_default() += 1
            }
            ("acceptable", r) => {
                *tally
                    .entry(format!(
                        "{label} acceptable {}",
                        if r.is_ok() { "accepted" } else { "refused" }
                    ))
                    .or_default() += 1
            }
            (verdict, r) => panic!(
                "{label} {} ({}): {verdict}, got {r:?}",
                case["tcId"], case["comment"]
            ),
        }
    }
    println!("{tally:#?}");
    for label in [
        "p256 sha256 p1363",
        "p384 sha384 p1363",
        "p521 sha512 p1363",
        "p256 sha512 der",
        "p384 sha512 der",
    ] {
        assert!(
            tally
                .get(&format!("{label} valid accepted"))
                .copied()
                .unwrap_or(0)
                > 0,
            "{label}: {tally:?}"
        );
        assert!(
            tally
                .get(&format!("{label} invalid refused"))
                .copied()
                .unwrap_or(0)
                > 50,
            "{label}: {tally:?}"
        );
    }
    assert!(
        tally
            .get("p384 sha256 der refused by rule")
            .copied()
            .unwrap_or(0)
            > 100
    );
}

#[test]
fn wycheproof_aes_gmac() {
    let Some(file) = VectorFile::load_or_report("wycheproof-gmac") else {
        return;
    };
    let mut tally = BTreeMap::<String, usize>::new();
    for case in &file.cases {
        let (key, iv, msg, tag) = (
            hex_field(case, "key"),
            hex_field(case, "iv"),
            hex_field(case, "msg"),
            hex_field(case, "tag"),
        );
        // GMAC is GCM with the message as additional data and nothing to
        // encrypt.
        let mut empty = [0u8; 0];
        let opened = match key.len() {
            16 => cipher::Aes128Gcm::new(&key)
                .unwrap()
                .open_detached(&iv, &msg, &mut empty, &tag),
            24 => cipher::Aes192Gcm::new(&key)
                .unwrap()
                .open_detached(&iv, &msg, &mut empty, &tag),
            32 => cipher::Aes256Gcm::new(&key)
                .unwrap()
                .open_detached(&iv, &msg, &mut empty, &tag),
            other => panic!("key length {other}"),
        };
        if case["result"] == "valid" {
            opened.unwrap_or_else(|e| panic!("gmac {}: {e:?}", case["tcId"]));
            // And the tag computes the other way too.
            let mut made = [0u8; 16];
            match key.len() {
                16 => cipher::Aes128Gcm::new(&key)
                    .unwrap()
                    .seal_detached(&iv, &msg, &mut empty, &mut made),
                24 => cipher::Aes192Gcm::new(&key)
                    .unwrap()
                    .seal_detached(&iv, &msg, &mut empty, &mut made),
                _ => cipher::Aes256Gcm::new(&key)
                    .unwrap()
                    .seal_detached(&iv, &msg, &mut empty, &mut made),
            }
            .unwrap();
            assert_eq!(hex(&made), case["tag"], "gmac {}", case["tcId"]);
            *tally
                .entry(format!("{}-bit iv valid", iv.len() * 8))
                .or_default() += 1;
        } else {
            assert_eq!(
                opened.unwrap_err().kind(),
                ErrorKind::AuthenticationFailed,
                "gmac {} ({})",
                case["tcId"],
                case["comment"]
            );
            *tally
                .entry(format!("{}-bit iv invalid", iv.len() * 8))
                .or_default() += 1;
        }
    }
    println!("{tally:#?}");
    for key in [
        "96-bit iv valid",
        "128-bit iv valid",
        "96-bit iv invalid",
        "128-bit iv invalid",
    ] {
        assert!(
            tally.get(key).copied().unwrap_or(0) >= 40,
            "{key}: {tally:?}"
        );
    }
}

/// Wycheproof's primality cases against `ic_rsa`'s key-generation primality
/// decision. `valid` must be accepted, `invalid` refused, `acceptable` either
/// way. Values are signed big-endian in Wycheproof, so a negative one (first
/// byte 0x80 or more) is skipped and counted: the API takes unsigned integers
/// and a negative has no unsigned reading. A value wider than the 4096-bit
/// capacity is skipped and counted too.
///
/// The bases are drawn at random, as FIPS 186-5 B.3.1 specifies, so the decision
/// is random. It is seeded with a constant here, which makes it the same on every
/// run. The composites that a fixed set of prime bases accepted (Wycheproof's
/// cases 22 to 25, 31, 32, 38, 87 and 105 to 116) are now refused, and no case
/// is listed as a known disagreement. The seed is part of the test: under a
/// different seed, a composite passes with probability at most 4^-8 per case.
#[test]
fn wycheproof_primality_every_case() {
    let Some(file) = VectorFile::load_or_report("wycheproof-primality") else {
        return;
    };
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x5au8; 32], b"wycheproof primality")
        .expect("seeded rng");
    let mut tally = BTreeMap::<String, usize>::new();
    for key in [
        "valid agrees",
        "invalid agrees",
        "acceptable, either answer",
        "negative, skipped",
        "wider than 4096 bits, skipped",
    ] {
        tally.insert(key.to_string(), 0);
    }
    let mut disagreements: Vec<(String, String, String, &str, bool)> = Vec::new();
    for case in &file.cases {
        let value = hex_field(case, "value");
        if value.first().is_some_and(|b| *b >= 0x80) {
            *tally.get_mut("negative, skipped").unwrap() += 1;
            continue;
        }
        let Some(got) = ic_rsa::key::probable_prime_be(&value, &mut rng) else {
            *tally.get_mut("wider than 4096 bits, skipped").unwrap() += 1;
            continue;
        };
        let result = case["result"].as_str();
        let agrees = match result {
            "valid" => got,
            "invalid" => !got,
            "acceptable" => {
                *tally.get_mut("acceptable, either answer").unwrap() += 1;
                continue;
            }
            other => panic!("result {other}"),
        };
        if agrees {
            *tally.get_mut(&format!("{result} agrees")).unwrap() += 1;
        } else {
            disagreements.push((
                case["tcId"].clone(),
                case["comment"].clone(),
                hex(&value),
                result,
                got,
            ));
        }
    }
    println!("{tally:#?}");
    for (tc, comment, value, result, got) in &disagreements {
        println!(
            "disagreement tcId {tc}: {comment}; value {value}; result {result}; library says prime = {got}"
        );
    }
    // Every case is in exactly one bucket.
    let counted: usize = tally.values().sum::<usize>() + disagreements.len();
    assert_eq!(counted, file.cases.len(), "{tally:?}");
    // No disagreement is allowed. A composite accepted here is a bug in the
    // primality test, not a known limitation.
    assert!(disagreements.is_empty(), "disagreements: {disagreements:?}");
    // Every prime was accepted and most composites refused, so a test that
    // always says prime, or never does, cannot pass.
    assert!(tally["valid agrees"] >= 60, "{tally:?}");
    assert!(tally["invalid agrees"] >= 200, "{tally:?}");
}
