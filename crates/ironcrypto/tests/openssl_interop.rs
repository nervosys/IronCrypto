//! ML-KEM and ML-DSA against OpenSSL, from bytes OpenSSL produced.
//!
//! NIST's ACVP vectors show each parameter set computes the right values. They
//! do not show that a key or signature from another implementation is read the
//! same way here, which is what interoperating means. These fixtures were made
//! by OpenSSL 3.5.7 -- keys, ciphertexts, shared secrets and signatures -- and
//! the file records the commands, so they can be regenerated.
//!
//! What each case establishes:
//!
//! - Key generation from OpenSSL's seed reproduces OpenSSL's keys, both halves.
//! - For ML-DSA, the deterministic signature produced here is byte for byte
//!   OpenSSL's, which shows agreement in both directions at once: OpenSSL
//!   accepts it because it is its own. OpenSSL's hedged signature, whose
//!   randomness is unknown here, verifies here.
//! - For ML-KEM, decapsulating OpenSSL's ciphertext recovers OpenSSL's secret.
//!
//! One direction is left to a manual check, recorded in `docs/FIPS.md`: an
//! ML-KEM ciphertext made here, decapsulated by OpenSSL. It needs OpenSSL at
//! test time, and nothing under `crates/` depends on it.

use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::{mldsa, mlkem};

/// Run one ML-DSA case against the module for its parameter set.
macro_rules! dsa_case {
    ($m:ident, $case:expr, $index:expr) => {{
        let case = $case;
        let index = $index;
        let mut pk = [0u8; mldsa::$m::PUBLIC_KEY_LEN];
        let mut sk = [0u8; mldsa::$m::SECRET_KEY_LEN];
        assert!(mldsa::$m::keygen(
            hex_field(case, "seed")[..].try_into().unwrap(),
            &mut pk,
            &mut sk
        ));
        assert_eq!(
            hex(&pk),
            hex(&hex_field(case, "pk")),
            "OpenSSL's pk, case {index}"
        );
        assert_eq!(
            hex(&sk),
            hex(&hex_field(case, "sk")),
            "OpenSSL's sk, case {index}"
        );

        let message = hex_field(case, "message");
        let ctx = hex_field(case, "context");
        let mut ours = [0u8; mldsa::$m::SIGNATURE_LEN];
        assert!(mldsa::$m::sign_deterministic(
            &sk, &message, &ctx, &mut ours
        ));
        let theirs = hex_field(case, "signature_deterministic");
        assert_eq!(
            hex(&ours),
            hex(&theirs),
            "deterministic signature, case {index}"
        );

        for field in ["signature_deterministic", "signature_hedged"] {
            let sig: [u8; mldsa::$m::SIGNATURE_LEN] =
                hex_field(case, field)[..].try_into().unwrap();
            assert!(
                mldsa::$m::verify(&pk, &message, &ctx, &sig),
                "{field}, case {index}"
            );
            // Bound to the context: the same signature under another fails.
            let other: &[u8] = if ctx.is_empty() { b"x" } else { b"" };
            assert!(
                !mldsa::$m::verify(&pk, &message, other, &sig),
                "{field} context, case {index}"
            );
        }
    }};
}

#[test]
fn ml_dsa_agrees_with_openssl() {
    let Some(file) = VectorFile::load_or_report("openssl-ml-dsa") else {
        return;
    };
    let mut seen = [0usize; 3];
    for (index, case) in file.cases.iter().enumerate() {
        match case["parameter_set"].as_str() {
            "ML-DSA-44" => {
                dsa_case!(sign44, case, index);
                seen[0] += 1
            }
            "ML-DSA-65" => {
                dsa_case!(sign, case, index);
                seen[1] += 1
            }
            "ML-DSA-87" => {
                dsa_case!(sign87, case, index);
                seen[2] += 1
            }
            other => panic!("case {index}: unknown parameter set {other}"),
        }
    }
    assert_eq!(seen, [2, 2, 2], "one plain and one with a context, per set");
}

/// Run one ML-KEM case against the type for its parameter set.
macro_rules! kem_case {
    ($module:ident, $ty:ident, $case:expr, $index:expr) => {{
        let case = $case;
        let index = $index;
        // OpenSSL's seed is FIPS 203's `d || z`.
        let seed = hex_field(case, "seed");
        assert_eq!(seed.len(), 64, "case {index}: seed");
        let mut ek = [0u8; mlkem::$module::ENCAPS_KEY_LEN];
        let mut dk = [0u8; mlkem::$module::DECAPS_KEY_LEN];
        mlkem::$ty::keygen_deterministic(
            seed[..32].try_into().unwrap(),
            seed[32..].try_into().unwrap(),
            &mut ek,
            &mut dk,
        );
        assert_eq!(
            hex(&ek),
            hex(&hex_field(case, "ek")),
            "OpenSSL's ek, case {index}"
        );
        assert_eq!(
            hex(&dk),
            hex(&hex_field(case, "dk")),
            "OpenSSL's dk, case {index}"
        );

        let ct: [u8; mlkem::$module::CIPHERTEXT_LEN] = hex_field(case, "c")[..].try_into().unwrap();
        let mut shared = [0u8; mlkem::$module::SHARED_SECRET_LEN];
        mlkem::$ty::decapsulate(&dk, &ct, &mut shared).unwrap();
        assert_eq!(
            hex(&shared),
            hex(&hex_field(case, "k")),
            "OpenSSL's secret, case {index}"
        );
    }};
}

#[test]
fn ml_kem_agrees_with_openssl() {
    let Some(file) = VectorFile::load_or_report("openssl-ml-kem") else {
        return;
    };
    let mut seen = [0usize; 3];
    for (index, case) in file.cases.iter().enumerate() {
        match case["parameter_set"].as_str() {
            "ML-KEM-512" => {
                kem_case!(kem512, MlKem512, case, index);
                seen[0] += 1
            }
            "ML-KEM-768" => {
                kem_case!(kem, MlKem768, case, index);
                seen[1] += 1
            }
            "ML-KEM-1024" => {
                kem_case!(kem1024, MlKem1024, case, index);
                seen[2] += 1
            }
            other => panic!("case {index}: unknown parameter set {other}"),
        }
    }
    assert_eq!(seen, [1, 1, 1], "one case per set");
}

/// ML-DSA private keys in each of RFC 9881's PKCS#8 forms, as OpenSSL writes
/// them, read by `ic_pkix::MlDsaPrivateKey` and written back byte for byte.
///
/// The seed and expanded key the parser finds are compared with OpenSSL's own
/// account of them, not with the parser's, and the expanded key is regenerated
/// from the seed by `ic_mldsa`: the check RFC 9881's `both` form calls for,
/// done the way the parser's documentation tells a caller to.
#[test]
fn ml_dsa_pkcs8_agrees_with_openssl() {
    use ironcrypto::pkix::{MlDsaParameterSet, MlDsaPrivateKey};

    let Some(file) = VectorFile::load_or_report("openssl-ml-dsa-pkcs8") else {
        return;
    };
    let mut checked = 0;
    for (index, case) in file.cases.iter().enumerate() {
        let seed = hex_field(case, "seed");
        let expanded = hex_field(case, "expanded_key");
        let set = match case["parameter_set"].as_str() {
            "ML-DSA-44" => MlDsaParameterSet::MlDsa44,
            "ML-DSA-65" => MlDsaParameterSet::MlDsa65,
            "ML-DSA-87" => MlDsaParameterSet::MlDsa87,
            other => panic!("case {index}: unknown parameter set {other}"),
        };

        // ic_mldsa regenerates OpenSSL's expanded key from the seed.
        let regenerated = match set {
            MlDsaParameterSet::MlDsa44 => {
                let (mut pk, mut sk) = (
                    [0u8; mldsa::sign44::PUBLIC_KEY_LEN],
                    [0u8; mldsa::sign44::SECRET_KEY_LEN],
                );
                assert!(mldsa::sign44::keygen(
                    seed[..].try_into().unwrap(),
                    &mut pk,
                    &mut sk
                ));
                sk.to_vec()
            }
            MlDsaParameterSet::MlDsa65 => {
                let (mut pk, mut sk) = (
                    [0u8; mldsa::sign::PUBLIC_KEY_LEN],
                    [0u8; mldsa::sign::SECRET_KEY_LEN],
                );
                assert!(mldsa::sign::keygen(
                    seed[..].try_into().unwrap(),
                    &mut pk,
                    &mut sk
                ));
                sk.to_vec()
            }
            MlDsaParameterSet::MlDsa87 => {
                let (mut pk, mut sk) = (
                    [0u8; mldsa::sign87::PUBLIC_KEY_LEN],
                    [0u8; mldsa::sign87::SECRET_KEY_LEN],
                );
                assert!(mldsa::sign87::keygen(
                    seed[..].try_into().unwrap(),
                    &mut pk,
                    &mut sk
                ));
                sk.to_vec()
            }
        };
        assert_eq!(
            regenerated.len(),
            set.expanded_key_len(),
            "case {index}: length table"
        );
        assert!(
            ironcrypto::core_types::ct::verify(&regenerated, &expanded),
            "case {index}: keygen"
        );

        for (field, want_seed, want_expanded) in [
            ("pkcs8_seed", true, false),
            ("pkcs8_expanded", false, true),
            ("pkcs8_both", true, true),
        ] {
            let der = hex_field(case, field);
            let key = MlDsaPrivateKey::from_der(&der)
                .unwrap_or_else(|e| panic!("case {index} {field}: {e:?}"));
            assert_eq!(key.parameter_set(), set, "case {index} {field}");
            assert_eq!(
                key.seed().map(<[u8]>::to_vec),
                want_seed.then(|| seed.clone()),
                "case {index} {field}: seed"
            );
            assert_eq!(
                key.expanded_key().map(<[u8]>::to_vec),
                want_expanded.then(|| expanded.clone()),
                "case {index} {field}: expanded key"
            );
            let mut out = vec![0u8; der.len() + 16];
            let n = key.to_der(&mut out).unwrap();
            assert_eq!(
                hex(&out[..n]),
                hex(&der),
                "case {index} {field}: written back"
            );
            assert!(
                matches!(
                    ironcrypto::pkix::PrivateKeyInfo::from_der(&der),
                    Ok(ironcrypto::pkix::PrivateKeyInfo::Unsupported { .. })
                ),
                "case {index} {field}: the general parser still says unsupported"
            );
        }

        // A both-form file whose halves disagree parses -- the structure is
        // fine -- and the regeneration check is what catches it.
        let mut der = hex_field(case, "pkcs8_both");
        let last = der.len() - 1;
        der[last] ^= 1;
        let key = MlDsaPrivateKey::from_der(&der).unwrap();
        assert!(
            !ironcrypto::core_types::ct::verify(&regenerated, key.expanded_key().unwrap()),
            "case {index}: a disagreeing pair must be detectable"
        );
        checked += 1;
    }
    assert_eq!(checked, 6, "two seeds per parameter set");
}
