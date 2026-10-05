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
