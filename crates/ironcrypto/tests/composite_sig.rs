//! Composite ML-DSA against draft-ietf-lamps-pq-composite-sigs-19.
//!
//! `testvectors/composite-mldsa-draft19.json`, from
//! `scripts/gen_composite_sig_vectors.py`: Appendix E's three EdDSA
//! composites. For each:
//!
//! - the private key derives the draft's public key byte for byte;
//! - the draft's signature verifies, over the empty context and over its
//!   context, and neither verifies under the other context, another message,
//!   or another composite;
//! - a signature made here verifies, and fails with either half altered.
//!
//! ML-DSA signing is hedged, so the draft's signatures cannot be reproduced
//! byte for byte; the public key and verification are what the vectors hold.
#![cfg(not(ic_approved_only))]

use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::sig::composite::{self, Composite};

fn algorithm(tc_id: &str) -> Composite {
    match tc_id {
        "id-MLDSA44-Ed25519-SHA512" => Composite::MlDsa44Ed25519Sha512,
        "id-MLDSA65-Ed25519-SHA512" => Composite::MlDsa65Ed25519Sha512,
        "id-MLDSA87-Ed448-SHAKE256" => Composite::MlDsa87Ed448Shake256,
        other => panic!("unexpected case {other}"),
    }
}

#[test]
fn composites_match_the_draft() {
    let Some(file) = VectorFile::load_or_report("composite-mldsa-draft19") else {
        return;
    };
    assert_eq!(file.cases.len(), 3);
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x77; 48], b"composite test").unwrap();
    for case in &file.cases {
        let name = case["tcId"].as_str();
        let alg = algorithm(name);
        let (pk, sk, m, ctx, s, s_ctx) = (
            hex_field(case, "pk"),
            hex_field(case, "sk"),
            hex_field(case, "m"),
            hex_field(case, "ctx"),
            hex_field(case, "s"),
            hex_field(case, "sWithContext"),
        );
        assert_eq!(pk.len(), alg.public_key_len(), "{name}");
        assert_eq!(sk.len(), alg.private_key_len(), "{name}");
        assert_eq!(s.len(), alg.signature_len(), "{name}");

        let mut derived = vec![0u8; alg.public_key_len()];
        composite::public_key(alg, &sk, &mut derived).unwrap();
        assert!(derived == pk, "{name}: public key");

        composite::verify(alg, &pk, &m, b"", &s).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        composite::verify(alg, &pk, &m, &ctx, &s_ctx)
            .unwrap_or_else(|e| panic!("{name} ctx: {e:?}"));
        let refused = |r: ironcrypto::core_types::Result<()>| {
            assert_eq!(
                r.unwrap_err().kind(),
                ErrorKind::AuthenticationFailed,
                "{name}"
            )
        };
        refused(composite::verify(alg, &pk, &m, &ctx, &s));
        refused(composite::verify(alg, &pk, &m, b"", &s_ctx));
        refused(composite::verify(alg, &pk, b"another message", b"", &s));
        for other in Composite::ALL.into_iter().filter(|o| *o != alg) {
            refused(composite::verify(other, &pk, &m, b"", &s));
        }

        // Signed here.
        let mut sig = vec![0u8; alg.signature_len()];
        composite::sign(alg, &sk, &m, &ctx, &mut rng, &mut sig).unwrap();
        composite::verify(alg, &pk, &m, &ctx, &sig).unwrap();
        // Either half altered fails: the first byte of ML-DSA's, the last of
        // EdDSA's.
        for at in [0, sig.len() - 1] {
            let mut bad = sig.clone();
            bad[at] ^= 1;
            refused(composite::verify(alg, &pk, &m, &ctx, &bad));
        }
        // Too long a context is the caller's error.
        assert_eq!(
            composite::sign(alg, &sk, &m, &[0u8; 256], &mut rng, &mut sig)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidParameter
        );
    }
}

/// Each half is checked. Two more keys share one component with the
/// vector's key and differ in the other: one shares the ML-DSA seed, one the
/// EdDSA seed. A signature with one half taken from such a key verifies under
/// the key it now matches and is refused under the vector's -- so a verifier
/// that skipped either half would accept what this refuses.
#[test]
fn both_halves_are_checked() {
    let Some(file) = VectorFile::load_or_report("composite-mldsa-draft19") else {
        return;
    };
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x78; 48], b"composite halves").unwrap();
    for case in &file.cases {
        let name = case["tcId"].as_str();
        let alg = algorithm(name);
        let (pk, sk) = (hex_field(case, "pk"), hex_field(case, "sk"));
        let trad_sig_len = if alg == Composite::MlDsa87Ed448Shake256 {
            114
        } else {
            64
        };
        let split = alg.signature_len() - trad_sig_len;
        let m = b"spliced";
        let mut sig = vec![0u8; alg.signature_len()];
        composite::sign(alg, &sk, m, b"", &mut rng, &mut sig).unwrap();

        // Byte 0 is in the ML-DSA seed, byte 40 in the EdDSA seed.
        for (flip, half) in [(40usize, "eddsa"), (0, "ml-dsa")] {
            let mut sk2 = sk.clone();
            sk2[flip] ^= 1;
            let mut pk2 = vec![0u8; alg.public_key_len()];
            composite::public_key(alg, &sk2, &mut pk2).unwrap();
            let mut sig2 = vec![0u8; alg.signature_len()];
            composite::sign(alg, &sk2, m, b"", &mut rng, &mut sig2).unwrap();
            // The vector key's signature with the changed component's half
            // taken from the other key's signature.
            let mut spliced = sig.clone();
            if half == "eddsa" {
                spliced[split..].copy_from_slice(&sig2[split..]);
            } else {
                spliced[..split].copy_from_slice(&sig2[..split]);
            }
            assert!(
                composite::verify(alg, &pk, m, b"", &spliced).is_err(),
                "{name}: a foreign {half} half was accepted"
            );
            composite::verify(alg, &pk2, m, b"", &spliced)
                .unwrap_or_else(|e| panic!("{name} {half}: {e:?}"));
        }
    }
}
