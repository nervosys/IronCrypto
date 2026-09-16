//! Vector tests for anything whose vectors are not in the repository.
//!
//! Each of these loads a file from `testvectors/`, checks against it, and skips
//! with a printed notice when it is absent. See `testvectors/README.md`.
//!
//! The AES Key Wrap case is different: its file *is* bundled, because a harness
//! nobody can exercise proves nothing. It runs on every build and is what
//! demonstrates the loading, decoding and comparison machinery actually works,
//! so that when someone drops in an ACVP file the only new thing is the data.

use ac_vectors::{hex, hex_field, optional_hex_field, VectorFile};
use agentic_crypto::prelude::*;
use agentic_crypto::{cipher, mldsa, mlkem};

/// RFC 3394, loaded from the bundled file rather than inlined.
///
/// The same vectors are asserted inline in `ac_cipher::keywrap`. The
/// duplication is on purpose: that test proves Key Wrap is correct, and this
/// one proves the harness is, using data whose answer is already known.
#[test]
fn aes_key_wrap_vectors_from_file() {
    let Some(file) = VectorFile::load_or_report("aes-kw") else {
        panic!("testvectors/aes-kw.json is bundled and must be present");
    };
    assert!(!file.cases.is_empty());

    for (index, case) in file.cases.iter().enumerate() {
        let kek = hex_field(case, "key");
        let pt = hex_field(case, "pt");
        let want = hex_field(case, "ct");

        let mut got = vec![0u8; pt.len() + 8];
        match kek.len() {
            16 => cipher::Aes128Kw::wrap(&kek, &pt, &mut got),
            24 => cipher::Aes192Kw::wrap(&kek, &pt, &mut got),
            32 => cipher::Aes256Kw::wrap(&kek, &pt, &mut got),
            other => panic!("case {index}: unsupported KEK length {other}"),
        }
        .unwrap();
        assert_eq!(hex(&got), hex(&want), "wrap, case {index}");

        let mut back = vec![0u8; pt.len()];
        match kek.len() {
            16 => cipher::Aes128Kw::unwrap(&kek, &want, &mut back),
            24 => cipher::Aes192Kw::unwrap(&kek, &want, &mut back),
            _ => cipher::Aes256Kw::unwrap(&kek, &want, &mut back),
        }
        .unwrap();
        assert_eq!(hex(&back), hex(&pt), "unwrap, case {index}");
    }
}

/// RFC 8452 Appendix C, when someone supplies it.
///
/// This is the file that would move AES-GCM-SIV from `experimental` to
/// `available`. Everything beneath it is verified; only the assembly is not.
#[test]
fn aes_gcm_siv_vectors_from_file() {
    let Some(file) = VectorFile::load_or_report("aes-gcm-siv") else {
        return;
    };

    for (index, case) in file.cases.iter().enumerate() {
        let key = hex_field(case, "key");
        let nonce = hex_field(case, "nonce");
        let aad = optional_hex_field(case, "aad").unwrap_or_default();
        let pt = hex_field(case, "pt");
        let want = hex_field(case, "ct");
        assert_eq!(
            want.len(),
            pt.len() + 16,
            "case {index}: ct should carry the 16-byte tag"
        );

        let mut buf = pt.clone();
        let mut tag = [0u8; 16];
        match key.len() {
            16 => {
                let c = cipher::Aes128GcmSiv::new(&key).unwrap();
                c.seal_detached(&nonce, &aad, &mut buf, &mut tag).unwrap();
            }
            32 => {
                let c = cipher::Aes256GcmSiv::new(&key).unwrap();
                c.seal_detached(&nonce, &aad, &mut buf, &mut tag).unwrap();
            }
            other => panic!("case {index}: unsupported key length {other}"),
        }
        let mut got = buf.clone();
        got.extend_from_slice(&tag);
        assert_eq!(hex(&got), hex(&want), "seal, case {index}");

        // And the other direction, from the published ciphertext.
        let mut opened = want[..pt.len()].to_vec();
        let published_tag = &want[pt.len()..];
        match key.len() {
            16 => cipher::Aes128GcmSiv::new(&key).unwrap().open_detached(
                &nonce,
                &aad,
                &mut opened,
                published_tag,
            ),
            _ => cipher::Aes256GcmSiv::new(&key).unwrap().open_detached(
                &nonce,
                &aad,
                &mut opened,
                published_tag,
            ),
        }
        .unwrap();
        assert_eq!(hex(&opened), hex(&pt), "open, case {index}");
    }
}

/// ACVP ML-KEM key generation, when someone supplies it.
///
/// Key generation is the right place to start: it is deterministic in `d` and
/// `z`, so a single vector pins the matrix expansion, both samplers, the NTT
/// and the whole encoding at once. If this passes, very little of the scheme is
/// left unchecked.
#[test]
fn ml_kem_keygen_vectors_from_file() {
    let Some(file) = VectorFile::load_or_report("ml-kem-768-keygen") else {
        return;
    };

    for (index, case) in file.cases.iter().enumerate() {
        let d = hex_field(case, "d");
        let z = hex_field(case, "z");
        let want_ek = hex_field(case, "ek");
        let want_dk = hex_field(case, "dk");
        assert_eq!(d.len(), 32, "case {index}: d");
        assert_eq!(z.len(), 32, "case {index}: z");

        let mut ek = [0u8; mlkem::kem::ENCAPS_KEY_LEN];
        let mut dk = [0u8; mlkem::kem::DECAPS_KEY_LEN];
        mlkem::MlKem768::keygen_deterministic(
            d[..].try_into().unwrap(),
            z[..].try_into().unwrap(),
            &mut ek,
            &mut dk,
        );

        assert_eq!(hex(&ek), hex(&want_ek), "encapsulation key, case {index}");
        assert_eq!(hex(&dk), hex(&want_dk), "decapsulation key, case {index}");
    }
}

/// ACVP ML-KEM encapsulation, when someone supplies it.
#[test]
fn ml_kem_encap_vectors_from_file() {
    let Some(file) = VectorFile::load_or_report("ml-kem-768-encap") else {
        return;
    };

    for (index, case) in file.cases.iter().enumerate() {
        let ek = hex_field(case, "ek");
        let m = hex_field(case, "m");
        let want_ct = hex_field(case, "c");
        let want_k = hex_field(case, "k");

        let ek: &[u8; mlkem::kem::ENCAPS_KEY_LEN] = ek[..]
            .try_into()
            .unwrap_or_else(|_| panic!("case {index}: ek is the wrong length"));

        let mut ct = [0u8; mlkem::kem::CIPHERTEXT_LEN];
        let mut shared = [0u8; mlkem::kem::SHARED_SECRET_LEN];
        mlkem::MlKem768::encapsulate_deterministic(
            m[..].try_into().unwrap(),
            ek,
            &mut ct,
            &mut shared,
        );

        assert_eq!(hex(&ct), hex(&want_ct), "ciphertext, case {index}");
        assert_eq!(hex(&shared), hex(&want_k), "shared secret, case {index}");
    }
}

/// ACVP ML-DSA key generation, when someone supplies it.
///
/// As with ML-KEM, key generation is the right place to start: it is
/// deterministic in the seed, so one case pins `ExpandA`, `ExpandS`, the NTT,
/// `Power2Round` and the whole key encoding at once.
#[test]
fn ml_dsa_keygen_vectors_from_file() {
    let Some(file) = VectorFile::load_or_report("ml-dsa-65-keygen") else {
        return;
    };

    for (index, case) in file.cases.iter().enumerate() {
        let seed = hex_field(case, "seed");
        let want_pk = hex_field(case, "pk");
        let want_sk = hex_field(case, "sk");
        assert_eq!(seed.len(), 32, "case {index}: seed");

        let mut pk = [0u8; mldsa::sign::PUBLIC_KEY_LEN];
        let mut sk = [0u8; mldsa::sign::SECRET_KEY_LEN];
        assert!(
            mldsa::sign::keygen(seed[..].try_into().unwrap(), &mut pk, &mut sk),
            "case {index}: the generated key failed its consistency test"
        );

        assert_eq!(hex(&pk), hex(&want_pk), "verification key, case {index}");
        assert_eq!(hex(&sk), hex(&want_sk), "signing key, case {index}");
    }
}

/// ACVP ML-DSA signature generation, when someone supplies it.
///
/// `rnd` is optional: absent means the deterministic variant, which is the
/// same code path with zeros.
#[test]
fn ml_dsa_siggen_vectors_from_file() {
    let Some(file) = VectorFile::load_or_report("ml-dsa-65-siggen") else {
        return;
    };

    for (index, case) in file.cases.iter().enumerate() {
        let sk = hex_field(case, "sk");
        let message = hex_field(case, "message");
        let ctx = optional_hex_field(case, "context").unwrap_or_default();
        let rnd = optional_hex_field(case, "rnd").unwrap_or_else(|| vec![0u8; 32]);
        let want = hex_field(case, "signature");

        let sk: &[u8; mldsa::sign::SECRET_KEY_LEN] = sk[..]
            .try_into()
            .unwrap_or_else(|_| panic!("case {index}: sk is the wrong length"));

        let mut sig = [0u8; mldsa::sign::SIGNATURE_LEN];
        assert!(
            mldsa::sign::sign(sk, &message, &ctx, rnd[..].try_into().unwrap(), &mut sig),
            "case {index}: signing failed"
        );
        assert_eq!(hex(&sig), hex(&want), "signature, case {index}");
    }
}

/// The harness's own contract: an absent file must skip, not fail.
///
/// Without this, a typo in a filename would look exactly like a passing test,
/// which is the failure mode the whole design is trying to avoid.
#[test]
fn a_missing_vector_file_skips_rather_than_failing() {
    assert!(VectorFile::load_or_report("no-such-algorithm-exists").is_none());
}
