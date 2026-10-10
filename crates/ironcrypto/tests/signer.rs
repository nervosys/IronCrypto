//! `ic_sig::SoftwareSigner` on private keys OpenSSL made.
//!
//! `testvectors/openssl-private-keys.json`, from
//! `scripts/gen_signer_vectors.py`, carries one PKCS#8 key per algorithm and
//! the SubjectPublicKeyInfo OpenSSL derived from it. For each:
//!
//! - the key is read, and the public key the signer reports is OpenSSL's,
//!   byte for byte -- callers match a signer to a certificate that way;
//! - it signs under every algorithm it lists, and `ic_sig::verify` accepts
//!   each signature under that public key and refuses it for another message;
//! - where OpenSSL signed deterministically, the signature is OpenSSL's.
//!
//! Loading an SLH-DSA key regenerates its root, and signing with a
//! small-signature set takes millions of hash calls, so by default the `s`
//! sets are skipped here; `IC_SLOW_SLH_DSA` runs them.

use ic_core::sig::{Custody, SignatureAlgorithm, Signer};
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::sig::{verify_spki, SoftwareSigner};

#[test]
fn the_software_signer_reads_openssl_keys_and_signs_what_verify_accepts() {
    let Some(file) = VectorFile::load_or_report("openssl-private-keys") else {
        return;
    };
    let slow = std::env::var_os("IC_SLOW_SLH_DSA").is_some();
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x33; 48], b"signer test").unwrap();
    let mut ran = std::collections::BTreeSet::new();
    let mut skipped = 0;
    for case in &file.cases {
        let name = case["key"].as_str();
        if name.starts_with("slh-dsa") && name.ends_with('s') && !slow {
            skipped += 1;
            continue;
        }
        let (pkcs8, spki, message) = (
            hex_field(case, "pkcs8"),
            hex_field(case, "spki"),
            hex_field(case, "message"),
        );
        let signer = SoftwareSigner::from_pkcs8(&pkcs8).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(hex(signer.public_key()), case["spki"], "{name}: public key");
        assert_eq!(signer.custody(), Custody::Software);
        // The key signs through the trait object a protocol would hold.
        let signer: &dyn Signer = &signer;

        let expected = if name.starts_with("rsa") { 6 } else { 1 };
        assert_eq!(signer.algorithms().len(), expected, "{name}");
        for &algorithm in signer.algorithms() {
            let mut out = vec![0u8; algorithm.max_signature_len()];
            let len = signer
                .sign(algorithm, &message, &mut rng, &mut out)
                .unwrap_or_else(|e| panic!("{name} {}: {e:?}", algorithm.id()));
            verify_spki(algorithm, &spki, &message, &out[..len])
                .unwrap_or_else(|e| panic!("{name} {}: {e:?}", algorithm.id()));
            let mut other = message.clone();
            other.push(0);
            assert_eq!(
                verify_spki(algorithm, &spki, &other, &out[..len])
                    .unwrap_err()
                    .kind(),
                ErrorKind::AuthenticationFailed
            );
            // OpenSSL's own signature, where signing is deterministic.
            let deterministic = matches!(
                algorithm,
                SignatureAlgorithm::Ed25519 | SignatureAlgorithm::RsaPkcs1Sha256
            );
            if deterministic {
                assert!(
                    !case["signature"].is_empty(),
                    "{name}: no OpenSSL signature"
                );
                assert_eq!(
                    hex(&out[..len]),
                    case["signature"],
                    "{name} {}: not OpenSSL's signature",
                    algorithm.id()
                );
            }
        }
        // Whatever algorithm the key's name says, the signer says too.
        if !name.starts_with("rsa") {
            assert!(
                signer.algorithms()[0].id().starts_with(name),
                "{name} signs with {}",
                signer.algorithms()[0].id()
            );
        }
        ran.insert(name.to_string());
    }
    // Nine classical and ML-DSA keys, six fast SLH-DSA sets, and the six
    // small-signature sets when asked.
    assert_eq!(ran.len(), if slow { 21 } else { 15 }, "{ran:?}");
    if !slow {
        println!("{skipped} SLH-DSA s-set keys skipped; set IC_SLOW_SLH_DSA to run them");
    }
}

/// Two things about an RSA key that the test above does not separate.
///
/// The order of its algorithms is a promise: a protocol takes the first one
/// its peer allows, so PSS comes before PKCS#1 v1.5. And the modulus in the
/// file is a stated value: the key is built from the primes, and a file whose
/// modulus is not their product names a different key from the one it holds.
#[test]
fn an_rsa_key_prefers_pss_and_must_be_the_key_its_file_names() {
    let Some(file) = VectorFile::load_or_report("openssl-private-keys") else {
        return;
    };
    let case = file
        .cases
        .iter()
        .find(|c| c["key"] == "rsa-2048")
        .expect("an RSA key");
    let pkcs8 = hex_field(case, "pkcs8");
    let signer = SoftwareSigner::from_pkcs8(&pkcs8).unwrap();
    let ids: Vec<&str> = signer.algorithms().iter().map(|a| a.id()).collect();
    assert_eq!(
        ids,
        [
            "rsa-pss-sha256",
            "rsa-pss-sha384",
            "rsa-pss-sha512",
            "rsa-pkcs1-sha256",
            "rsa-pkcs1-sha384",
            "rsa-pkcs1-sha512"
        ]
    );

    // The same key with its modulus changed in the last byte, which keeps it
    // odd and the same size.
    let ironcrypto::pkix::PrivateKeyInfo::Rsa {
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
    } = ironcrypto::pkix::PrivateKeyInfo::from_der(&pkcs8).unwrap()
    else {
        panic!("not an RSA key");
    };
    let rebuild = |modulus: &[u8]| {
        let mut out = vec![0u8; 2000];
        let n = ironcrypto::pkix::PrivateKeyInfo::Rsa {
            modulus,
            public_exponent,
            private_exponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        }
        .to_der(&mut out)
        .unwrap();
        out.truncate(n);
        out
    };
    // Re-encoding changes nothing by itself.
    SoftwareSigner::from_pkcs8(&rebuild(modulus)).unwrap();
    let mut wrong = modulus.to_vec();
    *wrong.last_mut().unwrap() ^= 0x02;
    assert_eq!(
        SoftwareSigner::from_pkcs8(&rebuild(&wrong))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParameter
    );
}
