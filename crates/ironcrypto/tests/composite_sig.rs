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

/// DER: `tag`, its length, `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n @ 0..=127 => out.push(n as u8),
        n @ 128..=255 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// A `SubjectPublicKeyInfo`, with NULL parameters if asked.
fn spki_of(oid: &[u8], parameters: bool, key: &[u8]) -> Vec<u8> {
    let mut alg = der(0x06, oid);
    if parameters {
        alg.extend([0x05, 0x00]);
    }
    let mut bits = vec![0u8];
    bits.extend_from_slice(key);
    der(0x30, &[der(0x30, &alg), der(0x03, &bits)].concat())
}

/// A version 0 PKCS#8 key, with NULL parameters if asked, and anything after
/// the private key octet string.
fn pkcs8_of(oid: &[u8], parameters: bool, key: &[u8], after: &[u8]) -> Vec<u8> {
    let mut alg = der(0x06, oid);
    if parameters {
        alg.extend([0x05, 0x00]);
    }
    der(
        0x30,
        &[&[2, 1, 0][..], &der(0x30, &alg), &der(0x04, key), after].concat(),
    )
}

/// The composites through `SubjectPublicKeyInfo`, PKCS#8, `ic_sig::verify`
/// and `SoftwareSigner`, against the draft's keys and the self-signed
/// certificate each case carries.
#[test]
fn composites_through_spki_pkcs8_and_certificates() {
    use ironcrypto::core_types::sig::{SignatureAlgorithm, Signer};
    use ironcrypto::sig::{verify_spki, PublicKey, SoftwareSigner};
    let Some(file) = VectorFile::load_or_report("composite-mldsa-draft19") else {
        return;
    };
    let kind = |r: ironcrypto::core_types::Result<()>| r.unwrap_err().kind();
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x78; 48], b"composite pkix").unwrap();
    for case in &file.cases {
        let name = case["tcId"].as_str();
        let c = algorithm(name);
        let alg = SignatureAlgorithm::from_id(c.id()).unwrap();
        let (pk, sk_pkcs8, sk, m, s, s_ctx, oid, spki, tbs, cert_sig) = (
            hex_field(case, "pk"),
            hex_field(case, "sk_pkcs8"),
            hex_field(case, "sk"),
            hex_field(case, "m"),
            hex_field(case, "s"),
            hex_field(case, "sWithContext"),
            hex_field(case, "oid"),
            hex_field(case, "spki"),
            hex_field(case, "tbs"),
            hex_field(case, "certSignature"),
        );
        assert_eq!(oid, c.oid(), "{name}");

        // The certificate's key is read as the composite, and the
        // certificate's own signature verifies.
        assert_eq!(
            PublicKey::from_spki(&spki).unwrap(),
            PublicKey::Composite(c, &pk),
            "{name}"
        );
        verify_spki(alg, &spki, &tbs, &cert_sig).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        verify_spki(alg, &spki, &m, &s).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // `verify` is the empty context: the signature over `ctx` is refused.
        assert_eq!(
            kind(verify_spki(alg, &spki, &m, &s_ctx)),
            ErrorKind::AuthenticationFailed,
            "{name}"
        );
        let mut tbs_altered = tbs.clone();
        tbs_altered[10] ^= 1;
        assert_eq!(
            kind(verify_spki(alg, &spki, &tbs_altered, &cert_sig)),
            ErrorKind::AuthenticationFailed,
            "{name}"
        );
        for &other in SignatureAlgorithm::ALL.iter().filter(|a| **a != alg) {
            assert_eq!(
                kind(verify_spki(other, &spki, &tbs, &cert_sig)),
                ErrorKind::InvalidParameter,
                "{name} as {}",
                other.id()
            );
        }

        // The draft's PKCS#8 key signs, and reports the certificate's key.
        let signer =
            SoftwareSigner::from_pkcs8(&sk_pkcs8).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(signer.algorithms(), [alg], "{name}");
        assert!(signer.public_key() == spki.as_slice(), "{name}: public key");
        let mut out = vec![0u8; alg.max_signature_len()];
        let n = signer.sign(alg, &m, &mut rng, &mut out).unwrap();
        assert_eq!(n, c.signature_len());
        verify_spki(alg, &spki, &m, &out[..n]).unwrap();
        assert_eq!(
            kind(
                signer
                    .sign(alg, &m, &mut rng, &mut out[..n - 1])
                    .map(|_| ())
            ),
            ErrorKind::InvalidLength,
            "{name}"
        );

        // Against the rule rather than a value. These builders reproduce the
        // draft's encodings first, so each refusal below is for the one thing
        // changed.
        assert_eq!(spki_of(&oid, false, &pk), spki, "{name}");
        assert_eq!(pkcs8_of(&oid, false, &sk, &[]), sk_pkcs8, "{name}");
        let spki_err = |bytes: Vec<u8>| PublicKey::from_spki(&bytes).unwrap_err().kind();
        assert_eq!(
            spki_err(spki_of(&oid, true, &pk)),
            ErrorKind::MalformedEncoding
        );
        assert_eq!(
            spki_err(spki_of(&oid, false, &pk[1..])),
            ErrorKind::MalformedEncoding
        );
        assert_eq!(
            spki_err(spki_of(&oid, false, &[&pk[..], &[0]].concat())),
            ErrorKind::MalformedEncoding
        );
        let pkcs8_err = |bytes: Vec<u8>| SoftwareSigner::from_pkcs8(&bytes).unwrap_err().kind();
        assert_eq!(
            pkcs8_err(pkcs8_of(&oid, true, &sk, &[])),
            ErrorKind::MalformedEncoding
        );
        assert_eq!(
            pkcs8_err(pkcs8_of(&oid, false, &sk[1..], &[])),
            ErrorKind::MalformedEncoding
        );
        assert_eq!(
            pkcs8_err(pkcs8_of(&oid, false, &[&sk[..], &[0]].concat(), &[])),
            ErrorKind::MalformedEncoding
        );
        // A stated public key is refused, as `ic_pkix` refuses one for every
        // algorithm. RFC 5958 puts one only in a version 1 key.
        let mut stated = vec![0u8];
        stated.extend_from_slice(&pk);
        let mut with_public = pkcs8_of(&oid, false, &sk, &der(0x81, &stated));
        assert_eq!(with_public[4..7], [2, 1, 0]);
        with_public[6] = 1;
        assert_eq!(pkcs8_err(with_public), ErrorKind::Unsupported);
    }
}
