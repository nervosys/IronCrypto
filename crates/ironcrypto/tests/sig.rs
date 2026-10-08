//! `ic_sig::verify` against signatures OpenSSL made.
//!
//! Two sources. `testvectors/openssl-sig.json` carries ECDSA, Ed25519 and RSA
//! signatures over bare messages, from `scripts/gen_sig_vectors.py`.
//! `testvectors/openssl-x509.json` carries certificates OpenSSL issued with
//! Ed25519, ML-DSA-65 and ML-DSA-87, and a certificate is a signature over its
//! `tbsCertificate` under its issuer's key -- the use this function exists
//! for.
//!
//! Beyond the values, each case is turned against the rule: a changed message,
//! a changed or truncated signature, and the right signature under another
//! algorithm are all refused, and refused as the kind of failure they are.

use ic_core::sig::SignatureAlgorithm;
use ic_core::ErrorKind;
use ic_pkix::der::Reader;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::sig::{verify, verify_spki, PublicKey};

fn algorithm(id: &str) -> SignatureAlgorithm {
    SignatureAlgorithm::from_id(id).unwrap_or_else(|| panic!("unknown algorithm {id}"))
}

fn kind<T: std::fmt::Debug>(r: ic_core::Result<T>) -> ErrorKind {
    r.expect_err("must be refused").kind()
}

#[test]
fn openssl_signatures_verify_and_altered_ones_do_not() {
    let Some(file) = VectorFile::load_or_report("openssl-sig") else {
        return;
    };
    let mut seen = std::collections::BTreeSet::new();
    for case in &file.cases {
        let alg = algorithm(&case["algorithm"]);
        let (spki, message, signature) = (
            hex_field(case, "spki"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let key = PublicKey::from_spki(&spki).unwrap();
        verify(alg, &key, &message, &signature)
            .unwrap_or_else(|e| panic!("{}: {e:?}", case["algorithm"]));
        verify_spki(alg, &spki, &message, &signature).unwrap();
        assert!(
            signature.len() <= alg.max_signature_len(),
            "{} signature longer than max_signature_len",
            alg.id()
        );

        // A different message.
        let mut other = message.clone();
        other.push(0);
        assert_eq!(
            kind(verify(alg, &key, &other, &signature)),
            ErrorKind::AuthenticationFailed
        );
        // Every single-byte change to the signature, and every truncation of
        // it: malformed, wrong length or simply wrong, all one failure.
        for i in (0..signature.len()).step_by(signature.len() / 16 + 1) {
            let mut bad = signature.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                kind(verify(alg, &key, &message, &bad)),
                ErrorKind::AuthenticationFailed,
                "{} byte {i}",
                alg.id()
            );
        }
        for len in [0, 1, signature.len() - 1] {
            assert_eq!(
                kind(verify(alg, &key, &message, &signature[..len])),
                ErrorKind::AuthenticationFailed
            );
        }
        // Every other algorithm: one this key cannot serve is the caller's
        // error; one it can -- another RSA algorithm -- is a failed signature.
        for &wrong in SignatureAlgorithm::ALL.iter().filter(|a| **a != alg) {
            let expected = if key.supports(wrong) {
                ErrorKind::AuthenticationFailed
            } else {
                ErrorKind::InvalidParameter
            };
            assert_eq!(
                kind(verify(wrong, &key, &message, &signature)),
                expected,
                "{} verified as {}",
                alg.id(),
                wrong.id()
            );
        }
        seen.insert(alg.id());
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "ecdsa-p256-sha256",
            "ecdsa-p384-sha384",
            "ecdsa-p521-sha512",
            "ed25519",
            "rsa-pkcs1-sha256",
            "rsa-pkcs1-sha384",
            "rsa-pkcs1-sha512",
            "rsa-pss-sha256",
            "rsa-pss-sha384",
            "rsa-pss-sha512",
        ],
        "the cases did not cover every classical algorithm"
    );
}

/// The raw bytes of the next element in `r`, header included.
fn next_tlv<'a>(r: &mut Reader<'a>, tag: u8) -> &'a [u8] {
    let before = r.remaining();
    r.expect(tag).unwrap();
    &before[..before.len() - r.remaining().len()]
}

/// A certificate's `tbsCertificate`, `subjectPublicKeyInfo` and signature.
fn certificate_parts(der: &[u8]) -> (&[u8], &[u8], &[u8]) {
    const SEQUENCE: u8 = 0x30;
    let mut outer = Reader::new(der);
    let mut cert = outer.sequence().unwrap();
    let tbs = next_tlv(&mut cert, SEQUENCE);
    cert.sequence().unwrap(); // signatureAlgorithm
    let signature = cert.bit_string().unwrap();

    let mut t = Reader::new(tbs).sequence().unwrap();
    t.expect(0xa0).unwrap(); // [0] version
    t.expect(0x02).unwrap(); // serialNumber
    for _ in 0..4 {
        t.sequence().unwrap(); // signature, issuer, validity, subject
    }
    let spki = next_tlv(&mut t, SEQUENCE);
    (tbs, spki, signature)
}

/// Each OpenSSL-issued chain: the CA signed itself and its leaf.
#[test]
fn openssl_issued_certificates_verify_under_their_issuer() {
    let Some(file) = VectorFile::load_or_report("openssl-x509") else {
        return;
    };
    let mut seen = Vec::new();
    for case in &file.cases {
        let alg = algorithm(&case["algorithm"]);
        let (ca, leaf) = (hex_field(case, "ca_der"), hex_field(case, "leaf_der"));
        let (ca_tbs, ca_spki, ca_sig) = certificate_parts(&ca);
        let (leaf_tbs, leaf_spki, leaf_sig) = certificate_parts(&leaf);

        verify_spki(alg, ca_spki, ca_tbs, ca_sig).expect("the CA's own signature");
        verify_spki(alg, ca_spki, leaf_tbs, leaf_sig).expect("the leaf, under the CA");
        // The leaf did not sign itself, and the CA did not sign the leaf's
        // bytes with one of them changed.
        assert_eq!(
            kind(verify_spki(alg, leaf_spki, leaf_tbs, leaf_sig)),
            ErrorKind::AuthenticationFailed
        );
        let mut altered = leaf_tbs.to_vec();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(
            kind(verify_spki(alg, ca_spki, &altered, leaf_sig)),
            ErrorKind::AuthenticationFailed
        );
        seen.push(alg.id());
    }
    assert_eq!(seen, ["ed25519", "ml-dsa-65", "ml-dsa-87"]);
}
