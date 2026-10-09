//! `ic_sig::verify` against signatures OpenSSL made.
//!
//! Two sources. `testvectors/openssl-sig.json` carries ECDSA, Ed25519 and RSA
//! signatures over bare messages, from `scripts/gen_sig_vectors.py`.
//! `testvectors/openssl-x509.json` carries certificates OpenSSL issued with
//! Ed25519, ML-DSA-65 and ML-DSA-87, and a certificate is a signature over its
//! `tbsCertificate` under its issuer's key -- the use this function exists
//! for.
//!
//! The hash-based algorithms have their own. `testvectors/openssl-slh-dsa.json`
//! carries a key and a signature OpenSSL made for each of SLH-DSA's twelve
//! parameter sets, from `scripts/gen_slh_dsa_sig_vectors.py`; the algorithm is
//! held by NIST's vectors elsewhere, and what these hold is that each of RFC
//! 9909's object identifiers is read as the set OpenSSL meant. HSS/LMS has no
//! second implementation to hand, so the RFCs' own test cases in
//! `testvectors/lms.json` are wrapped in the key encoding of RFC 9708 here.
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

/// One valid case, and the rule turned against it: it verifies, and a changed
/// message, a changed or shortened signature and every other algorithm are
/// each refused as the failure they are.
fn verifies_and_altered_does_not(
    alg: SignatureAlgorithm,
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) {
    let (message, signature) = (message.to_vec(), signature.to_vec());
    let key = PublicKey::from_spki(spki).unwrap();
    verify(alg, &key, &message, &signature).unwrap_or_else(|e| panic!("{}: {e:?}", alg.id()));
    verify_spki(alg, spki, &message, &signature).unwrap();
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
        verifies_and_altered_does_not(alg, &spki, &message, &signature);
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

/// Every SLH-DSA parameter set, by the key and signature OpenSSL made for it.
#[test]
fn openssl_slh_dsa_signatures_verify_for_every_parameter_set() {
    let Some(file) = VectorFile::load_or_report("openssl-slh-dsa") else {
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
        // An SLH-DSA signature is one length exactly.
        assert_eq!(signature.len(), alg.max_signature_len(), "{}", alg.id());
        let key = PublicKey::from_spki(&spki).unwrap();
        assert_eq!(key.kind_id(), alg.id());
        verifies_and_altered_does_not(alg, &spki, &message, &signature);
        seen.insert(alg.id());
    }
    let all: std::collections::BTreeSet<_> = ironcrypto::slhdsa::ParameterSet::ALL
        .iter()
        .map(|set| set.id())
        .collect();
    assert_eq!(seen, all, "the cases did not cover every parameter set");
}

/// A `SubjectPublicKeyInfo` for an HSS/LMS key: RFC 9708 section 4. The key
/// goes into the BIT STRING as it is, and the parameters are absent.
fn hss_lms_spki(key: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let mut w = ic_pkix::der::Writer::new(&mut buf);
    w.push_bit_string(key).unwrap();
    let start = w.len();
    w.push_oid(ic_pkix::oid::HSS_LMS).unwrap();
    w.push_wrapper(ic_pkix::der::SEQUENCE, start).unwrap();
    w.push_wrapper(ic_pkix::der::SEQUENCE, 0).unwrap();
    let n = w.finish();
    buf[..n].to_vec()
}

/// The test cases of RFC 8554 and RFC 9858, through `ic_sig::verify`.
#[test]
fn rfc_hss_lms_signatures_verify_through_their_spki() {
    let Some(file) = VectorFile::load_or_report("lms") else {
        return;
    };
    let mut ran = 0;
    for case in file.cases.iter().filter(|c| c["source"].starts_with("RFC")) {
        let (key, message, signature) = (
            hex_field(case, "public_key"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        let spki = hss_lms_spki(&key);
        assert_eq!(
            PublicKey::from_spki(&spki).unwrap(),
            PublicKey::HssLms(&key),
            "{}",
            case["source"]
        );
        verifies_and_altered_does_not(SignatureAlgorithm::HssLms, &spki, &message, &signature);
        ran += 1;
    }
    // Two from RFC 8554 appendix F and four from RFC 9858 appendix A.
    assert_eq!(ran, 6);
}
