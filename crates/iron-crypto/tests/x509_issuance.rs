//! Certificates issued by `ic_pkix::cert`, compared with OpenSSL's.
//!
//! Ed25519 signs deterministically, and ML-DSA can: with every input fixed --
//! keys, serials, names, validity, extensions -- a certificate is then a
//! function of its inputs, and two correct issuers must produce the same
//! bytes. `testvectors/openssl-x509.json` holds a CA and a leaf that OpenSSL
//! 3.5.7 issued for Ed25519, ML-DSA-65 and ML-DSA-87, with the commands that
//! made them. This issues the same six certificates here and requires them to
//! be byte for byte OpenSSL's.
//!
//! That checks every field this profile writes, its order, its DER, and the
//! signature over it, against an independent implementation -- which also
//! verified each chain under `-x509_strict` when it produced them. ECDSA
//! certificates cannot be compared this way, since the signature is random;
//! `docs/FIPS.md` records that those were verified by OpenSSL instead.

use ic_vectors::{hex, hex_field, VectorFile};
use iron_crypto::{ec, mldsa, pkix};
use pkix::cert::{
    write_certificate, write_ml_dsa_public_key, write_tbs_certificate, BasicConstraints,
    CertificateParams, ExtendedKeyUsage, KeyUsage, SignatureAlgorithm, SubjectAltName,
};

/// A key that can be embedded in a certificate and sign one.
trait Issuer {
    fn spki(&self, out: &mut [u8]) -> usize;
    fn sign(&self, tbs: &[u8], out: &mut [u8]) -> usize;
}

struct Ed(ec::Ed25519Key);

impl Issuer for Ed {
    fn spki(&self, out: &mut [u8]) -> usize {
        pkix::PublicKeyInfo::Ed25519(self.0.public_key())
            .to_der(out)
            .unwrap()
    }
    fn sign(&self, tbs: &[u8], out: &mut [u8]) -> usize {
        self.0.sign(tbs, &mut out[..64]).unwrap();
        64
    }
}

macro_rules! ml_dsa_issuer {
    ($name:ident, $m:ident, $alg:ident) => {
        struct $name {
            pk: [u8; mldsa::$m::PUBLIC_KEY_LEN],
            sk: [u8; mldsa::$m::SECRET_KEY_LEN],
        }
        impl $name {
            fn from_seed(seed: &[u8]) -> Self {
                let mut me = Self {
                    pk: [0; mldsa::$m::PUBLIC_KEY_LEN],
                    sk: [0; mldsa::$m::SECRET_KEY_LEN],
                };
                assert!(mldsa::$m::keygen(
                    seed.try_into().unwrap(),
                    &mut me.pk,
                    &mut me.sk
                ));
                me
            }
        }
        impl Issuer for $name {
            fn spki(&self, out: &mut [u8]) -> usize {
                write_ml_dsa_public_key(SignatureAlgorithm::$alg, &self.pk, out).unwrap()
            }
            fn sign(&self, tbs: &[u8], out: &mut [u8]) -> usize {
                let sig: &mut [u8; mldsa::$m::SIGNATURE_LEN] =
                    (&mut out[..mldsa::$m::SIGNATURE_LEN]).try_into().unwrap();
                // RFC 9881: the empty context string.
                assert!(mldsa::$m::sign_deterministic(&self.sk, tbs, b"", sig));
                mldsa::$m::SIGNATURE_LEN
            }
        }
    };
}
ml_dsa_issuer!(Dsa65, sign, MlDsa65);
ml_dsa_issuer!(Dsa87, sign87, MlDsa87);

/// Issue one certificate: TBS, signature, wrapper.
fn issue(params: &CertificateParams, alg: SignatureAlgorithm, issuer: &dyn Issuer) -> Vec<u8> {
    let mut tbs = vec![0u8; 16 * 1024];
    let n = write_tbs_certificate(params, alg, &mut tbs).unwrap();
    let mut sig = vec![0u8; 8 * 1024];
    let s = issuer.sign(&tbs[..n], &mut sig);
    let mut cert = vec![0u8; 16 * 1024];
    let c = write_certificate(&tbs[..n], alg, &sig[..s], &mut cert).unwrap();
    cert.truncate(c);
    cert
}

#[test]
fn issued_certificates_are_byte_for_byte_openssl_s() {
    let Some(file) = VectorFile::load_or_report("openssl-x509") else {
        return;
    };
    let mut checked = 0;
    for case in &file.cases {
        let (alg, ca, leaf): (_, Box<dyn Issuer>, Box<dyn Issuer>) =
            match case["algorithm"].as_str() {
                "ed25519" => (
                    SignatureAlgorithm::Ed25519,
                    Box::new(Ed(
                        ec::Ed25519Key::from_seed(&hex_field(case, "ca_seed")).unwrap()
                    )),
                    Box::new(Ed(
                        ec::Ed25519Key::from_seed(&hex_field(case, "leaf_seed")).unwrap()
                    )),
                ),
                "ml-dsa-65" => (
                    SignatureAlgorithm::MlDsa65,
                    Box::new(Dsa65::from_seed(&hex_field(case, "ca_seed"))),
                    Box::new(Dsa65::from_seed(&hex_field(case, "leaf_seed"))),
                ),
                "ml-dsa-87" => (
                    SignatureAlgorithm::MlDsa87,
                    Box::new(Dsa87::from_seed(&hex_field(case, "ca_seed"))),
                    Box::new(Dsa87::from_seed(&hex_field(case, "leaf_seed"))),
                ),
                other => panic!("unknown algorithm {other}"),
            };
        let name = case["algorithm"].clone();
        let not_before: u64 = case["not_before"].parse().unwrap();
        let not_after: u64 = case["not_after"].parse().unwrap();
        let ca_ski = hex_field(case, "ca_ski");
        let leaf_ski = hex_field(case, "leaf_ski");

        let mut ca_spki = vec![0u8; 4096];
        let n = ca.spki(&mut ca_spki);
        ca_spki.truncate(n);
        let ca_cert = issue(
            &CertificateParams {
                serial: &hex_field(case, "ca_serial"),
                issuer_common_name: "IronCrypto Test CA",
                subject_common_name: "IronCrypto Test CA",
                not_before,
                not_after,
                subject_public_key_info: &ca_spki,
                basic_constraints: BasicConstraints::Ca { path_len: Some(0) },
                key_usage: KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
                extended_key_usage: &[],
                subject_alt_names: &[],
                subject_key_id: Some(&ca_ski),
                authority_key_id: Some(&ca_ski),
            },
            alg,
            ca.as_ref(),
        );
        assert_eq!(hex(&ca_cert), hex(&hex_field(case, "ca_der")), "{name} CA");

        let mut leaf_spki = vec![0u8; 4096];
        let n = leaf.spki(&mut leaf_spki);
        leaf_spki.truncate(n);
        let leaf_cert = issue(
            &CertificateParams {
                serial: &hex_field(case, "leaf_serial"),
                issuer_common_name: "IronCrypto Test CA",
                subject_common_name: "sandbox.example",
                not_before,
                not_after,
                subject_public_key_info: &leaf_spki,
                basic_constraints: BasicConstraints::EndEntity,
                key_usage: KeyUsage::DIGITAL_SIGNATURE,
                extended_key_usage: &[ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
                subject_alt_names: &[
                    SubjectAltName::Dns("sandbox.example"),
                    SubjectAltName::Dns("*.sandbox.example"),
                    SubjectAltName::Ipv4([10, 0, 0, 7]),
                    SubjectAltName::Ipv6([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                ],
                subject_key_id: Some(&leaf_ski),
                authority_key_id: Some(&ca_ski),
            },
            alg,
            ca.as_ref(),
        );
        assert_eq!(
            hex(&leaf_cert),
            hex(&hex_field(case, "leaf_der")),
            "{name} leaf"
        );
        checked += 2;
    }
    assert_eq!(checked, 6, "a CA and a leaf for each of three algorithms");
}
