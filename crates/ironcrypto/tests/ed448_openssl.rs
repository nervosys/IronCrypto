//! Ed448 against keys and signatures OpenSSL made.
//!
//! `testvectors/openssl-ed448.json`, from `scripts/gen_ed448_vectors.py`:
//! four keys, three messages each. For every case:
//!
//! - the PKCS#8 reads as an Ed448 seed and the SubjectPublicKeyInfo as an
//!   Ed448 key, and each writes back to OpenSSL's bytes exactly;
//! - the seed derives OpenSSL's public key, and signs the message to
//!   OpenSSL's signature byte for byte -- Ed448 is deterministic;
//! - `ic_sig::verify` accepts it under `Ed448`, refuses it under another
//!   algorithm as the caller's error, and refuses it for another message as a
//!   failed signature;
//! - `SoftwareSigner` reads the key, reports OpenSSL's public key and signs
//!   to the same bytes.
//!
//! RFC 8032's own vectors hold the algorithm, in `ic_ec`; these hold the key
//! encodings and agreement with a second implementation on keys the RFC did
//! not choose.

use ic_core::sig::{SignatureAlgorithm, Signer};
#[cfg(not(ic_approved_only))]
use ic_core::traits::SignatureScheme;
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::pkix::{KeyAlgorithm, PrivateKeyInfo, PublicKeyInfo};
use ironcrypto::sig::{verify_spki, SoftwareSigner};

#[test]
fn ed448_matches_openssl() {
    let Some(file) = VectorFile::load_or_report("openssl-ed448") else {
        return;
    };
    assert_eq!(file.cases.len(), 12, "four keys, three messages each");
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x48; 48], b"ed448 test").unwrap();
    for (i, case) in file.cases.iter().enumerate() {
        let (pkcs8, spki, message, signature) = (
            hex_field(case, "pkcs8"),
            hex_field(case, "spki"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );

        // The encodings, both ways.
        let private = PrivateKeyInfo::from_der(&pkcs8).unwrap();
        let PrivateKeyInfo::Ed448(seed) = private else {
            panic!("case {i}: not read as Ed448: {private:?}");
        };
        assert_eq!(private.algorithm(), KeyAlgorithm::Ed448);
        let mut out = [0u8; 128];
        let n = private.to_der(&mut out).unwrap();
        assert_eq!(&out[..n], &pkcs8[..], "case {i}: pkcs#8 written back");

        let public = PublicKeyInfo::from_der(&spki).unwrap();
        let PublicKeyInfo::Ed448(raw_public) = public else {
            panic!("case {i}: not read as Ed448: {public:?}");
        };
        let n = public.to_der(&mut out).unwrap();
        assert_eq!(&out[..n], &spki[..], "case {i}: spki written back");

        if cfg!(ic_approved_only) {
            // Nothing below that would use the key runs in this build.
            let _ = (seed, raw_public);
            // Not in this build, and refused as that.
            assert_eq!(
                SoftwareSigner::from_pkcs8(&pkcs8).unwrap_err().kind(),
                ErrorKind::NotApprovedInFipsMode
            );
            assert_eq!(
                verify_spki(SignatureAlgorithm::Ed448, &spki, &message, &signature)
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotApprovedInFipsMode
            );
            continue;
        }

        #[cfg(not(ic_approved_only))]
        {
            // The algorithm, against OpenSSL's values.
            let mut derived = [0u8; 57];
            ironcrypto::ec::Ed448::public_key(seed, &mut derived).unwrap();
            assert_eq!(&derived[..], raw_public, "case {i}: public key");
            let mut sig = [0u8; 114];
            ironcrypto::ec::Ed448::sign(seed, &message, &mut sig).unwrap();
            assert_eq!(hex(&sig), case["signature"], "case {i}: signature");
        }

        // Verification through the dispatch.
        verify_spki(SignatureAlgorithm::Ed448, &spki, &message, &signature)
            .unwrap_or_else(|e| panic!("case {i}: {e:?}"));
        let mut other = message.clone();
        other.push(0);
        assert_eq!(
            verify_spki(SignatureAlgorithm::Ed448, &spki, &other, &signature)
                .unwrap_err()
                .kind(),
            ErrorKind::AuthenticationFailed
        );
        for &wrong in [
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::MlDsa87,
            SignatureAlgorithm::EcdsaP384Sha384,
        ]
        .iter()
        {
            assert_eq!(
                verify_spki(wrong, &spki, &message, &signature)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidParameter,
                "case {i}: {}",
                wrong.id()
            );
        }

        // Signing through the interface.
        let signer = SoftwareSigner::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(hex(signer.public_key()), case["spki"], "case {i}");
        assert_eq!(signer.algorithms(), [SignatureAlgorithm::Ed448]);
        let mut out = vec![0u8; SignatureAlgorithm::Ed448.max_signature_len()];
        let len = signer
            .sign(SignatureAlgorithm::Ed448, &message, &mut rng, &mut out)
            .unwrap();
        assert_eq!(hex(&out[..len]), case["signature"], "case {i}: signer");
    }
}

/// An Ed448 key is 57 bytes in both forms; one byte short or long is refused
/// as malformed rather than read as something else.
#[test]
fn ed448_keys_of_the_wrong_length_are_refused() {
    let Some(file) = VectorFile::load_or_report("openssl-ed448") else {
        return;
    };
    let case = &file.cases[0];
    let (pkcs8, spki) = (hex_field(case, "pkcs8"), hex_field(case, "spki"));
    // SPKI: 30 43 | 30 05 06 03 2b6571 | 03 3a 00 <57 bytes>, the BIT
    // STRING's length at offset 10. PKCS#8: 30 47 | 02 01 00 | 30 05 06 03
    // 2b6571 | 04 3b 04 39 <57 bytes>, the two OCTET STRING lengths at 13 and
    // 15. Checked first, so a malformed input below is refused for its key
    // length and not because the edit broke something else.
    assert_eq!(
        &spki[..11],
        &[0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a]
    );
    assert_eq!(
        &pkcs8[..16],
        &[
            0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x04, 0x3b,
            0x04, 0x39
        ]
    );
    for delta in [-1i32, 1] {
        let resize = |der: &[u8], at: &[usize]| {
            let mut v = der.to_vec();
            if delta < 0 {
                v.pop();
            } else {
                v.push(0);
            }
            for &i in at {
                v[i] = (i32::from(v[i]) + delta) as u8;
            }
            v
        };
        assert_eq!(
            PublicKeyInfo::from_der(&resize(&spki, &[1, 10]))
                .unwrap_err()
                .kind(),
            ErrorKind::MalformedEncoding,
            "spki key {delta:+} byte"
        );
        assert_eq!(
            PrivateKeyInfo::from_der(&resize(&pkcs8, &[1, 13, 15]))
                .unwrap_err()
                .kind(),
            ErrorKind::MalformedEncoding,
            "pkcs#8 key {delta:+} byte"
        );
    }
    // And writing refuses a key of the wrong length.
    let mut out = [0u8; 128];
    assert!(PublicKeyInfo::Ed448(&[0u8; 56]).to_der(&mut out).is_err());
    assert!(PrivateKeyInfo::Ed448(&[0u8; 58]).to_der(&mut out).is_err());
}
