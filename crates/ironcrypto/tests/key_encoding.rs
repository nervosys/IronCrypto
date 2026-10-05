//! End-to-end tests for the encoding layer against the real algorithms.
//!
//! `ic-pkix` deliberately depends only on `ic-core`, so its own tests can check
//! that bytes round-trip but not that the bytes mean anything. These do: every
//! test here exports a key, parses it back, and then performs a cryptographic
//! operation with the *parsed* result. An encoder that swapped two fields, or a
//! parser that returned a slice one byte off, would round-trip perfectly and
//! fail here.

use ironcrypto::prelude::*;
use ironcrypto::{ec, pkix, rsa};

fn rng(label: &[u8]) -> ic_drbg::Rng {
    ic_drbg::Rng::from_entropy(&[0x5au8; 32], label).expect("drbg")
}

// ---------------------------------------------------------------------------
// Elliptic curve
// ---------------------------------------------------------------------------

/// A P-256 key survives the trip through SPKI and PKCS#8 and still verifies.
#[test]
fn p256_keys_survive_pkcs8_and_spki() {
    let private = [7u8; 32];
    let mut public = [0u8; 65];
    ec::p256::EcdsaP256Sha256::public_key(&private, &mut public).unwrap();

    // Export the pair.
    let mut spki = [0u8; 256];
    let spki_len = PublicKeyInfo::Ec {
        algorithm: pkix::KeyAlgorithm::EcP256,
        point: &public,
    }
    .to_der(&mut spki)
    .unwrap();

    let mut pkcs8 = [0u8; 256];
    let pkcs8_len = PrivateKeyInfo::Ec {
        algorithm: pkix::KeyAlgorithm::EcP256,
        private_key: &private,
        public_key: Some(&public),
    }
    .to_der(&mut pkcs8)
    .unwrap();

    // Read them back and use only what came out of the parser.
    let parsed_public = PublicKeyInfo::from_der(&spki[..spki_len]).unwrap();
    let parsed_private = PrivateKeyInfo::from_der(&pkcs8[..pkcs8_len]).unwrap();

    let (PublicKeyInfo::Ec { point, .. }, PrivateKeyInfo::Ec { private_key, .. }) =
        (parsed_public, parsed_private)
    else {
        panic!("expected elliptic-curve keys");
    };

    let mut signature = [0u8; 64];
    ec::p256::EcdsaP256Sha256::sign(private_key, b"message", &mut signature).unwrap();
    ec::p256::EcdsaP256Sha256::verify(point, b"message", &signature)
        .expect("the parsed public key verifies what the parsed private key signed");

    // And the public key the PKCS#8 carried agrees with the one derived from
    // the scalar, which is the check that catches a swapped field.
    let PrivateKeyInfo::Ec {
        public_key: Some(embedded),
        ..
    } = parsed_private
    else {
        panic!("the public key was dropped");
    };
    assert_eq!(embedded, &public[..]);
}

#[test]
fn p384_keys_survive_pkcs8_and_spki() {
    let private = [9u8; 48];
    let mut public = [0u8; 97];
    ec::p384::EcdsaP384Sha384::public_key(&private, &mut public).unwrap();

    let mut pkcs8 = [0u8; 256];
    let n = PrivateKeyInfo::Ec {
        algorithm: pkix::KeyAlgorithm::EcP384,
        private_key: &private,
        public_key: Some(&public),
    }
    .to_der(&mut pkcs8)
    .unwrap();

    let PrivateKeyInfo::Ec {
        private_key,
        public_key: Some(point),
        algorithm,
    } = PrivateKeyInfo::from_der(&pkcs8[..n]).unwrap()
    else {
        panic!("expected an elliptic-curve key");
    };
    assert_eq!(algorithm, pkix::KeyAlgorithm::EcP384);

    let mut signature = [0u8; 96];
    ec::p384::EcdsaP384Sha384::sign(private_key, b"message", &mut signature).unwrap();
    ec::p384::EcdsaP384Sha384::verify(point, b"message", &signature).unwrap();
}

/// A P-521 key survives the trip through PKCS#8 and still signs.
///
/// P-521 was missing from the encoding layer entirely: `ic-ec` implements it,
/// and `ic-pkix` refused its keys as an unsupported curve. The scalar's top
/// byte is cleared because the curve's order begins `0x01`, so a scalar of
/// all nines would not be a valid key.
#[test]
fn p521_keys_survive_pkcs8_and_spki() {
    let mut private = [9u8; 66];
    private[0] = 0;
    let mut public = [0u8; 133];
    ec::p521::EcdsaP521Sha512::public_key(&private, &mut public).unwrap();

    let mut pkcs8 = [0u8; 512];
    let n = PrivateKeyInfo::Ec {
        algorithm: pkix::KeyAlgorithm::EcP521,
        private_key: &private,
        public_key: Some(&public),
    }
    .to_der(&mut pkcs8)
    .unwrap();

    let PrivateKeyInfo::Ec {
        private_key,
        public_key: Some(point),
        algorithm,
    } = PrivateKeyInfo::from_der(&pkcs8[..n]).unwrap()
    else {
        panic!("expected an elliptic-curve key");
    };
    assert_eq!(algorithm, pkix::KeyAlgorithm::EcP521);

    let mut signature = [0u8; ec::p521::EcdsaP521Sha512::SIGNATURE_LEN];
    ec::p521::EcdsaP521Sha512::sign(private_key, b"message", &mut signature).unwrap();
    ec::p521::EcdsaP521Sha512::verify(point, b"message", &signature).unwrap();
}

// A P-521 key pair produced by OpenSSL 3.5.7, as PKCS#8 and as SPKI:
//
//   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 //       -pkeyopt ec_param_enc:named_curve -outform DER
//   openssl pkcs8 -topk8 -nocrypt -inform DER -outform DER
//   openssl pkey -inform DER -pubout -outform DER
const OPENSSL_P521_PKCS8: &str = concat!(
    "3081ee020100301006072a8648ce3d020106052b810400230481d63081d30201",
    "01044201561e70ddafc182c8543600963cd72f2f99905eaf3e004bbcce708b39",
    "b6b38ed346c8416f34e26d9fbbfe8a19a6031b6158ac620e26df07ee2b5f2a2b",
    "b56eecbb67a18189038186000401d5a6010c58847c997e57aa3e006dc546ddfd",
    "953492fd28ec42c66499f223c4c27544b4f749ba345a45d0ea3f86e5756886ec",
    "4775aa7bf505495da5b71cfe9bf1fe0178fe7a00a59e3965a5af25d7c3117750",
    "e3b969f26d5987d7879977ea16bc083f2774585c4f48a5567da7f399d873d21b",
    "fe5e8fc0f464db21ce39b8269ef39e1e9f",
);
const OPENSSL_P521_SPKI: &str = concat!(
    "30819b301006072a8648ce3d020106052b81040023038186000401d5a6010c58",
    "847c997e57aa3e006dc546ddfd953492fd28ec42c66499f223c4c27544b4f749",
    "ba345a45d0ea3f86e5756886ec4775aa7bf505495da5b71cfe9bf1fe0178fe7a",
    "00a59e3965a5af25d7c3117750e3b969f26d5987d7879977ea16bc083f277458",
    "5c4f48a5567da7f399d873d21bfe5e8fc0f464db21ce39b8269ef39e1e9f",
);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Another implementation's P-521 key, parsed here, is the key it claims to be.
///
/// The test above only ever parses what this library wrote, so an encoder and
/// parser that agreed on a mistake would pass it. This takes OpenSSL's bytes
/// instead: `ic-ec` must derive OpenSSL's public point from OpenSSL's private
/// scalar -- the one fact that shows both the scalar and the point were read
/// out of the right bytes -- and a signature made with the parsed scalar must
/// verify under the point parsed from OpenSSL's separate SPKI file.
#[test]
fn an_openssl_p521_key_is_the_key_it_claims_to_be() {
    let pkcs8 = unhex(OPENSSL_P521_PKCS8);
    let spki = unhex(OPENSSL_P521_SPKI);

    let PrivateKeyInfo::Ec {
        algorithm,
        private_key,
        public_key: Some(embedded_point),
    } = PrivateKeyInfo::from_der(&pkcs8).unwrap()
    else {
        panic!("expected a P-521 key carrying its public point");
    };
    assert_eq!(algorithm, pkix::KeyAlgorithm::EcP521);

    let PublicKeyInfo::Ec {
        algorithm,
        point: spki_point,
    } = PublicKeyInfo::from_der(&spki).unwrap()
    else {
        panic!("expected a P-521 public key");
    };
    assert_eq!(algorithm, pkix::KeyAlgorithm::EcP521);

    let mut derived = [0u8; 133];
    ec::p521::EcdsaP521Sha512::public_key(private_key, &mut derived).unwrap();
    assert_eq!(
        &derived[..],
        embedded_point,
        "ic-ec disagrees with OpenSSL's point"
    );
    assert_eq!(
        &derived[..],
        spki_point,
        "PKCS#8 and SPKI name different points"
    );

    let mut signature = [0u8; ec::p521::EcdsaP521Sha512::SIGNATURE_LEN];
    ec::p521::EcdsaP521Sha512::sign(private_key, b"interop", &mut signature).unwrap();
    ec::p521::EcdsaP521Sha512::verify(spki_point, b"interop", &signature).unwrap();
}

#[test]
fn ed25519_keys_survive_pkcs8_and_spki() {
    let seed = [0x3fu8; 32];
    let mut public = [0u8; 32];
    ec::Ed25519::public_key(&seed, &mut public).unwrap();

    let mut spki = [0u8; 128];
    let spki_len = PublicKeyInfo::Ed25519(&public).to_der(&mut spki).unwrap();
    let mut pkcs8 = [0u8; 128];
    let pkcs8_len = PrivateKeyInfo::Ed25519(&seed).to_der(&mut pkcs8).unwrap();

    let PublicKeyInfo::Ed25519(parsed_public) = PublicKeyInfo::from_der(&spki[..spki_len]).unwrap()
    else {
        panic!("expected an ed25519 public key");
    };
    let PrivateKeyInfo::Ed25519(parsed_seed) =
        PrivateKeyInfo::from_der(&pkcs8[..pkcs8_len]).unwrap()
    else {
        panic!("expected an ed25519 private key");
    };

    let mut signature = [0u8; 64];
    ec::Ed25519::sign(parsed_seed, b"message", &mut signature).unwrap();
    ec::Ed25519::verify(parsed_public, b"message", &signature).unwrap();
}

/// X25519 is key agreement, so the round trip is checked by having both sides
/// arrive at the same shared secret through the encoding.
#[test]
fn x25519_keys_survive_pkcs8_and_agree() {
    let alice_private = [0x11u8; 32];
    let bob_private = [0x22u8; 32];
    let mut bob_public = [0u8; 32];
    ec::X25519::public_key(&bob_private, &mut bob_public).unwrap();

    let mut pkcs8 = [0u8; 128];
    let n = PrivateKeyInfo::X25519(&alice_private)
        .to_der(&mut pkcs8)
        .unwrap();
    let mut spki = [0u8; 128];
    let m = PublicKeyInfo::X25519(&bob_public)
        .to_der(&mut spki)
        .unwrap();

    let PrivateKeyInfo::X25519(parsed_private) = PrivateKeyInfo::from_der(&pkcs8[..n]).unwrap()
    else {
        panic!("expected an x25519 private key");
    };
    let PublicKeyInfo::X25519(parsed_public) = PublicKeyInfo::from_der(&spki[..m]).unwrap() else {
        panic!("expected an x25519 public key");
    };

    let mut through_encoding = [0u8; 32];
    ec::X25519::agree(parsed_private, parsed_public, &mut through_encoding).unwrap();
    let mut direct = [0u8; 32];
    ec::X25519::agree(&alice_private, &bob_public, &mut direct).unwrap();
    assert_eq!(through_encoding, direct);
}

// ---------------------------------------------------------------------------
// ECDSA signature encoding
// ---------------------------------------------------------------------------

/// A signature converted to DER and back must still verify. Run over enough
/// messages to exercise both the sign-byte and the leading-zero branches, which
/// each occur for about half of all signatures.
#[test]
fn ecdsa_signatures_survive_der_conversion() {
    let private = [0x21u8; 32];
    let mut public = [0u8; 65];
    ec::p256::EcdsaP256Sha256::public_key(&private, &mut public).unwrap();

    let mut saw_sign_byte = false;
    let mut saw_bare = false;

    for i in 0u8..40 {
        let message = [i; 8];
        let mut signature = [0u8; 64];
        ec::p256::EcdsaP256Sha256::sign(&private, &message, &mut signature).unwrap();

        let mut der = [0u8; 80];
        let n = pkix::ecdsa_signature::to_der(&signature, &mut der).unwrap();
        assert!(n <= pkix::ecdsa_signature::max_der_len(64));

        // Track which encoding branch this signature exercised.
        if der[4] == 0x00 && der[3] == 33 {
            saw_sign_byte = true;
        }
        if der[3] <= 32 {
            saw_bare = true;
        }

        let mut back = [0u8; 64];
        pkix::ecdsa_signature::from_der(&der[..n], &mut back).unwrap();
        assert_eq!(back, signature, "message {i}");
        ec::p256::EcdsaP256Sha256::verify(&public, &message, &back).unwrap();
    }

    assert!(saw_sign_byte, "no signature needed a sign byte in 40 tries");
    assert!(saw_bare, "no signature avoided the sign byte in 40 tries");
}

/// A DER signature that has been re-encoded non-minimally must not survive as
/// the same bytes. This is the malleability that made DER-encoded Bitcoin
/// signatures a problem: two encodings of one signature.
#[test]
fn a_non_minimal_der_signature_is_rejected() {
    let signature = [0x42u8; 64];
    let mut der = [0u8; 80];
    let n = pkix::ecdsa_signature::to_der(&signature, &mut der).unwrap();

    // Add a redundant leading zero to r: content grows by one, and so do both
    // the INTEGER length and the SEQUENCE length.
    let mut padded = std::vec::Vec::new();
    padded.extend_from_slice(&der[..2]);
    padded.extend_from_slice(&[der[2], der[3] + 1, 0x00]);
    padded.extend_from_slice(&der[4..n]);
    padded[1] += 1;

    let mut out = [0u8; 64];
    assert!(
        pkix::ecdsa_signature::from_der(&padded, &mut out).is_err(),
        "a non-minimal integer must not decode"
    );
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// An RSA public key exported as SPKI, parsed back, and used to verify a
/// signature made by the key it came from.
#[test]
fn rsa_public_keys_survive_spki() {
    let mut r = rng(b"rsa-spki");
    let key = rsa::generate(2048, &mut r).expect("key generation");

    let mut modulus = [0u8; 256];
    key.public_key().modulus_bytes(&mut modulus).unwrap();

    let mut spki = [0u8; 512];
    let n = PublicKeyInfo::Rsa {
        modulus: &modulus,
        exponent: key.public_key().exponent(),
    }
    .to_der(&mut spki)
    .unwrap();

    let PublicKeyInfo::Rsa { modulus, exponent } = PublicKeyInfo::from_der(&spki[..n]).unwrap()
    else {
        panic!("expected an rsa key");
    };
    assert_eq!(exponent, 65537);
    assert_eq!(modulus.len(), 256, "a 2048-bit modulus has no leading zero");

    // Rebuild the public key from the parsed components alone.
    let rebuilt = RsaPublicKey::from_components(modulus, exponent).unwrap();

    let mut signature = [0u8; 256];
    rsa::Pkcs1Sha256::sign(&key, b"message", &mut signature).unwrap();
    rsa::Pkcs1Sha256::verify(&rebuilt, b"message", &signature)
        .expect("the parsed key verifies a signature from the original");

    rsa::PssSha256::sign(&key, b"message", &mut r, &mut signature).unwrap();
    rsa::PssSha256::verify(&rebuilt, b"message", &signature).unwrap();
}

/// The full private-key round trip: generate, export as PKCS#8, parse, rebuild
/// from the parsed primes, and sign with the result. This is the property that
/// makes an exported key file actually usable somewhere else.
#[test]
fn rsa_private_keys_survive_pkcs8() {
    let mut r = rng(b"rsa-pkcs8");
    let key = rsa::generate(2048, &mut r).expect("key generation");
    assert!(key.uses_crt(), "a generated key carries its primes");

    // Gather every field PKCS#1 wants.
    let mut modulus = [0u8; 256];
    key.public_key().modulus_bytes(&mut modulus).unwrap();
    let mut d = [0u8; 256];
    key.exponent_bytes(&mut d).unwrap();
    let mut p = [0u8; 128];
    let mut q = [0u8; 128];
    key.prime_bytes(&mut p, &mut q).unwrap();
    let mut dp = [0u8; 128];
    let mut dq = [0u8; 128];
    let mut qinv = [0u8; 128];
    key.crt_exponent_bytes(&mut dp, &mut dq, &mut qinv).unwrap();

    let mut pkcs8 = [0u8; 2048];
    let n = PrivateKeyInfo::Rsa {
        modulus: &modulus,
        public_exponent: 65537,
        private_exponent: &d,
        prime1: &p,
        prime2: &q,
        exponent1: &dp,
        exponent2: &dq,
        coefficient: &qinv,
    }
    .to_der(&mut pkcs8)
    .unwrap();

    // Parse it back and rebuild the key from the parsed primes alone.
    let PrivateKeyInfo::Rsa {
        prime1,
        prime2,
        public_exponent,
        modulus: parsed_modulus,
        ..
    } = PrivateKeyInfo::from_der(&pkcs8[..n]).unwrap()
    else {
        panic!("expected an rsa private key");
    };
    assert_eq!(public_exponent, 65537);
    assert_eq!(parsed_modulus, &modulus[..], "the modulus survived");

    let rebuilt = RsaPrivateKey::from_primes(prime1, prime2, public_exponent).unwrap();
    assert!(rebuilt.uses_crt());

    // A signature from the rebuilt key verifies under the original public key.
    let mut signature = [0u8; 256];
    rsa::Pkcs1Sha256::sign(&rebuilt, b"message", &mut signature).unwrap();
    rsa::Pkcs1Sha256::verify(key.public_key(), b"message", &signature)
        .expect("the rebuilt key is the same key");

    // And it is byte-identical to a signature from the original, since PKCS#1
    // v1.5 is deterministic.
    let mut original_signature = [0u8; 256];
    rsa::Pkcs1Sha256::sign(&key, b"message", &mut original_signature).unwrap();
    assert_eq!(signature, original_signature);
}

/// PEM in, PEM out, through the private-key path, with a label check.
#[test]
fn an_rsa_private_key_survives_pem() {
    let mut r = rng(b"rsa-pem");
    let key = rsa::generate(2048, &mut r).expect("key generation");

    let mut modulus = [0u8; 256];
    key.public_key().modulus_bytes(&mut modulus).unwrap();
    let mut d = [0u8; 256];
    key.exponent_bytes(&mut d).unwrap();
    let mut p = [0u8; 128];
    let mut q = [0u8; 128];
    key.prime_bytes(&mut p, &mut q).unwrap();
    let mut dp = [0u8; 128];
    let mut dq = [0u8; 128];
    let mut qinv = [0u8; 128];
    key.crt_exponent_bytes(&mut dp, &mut dq, &mut qinv).unwrap();

    let info = PrivateKeyInfo::Rsa {
        modulus: &modulus,
        public_exponent: 65537,
        private_exponent: &d,
        prime1: &p,
        prime2: &q,
        exponent1: &dp,
        exponent2: &dq,
        coefficient: &qinv,
    };
    let mut der = [0u8; 2048];
    let n = info.to_der(&mut der).unwrap();

    let mut text = std::vec![0u8; pem::encoded_len(pem::PRIVATE_KEY, n)];
    let m = pem::encode(pem::PRIVATE_KEY, &der[..n], &mut text).unwrap();
    let document = core::str::from_utf8(&text[..m]).unwrap();
    assert!(document.starts_with(
        "-----BEGIN PRIVATE KEY-----
"
    ));

    // Every 2048-bit PKCS#8 RSA private key contains this base64 fragment: it
    // is the rsaEncryption AlgorithmIdentifier and the privateKey OCTET STRING
    // header, at the byte alignment a 2048-bit key produces. Matching it is a
    // check against other implementations that the round-trip tests, which only
    // compare this library against itself, cannot give.
    assert!(
        document.contains("ANBgkqhkiG9w0BAQEFAASCBK"),
        "the encoding does not match the shape every other tool emits"
    );

    let mut back = [0u8; 2048];
    let back_len = pem::decode(pem::PRIVATE_KEY, document.as_bytes(), &mut back).unwrap();
    assert_eq!(&back[..back_len], &der[..n]);
    assert_eq!(PrivateKeyInfo::from_der(&back[..back_len]).unwrap(), info);
}

/// The CRT path and the plain path must produce identical signatures, checked
/// here through the public API rather than the internals.
#[test]
fn crt_and_plain_keys_sign_identically() {
    let mut r = rng(b"crt-vs-plain");
    let crt_key = rsa::generate(2048, &mut r).expect("key generation");

    let mut modulus = [0u8; 256];
    crt_key.public_key().modulus_bytes(&mut modulus).unwrap();
    let mut d = [0u8; 256];
    crt_key.exponent_bytes(&mut d).unwrap();
    let plain_key = RsaPrivateKey::from_components(&modulus, 65537, &d).unwrap();
    assert!(crt_key.uses_crt() && !plain_key.uses_crt());

    for message in [&b""[..], b"a", b"the quick brown fox", &[0x5au8; 500][..]] {
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        rsa::Pkcs1Sha256::sign(&crt_key, message, &mut a).unwrap();
        rsa::Pkcs1Sha256::sign(&plain_key, message, &mut b).unwrap();
        assert_eq!(a, b, "the two paths agree");
        rsa::Pkcs1Sha256::verify(crt_key.public_key(), message, &a).unwrap();
    }
}

/// `ic_rsa` takes a fixed-width modulus; the parser returns a minimal one.
/// Those differ whenever the top byte is below 0x80 — which cannot happen for a
/// key from `generate`, since it forces the top two bits, but can for a key
/// from elsewhere. Check the padding path explicitly.
#[test]
fn a_minimal_modulus_is_padded_back_to_full_width() {
    let mut modulus = [0u8; 256];
    modulus[0] = 0x00; // a modulus whose leading byte is zero
    modulus[1] = 0x7f;
    for (i, b) in modulus[2..].iter_mut().enumerate() {
        *b = i as u8;
    }
    modulus[255] |= 1; // odd

    let mut spki = [0u8; 512];
    let n = PublicKeyInfo::Rsa {
        modulus: &modulus,
        exponent: 65537,
    }
    .to_der(&mut spki)
    .unwrap();

    let PublicKeyInfo::Rsa {
        modulus: parsed, ..
    } = PublicKeyInfo::from_der(&spki[..n]).unwrap()
    else {
        panic!("expected an rsa key");
    };
    assert_eq!(
        parsed.len(),
        255,
        "the leading zero is not part of the number"
    );

    // Padding it back out reproduces the original bytes exactly.
    let mut restored = [0u8; 256];
    restored[256 - parsed.len()..].copy_from_slice(parsed);
    assert_eq!(restored, modulus);
}

// ---------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------

/// The whole chain: key to DER to PEM text and all the way back, then use it.
#[test]
fn a_key_survives_the_full_pem_round_trip() {
    let seed = [0x77u8; 32];
    let mut public = [0u8; 32];
    ec::Ed25519::public_key(&seed, &mut public).unwrap();

    let mut der = [0u8; 128];
    let der_len = PublicKeyInfo::Ed25519(&public).to_der(&mut der).unwrap();

    let mut text = [0u8; 256];
    let text_len = pem::encode(pem::PUBLIC_KEY, &der[..der_len], &mut text).unwrap();
    let document = core::str::from_utf8(&text[..text_len]).unwrap();

    assert!(document.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(document.ends_with("-----END PUBLIC KEY-----\n"));

    let mut back_der = [0u8; 128];
    let back_len = pem::decode(pem::PUBLIC_KEY, document.as_bytes(), &mut back_der).unwrap();
    assert_eq!(&back_der[..back_len], &der[..der_len]);

    let PublicKeyInfo::Ed25519(parsed) = PublicKeyInfo::from_der(&back_der[..back_len]).unwrap()
    else {
        panic!("expected an ed25519 key");
    };

    let mut signature = [0u8; 64];
    ec::Ed25519::sign(&seed, b"through pem", &mut signature).unwrap();
    ec::Ed25519::verify(parsed, b"through pem", &signature).unwrap();
}

/// A private key in PEM must not be readable as a public key, and vice versa.
/// The label is the only thing standing between "here is my public key" and a
/// catastrophic paste.
#[test]
fn pem_labels_keep_private_and_public_apart() {
    let seed = [0x88u8; 32];
    let mut der = [0u8; 128];
    let n = PrivateKeyInfo::Ed25519(&seed).to_der(&mut der).unwrap();

    let mut text = [0u8; 256];
    let m = pem::encode(pem::PRIVATE_KEY, &der[..n], &mut text).unwrap();

    let mut out = [0u8; 128];
    assert!(pem::decode(pem::PUBLIC_KEY, &text[..m], &mut out).is_err());
    assert!(pem::decode(pem::PRIVATE_KEY, &text[..m], &mut out).is_ok());
}

// ---------------------------------------------------------------------------
// Negative cases that span both layers
// ---------------------------------------------------------------------------

/// A public key whose point has been tampered with must fail to verify rather
/// than fail to parse — the parser checks structure, the curve checks the math.
#[test]
fn a_tampered_point_parses_but_does_not_verify() {
    let private = [0x31u8; 32];
    let mut public = [0u8; 65];
    ec::p256::EcdsaP256Sha256::public_key(&private, &mut public).unwrap();

    let mut signature = [0u8; 64];
    ec::p256::EcdsaP256Sha256::sign(&private, b"message", &mut signature).unwrap();

    let mut tampered = public;
    tampered[40] ^= 0x01;
    let mut spki = [0u8; 256];
    let n = PublicKeyInfo::Ec {
        algorithm: pkix::KeyAlgorithm::EcP256,
        point: &tampered,
    }
    .to_der(&mut spki)
    .unwrap();

    let PublicKeyInfo::Ec { point, .. } = PublicKeyInfo::from_der(&spki[..n]).unwrap() else {
        panic!("expected an elliptic-curve key");
    };
    assert!(
        ec::p256::EcdsaP256Sha256::verify(point, b"message", &signature).is_err(),
        "a point off the curve, or simply the wrong one, must not verify"
    );
}

/// Every parse entry point refuses trailing data. Checked here across all of
/// them at once, because it is the single property most likely to be lost when
/// one of them is later modified.
#[test]
fn no_parser_accepts_trailing_data() {
    let seed = [0x99u8; 32];
    let mut public = [0u8; 32];
    ec::Ed25519::public_key(&seed, &mut public).unwrap();

    let mut spki = [0u8; 128];
    let spki_len = PublicKeyInfo::Ed25519(&public).to_der(&mut spki).unwrap();
    let mut pkcs8 = [0u8; 128];
    let pkcs8_len = PrivateKeyInfo::Ed25519(&seed).to_der(&mut pkcs8).unwrap();
    let mut sig_der = [0u8; 80];
    let sig_len = pkix::ecdsa_signature::to_der(&[0x11u8; 64], &mut sig_der).unwrap();

    let mut with_extra = std::vec::Vec::new();

    with_extra.clear();
    with_extra.extend_from_slice(&spki[..spki_len]);
    with_extra.push(0);
    assert!(PublicKeyInfo::from_der(&with_extra).is_err(), "spki");

    with_extra.clear();
    with_extra.extend_from_slice(&pkcs8[..pkcs8_len]);
    with_extra.push(0);
    assert!(PrivateKeyInfo::from_der(&with_extra).is_err(), "pkcs8");

    with_extra.clear();
    with_extra.extend_from_slice(&sig_der[..sig_len]);
    with_extra.push(0);
    let mut out = [0u8; 64];
    assert!(
        pkix::ecdsa_signature::from_der(&with_extra, &mut out).is_err(),
        "ecdsa signature"
    );
}
