//! Once the module is in its error state, every algorithm refuses.
//!
//! `ic_core::module` holds one flag that cannot be cleared, and every
//! operation that can report an error consults it. That is a property of
//! about a hundred functions in a dozen crates, and a new algorithm that
//! forgot the check would look exactly like one that had it. So the list of
//! what must refuse is not written here: it is the ontology's list of what
//! this build implements, and the test fails for any entry it was not shown
//! refusing.
//!
//! Two classes are exempt because they cannot refuse: hash functions and
//! XOFs have no error to return. The test names them rather than skipping
//! them silently, and checks that a digest still comes out right, so the
//! limit of the gate is on the record beside its coverage.
//!
//! Everything a refusal needs -- keys, signatures, ciphertexts, objects made
//! while the module worked -- is made first. Then the state is entered, once,
//! and never left: this file is a process of its own for that reason, and has
//! one test.

use std::collections::BTreeSet;

use ironcrypto::core_types::module;
use ironcrypto::core_types::sig::SignatureAlgorithm;
use ironcrypto::core_types::traits::{
    Aead, BlockCipher, Digest, Drbg, Kdf, KeyAgreement, Mac, SignatureScheme,
};
use ironcrypto::core_types::ErrorKind;
use ironcrypto::{cipher, drbg, ec, hpke, kdf, lms, mac, mldsa, mlkem, rsa, sig, slhdsa};

/// Records that `id` was shown refusing, and that it refused as it should.
struct Seen(BTreeSet<&'static str>);

impl Seen {
    fn refused<T>(
        &mut self,
        id: &'static str,
        what: &str,
        result: ironcrypto::core_types::Result<T>,
    ) {
        match result {
            Ok(_) => panic!("{id}: {what} worked in the error state"),
            Err(e) => assert_eq!(
                e.kind(),
                ErrorKind::ModuleErrorState,
                "{id}: {what} failed for another reason: {e:?}"
            ),
        }
        self.0.insert(id);
    }

    /// For the interfaces that answer with a `bool`.
    fn refused_bool(&mut self, id: &'static str, what: &str, result: bool) {
        assert!(!result, "{id}: {what} worked in the error state");
        self.0.insert(id);
    }
}

#[test]
fn every_implemented_algorithm_refuses_in_the_error_state() {
    assert!(!module::in_error_state());
    module::operational().unwrap();

    // ---- Made while the module works -------------------------------------
    let mut rng = drbg::Rng::from_entropy(&[0x5a; 48], b"error-state test").unwrap();
    let key32 = [7u8; 32];
    let message = b"made before the failure";

    let aes128 = cipher::Aes128::new(&key32[..16]).unwrap();
    let aes192 = cipher::Aes192::new(&key32[..24]).unwrap();
    let aes256 = cipher::Aes256::new(&key32).unwrap();
    let gcm128 = cipher::Aes128Gcm::new(&key32[..16]).unwrap();
    let gcm192 = cipher::Aes192Gcm::new(&key32[..24]).unwrap();
    let gcm256 = cipher::Aes256Gcm::new(&key32).unwrap();
    let chacha = cipher::ChaCha20Poly1305::new(&key32).unwrap();
    let siv128 = cipher::Aes128GcmSiv::new(&key32[..16]).unwrap();
    let siv256 = cipher::Aes256GcmSiv::new(&key32).unwrap();
    // One sealed message per AEAD, so that opening is refused for a
    // ciphertext that would have opened.
    let mut sealed = [[0u8; 16]; 6];
    let mut tags = [[0u8; 16]; 6];
    let nonce = [3u8; 12];
    {
        type Seal<'a> = &'a dyn Fn(&mut [u8], &mut [u8]);
        let aeads: [Seal; 6] = [
            &|d, t| gcm128.seal_detached(&nonce, b"", d, t).unwrap(),
            &|d, t| gcm192.seal_detached(&nonce, b"", d, t).unwrap(),
            &|d, t| gcm256.seal_detached(&nonce, b"", d, t).unwrap(),
            &|d, t| chacha.seal_detached(&nonce, b"", d, t).unwrap(),
            &|d, t| siv128.seal_detached(&nonce, b"", d, t).unwrap(),
            &|d, t| siv256.seal_detached(&nonce, b"", d, t).unwrap(),
        ];
        for (i, seal) in aeads.iter().enumerate() {
            seal(&mut sealed[i], &mut tags[i]);
        }
    }
    let mut wrapped = [0u8; 40];
    cipher::Aes256Kw::wrap(&key32, &[1u8; 32], &mut wrapped).unwrap();

    let mut hmac_drbg256 = drbg::HmacDrbgSha256::instantiate(&[1u8; 48], &[2u8; 16], b"").unwrap();
    let mut hmac_drbg512 = drbg::HmacDrbgSha512::instantiate(&[1u8; 48], &[2u8; 16], b"").unwrap();
    let mut ctr_drbg = drbg::CtrDrbg::instantiate(&[1u8; 48], &[2u8; 16], b"").unwrap();

    // Elliptic curves: a key pair and a signature each.
    macro_rules! ecdsa {
        ($scheme:ty) => {{
            let mut private = vec![0u8; <$scheme>::PRIVATE_KEY_LEN];
            private[<$scheme>::PRIVATE_KEY_LEN - 1] = 9;
            let mut public = vec![0u8; <$scheme>::PUBLIC_KEY_LEN];
            <$scheme>::public_key(&private, &mut public).unwrap();
            let mut signature = vec![0u8; <$scheme>::SIGNATURE_LEN];
            <$scheme>::sign(&private, message, &mut signature).unwrap();
            <$scheme>::verify(&public, message, &signature).unwrap();
            (private, public, signature)
        }};
    }
    let p256 = ecdsa!(ec::p256::EcdsaP256Sha256);
    let p384 = ecdsa!(ec::p384::EcdsaP384Sha384);
    let p521 = ecdsa!(ec::p521::EcdsaP521Sha512);
    let ed = ecdsa!(ec::Ed25519);
    let ed_key = ec::Ed25519Key::from_seed(&ed.0).unwrap();
    let ed_verify = ec::Ed25519VerifyKey::from_bytes(&ed.1).unwrap();

    macro_rules! ecdh {
        ($scheme:ty) => {{
            let mut private = vec![0u8; <$scheme>::PRIVATE_KEY_LEN];
            private[1] = 0x48;
            private[<$scheme>::PRIVATE_KEY_LEN - 1] = 0x49;
            let mut public = vec![0u8; <$scheme>::PUBLIC_KEY_LEN];
            <$scheme>::public_key(&private, &mut public).unwrap();
            let mut shared = vec![0u8; <$scheme>::SHARED_SECRET_LEN];
            <$scheme>::agree(&private, &public, &mut shared).unwrap();
            (private, public)
        }};
    }
    let dh256 = ecdh!(ec::p256::EcdhP256);
    let dh384 = ecdh!(ec::p384::EcdhP384);
    let dh521 = ecdh!(ec::p521::EcdhP521);
    let x = ecdh!(ec::X25519);

    // RSA: one key, a signature under each of the six algorithms.
    let rsa_key = rsa::generate(2048, &mut rng).unwrap();
    let rsa_public = *rsa_key.public_key();
    let mut rsa_sigs = vec![[0u8; 256]; 6];
    rsa::Pkcs1Sha256::sign(&rsa_key, message, &mut rsa_sigs[0]).unwrap();
    rsa::Pkcs1Sha384::sign(&rsa_key, message, &mut rsa_sigs[1]).unwrap();
    rsa::Pkcs1Sha512::sign(&rsa_key, message, &mut rsa_sigs[2]).unwrap();
    rsa::PssSha256::sign(&rsa_key, message, &mut rng, &mut rsa_sigs[3]).unwrap();
    rsa::PssSha384::sign(&rsa_key, message, &mut rng, &mut rsa_sigs[4]).unwrap();
    rsa::PssSha512::sign(&rsa_key, message, &mut rng, &mut rsa_sigs[5]).unwrap();
    rsa::PssSha512::verify(&rsa_public, message, &rsa_sigs[5]).unwrap();

    // ML-KEM and ML-DSA: keys, a ciphertext and a signature per parameter set.
    macro_rules! ml_kem {
        ($set:ident, $scheme:ident) => {{
            use mlkem::$set as m;
            let mut ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
            let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
            mlkem::$scheme::keygen(&mut rng, &mut ek, &mut dk).unwrap();
            let mut ct = Box::new([0u8; m::CIPHERTEXT_LEN]);
            let mut shared = [0u8; 32];
            mlkem::$scheme::encapsulate(&mut rng, &ek, &mut ct, &mut shared).unwrap();
            (ek, dk, ct)
        }};
    }
    let kem512 = ml_kem!(kem512, MlKem512);
    let kem768 = ml_kem!(kem, MlKem768);
    let kem1024 = ml_kem!(kem1024, MlKem1024);

    macro_rules! ml_dsa {
        ($set:ident) => {{
            use mldsa::$set as m;
            let mut pk = Box::new([0u8; m::PUBLIC_KEY_LEN]);
            let mut sk = Box::new([0u8; m::SECRET_KEY_LEN]);
            assert!(m::keygen(&[4u8; 32], &mut pk, &mut sk));
            let mut signature = Box::new([0u8; m::SIGNATURE_LEN]);
            assert!(m::sign(&sk, message, b"", &[0u8; 32], &mut signature));
            assert!(m::verify(&pk, message, b"", &signature));
            (pk, sk, signature)
        }};
    }
    let dsa44 = ml_dsa!(sign44);
    let dsa65 = ml_dsa!(sign);
    let dsa87 = ml_dsa!(sign87);

    // SLH-DSA, at the set that signs fastest.
    let slh_set = slhdsa::ParameterSet::Shake_128f;
    let (mut slh_sk, mut slh_pk) = ([0u8; 64], [0u8; 32]);
    slhdsa::keygen(slh_set, &mut rng, &mut slh_sk, &mut slh_pk).unwrap();
    let mut slh_sig = vec![0u8; slh_set.signature_len()];
    slhdsa::sign_deterministic(slh_set, &slh_sk, message, b"", &mut slh_sig).unwrap();
    slhdsa::verify(slh_set, &slh_pk, message, b"", &slh_sig).unwrap();

    // HSS/LMS: RFC 9858's case, which verifies.
    let (lms_key, lms_message, lms_signature) = lms::example();
    lms::verify(&lms_key, &lms_message, &lms_signature).unwrap();

    // HPKE, both KEMs: a recipient, and a context open at each end.
    let hpke_recipient = hpke::KeyPair::generate(&mut rng).unwrap();
    let (hpke_enc, mut hpke_sender) = hpke::setup_sender(
        hpke_recipient.public(),
        b"info",
        hpke::Aead::Aes256Gcm,
        &mut rng,
    )
    .unwrap();
    let hpke384_recipient = hpke::p384::KeyPair::generate(&mut rng).unwrap();
    let (hpke384_enc, mut hpke384_sender) = hpke::p384::setup_sender(
        hpke384_recipient.public(),
        b"info",
        hpke::Aead::Aes256Gcm,
        &mut rng,
    )
    .unwrap();

    let mut hpke_receiver =
        hpke::setup_receiver(&hpke_enc, &hpke_recipient, b"info", hpke::Aead::Aes256Gcm).unwrap();
    let mut hpke_sealed = [0x33u8; 16];
    let mut hpke_tag = [0u8; 16];
    hpke_sender
        .seal_in_place(b"", &mut hpke_sealed, &mut hpke_tag)
        .unwrap();
    let hpke_ephemeral = hpke::KeyPair::generate(&mut rng).unwrap();
    let hpke384_ephemeral = hpke::p384::KeyPair::generate(&mut rng).unwrap();
    let mut hpke384_receiver = hpke::p384::setup_receiver(
        &hpke384_enc,
        &hpke384_recipient,
        b"info",
        hpke::Aead::Aes256Gcm,
    )
    .unwrap();
    let mut hpke384_sealed = [0x33u8; 16];
    let mut hpke384_tag = [0u8; 16];
    hpke384_sender
        .seal_in_place(b"", &mut hpke384_sealed, &mut hpke384_tag)
        .unwrap();

    // An HMAC keyed while the module worked, for the one KDF entry point
    // that takes a MAC rather than a key.
    let keyed = mac::HmacSha256::new(&key32).unwrap();

    // Shamir: shares of a secret, three of five.
    let mut shares = [0u8; 5 * 16];
    cipher::shamir::split(&[6u8; 16], 3, 5, &mut rng, &mut shares).unwrap();

    // A digest, to compare with the one computed afterwards.
    let digest_before = ironcrypto::hash::Sha256::digest(message);

    // ---- The failure ------------------------------------------------------
    module::enter_error_state();
    assert!(module::in_error_state());
    assert_eq!(
        module::operational().unwrap_err().kind(),
        ErrorKind::ModuleErrorState
    );
    assert_eq!(ironcrypto::fips::state(), ironcrypto::fips::State::Error);

    let mut seen = Seen(BTreeSet::new());
    let mut out = [0u8; 64];
    let mut block = [0u8; 16];
    let mut tag = [0u8; 16];

    // Block ciphers refuse a new key. Their per-block methods are the one
    // fallible interface left ungated, by decision: see `ic_core::module`.
    seen.refused("aes-128", "new", cipher::Aes128::new(&key32[..16]));
    seen.refused("aes-192", "new", cipher::Aes192::new(&key32[..24]));
    seen.refused("aes-256", "new", cipher::Aes256::new(&key32));

    // Modes, with keys made before the failure.
    let mut two_blocks = [0u8; 32];
    seen.refused(
        "aes-cbc",
        "encrypt",
        cipher::cbc_encrypt(&aes128, &[0u8; 16], &mut two_blocks),
    );
    seen.refused(
        "aes-cbc",
        "decrypt",
        cipher::cbc_decrypt(&aes192, &[0u8; 16], &mut two_blocks),
    );
    seen.refused(
        "aes-ctr",
        "xor",
        cipher::ctr_xor(&aes256, &[0u8; 16], &mut two_blocks),
    );
    assert_eq!(two_blocks, [0u8; 32], "a refused mode wrote nothing");
    let mut unwrapped = [0u8; 32];
    seen.refused(
        "aes-256-kw",
        "wrap",
        cipher::Aes256Kw::wrap(&key32, &[1u8; 32], &mut [0u8; 40]),
    );
    seen.refused(
        "aes-256-kw",
        "unwrap",
        cipher::Aes256Kw::unwrap(&key32, &wrapped, &mut unwrapped),
    );
    assert_eq!(unwrapped, [0u8; 32], "a refused unwrap released no key");
    seen.refused(
        "aes-128-kw",
        "wrap",
        cipher::Aes128Kw::wrap(&key32[..16], &[1u8; 16], &mut [0u8; 24]),
    );
    seen.refused(
        "aes-256-kwp",
        "wrap",
        cipher::Aes256Kwp::wrap(&key32, &[1u8; 5], &mut [0u8; 16]),
    );
    seen.refused(
        "aes-192-kwp",
        "unwrap",
        cipher::Aes192Kwp::unwrap(&key32[..24], &[0u8; 16], &mut [0u8; 16]),
    );

    // AEADs: no new key, and a key made before seals and opens nothing.
    macro_rules! aead {
        ($id:literal, $ty:ty, $made:expr, $index:literal, $key:expr) => {{
            seen.refused($id, "new", <$ty>::new($key));
            let mut data = [0u8; 16];
            seen.refused(
                $id,
                "seal",
                $made.seal_detached(&[9u8; 12], b"", &mut data, &mut tag),
            );
            assert_eq!(data, [0u8; 16], "{}: a refused seal encrypted nothing", $id);
            let mut ciphertext = sealed[$index];
            seen.refused(
                $id,
                "open",
                $made.open_detached(&nonce, b"", &mut ciphertext, &tags[$index]),
            );
            assert_eq!(
                ciphertext, sealed[$index],
                "{}: a refused open released no plaintext",
                $id
            );
        }};
    }
    aead!("aes-128-gcm", cipher::Aes128Gcm, gcm128, 0, &key32[..16]);
    aead!("aes-192-gcm", cipher::Aes192Gcm, gcm192, 1, &key32[..24]);
    aead!("aes-256-gcm", cipher::Aes256Gcm, gcm256, 2, &key32);
    aead!(
        "chacha20-poly1305",
        cipher::ChaCha20Poly1305,
        chacha,
        3,
        &key32
    );
    aead!(
        "aes-128-gcm-siv",
        cipher::Aes128GcmSiv,
        siv128,
        4,
        &key32[..16]
    );
    aead!("aes-256-gcm-siv", cipher::Aes256GcmSiv, siv256, 5, &key32);
    // The sealer is those AEADs behind a counter.
    assert_eq!(
        cipher::Sealer::<cipher::Aes256Gcm>::new(&key32, [0u8; 4])
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::ModuleErrorState)
    );

    // MACs refuse where they are made.
    seen.refused("hmac-sha2-256", "new", mac::HmacSha256::new(b"key"));
    seen.refused("hmac-sha2-384", "new", mac::HmacSha384::new(b"key"));
    seen.refused("hmac-sha2-512", "new", mac::HmacSha512::new(b"key"));
    seen.refused("hmac-sha2-512-256", "new", mac::HmacSha512_256::new(b"key"));
    seen.refused("hmac-sha3-256", "new", mac::HmacSha3_256::new(b"key"));
    seen.refused("hmac-sha3-512", "new", mac::HmacSha3_512::new(b"key"));
    seen.refused(
        "hmac-sha2-256",
        "mac",
        mac::HmacSha256::mac(b"key", message),
    );
    seen.refused(
        "hmac-sha2-256",
        "verify",
        mac::HmacSha256::verify(b"key", message, &[0u8; 32]),
    );
    seen.refused("cmac-aes-128", "new", mac::CmacAes128::new(&key32[..16]));
    seen.refused("cmac-aes-192", "new", mac::CmacAes192::new(&key32[..24]));
    seen.refused("cmac-aes-256", "new", mac::CmacAes256::new(&key32));
    seen.refused("poly1305", "new", mac::Poly1305::new(&key32));
    // KMAC is made and computed infallibly, so only its verification refuses.
    let mut kmac_tag = [0u8; 32];
    mac::Kmac128::mac(&key32, b"", message, &mut kmac_tag);
    seen.refused(
        "kmac128",
        "verify",
        mac::Kmac128::verify(&key32, b"", message, &kmac_tag),
    );
    mac::Kmac256::mac(&key32, b"", message, &mut kmac_tag);
    seen.refused(
        "kmac256",
        "verify",
        mac::Kmac256::verify(&key32, b"", message, &kmac_tag),
    );

    // Key derivation.
    seen.refused(
        "hkdf-sha2-256",
        "derive",
        kdf::Hkdf::<mac::HmacSha256>::derive(b"secret", b"salt", b"info", &mut out),
    );
    seen.refused(
        "hkdf-sha2-256",
        "extract",
        kdf::Hkdf::<mac::HmacSha256>::extract(b"salt", b"secret", &mut out[..32]),
    );
    seen.refused(
        "hkdf-sha2-256",
        "expand",
        kdf::Hkdf::<mac::HmacSha256>::expand(&key32, b"info", &mut out),
    );
    seen.refused(
        "hkdf-sha2-384",
        "derive",
        kdf::Hkdf::<mac::HmacSha384>::derive(b"secret", b"salt", b"info", &mut out),
    );
    seen.refused(
        "hkdf-sha2-512",
        "derive",
        kdf::Hkdf::<mac::HmacSha512>::derive(b"secret", b"salt", b"info", &mut out),
    );
    seen.refused(
        "sp800-108-counter-hmac-sha2-256",
        "derive",
        kdf::kbkdf_counter::<mac::HmacSha256>(&key32, b"label", b"context", &mut out),
    );
    seen.refused(
        "pbkdf2-hmac-sha2-256",
        "derive",
        kdf::pbkdf2::<mac::HmacSha256>(b"password", &[1u8; 16], 2, &mut out),
    );
    seen.refused(
        "pbkdf2-hmac-sha2-512",
        "derive",
        kdf::pbkdf2::<mac::HmacSha512>(b"password", &[1u8; 16], 2, &mut out),
    );
    let small = kdf::Argon2Params {
        memory_kib: 64,
        passes: 1,
        lanes: 1,
    };
    seen.refused(
        "argon2id",
        "derive",
        kdf::argon2(
            kdf::Variant::Argon2id,
            &small,
            b"password",
            &[1u8; 16],
            &mut out[..32],
        ),
    );
    assert_eq!(out, [0u8; 64], "a refused derivation wrote nothing");

    // Random generation: no new generator, and one made before gives nothing.
    seen.refused(
        "hmac-drbg-sha2-256",
        "instantiate",
        drbg::HmacDrbgSha256::instantiate(&[1u8; 48], &[2u8; 16], b""),
    );
    seen.refused(
        "hmac-drbg-sha2-256",
        "generate",
        hmac_drbg256.generate(b"", &mut out),
    );
    seen.refused(
        "hmac-drbg-sha2-256",
        "reseed",
        hmac_drbg256.reseed(&[3u8; 48], b""),
    );
    seen.refused(
        "hmac-drbg-sha2-512",
        "generate",
        hmac_drbg512.generate(b"", &mut out),
    );
    seen.refused(
        "ctr-drbg-aes-256",
        "instantiate",
        drbg::CtrDrbg::instantiate(&[1u8; 48], &[2u8; 16], b""),
    );
    seen.refused(
        "ctr-drbg-aes-256",
        "generate",
        ctr_drbg.generate(b"", &mut out),
    );
    assert_eq!(out, [0u8; 64], "a refused generator produced nothing");
    assert_eq!(
        rng.fill(&mut out).unwrap_err().kind(),
        ErrorKind::ModuleErrorState
    );
    assert_eq!(
        drbg::Rng::from_os().err().map(|e| e.kind()),
        Some(ErrorKind::ModuleErrorState)
    );

    // Signatures: no public key, no signature, and a valid one not verified.
    macro_rules! signature {
        ($id:literal, $scheme:ty, $made:expr) => {{
            let (private, public, signature) = &$made;
            let mut buf = vec![0u8; <$scheme>::PUBLIC_KEY_LEN];
            seen.refused($id, "public_key", <$scheme>::public_key(private, &mut buf));
            let mut buf = vec![0u8; <$scheme>::SIGNATURE_LEN];
            seen.refused($id, "sign", <$scheme>::sign(private, message, &mut buf));
            assert!(buf.iter().all(|b| *b == 0), "{}: nothing was signed", $id);
            seen.refused($id, "verify", <$scheme>::verify(public, message, signature));
        }};
    }
    signature!("ecdsa-p256-sha256", ec::p256::EcdsaP256Sha256, p256);
    signature!("ecdsa-p384-sha384", ec::p384::EcdsaP384Sha384, p384);
    signature!("ecdsa-p521-sha512", ec::p521::EcdsaP521Sha512, p521);
    signature!("ed25519", ec::Ed25519, ed);
    seen.refused("ed25519", "key sign", ed_key.sign(message, &mut out));
    seen.refused("ed25519", "key verify", ed_verify.verify(message, &ed.2));
    seen.refused(
        "ed25519",
        "from_seed",
        ec::Ed25519Key::from_seed(&ed.0).map(|_| ()),
    );
    seen.refused(
        "ecdsa-p256-sha256",
        "verify_prehash",
        ec::p256::EcdsaP256Sha256::verify_prehash(&p256.1, &[1u8; 32], &p256.2),
    );

    macro_rules! agreement {
        ($id:literal, $scheme:ty, $made:expr) => {{
            let (private, public) = &$made;
            let mut buf = vec![0u8; <$scheme>::PUBLIC_KEY_LEN];
            seen.refused($id, "public_key", <$scheme>::public_key(private, &mut buf));
            let mut shared = vec![0u8; <$scheme>::SHARED_SECRET_LEN];
            seen.refused($id, "agree", <$scheme>::agree(private, public, &mut shared));
            assert!(shared.iter().all(|b| *b == 0), "{}: no secret", $id);
        }};
    }
    agreement!("ecdh-p256", ec::p256::EcdhP256, dh256);
    agreement!("ecdh-p384", ec::p384::EcdhP384, dh384);
    agreement!("ecdh-p521", ec::p521::EcdhP521, dh521);
    agreement!("x25519", ec::X25519, x);

    let mut rsa_out = [0u8; 256];
    seen.refused(
        "rsa-pkcs1-sha256",
        "sign",
        rsa::Pkcs1Sha256::sign(&rsa_key, message, &mut rsa_out),
    );
    seen.refused(
        "rsa-pkcs1-sha256",
        "verify",
        rsa::Pkcs1Sha256::verify(&rsa_public, message, &rsa_sigs[0]),
    );
    seen.refused(
        "rsa-pkcs1-sha384",
        "verify",
        rsa::Pkcs1Sha384::verify(&rsa_public, message, &rsa_sigs[1]),
    );
    seen.refused(
        "rsa-pkcs1-sha512",
        "verify",
        rsa::Pkcs1Sha512::verify(&rsa_public, message, &rsa_sigs[2]),
    );
    seen.refused(
        "rsa-pss-sha256",
        "sign",
        rsa::PssSha256::sign(&rsa_key, message, &mut rng, &mut rsa_out),
    );
    seen.refused(
        "rsa-pss-sha256",
        "verify",
        rsa::PssSha256::verify(&rsa_public, message, &rsa_sigs[3]),
    );
    seen.refused(
        "rsa-pss-sha384",
        "verify",
        rsa::PssSha384::verify(&rsa_public, message, &rsa_sigs[4]),
    );
    seen.refused(
        "rsa-pss-sha512",
        "verify",
        rsa::PssSha512::verify(&rsa_public, message, &rsa_sigs[5]),
    );
    assert_eq!(rsa_out, [0u8; 256], "nothing was signed");
    assert_eq!(
        rsa_public
            .raw_public(&rsa_sigs[0], &mut rsa_out)
            .unwrap_err()
            .kind(),
        ErrorKind::ModuleErrorState
    );
    assert_eq!(
        rsa_key
            .raw_private(&rsa_sigs[0], &mut rsa_out)
            .unwrap_err()
            .kind(),
        ErrorKind::ModuleErrorState
    );
    assert_eq!(
        rsa::generate(2048, &mut rng).err().map(|e| e.kind()),
        Some(ErrorKind::ModuleErrorState)
    );

    // ML-KEM.
    macro_rules! ml_kem_refuses {
        ($id:literal, $set:ident, $scheme:ident, $made:expr) => {{
            use mlkem::$set as m;
            let (ek, dk, ct) = &$made;
            let mut new_ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
            let mut new_dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
            seen.refused(
                $id,
                "keygen",
                mlkem::$scheme::keygen(&mut rng, &mut new_ek, &mut new_dk),
            );
            let mut new_ct = Box::new([0u8; m::CIPHERTEXT_LEN]);
            let mut shared = [0u8; 32];
            seen.refused(
                $id,
                "encapsulate",
                mlkem::$scheme::encapsulate(&mut rng, ek, &mut new_ct, &mut shared),
            );
            seen.refused(
                $id,
                "decapsulate",
                mlkem::$scheme::decapsulate(dk, ct, &mut shared),
            );
            assert_eq!(shared, [0u8; 32], "{}: no shared secret", $id);
        }};
    }
    ml_kem_refuses!("ml-kem-512", kem512, MlKem512, kem512);
    ml_kem_refuses!("ml-kem-768", kem, MlKem768, kem768);
    ml_kem_refuses!("ml-kem-1024", kem1024, MlKem1024, kem1024);

    // ML-DSA answers with a bool. Each call here returned true above.
    macro_rules! ml_dsa_refuses {
        ($id:literal, $set:ident, $made:expr) => {{
            use mldsa::$set as m;
            let (pk, sk, signature) = &$made;
            let mut new_pk = Box::new([0u8; m::PUBLIC_KEY_LEN]);
            let mut new_sk = Box::new([0u8; m::SECRET_KEY_LEN]);
            seen.refused_bool(
                $id,
                "keygen",
                m::keygen(&[4u8; 32], &mut new_pk, &mut new_sk),
            );
            let mut new_sig = Box::new([0u8; m::SIGNATURE_LEN]);
            seen.refused_bool(
                $id,
                "sign",
                m::sign(sk, message, b"", &[0u8; 32], &mut new_sig),
            );
            assert!(new_sig.iter().all(|b| *b == 0), "{}: nothing signed", $id);
            seen.refused_bool($id, "verify", m::verify(pk, message, b"", signature));
            seen.refused_bool(
                $id,
                "sign_deterministic",
                m::sign_deterministic(sk, message, b"", &mut new_sig),
            );
        }};
    }
    ml_dsa_refuses!("ml-dsa-44", sign44, dsa44);
    ml_dsa_refuses!("ml-dsa-65", sign, dsa65);
    ml_dsa_refuses!("ml-dsa-87", sign87, dsa87);

    // SLH-DSA, both interfaces.
    let mut new_sig = vec![0u8; slh_set.signature_len()];
    seen.refused(
        "slh-dsa",
        "keygen",
        slhdsa::keygen(slh_set, &mut rng, &mut [0u8; 64], &mut [0u8; 32]),
    );
    seen.refused(
        "slh-dsa",
        "sign",
        slhdsa::sign_deterministic(slh_set, &slh_sk, message, b"", &mut new_sig),
    );
    seen.refused(
        "slh-dsa",
        "verify",
        slhdsa::verify(slh_set, &slh_pk, message, b"", &slh_sig),
    );
    seen.refused(
        "slh-dsa",
        "hash_sign",
        slhdsa::hash_sign_deterministic(
            slh_set,
            &slh_sk,
            message,
            b"",
            slhdsa::PreHash::Sha256,
            &mut new_sig,
        ),
    );
    seen.refused(
        "slh-dsa",
        "hash_verify",
        slhdsa::hash_verify(
            slh_set,
            &slh_pk,
            message,
            b"",
            slhdsa::PreHash::Sha256,
            &slh_sig,
        ),
    );
    assert!(new_sig.iter().all(|b| *b == 0), "slh-dsa: nothing signed");

    // HSS/LMS, directly and through the one call protocols use.
    seen.refused(
        "hss-lms",
        "verify",
        lms::verify(&lms_key, &lms_message, &lms_signature),
    );
    assert_eq!(
        sig::verify(
            SignatureAlgorithm::HssLms,
            &sig::PublicKey::HssLms(&lms_key),
            &lms_message,
            &lms_signature
        )
        .unwrap_err()
        .kind(),
        ErrorKind::ModuleErrorState,
        "ic_sig reports the module's state, not a bad signature"
    );
    assert_eq!(
        sig::verify(
            SignatureAlgorithm::Ed25519,
            &sig::PublicKey::Ed25519(&ed.1),
            message,
            &ed.2
        )
        .unwrap_err()
        .kind(),
        ErrorKind::ModuleErrorState
    );

    // HPKE: no key pair, no new context, and an open one seals nothing.
    seen.refused(
        "hpke-x25519-sha256",
        "generate",
        hpke::KeyPair::generate(&mut rng),
    );
    seen.refused(
        "hpke-x25519-sha256",
        "setup_sender",
        hpke::setup_sender(
            hpke_recipient.public(),
            b"info",
            hpke::Aead::Aes256Gcm,
            &mut rng,
        ),
    );
    seen.refused(
        "hpke-x25519-sha256",
        "setup_receiver",
        hpke::setup_receiver(&hpke_enc, &hpke_recipient, b"info", hpke::Aead::Aes256Gcm),
    );
    let mut data = [0u8; 16];
    seen.refused(
        "hpke-x25519-sha256",
        "seal",
        hpke_sender.seal_in_place(b"", &mut data, &mut tag),
    );
    seen.refused(
        "hpke-x25519-sha256",
        "export",
        hpke_sender.export(b"context", &mut out),
    );
    seen.refused(
        "hpke-p384-sha384",
        "generate",
        hpke::p384::KeyPair::generate(&mut rng),
    );
    seen.refused(
        "hpke-p384-sha384",
        "setup_receiver",
        hpke::p384::setup_receiver(
            &hpke384_enc,
            &hpke384_recipient,
            b"info",
            hpke::Aead::Aes256Gcm,
        ),
    );
    seen.refused(
        "hpke-p384-sha384",
        "seal",
        hpke384_sender.seal_in_place(b"", &mut data, &mut tag),
    );
    assert_eq!(data, [0u8; 16], "hpke: nothing was sealed");

    // Shamir.
    seen.refused(
        "shamir-gf256",
        "split",
        cipher::shamir::split(&[6u8; 16], 3, 5, &mut rng, &mut [0u8; 80]),
    );
    seen.refused(
        "shamir-gf256",
        "combine",
        cipher::shamir::combine(
            &[
                (1, &shares[..16]),
                (2, &shares[16..32]),
                (3, &shares[32..48]),
            ],
            &mut block,
        ),
    );
    assert_eq!(block, [0u8; 16], "shamir: no secret was recovered");
    assert_eq!(out, [0u8; 64], "nothing above wrote to the shared buffer");

    // Every remaining function that carries the check, called by name. Most
    // of them sit outside or inside another that refuses too, so removing one
    // check alone changes nothing a caller sees; what is held here is that
    // none of them is reachable in the error state by any route.
    seen.refused(
        "aes-128",
        "new_portable",
        cipher::Aes128::new_portable(&key32[..16]),
    );
    seen.refused(
        "chacha20-poly1305",
        "chacha20_xor",
        cipher::chacha20_xor(&key32, &[0u8; 12], 0, &mut block),
    );
    seen.refused(
        "hss-lms",
        "verify_lms",
        lms::verify_lms(&lms_key[4..], &lms_message, &lms_signature[4..]),
    );
    seen.refused(
        "hkdf-sha2-256",
        "expand_from",
        kdf::Hkdf::<mac::HmacSha256>::expand_from(&keyed, b"info", &mut out),
    );
    seen.refused(
        "argon2id",
        "argon2_full",
        kdf::argon2::argon2_full(
            kdf::Variant::Argon2id,
            &small,
            b"password",
            &[1u8; 16],
            b"",
            b"",
            &mut out[..32],
        ),
    );
    seen.refused(
        "ecdsa-p256-sha256",
        "public_key_compressed",
        ec::p256::EcdsaP256Sha256::public_key_compressed(&p256.0, &mut [0u8; 33]),
    );
    seen.refused(
        "ecdh-p256",
        "public_key_compressed",
        ec::p256::EcdhP256::public_key_compressed(&dh256.0, &mut [0u8; 33]),
    );
    seen.refused(
        "ctr-drbg-aes-256",
        "reseed",
        ctr_drbg.reseed(&[3u8; 48], b""),
    );
    seen.refused(
        "hmac-drbg-sha2-512",
        "instantiate",
        drbg::HmacDrbgSha512::instantiate(&[1u8; 48], &[2u8; 16], b""),
    );
    assert_eq!(
        rng.reseed_from_os().unwrap_err().kind(),
        ErrorKind::ModuleErrorState
    );
    // The same generator through the trait every key generator takes it by.
    assert_eq!(
        ironcrypto::core_types::traits::RandomSource::fill(&mut rng, &mut out)
            .unwrap_err()
            .kind(),
        ErrorKind::ModuleErrorState
    );
    assert_eq!(
        drbg::Rng::from_entropy(&[0x5a; 48], b"")
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::ModuleErrorState)
    );
    seen.refused(
        "slh-dsa",
        "keygen_internal",
        slhdsa::keygen_internal(
            slh_set,
            &[1u8; 16],
            &[2u8; 16],
            &[3u8; 16],
            &mut [0u8; 64],
            &mut [0u8; 32],
        ),
    );
    seen.refused(
        "hpke-x25519-sha256",
        "from_private",
        hpke::KeyPair::from_private(&key32),
    );
    seen.refused(
        "hpke-x25519-sha256",
        "derive",
        hpke::KeyPair::derive(&key32),
    );
    seen.refused(
        "hpke-x25519-sha256",
        "setup_sender_with_ephemeral",
        hpke::setup_sender_with_ephemeral(
            hpke_recipient.public(),
            b"info",
            hpke::Aead::Aes256Gcm,
            &hpke_ephemeral,
        ),
    );
    let mut ciphertext = hpke_sealed;
    seen.refused(
        "hpke-x25519-sha256",
        "open",
        hpke_receiver.open_in_place(b"", &mut ciphertext, &hpke_tag),
    );
    assert_eq!(ciphertext, hpke_sealed, "hpke: no plaintext was released");
    seen.refused(
        "hpke-p384-sha384",
        "from_private",
        hpke::p384::KeyPair::from_private(&[7u8; 48]),
    );
    seen.refused(
        "hpke-p384-sha384",
        "derive",
        hpke::p384::KeyPair::derive(&[7u8; 48]),
    );
    seen.refused(
        "hpke-p384-sha384",
        "setup_sender",
        hpke::p384::setup_sender(
            hpke384_recipient.public(),
            b"info",
            hpke::Aead::Aes256Gcm,
            &mut rng,
        ),
    );
    seen.refused(
        "hpke-p384-sha384",
        "setup_sender_with_ephemeral",
        hpke::p384::setup_sender_with_ephemeral(
            hpke384_recipient.public(),
            b"info",
            hpke::Aead::Aes256Gcm,
            &hpke384_ephemeral,
        ),
    );
    let mut ciphertext = hpke384_sealed;
    seen.refused(
        "hpke-p384-sha384",
        "open",
        hpke384_receiver.open_in_place(b"", &mut ciphertext, &hpke384_tag),
    );
    assert_eq!(
        ciphertext, hpke384_sealed,
        "hpke: no plaintext was released"
    );
    assert_eq!(out, [0u8; 64], "nothing above wrote to the shared buffer");
    assert_eq!(block, [0u8; 16]);

    // ---- The list is the ontology's ---------------------------------------
    let mut cannot_refuse = Vec::new();
    let mut missing = Vec::new();
    for entry in ironcrypto::ontology::all() {
        if entry.status != ironcrypto::ontology::ImplStatus::Available {
            continue;
        }
        if seen.0.contains(entry.id) {
            continue;
        }
        match entry.class.id() {
            // No error to return: `ic_core::module` says so, and why.
            "hash" | "xof" => cannot_refuse.push(entry.id),
            _ => missing.push(entry.id),
        }
    }
    assert!(
        missing.is_empty(),
        "implemented, and not shown refusing in the error state: {missing:?}"
    );
    // Every name recorded above is a real entry, so a typo cannot stand in
    // for coverage.
    for id in &seen.0 {
        assert!(
            ironcrypto::ontology::get(id).is_some(),
            "{id} is not an entry"
        );
    }
    println!(
        "{} algorithms refuse; {} cannot: {cannot_refuse:?}",
        seen.0.len(),
        cannot_refuse.len()
    );
    assert!(!cannot_refuse.is_empty());

    // The stated limit, asserted so it is not mistaken for coverage: a hash
    // goes on working, and gives the answer it gave before.
    assert_eq!(
        ironcrypto::hash::Sha256::digest(message).as_ref(),
        digest_before.as_ref()
    );
}
