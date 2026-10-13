//! IronCrypto against Graviola, operation by operation.
//!
//! ```text
//! cargo run --release -- graviola
//! ```
//!
//! Graviola runs only on x86-64 with AES, AVX2, ADX, BMI2 and PCLMULQDQ, or on
//! aarch64 with the crypto extensions, and uses formally verified assembly
//! from s2n-bignum for its field arithmetic. So this compares the two on the
//! machines Graviola supports, and says nothing about the others, where
//! Graviola does not run at all.
//!
//! Both sides do the same work per row: the same key, message and output
//! size, a key prepared once outside the loop where both libraries allow it.
//! Each figure is the best of several runs, as in `main.rs`.

use crate::{bulk, per_op, verdict};
use ic_core::traits::{Aead, Digest, KeyAgreement, Mac, SignatureScheme};

const SIZE: usize = 4 * 1024 * 1024;
const REPEATS: usize = 5;

pub fn run() {
    println!();
    println!("IronCrypto vs Graviola 0.4.1 — best of {REPEATS}");
    println!(
        "IronCrypto AES backend: {:?}",
        ic_cipher::aes::active_backend()
    );

    let key = [0x2au8; 32];
    let nonce = [0x24u8; 12];
    let mut data = vec![0u8; SIZE];
    let mut tag = [0u8; 16];

    // ---------------------------------------------------------- AEADs ---
    for (label, size) in [("4 MiB", SIZE), ("1 KiB", 1024), ("64 B", 64)] {
        println!();
        println!("AEAD sealing, {label} messages");
        let reps = SIZE / size;
        let ic = ironcrypto::cipher::Aes256Gcm::new(&key).unwrap();
        let a1 = bulk("ironcrypto aes-256-gcm", SIZE, REPEATS, || {
            for chunk in data.chunks_mut(size).take(reps) {
                ic.seal_detached(&nonce, b"", chunk, &mut tag).unwrap();
            }
        });
        let g = graviola::aead::AesGcm::new(&key);
        let a2 = bulk("graviola aes-256-gcm", SIZE, REPEATS, || {
            for chunk in data.chunks_mut(size).take(reps) {
                g.encrypt(&nonce, b"", chunk, &mut tag);
            }
        });
        verdict(&format!("aes-256-gcm, {label}"), a1, a2, true);

        let ic = ironcrypto::cipher::ChaCha20Poly1305::new(&key).unwrap();
        let c1 = bulk("ironcrypto chacha20-poly1305", SIZE, REPEATS, || {
            for chunk in data.chunks_mut(size).take(reps) {
                ic.seal_detached(&nonce, b"", chunk, &mut tag).unwrap();
            }
        });
        let g = graviola::aead::ChaCha20Poly1305::new(key);
        let c2 = bulk("graviola chacha20-poly1305", SIZE, REPEATS, || {
            for chunk in data.chunks_mut(size).take(reps) {
                g.encrypt(&nonce, b"", chunk, &mut tag);
            }
        });
        verdict(&format!("chacha20-poly1305, {label}"), c1, c2, true);
    }

    // --------------------------------------------------------- hashes ---
    println!();
    println!("Hashes and HMAC, 4 MiB");
    let h1 = bulk("ironcrypto sha-256", SIZE, REPEATS, || {
        std::hint::black_box(ironcrypto::hash::Sha256::digest(&data).unwrap());
    });
    let h2 = bulk("graviola sha-256", SIZE, REPEATS, || {
        let mut c = graviola::hashing::sha2::Sha256Context::new();
        c.update(&data);
        std::hint::black_box(c.finish());
    });
    verdict("sha-256", h1, h2, true);

    let h3 = bulk("ironcrypto sha-512", SIZE, REPEATS, || {
        std::hint::black_box(ironcrypto::hash::Sha512::digest(&data).unwrap());
    });
    let h4 = bulk("graviola sha-512", SIZE, REPEATS, || {
        let mut c = graviola::hashing::sha2::Sha512Context::new();
        c.update(&data);
        std::hint::black_box(c.finish());
    });
    verdict("sha-512", h3, h4, true);

    let h5 = bulk("ironcrypto sha3-256", SIZE, REPEATS, || {
        std::hint::black_box(ironcrypto::hash::Sha3_256::digest(&data).unwrap());
    });
    let h6 = bulk("graviola sha3-256", SIZE, REPEATS, || {
        let mut c = graviola::hashing::sha3::Sha3_256Context::new();
        c.update(&data);
        std::hint::black_box(c.finish());
    });
    verdict("sha3-256", h5, h6, true);

    let m1 = bulk("ironcrypto hmac-sha256", SIZE, REPEATS, || {
        std::hint::black_box(ironcrypto::mac::HmacSha256::mac(&key, &data).unwrap());
    });
    let m2 = bulk("graviola hmac-sha256", SIZE, REPEATS, || {
        let mut h = graviola::hashing::hmac::Hmac::<graviola::hashing::Sha256>::new(key);
        h.update(&data);
        std::hint::black_box(h.finish());
    });
    verdict("hmac-sha256, 4 MiB", m1, m2, true);

    println!();
    println!("Short inputs, per operation (lower is better)");
    let short = &data[..200];
    let s1 = per_op("ironcrypto hmac-sha256, 200 B", 200_000, 5, || {
        std::hint::black_box(ironcrypto::mac::HmacSha256::mac(&key, short).unwrap());
    });
    let s2 = per_op("graviola hmac-sha256, 200 B", 200_000, 5, || {
        let mut h = graviola::hashing::hmac::Hmac::<graviola::hashing::Sha256>::new(key);
        h.update(short);
        std::hint::black_box(h.finish());
    });
    verdict("hmac-sha256, 200 B", s1, s2, false);
    let s3 = per_op("ironcrypto sha-256, 64 B", 500_000, 5, || {
        std::hint::black_box(ironcrypto::hash::Sha256::digest(&data[..64]).unwrap());
    });
    let s4 = per_op("graviola sha-256, 64 B", 500_000, 5, || {
        let mut c = graviola::hashing::sha2::Sha256Context::new();
        c.update(&data[..64]);
        std::hint::black_box(c.finish());
    });
    verdict("sha-256, 64 B", s3, s4, false);

    // ----------------------------------------------------- public key ---
    println!();
    println!("Public key, per operation (lower is better)");
    let sk = [0x77u8; 32];

    let mut pk = [0u8; 32];
    ironcrypto::ec::X25519::public_key(&sk, &mut pk).unwrap();
    let mut shared = [0u8; 32];
    let x1 = per_op("ironcrypto x25519 agree", 3000, 5, || {
        ironcrypto::ec::X25519::agree(&sk, &pk, &mut shared).unwrap();
    });
    let g_sk = graviola::key_agreement::x25519::StaticPrivateKey::from_array(&sk);
    let g_pk = graviola::key_agreement::x25519::PublicKey::from_array(&pk);
    let x2 = per_op("graviola x25519 agree", 3000, 5, || {
        std::hint::black_box(g_sk.diffie_hellman(&g_pk).unwrap());
    });
    verdict("x25519 agree", x1, x2, false);

    let p_sk = [0x5au8; 32];
    let mut p_pk = [0u8; 65];
    ironcrypto::ec::EcdhP256::public_key(&p_sk, &mut p_pk).unwrap();
    let mut p_shared = [0u8; 32];
    let p1 = per_op("ironcrypto p-256 ecdh", 1000, 5, || {
        ironcrypto::ec::EcdhP256::agree(&p_sk, &p_pk, &mut p_shared).unwrap();
    });
    let gp_sk = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&p_sk).unwrap();
    let gp_pk = graviola::key_agreement::p256::PublicKey::from_x962_uncompressed(&p_pk).unwrap();
    let p2 = per_op("graviola p-256 ecdh", 1000, 5, || {
        std::hint::black_box(gp_sk.diffie_hellman(&gp_pk).unwrap());
    });
    verdict("p-256 ecdh", p1, p2, false);

    let msg = b"benchmark message";
    let mut p_sig = [0u8; 64];
    let e1 = per_op("ironcrypto ecdsa p-256 sign", 1000, 5, || {
        ironcrypto::ec::p256::EcdsaP256Sha256::sign(&p_sk, msg, &mut p_sig).unwrap();
    });
    let g_signer = graviola::signing::ecdsa::SigningKey::<graviola::signing::ecdsa::P256> {
        private_key: graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&p_sk).unwrap(),
    };
    let mut g_sig = [0u8; 64];
    let e2 = per_op("graviola ecdsa p-256 sign", 1000, 5, || {
        std::hint::black_box(
            g_signer
                .sign::<graviola::hashing::Sha256>(&[msg], &mut g_sig)
                .unwrap(),
        );
    });
    verdict("ecdsa p-256 sign", e1, e2, false);

    let v1 = per_op("ironcrypto ecdsa p-256 verify", 1000, 5, || {
        ironcrypto::ec::p256::EcdsaP256Sha256::verify(&p_pk, msg, &p_sig).unwrap();
    });
    let g_verifier =
        graviola::signing::ecdsa::VerifyingKey::<graviola::signing::ecdsa::P256>::from_x962_uncompressed(
            &p_pk,
        )
        .unwrap();
    let v2 = per_op("graviola ecdsa p-256 verify", 1000, 5, || {
        g_verifier
            .verify::<graviola::hashing::Sha256>(&[msg], &p_sig)
            .unwrap();
    });
    verdict("ecdsa p-256 verify", v1, v2, false);

    let mut ed_sig = [0u8; 64];
    let ic_key = ironcrypto::ec::Ed25519Key::from_seed(&sk).unwrap();
    let d1 = per_op("ironcrypto ed25519 sign", 3000, 5, || {
        ic_key.sign(msg, &mut ed_sig).unwrap();
    });
    let g_ed = graviola::signing::eddsa::Ed25519SigningKey::from_bytes(&sk).unwrap();
    let d2 = per_op("graviola ed25519 sign", 3000, 5, || {
        std::hint::black_box(g_ed.sign(msg));
    });
    verdict("ed25519 sign", d1, d2, false);
    let mut ed_pk = [0u8; 32];
    ironcrypto::ec::Ed25519::public_key(&sk, &mut ed_pk).unwrap();
    let d3 = per_op("ironcrypto ed25519 verify", 3000, 5, || {
        ironcrypto::ec::Ed25519::verify(&ed_pk, msg, &ed_sig).unwrap();
    });
    let g_ed_pk = g_ed.public_key();
    let d4 = per_op("graviola ed25519 verify", 3000, 5, || {
        g_ed_pk.verify(&ed_sig, msg).unwrap();
    });
    verdict("ed25519 verify", d3, d4, false);

    // ML-KEM-768. Graviola's public calls draw their own randomness, so both
    // sides here include one draw from the operating system per operation.
    {
        use ic_mlkem::kem as m;
        let mut rng = ironcrypto::drbg::Rng::from_os().unwrap();
        let mut ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
        let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
        // IronCrypto's `keygen` runs the FIPS 140-3 pairwise-consistency test
        // (an encapsulation and a decapsulation) on every key; Graviola's
        // `generate` has none. So this row is not like for like.
        let k1 = per_op("ironcrypto ml-kem-768 keygen + pairwise", 2000, 5, || {
            ic_mlkem::MlKem768::keygen(&mut rng, &mut ek, &mut dk).unwrap();
        });
        let k2 = per_op("graviola ml-kem-768 keygen", 2000, 5, || {
            std::hint::black_box(graviola::key_agreement::mlkem768::DecapKey::generate().unwrap());
        });
        verdict("keygen (ironcrypto with pairwise test)", k1, k2, false);

        // Like for like: key generation alone, from 64 bytes drawn from the
        // operating system per key, as Graviola's `generate` draws them.
        let k3 = per_op("ironcrypto ml-kem-768 keygen, no pairwise", 2000, 5, || {
            let mut seed = [0u8; 64];
            ic_core::entropy::fill(&mut seed).unwrap();
            ic_mlkem::MlKem768::keygen_deterministic(
                seed[..32].try_into().unwrap(),
                seed[32..].try_into().unwrap(),
                &mut ek,
                &mut dk,
            )
            .unwrap();
        });
        verdict("keygen (like for like, no pairwise test)", k3, k2, false);

        let mut ct = Box::new([0u8; m::CIPHERTEXT_LEN]);
        let mut ss = [0u8; 32];
        let n1 = per_op("ironcrypto ml-kem-768 encapsulate", 2000, 5, || {
            ic_mlkem::MlKem768::encapsulate(&mut rng, &ek, &mut ct, &mut ss).unwrap();
        });
        let g_dk = graviola::key_agreement::mlkem768::DecapKey::generate().unwrap();
        let g_ek = g_dk.encapsulation_key();
        let n2 = per_op("graviola ml-kem-768 encapsulate", 2000, 5, || {
            std::hint::black_box(g_ek.clone().encaps().unwrap());
        });
        verdict("ml-kem-768 encapsulate", n1, n2, false);

        let o1 = per_op("ironcrypto ml-kem-768 decapsulate", 2000, 5, || {
            ic_mlkem::MlKem768::decapsulate(&dk, &ct, &mut ss).unwrap();
        });
        let (_, g_ct) = g_ek.clone().encaps().unwrap();
        let o2 = per_op("graviola ml-kem-768 decapsulate", 2000, 5, || {
            std::hint::black_box(g_dk.decaps_internal(&g_ct));
        });
        verdict("ml-kem-768 decapsulate", o1, o2, false);

        // The same, with each side's key parsed once outside the loop:
        // IronCrypto's prepared keys hold A^T, t and H(ek); Graviola's
        // `EncapKey::from_bytes` holds A^T, and its `DecapKey` is always in
        // that form. Graviola's `encaps` consumes the key, so it is cloned
        // per operation, as above. Both encapsulate to the same key bytes.
        let p_ek = m::PreparedEncapsulationKey::new(&ek).unwrap();
        let p1 = per_op("ironcrypto ml-kem-768 encaps, prepared", 2000, 5, || {
            p_ek.encapsulate(&mut rng, &mut ct, &mut ss).unwrap();
        });
        let g_parsed = graviola::key_agreement::mlkem768::EncapKey::from_bytes(&ek).unwrap();
        let p2 = per_op("graviola ml-kem-768 encaps, parsed once", 2000, 5, || {
            std::hint::black_box(g_parsed.clone().encaps().unwrap());
        });
        verdict("ml-kem-768 encapsulate, prepared", p1, p2, false);

        let p_dk = m::PreparedDecapsulationKey::new(&dk).unwrap();
        let q1 = per_op("ironcrypto ml-kem-768 decaps, prepared", 2000, 5, || {
            p_dk.decapsulate(&ct, &mut ss).unwrap();
        });
        let q2 = per_op("graviola ml-kem-768 decaps", 2000, 5, || {
            std::hint::black_box(g_dk.decaps_internal(&g_ct));
        });
        verdict("ml-kem-768 decapsulate, prepared", q1, q2, false);
    }

    // RSA-2048 PKCS#1 v1.5 signing, on one key loaded into both.
    {
        let g_key =
            graviola::signing::rsa::SigningKey::generate(graviola::signing::rsa::KeySize::Rsa2048)
                .unwrap();
        let mut der = vec![0u8; 4096];
        let der = g_key.to_pkcs8_der(&mut der).unwrap();
        let ic_pkix::PrivateKeyInfo::Rsa { public_exponent, prime1, prime2, .. } =
            ic_pkix::PrivateKeyInfo::from_der(der).unwrap()
        else {
            panic!("graviola wrote an RSA key that is not RSA");
        };
        let ic_key = ic_rsa::RsaPrivateKey::from_primes(prime1, prime2, public_exponent).unwrap();
        let mut sig = vec![0u8; 256];
        let r1 = per_op("ironcrypto rsa-2048 pkcs1 sign", 200, 5, || {
            ic_rsa::Pkcs1Sha256::sign(&ic_key, msg, &mut sig).unwrap();
        });
        let mut g_sig = vec![0u8; 256];
        let r2 = per_op("graviola rsa-2048 pkcs1 sign", 200, 5, || {
            std::hint::black_box(g_key.sign_pkcs1_sha256(&mut g_sig, msg).unwrap());
        });
        verdict("rsa-2048 sign", r1, r2, false);
        let public = ic_key.public_key();
        let r3 = per_op("ironcrypto rsa-2048 pkcs1 verify", 5000, 5, || {
            ic_rsa::Pkcs1Sha256::verify(&public, msg, &sig).unwrap();
        });
        let g_pub = g_key.public_key();
        let r4 = per_op("graviola rsa-2048 pkcs1 verify", 5000, 5, || {
            g_pub.verify_pkcs1_sha256(&sig, msg).unwrap();
        });
        verdict("rsa-2048 verify", r3, r4, false);
    }
}
