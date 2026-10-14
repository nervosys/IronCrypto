//! IronCrypto against Graviola, operation by operation.
//!
//! ```text
//! cargo run --release -- graviola
//! cargo run --release -- graviola-p384   # the P-384 rows alone
//! cargo run --release -- graviola-chacha # ChaCha20-Poly1305, split in halves
//! cargo run --release -- graviola-rsa    # RSA at 2048, 3072 and 4096 bits
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
    backends();

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

    p384();

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

    // ML-KEM-768. Graviola's public calls draw their own randomness from the
    // operating system on every call. The rows below say which of the two
    // ways of holding a key each pair compares: from bytes, or parsed once.
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

        // Graviola's encapsulation draws its 32-byte message from the operating
        // system on every call, so the IronCrypto encapsulation rows draw from
        // `OsEntropy` too, not from the DRBG `rng` above.
        let mut os = ic_core::entropy::OsEntropy;

        // A Graviola key for the decapsulation rows, and a ciphertext to it.
        let g_dk = graviola::key_agreement::mlkem768::DecapKey::generate().unwrap();
        let g_ek = g_dk.encapsulation_key();
        let (_, g_ct) = g_ek.clone().encaps().unwrap();

        // FROM BYTES, both sides. Each call starts from the encoded key.
        // IronCrypto's `encapsulate` checks the encoding (FIPS 203 7.2) and
        // expands the key. Graviola's `EncapKey::from_bytes` also checks the
        // encoding (ByteDecode12 round trip) and expands A^T. Both then compute
        // H(ek) inside the encapsulation, as FIPS 203 requires.
        let a1 = per_op("ironcrypto ml-kem-768 encaps, from bytes", 2000, 5, || {
            ic_mlkem::MlKem768::encapsulate(&mut os, &ek, &mut ct, &mut ss).unwrap();
        });
        let a2 = per_op("graviola ml-kem-768 encaps, from bytes", 2000, 5, || {
            let key = graviola::key_agreement::mlkem768::EncapKey::from_bytes(&ek).unwrap();
            std::hint::black_box(key.encaps().unwrap());
        });
        verdict("ml-kem-768 encaps, from bytes, both", a1, a2, false);

        // Decapsulation from bytes has no Graviola row. Graviola 0.4.1 has no
        // decapsulation-key parser: its `DecapKey` comes only from `generate`
        // (or the hidden `keygen_internal`). So Graviola never does the work
        // a from-bytes decapsulation does, including the H(ek) hash check
        // that FIPS 203 7.3 requires on the decapsulation key. IronCrypto's
        // figure below includes that check, and is not compared with anything.
        per_op(
            "ironcrypto ml-kem-768 decaps, from bytes (no graviola row)",
            2000,
            5,
            || {
                ic_mlkem::MlKem768::decapsulate(&dk, &ct, &mut ss).unwrap();
            },
        );

        // PARSED ONCE, both sides. IronCrypto's prepared keys hold A^T, t and
        // H(ek) (encapsulation) and the checked s, z, t, A^T and H(ek)
        // (decapsulation). Graviola's `EncapKey` holds A^T and its `DecapKey`
        // is always in parsed form. Graviola's `encaps` consumes its key, so
        // the encapsulation row clones it per call; the row after it is that
        // clone alone, for scale.
        let p_ek = m::PreparedEncapsulationKey::new(&ek).unwrap();
        let b1 = per_op("ironcrypto ml-kem-768 encaps, parsed once", 2000, 5, || {
            p_ek.encapsulate(&mut os, &mut ct, &mut ss).unwrap();
        });
        let g_parsed = graviola::key_agreement::mlkem768::EncapKey::from_bytes(&ek).unwrap();
        let b2 = per_op("graviola ml-kem-768 encaps, parsed once", 2000, 5, || {
            std::hint::black_box(g_parsed.clone().encaps().unwrap());
        });
        verdict("ml-kem-768 encaps, parsed once, both", b1, b2, false);
        per_op("  graviola EncapKey clone alone", 2000, 5, || {
            std::hint::black_box(g_parsed.clone());
        });

        let p_dk = m::PreparedDecapsulationKey::new(&dk).unwrap();
        let q1 = per_op("ironcrypto ml-kem-768 decaps, parsed once", 2000, 5, || {
            p_dk.decapsulate(&ct, &mut ss).unwrap();
        });
        // `DecapKey::decaps` consumes the key, so the Graviola row uses the
        // hidden `decaps_internal`, which does the same work on `&self`.
        let q2 = per_op("graviola ml-kem-768 decaps, parsed once", 2000, 5, || {
            std::hint::black_box(g_dk.decaps_internal(&g_ct));
        });
        verdict("ml-kem-768 decaps, parsed once, both", q1, q2, false);
    }

    rsa(graviola::signing::rsa::KeySize::Rsa2048, 2048, msg);
}

/// The RSA rows at every size both libraries take:
/// `cargo run --release -- graviola-rsa`.
pub fn rsa_sizes() {
    println!();
    backends();
    println!("RSA PKCS#1 v1.5 with SHA-256, per operation (lower is better)");
    let msg = b"benchmark message";
    use graviola::signing::rsa::KeySize;
    for (size, bits) in [
        (KeySize::Rsa2048, 2048),
        (KeySize::Rsa3072, 3072),
        (KeySize::Rsa4096, 4096),
    ] {
        rsa(size, bits, msg);
    }
}

/// PKCS#1 v1.5 signing and verification, on one key loaded into both.
fn rsa(size: graviola::signing::rsa::KeySize, bits: usize, msg: &[u8]) {
    let g_key = graviola::signing::rsa::SigningKey::generate(size).unwrap();
    let mut der = vec![0u8; 4096];
    let der = g_key.to_pkcs8_der(&mut der).unwrap();
    let ic_pkix::PrivateKeyInfo::Rsa {
        public_exponent,
        prime1,
        prime2,
        ..
    } = ic_pkix::PrivateKeyInfo::from_der(der).unwrap()
    else {
        panic!("graviola wrote an RSA key that is not RSA");
    };
    let ic_key = ic_rsa::RsaPrivateKey::from_primes(prime1, prime2, public_exponent).unwrap();
    // Fewer iterations as the key grows: signing is cubic in the size.
    let (sign_iters, verify_iters) = match bits {
        2048 => (200, 5000),
        3072 => (60, 2000),
        _ => (30, 1000),
    };
    let mut sig = vec![0u8; bits / 8];
    let r1 = per_op(&format!("ironcrypto rsa-{bits} pkcs1 sign"), sign_iters, 5, || {
        ic_rsa::Pkcs1Sha256::sign(&ic_key, msg, &mut sig).unwrap();
    });
    let mut g_sig = vec![0u8; bits / 8];
    let r2 = per_op(&format!("graviola rsa-{bits} pkcs1 sign"), sign_iters, 5, || {
        std::hint::black_box(g_key.sign_pkcs1_sha256(&mut g_sig, msg).unwrap());
    });
    verdict(&format!("rsa-{bits} sign"), r1, r2, false);
    let public = ic_key.public_key();
    let r3 = per_op(&format!("ironcrypto rsa-{bits} pkcs1 verify"), verify_iters, 5, || {
        ic_rsa::Pkcs1Sha256::verify(&public, msg, &sig).unwrap();
    });
    let g_pub = g_key.public_key();
    let r4 = per_op(&format!("graviola rsa-{bits} pkcs1 verify"), verify_iters, 5, || {
        g_pub.verify_pkcs1_sha256(&sig, msg).unwrap();
    });
    verdict(&format!("rsa-{bits} verify"), r3, r4, false);
}

/// The P-384 rows alone: `cargo run --release -- graviola-p384`.
pub fn p384() {
    println!();
    backends();
    println!("P-384, per operation (lower is better)");
    let msg = b"benchmark message";
    // The same three rows as P-256, on one key loaded into both.
    let q_sk = [0x5au8; 48];
    let mut q_pk = [0u8; 97];
    ironcrypto::ec::EcdhP384::public_key(&q_sk, &mut q_pk).unwrap();
    let mut q_shared = [0u8; 48];
    let q1 = per_op("ironcrypto p-384 ecdh", 500, 5, || {
        ironcrypto::ec::EcdhP384::agree(&q_sk, &q_pk, &mut q_shared).unwrap();
    });
    let gq_sk = graviola::key_agreement::p384::StaticPrivateKey::from_bytes(&q_sk).unwrap();
    let gq_pk = graviola::key_agreement::p384::PublicKey::from_x962_uncompressed(&q_pk).unwrap();
    let q2 = per_op("graviola p-384 ecdh", 500, 5, || {
        std::hint::black_box(gq_sk.diffie_hellman(&gq_pk).unwrap());
    });
    assert_eq!(gq_sk.diffie_hellman(&gq_pk).unwrap().0, q_shared);
    verdict("p-384 ecdh", q1, q2, false);

    let mut q_sig = [0u8; 96];
    let f1 = per_op("ironcrypto ecdsa p-384 sign", 500, 5, || {
        ironcrypto::ec::p384::EcdsaP384Sha384::sign(&q_sk, msg, &mut q_sig).unwrap();
    });
    let gq_signer = graviola::signing::ecdsa::SigningKey::<graviola::signing::ecdsa::P384> {
        private_key: graviola::key_agreement::p384::StaticPrivateKey::from_bytes(&q_sk).unwrap(),
    };
    let mut gq_sig = [0u8; 96];
    let f2 = per_op("graviola ecdsa p-384 sign", 500, 5, || {
        std::hint::black_box(
            gq_signer
                .sign::<graviola::hashing::Sha384>(&[msg], &mut gq_sig)
                .unwrap(),
        );
    });
    verdict("ecdsa p-384 sign", f1, f2, false);

    let f3 = per_op("ironcrypto ecdsa p-384 verify", 500, 5, || {
        ironcrypto::ec::p384::EcdsaP384Sha384::verify(&q_pk, msg, &q_sig).unwrap();
    });
    let gq_verifier =
        graviola::signing::ecdsa::VerifyingKey::<graviola::signing::ecdsa::P384>::from_x962_uncompressed(
            &q_pk,
        )
        .unwrap();
    let f4 = per_op("graviola ecdsa p-384 verify", 500, 5, || {
        gq_verifier
            .verify::<graviola::hashing::Sha384>(&[msg], &q_sig)
            .unwrap();
    });
    verdict("ecdsa p-384 verify", f3, f4, false);
}

/// The ChaCha20-Poly1305 rows alone, with the AEAD split into its halves.
///
/// ```text
/// cargo run --release -- graviola-chacha
/// ```
///
/// The split says which half limits the AEAD: the keystream alone and
/// Poly1305 alone. The two back to back, against the AEAD, leave what the
/// AEAD adds per message: the Poly1305 key block and the padding.
pub fn chacha() {
    println!();
    println!("IronCrypto vs Graviola 0.4.1, ChaCha20-Poly1305 — best of {REPEATS}");
    backends();
    let key = [0x2au8; 32];
    let nonce = [0x24u8; 12];
    let mut data = vec![0u8; SIZE];
    let mut tag = [0u8; 16];
    for (label, size) in [("4 MiB", SIZE), ("1 KiB", 1024), ("64 B", 64)] {
        println!();
        println!("{label} messages");
        let reps = SIZE / size;
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
        bulk(
            "  ironcrypto chacha20 keystream only",
            SIZE,
            REPEATS,
            || {
                for chunk in data.chunks_mut(size).take(reps) {
                    ic_cipher::chacha20_xor(&key, &nonce, 1, chunk).unwrap();
                }
            },
        );
        bulk("  ironcrypto poly1305 only", SIZE, REPEATS, || {
            for chunk in data.chunks(size).take(reps) {
                std::hint::black_box(<ic_cipher::Poly1305 as Mac>::mac(&key, chunk).unwrap());
            }
        });
        bulk(
            "  ironcrypto both halves, back to back",
            SIZE,
            REPEATS,
            || {
                for chunk in data.chunks_mut(size).take(reps) {
                    ic_cipher::chacha20_xor(&key, &nonce, 1, chunk).unwrap();
                    std::hint::black_box(<ic_cipher::Poly1305 as Mac>::mac(&key, chunk).unwrap());
                }
            },
        );
    }
}

/// The backends this build selects, so a run says which paths it measured.
/// `--cfg ic_no_avx512` turns the AVX-512 paths off. The ChaCha20 and AES-GCM
/// kernels have no public reporter; their choice is pinned by unit tests in
/// `ic-cipher` instead.
fn backends() {
    println!("IronCrypto X25519 backend: {:?}", ic_ec::curve25519_backend());
    println!(
        "IronCrypto RSA-2048 backend: {:?}",
        ic_rsa::uint::backend_for(32)
    );
    if cfg!(ic_no_avx512) {
        println!("IronCrypto built with --cfg ic_no_avx512 (AVX-512 paths off)");
    }
}
