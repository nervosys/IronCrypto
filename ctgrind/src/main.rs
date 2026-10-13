//! Does any secret reach a branch or a memory address? Ask Valgrind.
//!
//! The technique is Adam Langley's ctgrind, done with memcheck alone: mark
//! the bytes of a secret *undefined*, run the operation, and memcheck
//! reports every conditional jump that depends on them and every load or
//! store whose address does. Defined-ness propagates through arithmetic
//! exactly as secret-ness does, so a report is a place where the program's
//! control flow or memory access pattern was a function of the secret.
//!
//! Each case runs in a process of its own (`scripts/ctgrind.sh` drives them),
//! so a report is attributed to one operation. Cases exist for IronCrypto and,
//! for comparison, for Graviola, through each library's public API with the
//! same inputs: the secrets marked are the ones a caller would hold.
//!
//! What this cannot see: anything Valgrind's virtual CPU does not run. It
//! reports CPUID without AVX-512, so paths behind runtime detection of it are
//! not exercised; and it says nothing about timing that does not come from a
//! branch or an address -- variable-latency instructions are out of its
//! reach, which is what `ic timing` and the compiled-code gate are for.
//!
//! A report is not automatically a defect. Some branches on secret-derived
//! values are by design and declassify a result that is public anyway: an
//! AEAD's decision that a tag was wrong, a signature's rejection of an
//! unlucky nonce. Those are listed, with the reason, in `docs/CTGRIND.md`.

use std::env;
use std::process::ExitCode;

mod vg {
    //! Valgrind client requests, without valgrind.h: the magic instruction
    //! sequence from valgrind.h for amd64, which is a no-op on a real CPU.

    const MC_BASE: usize = ((b'M' as usize) << 24) | ((b'C' as usize) << 16);
    const MAKE_MEM_UNDEFINED: usize = MC_BASE + 1;
    const MAKE_MEM_DEFINED: usize = MC_BASE + 2;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn request(code: usize, a1: usize, a2: usize) -> usize {
        let args: [usize; 6] = [code, a1, a2, 0, 0, 0];
        let mut result: usize = 0;
        // SAFETY: the rotations leave rdi unchanged (3+13+61+51 = 128) and
        // xchg rbx,rbx is a no-op; under Valgrind the sequence is recognised
        // and the request at `args` is read. Nothing is written but rdx.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                in("rax") args.as_ptr(),
                inout("rdx") result,
                out("rdi") _,
                options(nostack),
            );
        }
        result
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    fn request(_code: usize, _a1: usize, _a2: usize) -> usize {
        0
    }

    /// Mark `bytes` as secret.
    pub fn secret<T: ?Sized>(value: &T) {
        request(
            MAKE_MEM_UNDEFINED,
            value as *const T as *const u8 as usize,
            core::mem::size_of_val(value),
        );
    }

    /// Mark `bytes` as public again, once the program has released them.
    pub fn public<T: ?Sized>(value: &T) {
        request(
            MAKE_MEM_DEFINED,
            value as *const T as *const u8 as usize,
            core::mem::size_of_val(value),
        );
    }
}

use vg::{public, secret};

type Case = (&'static str, fn());

/// Positive controls: code that does depend on a secret, which must be
/// reported. Without them a clean run could mean the client requests never
/// reached Valgrind.
fn control_cases() -> Vec<Case> {
    vec![
        ("control-branch-on-secret", || {
            let s = [7u8; 4];
            secret(&s);
            // A loop whose trip count is the secret: a conditional jump the
            // compiler cannot turn into a conditional move.
            let mut n = 0u32;
            while n < u32::from(std::hint::black_box(s[0])) {
                n = std::hint::black_box(n + 1);
            }
        }),
        ("control-index-by-secret", || {
            let table = [0u8; 256];
            let s = [7u8; 4];
            secret(&s);
            let i = std::hint::black_box(s[0]) as usize;
            std::hint::black_box(std::hint::black_box(&table)[i]);
        }),
    ]
}

fn ic_cases() -> Vec<Case> {
    use ironcrypto::core_types::traits::{Aead, Digest, Kdf, KeyAgreement, Mac, SignatureScheme};
    vec![
        ("ic-aes-256-gcm-seal", || {
            let key = [7u8; 32];
            let mut msg = [9u8; 100];
            secret(&key);
            secret(&msg);
            let c = ironcrypto::cipher::Aes256Gcm::new(&key).unwrap();
            let mut tag = [0u8; 16];
            let r = c.seal_detached(&[1u8; 12], b"aad", &mut msg, &mut tag);
            public(&r);
            r.unwrap();
        }),
        ("ic-aes-256-gcm-open", || {
            let key = [7u8; 32];
            let mut msg = [9u8; 100];
            let mut tag = [0u8; 16];
            ironcrypto::cipher::Aes256Gcm::new(&key)
                .unwrap()
                .seal_detached(&[1u8; 12], b"aad", &mut msg, &mut tag)
                .unwrap();
            secret(&key);
            let c = ironcrypto::cipher::Aes256Gcm::new(&key).unwrap();
            let r = c.open_detached(&[1u8; 12], b"aad", &mut msg, &tag);
            public(&r);
            r.unwrap();
        }),
        ("ic-chacha20-poly1305-seal", || {
            let key = [7u8; 32];
            let mut msg = [9u8; 100];
            secret(&key);
            secret(&msg);
            let c = ironcrypto::cipher::ChaCha20Poly1305::new(&key).unwrap();
            let mut tag = [0u8; 16];
            let r = c.seal_detached(&[1u8; 12], b"aad", &mut msg, &mut tag);
            public(&r);
            r.unwrap();
        }),
        ("ic-hmac-sha256", || {
            let key = [7u8; 32];
            let msg = [9u8; 100];
            secret(&key);
            secret(&msg);
            let r = ironcrypto::mac::HmacSha256::mac(&key, &msg);
            public(&r);
            r.unwrap();
        }),
        ("ic-hkdf-sha256", || {
            let ikm = [7u8; 32];
            secret(&ikm);
            let mut out = [0u8; 64];
            let r = ironcrypto::kdf::Hkdf::<ironcrypto::mac::HmacSha256>::derive(
                &ikm, b"salt", b"info", &mut out,
            );
            public(&r);
            r.unwrap();
        }),
        ("ic-sha256", || {
            let msg = [9u8; 300];
            secret(&msg);
            let r = ironcrypto::hash::Sha256::digest(&msg);
            public(&r);
            r.unwrap();
        }),
        ("ic-sha512", || {
            let msg = [9u8; 300];
            secret(&msg);
            let r = ironcrypto::hash::Sha512::digest(&msg);
            public(&r);
            r.unwrap();
        }),
        ("ic-sha3-256", || {
            let msg = [9u8; 300];
            secret(&msg);
            let r = ironcrypto::hash::Sha3_256::digest(&msg);
            public(&r);
            r.unwrap();
        }),
        ("ic-x25519", || {
            let sk = [0x77u8; 32];
            let mut pk = [0u8; 32];
            ironcrypto::ec::X25519::public_key(&[0x55u8; 32], &mut pk).unwrap();
            secret(&sk);
            let mut out = [0u8; 32];
            let r = ironcrypto::ec::X25519::agree(&sk, &pk, &mut out);
            public(&r);
            r.unwrap();
        }),
        ("ic-p256-ecdh", || {
            let sk = [0x5au8; 32];
            let mut pk = [0u8; 65];
            ironcrypto::ec::EcdhP256::public_key(&[0x33u8; 32], &mut pk).unwrap();
            secret(&sk);
            let mut out = [0u8; 32];
            let r = ironcrypto::ec::EcdhP256::agree(&sk, &pk, &mut out);
            public(&r);
            r.unwrap();
        }),
        ("ic-p256-ecdsa-sign", || {
            let sk = [0x5au8; 32];
            secret(&sk);
            let mut sig = [0u8; 64];
            let r = ironcrypto::ec::p256::EcdsaP256Sha256::sign(&sk, b"message", &mut sig);
            public(&r);
            r.unwrap();
        }),
        ("ic-p384-ecdsa-sign", || {
            let sk = [0x5au8; 48];
            secret(&sk);
            let mut sig = [0u8; 96];
            let r = ironcrypto::ec::p384::EcdsaP384Sha384::sign(&sk, b"message", &mut sig);
            public(&r);
            r.unwrap();
        }),
        ("ic-ed25519-sign", || {
            let seed = [0x44u8; 32];
            secret(&seed);
            let mut sig = [0u8; 64];
            let r = ironcrypto::ec::Ed25519::sign(&seed, b"message", &mut sig);
            public(&r);
            r.unwrap();
        }),
        ("ic-ml-kem-768-keygen", || {
            use ic_mlkem::kem as m;
            let (d, z) = ([1u8; 32], [2u8; 32]);
            secret(&d);
            secret(&z);
            let mut ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
            let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
            let r = ic_mlkem::MlKem768::keygen_deterministic(&d, &z, &mut ek, &mut dk);
            public(&r);
            r.unwrap();
        }),
        ("ic-ml-kem-768-encapsulate", || {
            use ic_mlkem::kem as m;
            let mut ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
            let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
            ic_mlkem::MlKem768::keygen_deterministic(&[1u8; 32], &[2u8; 32], &mut ek, &mut dk)
                .unwrap();
            let msg = [3u8; 32];
            secret(&msg);
            let mut ct = Box::new([0u8; m::CIPHERTEXT_LEN]);
            let mut ss = [0u8; 32];
            let r = ic_mlkem::MlKem768::encapsulate_deterministic(&msg, &ek, &mut ct, &mut ss);
            public(&r);
            r.unwrap();
        }),
        ("ic-ml-kem-768-decapsulate", || {
            use ic_mlkem::kem as m;
            let mut ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
            let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
            ic_mlkem::MlKem768::keygen_deterministic(&[1u8; 32], &[2u8; 32], &mut ek, &mut dk)
                .unwrap();
            let mut ct = Box::new([0u8; m::CIPHERTEXT_LEN]);
            let mut ss = [0u8; 32];
            ic_mlkem::MlKem768::encapsulate_deterministic(&[3u8; 32], &ek, &mut ct, &mut ss)
                .unwrap();
            // The secret parts of the decapsulation key: the secret vector
            // and the rejection seed z. The encapsulation key and its hash,
            // stored beside them, are public.
            secret(&dk[..384 * 3]);
            secret(&dk[m::DECAPS_KEY_LEN - 32..]);
            // A tampered ciphertext as well, so the rejection path runs.
            for flip in [false, true] {
                let mut c = ct.clone();
                c[0] ^= flip as u8;
                let r = ic_mlkem::MlKem768::decapsulate(&dk, &c, &mut ss);
                public(&r);
                r.unwrap();
            }
        }),
        ("ic-ml-dsa-65-sign", || {
            let mut pk = Box::new([0u8; ic_mldsa::sign::PUBLIC_KEY_LEN]);
            let mut sk = Box::new([0u8; ic_mldsa::sign::SECRET_KEY_LEN]);
            assert!(ic_mldsa::sign::keygen(&[5u8; 32], &mut pk, &mut sk));
            secret(&sk[..]);
            let mut sig = Box::new([0u8; ic_mldsa::sign::SIGNATURE_LEN]);
            let ok = ic_mldsa::sign::sign_deterministic(&sk, b"message", b"", &mut sig);
            public(&ok);
            assert!(ok);
        }),
        ("ic-rsa-2048-sign", || {
            let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x41u8; 48], b"ctgrind").unwrap();
            let key = ic_rsa::generate(2048, &mut rng).unwrap();
            // The whole private key: its public modulus and exponent too, which
            // the checks on it may branch on. Reports there are read and
            // classified rather than avoided by marking less.
            secret(&key);
            let mut sig = vec![0u8; 256];
            let r = ironcrypto::rsa::Pkcs1Sha256::sign(&key, b"message", &mut sig);
            public(&r);
            r.unwrap();
        }),
    ]
}

fn graviola_cases() -> Vec<Case> {
    vec![
        ("graviola-aes-256-gcm-seal", || {
            let key = [7u8; 32];
            let mut msg = [9u8; 100];
            secret(&key);
            secret(&msg);
            let c = graviola::aead::AesGcm::new(&key);
            let mut tag = [0u8; 16];
            c.encrypt(&[1u8; 12], b"aad", &mut msg, &mut tag);
        }),
        ("graviola-chacha20-poly1305-seal", || {
            let key = [7u8; 32];
            let mut msg = [9u8; 100];
            secret(&key);
            secret(&msg);
            let c = graviola::aead::ChaCha20Poly1305::new(key);
            let mut tag = [0u8; 16];
            c.encrypt(&[1u8; 12], b"aad", &mut msg, &mut tag);
        }),
        ("graviola-hmac-sha256", || {
            let key = [7u8; 32];
            let msg = [9u8; 100];
            secret(&key);
            secret(&msg);
            let mut h = graviola::hashing::hmac::Hmac::<graviola::hashing::Sha256>::new(key);
            h.update(msg);
            let _ = h.finish();
        }),
        ("graviola-sha256", || {
            let msg = [9u8; 300];
            secret(&msg);
            let mut c = graviola::hashing::sha2::Sha256Context::new();
            c.update(&msg);
            let _ = c.finish();
        }),
        ("graviola-x25519", || {
            let sk = [0x77u8; 32];
            let pk = graviola::key_agreement::x25519::StaticPrivateKey::from_array(&[0x55u8; 32])
                .public_key();
            secret(&sk);
            let k = graviola::key_agreement::x25519::StaticPrivateKey::from_array(&sk);
            let r = k.diffie_hellman(&pk);
            public(&r);
            r.unwrap();
        }),
        ("graviola-p256-ecdh", || {
            let peer = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&[0x33u8; 32])
                .unwrap()
                .public_key_uncompressed();
            let pk = graviola::key_agreement::p256::PublicKey::from_x962_uncompressed(&peer).unwrap();
            let sk = [0x5au8; 32];
            secret(&sk);
            let k = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&sk);
            public(&k.is_ok());
            let r = k.unwrap().diffie_hellman(&pk);
            public(&r);
            r.unwrap();
        }),
        ("graviola-p256-ecdsa-sign", || {
            let sk = [0x5au8; 32];
            secret(&sk);
            let key = graviola::key_agreement::p256::StaticPrivateKey::from_bytes(&sk);
            public(&key.is_ok());
            let signer = graviola::signing::ecdsa::SigningKey::<graviola::signing::ecdsa::P256> {
                private_key: key.unwrap(),
            };
            let mut sig = [0u8; 64];
            let r = signer.sign::<graviola::hashing::Sha256>(&[b"message"], &mut sig).map(|_| ());
            public(&r);
            r.unwrap();
        }),
        ("graviola-ed25519-sign", || {
            let seed = [0x44u8; 32];
            secret(&seed);
            let k = graviola::signing::eddsa::Ed25519SigningKey::from_bytes(&seed);
            public(&k.is_ok());
            let _ = k.unwrap().sign(b"message");
        }),
        ("graviola-ml-kem-768-decapsulate", || {
            let seed = [7u8; 64];
            let dk = graviola::key_agreement::mlkem768::DecapKey::keygen_internal(&seed);
            let (_, ct) = dk.encapsulation_key().encaps().unwrap();
            // Graviola's DecapKey has no public way to mark its secret parts,
            // so the seed it is made from is marked and the key rebuilt.
            secret(&seed);
            let dk = graviola::key_agreement::mlkem768::DecapKey::keygen_internal(&seed);
            public(&seed);
            let _ = dk.decaps_internal(&ct);
        }),
    ]
}

fn main() -> ExitCode {
    let all: Vec<Case> = control_cases()
        .into_iter()
        .chain(ic_cases())
        .chain(graviola_cases())
        .collect();
    match env::args().nth(1).as_deref() {
        Some("--list") | None => {
            for (name, _) in &all {
                println!("{name}");
            }
            ExitCode::SUCCESS
        }
        Some(name) => match all.iter().find(|(n, _)| *n == name) {
            Some((_, f)) => {
                f();
                ExitCode::SUCCESS
            }
            None => {
                eprintln!("no case {name}");
                ExitCode::FAILURE
            }
        },
    }
}
