//! Throughput of IronCrypto against the mature Rust implementations.
//!
//! ```text
//! cargo run --release -- hw
//! RUSTFLAGS="--cfg aes_force_soft" cargo run --release -- soft
//! ```
//!
//! RustCrypto's `aes` 0.8 selects its software path with a cfg flag rather than
//! a Cargo feature, so the second form rebuilds the dependency. The argument is
//! only a label: nothing here can detect which path `aes` was compiled with, so
//! it reports what it was told and the caller has to be right about it.
//!
//! The software run is the one that matters for the portable backend.
//! RustCrypto's software AES is fixsliced -- constant-time and table-free, the
//! same property IronCrypto's portable path is built for -- so comparing the
//! two measures the implementation. Comparing IronCrypto's software path
//! against AES-NI measures the instruction set instead, which nobody needs a
//! benchmark to predict.
//!
//! Bulk figures are wall-clock over a large buffer, repeated, minimum taken. A
//! minimum rather than a mean because the machine is shared with whatever else
//! is running, and interference only ever makes a result slower. Per-operation
//! figures are the same idea over an iteration count.

use std::time::Instant;

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::KeyInit as _;
use ic_core::traits::{Aead, BlockCipher, Digest, KeyAgreement, Mac, SignatureScheme};

const SIZE: usize = 4 * 1024 * 1024;
const REPEATS: usize = 5;

fn mib_s(bytes: usize, secs: f64) -> f64 {
    (bytes as f64) / secs / (1024.0 * 1024.0)
}

/// Bulk throughput: best rate over `repeats` passes.
fn bulk(label: &str, bytes: usize, repeats: usize, mut f: impl FnMut()) -> f64 {
    let mut fastest = f64::INFINITY;
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        let s = t.elapsed().as_secs_f64();
        if s < fastest {
            fastest = s;
        }
    }
    let rate = mib_s(bytes, fastest);
    println!("  {label:<40} {rate:>12.1} MiB/s");
    rate
}

/// Per-operation cost: best microseconds over `repeats` batches of `iters`.
fn per_op(label: &str, iters: usize, repeats: usize, mut f: impl FnMut()) -> f64 {
    let mut fastest = f64::INFINITY;
    for _ in 0..repeats {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let s = t.elapsed().as_secs_f64();
        if s < fastest {
            fastest = s;
        }
    }
    let us = fastest / (iters as f64) * 1e6;
    println!("  {label:<40} {us:>12.1} us/op");
    us
}

/// `ic` against `other`, phrased so the direction is unambiguous.
fn verdict(what: &str, ic: f64, other: f64, higher_is_better: bool) {
    let (ratio, word) = if higher_is_better {
        if ic >= other {
            (ic / other, "faster")
        } else {
            (other / ic, "SLOWER")
        }
    } else if ic <= other {
        (other / ic, "faster")
    } else {
        (ic / other, "SLOWER")
    };
    println!("  {what:<40} {ratio:>9.2}x {word}");
}

fn main() {
    let soft = std::env::args().nth(1).as_deref() == Some("soft");
    println!();
    println!("IronCrypto vs RustCrypto/dalek — 4 MiB buffers, best of {REPEATS}");
    println!(
        "RustCrypto AES path: {}",
        if soft {
            "forced software (fixsliced)"
        } else {
            "runtime-detected (AES-NI where available)"
        }
    );
    println!(
        "IronCrypto AES backend: {:?}",
        ic_cipher::aes::active_backend()
    );

    let key = [0x2au8; 32];
    let mut data = vec![0u8; SIZE];
    let mut tag = [0u8; 16];

    // ---------------------------------------------------------------- AES ---
    println!();
    println!("AES-256, raw blocks");
    let ic_aes = <ic_cipher::Aes256 as BlockCipher>::new(&key).unwrap();
    let a = bulk("iron-crypto (active)", SIZE, REPEATS, || {
        ic_aes.encrypt_blocks(&mut data).unwrap();
    });
    let rc_key = aes::cipher::generic_array::GenericArray::from_slice(&key);
    let rc = aes::Aes256::new(rc_key);
    let b = bulk("rustcrypto aes", SIZE, REPEATS, || {
        for c in data.chunks_exact_mut(16) {
            rc.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(c));
        }
    });
    let small = 64 * 1024;
    let mut small_buf = vec![0u8; small];
    let ic_port = ic_cipher::Aes256::new_portable(&key).unwrap();
    let p = bulk("iron-crypto (portable)", small, 3, || {
        ic_port.encrypt_blocks(&mut small_buf).unwrap();
    });
    verdict("aes blocks, active vs rustcrypto", a, b, true);
    verdict("aes blocks, portable vs rustcrypto", p, b, true);

    // --------------------------------------------------------------- AEAD ---
    println!();
    println!("AEAD, sealing in place");
    let gcm = <ic_cipher::Aes256Gcm as Aead>::new(&key).unwrap();
    let g1 = bulk("iron-crypto aes-256-gcm", SIZE, REPEATS, || {
        gcm.seal_detached(&[0u8; 12], b"", &mut data, &mut tag)
            .unwrap();
    });
    let rc_gcm = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let g2 = bulk("rustcrypto aes-gcm", SIZE, REPEATS, || {
        let _ = rc_gcm
            .encrypt_in_place_detached(nonce, b"", &mut data)
            .unwrap();
    });
    verdict("aes-256-gcm", g1, g2, true);

    let cc = <ic_cipher::ChaCha20Poly1305 as Aead>::new(&key).unwrap();
    let c1 = bulk("iron-crypto chacha20-poly1305", SIZE, REPEATS, || {
        cc.seal_detached(&[0u8; 12], b"", &mut data, &mut tag)
            .unwrap();
    });
    let rc_cc = chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
    let cc_nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]);
    let c2 = bulk("rustcrypto chacha20poly1305", SIZE, REPEATS, || {
        let _ = rc_cc
            .encrypt_in_place_detached(cc_nonce, b"", &mut data)
            .unwrap();
    });
    verdict("chacha20-poly1305", c1, c2, true);

    // Which half is the cost? The AEAD is a stream cipher and a one-time MAC,
    // and they fail differently: a scalar ChaCha loses to SIMD, while Poly1305
    // is a Horner chain like GHASH and can lose to its own latency. Guessing
    // between them is how the GCM gap nearly got attributed to the cipher.
    println!();
    println!("ChaCha20-Poly1305, split");
    bulk("  iron-crypto chacha20 keystream only", SIZE, REPEATS, || {
        ic_cipher::chacha20_xor(&key, &[0u8; 12], 1, &mut data).unwrap();
    });
    bulk("  iron-crypto poly1305 only", SIZE, REPEATS, || {
        let _ = <ic_cipher::Poly1305 as Mac>::mac(&key, &data).unwrap();
    });

    // ------------------------------------------------------------- hashes ---
    println!();
    println!("Hashes");
    let mut out32 = [0u8; 32];
    let h1 = bulk("iron-crypto sha-256", SIZE, REPEATS, || {
        out32 = iron_crypto::hash::Sha256::digest(&data);
    });
    let h2 = bulk("rustcrypto sha2 sha-256", SIZE, REPEATS, || {
        use sha2::Digest;
        let _ = sha2::Sha256::digest(&data);
    });
    verdict("sha-256", h1, h2, true);

    let mut out64 = [0u8; 64];
    let h3 = bulk("iron-crypto sha-512", SIZE, REPEATS, || {
        out64 = iron_crypto::hash::Sha512::digest(&data);
    });
    let h4 = bulk("rustcrypto sha2 sha-512", SIZE, REPEATS, || {
        use sha2::Digest;
        let _ = sha2::Sha512::digest(&data);
    });
    verdict("sha-512", h3, h4, true);

    let h5 = bulk("iron-crypto sha3-256", SIZE, REPEATS, || {
        out32 = iron_crypto::hash::Sha3_256::digest(&data);
    });
    let h6 = bulk("rustcrypto sha3-256", SIZE, REPEATS, || {
        use sha3::Digest;
        let _ = sha3::Sha3_256::digest(&data);
    });
    verdict("sha3-256", h5, h6, true);

    // ---------------------------------------------------------------- MAC ---
    println!();
    println!("HMAC-SHA256");
    let m1 = bulk("iron-crypto hmac-sha256", SIZE, REPEATS, || {
        let _ = iron_crypto::mac::HmacSha256::mac(&key, &data).unwrap();
    });
    let m2 = bulk("rustcrypto hmac", SIZE, REPEATS, || {
        use hmac::Mac as _;
        let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&key).unwrap();
        m.update(&data);
        let _ = m.finalize();
    });
    verdict("hmac-sha256", m1, m2, true);

    // ---------------------------------------------------------- public key ---
    println!();
    println!("Public key, per operation (lower is better)");

    let sk = [0x77u8; 32];
    let mut pk = [0u8; 32];
    iron_crypto::ec::X25519::public_key(&sk, &mut pk).unwrap();
    let mut shared = [0u8; 32];
    let x1 = per_op("iron-crypto x25519 agree", 3000, 5, || {
        iron_crypto::ec::X25519::agree(&sk, &pk, &mut shared).unwrap();
    });
    let d_sk = x25519_dalek::StaticSecret::from(sk);
    let d_pk = x25519_dalek::PublicKey::from(pk);
    let x2 = per_op("dalek x25519 agree", 3000, 5, || {
        let _ = d_sk.diffie_hellman(&d_pk);
    });
    verdict("x25519 agreement", x1, x2, false);

    let msg = b"benchmark message";
    let mut sig = [0u8; 64];
    // dalek's SigningKey derives its public key once at construction, so
    // comparing it against the seed-only call had IronCrypto doing a second
    // basepoint multiplication dalek never pays. `Ed25519Key` is the
    // equivalent; both figures are kept so the cost of that derivation shows.
    let e0 = per_op("iron-crypto ed25519 sign (from seed)", 3000, 5, || {
        iron_crypto::ec::Ed25519::sign(&sk, msg, &mut sig).unwrap();
    });
    let ic_key = iron_crypto::ec::Ed25519Key::from_seed(&sk).unwrap();
    let e1 = per_op("iron-crypto ed25519 sign (cached key)", 3000, 5, || {
        ic_key.sign(msg, &mut sig).unwrap();
    });
    let d_key = ed25519_dalek::SigningKey::from_bytes(&sk);
    let e2 = per_op("dalek ed25519 sign", 3000, 5, || {
        use ed25519_dalek::Signer;
        let _ = d_key.sign(msg);
    });
    verdict("ed25519 sign (cached vs dalek)", e1, e2, false);
    verdict("ed25519 sign, seed vs cached", e0, e1, false);

    let mut ed_pk = [0u8; 32];
    iron_crypto::ec::Ed25519::public_key(&sk, &mut ed_pk).unwrap();
    iron_crypto::ec::Ed25519::sign(&sk, msg, &mut sig).unwrap();
    // Point primitives against dalek's, directly. Everything above is a whole
    // operation, which cannot separate "our field arithmetic is slower" from
    // "our scalar multiplication does more work". These can.
    println!("
Edwards point primitives (lower is better)");
    {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use ic_ec::ed25519::Point;

        let seed = [9u8; 32];
        let mut pk = [0u8; 32];
        <ic_ec::Ed25519 as SignatureScheme>::public_key(&seed, &mut pk).unwrap();
        let ours = Point::decompress(&pk).unwrap();
        let theirs = CompressedEdwardsY(pk).decompress().unwrap();

        let a0 = per_op("iron-crypto point add", 20000, 5, || {
            std::hint::black_box(std::hint::black_box(&ours).add(std::hint::black_box(&ours)));
        });
        let a1 = per_op("dalek point add", 20000, 5, || {
            std::hint::black_box(std::hint::black_box(&theirs) + std::hint::black_box(&theirs));
        });
        verdict("point addition", a0, a1, false);

        let d0 = per_op("iron-crypto point double", 20000, 5, || {
            std::hint::black_box(std::hint::black_box(&ours).double());
        });
        let d1 = per_op("dalek point double (via mul by 2)", 20000, 5, || {
            let two = curve25519_dalek::scalar::Scalar::from(2u64);
            std::hint::black_box(std::hint::black_box(&theirs) * two);
        });
        println!("  (dalek has no public double; the row above is a scalar mul, not comparable)");
        let _ = (d0, d1);

        // The double-scalar multiplication on its own, which is what
        // verification spends most of its time in.
        use curve25519_dalek::scalar::Scalar as DScalar;
        let mut kb = [0u8; 32];
        kb.copy_from_slice(&pk);
        kb[31] &= 0x0f;
        let k = DScalar::from_bytes_mod_order(kb);
        let s = DScalar::from_bytes_mod_order(kb);
        let m0 = per_op("iron-crypto [k]A + [s]B", 2000, 5, || {
            std::hint::black_box(ic_ec::ed25519::double_scalar_mul_vartime_for_bench(
                std::hint::black_box(&ours),
                &kb,
                &kb,
            ));
        });
        let m1 = per_op("dalek [k]A + [s]B", 2000, 5, || {
            std::hint::black_box(
                curve25519_dalek::edwards::EdwardsPoint::vartime_double_scalar_mul_basepoint(
                    &k,
                    std::hint::black_box(&theirs),
                    &s,
                ),
            );
        });
        verdict("double-scalar multiplication", m0, m1, false);

        let b0 = per_op("iron-crypto [s]B (const time)", 5000, 5, || {
            std::hint::black_box(ic_ec::ed25519::mul_basepoint_for_bench(std::hint::black_box(
                &kb,
            )));
        });
        let b1 = per_op("dalek [s]B (const time)", 5000, 5, || {
            std::hint::black_box(curve25519_dalek::edwards::EdwardsPoint::mul_base(
                std::hint::black_box(&k),
            ));
        });
        verdict("basepoint multiplication", b0, b1, false);

        let p0 = per_op("iron-crypto compress", 20000, 5, || {
            std::hint::black_box(std::hint::black_box(&ours).compress());
        });
        let p1 = per_op("dalek compress", 20000, 5, || {
            std::hint::black_box(std::hint::black_box(&theirs).compress());
        });
        verdict("compression", p0, p1, false);

        let c0 = per_op("iron-crypto decompress", 20000, 5, || {
            std::hint::black_box(Point::decompress(std::hint::black_box(&pk)));
        });
        let c1 = per_op("dalek decompress", 20000, 5, || {
            std::hint::black_box(CompressedEdwardsY(std::hint::black_box(pk)).decompress());
        });
        verdict("decompression", c0, c1, false);
    }

    // Held, not rebuilt per call -- the like-for-like comparison with dalek's
    // VerifyingKey, which caches its decompressed point the same way.
    let ic_vk = ic_ec::Ed25519VerifyKey::from_bytes(&ed_pk).unwrap();
    let e3 = per_op("iron-crypto ed25519 verify", 3000, 5, || {
        ic_vk.verify(msg, &sig).unwrap();
    });
    let e3b = per_op("iron-crypto ed25519 verify (from bytes)", 3000, 5, || {
        iron_crypto::ec::Ed25519::verify(&ed_pk, msg, &sig).unwrap();
    });
    let d_vk = d_key.verifying_key();
    let d_sig = {
        use ed25519_dalek::Signer;
        d_key.sign(msg)
    };
    let e4 = per_op("dalek ed25519 verify", 3000, 5, || {
        use ed25519_dalek::Verifier;
        d_vk.verify(msg, &d_sig).unwrap();
    });
    verdict("ed25519 verify", e3, e4, false);
    verdict("ed25519 verify, bytes vs held key", e3b, e3, false);

    // How much of ECDSA is the scalar multiplication? ECDH is exactly one, on
    // an arbitrary point, so it separates the multiplication from RFC 6979
    // nonce derivation and the modular inversion. Building a generator table
    // is only worth it if the multiplication is where the time goes.
    let mut ecdh_pk = [0u8; 65];
    iron_crypto::ec::EcdhP256::public_key(&[0x5au8; 32], &mut ecdh_pk).unwrap();
    let mut shared_p = [0u8; 32];
    per_op("iron-crypto ecdh p-256 (one scalar mul)", 200, 3, || {
        iron_crypto::ec::EcdhP256::agree(&[0x5au8; 32], &ecdh_pk, &mut shared_p).unwrap();
    });

    let p_sk = [0x5au8; 32];
    let mut p_sig = [0u8; 64];
    let s1 = per_op("iron-crypto ecdsa p-256 sign", 200, 3, || {
        iron_crypto::ec::p256::EcdsaP256Sha256::sign(&p_sk, msg, &mut p_sig).unwrap();
    });
    let p_key = p256::ecdsa::SigningKey::from_bytes(&p_sk.into()).unwrap();
    let s2 = per_op("p256 crate ecdsa sign", 200, 3, || {
        use p256::ecdsa::signature::Signer;
        let _: p256::ecdsa::Signature = p_key.sign(msg);
    });
    verdict("ecdsa p-256 sign", s1, s2, false);

    let mut p_pk = [0u8; 65];
    iron_crypto::ec::p256::EcdsaP256Sha256::public_key(&p_sk, &mut p_pk).unwrap();
    iron_crypto::ec::p256::EcdsaP256Sha256::sign(&p_sk, msg, &mut p_sig).unwrap();
    let v1 = per_op("iron-crypto ecdsa p-256 verify", 200, 3, || {
        iron_crypto::ec::p256::EcdsaP256Sha256::verify(&p_pk, msg, &p_sig).unwrap();
    });
    let p_vk = p256::ecdsa::VerifyingKey::from(&p_key);
    let p_s: p256::ecdsa::Signature = {
        use p256::ecdsa::signature::Signer;
        p_key.sign(msg)
    };
    let v2 = per_op("p256 crate ecdsa verify", 200, 3, || {
        use p256::ecdsa::signature::Verifier;
        p_vk.verify(msg, &p_s).unwrap();
    });
    verdict("ecdsa p-256 verify", v1, v2, false);

    println!();
    if !soft {
        println!("Labelled as the hardware run. For software vs software:");
        println!("  RUSTFLAGS=\"--cfg aes_force_soft\" cargo run --release -- soft");
        println!();
    }
}
