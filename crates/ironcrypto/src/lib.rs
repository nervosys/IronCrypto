//! # IronCrypto
//!
//! An agentic-first, FIPS-oriented cryptography library in pure Rust, with a
//! machine-readable ontology so that autonomous callers can choose correctly
//! instead of guessing.
//!
//! ## The short version
//!
//! ```
//! use ironcrypto::prelude::*;
//!
//! // 1. Ask what to use, rather than picking a name from memory.
//! let choice = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
//! assert_eq!(choice.primary.id, "aes-256-gcm");
//!
//! // 2. Use it. The sealer picks each nonce, so none is ever reused; the
//! //    receiver refuses replays. In real use the key comes from a key
//! //    exchange and a KDF, never a constant.
//! let key = [0x2a; 32];
//! let mut tx = Sealer::<Aes256Gcm>::new(&key, *b"c->s")?;
//! let mut rx = Opener::<Aes256Gcm>::new(&key, *b"c->s")?;
//! let mut buf = *b"the payload";
//! let mut tag = [0u8; 16];
//! let nonce = tx.seal(b"context", &mut buf, &mut tag)?;
//! rx.open(&nonce, b"context", &mut buf, &tag)?;
//! assert_eq!(&buf, b"the payload");
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! ## Why it is shaped this way
//!
//! Most cryptographic failures are not broken primitives. They are correct
//! primitives used wrongly: a reused nonce, an unauthenticated mode, a password
//! fed to a fast hash, a tag compared with `==`. A human learns those rules from
//! prose; an agent cannot. So the rules live in the
//! [`ic_ontology`] registry as data — with severities, consequences, and
//! parameter bounds — and the library refuses at runtime when it can.
//!
//! ## The four entry points
//!
//! | goal | entry point |
//! |---|---|
//! | pick an algorithm | [`recommend`], [`ic_ontology::Query`] |
//! | use an algorithm | the re-exports in [`prelude`] |
//! | enforce a policy | [`ic_fips::check`], [`ic_fips::guarded`] |
//! | inspect this build | [`ic_ontology::runtime`] |
//!
//! ## Rules that hold for every algorithm
//!
//! Whichever algorithm [`recommend`] picks, these hold. They are data in
//! [`ic_ontology::RULES`], with the reason for each; the MCP server sends them
//! to a client when it connects, and `ic rules` prints them.
//!
//! * **Never reuse a (key, nonce) pair.** Use [`ic_cipher::Sealer`], which
//!   chooses each nonce, and [`ic_cipher::Opener`], which refuses replays.
//! * **Never use an unauthenticated mode alone.** CBC and CTR need a MAC;
//!   prefer an AEAD.
//! * **Never compare tags or MACs with ==.** Use [`ic_core::ct::verify`].
//! * **Never hash a password with a plain hash.** Use `ic_kdf::pbkdf2` with at
//!   least 600 000 iterations and 16 bytes of fresh salt, or Argon2id.
//! * **Never use raw OS bytes as key material.** Use `ic_drbg::Rng::from_os()`.
//! * **Never use a raw X25519 or ECDH shared secret as a key.** Run it through
//!   HKDF with both public keys in `info`, or use `ic_hpke`.
//! * **Wrap secrets in Zeroizing.** Keys, derived keys, shared secrets.
//!
//! ## Honest limits
//!
//! * **Not CMVP validated.** The FIPS machinery is real; the certificate does
//!   not exist. See [`ic_fips::VALIDATION_STATEMENT`].
//! * **RSA key generation is variable time**, by design and like every other
//!   implementation: the prime search branches on candidate values. Generate
//!   keys somewhere an attacker is not measuring. Signing and decryption are
//!   constant time in the exponent.
//! * **An RSA private key is about five kilobytes**, because every integer
//!   inside is a fixed-capacity 4096-bit buffer. That is what keeps the crate
//!   allocation free; box it on a small stack.
//! * **Post-quantum means every parameter set of ML-KEM and ML-DSA.**
//!   ML-KEM-512, -768 and -1024 are each checked against NIST's ACVP vectors,
//!   50 cases apiece, and ML-DSA-44, -65 and -87 against 55 apiece. All are
//!   available in the approved mode; [`recommend`] offers the middle sets,
//!   ML-KEM-768 and ML-DSA-65, with a constraint to deploy them in a hybrid.
//!   SLH-DSA is not implemented; the ontology lists it as `planned` so that a
//!   request for it resolves to an absence rather than to nothing.
//! * **ARM gets hardware AES but not hardware GHASH.** x86-64 gets AES-NI and
//!   PCLMULQDQ, selected at run time. On AArch64 the ARMv8 AES instructions are
//!   used behind the `aarch64-crypto` feature, but there is no `PMULL` path, so
//!   AES-GCM there is limited by a portable GHASH and [`recommend`] prefers
//!   ChaCha20-Poly1305. Everywhere else runs the portable constant-time code.
//!
//! Each of those is queryable at runtime through
//! [`ic_ontology::runtime::capabilities`], so an agent can discover them
//! without reading this page.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub use ic_cipher as cipher;
pub use ic_core as core_types;
pub use ic_drbg as drbg;
pub use ic_ec as ec;
pub use ic_fips as fips;
pub use ic_hash as hash;
pub use ic_hpke as hpke;
pub use ic_kdf as kdf;
pub use ic_mac as mac;
pub use ic_mldsa as mldsa;
pub use ic_mlkem as mlkem;
pub use ic_ontology as ontology;
pub use ic_pkix as pkix;
pub use ic_rsa as rsa;

/// Everything needed for ordinary use, in one import.
pub mod prelude {
    pub use ic_core::traits::{
        Aead, Algorithm, BlockCipher, Digest, Drbg, Kdf, KeyAgreement, Mac, RandomSource, SelfTest,
        SignatureScheme, Xof,
    };
    pub use ic_core::{Error, ErrorKind, Result, Zeroize, Zeroizing};

    pub use ic_cipher::{Aes128, Aes192, Aes256};
    pub use ic_cipher::{Aes128Gcm, Aes192Gcm, Aes256Gcm, ChaCha20Poly1305};
    pub use ic_cipher::{Aes128GcmSiv, Aes256GcmSiv};
    pub use ic_cipher::{Aes128Kw, Aes192Kwp, Aes256Kw, Aes256Kwp};
    pub use ic_cipher::{Opener, Sealer};
    pub use ic_ec::p256::{EcdhP256, EcdsaP256Sha256};
    pub use ic_ec::p384::{EcdhP384, EcdsaP384Sha384};
    pub use ic_ec::p521::{EcdhP521, EcdsaP521Sha512};
    pub use ic_ec::{Ed25519, X25519};
    pub use ic_hash::Blake2b;
    pub use ic_hash::{CShake128, CShake256};
    pub use ic_hash::{ParallelHash128, ParallelHash256, TupleHash128, TupleHash256};
    pub use ic_hash::{Sha256, Sha384, Sha3_256, Sha3_512, Sha512, Shake128, Shake256};
    pub use ic_kdf::argon2::{argon2, Argon2Params, Variant};
    pub use ic_kdf::{pbkdf2, Hkdf};
    pub use ic_mac::{CmacAes256, HmacSha256, HmacSha384, HmacSha512};
    pub use ic_mac::{Kmac128, Kmac256};
    pub use ic_rsa::{Pkcs1Sha256, Pkcs1Sha384, Pkcs1Sha512, PssSha256, PssSha384, PssSha512};
    pub use ic_rsa::{RsaPrivateKey, RsaPublicKey};

    pub use ic_pkix::{pem, PrivateKeyInfo, PublicKeyInfo};

    #[cfg(feature = "std")]
    pub use ic_drbg::Rng;

    pub use ic_ontology::select::{recommend, Intent, NoRecommendation, Policy, Recommendation};
    pub use ic_ontology::{Class, FipsStatus, Purpose, Query};
}

pub use ic_ontology::select::{recommend, Intent, Policy};

/// The library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Bring the module up: run every known-answer test and report the result.
///
/// Calling this is optional for ordinary use and mandatory if you intend to
/// operate under a FIPS policy. It is idempotent.
pub fn initialize() -> ic_core::Result<ic_fips::SelfTestReport> {
    ic_fips::initialize()
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    /// An end-to-end pass through the layers an agent actually uses: ask the
    /// ontology what to do, then do it.
    #[test]
    fn recommended_algorithm_is_usable_as_described() {
        let choice = recommend(Intent::EncryptMessage, Policy::FIPS_APPROVED).unwrap();
        assert_eq!(choice.primary.id, "aes-256-gcm");
        assert_eq!(choice.primary.rust_path, "ic_cipher::Aes256Gcm");

        // The ontology's declared parameter bounds must match the real type.
        let key_param = choice
            .primary
            .params
            .iter()
            .find(|p| p.name == "key")
            .expect("an AEAD entry must document its key size");
        assert_eq!(key_param.recommended as usize, Aes256Gcm::KEY_LEN);

        let cipher = Aes256Gcm::new(&[0u8; 32]).unwrap();
        let mut buf = *b"payload";
        let mut tag = [0u8; 16];
        cipher
            .seal_detached(&[0u8; 12], b"aad", &mut buf, &mut tag)
            .unwrap();
        cipher
            .open_detached(&[0u8; 12], b"aad", &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf, b"payload");
    }

    /// Every available entry's declared parameter sizes must agree with the
    /// constants on the implementing type. A drift here would make the ontology
    /// actively misleading, which is worse than having no ontology.
    #[test]
    fn ontology_sizes_match_the_implementations() {
        let cases: &[(&str, usize, usize, usize)] = &[
            (
                "aes-128-gcm",
                Aes128Gcm::KEY_LEN,
                Aes128Gcm::NONCE_LEN,
                Aes128Gcm::TAG_LEN,
            ),
            (
                "aes-192-gcm",
                Aes192Gcm::KEY_LEN,
                Aes192Gcm::NONCE_LEN,
                Aes192Gcm::TAG_LEN,
            ),
            (
                "aes-256-gcm",
                Aes256Gcm::KEY_LEN,
                Aes256Gcm::NONCE_LEN,
                Aes256Gcm::TAG_LEN,
            ),
            (
                "chacha20-poly1305",
                ChaCha20Poly1305::KEY_LEN,
                ChaCha20Poly1305::NONCE_LEN,
                ChaCha20Poly1305::TAG_LEN,
            ),
        ];
        for (id, key_len, nonce_len, tag_len) in cases {
            let e = ic_ontology::get(id).unwrap();
            let p = |name: &str| {
                e.params
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| p.recommended as usize)
            };
            assert_eq!(p("key"), Some(*key_len), "{id} key");
            assert_eq!(p("nonce"), Some(*nonce_len), "{id} nonce");
            assert_eq!(p("tag"), Some(*tag_len), "{id} tag");
        }
    }

    #[test]
    fn digest_output_sizes_match_the_ontology() {
        let cases: &[(&str, usize, usize)] = &[
            ("sha2-256", Sha256::OUTPUT_LEN, Sha256::BLOCK_LEN),
            ("sha2-384", Sha384::OUTPUT_LEN, Sha384::BLOCK_LEN),
            ("sha2-512", Sha512::OUTPUT_LEN, Sha512::BLOCK_LEN),
            ("sha3-256", Sha3_256::OUTPUT_LEN, Sha3_256::BLOCK_LEN),
            ("sha3-512", Sha3_512::OUTPUT_LEN, Sha3_512::BLOCK_LEN),
        ];
        for (id, out, block) in cases {
            let e = ic_ontology::get(id).unwrap();
            let p = |name: &str| {
                e.params
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| p.recommended as usize)
            };
            assert_eq!(p("output"), Some(*out), "{id} output");
            assert_eq!(p("block"), Some(*block), "{id} block");
        }
    }

    #[test]
    fn curve_key_sizes_match_the_ontology() {
        let e = ic_ontology::get("x25519").unwrap();
        let p = |name: &str| {
            e.params
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.recommended as usize)
        };
        assert_eq!(p("private-key"), Some(X25519::PRIVATE_KEY_LEN));
        assert_eq!(p("public-key"), Some(X25519::PUBLIC_KEY_LEN));
        assert_eq!(p("shared-secret"), Some(X25519::SHARED_SECRET_LEN));

        let e = ic_ontology::get("ed25519").unwrap();
        let p = |name: &str| {
            e.params
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.recommended as usize)
        };
        assert_eq!(p("private-key"), Some(Ed25519::PRIVATE_KEY_LEN));
        assert_eq!(p("public-key"), Some(Ed25519::PUBLIC_KEY_LEN));
        assert_eq!(p("signature"), Some(Ed25519::SIGNATURE_LEN));
    }

    /// The `ID` constant each implementation carries must resolve in the
    /// ontology; that join is the whole point of `Algorithm::ID`.
    #[test]
    fn algorithm_ids_resolve_in_the_ontology() {
        let ids = [
            Sha256::ID,
            Sha512::ID,
            Sha3_256::ID,
            Aes256::ID,
            Aes256Gcm::ID,
            ChaCha20Poly1305::ID,
            HmacSha256::ID,
            CmacAes256::ID,
            X25519::ID,
            Ed25519::ID,
        ];
        for id in ids {
            assert!(
                ic_ontology::get(id).is_some(),
                "{id} is not in the ontology"
            );
        }
    }

    #[test]
    fn a_full_agent_workflow_runs_end_to_end() {
        // Agree a key, derive from it, encrypt with the result, and sign the
        // ciphertext — the shape of a real protocol.
        let alice_sk = [0x11u8; 32];
        let bob_sk = [0x22u8; 32];
        let (mut alice_pk, mut bob_pk) = ([0u8; 32], [0u8; 32]);
        X25519::public_key(&alice_sk, &mut alice_pk).unwrap();
        X25519::public_key(&bob_sk, &mut bob_pk).unwrap();

        let mut shared = Zeroizing::new([0u8; 32]);
        X25519::agree(&alice_sk, &bob_pk, shared.get_mut()).unwrap();

        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<HmacSha256>::derive(shared.get(), b"salt", b"agentic/v1", key.get_mut()).unwrap();

        let cipher = Aes256Gcm::new(key.get()).unwrap();
        let mut buf = b"protocol payload".to_vec();
        let mut tag = [0u8; 16];
        cipher
            .seal_detached(&[1u8; 12], b"", &mut buf, &mut tag)
            .unwrap();

        let mut sig = [0u8; 64];
        let mut signer_pk = [0u8; 32];
        Ed25519::public_key(&alice_sk, &mut signer_pk).unwrap();
        Ed25519::sign(&alice_sk, &buf, &mut sig).unwrap();
        Ed25519::verify(&signer_pk, &buf, &sig).unwrap();

        cipher
            .open_detached(&[1u8; 12], b"", &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf[..], b"protocol payload");
    }
}

// The README's Rust examples, compiled and run as doctests so they cannot
// drift from the API. Only under `cargo test`: a published package has no
// README at this path, and does not need one to build. The rustls example is
// marked `ignore` there, since this crate does not depend on rustls; the same
// code is a doctest in `ic-rustls`.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
struct ReadmeDoctests;
