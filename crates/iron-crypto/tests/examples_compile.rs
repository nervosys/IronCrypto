//! The registry's `example` snippets, compiled and run.
//!
//! Every entry carries an `example`, and it is the first thing an agent copies
//! when it decides which algorithm to use. Nothing compiled them. They are
//! stored as strings, so a renamed type, a changed signature or a stale module
//! path leaves them looking authoritative and being wrong — and the reader most
//! likely to be misled is the one least able to notice, since an agent has no
//! way to tell a plausible snippet from a correct one.
//!
//! # How this avoids testing a copy of itself
//!
//! Each function below contains an example verbatim, and a test asserts the
//! text it contains is byte-identical to the registry's. Compiling a
//! paraphrase would prove nothing about what the registry actually serves, so
//! the equality check is what makes the compilation meaningful. Change either
//! side and this fails.
//!
//! # Scope
//!
//! Six entries, chosen one per API shape: authenticated encryption, signing,
//! key encapsulation, key derivation, key wrapping, and post-quantum signing.
//! Not all seventy-five.
//!
//! The sixth was not chosen for coverage. It was added because ML-DSA's example
//! turned out to discard all three of its return values, including `verify`, so
//! the registry was handing agents a snippet that checks a signature and throws
//! the answer away. The defect was in an entry this file did not compile, which
//! is the argument for the list being longer than it is.
//! The snippets are fragments rather than programs — they reference a `key`, a
//! `nonce`, an `rng` that the surrounding code is expected to supply — so each
//! one needs a preamble written by hand, and doing that for every entry would
//! be a large amount of work to re-confirm a property that holds structurally:
//! they all name types from the same few crates in the same few shapes.
//!
//! What these five do establish is that the shapes are right and that the
//! rename to `ic_*` reached the example strings, which is the drift most likely
//! to have happened recently.

use iron_crypto::core_types::traits::{Aead, Kdf, SignatureScheme};
use iron_crypto::prelude::*;
use iron_crypto::{cipher, drbg, ec, kdf, mac, mldsa, mlkem};

/// `aes-256-gcm`.
const AES_256_GCM: &str =
    "let c = ic_cipher::Aes256Gcm::new(key)?;\nc.seal_detached(&nonce, aad, &mut buf, &mut tag)?;";

fn run_aes_256_gcm() -> Result<()> {
    let key: &[u8] = &[0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad: &[u8] = b"aad";
    let mut buf = [0x33u8; 16];
    let mut tag = [0u8; 16];

    let c = cipher::Aes256Gcm::new(key)?;
    c.seal_detached(&nonce, aad, &mut buf, &mut tag)?;
    Ok(())
}

/// `ecdsa-p256-sha256`.
const ECDSA_P256: &str = "ic_ec::p256::EcdsaP256Sha256::sign(&sk, msg, &mut sig)?;\nic_ec::p256::EcdsaP256Sha256::verify(&pk, msg, &sig)?;";

fn run_ecdsa_p256() -> Result<()> {
    let sk = [7u8; 32];
    let mut pk = [0u8; 65];
    ec::p256::EcdsaP256Sha256::public_key(&sk, &mut pk)?;
    let msg: &[u8] = b"message";
    let mut sig = [0u8; 64];

    ec::p256::EcdsaP256Sha256::sign(&sk, msg, &mut sig)?;
    ec::p256::EcdsaP256Sha256::verify(&pk, msg, &sig)?;
    Ok(())
}

/// `ml-kem-768`.
const ML_KEM_768: &str = "let mut ek = [0u8; 1184];\nlet mut dk = [0u8; 2400];\nic_mlkem::MlKem768::keygen(&mut rng, &mut ek, &mut dk)?;\nic_mlkem::MlKem768::encapsulate(&mut rng, &ek, &mut ct, &mut secret)?;";

fn run_ml_kem_768() -> Result<()> {
    let mut rng = drbg::Rng::from_entropy(&[0x9au8; 32], b"examples")?;
    let mut ct = [0u8; 1088];
    let mut secret = [0u8; 32];

    let mut ek = [0u8; 1184];
    let mut dk = [0u8; 2400];
    mlkem::MlKem768::keygen(&mut rng, &mut ek, &mut dk)?;
    mlkem::MlKem768::encapsulate(&mut rng, &ek, &mut ct, &mut secret)?;
    Ok(())
}

/// `hkdf-sha2-256`.
const HKDF_SHA256: &str = "ic_kdf::Hkdf::<ic_mac::HmacSha256>::derive(ikm, salt, info, &mut key)?;";

fn run_hkdf_sha256() -> Result<()> {
    let ikm: &[u8] = b"input keying material";
    let salt: &[u8] = b"salt";
    let info: &[u8] = b"info";
    let mut key = [0u8; 32];

    kdf::Hkdf::<mac::HmacSha256>::derive(ikm, salt, info, &mut key)?;
    Ok(())
}

/// `aes-256-kwp`.
const AES_256_KWP: &str = "let n = ic_cipher::Aes256Kwp::wrapped_len(secret.len());\nic_cipher::Aes256Kwp::wrap(kek, secret, &mut out[..n])?;";

fn run_aes_256_kwp() -> Result<()> {
    let kek: &[u8] = &[0x44u8; 32];
    let secret: &[u8] = &[0x55u8; 20];
    let mut out = [0u8; 64];

    let n = cipher::Aes256Kwp::wrapped_len(secret.len());
    cipher::Aes256Kwp::wrap(kek, secret, &mut out[..n])?;
    Ok(())
}

/// `ml-dsa-65`.
///
/// Added after this entry's example was found discarding all three of its
/// return values, including `verify` -- the registry was teaching an agent to
/// check a signature and ignore the answer. Compiling it is what stops that
/// coming back: every one of these returns `#[must_use]`, so discarding one is
/// a warning, and the workspace builds with warnings denied.
const ML_DSA_65: &str = "let mut pk = [0u8; ic_mldsa::sign::PUBLIC_KEY_LEN];
let mut sk = [0u8; ic_mldsa::sign::SECRET_KEY_LEN];
// every call below returns a value you must check
assert!(ic_mldsa::sign::keygen(&seed, &mut pk, &mut sk));
let mut sig = [0u8; ic_mldsa::sign::SIGNATURE_LEN];
assert!(ic_mldsa::sign::sign(&sk, msg, ctx, &rnd, &mut sig));
assert!(ic_mldsa::sign::verify(&pk, msg, ctx, &sig));";

fn run_ml_dsa_65() -> Result<()> {
    let seed = [0x61u8; 32];
    let msg: &[u8] = b"message";
    let ctx: &[u8] = b"";
    let rnd = [0u8; 32];

    let mut pk = [0u8; mldsa::sign::PUBLIC_KEY_LEN];
    let mut sk = [0u8; mldsa::sign::SECRET_KEY_LEN];
    // every call below returns a value you must check
    assert!(mldsa::sign::keygen(&seed, &mut pk, &mut sk));
    let mut sig = [0u8; mldsa::sign::SIGNATURE_LEN];
    assert!(mldsa::sign::sign(&sk, msg, ctx, &rnd, &mut sig));
    assert!(mldsa::sign::verify(&pk, msg, ctx, &sig));
    Ok(())
}

/// The compiled code above must be what the registry actually serves.
///
/// Without this the file would prove only that *something* compiles. The
/// registry's snippet may carry a leading `use` line, which is hoisted to the
/// top of this file rather than repeated in each function, so the comparison is
/// against the example with any `use` lines removed.
#[test]
fn the_compiled_examples_match_the_registry() {
    let cases = [
        ("aes-256-gcm", AES_256_GCM),
        ("ecdsa-p256-sha256", ECDSA_P256),
        ("ml-kem-768", ML_KEM_768),
        ("hkdf-sha2-256", HKDF_SHA256),
        ("aes-256-kwp", AES_256_KWP),
        ("ml-dsa-65", ML_DSA_65),
    ];

    for (id, compiled) in cases {
        check_example(id, compiled);
    }
}

/// And the code runs, not merely type-checks.
///
/// A snippet can compile and still be wrong — a buffer sized from the wrong
/// constant type-checks and then fails at run time, which is exactly the
/// mistake someone copying it would make.
#[test]
fn the_examples_run() {
    run_aes_256_gcm().expect("aes-256-gcm");
    run_ecdsa_p256().expect("ecdsa-p256-sha256");
    run_ml_kem_768().expect("ml-kem-768");
    run_hkdf_sha256().expect("hkdf-sha2-256");
    run_aes_256_kwp().expect("aes-256-kwp");
    run_ml_dsa_65().expect("ml-dsa-65");
}

/// No example may still name the pre-rename crates.
///
/// Cheap, covers all seventy-five rather than the five above, and catches the
/// drift most likely to have happened recently. The rename was mechanical and
/// verified at the time; this is what keeps it verified.
#[test]
fn no_example_names_a_crate_that_no_longer_exists() {
    let mut checked = 0;
    for e in iron_crypto::ontology::REGISTRY {
        if e.example.is_empty() {
            continue;
        }
        checked += 1;
        for stale in ["ac_", "agentic_crypto", "acrypto"] {
            assert!(
                !e.example.contains(stale),
                "{}'s example still names {stale:?}: {}",
                e.id,
                e.example
            );
        }
        // And every crate it does name must be a real one.
        for part in e.example.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if let Some(rest) = part.strip_prefix("ic_") {
                let crate_dir = format!("crates/ic-{}", rest.replace('_', "-"));
                assert!(
                    std::path::Path::new(&crate_dir).exists()
                        || std::path::Path::new("../..").join(&crate_dir).exists(),
                    "{}'s example names {part}, and {crate_dir} does not exist",
                    e.id
                );
            }
        }
    }
    assert!(
        checked > 50,
        "only {checked} examples checked, which suggests they have gone missing rather than \
         that the registry shrank"
    );
}

/// Compare a compiled snippet against what the registry serves for `id`.
///
/// `use` lines are hoisted to the top of this file rather than repeated in
/// every function, so they are filtered out of the comparison.
fn check_example(id: &str, compiled: &str) {
    let entry = iron_crypto::ontology::get(id).unwrap_or_else(|| panic!("no entry {id}"));
    let body: String = entry
        .example
        .lines()
        .filter(|l| !l.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        body, compiled,
        "the registry's example for {id} is not the code compiled in this file"
    );
}

// ---------------------------------------------------------------------------
// The parametric families.
//
// Ten hash entries differ only by type, nine HMAC entries likewise, and so on
// through the block ciphers, AEADs, key derivation, key agreement and ECDSA.
// Writing each out would be several hundred lines of near-duplicate, and the
// duplication would be the kind that rots: change a signature and most copies
// get updated.
//
// Each macro below emits the compiled call *and* the expected registry string,
// both built from the same type name. That is what keeps the comparison
// honest — a paraphrase is not expressible, because there is only one source
// for the text.
// ---------------------------------------------------------------------------

/// Entries whose example is `let d = ic_hash::T::digest(b"message");`.
macro_rules! digest_family {
    ($($id:literal => $ty:ident),* $(,)?) => {
        #[test]
        fn digest_examples_compile_and_match() {
            $({
                let _d = iron_crypto::hash::$ty::digest(b"message");
                let expected = concat!(
                    "let d = ic_hash::", stringify!($ty), "::digest(b\"message\");"
                );
                check_example($id, expected);
            })*
        }
    };
}

digest_family! {
    "sha2-224" => Sha224,
    "sha2-256" => Sha256,
    "sha2-384" => Sha384,
    "sha2-512" => Sha512,
    "sha2-512-224" => Sha512_224,
    "sha2-512-256" => Sha512_256,
    "sha3-224" => Sha3_224,
    "sha3-256" => Sha3_256,
    "sha3-384" => Sha3_384,
    "sha3-512" => Sha3_512,
}

/// Entries whose example is `let tag = ic_mac::T::mac(key, msg)?;`.
macro_rules! mac_family {
    ($($id:literal => $ty:ident, $keylen:literal),* $(,)?) => {
        #[test]
        fn mac_examples_compile_and_match() -> Result<()> {
            let msg: &[u8] = b"message";
            $({
                // CMAC takes the key length of its cipher; HMAC takes any.
                let key: &[u8] = &[0x11u8; $keylen];
                let _tag = iron_crypto::mac::$ty::mac(key, msg)?;
                let expected = concat!(
                    "let tag = ic_mac::", stringify!($ty), "::mac(key, msg)?;"
                );
                check_example($id, expected);
            })*
            Ok(())
        }
    };
}

mac_family! {
    "hmac-sha2-256" => HmacSha256, 32,
    "hmac-sha2-384" => HmacSha384, 32,
    "hmac-sha2-512" => HmacSha512, 32,
    "hmac-sha2-512-256" => HmacSha512_256, 32,
    "hmac-sha3-256" => HmacSha3_256, 32,
    "hmac-sha3-512" => HmacSha3_512, 32,
    "cmac-aes-128" => CmacAes128, 16,
    "cmac-aes-192" => CmacAes192, 24,
    "cmac-aes-256" => CmacAes256, 32,

}

/// Entries whose example is `let c = ic_cipher::T::new(key)?;`.
macro_rules! block_cipher_family {
    ($($id:literal => $ty:ident, $len:literal),* $(,)?) => {
        #[test]
        fn block_cipher_examples_compile_and_match() -> Result<()> {
            $({
                let key: &[u8] = &[0x22u8; $len];
                let _c = iron_crypto::cipher::$ty::new(key)?;
                let expected = concat!(
                    "let c = ic_cipher::", stringify!($ty), "::new(key)?;"
                );
                check_example($id, expected);
            })*
            Ok(())
        }
    };
}

block_cipher_family! {
    "aes-128" => Aes128, 16,
    "aes-192" => Aes192, 24,
    "aes-256" => Aes256, 32,
}

/// Entries whose example seals with a detached tag.
macro_rules! aead_family {
    ($($id:literal => $ty:ident, $len:literal),* $(,)?) => {
        #[test]
        fn aead_examples_compile_and_match() -> Result<()> {
            let nonce = [0x33u8; 12];
            let aad: &[u8] = b"aad";
            $({
                let key: &[u8] = &[0x44u8; $len];
                let mut buf = [0x55u8; 16];
                let mut tag = [0u8; 16];
                let c = iron_crypto::cipher::$ty::new(key)?;
                c.seal_detached(&nonce, aad, &mut buf, &mut tag)?;
                let expected = concat!(
                    "let c = ic_cipher::", stringify!($ty), "::new(key)?;\n",
                    "c.seal_detached(&nonce, aad, &mut buf, &mut tag)?;"
                );
                check_example($id, expected);
            })*
            Ok(())
        }
    };
}

aead_family! {
    "aes-128-gcm" => Aes128Gcm, 16,
    "aes-192-gcm" => Aes192Gcm, 24,
    "aes-256-gcm" => Aes256Gcm, 32,
    "chacha20-poly1305" => ChaCha20Poly1305, 32,
}

/// HKDF entries, which name their MAC as a type parameter.
macro_rules! hkdf_family {
    ($($id:literal => $mac:ident),* $(,)?) => {
        #[test]
        fn hkdf_examples_compile_and_match() -> Result<()> {
            let ikm: &[u8] = b"input keying material";
            let salt: &[u8] = b"salt";
            let info: &[u8] = b"info";
            $({
                let mut key = [0u8; 32];
                iron_crypto::kdf::Hkdf::<iron_crypto::mac::$mac>::derive(
                    ikm, salt, info, &mut key,
                )?;
                let expected = concat!(
                    "ic_kdf::Hkdf::<ic_mac::", stringify!($mac), ">::derive(ikm, salt, info, &mut key)?;"
                );
                check_example($id, expected);
            })*
            Ok(())
        }
    };
}

hkdf_family! {
    "hkdf-sha2-256" => HmacSha256,
    "hkdf-sha2-384" => HmacSha384,
    "hkdf-sha2-512" => HmacSha512,
}

/// ECDSA signing entries.
macro_rules! ecdsa_family {
    ($($id:literal => $module:ident, $ty:ident, $sklen:literal, $siglen:literal),* $(,)?) => {
        #[test]
        fn ecdsa_examples_compile_and_match() -> Result<()> {
            let msg: &[u8] = b"message";
            $({
                // A P-521 scalar is 66 bytes and must be below the order,
                // so the top byte is cleared. A constant fill produces a value
                // larger than n, which the signer rightly refuses.
                let mut sk = [0x07u8; $sklen];
                sk[0] = 0;
                let mut sig = [0u8; $siglen];
                iron_crypto::ec::$module::$ty::sign(&sk, msg, &mut sig)?;
                let expected = concat!(
                    "ic_ec::", stringify!($module), "::", stringify!($ty),
                    "::sign(&sk, msg, &mut sig)?;"
                );
                check_example($id, expected);
            })*
            Ok(())
        }
    };
}

ecdsa_family! {
    "ecdsa-p384-sha384" => p384, EcdsaP384Sha384, 48, 96,
    "ecdsa-p521-sha512" => p521, EcdsaP521Sha512, 66, 132,
}
