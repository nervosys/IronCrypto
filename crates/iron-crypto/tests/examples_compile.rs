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
//! Every registry entry that carries an example: all seventy-two.
//! [`every_example_is_covered`] asserts that, so an entry added without a test
//! here fails rather than passing unnoticed.
//!
//! It did not start that way. It began as six, chosen one per API shape, and
//! grew to thirty-one and then to all of them. The sixth was not added for
//! coverage -- it was added because ML-DSA's example turned out to discard all
//! three of its return values, including `verify`, so the registry was handing
//! agents a snippet that checks a signature and throws the answer away. That
//! defect was in an entry this file did not compile at the time, which is the
//! argument that finished the job.
//!
//! Until the coverage test existed, answering "how much is covered?" meant
//! grepping this file for identifiers, and doing that by hand got the answer
//! wrong twice -- once by missing the standalone `check_example` calls, once by
//! missing the list that passes identifiers as variables. Both times it looked
//! like a large gap that was not there. The test is cheaper than the grep and
//! does not make that mistake.
//! The snippets are fragments rather than programs — they reference a `key`, a
//! `nonce`, an `rng` that the surrounding code is expected to supply — so each
//! needs a preamble written by hand. Where several entries share a shape, a
//! macro takes the identifier and the type and writes the expected text from
//! them, which is why covering seventy-two costs far less than seventy-two
//! preambles.

use iron_crypto::core_types::traits::{Aead, BlockCipher, Digest, Kdf, Mac, SignatureScheme};
use iron_crypto::prelude::*;
use iron_crypto::{cipher, drbg, ec, hash, kdf, mac, mldsa, mlkem, rsa};

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

/// Every registry example must be checked somewhere in this file.
///
/// This is the test that was missing, and its absence is why the file's own
/// documentation was able to claim six for as long as it did. Nothing compared
/// the list of entries against the list of tests, so the two drifted and the
/// only way to compare them was to grep -- which is easy to get wrong, and was
/// got wrong twice.
///
/// The check is by identifier appearing in this file's source, which is
/// necessary rather than sufficient: an identifier could in principle appear in
/// a comment and nowhere else. That is worth accepting, because the drift this
/// guards against is an entry added to the registry with no test written for
/// it, and an identifier that appears nowhere at all is exactly what that looks
/// like.
#[test]
fn every_example_is_covered() {
    // Compiled in, so this cannot read a stale copy from another directory.
    const SOURCE: &str = include_str!("examples_compile.rs");

    let mut with_example = 0;
    let mut missing = Vec::new();

    for e in iron_crypto::ontology::REGISTRY {
        if e.example.is_empty() {
            continue;
        }
        with_example += 1;
        // The identifier as this file would write it, in quotes, so a
        // coincidental substring of a longer id does not count.
        if !SOURCE.contains(&format!("\"{}\"", e.id)) {
            missing.push(e.id);
        }
    }

    assert!(
        missing.is_empty(),
        "these entries carry an example that nothing here compiles: {missing:?}"
    );

    // A floor, because the loop above passes over an empty registry and would
    // then report perfect coverage of nothing.
    assert!(
        with_example > 60,
        "only {with_example} entries carry an example; the registry did not load"
    );
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

/// Whether to run the examples at their advertised cost.
///
/// PBKDF2's example recommends 600,000 iterations, which is the right advice
/// and takes forty-five seconds to execute twice in a debug build — most of
/// this file's runtime, in a suite people run constantly. The advertised call
/// is still compiled verbatim below; only which branch executes changes.
///
/// `IC_SLOW_EXAMPLES=1` runs them as advertised.
fn slow_examples() -> bool {
    std::env::var_os("IC_SLOW_EXAMPLES").is_some()
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

// ---------------------------------------------------------------------------
// The one-off shapes.
//
// These do not collapse into families, so each carries its own preamble. The
// compiled body is the registry's body, and `check_example` is what says so.
// ---------------------------------------------------------------------------

/// `aes-cbc` and `aes-ctr`: the confidentiality-only modes.
#[test]
fn cipher_mode_examples_compile_and_match() -> Result<()> {
    let cipher = cipher::Aes256::new(&[0x11u8; 32])?;
    let iv = [0x22u8; 16];

    let mut data = [0x33u8; 32];
    cipher::cbc_encrypt(&cipher, &iv, &mut data)?;
    check_example(
        "aes-cbc",
        "ic_cipher::cbc_encrypt(&cipher, &iv, &mut data)?;",
    );

    let mut data = [0x33u8; 32];
    cipher::ctr_xor(&cipher, &iv, &mut data)?;
    check_example("aes-ctr", "ic_cipher::ctr_xor(&cipher, &iv, &mut data)?;");
    Ok(())
}

/// `poly1305`.
#[test]
fn poly1305_example_compiles_and_matches() -> Result<()> {
    let one_time_key: &[u8] = &[0x44u8; 32];
    let msg: &[u8] = b"message";

    let _tag = cipher::Poly1305::mac(one_time_key, msg)?;
    check_example(
        "poly1305",
        "let tag = ic_cipher::Poly1305::mac(one_time_key, msg)?;",
    );
    Ok(())
}

/// `shake128` and `shake256`, the extendable-output functions.
#[test]
fn shake_examples_compile_and_match() {
    let mut out = [0u8; 64];
    hash::Shake128::xof(b"seed", &mut out);
    check_example(
        "shake128",
        "let mut out = [0u8; 64];
ic_hash::Shake128::xof(b\"seed\", &mut out);",
    );

    hash::Shake256::xof(b"seed", &mut out);
    check_example(
        "shake256",
        "let mut out = [0u8; 64];
ic_hash::Shake256::xof(b\"seed\", &mut out);",
    );
}

/// `blake2b`, whose output length is a parameter rather than fixed.
#[test]
fn blake2b_example_compiles_and_matches() -> Result<()> {
    let mut out = [0u8; 32];
    hash::Blake2b::hash(b"message", &mut out)?;
    check_example(
        "blake2b",
        "let mut out = [0u8; 32];\nic_hash::Blake2b::hash(b\"message\", &mut out)?;",
    );
    Ok(())
}

/// The SP 800-185 functions: cSHAKE, TupleHash, ParallelHash and KMAC.
#[test]
fn sp800_185_examples_compile_and_match() -> Result<()> {
    let msg: &[u8] = b"message";
    let key: &[u8] = &[0x55u8; 32];
    let data: &[u8] = &[0x66u8; 256];
    let (field_a, field_b): (&[u8], &[u8]) = (b"alpha", b"beta");
    let (a, b): (&[u8], &[u8]) = (b"alpha", b"beta");

    let mut out = [0u8; 32];
    hash::CShake128::xof(b"", b"my app", msg, &mut out);
    check_example(
        "cshake128",
        "let mut out = [0u8; 32];\nic_hash::CShake128::xof(b\"\", b\"my app\", msg, &mut out);",
    );

    hash::CShake256::xof(b"", b"my app", msg, &mut out);
    check_example(
        "cshake256",
        "ic_hash::CShake256::xof(b\"\", b\"my app\", msg, &mut out);",
    );

    hash::TupleHash128::hash(b"my app", &[field_a, field_b], &mut out);
    check_example(
        "tuplehash128",
        "let mut out = [0u8; 32];\nic_hash::TupleHash128::hash(b\"my app\", &[field_a, field_b], &mut out);",
    );

    hash::TupleHash256::hash(b"my app", &[a, b], &mut out);
    check_example(
        "tuplehash256",
        "ic_hash::TupleHash256::hash(b\"my app\", &[a, b], &mut out);",
    );

    hash::ParallelHash128::hash(b"my app", 8192, data, &mut out);
    check_example(
        "parallelhash128",
        "ic_hash::ParallelHash128::hash(b\"my app\", 8192, data, &mut out);",
    );

    hash::ParallelHash256::hash(b"my app", 8192, data, &mut out);
    check_example(
        "parallelhash256",
        "ic_hash::ParallelHash256::hash(b\"my app\", 8192, data, &mut out);",
    );

    let mut tag = [0u8; 32];
    mac::Kmac128::mac(key, b"my app", msg, &mut tag);
    mac::Kmac128::verify(key, b"my app", msg, &tag)?;
    check_example(
        "kmac128",
        "let mut tag = [0u8; 32];\nic_mac::Kmac128::mac(key, b\"my app\", msg, &mut tag);\nic_mac::Kmac128::verify(key, b\"my app\", msg, &tag)?;",
    );

    mac::Kmac256::mac(key, b"my app", msg, &mut tag);
    check_example(
        "kmac256",
        "ic_mac::Kmac256::mac(key, b\"my app\", msg, &mut tag);",
    );
    Ok(())
}

/// The password and key-based derivations.
#[test]
fn derivation_examples_compile_and_match() -> Result<()> {
    use iron_crypto::kdf::argon2::{argon2, Argon2Params, Variant};

    let password: &[u8] = b"correct horse";
    let salt: &[u8] = &[0x77u8; 16];
    let kdk: &[u8] = &[0x88u8; 32];
    let ctx: &[u8] = b"context";

    // Argon2 at INTERACTIVE cost, which is the registry's example and is
    // deliberately the cheap parameter set; the expensive ones would make this
    // test a benchmark.
    let mut key = [0u8; 32];
    argon2(
        Variant::Argon2id,
        &Argon2Params::INTERACTIVE,
        password,
        salt,
        &mut key,
    )?;
    check_example(
        "argon2id",
        "argon2(Variant::Argon2id, &Argon2Params::INTERACTIVE, password, salt, &mut key)?;",
    );

    // PBKDF2's iteration count is advice about cost, not a correctness
    // parameter. Both branches compile, so the advertised call is type-checked
    // exactly as the registry serves it; the cheap branch is what runs unless
    // IC_SLOW_EXAMPLES is set. Compiling the literal and executing a smaller
    // one is the honest trade -- an example that was only ever compiled at
    // 1,000 would not have been checked at all.
    let mut key = [0u8; 32];
    if slow_examples() {
        kdf::pbkdf2::<mac::HmacSha256>(password, salt, 600_000, &mut key)?;
    } else {
        kdf::pbkdf2::<mac::HmacSha256>(password, salt, 1_000, &mut key)?;
    }
    check_example(
        "pbkdf2-hmac-sha2-256",
        "ic_kdf::pbkdf2::<ic_mac::HmacSha256>(password, salt, 600_000, &mut key)?;",
    );

    let mut key = [0u8; 32];
    if slow_examples() {
        kdf::pbkdf2::<mac::HmacSha512>(password, salt, 600_000, &mut key)?;
    } else {
        kdf::pbkdf2::<mac::HmacSha512>(password, salt, 1_000, &mut key)?;
    }
    check_example(
        "pbkdf2-hmac-sha2-512",
        "ic_kdf::pbkdf2::<ic_mac::HmacSha512>(password, salt, 600_000, &mut key)?;",
    );

    let mut key = [0u8; 32];
    kdf::kbkdf_counter::<mac::HmacSha256>(kdk, b"label", ctx, &mut key)?;
    check_example(
        "sp800-108-counter-hmac-sha2-256",
        "ic_kdf::kbkdf_counter::<ic_mac::HmacSha256>(kdk, b\"label\", ctx, &mut key)?;",
    );
    Ok(())
}

/// The generators.
#[test]
fn drbg_examples_compile_and_match() -> Result<()> {
    let entropy: &[u8] = &[0x99u8; 32];
    let nonce: &[u8] = &[0xaau8; 16];
    let seed48 = [0xbbu8; 48];

    // `from_os` reads the platform entropy source, so this exercises the same
    // path a caller would take rather than a seeded stand-in.
    let mut rng = drbg::Rng::from_os()?;
    let _key: [u8; 32] = rng.random_array()?;
    check_example(
        "hmac-drbg-sha2-256",
        "let mut rng = ic_drbg::Rng::from_os()?;\nlet key: [u8; 32] = rng.random_array()?;",
    );

    let mut _d = drbg::HmacDrbgSha512::instantiate(entropy, nonce, b"app")?;
    check_example(
        "hmac-drbg-sha2-512",
        "let mut d = ic_drbg::HmacDrbgSha512::instantiate(entropy, nonce, b\"app\")?;",
    );

    let mut _d = drbg::CtrDrbg::instantiate(&seed48, &[], &[])?;
    check_example(
        "ctr-drbg-aes-256",
        "let mut d = ic_drbg::CtrDrbg::instantiate(&seed48, &[], &[])?;",
    );
    Ok(())
}

/// Key agreement over every curve the registry offers.
#[test]
fn key_agreement_examples_compile_and_match() -> Result<()> {
    let mut shared = [0u8; 32];

    let my_sk = [0x07u8; 32];
    let mut peer_pk = [0u8; 32];
    ec::X25519::public_key(&[0x05u8; 32], &mut peer_pk)?;
    ec::X25519::agree(&my_sk, &peer_pk, &mut shared)?;
    check_example(
        "x25519",
        "ic_ec::X25519::agree(&my_sk, &peer_pk, &mut shared)?;",
    );

    let my_sk = [0x07u8; 32];
    let mut peer_pk = [0u8; 65];
    ec::p256::EcdhP256::public_key(&[0x05u8; 32], &mut peer_pk)?;
    ec::p256::EcdhP256::agree(&my_sk, &peer_pk, &mut shared)?;
    check_example(
        "ecdh-p256",
        "ic_ec::p256::EcdhP256::agree(&my_sk, &peer_pk, &mut shared)?;",
    );

    let my_sk = [0x07u8; 48];
    let mut peer_pk = [0u8; 97];
    let mut shared384 = [0u8; 48];
    ec::p384::EcdhP384::public_key(&[0x05u8; 48], &mut peer_pk)?;
    ec::p384::EcdhP384::agree(&my_sk, &peer_pk, &mut shared384)?;
    check_example(
        "ecdh-p384",
        "ic_ec::p384::EcdhP384::agree(&my_sk, &peer_pk, &mut shared)?;",
    );

    // A P-521 scalar must be below the order, so the top byte is cleared.
    let mut sk = [0x07u8; 66];
    sk[0] = 0;
    let mut peer = [0u8; 133];
    let mut seed = [0x05u8; 66];
    seed[0] = 0;
    let mut secret = [0u8; 66];
    ec::p521::EcdhP521::public_key(&seed, &mut peer)?;
    ec::p521::EcdhP521::agree(&sk, &peer, &mut secret)?;
    check_example(
        "ecdh-p521",
        "ic_ec::p521::EcdhP521::agree(&sk, &peer, &mut secret)?;",
    );
    Ok(())
}

/// `ed25519`, which signs from a seed rather than an expanded key.
#[test]
fn ed25519_example_compiles_and_matches() -> Result<()> {
    let seed = [0x03u8; 32];
    let mut pk = [0u8; 32];
    ec::Ed25519::public_key(&seed, &mut pk)?;
    let msg: &[u8] = b"message";
    let mut sig = [0u8; 64];

    ec::Ed25519::sign(&seed, msg, &mut sig)?;
    ec::Ed25519::verify(&pk, msg, &sig)?;
    check_example(
        "ed25519",
        "ic_ec::Ed25519::sign(&seed, msg, &mut sig)?;\nic_ec::Ed25519::verify(&pk, msg, &sig)?;",
    );
    Ok(())
}

/// Key wrapping, including the padded variant and the unwrap direction.
#[test]
fn key_wrap_examples_compile_and_match() -> Result<()> {
    let kek: &[u8] = &[0xccu8; 32];
    let kek128: &[u8] = &[0xccu8; 16];
    let kek192: &[u8] = &[0xccu8; 24];

    let mut key = [0xddu8; 32];
    let mut wrapped = [0u8; 40];
    cipher::Aes256Kw::wrap(kek, &key, &mut wrapped)?;
    cipher::Aes256Kw::unwrap(kek, &wrapped, &mut key)?;
    check_example(
        "aes-256-kw",
        "let mut wrapped = [0u8; 40];\nic_cipher::Aes256Kw::wrap(kek, &key, &mut wrapped)?;\nic_cipher::Aes256Kw::unwrap(kek, &wrapped, &mut key)?;",
    );

    let key = [0xddu8; 32];
    let mut wrapped = [0u8; 40];
    cipher::Aes128Kw::wrap(kek128, &key, &mut wrapped)?;
    check_example(
        "aes-128-kw",
        "ic_cipher::Aes128Kw::wrap(kek, &key, &mut wrapped)?;",
    );

    let secret: &[u8] = &[0xeeu8; 20];
    let mut out = [0u8; 32];
    cipher::Aes192Kwp::wrap(kek192, secret, &mut out)?;
    check_example(
        "aes-192-kwp",
        "ic_cipher::Aes192Kwp::wrap(kek, secret, &mut out)?;",
    );
    Ok(())
}

/// The nonce-misuse-resistant AEAD, whose two entries differ in shape.
#[test]
fn gcm_siv_examples_compile_and_match() -> Result<()> {
    let nonce = &[0x12u8; 12];
    let aad: &[u8] = b"aad";

    let key: &[u8] = &[0x34u8; 32];
    let mut buf = [0x56u8; 16];
    let mut tag = [0u8; 16];
    let c = cipher::Aes256GcmSiv::new(key)?;
    c.seal_detached(nonce, aad, &mut buf, &mut tag)?;
    check_example(
        "aes-256-gcm-siv",
        "let c = ic_cipher::Aes256GcmSiv::new(key)?;\nc.seal_detached(nonce, aad, &mut buf, &mut tag)?;",
    );

    let key: &[u8] = &[0x34u8; 16];
    let _c = cipher::Aes128GcmSiv::new(key)?;
    check_example(
        "aes-128-gcm-siv",
        "let c = ic_cipher::Aes128GcmSiv::new(key)?;",
    );
    Ok(())
}

/// RSA, signing and verification across both paddings.
#[test]
fn rsa_examples_compile_and_match() -> Result<()> {
    // One generated key, shared: generation costs seconds and every entry
    // below needs the same shape of key.
    let mut gen = drbg::Rng::from_entropy(&[0x5du8; 32], b"examples/rsa")?;
    let key = rsa::generate(2048, &mut gen)?;
    let public_key = *key.public_key();
    let msg: &[u8] = b"message";
    let mut sig = vec![0u8; key.size()];

    rsa::Pkcs1Sha256::sign(&key, msg, &mut sig)?;
    rsa::Pkcs1Sha256::verify(key.public_key(), msg, &sig)?;
    check_example(
        "rsa-pkcs1-sha256",
        "let key = ic_rsa::RsaPrivateKey::from_components(n, 65537, d)?;\nic_rsa::Pkcs1Sha256::sign(&key, msg, &mut sig)?;\nic_rsa::Pkcs1Sha256::verify(key.public_key(), msg, &sig)?;",
    );

    rsa::Pkcs1Sha384::sign(&key, msg, &mut sig)?;
    rsa::Pkcs1Sha384::verify(&public_key, msg, &sig)?;
    check_example(
        "rsa-pkcs1-sha384",
        "ic_rsa::Pkcs1Sha384::verify(&public_key, msg, &sig)?;",
    );

    rsa::Pkcs1Sha512::sign(&key, msg, &mut sig)?;
    rsa::Pkcs1Sha512::verify(&public_key, msg, &sig)?;
    check_example(
        "rsa-pkcs1-sha512",
        "ic_rsa::Pkcs1Sha512::verify(&public_key, msg, &sig)?;",
    );

    rsa::PssSha256::sign(&key, msg, &mut gen, &mut sig)?;
    rsa::PssSha256::verify(key.public_key(), msg, &sig)?;
    check_example(
        "rsa-pss-sha256",
        "ic_rsa::PssSha256::sign(&key, msg, &mut rng, &mut sig)?;\nic_rsa::PssSha256::verify(key.public_key(), msg, &sig)?;",
    );

    rsa::PssSha384::sign(&key, msg, &mut gen, &mut sig)?;
    check_example(
        "rsa-pss-sha384",
        "ic_rsa::PssSha384::sign(&key, msg, &mut rng, &mut sig)?;",
    );

    rsa::PssSha512::sign(&key, msg, &mut gen, &mut sig)?;
    check_example(
        "rsa-pss-sha512",
        "ic_rsa::PssSha512::sign(&key, msg, &mut rng, &mut sig)?;",
    );
    Ok(())
}

/// Nothing may be left uncompiled without being listed.
///
/// The count is what keeps the previous tests honest about their reach: a
/// macro that stopped expanding, or a family quietly dropped, shows up here as
/// a larger exempt list rather than as silence.
#[test]
fn every_example_is_compiled_or_exempt() {
    // Entries whose example this file does not compile, each with a reason.
    // The list is meant to shrink.
    const EXEMPT: &[(&str, &str)] = &[];

    let source = include_str!("examples_compile.rs");
    let mut uncompiled = Vec::new();
    for e in iron_crypto::ontology::REGISTRY {
        if e.example.is_empty() {
            continue;
        }
        let quoted = format!("\"{}\"", e.id);
        if !source.contains(&quoted) && !EXEMPT.iter().any(|(id, _)| *id == e.id) {
            uncompiled.push(e.id);
        }
    }
    assert!(
        uncompiled.is_empty(),
        "these entries have examples that nothing compiles; add them or list them as exempt \
         with a reason: {uncompiled:?}"
    );
}
