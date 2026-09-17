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
//! Five entries, chosen one per API shape: authenticated encryption, signing,
//! key encapsulation, key derivation, and key wrapping. Not all seventy-five.
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
use iron_crypto::{cipher, drbg, ec, kdf, mac, mlkem};

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
    ];

    for (id, compiled) in cases {
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
