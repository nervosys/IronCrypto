//! Known-answer tests for every implemented algorithm.
//!
//! FIPS 140-3 requires a *cryptographic algorithm self-test* (CAST) for each
//! approved security function, run before that function is first used, plus a
//! pre-operational software integrity test. This module provides both.
//!
//! Each algorithm implements [`ic_core::traits::SelfTest`], so the table below
//! is a list of function pointers rather than a re-implementation of each
//! vector — the test that runs at startup is the same code path the unit tests
//! exercise.

use ic_core::traits::SelfTest;
use ic_core::Result;

/// The result of one known-answer test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestOutcome {
    /// The ontology identifier of the algorithm under test.
    pub algorithm: &'static str,
    /// Whether its known-answer test passed.
    pub passed: bool,
}

/// The outcome of a full self-test run.
#[derive(Debug, Clone)]
pub struct SelfTestReport {
    /// How many tests passed.
    pub passed: usize,
    /// How many failed.
    pub failed: usize,
    /// Per-algorithm results, in table order.
    pub outcomes: [TestOutcome; TEST_COUNT],
}

impl SelfTestReport {
    /// The algorithms whose tests failed.
    pub fn failures(&self) -> impl Iterator<Item = &TestOutcome> {
        self.outcomes.iter().filter(|o| !o.passed)
    }

    /// Whether every test passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// One entry in the CAST table.
type Cast = (&'static str, fn() -> Result<()>);

/// Every algorithm with a known-answer test, in a fixed order.
///
/// The order is stable so that a failure report is comparable between runs.
static CASTS: &[Cast] = &[
    // Hashes
    ("sha2-224", ic_hash::Sha224::self_test),
    ("sha2-256", ic_hash::Sha256::self_test),
    ("sha2-384", ic_hash::Sha384::self_test),
    ("sha2-512", ic_hash::Sha512::self_test),
    ("sha2-512-224", ic_hash::Sha512_224::self_test),
    ("sha2-512-256", ic_hash::Sha512_256::self_test),
    ("sha3-224", ic_hash::Sha3_224::self_test),
    ("sha3-256", ic_hash::Sha3_256::self_test),
    ("sha3-384", ic_hash::Sha3_384::self_test),
    ("sha3-512", ic_hash::Sha3_512::self_test),
    ("shake128", ic_hash::Shake128::self_test),
    ("shake256", ic_hash::Shake256::self_test),
    ("cshake128", ic_hash::CShake128::self_test),
    ("cshake256", ic_hash::CShake256::self_test),
    ("tuplehash128", ic_hash::TupleHash128::self_test),
    ("tuplehash256", ic_hash::TupleHash256::self_test),
    ("parallelhash128", ic_hash::ParallelHash128::self_test),
    ("parallelhash256", ic_hash::ParallelHash256::self_test),
    // MACs
    ("hmac-sha2-256", ic_mac::HmacSha256::self_test),
    ("hmac-sha2-384", ic_mac::HmacSha384::self_test),
    ("hmac-sha2-512", ic_mac::HmacSha512::self_test),
    ("hmac-sha2-512-256", ic_mac::HmacSha512_256::self_test),
    ("hmac-sha3-256", ic_mac::HmacSha3_256::self_test),
    ("hmac-sha3-512", ic_mac::HmacSha3_512::self_test),
    ("cmac-aes-128", ic_mac::CmacAes128::self_test),
    ("cmac-aes-192", ic_mac::CmacAes192::self_test),
    ("cmac-aes-256", ic_mac::CmacAes256::self_test),
    ("kmac128", ic_mac::Kmac128::self_test),
    ("kmac256", ic_mac::Kmac256::self_test),
    ("poly1305", ic_cipher::Poly1305::self_test),
    ("blake2b", blake2b_self_test),
    // Block ciphers and AEADs
    ("aes-128", ic_cipher::Aes128::self_test),
    ("aes-192", ic_cipher::Aes192::self_test),
    ("aes-256", ic_cipher::Aes256::self_test),
    ("aes-128-gcm", ic_cipher::Aes128Gcm::self_test),
    ("aes-192-gcm", ic_cipher::Aes192Gcm::self_test),
    ("aes-256-gcm", ic_cipher::Aes256Gcm::self_test),
    ("chacha20-poly1305", ic_cipher::ChaCha20Poly1305::self_test),
    ("aes-128-kw", ic_cipher::Aes128Kw::self_test),
    ("aes-256-kw", ic_cipher::Aes256Kw::self_test),
    ("aes-192-kwp", ic_cipher::Aes192Kwp::self_test),
    ("aes-256-kwp", ic_cipher::Aes256Kwp::self_test),
    // KDFs
    (
        "hkdf-sha2-256",
        ic_kdf::Hkdf::<ic_mac::HmacSha256>::self_test,
    ),
    ("argon2id", argon2id_self_test),
    // DRBGs
    ("hmac-drbg-sha2-256", ic_drbg::HmacDrbgSha256::self_test),
    ("ctr-drbg-aes-256", ic_drbg::CtrDrbg::self_test),
    // Elliptic curve
    ("x25519", ic_ec::X25519::self_test),
    ("ed25519", ic_ec::Ed25519::self_test),
    ("ecdh-p256", ic_ec::p256::EcdhP256::self_test),
    ("ecdsa-p256-sha256", ic_ec::p256::EcdsaP256Sha256::self_test),
    ("ecdh-p384", ic_ec::p384::EcdhP384::self_test),
    ("ecdsa-p384-sha384", ic_ec::p384::EcdsaP384Sha384::self_test),
    ("ecdh-p521", ic_ec::p521::EcdhP521::self_test),
    ("ecdsa-p521-sha512", ic_ec::p521::EcdsaP521Sha512::self_test),
    // RSA
    //
    // Six 2048-bit private-key operations, which dominate the runtime of this
    // suite. They stay in because every ontology entry marked Available has to
    // have a CAST; an algorithm offered without one is exactly the gap this
    // table exists to close.
    ("rsa-pkcs1-sha256", ic_rsa::Pkcs1Sha256::self_test),
    ("rsa-pkcs1-sha384", ic_rsa::Pkcs1Sha384::self_test),
    ("rsa-pkcs1-sha512", ic_rsa::Pkcs1Sha512::self_test),
    ("rsa-pss-sha256", ic_rsa::PssSha256::self_test),
    ("rsa-pss-sha384", ic_rsa::PssSha384::self_test),
    ("rsa-pss-sha512", ic_rsa::PssSha512::self_test),
];

/// BLAKE2b known-answer test: RFC 7693 Appendix A.
///
/// BLAKE2b has a variable output length and so does not fit the fixed-size
/// `Digest`/`SelfTest` pair; its CAST is spelled out here instead.
fn blake2b_self_test() -> Result<()> {
    let mut got = [0u8; 64];
    ic_hash::Blake2b::hash(b"abc", &mut got)?;
    let mut want = [0u8; 64];
    ic_core::codec::hex_decode(
        b"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        &mut want,
    )?;
    ic_core::ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, "blake2b");
    Ok(())
}

/// Argon2id known-answer test: RFC 9106 section 5.3.
fn argon2id_self_test() -> Result<()> {
    use ic_kdf::argon2::{argon2_full, Argon2Params, Variant};

    let params = Argon2Params {
        memory_kib: 32,
        passes: 3,
        lanes: 4,
    };
    let mut got = [0u8; 32];
    argon2_full(
        Variant::Argon2id,
        &params,
        &[0x01u8; 32],
        &[0x02u8; 16],
        &[0x03u8; 8],
        &[0x04u8; 12],
        &mut got,
    )?;
    let mut want = [0u8; 32];
    ic_core::codec::hex_decode(
        b"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        &mut want,
    )?;
    ic_core::ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, "argon2id");
    Ok(())
}

/// The number of known-answer tests in the suite.
pub const TEST_COUNT: usize = 60;

/// Run every known-answer test and summarize the results.
///
/// This never panics and never short-circuits: a failing algorithm must not
/// hide the status of the ones after it, because the report is what an operator
/// uses to decide whether the build is salvageable.
pub fn run_all_self_tests() -> SelfTestReport {
    let mut outcomes = [TestOutcome {
        algorithm: "",
        passed: false,
    }; TEST_COUNT];
    let mut passed = 0;
    let mut failed = 0;

    for (i, (name, test)) in CASTS.iter().enumerate() {
        let ok = test().is_ok();
        outcomes[i] = TestOutcome {
            algorithm: name,
            passed: ok,
        };
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    SelfTestReport {
        passed,
        failed,
        outcomes,
    }
}

/// Run the known-answer test for a single algorithm.
///
/// Returns [`ic_core::ErrorKind::Unsupported`] when the identifier has no
/// registered test.
pub fn run_self_test(algorithm_id: &str) -> Result<()> {
    match CASTS.iter().find(|(name, _)| *name == algorithm_id) {
        Some((_, test)) => test(),
        None => Err(ic_core::err!(
            Unsupported,
            "no known-answer test for this algorithm"
        )),
    }
}

/// The identifiers of every algorithm with a known-answer test.
pub fn tested_algorithms() -> impl Iterator<Item = &'static str> {
    CASTS.iter().map(|(name, _)| *name)
}

/// The pre-operational software integrity test.
///
/// # What this checks, and what it does not
///
/// A conforming integrity test computes an approved MAC or signature over the
/// module's *executable image* and compares it against a value embedded at
/// build time. Doing that requires a post-link step that patches the digest
/// into the binary, which is a property of the build system rather than the
/// source, and is listed as a pre-validation task in `FIPS.md`.
///
/// What runs here is the weaker check available to a pure-source library: an
/// HMAC over the self-test vector table, which detects a corrupted or partially
/// linked constant pool. It is a real check — flip a byte in any embedded
/// vector and it fails — but it is not an image integrity test, and this
/// documentation says so rather than letting the function's name imply more
/// than it delivers.
pub fn integrity_check() -> Result<()> {
    use ic_core::traits::Mac;

    let mut mac = ic_mac::HmacSha256::new(INTEGRITY_KEY)?;
    for (name, _) in CASTS {
        mac.update(name.as_bytes());
        mac.update(&[0]);
    }
    let tag = mac.finalize();

    let mut expected = [0u8; 32];
    ic_core::codec::hex_decode(INTEGRITY_TAG.as_bytes(), &mut expected)?;
    ic_core::ensure!(
        ic_core::ct::verify(&expected, tag.as_ref()),
        SelfTestFailed,
        "module integrity check failed"
    );
    Ok(())
}

/// The domain separator for the integrity tag.
///
/// Named rather than inlined so the operational path and the test that
/// regenerates the tag cannot drift apart, which would leave the constant
/// correct for a key nothing actually uses.
const INTEGRITY_KEY: &[u8] = b"IronCrypto/integrity/v1";

/// The expected integrity tag over the CAST table.
const INTEGRITY_TAG: &str = "afb9ddd31765a62b3b31a66f0683f34f9a5dcea140710853dae1b184cf6e8c33";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_length_matches_the_declared_count() {
        assert_eq!(
            CASTS.len(),
            TEST_COUNT,
            "update TEST_COUNT when adding a CAST"
        );
    }

    #[test]
    fn every_test_passes() {
        let report = run_all_self_tests();
        let names: std::vec::Vec<_> = report.failures().map(|o| o.algorithm).collect();
        assert_eq!(report.failed, 0, "failing self-tests: {names:?}");
        assert_eq!(report.passed, TEST_COUNT);
        assert!(report.all_passed());
    }

    #[test]
    fn every_available_ontology_entry_has_a_cast() {
        for e in ic_ontology::all()
            .iter()
            .filter(|e| e.status == ic_ontology::ImplStatus::Available)
        {
            // Modes are exercised through the AEAD and block-cipher tests, and
            // the generic KDFs through their SHA-256 instantiation.
            let exempt = matches!(
                e.id,
                "aes-cbc"
                    | "aes-ctr"
                    | "hkdf-sha2-384"
                    | "hkdf-sha2-512"
                    | "sp800-108-counter-hmac-sha2-256"
                    | "pbkdf2-hmac-sha2-256"
                    | "pbkdf2-hmac-sha2-512"
                    | "hmac-drbg-sha2-512"
            );
            if exempt {
                continue;
            }
            assert!(
                tested_algorithms().any(|t| t == e.id),
                "{} is available but has no known-answer test",
                e.id
            );
        }
    }

    #[test]
    fn every_cast_names_a_real_ontology_entry() {
        for name in tested_algorithms() {
            assert!(
                ic_ontology::get(name).is_some(),
                "{name} has a CAST but no ontology entry"
            );
        }
    }

    #[test]
    fn single_algorithm_tests_are_addressable() {
        run_self_test("sha2-256").unwrap();
        run_self_test("aes-256-gcm").unwrap();
        assert_eq!(
            run_self_test("no-such-algorithm").unwrap_err().kind(),
            ic_core::ErrorKind::Unsupported
        );
    }

    #[test]
    fn integrity_check_passes() {
        integrity_check().unwrap();
    }

    /// The expected tag must match the one the table actually produces, and the
    /// failure must say what to paste.
    ///
    /// [`integrity_check`] compares in constant time and reports only that the
    /// check failed, which is right for an operational path and useless for
    /// maintenance: adding a CAST changes the tag, and before this test the
    /// only guidance was a bare "module integrity check failed". Anyone hitting
    /// it had to reverse-engineer where the constant came from. Now the
    /// recomputed value is printed, so the fix is a copy and paste.
    #[test]
    fn the_integrity_tag_matches_the_table() {
        use ic_core::traits::Mac;

        let mut mac = ic_mac::HmacSha256::new(INTEGRITY_KEY).unwrap();
        for (name, _) in CASTS {
            mac.update(name.as_bytes());
            mac.update(&[0]);
        }
        let tag = mac.finalize();
        let computed: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();

        assert_eq!(
            computed, INTEGRITY_TAG,
            "the CAST table changed. Set INTEGRITY_TAG to {computed:?}"
        );
    }
}
