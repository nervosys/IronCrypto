//! Self-tests before first use, for a caller who never asks for them.
//!
//! In a build with `--cfg ic_approved_only` a primitive called directly is
//! refused until `ic_fips::initialize` has run the known-answer tests and they
//! have passed. In the default build it is not, and that is asserted too, so
//! the difference is a tested property of each build rather than a claim.
//!
//! In a file of its own because it is a process of its own: the state it
//! examines is set once and never reset, so it has to be looked at before
//! anything in the process calls `initialize`.

use ic_core::traits::{Aead, Kdf, Mac};
use ic_core::ErrorKind;

/// One operation from each of the families that can refuse.
fn attempts() -> [(&'static str, ic_core::Result<()>); 4] {
    let mut okm = [0u8; 32];
    [
        (
            "aes-256-gcm",
            ic_cipher::Aes256Gcm::new(&[7u8; 32]).map(|_| ()),
        ),
        (
            "hmac-sha2-256",
            ic_mac::HmacSha256::new(&[7u8; 32]).map(|_| ()),
        ),
        (
            "hkdf-sha2-256",
            ic_kdf::Hkdf::<ic_mac::HmacSha256>::derive(&[7u8; 32], b"salt", b"info", &mut okm),
        ),
        (
            "ecdsa-p256-sha256",
            <ic_ec::p256::EcdsaP256Sha256 as ic_core::traits::SignatureScheme>::public_key(
                &[7u8; 32],
                &mut [0u8; 65],
            )
            .map(|_| ()),
        ),
    ]
}

#[test]
fn a_direct_call_waits_for_the_self_tests_only_where_the_build_says_so() {
    let gated = cfg!(all(ic_approved_only, not(ic_startup_gate_off)));

    assert!(!ic_core::module::self_tests_have_passed());
    for (name, result) in attempts() {
        if gated {
            assert_eq!(
                result.expect_err(name).kind(),
                ErrorKind::ModuleErrorState,
                "{name} ran before the self-tests"
            );
        } else {
            result.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
    }

    ic_fips::initialize().unwrap();
    assert!(ic_core::module::self_tests_have_passed());
    for (name, result) in attempts() {
        result.unwrap_or_else(|e| panic!("{name} after initialize: {e:?}"));
    }
}
