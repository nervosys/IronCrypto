//! `ic_kdf::passphrase` against containers sealed elsewhere.
//!
//! `testvectors/passphrase.json`, from `scripts/gen_passphrase_vectors.py`:
//! the container format written a second time in Python, over libsodium's
//! XChaCha20-Poly1305 and the Argon2 reference implementation. Every case at
//! the floor opens here to its plaintext; the one under it, which is the
//! self-test's, is refused through the public API, as anything under the
//! floor must be.

// Every algorithm here is one approved mode does not permit.
#![cfg(not(ic_approved_only))]

use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::drbg;
use ironcrypto::kdf::passphrase;
use ironcrypto::kdf::Argon2Params;

#[test]
fn containers_sealed_by_libsodium_and_the_argon2_reference_open() {
    let Some(file) = VectorFile::load_or_report("passphrase") else {
        return;
    };
    let mut opened = 0;
    for case in &file.cases {
        let name = String::from_utf8(hex_field(case, "name")).unwrap();
        let sealed = hex_field(case, "sealed");
        let plaintext = hex_field(case, "plaintext");
        let pw = hex_field(case, "passphrase");
        let params = passphrase::params_of(&sealed).unwrap();
        assert_eq!(params.memory_kib.to_string(), case["memory_kib"], "{name}");
        assert_eq!(params.passes.to_string(), case["passes"], "{name}");
        assert_eq!(params.lanes.to_string(), case["lanes"], "{name}");

        let mut out = vec![0u8; sealed.len()];
        if name == "self-test" {
            let err = passphrase::open(&pw, &sealed, &mut out).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidParameter, "{name}");
            continue;
        }
        let n = passphrase::open(&pw, &sealed, &mut out).unwrap();
        assert_eq!(out[..n], plaintext[..], "{name}");
        opened += 1;

        // The wrong passphrase, and one changed byte anywhere, fail the
        // same way and release nothing.
        let mut out = vec![0xaau8; sealed.len()];
        let err = passphrase::open(b"wrong", &sealed, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AuthenticationFailed, "{name}");
        assert!(
            out[..plaintext.len()].iter().all(|b| *b == 0),
            "{name}: wiped"
        );
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let err = passphrase::open(&pw, &tampered, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AuthenticationFailed, "{name}");
    }
    assert_eq!(opened, 3);
}

/// What this seals, the other implementation's layout describes: the header
/// carries the parameters and draws, and the container opens again here.
#[test]
fn a_sealed_container_opens_and_names_its_parameters() {
    let floor = Argon2Params {
        memory_kib: passphrase::MIN_MEMORY_KIB,
        passes: 2,
        lanes: 1,
    };
    let mut rng = drbg::Rng::from_entropy(&[0x41u8; 32], b"passphrase test").unwrap();
    let secret = [0x5cu8; 48];
    let mut sealed = [0u8; 48 + passphrase::OVERHEAD];
    let n = passphrase::seal(b"pw", &floor, &mut rng, &secret, &mut sealed).unwrap();
    assert_eq!(n, sealed.len());
    assert_eq!(&sealed[..4], b"ICPW");
    let params = passphrase::params_of(&sealed).unwrap();
    assert_eq!(
        (params.memory_kib, params.passes, params.lanes),
        (floor.memory_kib, 2, 1)
    );
    let mut back = [0u8; 48];
    assert_eq!(passphrase::open(b"pw", &sealed, &mut back).unwrap(), 48);
    assert_eq!(back, secret);

    // A second seal of the same secret draws a fresh salt and nonce.
    let mut again = [0u8; 48 + passphrase::OVERHEAD];
    passphrase::seal(b"pw", &floor, &mut rng, &secret, &mut again).unwrap();
    assert_ne!(sealed[19..59], again[19..59]);
}
