//! scrypt against OpenSSL, and RFC 7914's largest vector.
//!
//! `testvectors/scrypt-openssl.json`, from `scripts/gen_scrypt_vectors.py`:
//! OpenSSL's scrypt, through Python's hashlib, over shapes RFC 7914's vectors
//! do not vary -- N, r and p independently, empty and odd-length inputs,
//! outputs either side of a SHA-256 block.

use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::kdf::scrypt::{scrypt, ScryptParams};

#[test]
fn scrypt_matches_openssl() {
    let Some(file) = VectorFile::load_or_report("scrypt-openssl") else {
        return;
    };
    for case in &file.cases {
        let params = ScryptParams {
            log_n: case["log_n"].parse().unwrap(),
            r: case["r"].parse().unwrap(),
            p: case["p"].parse().unwrap(),
        };
        let want = hex_field(case, "out");
        let mut out = vec![0u8; want.len()];
        scrypt(
            &hex_field(case, "password"),
            &hex_field(case, "salt"),
            &params,
            &mut out,
        )
        .unwrap();
        assert_eq!(hex(&out), case["out"], "{params:?}");
    }
    assert_eq!(file.cases.len(), 8);
}

/// RFC 7914 section 12's fourth vector: N = 2^20, r = 8, 1 GiB. Minutes in a
/// debug build, so it runs only when `IC_SLOW_SCRYPT` is set; it was run on
/// 2026-10-12 in a release build and passed.
#[test]
fn the_rfcs_one_gibibyte_vector() {
    if std::env::var_os("IC_SLOW_SCRYPT").is_none() {
        eprintln!("skipped: set IC_SLOW_SCRYPT to run the 1 GiB vector");
        return;
    }
    let mut out = [0u8; 64];
    scrypt(
        b"pleaseletmein",
        b"SodiumChloride",
        &ScryptParams {
            log_n: 20,
            r: 8,
            p: 1,
        },
        &mut out,
    )
    .unwrap();
    assert_eq!(
        hex(&out),
        "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa47\
         8e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"
    );
}
