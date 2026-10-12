//! `ic_kdf::password`: one door for stored hashes.
//!
//! The bcrypt and yescrypt strings are pyca/bcrypt's and libxcrypt's, from
//! `testvectors/`; the Argon2 and scrypt strings are made here, since their
//! formats are checked against other implementations in their own tests.
//! What is under test is the dispatch and the rehash decision.

use ic_core::ErrorKind;
use ironcrypto::drbg::Rng;
use ironcrypto::kdf::argon2::{phc, Argon2Params, Variant};
use ironcrypto::kdf::password::{self, Scheme};
use ironcrypto::kdf::scrypt::{self, ScryptParams};

const POLICY: Argon2Params = Argon2Params {
    memory_kib: 64,
    passes: 2,
    lanes: 1,
};
const BCRYPT: (&[u8], &str) = (
    b"U*U",
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
);
const YESCRYPT: (&[u8], &str) = (
    b"",
    "$y$j6.$k2XAnEHBqQ1Ct2aMXFKNa/$uRt0PX5XBXcPN8OMTEutejPUGqrWS8ZdIuU3wFAenN7",
);

fn rng() -> Rng {
    Rng::from_entropy(&[0x5au8; 32], b"tests/password").unwrap()
}

#[test]
fn every_format_is_verified_and_the_right_ones_are_replaced() {
    let mut rng = rng();
    let current = phc::hash_password(Variant::Argon2id, &POLICY, b"pw", &mut rng).unwrap();
    let weaker = Argon2Params {
        passes: 1,
        ..POLICY
    };
    let old = phc::hash_password(Variant::Argon2id, &weaker, b"pw", &mut rng).unwrap();
    let argon2i = phc::hash_password(Variant::Argon2i, &POLICY, b"pw", &mut rng).unwrap();
    let scrypt_params = ScryptParams {
        log_n: 4,
        r: 1,
        p: 1,
    };
    let scrypt = scrypt::phc::hash_password(&scrypt_params, b"pw", &mut rng).unwrap();

    let cases: [(&[u8], &str, Scheme, bool); 6] = [
        (b"pw", &current, Scheme::Argon2, false),
        (b"pw", &old, Scheme::Argon2, true),
        (b"pw", &argon2i, Scheme::Argon2, true),
        (b"pw", &scrypt, Scheme::Scrypt, true),
        (BCRYPT.0, BCRYPT.1, Scheme::Bcrypt, true),
        (YESCRYPT.0, YESCRYPT.1, Scheme::Yescrypt, true),
    ];
    for (pw, stored, scheme, rehash) in cases {
        let v = password::verify(pw, stored, &POLICY).unwrap();
        assert_eq!((v.scheme, v.needs_rehash), (scheme, rehash), "{stored}");

        let mut wrong = pw.to_vec();
        wrong.push(b'!');
        let e = password::verify(&wrong, stored, &POLICY).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AuthenticationFailed, "{stored}");
        let e = password::verify_and_upgrade(&wrong, stored, &POLICY, &mut rng).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AuthenticationFailed, "{stored}");

        match password::verify_and_upgrade(pw, stored, &POLICY, &mut rng).unwrap() {
            None => assert!(!rehash, "{stored}"),
            Some(new) => {
                assert!(rehash, "{stored}");
                assert!(new.starts_with("$argon2id$v=19$m=64,t=2,p=1$"), "{new}");
                let again = password::verify(pw, &new, &POLICY).unwrap();
                assert_eq!((again.scheme, again.needs_rehash), (Scheme::Argon2, false));
            }
        }
    }
}

#[test]
fn unknown_formats_are_unsupported() {
    for stored in [
        "",
        "plaintext",
        "$1$md5crypt$x",
        "$5$rounds=5000$sha256crypt$x",
        "$6$sha512crypt$x",
        "$pbkdf2-sha256$29000$x$y",
    ] {
        let e = password::verify(b"pw", stored, &POLICY).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{stored}");
        assert!(password::scheme(stored).is_err());
    }
    // $2x$ is recognised as bcrypt, and bcrypt refuses it.
    assert_eq!(password::scheme("$2x$05$x"), Ok(Scheme::Bcrypt));
    let e = password::verify(
        b"pw",
        "$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
        &POLICY,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported);
}
