//! bcrypt verification against pyca/bcrypt.
//!
//! `testvectors/bcrypt.json`, from `scripts/gen_bcrypt_vectors.py`: hashes
//! pyca/bcrypt made, and whether its checkpw accepts each password -- the
//! three prefixes, costs 4 to 10, the empty password, both sides of the
//! 72-byte limit, non-ASCII, and wrong passwords. Every verdict must match.

use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::kdf::bcrypt;

#[test]
fn bcrypt_verifies_as_pyca_does() {
    let Some(file) = VectorFile::load_or_report("bcrypt") else {
        return;
    };
    let (mut yes, mut no) = (0, 0);
    for case in &file.cases {
        let hash = String::from_utf8(hex_field(case, "hash")).unwrap();
        let result = bcrypt::verify_password(&hex_field(case, "password"), &hash);
        match case["verifies"].as_str() {
            "true" => {
                result.unwrap_or_else(|e| panic!("{hash}: {e:?}"));
                yes += 1;
            }
            _ => {
                assert_eq!(
                    result.unwrap_err().kind(),
                    ErrorKind::AuthenticationFailed,
                    "{hash}"
                );
                no += 1;
            }
        }
    }
    assert_eq!((yes, no), (35, 16));
}

#[test]
fn a_cost_above_the_default_ceiling_is_refused_at_once() {
    // Cost 31, about 2^19 times cost 12: refused before any work.
    let h = "$2a$31$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    assert_eq!(bcrypt::cost(h).unwrap(), 31);
    let e = bcrypt::verify_password(b"U*U", h).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidParameter);
    assert_eq!(bcrypt::DEFAULT_MAX_COST, 16);
}

/// Every character of a stored hash, replaced: nothing panics, and only the
/// string pyca made accepts the password.
#[test]
fn mangled_hashes_never_panic() {
    let good = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    for i in 0..good.len() {
        for c in ['.', '/', 'z', 'A', '$', '0', '9', '\0', 'é'] {
            let mut s: Vec<char> = good.chars().collect();
            s[i] = c;
            let h: String = s.into_iter().collect();
            if h != good {
                assert!(
                    bcrypt::verify_password_bounded(b"U*U", &h, 6).is_err(),
                    "{h}"
                );
            }
        }
        let _ = bcrypt::verify_password_bounded(b"U*U", &good[..i], 6);
    }
}
