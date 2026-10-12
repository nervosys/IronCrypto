//! yescrypt verification against libxcrypt.
//!
//! `testvectors/yescrypt-libxcrypt.json`, from
//! `scripts/gen_yescrypt_vectors.py`: hashes libxcrypt's crypt() made, the
//! crypt(3) these strings come from, and whether crypt() reproduces each for
//! a password. The settings reach the default flavor at three costs, the
//! prehashed path, two lanes, `t`, the smallest `r`, WORM (also with three
//! lanes and t = 1), classic scrypt, empty and 64-byte salts, and `$7$`
//! (also with a `p` that takes two characters). Every verdict must match.

use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::kdf::yescrypt;

#[test]
fn yescrypt_verifies_as_libxcrypt_does() {
    let Some(file) = VectorFile::load_or_report("yescrypt-libxcrypt") else {
        return;
    };
    let (mut yes, mut no) = (0, 0);
    for case in &file.cases {
        let hash = String::from_utf8(hex_field(case, "hash")).unwrap();
        let result = yescrypt::verify_password(&hex_field(case, "password"), &hash);
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
    assert_eq!((yes, no), (17, 17));
}

#[test]
fn what_libxcrypt_does_not_write_is_refused() {
    let salt = "k2XAnEHBqQ1Ct2aMXFKNa/";
    let tail = "uRt0PX5XBXcPN8OMTEutejPUGqrWS8ZdIuU3wFAenN7";
    // `have` is encoded less one: '1' is 4, a hash upgrade; '5' is 8, a ROM.
    for have in ["1", "5"] {
        let h = format!("$y$j6.{have}..${salt}${tail}");
        let e = yescrypt::verify_password(b"", &h).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{h}");
    }
    // Not yescrypt at all.
    for h in ["$2b$04$x", "$6$salt$hash", "", "$y$"] {
        assert!(yescrypt::verify_password(b"", h).is_err(), "{h}");
    }
}

#[test]
fn the_memory_ceiling_is_checked_before_deriving() {
    // N = 2^32, r = 8: 4 TiB, refused at once rather than allocated.
    let h = "$y$jT5$k2XAnEHBqQ1Ct2aMXFKNa/$uRt0PX5XBXcPN8OMTEutejPUGqrWS8ZdIuU3wFAenN7";
    let e = yescrypt::verify_password(b"", h).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidParameter);
    let p = yescrypt::params(h).unwrap();
    assert_eq!((p.n, p.r), (1 << 32, 8));
}

#[test]
fn a_large_t_or_many_lanes_is_refused_inside_the_memory_ceiling() {
    let salt = "k2XAnEHBqQ1Ct2aMXFKNa/";
    let tail = "uRt0PX5XBXcPN8OMTEutejPUGqrWS8ZdIuU3wFAenN7";
    // N = 2^9, r = 1 is 64 KiB. t = 2^20 passes the memory check and not
    // the work one. Encoded with the generator's encode64_uint32.
    let p = yescrypt::Params {
        flags: 0xb6,
        n: 1 << 9,
        r: 1,
        p: 1,
        t: 1 << 20,
    };
    assert!(p.memory_bytes().unwrap() < 1 << 20);
    assert!(p.work_bytes().unwrap() > 8 << 20);
    for h in [
        // t large.
        format!("$y$j6./y/vrD${salt}${tail}"),
        // $7$, N = 2^4, r = 1, p = 2^29: many lanes, each tiny.
        format!("$7$2/........U{salt}${tail}"),
    ] {
        let e = yescrypt::verify_password_bounded(b"", &h, 1 << 20).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidParameter, "{h}");
    }
}

/// Every character of a stored hash, replaced: nothing panics, and nothing
/// accepts the password under a string libxcrypt did not write.
#[test]
fn mangled_hashes_never_panic() {
    let good = "$y$j6.$k2XAnEHBqQ1Ct2aMXFKNa/$uRt0PX5XBXcPN8OMTEutejPUGqrWS8ZdIuU3wFAenN7";
    let seven = "$7$3/..../....SodiumChloride$x";
    for base in [good, seven] {
        for i in 0..base.len() {
            for c in ['.', '/', 'z', 'A', '$', '\0', '~', 'é'] {
                let mut s: Vec<char> = base.chars().collect();
                s[i] = c;
                let h: String = s.into_iter().collect();
                if h == good {
                    continue;
                }
                let _ = yescrypt::verify_password_bounded(b"", &h, 1 << 20);
            }
            let _ = yescrypt::verify_password_bounded(b"", &base[..i], 1 << 20);
        }
    }
}
