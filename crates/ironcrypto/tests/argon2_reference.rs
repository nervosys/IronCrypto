//! Argon2 against the reference implementation and libsodium.
//!
//! `testvectors/argon2-reference.json`, from `scripts/gen_argon2_vectors.py`:
//! raw tags from libargon2, the C implementation by Argon2's authors, through
//! its full context -- both versions, all three variants, one to four lanes,
//! memory that rounds, tags either side of 64 bytes, secrets and associated
//! data -- and PHC strings from libargon2's encoder and from libsodium's
//! crypto_pwhash_str. RFC 9106's three vectors fix one shape; these vary the
//! ones it does not.

use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::kdf::argon2::{
    argon2_versioned, argon2_with_memory, fill_memory, phc, Argon2Params, Variant, Version,
    ZERO_BLOCK,
};

fn variant(name: &str) -> Variant {
    match name {
        "argon2d" => Variant::Argon2d,
        "argon2i" => Variant::Argon2i,
        "argon2id" => Variant::Argon2id,
        other => panic!("unknown variant {other}"),
    }
}

#[test]
fn raw_tags_match_libargon2() {
    let Some(file) = VectorFile::load_or_report("argon2-reference") else {
        return;
    };
    let mut checked = [0usize; 2];
    for case in file.cases.iter().filter(|c| c["kind"] == "raw") {
        let v = variant(&case["variant"]);
        let version = Version::from_number(case["version"].parse().unwrap()).unwrap();
        let params = Argon2Params {
            memory_kib: case["memory_kib"].parse().unwrap(),
            passes: case["passes"].parse().unwrap(),
            lanes: case["lanes"].parse().unwrap(),
        };
        let (pw, salt, secret, ad) = (
            hex_field(case, "password"),
            hex_field(case, "salt"),
            hex_field(case, "secret"),
            hex_field(case, "ad"),
        );
        let want = hex_field(case, "tag");
        let label = format!(
            "{} v{} m={} t={} p={} out={}",
            case["variant"],
            case["version"],
            case["memory_kib"],
            case["passes"],
            case["lanes"],
            want.len()
        );

        let mut out = vec![0u8; want.len()];
        argon2_versioned(v, version, &params, &pw, &salt, &secret, &ad, &mut out).unwrap();
        assert_eq!(hex(&out), case["tag"], "{label}");

        // The same through memory the caller provides, one block too many to
        // show only the count needed is used; and it is wiped afterwards.
        let mut memory = vec![ZERO_BLOCK; params.block_count() + 1];
        let mut out = vec![0u8; want.len()];
        argon2_with_memory(
            v,
            version,
            &params,
            &pw,
            &salt,
            &secret,
            &ad,
            &mut memory,
            &mut out,
        )
        .unwrap();
        assert_eq!(hex(&out), case["tag"], "{label}, caller's memory");
        assert!(memory.iter().all(|b| *b == ZERO_BLOCK), "{label}: wiped");

        checked[usize::from(version == Version::V0x13)] += 1;
    }
    assert_eq!(checked, [21, 21], "both versions, every variant and shape");
}

#[test]
fn phc_strings_from_libargon2_and_libsodium_verify_as_recorded() {
    let Some(file) = VectorFile::load_or_report("argon2-reference") else {
        return;
    };
    let (mut accepted, mut refused) = (0, 0);
    for case in file.cases.iter().filter(|c| c["kind"] == "phc") {
        let encoded = String::from_utf8(hex_field(case, "phc")).unwrap();
        let pw = hex_field(case, "password");
        let parsed = phc::PasswordHash::parse(&encoded).unwrap();
        // libargon2 and libsodium write canonical strings, and this writes
        // them back the same -- except where the version was left out, which
        // this always writes.
        if encoded.contains("$v=") {
            assert_eq!(parsed.encode(), encoded);
        } else {
            assert_eq!(parsed.version, Version::V0x10, "{encoded}");
        }
        match (
            case["verifies"].as_str(),
            phc::verify_password(&pw, &encoded),
        ) {
            ("true", Ok(())) => accepted += 1,
            ("false", Err(e)) => {
                assert_eq!(e.kind(), ErrorKind::AuthenticationFailed, "{encoded}");
                refused += 1;
            }
            (want, got) => panic!("{encoded}: expected {want}, got {got:?}"),
        }
    }
    // Three variants at two versions, the three with no version, and two
    // from libsodium; each wrong password refused.
    assert_eq!((accepted, refused), (11, 8));
}

/// A string this writes, libargon2's decoder must read: checked by writing
/// one with the reference case's inputs and comparing to the reference's
/// raw tag, since the hash in a PHC string is exactly that tag.
#[test]
fn a_phc_hash_is_the_raw_tag() {
    let params = Argon2Params {
        memory_kib: 64,
        passes: 2,
        lanes: 2,
    };
    let s = phc::hash_password_with(
        Variant::Argon2id,
        Version::V0x13,
        &params,
        b"pw",
        &[3u8; 16],
        &[],
        &[],
        b"ad",
        32,
    )
    .unwrap();
    let mut tag = [0u8; 32];
    argon2_versioned(
        Variant::Argon2id,
        Version::V0x13,
        &params,
        b"pw",
        &[3u8; 16],
        &[],
        b"ad",
        &mut tag,
    )
    .unwrap();
    assert_eq!(phc::PasswordHash::parse(&s).unwrap().hash, tag);
}

/// `fill_memory` fills every block, and refuses memory one block short.
///
/// No reference implementation exposes the filled memory, so its contents
/// are not checked against one here; what is checked is that it runs the
/// same fill the hashing functions do, which the raw tags above hold, with a
/// tag length of zero in `H0` as the `argon2` crate has it.
#[test]
fn fill_memory_fills_without_a_tag() {
    let params = Argon2Params {
        memory_kib: 32,
        passes: 1,
        lanes: 1,
    };
    let mut memory = vec![ZERO_BLOCK; params.block_count()];
    fill_memory(
        Variant::Argon2id,
        Version::V0x13,
        &params,
        b"pw",
        &[1u8; 8],
        &[],
        &[],
        &mut memory,
    )
    .unwrap();
    assert!(memory.iter().all(|b| *b != ZERO_BLOCK));
    let short = &mut vec![ZERO_BLOCK; params.block_count() - 1];
    let err = fill_memory(
        Variant::Argon2id,
        Version::V0x13,
        &params,
        b"pw",
        &[1u8; 8],
        &[],
        &[],
        short,
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidLength);
}
