//! Ed25519 point encodings a strict verifier refuses.
//!
//! `testvectors/ed25519-degenerate-points.json`, from
//! `scripts/gen_ed25519_degenerate_points.py`: the eight points of small
//! order and the nineteen-odd non-canonical encodings, derived from the curve
//! equation and each refused by libsodium. Here, every one is refused as a
//! public key, and as the R of a signature under a real key.

// Every algorithm here is one approved mode does not permit.
#![cfg(not(ic_approved_only))]

use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::ec::{Ed25519Key, Ed25519VerifyKey};

#[test]
fn degenerate_points_are_refused_as_keys_and_as_r() {
    let Some(file) = VectorFile::load_or_report("ed25519-degenerate-points") else {
        return;
    };
    let key = Ed25519Key::from_seed(&[0x24u8; 32]).unwrap();
    let mut good = [0u8; 64];
    key.sign(b"message", &mut good).unwrap();
    let vk = Ed25519VerifyKey::from_bytes(key.public_key()).unwrap();
    vk.verify(b"message", &good).unwrap();

    let (mut small, mut aliases) = (0, 0);
    for case in &file.cases {
        let point = hex_field(case, "point");
        let as_key = Ed25519VerifyKey::from_bytes(&point).err().map(|e| e.kind());
        let mut sig = good;
        sig[..32].copy_from_slice(&point);
        let as_r = vk.verify(b"message", &sig).err().map(|e| e.kind());
        match case["kind"].as_str() {
            "small-order" => {
                assert_eq!(
                    as_key,
                    Some(ErrorKind::InvalidParameter),
                    "{}",
                    case["point"]
                );
                small += 1;
            }
            "non-canonical" => {
                assert_eq!(
                    as_key,
                    Some(ErrorKind::MalformedEncoding),
                    "{}",
                    case["point"]
                );
                aliases += 1;
            }
            other => panic!("unknown kind {other}"),
        }
        assert_eq!(
            as_r,
            Some(ErrorKind::MalformedEncoding),
            "R {}",
            case["point"]
        );
    }
    assert_eq!(small, 8);
    assert!(aliases >= 19, "{aliases}");
}
