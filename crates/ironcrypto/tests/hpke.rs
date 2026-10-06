//! HPKE against `testvectors/hpke-x25519.json`.
//!
//! The file reproduces RFC 9180 appendix A.1.1 before it writes anything, and
//! carries A.1.1's inputs through all three AEADs; `scripts/gen_hpke_vectors.py`
//! says what is published and what is the generator's own. Every setup is run
//! from both sides, every encryption is sealed by the sender at its sequence
//! number and opened by the receiver, and every export is compared.

use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::hpke::{self, Aead, Context, KeyPair, TAG_LEN};

fn aead(case: &std::collections::BTreeMap<String, String>) -> Aead {
    let id = u16::from_str_radix(&case["aead_id"], 16).expect("aead id");
    Aead::from_id(id).expect("an AEAD this crate implements")
}

/// Both sides of a context, positioned at `seq`.
fn contexts_at(setup: &std::collections::BTreeMap<String, String>, seq: u64) -> (Context, Context) {
    let aead = aead(setup);
    let info = hex_field(setup, "info");
    let ephemeral = KeyPair::from_private(&hex_field(setup, "sk_em")).unwrap();
    let recipient = KeyPair::from_private(&hex_field(setup, "sk_rm")).unwrap();
    assert_eq!(
        hex(ephemeral.public()),
        hex(&hex_field(setup, "pk_em")),
        "pkEm"
    );
    assert_eq!(
        hex(recipient.public()),
        hex(&hex_field(setup, "pk_rm")),
        "pkRm"
    );
    let (enc, mut tx) =
        hpke::setup_sender_with_ephemeral(recipient.public(), &info, aead, &ephemeral).unwrap();
    assert_eq!(hex(&enc), hex(&hex_field(setup, "enc")), "enc");
    let mut rx = hpke::setup_receiver(&enc, &recipient, &info, aead).unwrap();
    // Advance both sides by sealing and opening throwaway messages, which is
    // the only way a context's sequence moves.
    for _ in 0..seq {
        let mut m = [0u8; 1];
        let mut tag = [0u8; TAG_LEN];
        tx.seal_in_place(b"", &mut m, &mut tag).unwrap();
        rx.open_in_place(b"", &mut m, &tag).unwrap();
    }
    (tx, rx)
}

#[test]
fn hpke_agrees_with_the_vectors() {
    let Some(file) = VectorFile::load_or_report("hpke-x25519") else {
        return;
    };
    let setup_for = |id: &str| {
        file.cases
            .iter()
            .find(|c| c["kind"] == "setup" && c["aead_id"] == id)
            .expect("a setup case for each AEAD")
    };
    let (mut setups, mut encryptions, mut exports) = (0, 0, 0);
    for case in &file.cases {
        let setup = setup_for(&case["aead_id"]);
        match case["kind"].as_str() {
            "setup" => {
                let (tx, _) = contexts_at(setup, 0);
                assert_eq!(tx.aead(), aead(case));
                setups += 1;
            }
            "encryption" => {
                let seq: u64 = case["seq"].parse().unwrap();
                let (mut tx, mut rx) = contexts_at(setup, seq);
                let (aad, pt, want) = (
                    hex_field(case, "aad"),
                    hex_field(case, "pt"),
                    hex_field(case, "ct"),
                );
                let mut body = pt.clone();
                let mut tag = [0u8; TAG_LEN];
                tx.seal_in_place(&aad, &mut body, &mut tag).unwrap();
                let mut got = body.clone();
                got.extend_from_slice(&tag);
                assert_eq!(hex(&got), hex(&want), "{} seq {seq}", case["aead"]);
                rx.open_in_place(&aad, &mut body, &tag).unwrap();
                assert_eq!(body, pt, "{} seq {seq}: opened", case["aead"]);
                encryptions += 1;
            }
            "export" => {
                let (tx, rx) = contexts_at(setup, 0);
                let len: usize = case["length"].parse().unwrap();
                let ctx = hex_field(case, "exporter_context");
                let want = hex_field(case, "value");
                for side in [&tx, &rx] {
                    let mut out = vec![0u8; len];
                    side.export(&ctx, &mut out).unwrap();
                    assert_eq!(
                        hex(&out),
                        hex(&want),
                        "{} export {}",
                        case["aead"],
                        hex(&ctx)
                    );
                }
                exports += 1;
            }
            other => panic!("unknown case kind {other}"),
        }
    }
    assert_eq!((setups, encryptions, exports), (3, 18, 9));
}

/// Both sides of a P-384 context, positioned at `seq`, with both keys taken
/// through `DeriveKeyPair` from the file's `ikm` and checked against it.
fn p384_contexts_at(
    setup: &std::collections::BTreeMap<String, String>,
    seq: u64,
) -> (Context, Context) {
    use hpke::p384;
    let aead = aead(setup);
    let info = hex_field(setup, "info");
    let ephemeral = p384::KeyPair::derive(&hex_field(setup, "ikm_e")).unwrap();
    let recipient = p384::KeyPair::derive(&hex_field(setup, "ikm_r")).unwrap();
    for (key, sk, pk) in [
        (&ephemeral, "sk_em", "pk_em"),
        (&recipient, "sk_rm", "pk_rm"),
    ] {
        assert_eq!(hex(key.public()), hex(&hex_field(setup, pk)), "{pk}");
        let again = p384::KeyPair::from_private(&hex_field(setup, sk)).unwrap();
        assert_eq!(again.public(), key.public(), "{sk} gives {pk}");
    }
    let (enc, mut tx) =
        p384::setup_sender_with_ephemeral(recipient.public(), &info, aead, &ephemeral).unwrap();
    assert_eq!(hex(&enc), hex(&hex_field(setup, "enc")), "enc");
    let mut rx = p384::setup_receiver(&enc, &recipient, &info, aead).unwrap();
    for _ in 0..seq {
        let mut m = [0u8; 1];
        let mut tag = [0u8; TAG_LEN];
        tx.seal_in_place(b"", &mut m, &mut tag).unwrap();
        rx.open_in_place(b"", &mut m, &tag).unwrap();
    }
    (tx, rx)
}

/// DHKEM(P-384, HKDF-SHA384) against `testvectors/hpke-p384.json`. No
/// published HPKE vector uses P-384; `scripts/gen_hpke_p384_vectors.py` says
/// how these were checked before they were written.
#[test]
fn hpke_p384_agrees_with_the_vectors() {
    let Some(file) = VectorFile::load_or_report("hpke-p384") else {
        return;
    };
    let setup_for = |id: &str| {
        file.cases
            .iter()
            .find(|c| c["kind"] == "setup" && c["aead_id"] == id)
            .expect("a setup case for each AEAD")
    };
    let (mut setups, mut encryptions, mut exports) = (0, 0, 0);
    for case in &file.cases {
        let setup = setup_for(&case["aead_id"]);
        match case["kind"].as_str() {
            "setup" => {
                p384_contexts_at(setup, 0);
                setups += 1;
            }
            "encryption" => {
                let seq: u64 = case["seq"].parse().unwrap();
                let (mut tx, mut rx) = p384_contexts_at(setup, seq);
                let (aad, pt, want) = (
                    hex_field(case, "aad"),
                    hex_field(case, "pt"),
                    hex_field(case, "ct"),
                );
                let mut body = pt.clone();
                let mut tag = [0u8; TAG_LEN];
                tx.seal_in_place(&aad, &mut body, &mut tag).unwrap();
                let mut got = body.clone();
                got.extend_from_slice(&tag);
                assert_eq!(hex(&got), hex(&want), "{} seq {seq}", case["aead"]);
                rx.open_in_place(&aad, &mut body, &tag).unwrap();
                assert_eq!(body, pt);
                encryptions += 1;
            }
            "export" => {
                let (tx, rx) = p384_contexts_at(setup, 0);
                let len: usize = case["length"].parse().unwrap();
                let ctx = hex_field(case, "exporter_context");
                for side in [&tx, &rx] {
                    let mut out = vec![0u8; len];
                    side.export(&ctx, &mut out).unwrap();
                    assert_eq!(
                        hex(&out),
                        case["value"],
                        "export {}",
                        case["exporter_context"]
                    );
                }
                exports += 1;
            }
            other => panic!("unknown case kind {other}"),
        }
    }
    assert_eq!((setups, encryptions, exports), (3, 18, 9));
}
