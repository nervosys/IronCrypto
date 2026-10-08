//! HSS/LMS verification against `testvectors/lms.json`.
//!
//! The first six cases are the published ones: RFC 8554 appendix F's two and
//! RFC 9858 appendix A's four, read from the RFCs' text by
//! `scripts/gen_lms_vectors.py`. The rest are that script's, for the parameter
//! sets no RFC publishes a case for, and it says how they were checked.
//!
//! A signature that verifies proves little about a verifier: one that returned
//! `Ok` for everything would pass. So each case is also turned against the
//! rule, and every alteration must be refused as a failed signature.

use ic_core::ErrorKind;
use ic_vectors::{hex_field, VectorFile};
use ironcrypto::lms::{parameters, verify};

fn refused(public_key: &[u8], message: &[u8], signature: &[u8], what: &str) {
    match verify(public_key, message, signature) {
        Ok(()) => panic!("{what}: verified"),
        Err(e) => assert_eq!(e.kind(), ErrorKind::AuthenticationFailed, "{what}"),
    }
}

#[test]
fn every_case_verifies_and_no_alteration_does() {
    let Some(file) = VectorFile::load_or_report("lms") else {
        return;
    };
    let (mut published, mut generated) = (0, 0);
    let mut sets = std::collections::BTreeSet::new();
    for case in &file.cases {
        let source = case["source"].as_str();
        let (key, message, signature) = (
            hex_field(case, "public_key"),
            hex_field(case, "message"),
            hex_field(case, "signature"),
        );
        verify(&key, &message, &signature).unwrap_or_else(|e| panic!("{source}: {e:?}"));
        let p = parameters(&key).unwrap();
        sets.insert((p.hash.id(), p.width));

        // The message: a byte added, a byte changed, a byte removed.
        let mut other = message.clone();
        other.push(0);
        refused(&key, &other, &signature, source);
        if !message.is_empty() {
            let mut other = message.clone();
            other[0] ^= 1;
            refused(&key, &other, &signature, source);
            refused(&key, &message[1..], &signature, source);
        }
        // The signature: one bit changed at positions spread over all of it --
        // the level count, each typecode, the leaf number, the randomizer, the
        // chain values and the path -- and the first and last bytes always.
        let step = signature.len() / 97 + 1;
        for i in (0..signature.len())
            .step_by(step)
            .chain([signature.len() - 1])
        {
            let mut bad = signature.clone();
            bad[i] ^= 0x10;
            refused(&key, &message, &bad, &format!("{source}, byte {i}"));
        }
        // Its length: shorter by one, longer by one, and gone.
        refused(&key, &message, &signature[..signature.len() - 1], source);
        let mut long = signature.clone();
        long.push(0);
        refused(&key, &message, &long, source);
        refused(&key, &message, &[], source);
        // The public key's root, the one part of it a signature must match.
        let mut wrong_key = key.clone();
        *wrong_key.last_mut().unwrap() ^= 1;
        refused(&wrong_key, &message, &signature, source);
        let mut wrong_tree = key.clone();
        wrong_tree[12] ^= 1; // the first byte of I
        refused(&wrong_tree, &message, &signature, source);

        if source.starts_with("RFC ") {
            published += 1;
        } else {
            generated += 1;
        }
    }
    assert_eq!((published, generated), (6, 21), "the cases did not run");
    // Every hash at every Winternitz width.
    assert_eq!(sets.len(), 16, "{sets:?}");
}

/// A signature from one case never verifies under another case's key, though
/// both are well-formed: nothing about a signature's shape makes it valid.
#[test]
fn a_signature_belongs_to_its_own_key() {
    let Some(file) = VectorFile::load_or_report("lms") else {
        return;
    };
    let cases: Vec<_> = file
        .cases
        .iter()
        .map(|c| {
            (
                hex_field(c, "public_key"),
                hex_field(c, "message"),
                hex_field(c, "signature"),
            )
        })
        .collect();
    let mut crossed = 0;
    for (i, (key, _, _)) in cases.iter().enumerate() {
        for (j, (other_key, message, signature)) in cases.iter().enumerate() {
            if i != j && key != other_key {
                assert!(
                    verify(key, message, signature).is_err(),
                    "case {j} under key {i}"
                );
                crossed += 1;
            }
        }
    }
    assert!(crossed > 600, "only {crossed} pairs crossed");
}
