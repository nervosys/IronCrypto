//! Hash-to-curve and the OPRF, against RFC 9380 and RFC 9497.
//!
//! `testvectors/rfc9380-p256.json` and `testvectors/rfc9497-p256.json`, from
//! `scripts/gen_oprf_vectors.py`, which transcribes them from the RFC text.
//! The OPRF vectors fix the client's blinds and the server's proof nonce;
//! a scripted random source hands those out in the order the protocol draws
//! them, so every intermediate value -- derived key, blinded element,
//! evaluated element, proof, output -- is compared, in all three modes and
//! for the batches.

// Every algorithm here is one approved mode does not permit.
#![cfg(not(ic_approved_only))]

use ic_core::traits::RandomSource;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::ec::hash_to_curve::{expand_message_xmd, hash_to_curve};
use ironcrypto::ec::oprf::{
    blind, finalize_batch, BlindState, Mode, ServerKey, ELEMENT_LEN, OUTPUT_LEN, PROOF_LEN,
};

#[test]
fn hash_to_curve_matches_rfc_9380() {
    let Some(file) = VectorFile::load_or_report("rfc9380-p256") else {
        return;
    };
    let (mut points, mut expands) = (0, 0);
    for case in &file.cases {
        let msg = hex_field(case, "msg");
        match case["kind"].as_str() {
            "h2c" => {
                let p =
                    hash_to_curve(&msg, b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_").unwrap();
                assert_eq!(hex(&p[1..33]), case["P_x"]);
                assert_eq!(hex(&p[33..]), case["P_y"]);
                points += 1;
            }
            "xmd" => {
                let mut out = vec![0u8; case["len"].parse().unwrap()];
                expand_message_xmd(&msg, b"QUUX-V01-CS02-with-expander-SHA256-128", &mut out)
                    .unwrap();
                assert_eq!(hex(&out), case["uniform_bytes"]);
                expands += 1;
            }
            other => panic!("unknown kind {other}"),
        }
    }
    assert_eq!((points, expands), (5, 10));
}

/// Hands out given scalars, one per draw.
struct Script(Vec<Vec<u8>>);

impl RandomSource for Script {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        let next = self.0.remove(0);
        assert_eq!(next.len(), out.len());
        out.copy_from_slice(&next);
        Ok(())
    }
}

fn list(field: &str) -> Vec<Vec<u8>> {
    field
        .split(',')
        .map(|h| {
            let mut out = vec![0u8; h.len() / 2];
            ic_core::codec::hex_decode(h.as_bytes(), &mut out).unwrap();
            out
        })
        .collect()
}

fn element(bytes: &[u8]) -> [u8; ELEMENT_LEN] {
    bytes.try_into().unwrap()
}

#[test]
fn the_oprf_matches_rfc_9497_in_every_mode() {
    let Some(file) = VectorFile::load_or_report("rfc9497-p256") else {
        return;
    };
    let mut checked = [0usize; 3];
    for case in &file.cases {
        let mode = match case["mode"].as_str() {
            "OPRF" => Mode::Oprf,
            "VOPRF" => Mode::Voprf,
            "POPRF" => Mode::Poprf,
            other => panic!("unknown mode {other}"),
        };
        let seed: [u8; 32] = hex_field(case, "Seed").try_into().unwrap();
        let key = ServerKey::derive(mode, &seed, &hex_field(case, "KeyInfo")).unwrap();
        assert_eq!(hex(key.to_bytes().as_ref()), case["skSm"], "{mode:?} key");
        if let Some(pk) = case.get("pkSm") {
            assert_eq!(&hex(&key.public_key()), pk, "{mode:?} public key");
        }
        let info = case
            .get("Info")
            .map(|_| hex_field(case, "Info"))
            .unwrap_or_default();
        let inputs = list(&case["Input"]);
        let n = inputs.len();
        let pk = key.public_key();

        // The client blinds each input with the RFC's blind.
        let mut rng = Script(list(&case["Blind"]));
        let mut states: Vec<BlindState> = Vec::new();
        let mut blinded = Vec::new();
        for input in &inputs {
            let (state, b) = blind(mode, input, &info, Some(&pk), &mut rng).unwrap();
            states.push(state);
            blinded.push(b);
        }
        let want_blinded: Vec<[u8; ELEMENT_LEN]> = list(&case["BlindedElement"])
            .iter()
            .map(|b| element(b))
            .collect();
        assert_eq!(blinded, want_blinded, "{mode:?} blinded");

        // The server evaluates, drawing the RFC's proof nonce.
        let mut rng = Script(
            case.get("ProofRandomScalar")
                .map(|s| list(s))
                .unwrap_or_default(),
        );
        let mut evaluated = vec![[0u8; ELEMENT_LEN]; n];
        let proof = key
            .blind_evaluate_batch(&blinded, &info, &mut rng, &mut evaluated)
            .unwrap();
        let want_evaluated: Vec<[u8; ELEMENT_LEN]> = list(&case["EvaluationElement"])
            .iter()
            .map(|b| element(b))
            .collect();
        assert_eq!(evaluated, want_evaluated, "{mode:?} evaluated");
        match (mode, &proof) {
            (Mode::Oprf, None) => {}
            (_, Some(p)) => assert_eq!(hex(p), case["Proof"], "{mode:?} proof"),
            _ => panic!("{mode:?}: proof present or missing wrongly"),
        }

        // The client verifies and unblinds.
        let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let mut outputs = vec![[0u8; OUTPUT_LEN]; n];
        finalize_batch(
            &input_refs,
            &info,
            &states,
            &blinded,
            &evaluated,
            proof.as_ref(),
            &mut outputs,
        )
        .unwrap();
        let want: Vec<String> = case["Output"].split(',').map(String::from).collect();
        let got: Vec<String> = outputs.iter().map(|o| hex(o)).collect();
        assert_eq!(got, want, "{mode:?} output");
        // And the server's direct evaluation agrees.
        for (input, output) in inputs.iter().zip(outputs.iter()) {
            assert_eq!(
                &key.evaluate(input, &info).unwrap(),
                output,
                "{mode:?} evaluate"
            );
        }

        // A proof with one bit changed is refused, and nothing is written.
        if let Some(mut bad) = proof {
            bad[PROOF_LEN - 1] ^= 1;
            let mut untouched = vec![[0xaau8; OUTPUT_LEN]; n];
            let err = finalize_batch(
                &input_refs,
                &info,
                &states,
                &blinded,
                &evaluated,
                Some(&bad),
                &mut untouched,
            )
            .unwrap_err();
            assert!(matches!(
                err.kind(),
                ic_core::ErrorKind::AuthenticationFailed | ic_core::ErrorKind::MalformedEncoding
            ));
            assert!(untouched.iter().all(|o| *o == [0xaau8; OUTPUT_LEN]));
        }
        checked[mode as usize] += 1;
    }
    assert_eq!(checked, [2, 3, 3]);
}
