//! The DRBGs against NIST's ACVP vectors.
//!
//! `scripts/gen_drbg_vectors.py` converts NIST's files and says which groups
//! are kept: CTR_DRBG over AES-256 without a derivation function, and
//! HMAC_DRBG over every hash this library has an HMAC for, each with and
//! without prediction resistance.
//!
//! Every case drives all three functions of a DRBG. Without prediction
//! resistance it is instantiate, reseed, generate, generate; with it, each
//! generate draws entropy first, which SP 800-90A section 9.3.1 defines as a
//! reseed with the additional input followed by a generate with none. The
//! expected value is the second generate's output, so it depends on the
//! state every earlier step left behind.

use ic_core::traits::Drbg;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::drbg::{CtrDrbg, HmacDrbg};
use ironcrypto::mac;

type Case = std::collections::BTreeMap<String, String>;

/// Run one case's sequence and return what the second generate produced.
fn run<D: Drbg>(case: &Case) -> Vec<u8> {
    let field = |name: &str| hex_field(case, name);
    let mut drbg = D::instantiate(
        &field("entropy"),
        &field("nonce"),
        &field("personalization"),
    )
    .unwrap();
    let prediction_resistance = case["prediction_resistance"] == "true";
    if !prediction_resistance {
        drbg.reseed(&field("reseed_entropy"), &field("reseed_additional"))
            .unwrap();
    }
    let mut out = vec![0u8; case["returned"].len() / 2];
    for step in ["generate1", "generate2"] {
        let additional = field(&format!("{step}_additional"));
        if prediction_resistance {
            // SP 800-90A section 9.3.1, steps 7.1 to 7.3: reseed with the
            // fresh entropy and the additional input, then generate with no
            // additional input.
            drbg.reseed(&field(&format!("{step}_entropy")), &additional)
                .unwrap();
            drbg.generate(&[], &mut out).unwrap();
        } else {
            drbg.generate(&additional, &mut out).unwrap();
        }
    }
    out
}

#[test]
fn the_drbgs_match_every_acvp_case() {
    let Some(file) = VectorFile::load_or_report("drbg") else {
        return;
    };
    let mut ran = std::collections::BTreeMap::new();
    for case in &file.cases {
        let got = match case["algorithm"].as_str() {
            "ctr-drbg-aes-256" => run::<CtrDrbg>(case),
            "hmac-drbg-sha2-256" => run::<HmacDrbg<mac::HmacSha256>>(case),
            "hmac-drbg-sha2-384" => run::<HmacDrbg<mac::HmacSha384>>(case),
            "hmac-drbg-sha2-512" => run::<HmacDrbg<mac::HmacSha512>>(case),
            "hmac-drbg-sha2-512-256" => run::<HmacDrbg<mac::HmacSha512_256>>(case),
            "hmac-drbg-sha3-256" => run::<HmacDrbg<mac::HmacSha3_256>>(case),
            "hmac-drbg-sha3-512" => run::<HmacDrbg<mac::HmacSha3_512>>(case),
            other => panic!("unknown mechanism {other}"),
        };
        let label = format!(
            "{} prediction resistance {}",
            case["algorithm"], case["prediction_resistance"]
        );
        assert_eq!(hex(&got), case["returned"], "{label}");
        *ran.entry(label).or_insert(0) += 1;
    }
    // Seven mechanisms, each with and without prediction resistance, fifteen
    // cases apiece.
    assert_eq!(ran.len(), 14, "{ran:?}");
    assert!(ran.values().all(|n| *n == 15), "{ran:?}");
}
