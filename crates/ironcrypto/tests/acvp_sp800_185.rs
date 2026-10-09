//! TupleHash, ParallelHash and KMAC against NIST's ACVP vectors.
//!
//! `scripts/gen_acvp_sp800_185_vectors.py` converts NIST's files and keeps
//! the cases whose every length is whole bytes. That is uneven, and the
//! unevenness is the thing to know about this file:
//!
//! - TupleHash: 400 cases, fixed-length and XOF, both sizes. A real check.
//! - ParallelHash: 13 cases.
//! - KMAC: 3 cases, and only one of them says what a MAC should be. The
//!   other two are MACs NIST says are wrong, which a wrong KMAC would also
//!   disagree with. So KMAC128 has one published value here and KMAC256 has
//!   none; both still rest on the reconstruction in `ic-mac`'s own tests.

use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::hash::{ParallelHash128, ParallelHash256, TupleHash128, TupleHash256};
use ironcrypto::mac::{Kmac128, Kmac256};

#[test]
fn the_sp_800_185_functions_match_the_byte_aligned_acvp_cases() {
    let Some(file) = VectorFile::load_or_report("acvp-sp800-185") else {
        return;
    };
    let mut ran = std::collections::BTreeMap::new();
    for case in &file.cases {
        let custom = hex_field(case, "customization");
        let xof = case["xof"] == "true";
        let expected = case["valid"] == "true";
        let mut out = vec![0u8; case["output"].len() / 2];
        let function = case["function"].as_str();
        match function {
            "tuplehash128" | "tuplehash256" => {
                // Elements are comma-separated, and an element may be empty.
                let elements: Vec<Vec<u8>> = case["input"]
                    .split(',')
                    .map(|e| {
                        let mut bytes = vec![0u8; e.len() / 2];
                        ic_core::codec::hex_decode(e.as_bytes(), &mut bytes).expect("hex element");
                        bytes
                    })
                    .collect();
                assert_eq!(elements.len().to_string(), case["elements"]);
                let refs: Vec<&[u8]> = elements.iter().map(Vec::as_slice).collect();
                match (function, xof) {
                    ("tuplehash128", false) => TupleHash128::hash(&custom, &refs, &mut out),
                    ("tuplehash128", true) => TupleHash128::hash_xof(&custom, &refs, &mut out),
                    (_, false) => TupleHash256::hash(&custom, &refs, &mut out),
                    (_, true) => TupleHash256::hash_xof(&custom, &refs, &mut out),
                }
            }
            "parallelhash128" | "parallelhash256" => {
                let data = hex_field(case, "input");
                let block: usize = case["block_size"].parse().expect("block size");
                match (function, xof) {
                    ("parallelhash128", false) => {
                        ParallelHash128::hash(&custom, block, &data, &mut out)
                    }
                    ("parallelhash128", true) => {
                        ParallelHash128::hash_xof(&custom, block, &data, &mut out)
                    }
                    (_, false) => ParallelHash256::hash(&custom, block, &data, &mut out),
                    (_, true) => ParallelHash256::hash_xof(&custom, block, &data, &mut out),
                }
            }
            "kmac128" | "kmac256" => {
                let (key, data) = (hex_field(case, "key"), hex_field(case, "input"));
                match (function, xof) {
                    ("kmac128", false) => Kmac128::mac(&key, &custom, &data, &mut out),
                    ("kmac128", true) => Kmac128::mac_xof(&key, &custom, &data, &mut out),
                    (_, false) => Kmac256::mac(&key, &custom, &data, &mut out),
                    (_, true) => Kmac256::mac_xof(&key, &custom, &data, &mut out),
                }
            }
            other => panic!("unknown function {other}"),
        }
        assert_eq!(
            hex(&out) == case["output"],
            expected,
            "{function} xof {xof}: NIST says {expected}"
        );
        *ran.entry((function.to_string(), xof, expected))
            .or_insert(0usize) += 1;
    }
    println!("{ran:?}");
    for function in ["tuplehash128", "tuplehash256"] {
        for xof in [false, true] {
            assert_eq!(ran[&(function.to_string(), xof, true)], 100, "{function}");
        }
    }
    let count = |prefix: &str, valid| -> usize {
        ran.iter()
            .filter(|((f, _, v), _)| f.starts_with(prefix) && *v == valid)
            .map(|(_, n)| *n)
            .sum()
    };
    assert_eq!(count("parallelhash", true), 13);
    // One KMAC value that is right, and two NIST says are wrong.
    assert_eq!(count("kmac", true), 1);
    assert_eq!(count("kmac", false), 2);
}
