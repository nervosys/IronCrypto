//! Shamir secret sharing against `testvectors/shamir-gf256.json`.
//!
//! The file comes from an implementation written from Shamir's construction
//! with its own field arithmetic; `scripts/gen_shamir_vectors.py` says how.
//! Each case is split here under the same fixed coefficient stream and must
//! give the reference's shares byte for byte, then recombine from several
//! subsets -- including the last shares, which index 255 reaches.

use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::cipher::shamir;
use ironcrypto::core_types::traits::RandomSource;

/// The generator's coefficient stream: `s = 29 * s + 7 mod 256`.
struct Stream(u8);

impl RandomSource for Stream {
    fn fill(&mut self, out: &mut [u8]) -> ironcrypto::core_types::Result<()> {
        for b in out.iter_mut() {
            self.0 = self.0.wrapping_mul(29).wrapping_add(7);
            *b = self.0;
        }
        Ok(())
    }
}

#[test]
fn shamir_agrees_with_the_reference() {
    let Some(file) = VectorFile::load_or_report("shamir-gf256") else {
        return;
    };
    let mut checked = 0;
    for case in &file.cases {
        let secret = hex_field(case, "secret");
        let k: u8 = case["threshold"].parse().unwrap();
        let n: u8 = case["share_count"].parse().unwrap();
        let seed = u8::from_str_radix(&case["rng_seed"], 16).unwrap();
        let want = hex_field(case, "shares");

        let mut shares = vec![0u8; secret.len() * n as usize];
        shamir::split(&secret, k, n, &mut Stream(seed), &mut shares).unwrap();
        assert_eq!(hex(&shares), hex(&want), "{k}-of-{n}");

        let len = secret.len();
        let share = |i: usize| ((i + 1) as u8, &shares[i * len..(i + 1) * len]);
        let n = n as usize;
        let k = k as usize;
        for picked in [
            (0..k).map(share).collect::<Vec<_>>(),
            (n - k..n).map(share).collect(),
            (0..n).step_by((n / k).max(1)).take(k).map(share).collect(),
        ] {
            let mut out = vec![0u8; len];
            shamir::combine(&picked, &mut out).unwrap();
            assert_eq!(out, secret, "{k}-of-{n}");
        }
        checked += 1;
    }
    assert_eq!(checked, 5);
}
