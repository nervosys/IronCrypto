//! BLAKE2s and BLAKE3 against the vectors their authors publish.
//!
//! `testvectors/blake2s-kat.json`: the BLAKE2 team's keyed BLAKE2s-256 KAT,
//! inputs of 0 to 255 bytes, which crosses the 64-byte block boundary four
//! times. RFC 7693's unkeyed vector and its self-test, which varies the
//! output and key lengths, are unit tests in `ic_hash::blake2`.
//!
//! `testvectors/blake3.json`: the BLAKE3 team's vectors, 35 input lengths up
//! to 100 KiB -- every block, chunk and subtree boundary -- in all three
//! modes, each to 131 bytes of extended output. Inputs are the repeating
//! sequence 0, 1, ..., 250. Each is also checked fed one way in pieces and
//! read back in pieces, since the tree and the reader both buffer.

// Every algorithm here is one approved mode does not permit.
#![cfg(not(ic_approved_only))]

use ic_vectors::{hex_field, VectorFile};
use ironcrypto::hash::{Blake2s, Blake3};

#[test]
fn blake2s_matches_the_blake2_kat() {
    let Some(file) = VectorFile::load_or_report("blake2s-kat") else {
        return;
    };
    for case in &file.cases {
        let (input, key, want) = (
            hex_field(case, "in"),
            hex_field(case, "key"),
            hex_field(case, "hash"),
        );
        let mut got = [0u8; 32];
        Blake2s::keyed_hash(&key, &input, &mut got).unwrap();
        assert_eq!(got.as_slice(), want.as_slice(), "{} bytes", input.len());

        let mut h = Blake2s::with_key(32, &key).unwrap();
        for piece in input.chunks(7) {
            h.update(piece);
        }
        let mut streamed = [0u8; 32];
        h.finalize_into(&mut streamed).unwrap();
        assert_eq!(streamed, got);
    }
    assert_eq!(file.cases.len(), 256);
}

fn input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Feed `data` in uneven pieces and read `len` bytes back in uneven pieces.
fn streamed(mut h: Blake3, data: &[u8], len: usize) -> Vec<u8> {
    for piece in data.chunks(1000) {
        h.update(piece);
    }
    let mut out = vec![0u8; len];
    let mut reader = h.finalize_xof();
    for piece in out.chunks_mut(23) {
        reader.fill(piece).unwrap();
    }
    out
}

#[test]
fn blake3_matches_the_blake3_vectors() {
    let Some(file) = VectorFile::load_or_report("blake3") else {
        return;
    };
    for case in &file.cases {
        let len: usize = case["input_len"].parse().unwrap();
        let data = input(len);
        let key: [u8; 32] = hex_field(case, "key").try_into().unwrap();
        let context = String::from_utf8(hex_field(case, "context_string")).unwrap();

        let want = hex_field(case, "hash");
        let mut h = Blake3::new();
        h.update(&data);
        let mut got = vec![0u8; want.len()];
        h.finalize_xof().fill(&mut got).unwrap();
        assert_eq!(got, want, "hash, {len} bytes");
        assert_eq!(
            Blake3::hash(&data).unwrap(),
            want[..32],
            "hash, {len} bytes"
        );
        assert_eq!(streamed(Blake3::new(), &data, want.len()), want);

        let want = hex_field(case, "keyed_hash");
        let mut got = vec![0u8; want.len()];
        let mut h = Blake3::new_keyed(&key);
        h.update(&data);
        h.finalize_xof().fill(&mut got).unwrap();
        assert_eq!(got, want, "keyed_hash, {len} bytes");
        assert_eq!(Blake3::keyed_hash(&key, &data).unwrap(), want[..32]);
        assert_eq!(streamed(Blake3::new_keyed(&key), &data, want.len()), want);

        let want = hex_field(case, "derive_key");
        let mut got = vec![0u8; want.len()];
        Blake3::derive_key(&context, &data, &mut got).unwrap();
        assert_eq!(got, want, "derive_key, {len} bytes");
        assert_eq!(
            streamed(Blake3::new_derive_key(&context), &data, want.len()),
            want
        );
    }
    assert_eq!(file.cases.len(), 35);
}
