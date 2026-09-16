//! RFC 7693 BLAKE2b.
//!
//! **Not FIPS-approved.** BLAKE2b is here because Argon2 is defined in terms of
//! it: `ac_kdf::argon2` needs both the plain hash and the variable-length
//! `H'` construction built on top of it. It is a perfectly good general-purpose
//! hash — faster than SHA-512 on 64-bit hardware, and keyed without needing
//! HMAC — but the ontology marks it `not-approved`, so `ac-fips` blocks it in
//! approved mode.
//!
//! Unlike the SHA-2 and SHA-3 types, BLAKE2b has a *variable* output length
//! chosen at construction, which does not fit the fixed-size
//! [`Digest`][ac_core::traits::Digest] contract. It therefore exposes its own
//! API rather than pretending to be a fixed-width digest.

use ac_core::{ensure, Result, Zeroize};

/// Block size in bytes.
pub const BLOCK_LEN: usize = 128;

/// Largest digest this produces.
pub const MAX_OUTPUT_LEN: usize = 64;

/// Largest key accepted in keyed mode.
pub const MAX_KEY_LEN: usize = 64;

/// The BLAKE2b initialization vector, identical to SHA-512's.
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The message-word permutation, ten rows of sixteen.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The BLAKE2b mixing function.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// A BLAKE2b hasher with a caller-chosen output length.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buffered: usize,
    counter: u128,
    output_len: usize,
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        self.h.zeroize();
        self.buf.zeroize();
    }
}

impl Blake2b {
    /// Create a hasher producing `output_len` bytes, between 1 and 64.
    pub fn new(output_len: usize) -> Result<Self> {
        Self::with_key(output_len, &[])
    }

    /// Create a keyed hasher, the BLAKE2b equivalent of an HMAC.
    ///
    /// The key is absorbed as a zero-padded first block, exactly as RFC 7693
    /// specifies, so a keyed hash of an empty message is still one compression.
    pub fn with_key(output_len: usize, key: &[u8]) -> Result<Self> {
        ensure!(
            (1..=MAX_OUTPUT_LEN).contains(&output_len),
            InvalidLength,
            "blake2b output must be 1..=64 bytes"
        );
        ensure!(
            key.len() <= MAX_KEY_LEN,
            InvalidLength,
            "blake2b key must be at most 64 bytes"
        );

        let mut h = IV;
        // Parameter block word 0: digest length, key length, fanout, depth.
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ (output_len as u64);

        let mut state = Self {
            h,
            buf: [0u8; BLOCK_LEN],
            buffered: 0,
            counter: 0,
            output_len,
        };

        if !key.is_empty() {
            let mut block = [0u8; BLOCK_LEN];
            block[..key.len()].copy_from_slice(key);
            state.update(&block);
            block.zeroize();
        }
        Ok(state)
    }

    /// The compression function.
    fn compress(&mut self, block: &[u8; BLOCK_LEN], last: bool) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(b);
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.counter as u64;
        v[13] ^= (self.counter >> 64) as u64;
        if last {
            v[14] = !v[14];
        }

        for round in 0..12 {
            let s = &SIGMA[round % 10];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
        m.zeroize();
        v.zeroize();
    }

    /// Absorb more input.
    ///
    /// BLAKE2b marks the *last* block specially, so a full buffer is only
    /// compressed once more input is known to follow.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = core::cmp::min(BLOCK_LEN - self.buffered, data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < BLOCK_LEN || data.is_empty() {
                return;
            }
            let block = self.buf;
            self.counter = self.counter.wrapping_add(BLOCK_LEN as u128);
            self.compress(&block, false);
            self.buffered = 0;
        }

        while data.len() > BLOCK_LEN {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&data[..BLOCK_LEN]);
            self.counter = self.counter.wrapping_add(BLOCK_LEN as u128);
            self.compress(&block, false);
            data = &data[BLOCK_LEN..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        self.buffered = data.len();
    }

    /// Finish and write the digest into `out`, which must be `output_len` long.
    pub fn finalize_into(mut self, out: &mut [u8]) -> Result<()> {
        ensure!(
            out.len() == self.output_len,
            InvalidLength,
            "blake2b output buffer"
        );

        self.counter = self.counter.wrapping_add(self.buffered as u128);
        let mut block = [0u8; BLOCK_LEN];
        block[..self.buffered].copy_from_slice(&self.buf[..self.buffered]);
        self.compress(&block, true);
        block.zeroize();

        let mut full = [0u8; MAX_OUTPUT_LEN];
        for (i, word) in self.h.iter().enumerate() {
            full[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&full[..self.output_len]);
        full.zeroize();
        Ok(())
    }

    /// One-shot hash.
    pub fn hash(data: &[u8], out: &mut [u8]) -> Result<()> {
        let mut h = Self::new(out.len())?;
        h.update(data);
        h.finalize_into(out)
    }

    /// One-shot keyed hash.
    pub fn keyed_hash(key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()> {
        let mut h = Self::with_key(out.len(), key)?;
        h.update(data);
        h.finalize_into(out)
    }
}

/// The Argon2 variable-length hash `H'`.
///
/// For outputs up to 64 bytes this is just BLAKE2b with the length prefixed.
/// Beyond that, RFC 9106 chains 64-byte hashes and takes the first 32 bytes of
/// each, which is why Argon2 can fill a 1024-byte block from a 64-byte
/// primitive. Lives here because it is a property of BLAKE2b's use rather than
/// of Argon2's structure.
pub fn blake2b_long(input: &[&[u8]], out: &mut [u8]) -> Result<()> {
    ensure!(!out.is_empty(), InvalidLength, "blake2b_long output");
    let len_prefix = (out.len() as u32).to_le_bytes();

    if out.len() <= MAX_OUTPUT_LEN {
        let mut h = Blake2b::new(out.len())?;
        h.update(&len_prefix);
        for part in input {
            h.update(part);
        }
        return h.finalize_into(out);
    }

    // RFC 9106 §3.3, followed literally:
    //
    //   r      = ceil(T/32) - 2
    //   V_1    = H^64(LE32(T) || A)
    //   V_i    = H^64(V_{i-1})           for 2 <= i <= r
    //   V_{r+1} = H^(T - 32r)(V_r)
    //   output = A_1 || ... || A_r || V_{r+1},  A_i = first 32 bytes of V_i
    //
    // The final hash is taken from V_r, so the chain must *not* be advanced
    // after emitting the last 32-byte piece.
    let r = out.len().div_ceil(32) - 2;

    let mut v = [0u8; MAX_OUTPUT_LEN];
    let mut h = Blake2b::new(MAX_OUTPUT_LEN)?;
    h.update(&len_prefix);
    for part in input {
        h.update(part);
    }
    h.finalize_into(&mut v)?;

    for (i, piece) in out.chunks_exact_mut(32).take(r).enumerate() {
        piece.copy_from_slice(&v[..32]);
        if i + 1 < r {
            let previous = v;
            Blake2b::hash(&previous, &mut v)?;
        }
    }

    // `v` is now V_r; the tail is a single hash of it at the remaining length.
    let tail_len = out.len() - 32 * r;
    let mut tail = [0u8; MAX_OUTPUT_LEN];
    Blake2b::hash(&v, &mut tail[..tail_len])?;
    out[32 * r..].copy_from_slice(&tail[..tail_len]);

    v.zeroize();
    tail.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::hex;

    /// RFC 7693 Appendix A: BLAKE2b-512 of "abc".
    #[test]
    fn rfc7693_abc_vector() {
        let mut out = [0u8; 64];
        Blake2b::hash(b"abc", &mut out).unwrap();
        assert_eq!(
            hex(&out),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
                .replace(char::is_whitespace, "")
        );
    }

    /// The empty message, the other widely published BLAKE2b-512 value.
    #[test]
    fn empty_message_vector() {
        let mut out = [0u8; 64];
        Blake2b::hash(b"", &mut out).unwrap();
        assert_eq!(
            hex(&out),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn output_length_changes_the_digest() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 64];
        Blake2b::hash(b"same input", &mut a).unwrap();
        Blake2b::hash(b"same input", &mut b).unwrap();
        // The length is bound into the parameter block, so the short digest is
        // not a prefix of the long one.
        assert_ne!(&b[..32], &a[..]);
    }

    #[test]
    fn keying_changes_the_digest() {
        let mut unkeyed = [0u8; 32];
        let mut keyed = [0u8; 32];
        Blake2b::hash(b"message", &mut unkeyed).unwrap();
        Blake2b::keyed_hash(b"key", b"message", &mut keyed).unwrap();
        assert_ne!(unkeyed, keyed);

        let mut other = [0u8; 32];
        Blake2b::keyed_hash(b"kez", b"message", &mut other).unwrap();
        assert_ne!(keyed, other);
    }

    /// Streaming must match one-shot at every block boundary — BLAKE2b flags
    /// the final block, so an off-by-one in the buffering changes the result.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..400u32).map(|i| (i * 7) as u8).collect();
        let mut expected = [0u8; 64];
        Blake2b::hash(&data, &mut expected).unwrap();

        for split in [0usize, 1, 127, 128, 129, 200, 255, 256, 257, 400] {
            let mut h = Blake2b::new(64).unwrap();
            h.update(&data[..split]);
            h.update(&data[split..]);
            let mut got = [0u8; 64];
            h.finalize_into(&mut got).unwrap();
            assert_eq!(got, expected, "split at {split}");
        }
    }

    /// An input of exactly one block must not be compressed as a non-final
    /// block; this is the classic BLAKE2 implementation bug.
    #[test]
    fn exactly_one_block_is_handled() {
        let data = [0x61u8; BLOCK_LEN];
        let mut a = [0u8; 64];
        Blake2b::hash(&data, &mut a).unwrap();

        let mut h = Blake2b::new(64).unwrap();
        for byte in data.iter() {
            h.update(&[*byte]);
        }
        let mut b = [0u8; 64];
        h.finalize_into(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert!(Blake2b::new(0).is_err());
        assert!(Blake2b::new(65).is_err());
        assert!(Blake2b::with_key(32, &[0u8; 65]).is_err());
        let h = Blake2b::new(32).unwrap();
        assert!(h.finalize_into(&mut [0u8; 31]).is_err());
    }

    /// `blake2b_long` must agree with plain BLAKE2b for short outputs, and
    /// produce distinct, deterministic output beyond 64 bytes.
    #[test]
    fn long_hash_matches_short_path_and_extends() {
        for len in [1usize, 32, 64] {
            let mut via_long = vec![0u8; len];
            blake2b_long(&[b"input"], &mut via_long).unwrap();

            let mut direct = vec![0u8; len];
            let mut h = Blake2b::new(len).unwrap();
            h.update(&(len as u32).to_le_bytes());
            h.update(b"input");
            h.finalize_into(&mut direct).unwrap();

            assert_eq!(via_long, direct, "len {len}");
        }

        let mut a = [0u8; 1024];
        let mut b = [0u8; 1024];
        blake2b_long(&[b"input"], &mut a).unwrap();
        blake2b_long(&[b"input"], &mut b).unwrap();
        assert_eq!(a, b, "must be deterministic");
        assert_ne!(&a[..64], &a[64..128], "must not repeat");

        // The output length is bound in, so a short request is not a prefix.
        let mut short = [0u8; 128];
        blake2b_long(&[b"input"], &mut short).unwrap();
        assert_ne!(&a[..128], &short[..]);
    }

    #[test]
    fn long_hash_concatenates_its_inputs() {
        let mut joined = [0u8; 100];
        let mut split = [0u8; 100];
        blake2b_long(&[b"abcdef"], &mut joined).unwrap();
        blake2b_long(&[b"abc", b"def"], &mut split).unwrap();
        assert_eq!(joined, split);
    }
}
