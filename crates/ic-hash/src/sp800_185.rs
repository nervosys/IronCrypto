//! SP 800-185: the string encodings, and cSHAKE.
//!
//! Everything in SP 800-185 — cSHAKE, KMAC, TupleHash, ParallelHash — is built
//! out of three encoding functions and a padding rule. They are unglamorous and
//! easy to get subtly wrong, and a mistake in them does not look like a
//! mistake: the output is still a well-distributed hash, just not the one every
//! other implementation computes.
//!
//! ```text
//! left_encode(x)    = n || x as n big-endian bytes      -- length first
//! right_encode(x)   = x as n big-endian bytes || n      -- length last
//! encode_string(S)  = left_encode(len(S) in bits) || S
//! bytepad(X, w)     = left_encode(w) || X || zeros, to a multiple of w
//! ```
//!
//! Note that `encode_string` counts **bits**, while `bytepad` pads to a
//! multiple of **bytes**. Mixing those up is the classic error here, and it
//! produces output that is wrong by a factor of eight in one field.
//!
//! # Why cSHAKE lives here and not beside SHAKE
//!
//! cSHAKE is SHAKE with a different domain separator and a prefix. SP 800-185
//! section 3.3 defines it so that with no customization at all it is *exactly*
//! SHAKE:
//!
//! ```text
//! cSHAKE128(X, L, "", "") == SHAKE128(X, L)
//! ```
//!
//! That identity is a free oracle against an already-validated implementation,
//! and [`tests::empty_customization_is_plain_shake`] checks it. It does not
//! cover the customized path, which uses domain separator `0x04` where SHAKE
//! uses `0x1f`; that path is checked against an independent Keccak written from
//! FIPS 202 in the tests below.

use crate::sha3::Sponge;
use ic_core::traits::Algorithm;

/// The largest `left_encode`/`right_encode` output: eight value bytes plus the
/// length byte.
pub const MAX_ENCODE: usize = 9;

/// `left_encode(x)` from SP 800-185 section 2.3.1, written into `buf`.
///
/// Returns the number of bytes used.
pub fn left_encode(x: u64, buf: &mut [u8; MAX_ENCODE]) -> usize {
    let n = value_bytes(x);
    buf[0] = n as u8;
    for i in 0..n {
        buf[1 + i] = (x >> (8 * (n - 1 - i))) as u8;
    }
    n + 1
}

/// `right_encode(x)` from SP 800-185 section 2.3.1, written into `buf`.
pub fn right_encode(x: u64, buf: &mut [u8; MAX_ENCODE]) -> usize {
    let n = value_bytes(x);
    for (i, slot) in buf.iter_mut().take(n).enumerate() {
        *slot = (x >> (8 * (n - 1 - i))) as u8;
    }
    buf[n] = n as u8;
    n + 1
}

/// How many bytes the value needs. Zero takes one, not zero: the encodings have
/// no empty case.
fn value_bytes(x: u64) -> usize {
    if x == 0 {
        1
    } else {
        8 - (x.leading_zeros() / 8) as usize
    }
}

/// Absorbs a byte string into a sponge while counting what it fed in, so that
/// `bytepad` knows how much padding to add without a scratch buffer.
///
/// SP 800-185's `bytepad` is defined on a fully assembled string. Assembling it
/// would mean allocating, or a buffer large enough for the longest key anyone
/// might use. Streaming it and tracking the length gives the same bytes.
pub(crate) struct CountingAbsorb<'a> {
    sponge: &'a mut Sponge,
    written: usize,
}

impl<'a> CountingAbsorb<'a> {
    pub(crate) fn new(sponge: &'a mut Sponge) -> Self {
        Self { sponge, written: 0 }
    }

    pub(crate) fn feed(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
        self.written += data.len();
    }

    /// `encode_string(S)`: the bit length, then the bytes.
    pub(crate) fn feed_encoded_string(&mut self, s: &[u8]) {
        let mut buf = [0u8; MAX_ENCODE];
        // Bits, not bytes. The multiplication cannot overflow for any string
        // that fits in memory on a 64-bit target, and on a 32-bit one the
        // length is far smaller still.
        let n = left_encode((s.len() as u64) * 8, &mut buf);
        self.feed(&buf[..n]);
        self.feed(s);
    }

    /// Pad with zeros up to a multiple of `w` bytes, completing `bytepad`.
    pub(crate) fn finish_bytepad(self, w: usize) {
        let remainder = self.written % w;
        if remainder != 0 {
            let zeros = [0u8; 168];
            let mut left = w - remainder;
            while left > 0 {
                let chunk = core::cmp::min(left, zeros.len());
                self.sponge.absorb(&zeros[..chunk]);
                left -= chunk;
            }
        }
    }
}

/// Build a cSHAKE type over one SHAKE parameter set.
macro_rules! cshake {
    ($name:ident, $id:literal, $disp:literal, $rate:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            sponge: Sponge,
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl $name {
            /// The sponge rate in bytes, which is also `bytepad`'s width here.
            pub const RATE: usize = $rate;

            /// Start a cSHAKE with a function name `n` and customization `s`.
            ///
            /// `n` is reserved for NIST-defined functions — KMAC passes
            /// `"KMAC"`. Application customization belongs in `s`.
            ///
            /// With both empty this is plain SHAKE, per SP 800-185 section 3.3,
            /// including the domain separator.
            pub fn new(n: &[u8], s: &[u8]) -> Self {
                if n.is_empty() && s.is_empty() {
                    return Self {
                        sponge: Sponge::new($rate, 0x1f),
                    };
                }
                // The customized form uses the `00` domain bits, which become
                // 0x04 once the pad10*1 rule adds its leading one.
                let mut sponge = Sponge::new($rate, 0x04);
                let mut prefix = CountingAbsorb::new(&mut sponge);
                let mut buf = [0u8; MAX_ENCODE];
                let used = left_encode($rate as u64, &mut buf);
                prefix.feed(&buf[..used]);
                prefix.feed_encoded_string(n);
                prefix.feed_encoded_string(s);
                prefix.finish_bytepad($rate);
                Self { sponge }
            }

            /// Absorb more input.
            pub fn update(&mut self, data: &[u8]) {
                self.sponge.absorb(data);
            }

            /// Squeeze `out.len()` bytes.
            pub fn finalize_xof(mut self, out: &mut [u8]) {
                self.sponge.finish();
                self.sponge.squeeze(out);
            }

            /// One-shot.
            pub fn xof(n: &[u8], s: &[u8], data: &[u8], out: &mut [u8]) {
                let mut x = Self::new(n, s);
                x.update(data);
                x.finalize_xof(out);
            }

            /// Absorb `bytepad(encode_string(s), RATE)`.
            ///
            /// KMAC prefixes its message with the key encoded exactly this way.
            /// It is exposed here rather than rebuilt in `ic-mac` because the
            /// padding width is the sponge rate, which is cSHAKE's property and
            /// not the caller's to know.
            pub fn absorb_bytepadded_string(&mut self, s: &[u8]) {
                let mut pad = CountingAbsorb::new(&mut self.sponge);
                let mut buf = [0u8; MAX_ENCODE];
                let used = left_encode($rate as u64, &mut buf);
                pad.feed(&buf[..used]);
                pad.feed_encoded_string(s);
                pad.finish_bytepad($rate);
            }
        }
    };
}

/// Known-answer test for a cSHAKE, built on the SP 800-185 section 3.3
/// identity rather than on a pinned value.
macro_rules! cshake_self_test {
    ($name:ident, $shake:ty, $id:literal) => {
        impl ic_core::traits::SelfTest for $name {
            /// Two checks, neither of which needs a vector this code produced.
            ///
            /// With no customization cSHAKE must equal SHAKE exactly, and SHAKE
            /// has its own CAST against a published FIPS 202 answer — so this
            /// inherits that evidence. Then customization must change the
            /// output, which catches a build where the prefix was silently
            /// dropped and every customized call collapsed onto plain SHAKE.
            fn self_test() -> ic_core::Result<()> {
                let mut plain = [0u8; 32];
                let mut shake = [0u8; 32];
                Self::xof(b"", b"", b"abc", &mut plain);
                <$shake>::xof(b"abc", &mut shake);
                ic_core::ensure!(ic_core::ct::verify(&plain, &shake), SelfTestFailed, $id);

                let mut customized = [0u8; 32];
                Self::xof(b"", b"self-test", b"abc", &mut customized);
                ic_core::ensure!(
                    !ic_core::ct::verify(&plain, &customized),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

cshake!(
    CShake128,
    "cshake128",
    "cSHAKE128",
    168,
    "SP 800-185 cSHAKE128: SHAKE128 with a customization string."
);
cshake!(
    CShake256,
    "cshake256",
    "cSHAKE256",
    136,
    "SP 800-185 cSHAKE256: SHAKE256 with a customization string."
);

cshake_self_test!(CShake128, crate::Shake128, "cshake128");
cshake_self_test!(CShake256, crate::Shake256, "cshake256");

// ---------------------------------------------------------------------------
// TupleHash
// ---------------------------------------------------------------------------

/// Declare a TupleHash over one cSHAKE parameter set.
macro_rules! tuple_hash {
    ($name:ident, $cshake:ty, $id:literal, $disp:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            inner: $cshake,
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl $name {
            /// Start a TupleHash with a customization string.
            pub fn new(custom: &[u8]) -> Self {
                Self {
                    inner: <$cshake>::new(b"TupleHash", custom),
                }
            }

            /// Add one element of the tuple.
            ///
            /// Each element is length-prefixed, which is the entire point: see
            /// the type documentation.
            pub fn update(&mut self, element: &[u8]) {
                let mut buf = [0u8; MAX_ENCODE];
                let used = left_encode((element.len() as u64) * 8, &mut buf);
                self.inner.update(&buf[..used]);
                self.inner.update(element);
            }

            /// Finish with a fixed-length output, binding the length in.
            pub fn finalize(mut self, out: &mut [u8]) {
                let mut buf = [0u8; MAX_ENCODE];
                let used = right_encode((out.len() as u64) * 8, &mut buf);
                self.inner.update(&buf[..used]);
                self.inner.finalize_xof(out);
            }

            /// Finish in XOF mode, where the output is a stream.
            pub fn finalize_xof(mut self, out: &mut [u8]) {
                let mut buf = [0u8; MAX_ENCODE];
                let used = right_encode(0, &mut buf);
                self.inner.update(&buf[..used]);
                self.inner.finalize_xof(out);
            }

            /// One-shot over a slice of elements.
            pub fn hash(custom: &[u8], elements: &[&[u8]], out: &mut [u8]) {
                let mut t = Self::new(custom);
                for element in elements {
                    t.update(element);
                }
                t.finalize(out);
            }

            /// One-shot in XOF mode.
            pub fn hash_xof(custom: &[u8], elements: &[&[u8]], out: &mut [u8]) {
                let mut t = Self::new(custom);
                for element in elements {
                    t.update(element);
                }
                t.finalize_xof(out);
            }
        }

        impl ic_core::traits::SelfTest for $name {
            /// The property TupleHash exists for: two different tuples that
            /// concatenate to the same bytes must hash differently.
            fn self_test() -> ic_core::Result<()> {
                let mut a = [0u8; 32];
                let mut b = [0u8; 32];
                Self::hash(b"self-test", &[b"abc", b"d"], &mut a);
                Self::hash(b"self-test", &[b"ab", b"cd"], &mut b);
                ic_core::ensure!(!ic_core::ct::verify(&a, &b), SelfTestFailed, $id);

                // And it is deterministic.
                let mut again = [0u8; 32];
                Self::hash(b"self-test", &[b"abc", b"d"], &mut again);
                ic_core::ensure!(ic_core::ct::verify(&a, &again), SelfTestFailed, $id);
                Ok(())
            }
        }
    };
}

tuple_hash!(
    TupleHash128,
    CShake128,
    "tuplehash128",
    "TupleHash128",
    "SP 800-185 TupleHash128: hashes a *sequence* of strings unambiguously.\n\
     \n\
     Hashing `a || b` cannot distinguish `(\"abc\", \"d\")` from `(\"ab\", \"cd\")`,\n\
     and a protocol that concatenates fields before hashing them has a\n\
     forgery waiting in it. TupleHash length-prefixes every element, so\n\
     distinct tuples always hash distinctly."
);
tuple_hash!(
    TupleHash256,
    CShake256,
    "tuplehash256",
    "TupleHash256",
    "SP 800-185 TupleHash256, at the 256-bit security level."
);

// ---------------------------------------------------------------------------
// ParallelHash
// ---------------------------------------------------------------------------

/// Declare a ParallelHash over one cSHAKE parameter set.
///
/// `$chain` is the inner digest width in bytes: 32 for the 128-bit parameter
/// set, 64 for the 256-bit one, per SP 800-185 section 6.2.
macro_rules! parallel_hash {
    ($name:ident, $cshake:ty, $chain:literal, $id:literal, $disp:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl $name {
            /// Width of each block's inner digest, in bytes.
            pub const CHAINING_LEN: usize = $chain;

            /// Hash `data` in blocks of `block_size` bytes.
            ///
            /// `block_size` must be at least one. SP 800-185 places no upper
            /// bound on it, and neither does this.
            pub fn hash(custom: &[u8], block_size: usize, data: &[u8], out: &mut [u8]) {
                Self::run(custom, block_size, data, out, false)
            }

            /// As [`Self::hash`], in XOF mode.
            pub fn hash_xof(custom: &[u8], block_size: usize, data: &[u8], out: &mut [u8]) {
                Self::run(custom, block_size, data, out, true)
            }

            fn run(custom: &[u8], block_size: usize, data: &[u8], out: &mut [u8], xof: bool) {
                assert!(block_size > 0, "parallelhash block size must be positive");
                let mut outer = <$cshake>::new(b"ParallelHash", custom);
                let mut buf = [0u8; MAX_ENCODE];

                let used = left_encode(block_size as u64, &mut buf);
                outer.update(&buf[..used]);

                let mut blocks = 0u64;
                for block in data.chunks(block_size) {
                    // Each block's digest is plain SHAKE at the chaining width,
                    // which is what cSHAKE with no customization gives.
                    let mut chain = [0u8; $chain];
                    <$cshake>::xof(b"", b"", block, &mut chain);
                    outer.update(&chain);
                    blocks += 1;
                }

                let used = right_encode(blocks, &mut buf);
                outer.update(&buf[..used]);
                let used = right_encode(if xof { 0 } else { (out.len() as u64) * 8 }, &mut buf);
                outer.update(&buf[..used]);
                outer.finalize_xof(out);
            }
        }

        impl ic_core::traits::SelfTest for $name {
            /// The block size is bound into the result, and the whole thing is
            /// deterministic. A build that dropped `left_encode(B)` would give
            /// the same answer for every block size, which is what this catches.
            fn self_test() -> ic_core::Result<()> {
                let data = [0x5au8; 200];
                let mut a = [0u8; 32];
                let mut b = [0u8; 32];
                Self::hash(b"self-test", 16, &data, &mut a);
                Self::hash(b"self-test", 32, &data, &mut b);
                ic_core::ensure!(!ic_core::ct::verify(&a, &b), SelfTestFailed, $id);

                let mut again = [0u8; 32];
                Self::hash(b"self-test", 16, &data, &mut again);
                ic_core::ensure!(ic_core::ct::verify(&a, &again), SelfTestFailed, $id);
                Ok(())
            }
        }
    };
}

parallel_hash!(
    ParallelHash128,
    CShake128,
    32,
    "parallelhash128",
    "ParallelHash128",
    "SP 800-185 ParallelHash128: hashes fixed-size blocks independently, then\n\
     hashes their digests.\n\
     \n\
     The structure is designed so the per-block work can be spread across\n\
     cores. This implementation does them in order — the workspace has no\n\
     threading and `no_std` targets have no threads to spread onto — so what\n\
     it buys here is interoperability with implementations that do, not\n\
     speed. The output is identical either way."
);
parallel_hash!(
    ParallelHash256,
    CShake256,
    64,
    "parallelhash256",
    "ParallelHash256",
    "SP 800-185 ParallelHash256, at the 256-bit security level."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sha3_256, Shake128, Shake256};
    use ic_core::codec::hex;
    use ic_core::traits::Digest;

    // -- the encodings ----------------------------------------------------

    /// Straight from SP 800-185 section 2.3.1, independent of the
    /// implementation above.
    fn reference_left_encode(x: u64) -> Vec<u8> {
        let mut bytes = x.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let mut out = vec![bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }

    fn reference_right_encode(x: u64) -> Vec<u8> {
        let mut bytes = x.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let n = bytes.len() as u8;
        bytes.push(n);
        bytes
    }

    #[test]
    fn the_encodings_match_an_independent_construction() {
        for x in [
            0u64,
            1,
            2,
            127,
            128,
            255,
            256,
            65535,
            65536,
            1 << 24,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = [0u8; MAX_ENCODE];
            let n = left_encode(x, &mut buf);
            assert_eq!(&buf[..n], &reference_left_encode(x)[..], "left_encode({x})");

            let n = right_encode(x, &mut buf);
            assert_eq!(
                &buf[..n],
                &reference_right_encode(x)[..],
                "right_encode({x})"
            );
        }
    }

    /// The published examples in SP 800-185 section 2.3.1.
    #[test]
    fn the_encodings_match_the_published_examples() {
        let mut buf = [0u8; MAX_ENCODE];
        let n = left_encode(0, &mut buf);
        assert_eq!(&buf[..n], &[0x01, 0x00]);
        let n = right_encode(0, &mut buf);
        assert_eq!(&buf[..n], &[0x00, 0x01]);
        // 1 encodes as one value byte either way, with the count on the other
        // end; this is the pair that makes the difference between the two
        // functions visible.
        let n = left_encode(1, &mut buf);
        assert_eq!(&buf[..n], &[0x01, 0x01]);
        let n = right_encode(1, &mut buf);
        assert_eq!(&buf[..n], &[0x01, 0x01]);
        let n = left_encode(256, &mut buf);
        assert_eq!(&buf[..n], &[0x02, 0x01, 0x00]);
        let n = right_encode(256, &mut buf);
        assert_eq!(&buf[..n], &[0x01, 0x00, 0x02]);
    }

    // -- an independent Keccak -------------------------------------------

    /// Keccak-f[1600] written the slow, obvious way from FIPS 202 section 3.2:
    /// a 5x5 lane array, each step separate, no flattening and no precomputed
    /// permutation tables.
    ///
    /// This exists to check cSHAKE's customized path, which uses a domain
    /// separator the SHAKE vectors never exercise. Its own correctness is
    /// established by [`the_reference_keccak_reproduces_sha3`], which runs it
    /// against the published FIPS 202 SHA3-256 answer — so the chain is
    /// published vector -> this reference -> cSHAKE.
    ///
    /// The index-based loops are the point: FIPS 202 is written in terms of
    /// `A[x, y]`, and matching that notation is what makes this checkable
    /// against the document. Iterator form would be tidier and less useful.
    #[allow(clippy::needless_range_loop)]
    fn reference_keccak(lanes: &mut [[u64; 5]; 5]) {
        const RC: [u64; 24] = [
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808a,
            0x8000000080008000,
            0x000000000000808b,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008a,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000a,
            0x000000008000808b,
            0x800000000000008b,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800a,
            0x800000008000000a,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        ];
        // Rotation offsets, indexed [x][y], from FIPS 202 Table 2.
        const R: [[u32; 5]; 5] = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14],
        ];

        for rc in RC {
            // theta
            let mut c = [0u64; 5];
            for (x, cx) in c.iter_mut().enumerate() {
                *cx = lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for x in 0..5 {
                for y in 0..5 {
                    lanes[x][y] ^= d[x];
                }
            }

            // rho and pi
            let mut b = [[0u64; 5]; 5];
            for x in 0..5 {
                for y in 0..5 {
                    b[y][(2 * x + 3 * y) % 5] = lanes[x][y].rotate_left(R[x][y]);
                }
            }

            // chi
            for x in 0..5 {
                for y in 0..5 {
                    lanes[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
                }
            }

            // iota
            lanes[0][0] ^= rc;
        }
    }

    /// A sponge over the reference permutation, again written plainly.
    fn reference_sponge(rate: usize, pad: u8, input: &[u8], out: &mut [u8]) {
        let mut lanes = [[0u64; 5]; 5];
        let put = |lanes: &mut [[u64; 5]; 5], i: usize, byte: u8| {
            let lane = i / 8;
            lanes[lane % 5][lane / 5] ^= (byte as u64) << (8 * (i % 8));
        };
        let get = |lanes: &[[u64; 5]; 5], i: usize| -> u8 {
            let lane = i / 8;
            (lanes[lane % 5][lane / 5] >> (8 * (i % 8))) as u8
        };

        // Absorb, padding the final block with pad10*1.
        let mut padded = input.to_vec();
        padded.push(pad);
        while padded.len() % rate != 0 {
            padded.push(0);
        }
        let last = padded.len() - 1;
        padded[last] |= 0x80;

        for block in padded.chunks(rate) {
            for (i, byte) in block.iter().enumerate() {
                put(&mut lanes, i, *byte);
            }
            reference_keccak(&mut lanes);
        }

        // Squeeze.
        let mut produced = 0;
        while produced < out.len() {
            let take = core::cmp::min(rate, out.len() - produced);
            for i in 0..take {
                out[produced + i] = get(&lanes, i);
            }
            produced += take;
            if produced < out.len() {
                reference_keccak(&mut lanes);
            }
        }
    }

    /// Anchors the reference implementation to a published value before
    /// anything is checked against it. FIPS 202's SHA3-256("abc").
    #[test]
    fn the_reference_keccak_reproduces_sha3() {
        let mut got = [0u8; 32];
        // SHA-3 uses rate 136 for 256-bit output, and domain bits 01.
        reference_sponge(136, 0x06, b"abc", &mut got);
        assert_eq!(
            hex(&got),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        // And it agrees with the shipped implementation on the same input.
        assert_eq!(hex(Sha3_256::digest(b"abc").as_ref()), hex(&got));
    }

    // -- cSHAKE ------------------------------------------------------------

    /// SP 800-185 section 3.3: with no customization, cSHAKE *is* SHAKE.
    #[test]
    fn empty_customization_is_plain_shake() {
        for len in [1usize, 16, 32, 168, 169, 512] {
            let mut a = vec![0u8; len];
            let mut b = vec![0u8; len];
            CShake128::xof(b"", b"", b"the quick brown fox", &mut a);
            Shake128::xof(b"the quick brown fox", &mut b);
            assert_eq!(a, b, "cSHAKE128 with no customization, {len} bytes");

            CShake256::xof(b"", b"", b"the quick brown fox", &mut a);
            Shake256::xof(b"the quick brown fox", &mut b);
            assert_eq!(a, b, "cSHAKE256 with no customization, {len} bytes");
        }
    }

    /// The customized path, against the independent Keccak. This is the check
    /// the SHAKE identity above cannot make, because customization switches the
    /// domain separator from 0x1f to 0x04.
    #[test]
    fn the_customized_path_matches_the_reference_keccak() {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (b"", b"Email Signature", b"\x00\x01\x02\x03"),
            (b"KMAC", b"", b"hello"),
            (b"KMAC", b"My Tagged Application", b""),
            (b"N", b"S", &[0x5a; 200]),
        ];

        for (n, s, data) in cases {
            for (rate, is_128) in [(168usize, true), (136, false)] {
                // Assemble bytepad(encode_string(N) || encode_string(S), rate)
                // by hand, then the message, then run the reference sponge.
                let mut prefix = reference_left_encode(rate as u64);
                prefix.extend_from_slice(&reference_left_encode((n.len() as u64) * 8));
                prefix.extend_from_slice(n);
                prefix.extend_from_slice(&reference_left_encode((s.len() as u64) * 8));
                prefix.extend_from_slice(s);
                while prefix.len() % rate != 0 {
                    prefix.push(0);
                }
                prefix.extend_from_slice(data);

                let mut want = [0u8; 64];
                reference_sponge(rate, 0x04, &prefix, &mut want);

                let mut got = [0u8; 64];
                if is_128 {
                    CShake128::xof(n, s, data, &mut got);
                } else {
                    CShake256::xof(n, s, data, &mut got);
                }
                assert_eq!(
                    hex(&got),
                    hex(&want),
                    "cSHAKE rate {rate}, N={n:?}, S={s:?}"
                );
            }
        }
    }

    /// Different customization must give different output, or the parameter is
    /// not doing anything.
    #[test]
    fn customization_changes_the_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        CShake128::xof(b"", b"one", b"message", &mut a);
        CShake128::xof(b"", b"two", b"message", &mut b);
        CShake128::xof(b"", b"", b"message", &mut c);
        assert_ne!(a, b, "S is bound into the output");
        assert_ne!(a, c, "and distinguishes customized from plain");
    }

    #[test]
    fn streaming_matches_the_one_shot() {
        let data = [0x37u8; 500];
        let mut one = [0u8; 64];
        CShake128::xof(b"KMAC", b"S", &data, &mut one);

        let mut x = CShake128::new(b"KMAC", b"S");
        for chunk in data.chunks(7) {
            x.update(chunk);
        }
        let mut streamed = [0u8; 64];
        x.finalize_xof(&mut streamed);
        assert_eq!(one, streamed);
    }
}

#[cfg(test)]
mod tuple_parallel_tests {
    use super::*;
    use ic_core::traits::SelfTest;

    fn enc(x: u64) -> Vec<u8> {
        let mut bytes = x.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let mut v = vec![bytes.len() as u8];
        v.extend_from_slice(&bytes);
        v
    }

    fn renc(x: u64) -> Vec<u8> {
        let mut bytes = x.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let n = bytes.len() as u8;
        bytes.push(n);
        bytes
    }

    /// SP 800-185 section 5.1, assembled literally over cSHAKE.
    ///
    /// cSHAKE is trusted because its own tests check it against a Keccak
    /// written from FIPS 202 and anchored to a published SHA-3 vector, so this
    /// checks the layer TupleHash adds: the per-element length prefixes and the
    /// trailing output length.
    fn reference_tuple_hash(
        wide: bool,
        custom: &[u8],
        elements: &[&[u8]],
        out: &mut [u8],
        xof: bool,
    ) {
        let mut z = Vec::new();
        for e in elements {
            z.extend_from_slice(&enc((e.len() as u64) * 8));
            z.extend_from_slice(e);
        }
        z.extend_from_slice(&renc(if xof { 0 } else { (out.len() as u64) * 8 }));
        if wide {
            CShake256::xof(b"TupleHash", custom, &z, out);
        } else {
            CShake128::xof(b"TupleHash", custom, &z, out);
        }
    }

    /// SP 800-185 section 6.2, likewise.
    fn reference_parallel_hash(
        wide: bool,
        custom: &[u8],
        block_size: usize,
        data: &[u8],
        out: &mut [u8],
        xof: bool,
    ) {
        let chain_len = if wide { 64 } else { 32 };
        let mut z = enc(block_size as u64);
        let mut n = 0u64;
        for block in data.chunks(block_size) {
            let mut chain = vec![0u8; chain_len];
            if wide {
                CShake256::xof(b"", b"", block, &mut chain);
            } else {
                CShake128::xof(b"", b"", block, &mut chain);
            }
            z.extend_from_slice(&chain);
            n += 1;
        }
        z.extend_from_slice(&renc(n));
        z.extend_from_slice(&renc(if xof { 0 } else { (out.len() as u64) * 8 }));
        if wide {
            CShake256::xof(b"ParallelHash", custom, &z, out);
        } else {
            CShake128::xof(b"ParallelHash", custom, &z, out);
        }
    }

    #[test]
    fn tuple_hash_matches_an_independent_construction() {
        let cases: &[(&[u8], &[&[u8]])] = &[
            (b"", &[]),
            (b"", &[b"abc"]),
            (b"My Tupled App", &[b"abc", b"d"]),
            (b"", &[b"", b"", b""]),
            (b"S", &[&[0x5au8; 300][..], b"x", &[0u8; 168][..]]),
        ];

        for (custom, elements) in cases {
            for len in [16usize, 32, 64] {
                let mut want = vec![0u8; len];
                let mut got = vec![0u8; len];

                reference_tuple_hash(false, custom, elements, &mut want, false);
                TupleHash128::hash(custom, elements, &mut got);
                assert_eq!(got, want, "TupleHash128 fixed, {len} bytes");

                reference_tuple_hash(true, custom, elements, &mut want, false);
                TupleHash256::hash(custom, elements, &mut got);
                assert_eq!(got, want, "TupleHash256 fixed, {len} bytes");

                reference_tuple_hash(false, custom, elements, &mut want, true);
                TupleHash128::hash_xof(custom, elements, &mut got);
                assert_eq!(got, want, "TupleHash128 xof, {len} bytes");
            }
        }
    }

    /// The reason TupleHash exists. Concatenation cannot tell these apart;
    /// TupleHash must.
    #[test]
    fn tuples_that_concatenate_alike_hash_differently() {
        let splits: &[&[&[u8]]] = &[
            &[b"abc", b"d"],
            &[b"ab", b"cd"],
            &[b"a", b"bcd"],
            &[b"abcd"],
            &[b"abcd", b""],
            &[b"", b"abcd"],
        ];

        let mut seen: Vec<[u8; 32]> = Vec::new();
        for elements in splits {
            let mut out = [0u8; 32];
            TupleHash128::hash(b"", elements, &mut out);
            assert!(
                !seen.contains(&out),
                "two different tuples collided: {elements:?}"
            );
            seen.push(out);
        }
    }

    #[test]
    fn tuple_hash_streams() {
        let mut one = [0u8; 32];
        TupleHash128::hash(b"S", &[b"alpha", b"beta", b"gamma"], &mut one);

        let mut t = TupleHash128::new(b"S");
        t.update(b"alpha");
        t.update(b"beta");
        t.update(b"gamma");
        let mut streamed = [0u8; 32];
        t.finalize(&mut streamed);
        assert_eq!(one, streamed);
    }

    #[test]
    fn parallel_hash_matches_an_independent_construction() {
        let data = [0x37u8; 500];
        for block_size in [1usize, 8, 32, 137, 500, 1024] {
            for len in [16usize, 32, 64] {
                let mut want = vec![0u8; len];
                let mut got = vec![0u8; len];

                reference_parallel_hash(false, b"S", block_size, &data, &mut want, false);
                ParallelHash128::hash(b"S", block_size, &data, &mut got);
                assert_eq!(got, want, "ParallelHash128 B={block_size}, {len} bytes");

                reference_parallel_hash(true, b"", block_size, &data, &mut want, false);
                ParallelHash256::hash(b"", block_size, &data, &mut got);
                assert_eq!(got, want, "ParallelHash256 B={block_size}, {len} bytes");

                reference_parallel_hash(false, b"S", block_size, &data, &mut want, true);
                ParallelHash128::hash_xof(b"S", block_size, &data, &mut got);
                assert_eq!(got, want, "ParallelHash128 xof B={block_size}");
            }
        }
    }

    /// An empty input still has a well-defined answer: zero blocks.
    #[test]
    fn parallel_hash_handles_an_empty_input() {
        let mut want = [0u8; 32];
        let mut got = [0u8; 32];
        reference_parallel_hash(false, b"", 64, b"", &mut want, false);
        ParallelHash128::hash(b"", 64, b"", &mut got);
        assert_eq!(got, want);
    }

    /// The block size is part of the computation, not a performance knob.
    #[test]
    fn the_block_size_changes_the_result() {
        let data = [0xa1u8; 256];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        ParallelHash128::hash(b"", 32, &data, &mut a);
        ParallelHash128::hash(b"", 64, &data, &mut b);
        assert_ne!(a, b, "B is bound into the output");
    }

    #[test]
    fn output_length_is_bound_in_for_both() {
        let mut short = [0u8; 32];
        let mut long = [0u8; 64];
        TupleHash128::hash(b"", &[b"x"], &mut short);
        TupleHash128::hash(b"", &[b"x"], &mut long);
        assert_ne!(short[..], long[..32], "TupleHash binds L");

        ParallelHash128::hash(b"", 32, b"x", &mut short);
        ParallelHash128::hash(b"", 32, b"x", &mut long);
        assert_ne!(short[..], long[..32], "ParallelHash binds L");

        // The XOF forms, by contrast, extend.
        TupleHash128::hash_xof(b"", &[b"x"], &mut short);
        TupleHash128::hash_xof(b"", &[b"x"], &mut long);
        assert_eq!(short[..], long[..32], "the xof form is a stream");
    }

    #[test]
    fn every_self_test_passes() {
        TupleHash128::self_test().unwrap();
        TupleHash256::self_test().unwrap();
        ParallelHash128::self_test().unwrap();
        ParallelHash256::self_test().unwrap();
    }
}
