//! FIPS 202 SHA-3 and SHAKE, built on the Keccak-f[1600] permutation.

use ac_core::traits::{Algorithm, Digest, SelfTest, Xof};
use ac_core::{ensure, Result, Zeroize};

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
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

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over a 25-lane state.
fn keccak_f1600(a: &mut [u64; 25]) {
    for round in RC.iter().take(ROUNDS) {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut last = a[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }
        // chi
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        // iota
        a[0] ^= *round;
    }
}

/// A sponge over Keccak-f[1600] with a configurable rate and domain separator.
#[derive(Clone)]
pub(crate) struct Sponge {
    state: [u64; 25],
    rate: usize,
    pos: usize,
    pad: u8,
}

impl Sponge {
    pub(crate) const fn new(rate: usize, pad: u8) -> Self {
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
            pad,
        }
    }

    pub(crate) fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            let lane = self.pos / 8;
            let shift = 8 * (self.pos % 8);
            self.state[lane] ^= (byte as u64) << shift;
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    pub(crate) fn finish(&mut self) {
        let lane = self.pos / 8;
        let shift = 8 * (self.pos % 8);
        self.state[lane] ^= (self.pad as u64) << shift;
        let last = self.rate - 1;
        self.state[last / 8] ^= 0x80u64 << (8 * (last % 8));
        keccak_f1600(&mut self.state);
        self.pos = 0;
    }

    pub(crate) fn squeeze(&mut self, out: &mut [u8]) {
        let mut produced = 0;
        while produced < out.len() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            let lane = self.pos / 8;
            let shift = 8 * (self.pos % 8);
            out[produced] = (self.state[lane] >> shift) as u8;
            self.pos += 1;
            produced += 1;
        }
    }
}

impl Drop for Sponge {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

macro_rules! sha3_hash {
    ($name:ident, $id:literal, $disp:literal, $out:literal, $kat:literal) => {
        #[doc = concat!("FIPS 202 ", $disp, ".")]
        #[derive(Clone)]
        pub struct $name(Sponge);

        impl Default for $name {
            fn default() -> Self {
                Self(Sponge::new(200 - 2 * $out, 0x06))
            }
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Digest for $name {
            type Output = [u8; $out];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 200 - 2 * $out;

            fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            fn finalize(mut self) -> Self::Output {
                let mut out = [0u8; $out];
                self.0.finish();
                self.0.squeeze(&mut out);
                out
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                let got = <Self as Digest>::digest(b"abc");
                let mut want = [0u8; $out];
                ac_core::codec::hex_decode($kat.as_bytes(), &mut want)?;
                ensure!(
                    ac_core::ct::verify(&want, got.as_ref()),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

/// A finished sponge that can be squeezed repeatedly.
///
/// [`Xof::finalize_xof`] consumes the hasher and produces a fixed number of
/// bytes, which is the right shape for most callers. Rejection sampling is the
/// exception: it cannot know in advance how much output it needs, because that
/// depends on how many candidates it throws away. ML-KEM's `SampleNTT` is
/// exactly this case.
///
/// Reading is continuous — reading 32 bytes twice gives the same stream as
/// reading 64 once — which is what makes the sampler's output independent of
/// the chunk size it happens to ask for.
pub struct XofReader {
    sponge: Sponge,
}

impl XofReader {
    /// Squeeze the next `out.len()` bytes.
    pub fn read(&mut self, out: &mut [u8]) {
        self.sponge.squeeze(out);
    }
}

macro_rules! shake {
    ($name:ident, $id:literal, $disp:literal, $cap:literal, $kat:literal) => {
        #[doc = concat!("FIPS 202 ", $disp, " extendable-output function.")]
        #[derive(Clone)]
        pub struct $name(Sponge);

        impl Default for $name {
            fn default() -> Self {
                Self(Sponge::new(200 - $cap / 4, 0x1f))
            }
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Xof for $name {
            const BLOCK_LEN: usize = 200 - $cap / 4;

            fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            fn finalize_xof(mut self, out: &mut [u8]) {
                self.0.finish();
                self.0.squeeze(out);
            }
        }

        impl $name {
            /// Finish absorbing and return a reader for an unbounded stream.
            ///
            /// For callers that cannot size their output in advance; see
            /// [`XofReader`].
            pub fn finalize_reader(mut self) -> XofReader {
                self.0.finish();
                XofReader { sponge: self.0 }
            }

            /// One-shot: absorb `data` and squeeze `out.len()` bytes.
            pub fn xof(data: &[u8], out: &mut [u8]) {
                let mut x = Self::default();
                <Self as Xof>::update(&mut x, data);
                x.finalize_xof(out);
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                let mut got = [0u8; 32];
                Self::xof(b"abc", &mut got);
                let mut want = [0u8; 32];
                ac_core::codec::hex_decode($kat.as_bytes(), &mut want)?;
                ensure!(ac_core::ct::verify(&want, &got), SelfTestFailed, $id);
                Ok(())
            }
        }
    };
}

sha3_hash!(
    Sha3_224,
    "sha3-224",
    "SHA3-224",
    28,
    "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
);
sha3_hash!(
    Sha3_256,
    "sha3-256",
    "SHA3-256",
    32,
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
);
sha3_hash!(
    Sha3_384,
    "sha3-384",
    "SHA3-384",
    48,
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
);
sha3_hash!(
    Sha3_512,
    "sha3-512",
    "SHA3-512",
    64,
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
);

shake!(
    Shake128,
    "shake128",
    "SHAKE128",
    128,
    "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
);
shake!(
    Shake256,
    "shake256",
    "SHAKE256",
    256,
    "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
);

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::hex;

    #[test]
    fn sha3_abc_vectors() {
        assert_eq!(
            hex(Sha3_224::digest(b"abc").as_ref()),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
        assert_eq!(
            hex(Sha3_256::digest(b"abc").as_ref()),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(Sha3_384::digest(b"abc").as_ref()),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        );
        assert_eq!(
            hex(Sha3_512::digest(b"abc").as_ref()),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn sha3_empty_vectors() {
        assert_eq!(
            hex(Sha3_256::digest(b"").as_ref()),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(Sha3_512::digest(b"").as_ref()),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn shake_vectors() {
        let mut out = [0u8; 32];
        Shake128::xof(b"", &mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        Shake256::xof(b"", &mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    /// A long squeeze must agree with a short one on its prefix, proving the
    /// sponge rate boundary is handled correctly.
    #[test]
    fn shake_long_squeeze_is_prefix_consistent() {
        let mut short = [0u8; 16];
        let mut long = [0u8; 512];
        Shake128::xof(b"agentic", &mut short);
        Shake128::xof(b"agentic", &mut long);
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: [u8; 400] = core::array::from_fn(|i| (i * 7) as u8);
        for split in [0usize, 1, 135, 136, 137, 200, 400] {
            let mut h = Sha3_256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), Sha3_256::digest(&data), "split at {split}");
        }
    }

    #[test]
    fn all_self_tests_pass() {
        Sha3_224::self_test().unwrap();
        Sha3_256::self_test().unwrap();
        Sha3_384::self_test().unwrap();
        Sha3_512::self_test().unwrap();
        Shake128::self_test().unwrap();
        Shake256::self_test().unwrap();
    }
}
