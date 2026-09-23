//! FIPS 202 SHA-3 and SHAKE, built on the Keccak-f[1600] permutation.

use ic_core::traits::{Algorithm, Digest, SelfTest, Xof};
use ic_core::{ensure, Result, Zeroize};

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

/// Rotation amounts for rho, in lane-cycle order.
///
/// Only the tests use these now: `keccak_f1600` has the rotations written out.
/// They are kept because they, with `PI`, are the compact statement of what rho
/// and pi do, and `rho_and_pi_agree_with_the_lane_cycle` checks the written-out
/// form against them rather than against a stored answer.
#[cfg(test)]
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane-cycle order for pi. See [`RHO`].
#[cfg(test)]
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over a 25-lane state.
///
/// Straight-line rather than table-driven. The rho and pi steps used to walk
/// the lane cycle one position at a time, carrying a lane through a
/// twenty-four step chain of load, rotate and scattered store -- each
/// iteration waiting on the one before it, for no reason other than that the
/// cycle is a convenient way to write the permutation down. The rotations do
/// not depend on each other, so they are written out and the scheduler is free
/// to overlap them.
///
/// Theta's D is folded into the same expressions. The lanes had been xored
/// with it in a pass of their own, written back to the state, and read out
/// again by rho; applying it where rho reads removes a pass over all
/// twenty-five lanes per round.
///
/// The assignments below were generated from RHO and PI rather than
/// transcribed, and `rho_and_pi_agree_with_the_lane_cycle` checks them against
/// the cycle walk this replaced. Those tables are kept, under `cfg(test)`, so
/// the compact statement of what rho and pi do stays in the file and stays
/// checked against the version that runs.
fn keccak_f1600(a: &mut [u64; 25]) {
    for round in RC.iter().take(ROUNDS) {
        // theta
        let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        let d = [
            c4 ^ c1.rotate_left(1),
            c0 ^ c2.rotate_left(1),
            c1 ^ c3.rotate_left(1),
            c2 ^ c4.rotate_left(1),
            c3 ^ c0.rotate_left(1),
        ];

        // rho and pi, with theta's D applied as each lane is read
        let mut b = [0u64; 25];
        b[0] = a[0] ^ d[0];
        b[1] = (a[6] ^ d[1]).rotate_left(44);
        b[2] = (a[12] ^ d[2]).rotate_left(43);
        b[3] = (a[18] ^ d[3]).rotate_left(21);
        b[4] = (a[24] ^ d[4]).rotate_left(14);
        b[5] = (a[3] ^ d[3]).rotate_left(28);
        b[6] = (a[9] ^ d[4]).rotate_left(20);
        b[7] = (a[10] ^ d[0]).rotate_left(3);
        b[8] = (a[16] ^ d[1]).rotate_left(45);
        b[9] = (a[22] ^ d[2]).rotate_left(61);
        b[10] = (a[1] ^ d[1]).rotate_left(1);
        b[11] = (a[7] ^ d[2]).rotate_left(6);
        b[12] = (a[13] ^ d[3]).rotate_left(25);
        b[13] = (a[19] ^ d[4]).rotate_left(8);
        b[14] = (a[20] ^ d[0]).rotate_left(18);
        b[15] = (a[4] ^ d[4]).rotate_left(27);
        b[16] = (a[5] ^ d[0]).rotate_left(36);
        b[17] = (a[11] ^ d[1]).rotate_left(10);
        b[18] = (a[17] ^ d[2]).rotate_left(15);
        b[19] = (a[23] ^ d[3]).rotate_left(56);
        b[20] = (a[2] ^ d[2]).rotate_left(62);
        b[21] = (a[8] ^ d[3]).rotate_left(55);
        b[22] = (a[14] ^ d[4]).rotate_left(39);
        b[23] = (a[15] ^ d[0]).rotate_left(41);
        b[24] = (a[21] ^ d[1]).rotate_left(2);

        // chi
        a[0] = b[0] ^ (!b[1] & b[2]);
        a[1] = b[1] ^ (!b[2] & b[3]);
        a[2] = b[2] ^ (!b[3] & b[4]);
        a[3] = b[3] ^ (!b[4] & b[0]);
        a[4] = b[4] ^ (!b[0] & b[1]);
        a[5] = b[5] ^ (!b[6] & b[7]);
        a[6] = b[6] ^ (!b[7] & b[8]);
        a[7] = b[7] ^ (!b[8] & b[9]);
        a[8] = b[8] ^ (!b[9] & b[5]);
        a[9] = b[9] ^ (!b[5] & b[6]);
        a[10] = b[10] ^ (!b[11] & b[12]);
        a[11] = b[11] ^ (!b[12] & b[13]);
        a[12] = b[12] ^ (!b[13] & b[14]);
        a[13] = b[13] ^ (!b[14] & b[10]);
        a[14] = b[14] ^ (!b[10] & b[11]);
        a[15] = b[15] ^ (!b[16] & b[17]);
        a[16] = b[16] ^ (!b[17] & b[18]);
        a[17] = b[17] ^ (!b[18] & b[19]);
        a[18] = b[18] ^ (!b[19] & b[15]);
        a[19] = b[19] ^ (!b[15] & b[16]);
        a[20] = b[20] ^ (!b[21] & b[22]);
        a[21] = b[21] ^ (!b[22] & b[23]);
        a[22] = b[22] ^ (!b[23] & b[24]);
        a[23] = b[23] ^ (!b[24] & b[20]);
        a[24] = b[24] ^ (!b[20] & b[21]);

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

    /// Absorb a whole block at a time where the input allows it.
    ///
    /// This used to walk the input byte by byte, and a byte cost a division, a
    /// remainder, a shift and a read-modify-write of the state. At the SHA3-256
    /// rate that is 136 trips round the loop to feed one permutation -- about
    /// as much work as the permutation itself, so roughly half of hashing was
    /// spent getting the bytes into the state rather than mixing them.
    ///
    /// A block-aligned run is now xored a lane at a time, which is 17 of those
    /// operations instead of 136. The byte-wise path stays for whatever
    /// straddles the ends, since callers may hand over any lengths they like
    /// and the result must not depend on how the input was split up.
    pub(crate) fn absorb(&mut self, mut data: &[u8]) {
        // Every SHA-3 and SHAKE rate is a whole number of lanes, but the
        // sponge takes the rate as a parameter, so the fast path checks rather
        // than assumes. A rate that is not lane-aligned simply keeps the old
        // behaviour.
        let lane_aligned = self.rate % 8 == 0;

        while !data.is_empty() {
            if lane_aligned && self.pos == 0 && data.len() >= self.rate {
                let (block, rest) = data.split_at(self.rate);
                for (lane, chunk) in self.state.iter_mut().zip(block.chunks_exact(8)) {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(chunk);
                    *lane ^= u64::from_le_bytes(b);
                }
                keccak_f1600(&mut self.state);
                data = rest;
                continue;
            }

            let byte = data[0];
            let lane = self.pos / 8;
            let shift = 8 * (self.pos % 8);
            self.state[lane] ^= (byte as u64) << shift;
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            data = &data[1..];
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
                ic_core::codec::hex_decode($kat.as_bytes(), &mut want)?;
                ensure!(
                    ic_core::ct::verify(&want, got.as_ref()),
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
                ic_core::codec::hex_decode($kat.as_bytes(), &mut want)?;
                ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, $id);
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
    use ic_core::codec::hex;

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

    /// The table-driven permutation the straight-line one replaced.
    ///
    /// Transcribed unchanged from the previous revision, and the reason the
    /// rewrite is checkable: it derives rho and pi by walking the lane cycle
    /// out of RHO and PI, so agreeing with it means the twenty-four written-out
    /// assignments say what those tables say.
    fn keccak_f1600_by_lane_cycle(a: &mut [u64; 25]) {
        for round in RC.iter().take(ROUNDS) {
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
            let mut last = a[1];
            for i in 0..24 {
                let j = PI[i];
                let tmp = a[j];
                a[j] = last.rotate_left(RHO[i]);
                last = tmp;
            }
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
            a[0] ^= *round;
        }
    }

    /// The straight-line rho and pi say what RHO and PI say.
    ///
    /// Arbitrary states, not just the ones a sponge reaches: a padded sponge
    /// never presents a full-entropy state to the permutation, so testing only
    /// through `Sha3_256` would leave most lane patterns unexercised, and a
    /// misplaced rotation is exactly the kind of error that hides in the lanes
    /// nobody drives.
    #[test]
    fn rho_and_pi_agree_with_the_lane_cycle() {
        let mut state = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for case in 0..2_000 {
            let mut a = [0u64; 25];
            for lane in a.iter_mut() {
                *lane = next();
            }
            // One lane at a time as well, so a rotation landing on the wrong
            // lane cannot be masked by every other lane also being non-zero.
            if case < 25 {
                a = [0u64; 25];
                a[case] = 0x8000_0000_0000_0001;
            }
            let mut want = a;
            keccak_f1600_by_lane_cycle(&mut want);
            let mut got = a;
            keccak_f1600(&mut got);
            assert_eq!(got, want, "permutations disagree on state {a:?}");
        }
    }

    /// Straight-line against lane-cycle, in one process, alternating.
    ///
    /// Ignored: a measurement, not an assertion. Run it with
    /// `cargo test -p ic-hash --release -- --ignored --nocapture permutation_ab`.
    ///
    /// Both forms are called from the same binary in the same loop, taking the
    /// best of many alternating batches, because this machine has other work on
    /// it and two separate benchmark runs minutes apart measure the other work
    /// as much as this code. An earlier attempt to compare across runs had
    /// RustCrypto's own SHA3 moving 616 -> 425 MiB/s between them, untouched.
    #[test]
    #[ignore = "diagnostic, not a test"]
    fn permutation_ab() {
        use std::time::Instant;
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut a = [0u64; 25];
        for lane in a.iter_mut() {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            *lane = seed.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }

        let n = 20_000;
        let (mut best_new, mut best_old) = (f64::INFINITY, f64::INFINITY);
        for _ in 0..40 {
            let mut s1 = a;
            let t = Instant::now();
            for _ in 0..n {
                keccak_f1600(core::hint::black_box(&mut s1));
            }
            let e = t.elapsed().as_secs_f64() / n as f64 * 1e9;
            best_new = best_new.min(e);

            let mut s2 = a;
            let t = Instant::now();
            for _ in 0..n {
                keccak_f1600_by_lane_cycle(core::hint::black_box(&mut s2));
            }
            let e = t.elapsed().as_secs_f64() / n as f64 * 1e9;
            best_old = best_old.min(e);
        }
        println!(
            "
  keccak-f[1600] straight-line   {best_new:>8.1} ns"
        );
        println!("  keccak-f[1600] lane cycle     {best_old:>8.1} ns");
        println!(
            "  ratio                         {:>8.2}x",
            best_old / best_new
        );
    }

    /// The digest does not depend on how the input was handed over.
    ///
    /// `absorb` now has a block-aligned fast path and a byte-wise one, and
    /// which of them runs depends entirely on the caller's chunking: the same
    /// message delivered whole, in single bytes, or in awkward pieces has to
    /// cross between them at different points. Feeding one buffer in every
    /// chunking pattern below and demanding one answer is what holds the two
    /// paths together. Lengths either side of the 136-byte rate, and either
    /// side of two rates, so a block boundary falls inside a chunk as well as
    /// on one.
    #[test]
    fn chunking_the_input_does_not_change_the_digest() {
        use ic_core::traits::Digest;

        for len in [0usize, 1, 7, 8, 9, 135, 136, 137, 271, 272, 273, 400] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let want = Sha3_256::digest(&msg);

            for chunk in [1usize, 2, 3, 7, 8, 17, 64, 135, 136, 137, 200] {
                let mut h = Sha3_256::default();
                for piece in msg.chunks(chunk.max(1)) {
                    h.update(piece);
                }
                assert_eq!(
                    h.finalize().as_ref(),
                    want.as_ref(),
                    "len {len} split into {chunk}-byte pieces"
                );
            }

            // An uneven split, so the boundary is not at a regular stride.
            if len > 3 {
                let mut h = Sha3_256::default();
                h.update(&msg[..1]);
                h.update(&msg[1..len - 2]);
                h.update(&msg[len - 2..]);
                assert_eq!(
                    h.finalize().as_ref(),
                    want.as_ref(),
                    "len {len} split unevenly"
                );
            }
        }
    }

    /// The same, for the extendable-output side and its different rate.
    #[test]
    fn chunking_the_input_does_not_change_the_xof_output() {
        use ic_core::traits::Xof;

        for len in [0usize, 1, 167, 168, 169, 337, 500] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 17 + 3) as u8).collect();
            let mut want = [0u8; 137];
            {
                let mut x = Shake128::default();
                x.update(&msg);
                x.finalize_xof(&mut want);
            }
            for chunk in [1usize, 5, 8, 64, 167, 168, 169] {
                let mut x = Shake128::default();
                for piece in msg.chunks(chunk) {
                    x.update(piece);
                }
                let mut got = [0u8; 137];
                x.finalize_xof(&mut got);
                assert_eq!(got, want, "xof len {len} split into {chunk}-byte pieces");
            }
        }
    }
}
