//! A software model of the ARMv8 SHA-2 instructions, so the block structure in
//! [`super::armv8_rounds`] can be checked on a host that cannot run them.
//!
//! Each instruction is transcribed from its pseudocode in the Arm Architecture
//! Reference Manual for A-profile (`SHA256hash`, `SHA256SU0`, `SHA256SU1`,
//! `SHA512H`, `SHA512H2`, `SHA512SU0`, `SHA512SU1`), not from the portable
//! implementation in [`super`]. The model drives the same macro the real
//! backend does, and the result must equal the portable compression, which the
//! FIPS 180-4 vectors validate.
//!
//! What this closes and what it does not, separately: it checks the
//! composition -- which vector feeds which operand, the schedule window, the
//! role rotation of the SHA-512 state -- everywhere the suite runs. Whether the
//! intrinsics mean what this model says is checked only where they execute:
//! under QEMU (`scripts/test-aarch64.sh`) and on arm64 hardware.

use super::armv8_rounds::{
    armv8_sha256_blocks, armv8_sha256_quad, armv8_sha512_blocks, armv8_sha512_pair,
};
use super::{K256, K512};

/// `uint32x4_t`, lane 0 first.
mod ops256 {
    pub(super) type V = [u32; 4];

    pub(super) fn from_words(w: [u32; 4]) -> V {
        w
    }

    pub(super) fn to_words(v: V) -> [u32; 4] {
        v
    }

    /// `LD1` then `REV32`: four big-endian words.
    pub(super) fn load_be(b: &[u8]) -> V {
        core::array::from_fn(|i| {
            u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
        })
    }

    pub(super) fn add(a: V, b: V) -> V {
        core::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }

    fn choose(x: u32, y: u32, z: u32) -> u32 {
        ((y ^ z) & x) ^ z
    }

    fn majority(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((x | y) & z)
    }

    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    /// `SHA256hash(X, Y, W, part1)`.
    ///
    /// Four rounds. After each, the 256-bit value `Y:X` is rotated left by
    /// 32 bits, so the new `A` (written to the top of `Y`) moves to lane 0 of
    /// `X` and the old top of `X` moves to lane 0 of `Y`.
    fn hash(mut x: V, mut y: V, w: V, part1: bool) -> V {
        for e in 0..4 {
            let chs = choose(y[0], y[1], y[2]);
            let maj = majority(x[0], x[1], x[2]);
            let t = y[3]
                .wrapping_add(sigma1(y[0]))
                .wrapping_add(chs)
                .wrapping_add(w[e]);
            x[3] = t.wrapping_add(x[3]);
            y[3] = t.wrapping_add(sigma0(x[0])).wrapping_add(maj);
            // ROL(Y:X, 32)
            let top_x = x[3];
            let top_y = y[3];
            x = [top_y, x[0], x[1], x[2]];
            y = [top_x, y[0], y[1], y[2]];
        }
        if part1 {
            x
        } else {
            y
        }
    }

    /// `SHA256H Qd, Qn, Vm`: X = Vd, Y = Vn.
    pub(super) fn sha256h(abcd: V, efgh: V, wk: V) -> V {
        hash(abcd, efgh, wk, true)
    }

    /// `SHA256H2 Qd, Qn, Vm`: Y = Vd, X = Vn.
    pub(super) fn sha256h2(efgh: V, abcd: V, wk: V) -> V {
        hash(abcd, efgh, wk, false)
    }

    /// `SHA256SU0 Vd, Vn`: `T = Vn<31:0> : Vd<127:32>`, then
    /// `Vd[e] + sigma0(T[e])`.
    pub(super) fn sha256su0(d: V, n: V) -> V {
        let t = [d[1], d[2], d[3], n[0]];
        core::array::from_fn(|e| {
            let x = t[e];
            (x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)).wrapping_add(d[e])
        })
    }

    /// `SHA256SU1 Vd, Vn, Vm`: `T0 = Vm<31:0> : Vn<127:32>`, `T1 = Vm<127:64>`
    /// for the first two lanes, then the result's own first two lanes for
    /// the last two.
    pub(super) fn sha256su1(d: V, n: V, m: V) -> V {
        fn s1(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }
        let t0 = [n[1], n[2], n[3], m[0]];
        let mut r = [0u32; 4];
        let t1 = [m[2], m[3]];
        for e in 0..2 {
            r[e] = s1(t1[e]).wrapping_add(d[e]).wrapping_add(t0[e]);
        }
        let t1 = [r[0], r[1]];
        for e in 2..4 {
            r[e] = s1(t1[e - 2]).wrapping_add(d[e]).wrapping_add(t0[e]);
        }
        r
    }
}

/// `uint64x2_t`, lane 0 first. In the pseudocode `<63:0>` is lane 0 and
/// `<127:64>` lane 1.
mod ops512 {
    pub(super) type V = [u64; 2];

    pub(super) fn from_words(w: [u64; 2]) -> V {
        w
    }

    pub(super) fn to_words(v: V) -> [u64; 2] {
        v
    }

    /// `LD1` then `REV64`: two big-endian words.
    pub(super) fn load_be(b: &[u8]) -> V {
        core::array::from_fn(|i| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[8 * i..8 * i + 8]);
            u64::from_be_bytes(w)
        })
    }

    pub(super) fn add(a: V, b: V) -> V {
        [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])]
    }

    /// `EXT Vd.16B, Vn.16B, Vm.16B, #8`.
    pub(super) fn ext1(a: V, b: V) -> V {
        [a[1], b[0]]
    }

    /// `SHA512H Qd, Qn, Vm.2D`: W = Vd, X = Vn, Y = Vm.
    pub(super) fn sha512h(w: V, x: V, y: V) -> V {
        let big_sigma1 = |v: u64| v.rotate_right(14) ^ v.rotate_right(18) ^ v.rotate_right(41);
        let mut r = [0u64; 2];
        r[1] = ((y[1] & x[0]) ^ (!y[1] & x[1]))
            .wrapping_add(big_sigma1(y[1]))
            .wrapping_add(w[1]);
        let tmp = r[1].wrapping_add(y[0]);
        r[0] = ((tmp & y[1]) ^ (!tmp & x[0]))
            .wrapping_add(big_sigma1(tmp))
            .wrapping_add(w[0]);
        r
    }

    /// `SHA512H2 Qd, Qn, Vm.2D`: W = Vd, X = Vn, Y = Vm.
    pub(super) fn sha512h2(w: V, x: V, y: V) -> V {
        let big_sigma0 = |v: u64| v.rotate_right(28) ^ v.rotate_right(34) ^ v.rotate_right(39);
        let mut r = [0u64; 2];
        r[1] = ((x[0] & y[1]) ^ (x[0] & y[0]) ^ (y[1] & y[0]))
            .wrapping_add(big_sigma0(y[0]))
            .wrapping_add(w[1]);
        r[0] = ((r[1] & y[0]) ^ (r[1] & y[1]) ^ (y[1] & y[0]))
            .wrapping_add(big_sigma0(r[1]))
            .wrapping_add(w[0]);
        r
    }

    fn small_sigma0(v: u64) -> u64 {
        v.rotate_right(1) ^ v.rotate_right(8) ^ (v >> 7)
    }

    fn small_sigma1(v: u64) -> u64 {
        v.rotate_right(19) ^ v.rotate_right(61) ^ (v >> 6)
    }

    /// `SHA512SU0 Vd.2D, Vn.2D`.
    pub(super) fn sha512su0(d: V, n: V) -> V {
        [
            d[0].wrapping_add(small_sigma0(d[1])),
            d[1].wrapping_add(small_sigma0(n[0])),
        ]
    }

    /// `SHA512SU1 Vd.2D, Vn.2D, Vm.2D`.
    pub(super) fn sha512su1(d: V, n: V, m: V) -> V {
        [
            d[0].wrapping_add(small_sigma1(n[0])).wrapping_add(m[0]),
            d[1].wrapping_add(small_sigma1(n[1])).wrapping_add(m[1]),
        ]
    }
}

/// The model's SHA-256 compression, through the shared structure.
pub(super) fn compress256(state: &mut [u32; 8], blocks: &[u8]) {
    armv8_sha256_blocks!(ops256, state, blocks, K256);
}

/// The model's SHA-512 compression, through the shared structure.
pub(super) fn compress512(state: &mut [u64; 8], blocks: &[u8]) {
    armv8_sha512_blocks!(ops512, state, blocks, K512);
}

#[cfg(test)]
mod tests {
    use super::super::tests::{check_sha256_kernel, check_sha512_kernel};
    use super::*;

    /// The structure, over modelled instructions, against the portable
    /// compression at every length the kernel test covers.
    #[test]
    fn the_sha256_structure_matches_the_portable_compression() {
        check_sha256_kernel(compress256);
    }

    #[test]
    fn the_sha512_structure_matches_the_portable_compression() {
        check_sha512_kernel(compress512);
    }

    /// One instruction against the FIPS 180-4 round it should be, so a wrong
    /// model is caught as such rather than as a structural failure.
    ///
    /// `SHA256H` then `SHA256H2` on the same inputs is four rounds of
    /// FIPS 180-4 section 6.2.2 step 3, with the `K + W` sums supplied.
    #[test]
    fn four_modelled_rounds_are_four_fips_rounds() {
        let h = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];
        let wk = [0x1111_1111u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let abcd = [h[0], h[1], h[2], h[3]];
        let efgh = [h[4], h[5], h[6], h[7]];
        let got_abcd = ops256::sha256h(abcd, efgh, wk);
        let got_efgh = ops256::sha256h2(efgh, abcd, wk);

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for kw in wk {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(kw);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(s0.wrapping_add(maj));
        }
        assert_eq!(got_abcd, [a, b, c, d]);
        assert_eq!(got_efgh, [e, f, g, hh]);
    }
}
