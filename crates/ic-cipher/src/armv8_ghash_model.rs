//! A software model of `PMULL`, `RBIT` and `EXT`, so the GHASH structure in
//! [`crate::armv8_ghash`] can be checked on a host that cannot run them.
//!
//! The model drives the same macros the real backend does, and the result must
//! equal [`crate::gcm::portable_ghash_mul`], which the SP 800-38D vectors
//! validate. That checks the composition -- the representation, the operand
//! lanes, the reduction -- on every host. Whether the intrinsics mean what this
//! model says is checked only where they execute: under QEMU
//! (`scripts/test-aarch64.sh`) and on arm64 hardware.
//!
//! The carry-less multiply is shift-and-add over the bits of one operand,
//! which is its definition; it shares nothing with the portable GHASH, which
//! works in GCM's reflected order and reduces bit by bit.

use crate::armv8_ghash::{
    armv8_ghash_absorb8, armv8_ghash_mul, armv8_ghash_product, armv8_ghash_reduce,
};

/// `uint64x2_t`, lane 0 first.
mod ops {
    pub(super) type V = [u64; 2];

    /// `LD1` then `RBIT`: each byte bit-reversed, read little-endian.
    pub(super) fn load(b: &[u8; 16]) -> V {
        let mut r = *b;
        for byte in r.iter_mut() {
            *byte = byte.reverse_bits();
        }
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&r[..8]);
        hi.copy_from_slice(&r[8..]);
        [u64::from_le_bytes(lo), u64::from_le_bytes(hi)]
    }

    pub(super) fn store(v: V) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&v[0].to_le_bytes());
        out[8..].copy_from_slice(&v[1].to_le_bytes());
        for byte in out.iter_mut() {
            *byte = byte.reverse_bits();
        }
        out
    }

    /// The 128-bit carry-less product of two 64-bit polynomials.
    fn clmul(a: u64, b: u64) -> V {
        let mut acc = 0u128;
        for i in 0..64 {
            if (b >> i) & 1 == 1 {
                acc ^= u128::from(a) << i;
            }
        }
        [acc as u64, (acc >> 64) as u64]
    }

    /// `PMULL Vd.1Q, Vn.1D, Vm.1D`.
    pub(super) fn pmull(a: V, b: V) -> V {
        clmul(a[0], b[0])
    }

    /// `PMULL2 Vd.1Q, Vn.2D, Vm.2D`.
    pub(super) fn pmull2(a: V, b: V) -> V {
        clmul(a[1], b[1])
    }

    /// `EXT Vd.16B, Vn.16B, Vm.16B, #8`.
    pub(super) fn ext8(a: V, b: V) -> V {
        [a[1], b[0]]
    }

    pub(super) fn xor(a: V, b: V) -> V {
        [a[0] ^ b[0], a[1] ^ b[1]]
    }

    pub(super) fn zero() -> V {
        [0, 0]
    }

    pub(super) fn poly() -> V {
        [0x87, 0x87]
    }
}

/// The model's multiply, through the shared structure.
fn mul(x: &mut [u8; 16], h: &[u8; 16]) {
    armv8_ghash_mul!(ops, x, h);
}

/// The model's eight-block absorb, through the shared structure.
fn absorb8(acc: &mut [u8; 16], powers: &[[u8; 16]; 8], blocks: &[u8]) {
    armv8_ghash_absorb8!(ops, acc, powers, blocks);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::gcm::portable_ghash_mul;

    /// A small xorshift, so the sweep covers a wide spread of inputs without
    /// an RNG.
    fn pseudo_random(seed: &mut u64) -> [u8; 16] {
        let mut out = [0u8; 16];
        for chunk in out.chunks_mut(8) {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            chunk.copy_from_slice(&seed.to_be_bytes());
        }
        out
    }

    /// Hold a GHASH multiply to the portable one: structural cases first --
    /// zero, the identity, all ones, a single bit at either end, which between
    /// them reach both ends of the reduction -- then a pseudo-random sweep.
    pub(crate) fn check_mul(f: impl Fn(&mut [u8; 16], &[u8; 16])) {
        let mut one = [0u8; 16];
        one[0] = 0x80; // the multiplicative identity in GCM's bit order.
        let mut last = [0u8; 16];
        last[15] = 1; // x^127, the term that needs the most reduction.
        let mut first = [0u8; 16];
        first[0] = 1;
        let cases = [[0u8; 16], one, [0xffu8; 16], last, first];
        for x in cases {
            for h in cases {
                let (mut a, mut b) = (x, x);
                portable_ghash_mul(&mut a, &h);
                f(&mut b, &h);
                assert_eq!(a, b, "x={x:02x?} h={h:02x?}");
            }
        }
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        for i in 0..512 {
            let x = pseudo_random(&mut seed);
            let h = pseudo_random(&mut seed);
            let (mut a, mut b) = (x, x);
            portable_ghash_mul(&mut a, &h);
            f(&mut b, &h);
            assert_eq!(a, b, "iteration {i}");
        }
    }

    /// Hold an eight-block absorb to the serial definition, one portable
    /// multiply per block, over one, two and many groups from a nonzero
    /// accumulator.
    pub(crate) fn check_absorb8(f: impl Fn(&mut [u8; 16], &[[u8; 16]; 8], &[u8])) {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let h = pseudo_random(&mut seed);
        let mut powers = [h; 8];
        for i in 1..8 {
            let mut p = powers[i - 1];
            portable_ghash_mul(&mut p, &h);
            powers[i] = p;
        }
        for groups in [0usize, 1, 2, 3, 16] {
            let mut data = std::vec![0u8; groups * 128];
            for chunk in data.chunks_mut(16) {
                chunk.copy_from_slice(&pseudo_random(&mut seed));
            }
            let start = pseudo_random(&mut seed);

            let mut want = start;
            for block in data.chunks_exact(16) {
                for j in 0..16 {
                    want[j] ^= block[j];
                }
                portable_ghash_mul(&mut want, &h);
            }
            let mut got = start;
            f(&mut got, &powers, &data);
            assert_eq!(got, want, "{groups} groups");
        }
    }

    /// The model's primitives against their definitions, so a wrong model is
    /// caught as such rather than as a structural failure.
    #[test]
    fn the_model_primitives_are_right() {
        // RBIT then little-endian: GCM's leading bit is the polynomial's x^0.
        let mut one = [0u8; 16];
        one[0] = 0x80;
        assert_eq!(ops::load(&one), [1, 0]);
        let mut top = [0u8; 16];
        top[15] = 1;
        assert_eq!(ops::load(&top), [0, 1 << 63]);
        assert_eq!(ops::store(ops::load(&top)), top);
        // (x + 1)^2 = x^2 + 1 over GF(2); x^63 * x = x^64.
        assert_eq!(ops::pmull([3, 0], [3, 0]), [5, 0]);
        assert_eq!(ops::pmull([1 << 63, 0], [2, 0]), [0, 1]);
        assert_eq!(ops::pmull2([0, 3], [0, 3]), [5, 0]);
        assert_eq!(ops::ext8([1, 2], [3, 4]), [2, 3]);
    }

    #[test]
    fn the_modelled_multiply_matches_the_portable_one() {
        check_mul(mul);
    }

    #[test]
    fn the_modelled_absorb8_matches_the_serial_portable_ghash() {
        check_absorb8(absorb8);
    }
}
