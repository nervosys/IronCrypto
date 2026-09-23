//! A bitsliced AES encryption path, four blocks at a time.
//!
//! # Why
//!
//! [`super::portable`] computes one S-box at a time, and an S-box is an
//! inversion in GF(2^8): seven squarings and six multiplications, with each
//! multiplication a bit-serial loop. That is a few hundred operations per byte,
//! and it is why the portable backend ran some twenty-five times behind
//! RustCrypto's software AES, which is fixsliced.
//!
//! Bitslicing pays the same algebra once for sixty-four bytes instead of once
//! per byte. The state is held transposed: eight `u64` planes, where plane `i`
//! bit `j` is bit `i` of byte `j`. A field multiplication is then sixty-four
//! `AND`s and a reduction on whole words, and each of those words carries four
//! blocks' worth of work.
//!
//! # Constant time
//!
//! Nothing here indexes memory with a value derived from the key or the
//! plaintext, and nothing branches on one. The S-box is computed, as it is in
//! the byte-at-a-time path -- that property is the reason both exist rather
//! than a lookup table.
//!
//! # What it does not do
//!
//! Decryption. The inverse S-box and inverse MixColumns are a separate piece of
//! work, and the modes that move volume -- CTR, GCM, GCM-SIV -- only ever run
//! the forward direction. Decryption stays on the byte-at-a-time path.
//!
//! # Trusting it
//!
//! Every piece below was derived mechanically from the byte-at-a-time code
//! rather than transcribed, and each is checked against it: the field
//! operations over their entire domain, the round operations differentially.

use super::portable::{Schedule, BLOCK_LEN};

/// Blocks processed together. Four blocks of sixteen bytes fill a `u64` plane.
pub const LANES: usize = 4;

/// Bytes in a group.
pub const GROUP: usize = LANES * BLOCK_LEN;

/// The state, transposed: `planes[i]` bit `j` is bit `i` of byte `j`.
type Planes = [u64; 8];

/// Which input bits each output bit of a squaring draws from.
///
/// Squaring is linear over GF(2), so it is a fixed 8x8 matrix. This one was
/// produced by squaring each basis element with the byte-at-a-time multiply and
/// reading off the result, not copied from a reference.
const SQUARE_TERMS: [&[usize]; 8] = [
    &[0, 4, 6],
    &[4, 6, 7],
    &[1, 5],
    &[4, 5, 6, 7],
    &[2, 4, 7],
    &[5, 6],
    &[3, 5],
    &[6, 7],
];

/// Transpose the 8x8 bit matrix packed in a `u64`, sending bit `8j + i` to bit
/// `8i + j`.
///
/// Three masked swaps rather than sixty-four bit tests. Getting the bytes into
/// and out of plane form is pure overhead -- it computes nothing -- so it is
/// worth not doing it a bit at a time: the naive form was about a tenth of the
/// whole encryption.
///
/// `the_byte_transpose_matches_a_naive_one` checks it against the obvious
/// double loop, on every single-bit input and on random words.
#[inline(always)]
fn transpose8(mut x: u64) -> u64 {
    x = (x & 0xAA55_AA55_AA55_AA55)
        | ((x & 0x00AA_00AA_00AA_00AA) << 7)
        | ((x >> 7) & 0x00AA_00AA_00AA_00AA);
    x = (x & 0xCCCC_3333_CCCC_3333)
        | ((x & 0x0000_CCCC_0000_CCCC) << 14)
        | ((x >> 14) & 0x0000_CCCC_0000_CCCC);
    x = (x & 0xF0F0_F0F0_0F0F_0F0F)
        | ((x & 0x0000_0000_F0F0_F0F0) << 28)
        | ((x >> 28) & 0x0000_0000_F0F0_F0F0);
    x
}

/// Transpose sixty-four bytes into eight bit-planes.
///
/// Eight bytes at a time: one `transpose8` turns eight bytes into eight bytes
/// where the `i`th holds bit `i` of each, which is one byte of each plane.
fn transpose_in(bytes: &[u8]) -> Planes {
    let mut p = [0u64; 8];
    for (w, chunk) in bytes.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let t = transpose8(u64::from_le_bytes(word));
        for (i, plane) in p.iter_mut().enumerate() {
            *plane |= ((t >> (8 * i)) & 0xff) << (8 * w);
        }
    }
    p
}

/// Transpose eight bit-planes back into sixty-four bytes.
fn transpose_out(p: &Planes, out: &mut [u8]) {
    for (w, chunk) in out.chunks_exact_mut(8).enumerate() {
        let mut t = 0u64;
        for (i, plane) in p.iter().enumerate() {
            t |= ((plane >> (8 * w)) & 0xff) << (8 * i);
        }
        chunk.copy_from_slice(&transpose8(t).to_le_bytes());
    }
}

/// `x^2` in GF(2^8), on planes.
fn square(a: &Planes) -> Planes {
    let mut out = [0u64; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut v = 0u64;
        for &j in SQUARE_TERMS[i] {
            v ^= a[j];
        }
        *slot = v;
    }
    out
}

/// `a * b` in GF(2^8), on planes.
///
/// Schoolbook into fifteen coefficients, then reduced with
/// `x^8 = x^4 + x^3 + x + 1`, which sends `x^k` to
/// `x^(k-4) + x^(k-5) + x^(k-7) + x^(k-8)`. Taking `k` downwards means a
/// coefficient that lands at or above eight is reduced in its own turn.
fn mul(a: &Planes, b: &Planes) -> Planes {
    let mut t = [0u64; 15];
    for i in 0..8 {
        for j in 0..8 {
            t[i + j] ^= a[i] & b[j];
        }
    }
    let mut k = 14;
    while k >= 8 {
        let v = t[k];
        t[k - 4] ^= v;
        t[k - 5] ^= v;
        t[k - 7] ^= v;
        t[k - 8] ^= v;
        k -= 1;
    }
    let mut out = [0u64; 8];
    out.copy_from_slice(&t[..8]);
    out
}

/// `x^254`, which is the inverse for non-zero `x` and zero for zero.
fn inv(a: &Planes) -> Planes {
    let mut r = *a;
    let mut bit = 6i32;
    while bit >= 0 {
        r = square(&r);
        if bit > 0 {
            r = mul(&r, a);
        }
        bit -= 1;
    }
    r
}

/// The AES forward S-box.
///
/// The affine step is `y ^ rotl(y,1) ^ rotl(y,2) ^ rotl(y,3) ^ rotl(y,4) ^
/// 0x63`. Rotating a byte permutes its bits, so on planes it is a rotation of
/// the plane *indices* and costs nothing but the xors. The constant is a plane
/// of all ones wherever its bit is set, which is a complement.
fn sbox(a: &Planes) -> Planes {
    let y = inv(a);
    let mut out = [0u64; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = y[i] ^ y[(i + 7) % 8] ^ y[(i + 6) % 8] ^ y[(i + 5) % 8] ^ y[(i + 4) % 8];
    }
    // 0x63 = 0b0110_0011.
    for i in [0, 1, 5, 6] {
        out[i] = !out[i];
    }
    out
}

/// `x * 2` in GF(2^8), on planes: a shift of the plane indices, with the
/// overflow folded back in through `0x1b`.
fn xtime(a: &Planes) -> Planes {
    [
        a[7],
        a[0] ^ a[7],
        a[1],
        a[2] ^ a[7],
        a[3] ^ a[7],
        a[4],
        a[5],
        a[6],
    ]
}

/// Low bit of each nibble; a nibble is one four-byte AES column.
const NIBBLE_LOW: u64 = 0x1111_1111_1111_1111;

/// Rotate the bytes of each column by one, so position `r` takes what was at
/// `r + 1`.
///
/// A byte is one bit in a plane and a column is four consecutive bytes, so a
/// column is a nibble and this is a nibble-wise rotation.
fn rotate_column(v: u64) -> u64 {
    ((v >> 1) & 0x7777_7777_7777_7777) | ((v & NIBBLE_LOW) << 3)
}

/// MixColumns.
///
/// Written as `xtime(a) ^ xtime(R a) ^ R a ^ R^2 a ^ R^3 a`, where `R` is
/// [`rotate_column`]. Those are the same four output expressions the
/// byte-at-a-time version has, with the position within the column folded into
/// `R` so all four are computed at once.
fn mix_columns(a: &Planes) -> Planes {
    let r1 = a.map(rotate_column);
    let r2 = r1.map(rotate_column);
    let r3 = r2.map(rotate_column);
    let xa = xtime(a);
    let xr1 = xtime(&r1);
    let mut out = [0u64; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = xa[i] ^ xr1[i] ^ r1[i] ^ r2[i] ^ r3[i];
    }
    out
}

/// ShiftRows.
///
/// Row `r` of the column-major state occupies the byte positions congruent to
/// `r` modulo four, and rotates towards lower column indices by `r`. A byte is
/// one bit and a block is sixteen bits, so that is a rotation by `4r` within
/// each sixteen-bit group, applied to the bits that row owns.
fn shift_rows(a: &Planes) -> Planes {
    let mut out = [0u64; 8];
    for (slot, &v) in out.iter_mut().zip(a.iter()) {
        // Row 0 does not move.
        let mut acc = v & NIBBLE_LOW;
        for r in 1..4u32 {
            let row = v & (NIBBLE_LOW << r);
            let s = 4 * r;
            // A bit whose position within its sixteen-bit group is below `s`
            // wraps to the top of that group; the rest simply move down.
            let m = (1u64 << s) - 1;
            let low_mask = m | (m << 16) | (m << 32) | (m << 48);
            let lo = row & low_mask;
            let hi = row & !low_mask;
            acc |= (hi >> s) | (lo << (16 - s));
        }
        *slot = acc;
    }
    out
}

/// The round keys, transposed once so the round loop does not transpose them.
pub struct RoundKeys {
    planes: [Planes; 15],
    rounds: usize,
}

impl RoundKeys {
    /// Transpose every round key of `sched`.
    ///
    /// A round key is the same sixteen bytes for all four lanes, so it is
    /// repeated across the group before transposing. Done once per call rather
    /// than once per group, which is why it is worth doing at all.
    pub fn new(sched: &Schedule) -> Self {
        let mut planes = [[0u64; 8]; 15];
        for (r, slot) in planes.iter_mut().enumerate().take(sched.rounds + 1) {
            let rk = sched.round_key(r);
            let mut wide = [0u8; GROUP];
            for lane in 0..LANES {
                wide[lane * BLOCK_LEN..(lane + 1) * BLOCK_LEN].copy_from_slice(rk);
            }
            *slot = transpose_in(&wide);
        }
        Self {
            planes,
            rounds: sched.rounds,
        }
    }
}

/// Encrypt exactly [`GROUP`] bytes in place.
pub fn encrypt_group(keys: &RoundKeys, data: &mut [u8]) {
    debug_assert_eq!(data.len(), GROUP);
    let mut s = transpose_in(data);

    for (slot, k) in s.iter_mut().zip(keys.planes[0].iter()) {
        *slot ^= k;
    }
    for r in 1..keys.rounds {
        s = sbox(&s);
        s = shift_rows(&s);
        s = mix_columns(&s);
        for (slot, k) in s.iter_mut().zip(keys.planes[r].iter()) {
            *slot ^= k;
        }
    }
    s = sbox(&s);
    s = shift_rows(&s);
    for (slot, k) in s.iter_mut().zip(keys.planes[keys.rounds].iter()) {
        *slot ^= k;
    }

    transpose_out(&s, data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf;

    /// Pack 64 byte values into planes, run `f`, and read the bytes back.
    fn through<F: Fn(&Planes) -> Planes>(vals: &[u8; GROUP], f: F) -> [u8; GROUP] {
        let out_planes = f(&transpose_in(vals));
        let mut out = [0u8; GROUP];
        transpose_out(&out_planes, &mut out);
        out
    }

    /// `transpose8` against the obvious double loop.
    ///
    /// The masked-swap form is the one place here where the code does not look
    /// like what it computes, so it is checked against a version that does.
    #[test]
    fn the_byte_transpose_matches_a_naive_one() {
        fn naive(x: u64) -> u64 {
            let mut r = 0u64;
            for j in 0..8 {
                for i in 0..8 {
                    if (x >> (8 * j + i)) & 1 == 1 {
                        r |= 1 << (8 * i + j);
                    }
                }
            }
            r
        }
        for b in 0..64 {
            let v = 1u64 << b;
            assert_eq!(transpose8(v), naive(v), "single bit {b}");
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let v = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
            assert_eq!(transpose8(v), naive(v), "word {v:#018x}");
        }
    }

    /// The transpose is its own inverse, for every byte pattern that matters.
    ///
    /// Everything below reads its answer back through `transpose_out`, so a
    /// transpose that lost or moved a bit would make the other tests agree
    /// about the wrong thing.
    #[test]
    fn transposing_round_trips() {
        let mut v = [0u8; GROUP];
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        assert_eq!(through(&v, |p| *p), v);

        // One bit set at a time, across every byte and every bit, so a
        // transpose that swapped two positions cannot hide behind a pattern.
        for byte in 0..GROUP {
            for bit in 0..8 {
                let mut one = [0u8; GROUP];
                one[byte] = 1 << bit;
                assert_eq!(through(&one, |p| *p), one, "byte {byte} bit {bit}");
            }
        }
    }

    /// Bitsliced squaring against the byte-at-a-time multiply, over the whole
    /// domain.
    #[test]
    fn squaring_matches_the_byte_at_a_time_path() {
        for base in (0..=255u16).step_by(GROUP) {
            let mut vals = [0u8; GROUP];
            for (i, slot) in vals.iter_mut().enumerate() {
                *slot = (base as usize + i).min(255) as u8;
            }
            let got = through(&vals, square);
            for (i, &v) in vals.iter().enumerate() {
                assert_eq!(got[i], gf::mul(v, v), "square({v:#04x})");
            }
        }
    }

    /// Bitsliced multiplication against the byte-at-a-time one, over all
    /// 65536 pairs.
    ///
    /// Not a sample. GF(2^8) has 256 elements, so this is every pair of inputs
    /// the routine can ever be given, checked against the implementation the
    /// FIPS-197 vectors already validate.
    #[test]
    fn field_multiply_matches_the_byte_at_a_time_one() {
        for a in 0..=255u8 {
            let a_vals = [a; GROUP];
            let a_planes = transpose_in(&a_vals);
            for chunk in 0..(256 / GROUP) {
                let mut b_vals = [0u8; GROUP];
                for (i, slot) in b_vals.iter_mut().enumerate() {
                    *slot = (chunk * GROUP + i) as u8;
                }
                let planes = mul(&a_planes, &transpose_in(&b_vals));
                let mut got = [0u8; GROUP];
                transpose_out(&planes, &mut got);
                for (i, &b) in b_vals.iter().enumerate() {
                    assert_eq!(got[i], gf::mul(a, b), "{a:#04x} * {b:#04x}");
                }
            }
        }
    }

    /// The S-box, over all 256 inputs.
    #[test]
    fn sbox_matches_the_byte_at_a_time_path() {
        for chunk in 0..(256 / GROUP) {
            let mut vals = [0u8; GROUP];
            for (i, slot) in vals.iter_mut().enumerate() {
                *slot = (chunk * GROUP + i) as u8;
            }
            let got = through(&vals, sbox);
            for (i, &v) in vals.iter().enumerate() {
                assert_eq!(got[i], gf::sbox(v), "sbox({v:#04x})");
            }
        }
    }

    /// Four blocks through the bitsliced path must equal four blocks through
    /// the byte-at-a-time one.
    ///
    /// This is the test that matters: ShiftRows and MixColumns are not exposed
    /// separately, and a rotation applied to the wrong axis would still produce
    /// a permutation, still round-trip through the transpose, and still look
    /// like AES from the outside. Only agreement with the implementation the
    /// published vectors validate rules that out.
    ///
    /// Every key length, and byte patterns rather than one fixed buffer, since
    /// the lanes must stay independent: a bug that mixed lane 1 into lane 2
    /// would be invisible if all four lanes held the same block.
    #[test]
    fn four_blocks_match_the_byte_at_a_time_path() {
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| (i * 11 + 5) as u8).collect();
            let sched = Schedule::expand(&key).unwrap();
            let keys = RoundKeys::new(&sched);

            for case in 0..64u32 {
                let mut data = [0u8; GROUP];
                for (i, slot) in data.iter_mut().enumerate() {
                    *slot = (i as u32)
                        .wrapping_mul(case.wrapping_add(1))
                        .wrapping_add(case) as u8;
                }
                // Distinct lanes: otherwise cross-lane contamination is
                // indistinguishable from correct behaviour.
                let mut want = data;
                for block in want.chunks_exact_mut(BLOCK_LEN) {
                    super::super::portable::encrypt_block(&sched, block).unwrap();
                }
                let mut got = data;
                encrypt_group(&keys, &mut got);
                assert_eq!(got, want, "key_len {key_len}, case {case}");
            }
        }
    }

    /// One lane at a time, with the other three zeroed.
    ///
    /// A cross-lane leak that happens to cancel on structured data will not
    /// cancel here: three of the four blocks have a known answer of their own,
    /// and any bleed from the fourth shows up in them.
    #[test]
    fn lanes_do_not_leak_into_each_other() {
        let key = [0x42u8; 32];
        let sched = Schedule::expand(&key).unwrap();
        let keys = RoundKeys::new(&sched);

        for lane in 0..LANES {
            let mut data = [0u8; GROUP];
            for k in 0..BLOCK_LEN {
                data[lane * BLOCK_LEN + k] = (k as u8).wrapping_mul(37).wrapping_add(1);
            }
            let mut want = data;
            for block in want.chunks_exact_mut(BLOCK_LEN) {
                super::super::portable::encrypt_block(&sched, block).unwrap();
            }
            let mut got = data;
            encrypt_group(&keys, &mut got);
            assert_eq!(got, want, "lane {lane}");
        }
    }
}
