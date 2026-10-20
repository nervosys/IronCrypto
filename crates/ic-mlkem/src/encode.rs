//! Byte packing and lossy compression (FIPS 203 sections 4.2.1 and 4.2.2).
//!
//! ML-KEM moves polynomials over the wire as tightly packed bit fields, and
//! shrinks the ciphertext by throwing away low-order bits of each coefficient.
//! Both operations are pure index arithmetic, and both are places where an
//! implementation can be self-consistent and wrong: pack and unpack with the
//! same bit order and you round-trip perfectly while agreeing with nobody.
//!
//! So the tests do not round-trip. They rebuild each function from the
//! specification's own definition — a plain bit-at-a-time buffer for the
//! packing, and integer arithmetic straight from the formula for the
//! compression — and require agreement.
//!
//! # Compression is not a bijection
//!
//! `Compress_d` maps `Z_q` onto `d` bits and `Decompress_d` maps back. The
//! round trip is deliberately lossy; what the scheme needs is that the error
//! stays below a bound, which is what makes decryption succeed despite the
//! noise. `decompression_error_is_bounded` checks that bound directly
//! rather than assuming it.

use crate::poly::{Poly, N, Q};
use core::hint::black_box;

/// `Compress_d(x)`, FIPS 203 equation 4.7.
///
/// Defined as `round((2^d / q) * x) mod 2^d`. Written with integer arithmetic
/// so the rounding is exact: a floating-point version would round differently
/// on different targets.
///
/// # No division
///
/// The quotient by `q` is an estimate by multiplication, corrected once by a
/// mask. It used to be `/ q`, and the comment here said its timing did not
/// depend on the value. On most targets the compiler does turn division by a
/// constant into a multiplication -- but Cortex-M0 has no instruction for the
/// high half of a product, so there it called the library's division routine,
/// whose time depends on the dividend: the KyberSlash channel, on the
/// ciphertext `decapsulate` recomputes from secret data. Found reading the
/// compiled code. The multiplication below needs only the low 32 bits.
#[inline]
pub fn compress(x: i16, d: u32) -> u16 {
    debug_assert!((1..=12).contains(&d));
    // x is assumed already in [0, q), so t is below 2^24.
    let t = ((x as u32) << d) + (Q as u32) / 2;
    // 40318 = ceil(2^27 / q) (this said floor; the floor is 40317, and the
    // proof in `encode/proofs.rs` holds for either). (t >> 8) is below 2^16,
    // so the product is below 2^32, and the estimate is floor(t / q) or one
    // less -- the tests check every x and d, and so does the proof.
    let mut e = ((t >> 8) * 40318) >> 19;
    let r = t - e * (Q as u32);
    // One more if the remainder reached q.
    // LTO can turn this 0/1 correction into a branch on Cortex-M0. The
    // barriers hide both the subtraction's range and the correction's range.
    // An output-only barrier still lets LLVM branch to construct the bit.
    e += black_box(black_box((Q as u32 - 1).wrapping_sub(r)) >> 31);
    (e & ((1u32 << d) - 1)) as u16
}

/// `Decompress_d(y)`, FIPS 203 equation 4.8: `round((q / 2^d) * y)`.
#[inline]
pub fn decompress(y: u16, d: u32) -> i16 {
    debug_assert!((1..=12).contains(&d));
    let y = y as u32;
    (((y * (Q as u32)) + (1 << (d - 1))) >> d) as i16
}

/// `ByteEncode_d`: pack 256 coefficients of `d` bits each into `32 * d` bytes.
///
/// Little-endian bit order: coefficient 0 occupies the low `d` bits of the
/// output, and each subsequent coefficient continues from where the last one
/// stopped, crossing byte boundaries freely.
///
/// # Eight at a time
///
/// Eight coefficients of `d` bits are exactly `d` bytes, so a polynomial is 32
/// groups that each start on a byte boundary. A group is packed into one
/// integer with shifts the compiler knows, for each width ML-KEM uses, and
/// written out whole. This used to set one bit per trip round a loop, at a
/// division and a remainder per bit -- about a microsecond per polynomial,
/// twice an NTT. Only the low `d` bits of each coefficient are kept, as
/// before.
pub fn byte_encode(p: &Poly, d: u32, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d as usize);
    match d {
        1 => encode_groups::<1>(p, out),
        4 => encode_groups::<4>(p, out),
        5 => encode_groups::<5>(p, out),
        10 => encode_groups::<10>(p, out),
        11 => encode_groups::<11>(p, out),
        12 => encode_groups::<12>(p, out),
        _ => encode_bits(p, d, out),
    }
}

fn encode_groups<const D: usize>(p: &Poly, out: &mut [u8]) {
    for (group, bytes) in p.c.chunks_exact(8).zip(out.chunks_exact_mut(D)) {
        let mut eight = [0i16; 8];
        eight.copy_from_slice(group);
        bytes.copy_from_slice(&pack8::<D>(&eight)[..D]);
    }
}

/// Eight `D`-bit fields, packed little-endian into the low `D` bytes.
///
/// Public only so that `scripts/check-ct.py` can inspect it; not API.
#[doc(hidden)]
#[inline]
pub fn pack8<const D: usize>(v: &[i16; 8]) -> [u8; 16] {
    let mask = (1u128 << D) - 1;
    let mut acc = 0u128;
    for (k, x) in v.iter().enumerate() {
        acc |= ((*x as u16 as u128) & mask) << (D * k);
    }
    acc.to_le_bytes()
}

/// Eight `D`-bit fields from the low `D` bytes of `bytes`.
///
/// Public only so that `scripts/check-ct.py` can inspect it; not API.
#[doc(hidden)]
#[inline]
pub fn unpack8<const D: usize>(bytes: &[u8; 16]) -> [u16; 8] {
    // Two 64-bit words and scalar shifts, not one `u128`: LLVM lowered the
    // `u128` form to `movsd`, `andpd` and `movupd` on the secret bytes, which
    // Intel's Data Operand Independent Timing list does not cover. `D` and
    // `k` are constants, so each branch below is resolved at compile time.
    let (head, tail) = bytes.split_at(8);
    let lo = u64::from_le_bytes([
        head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
    ]);
    let hi = u64::from_le_bytes([
        tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
    ]);
    let mask = (1u64 << D) - 1;
    core::array::from_fn(|k| {
        let at = D * k;
        let field = if at + D <= 64 {
            lo >> at
        } else if at >= 64 {
            hi >> (at - 64)
        } else {
            (lo >> at) | (hi << (64 - at))
        };
        (field & mask) as u16
    })
}

/// The width-generic form, for the widths ML-KEM never packs at.
fn encode_bits(p: &Poly, d: u32, out: &mut [u8]) {
    let mask = (1u32 << d) - 1;
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut at = 0usize;
    for coefficient in p.c.iter() {
        acc |= ((*coefficient as u16 as u32) & mask) << bits;
        bits += d;
        while bits >= 8 {
            out[at] = acc as u8;
            at += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// `ByteDecode_d`: the inverse of [`byte_encode`].
///
/// For `d < 12` every bit pattern is a valid coefficient. For `d = 12` a
/// decoded value can land in `[q, 4096)`, which FIPS 203 reduces modulo `q`;
/// that case is the one where a decoder that skips the reduction accepts keys
/// another implementation would reject.
///
/// The reduction is [`reduce_12`], a subtraction and a mask. It was `% q`, on
/// what is, for a decapsulation key, the secret vector.
#[allow(unsafe_code)]
pub fn byte_decode(data: &[u8], d: u32, out: &mut Poly) {
    debug_assert_eq!(data.len(), 32 * d as usize);
    match d {
        1 => decode_groups::<1>(data, out),
        4 => decode_groups::<4>(data, out),
        5 => decode_groups::<5>(data, out),
        10 => decode_groups::<10>(data, out),
        11 => decode_groups::<11>(data, out),
        12 => {
            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            if let (true, Ok(bytes)) = (crate::poly::avx2(), <&[u8; 384]>::try_from(data)) {
                // SAFETY: `avx2()` is the feature test `avx2::decode12` requires.
                unsafe { crate::avx2::decode12(bytes, &mut out.c) };
                return;
            }
            decode_twelve(data, out);
        }
        _ => decode_bits(data, d, out),
    }
}

/// `ByteDecode_12` and its reduction, eight coefficients at a time.
fn decode_twelve(data: &[u8], out: &mut Poly) {
    decode_groups::<12>(data, out);
    for c in out.c.iter_mut() {
        *c = reduce_12(*c as u16);
    }
}

/// Whether every twelve-bit field of an encoded vector is below `q`.
///
/// This is FIPS 203's modulus check, `ByteEncode_12(ByteDecode_12(x)) == x`,
/// in the form that does not need the round trip: a field below `q` decodes
/// to itself and re-encodes to the same bits, and a field at or above `q`
/// decodes to itself less `q` and re-encodes to different bits. So the round
/// trip reproduces its input exactly when no field reaches `q`.
/// `the_modulus_check_is_the_round_trip` holds the two forms to each other
/// over every field value. `data.len()` must be a multiple of 384; anything
/// else is not an encoded vector and answers `false`.
#[allow(unsafe_code)]
pub(crate) fn all_below_q_12(data: &[u8]) -> bool {
    if !data.len().is_multiple_of(384) {
        return false;
    }
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if crate::poly::avx2() {
        // SAFETY: `avx2()` is the feature test `avx2::all_below_q_12` requires.
        return unsafe { crate::avx2::all_below_q_12(data) };
    }
    all_below_q_12_scalar(data)
}

/// [`all_below_q_12`], eight fields at a time.
fn all_below_q_12_scalar(data: &[u8]) -> bool {
    if !data.len().is_multiple_of(384) {
        return false;
    }
    // Every field is checked whatever the answer; the key is public, but
    // there is no reason for the work to depend on it.
    let mut below = true;
    for bytes in data.chunks_exact(12) {
        let mut buf = [0u8; 16];
        buf[..12].copy_from_slice(bytes);
        for v in unpack8::<12>(&buf) {
            below &= v < Q as u16;
        }
    }
    below
}

fn decode_groups<const D: usize>(data: &[u8], out: &mut Poly) {
    for (bytes, group) in data.chunks_exact(D).zip(out.c.chunks_exact_mut(8)) {
        let mut buf = [0u8; 16];
        buf[..D].copy_from_slice(bytes);
        for (c, v) in group.iter_mut().zip(unpack8::<D>(&buf)) {
            *c = v as i16;
        }
    }
}

fn decode_bits(data: &[u8], d: u32, out: &mut Poly) {
    let mask = (1u32 << d) - 1;
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut at = 0usize;
    for coefficient in out.c.iter_mut() {
        while bits < d {
            acc |= (data[at] as u32) << bits;
            at += 1;
            bits += 8;
        }
        *coefficient = (acc & mask) as i16;
        acc >>= d;
        bits -= d;
    }
}

/// `x mod q` for a twelve-bit `x`, without a division or a branch.
///
/// `x < 4096 < 2q`, so one conditional subtraction suffices, and the
/// condition is the sign bit of the difference rather than a comparison.
/// Public only so that `scripts/check-ct.py` can inspect it; not API.
#[doc(hidden)]
#[inline]
pub fn reduce_12(x: u16) -> i16 {
    // Without the barriers, LTO turns the sign mask back into a comparison
    // and a branch on Cortex-M0 -- found by `scripts/check-ct.py` the day this
    // function was written, as `compress` was before it. The first hides the
    // difference's range, the second the mask's, as there.
    let r = black_box((x & 0x0fff) as i16 - Q);
    r + (black_box(r >> 15) & Q)
}

/// Compress every coefficient and pack the result.
///
/// With AVX2 the compression runs eight coefficients to a register by the
/// same arithmetic as [`compress`]; see `crate::avx2::compress`.
#[allow(unsafe_code)]
pub fn compress_encode(p: &Poly, d: u32, out: &mut [u8]) {
    let mut compressed = Poly::ZERO;
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if crate::poly::avx2() && (1..=12).contains(&d) {
        // SAFETY: `avx2()` is the feature test `avx2::compress` requires.
        unsafe { crate::avx2::compress(&p.c, d, &mut compressed.c) };
        byte_encode(&compressed, d, out);
        return;
    }
    compress_poly(p, d, &mut compressed);
    byte_encode(&compressed, d, out);
}

/// [`compress`] of every coefficient.
fn compress_poly(p: &Poly, d: u32, out: &mut Poly) {
    for (dst, src) in out.c.iter_mut().zip(p.c.iter()) {
        *dst = compress(*src, d) as i16;
    }
}

/// Unpack and decompress.
pub fn decode_decompress(data: &[u8], d: u32, out: &mut Poly) {
    byte_decode(data, d, out);
    for c in out.c.iter_mut() {
        *c = decompress(*c as u16, d);
    }
}

/// Bytes a polynomial occupies at `d` bits per coefficient.
pub const fn encoded_len(d: u32) -> usize {
    32 * d as usize
}

/// Number of coefficients, re-exported so callers need not reach into
/// [`crate::poly`] for a loop bound.
pub const COEFFICIENTS: usize = N;

// Bounded proofs for Kani; see docs/PROOFS.md.
#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// FIPS 203 4.2.1, written as a bit buffer with no cleverness.
    fn reference_encode(values: &[u16], d: u32) -> Vec<u8> {
        let mut bits = Vec::new();
        for v in values {
            for b in 0..d {
                bits.push(((v >> b) & 1) as u8);
            }
        }
        let mut out = vec![0u8; bits.len() / 8];
        for (i, bit) in bits.iter().enumerate() {
            out[i / 8] |= bit << (i % 8);
        }
        out
    }

    fn reference_decode(data: &[u8], d: u32, count: usize) -> Vec<u16> {
        let mut out = Vec::new();
        for i in 0..count {
            let mut v = 0u16;
            for b in 0..d as usize {
                let index = i * d as usize + b;
                let bit = (data[index / 8] >> (index % 8)) & 1;
                v |= (bit as u16) << b;
            }
            out.push(v);
        }
        out
    }

    #[test]
    fn packing_matches_an_independent_bit_buffer() {
        let mut rng = Rng(0xabcd_ef01_2345_6789);
        for d in 1..=12u32 {
            let limit = 1u32 << d;
            let mut p = Poly::ZERO;
            let mut values = Vec::new();
            for c in p.c.iter_mut() {
                let v = (rng.next() % limit as u64) as u16;
                *c = v as i16;
                values.push(v);
            }

            let mut got = vec![0u8; encoded_len(d)];
            byte_encode(&p, d, &mut got);
            assert_eq!(got, reference_encode(&values, d), "byte_encode at d={d}");

            // And decoding agrees, for d < 12 where no reduction applies.
            if d < 12 {
                let mut back = Poly::ZERO;
                byte_decode(&got, d, &mut back);
                let want = reference_decode(&got, d, N);
                for (i, c) in back.c.iter().enumerate() {
                    assert_eq!(*c as u16, want[i], "byte_decode at d={d}, index {i}");
                }
            }
        }
    }

    #[test]
    fn packing_round_trips_at_every_width() {
        let mut rng = Rng(11);
        for d in 1..=11u32 {
            let limit = 1u32 << d;
            let mut p = Poly::ZERO;
            for c in p.c.iter_mut() {
                *c = (rng.next() % limit as u64) as i16;
            }
            let mut packed = vec![0u8; encoded_len(d)];
            byte_encode(&p, d, &mut packed);
            let mut back = Poly::ZERO;
            byte_decode(&packed, d, &mut back);
            assert_eq!(back, p, "round trip at d={d}");
        }
    }

    /// At `d = 12` a decoded value can exceed `q` and must be reduced. A decoder
    /// that skips this accepts encodings a conforming one rejects, which is an
    /// interoperability split rather than a round-trip failure.
    #[test]
    fn twelve_bit_decoding_reduces_modulo_q() {
        // Every coefficient set to 4095, the largest a 12-bit field holds.
        let mut p = Poly::ZERO;
        for c in p.c.iter_mut() {
            *c = 4095;
        }
        let mut packed = vec![0u8; encoded_len(12)];
        byte_encode(&p, 12, &mut packed);

        let mut back = Poly::ZERO;
        byte_decode(&packed, 12, &mut back);
        for c in back.c.iter() {
            assert_eq!(*c, 4095 % Q, "4095 must reduce to {}", 4095 % Q);
            assert!(*c < Q, "a decoded coefficient must be below q");
        }
    }

    /// The AVX2 compression against the scalar one at every `x` in `[0, q)`,
    /// for every width, through `compress_encode` -- which is what selects it.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_avx2_compression_matches_the_scalar_one_everywhere() {
        if !crate::poly::avx2() {
            println!("no AVX2 on this CPU; the vector compression was not exercised");
            return;
        }
        let mut checked = 0;
        for d in 1..=12u32 {
            for base in (0..Q).step_by(N) {
                let mut p = Poly::ZERO;
                for (i, c) in p.c.iter_mut().enumerate() {
                    *c = (base + i as i16).min(Q - 1);
                }
                let mut want = Poly::ZERO;
                compress_poly(&p, d, &mut want);
                let mut got = Poly::ZERO;
                // SAFETY: guarded by the `avx2()` check above.
                #[allow(unsafe_code)]
                unsafe {
                    crate::avx2::compress(&p.c, d, &mut got.c)
                };
                assert_eq!(got, want, "compress at d={d} from {base}");

                let mut packed = vec![0u8; encoded_len(d)];
                compress_encode(&p, d, &mut packed);
                let mut expected = vec![0u8; encoded_len(d)];
                byte_encode(&want, d, &mut expected);
                assert_eq!(packed, expected, "compress_encode at d={d} from {base}");
                checked += 1;
            }
        }
        assert_eq!(checked, 12 * 14, "the comparison did not run");
    }

    /// The modulus check against its definition, the FIPS 203 round trip:
    /// every field value from 0 to 4095, alone in an otherwise valid vector
    /// at a position that moves, and random vectors either side of the
    /// boundary -- through the scalar form and the one this CPU selects.
    #[test]
    fn the_modulus_check_is_the_round_trip() {
        fn round_trip(data: &[u8]) -> bool {
            data.chunks_exact(384).all(|chunk| {
                let mut p = Poly::ZERO;
                byte_decode(chunk, 12, &mut p);
                let mut again = [0u8; 384];
                byte_encode(&p, 12, &mut again);
                again[..] == chunk[..]
            })
        }
        let mut rng = Rng(0x600d_5eed);
        let mut base = vec![0u8; 3 * 384];
        let mut fields = Poly::ZERO;
        for chunk in base.chunks_exact_mut(384) {
            for c in fields.c.iter_mut() {
                *c = (rng.next() % Q as u64) as i16;
            }
            byte_encode(&fields, 12, chunk);
        }
        assert!(round_trip(&base) && all_below_q_12(&base) && all_below_q_12_scalar(&base));

        let mut checked = 0;
        for value in 0..4096u16 {
            let mut data = base.clone();
            let at = (value as usize * 37) % (3 * N);
            let (chunk, index) = (at / N, at % N);
            let mut p = Poly::ZERO;
            for (i, c) in p.c.iter_mut().enumerate() {
                *c = if i == index { value as i16 } else { 0 };
            }
            // Write the one field into the vector, leaving the rest valid.
            let mut one = [0u8; 384];
            byte_encode(&p, 12, &mut one);
            let byte = index * 12 / 8;
            let shift = (index * 12) % 8;
            let mask_lo = (0x0fffu32 << shift) as u16;
            let span = &mut data[chunk * 384 + byte..chunk * 384 + byte + 2];
            let old = u16::from_le_bytes([span[0], span[1]]);
            let new = (old & !mask_lo) | (u16::from_le_bytes([one[byte], one[byte + 1]]) & mask_lo);
            span.copy_from_slice(&new.to_le_bytes());

            let want = round_trip(&data);
            assert_eq!(
                want,
                value < Q as u16,
                "the round trip itself, value {value}"
            );
            assert_eq!(all_below_q_12_scalar(&data), want, "scalar, value {value}");
            assert_eq!(all_below_q_12(&data), want, "selected, value {value}");
            checked += 1;
        }
        assert_eq!(checked, 4096);
        assert!(!all_below_q_12(&base[..383]), "a partial vector is refused");
    }

    /// The AVX2 twelve-bit decode against the scalar one, over every field
    /// value at every position.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_avx2_twelve_bit_decode_matches_the_scalar_one() {
        if !crate::poly::avx2() {
            println!("no AVX2 on this CPU; the vector decode was not exercised");
            return;
        }
        for base in (0u16..4096).step_by(N) {
            let mut p = Poly::ZERO;
            for (i, c) in p.c.iter_mut().enumerate() {
                *c = ((base as usize + i * 17) % 4096) as i16;
            }
            let mut packed = [0u8; 384];
            byte_encode(&p, 12, &mut packed);
            let mut want = Poly::ZERO;
            decode_twelve(&packed, &mut want);
            let mut got = Poly::ZERO;
            // SAFETY: guarded by the `avx2()` check above.
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::decode12(&packed, &mut got.c)
            };
            assert_eq!(got, want, "from {base}");
        }
    }

    /// Every twelve-bit field decodes to itself modulo `q`: the branch-free
    /// reduction against `%`, for all 4096 values rather than only the largest.
    #[test]
    fn twelve_bit_decoding_reduces_every_value() {
        for base in (0u16..4096).step_by(N) {
            let mut p = Poly::ZERO;
            for (i, c) in p.c.iter_mut().enumerate() {
                *c = (base + i as u16) as i16;
            }
            let mut packed = vec![0u8; encoded_len(12)];
            byte_encode(&p, 12, &mut packed);
            let mut back = Poly::ZERO;
            byte_decode(&packed, 12, &mut back);
            for (i, c) in back.c.iter().enumerate() {
                let x = base + i as u16;
                assert_eq!(*c, (x % Q as u16) as i16, "decode of {x}");
            }
        }
    }

    /// Every width, including the ones only the generic path packs, agrees
    /// with the bit buffer -- and keeps only the low `d` bits of a coefficient
    /// that has more, which the group packer does with a mask.
    #[test]
    fn every_width_ignores_bits_above_d() {
        let mut rng = Rng(0x5151);
        for d in 1..=12u32 {
            let mut p = Poly::ZERO;
            let mut values = Vec::new();
            for c in p.c.iter_mut() {
                let v = rng.next() as u16;
                *c = v as i16;
                values.push(v & ((1u16 << d) - 1));
            }
            let mut got = vec![0u8; encoded_len(d)];
            byte_encode(&p, d, &mut got);
            assert_eq!(got, reference_encode(&values, d), "byte_encode at d={d}");
            let mut back = Poly::ZERO;
            byte_decode(&got, d, &mut back);
            let want = reference_decode(&got, d, N);
            for (i, c) in back.c.iter().enumerate() {
                let w = if d == 12 { want[i] % Q as u16 } else { want[i] };
                assert_eq!(*c as u16, w, "byte_decode at d={d}, index {i}");
            }
        }
    }

    /// Compression against the formula, computed independently with 64-bit
    /// arithmetic so no intermediate can overflow differently.
    #[test]
    fn compression_matches_the_formula() {
        for d in 1..=12u32 {
            for x in 0..Q {
                let got = compress(x, d);
                let want = {
                    let num = ((x as i64) << d) + (Q as i64) / 2;
                    ((num / Q as i64) as u64 & ((1u64 << d) - 1)) as u16
                };
                assert_eq!(got, want, "compress({x}, {d})");
            }
        }
    }

    #[test]
    fn decompression_matches_the_formula() {
        for d in 1..=11u32 {
            for y in 0..(1u32 << d) {
                let got = decompress(y as u16, d);
                let want = (((y as i64) * (Q as i64) + (1 << (d - 1))) >> d) as i16;
                assert_eq!(got, want, "decompress({y}, {d})");
            }
        }
    }

    /// The property the scheme actually depends on: compressing and
    /// decompressing moves a coefficient by less than `q / 2^(d+1)`, rounded up.
    /// Decryption succeeds because that error stays under the decision
    /// threshold; if this bound were wrong the scheme would fail at some rate
    /// too low for a round-trip test to notice.
    #[test]
    fn decompression_error_is_bounded() {
        for d in 1..=11u32 {
            let bound = ((Q as f64) / (1u64 << (d + 1)) as f64).ceil() as i32;
            for x in 0..Q {
                let round = decompress(compress(x, d), d) as i32;
                let mut error = (round - x as i32).abs();
                // The ring is cyclic, so an error that wraps is still small.
                if error > Q as i32 / 2 {
                    error = Q as i32 - error;
                }
                assert!(
                    error <= bound,
                    "compress/decompress at d={d} moved {x} by {error}, over the bound {bound}"
                );
            }
        }
    }

    /// One bit of compression keeps only the sign, which is what the message
    /// encoding relies on: a coefficient near zero decompresses to zero and one
    /// near q/2 decompresses to q/2.
    #[test]
    fn one_bit_compression_recovers_the_message_bit() {
        assert_eq!(compress(0, 1), 0);
        assert_eq!(compress(Q / 2, 1), 1);
        assert_eq!(decompress(0, 1), 0);
        assert_eq!(decompress(1, 1), (Q + 1) / 2);

        // Everything in the lower half rounds to 0, the upper half to 1.
        for x in 0..Q {
            let bit = compress(x, 1);
            let near_zero = !(Q / 4..=Q - Q / 4).contains(&x);
            if near_zero {
                assert_eq!(bit, 0, "{x} should compress to 0");
            }
        }
    }

    #[test]
    fn compress_encode_composes_its_parts() {
        let mut rng = Rng(77);
        let mut p = Poly::ZERO;
        for c in p.c.iter_mut() {
            *c = (rng.next() % Q as u64) as i16;
        }
        for d in [4u32, 5, 10, 11] {
            let mut packed = vec![0u8; encoded_len(d)];
            compress_encode(&p, d, &mut packed);

            let mut manual = Poly::ZERO;
            for (dst, src) in manual.c.iter_mut().zip(p.c.iter()) {
                *dst = compress(*src, d) as i16;
            }
            let mut want = vec![0u8; encoded_len(d)];
            byte_encode(&manual, d, &mut want);
            assert_eq!(packed, want, "compress_encode at d={d}");

            let mut back = Poly::ZERO;
            decode_decompress(&packed, d, &mut back);
            for (i, c) in back.c.iter().enumerate() {
                assert_eq!(*c, decompress(compress(p.c[i], d), d), "index {i}");
            }
        }
    }
}
