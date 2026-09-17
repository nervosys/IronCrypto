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

/// `Compress_d(x)`, FIPS 203 equation 4.7.
///
/// Defined as `round((2^d / q) * x) mod 2^d`. Written with integer arithmetic
/// so the rounding is exact and the timing does not depend on the value: a
/// floating-point version would round differently on different targets, and a
/// data-dependent branch would leak the coefficient.
#[inline]
pub fn compress(x: i16, d: u32) -> u16 {
    debug_assert!((1..=12).contains(&d));
    // x is assumed already in [0, q).
    let x = x as u32;
    let shifted = (x << d) + (Q as u32) / 2;
    ((shifted / (Q as u32)) & ((1u32 << d) - 1)) as u16
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
pub fn byte_encode(p: &Poly, d: u32, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d as usize);
    for byte in out.iter_mut() {
        *byte = 0;
    }
    let mut bit = 0usize;
    for coefficient in p.c.iter() {
        let value = *coefficient as u16;
        for b in 0..d as usize {
            let set = ((value >> b) & 1) as u8;
            out[(bit + b) / 8] |= set << ((bit + b) % 8);
        }
        bit += d as usize;
    }
}

/// `ByteDecode_d`: the inverse of [`byte_encode`].
///
/// For `d < 12` every bit pattern is a valid coefficient. For `d = 12` a
/// decoded value can land in `[q, 4096)`, which FIPS 203 reduces modulo `q`;
/// that case is the one where a decoder that skips the reduction accepts keys
/// another implementation would reject.
pub fn byte_decode(data: &[u8], d: u32, out: &mut Poly) {
    debug_assert_eq!(data.len(), 32 * d as usize);
    let mut bit = 0usize;
    for coefficient in out.c.iter_mut() {
        let mut value = 0u16;
        for b in 0..d as usize {
            let set = (data[(bit + b) / 8] >> ((bit + b) % 8)) & 1;
            value |= (set as u16) << b;
        }
        bit += d as usize;
        *coefficient = if d == 12 {
            (value % (Q as u16)) as i16
        } else {
            value as i16
        };
    }
}

/// Compress every coefficient and pack the result.
pub fn compress_encode(p: &Poly, d: u32, out: &mut [u8]) {
    let mut compressed = Poly::ZERO;
    for (dst, src) in compressed.c.iter_mut().zip(p.c.iter()) {
        *dst = compress(*src, d) as i16;
    }
    byte_encode(&compressed, d, out);
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

    /// Compression against the formula, computed independently with 64-bit
    /// arithmetic so no intermediate can overflow differently.
    #[test]
    fn compression_matches_the_formula() {
        for d in 1..=11u32 {
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
