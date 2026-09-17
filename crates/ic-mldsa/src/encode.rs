//! Bit packing: FIPS 204 algorithms 16 through 21.
//!
//! ML-DSA's keys and signatures are dense bit strings, not byte-aligned
//! records. Coefficients are packed at 3, 4, 6, 10, 13, 18 or 20 bits each
//! depending on what they are and which parameter set is in play, little-endian
//! within the stream and with no padding between them until the very end.
//!
//! # The oracle
//!
//! Packing is the classic place to be self-consistently wrong: write the bits
//! backwards and read them back the same way, and a round-trip test passes
//! while nothing interoperates. So the tests here do not rely on round trips.
//! They compare against a bit-at-a-time reference written from the definition
//! in `tests`, which shares no code with the production path — that one
//! accumulates through a 64-bit window, the reference shifts one bit at a time.
//! A round-trip test is *also* present, but as a cheap extra rather than the
//! argument.
//!
//! # Widths are derived
//!
//! Every width here comes from `bitlen` applied to the bound it encodes, not
//! from a table. `T0_BITS` is `bitlen(2^12 * 2 - 1)` because that is what the
//! range of `t0` demands; it is not `13` because a document says `13`. The
//! tests assert the derived values equal the ones FIPS 204 tabulates, which is
//! the one place a transcription is worth having — as a cross-check against a
//! derivation, rather than as the source.
//!
//! # Canonicity
//!
//! [`hint_unpack`] rejects encodings that decode to a valid hint but are not
//! the encoding that [`hint_pack`] would have produced: indices out of order,
//! repeated, or with nonzero padding. A signature scheme whose encoding admits
//! two spellings of one signature has a malleability problem, and the same
//! reject-rather-than-normalize rule applies here as in the DER reader.

use crate::poly::{Poly, N, Q};
use crate::rounding::{bucket_count, D};

/// Bits needed to represent `x`, i.e. `floor(log2(x)) + 1`, with `bitlen(0) = 0`.
pub const fn bitlen(x: u32) -> u32 {
    u32::BITS - x.leading_zeros()
}

/// Bytes a packed polynomial occupies at `bits` bits per coefficient.
///
/// `N` is 256, so this is always a whole number of bytes and the stream never
/// needs terminal padding.
pub const fn packed_len(bits: u32) -> usize {
    N * (bits as usize) / 8
}

/// Width for `t1`, the retained high part of the public key.
///
/// `t` lives in `[0, q)` and `power2round` drops `d` bits, so `t1` is bounded
/// by `2^(bitlen(q-1) - d) - 1`.
pub const T1_BITS: u32 = bitlen((1u32 << (bitlen((Q - 1) as u32) - D)) - 1);

/// Width for `t0`, the dropped low part, which is signed and offset-encoded.
pub const T0_BITS: u32 = bitlen((1u32 << D) - 1);

/// Width for `s1`/`s2` at `eta = 2`.
pub const ETA2_BITS: u32 = bitlen(4);

/// Width for `s1`/`s2` at `eta = 4`.
pub const ETA4_BITS: u32 = bitlen(8);

/// Width for `w1` at a given `gamma2`.
pub const fn w1_bits(gamma2: i32) -> u32 {
    bitlen((bucket_count(gamma2) - 1) as u32)
}

/// Width for `z` at a given `gamma1`.
pub const fn z_bits(gamma1: i32) -> u32 {
    bitlen((2 * gamma1 - 1) as u32)
}

/// FIPS 204 Algorithm 16. Pack unsigned coefficients at `bits` each.
///
/// Bits go out least-significant first, and a coefficient straddles a byte
/// boundary rather than being padded to one. `out` must be exactly
/// [`packed_len`] bytes.
pub fn simple_bit_pack(p: &Poly, bits: u32, out: &mut [u8]) {
    assert_eq!(out.len(), packed_len(bits), "output length");
    assert!(bits > 0 && bits <= 32, "width out of range");

    let mask = if bits == 32 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut window: u64 = 0;
    let mut filled: u32 = 0;
    let mut at = 0;

    for &c in p.c.iter() {
        debug_assert!(c >= 0, "simple_bit_pack takes unsigned coefficients");
        window |= ((c as u64) & mask) << filled;
        filled += bits;
        while filled >= 8 {
            out[at] = (window & 0xff) as u8;
            at += 1;
            window >>= 8;
            filled -= 8;
        }
    }
    debug_assert_eq!(filled, 0, "N*bits is a multiple of 8");
    debug_assert_eq!(at, out.len());
}

/// FIPS 204 Algorithm 18. The inverse of [`simple_bit_pack`].
pub fn simple_bit_unpack(data: &[u8], bits: u32, p: &mut Poly) {
    assert_eq!(data.len(), packed_len(bits), "input length");
    assert!(bits > 0 && bits <= 32, "width out of range");

    let mask = if bits == 32 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut window: u64 = 0;
    let mut filled: u32 = 0;
    let mut at = 0;

    for c in p.c.iter_mut() {
        while filled < bits {
            window |= (data[at] as u64) << filled;
            at += 1;
            filled += 8;
        }
        *c = (window & mask) as i32;
        window >>= bits;
        filled -= bits;
    }
}

/// FIPS 204 Algorithm 17. Pack signed coefficients from `[-a, b]`.
///
/// The encoding stores `b - w`, which maps the range onto `[0, a + b]` and lets
/// the unsigned packer do the work. Note the direction: `b - w`, not `w + a`.
/// Both would be valid offset encodings and only one interoperates.
pub fn bit_pack(p: &Poly, b: i32, bits: u32, out: &mut [u8]) {
    let mut shifted = Poly::ZERO;
    for (o, &c) in shifted.c.iter_mut().zip(p.c.iter()) {
        *o = b - c;
    }
    simple_bit_pack(&shifted, bits, out);
}

/// FIPS 204 Algorithm 19. The inverse of [`bit_pack`].
pub fn bit_unpack(data: &[u8], b: i32, bits: u32, p: &mut Poly) {
    simple_bit_unpack(data, bits, p);
    for c in p.c.iter_mut() {
        *c = b - *c;
    }
}

/// FIPS 204 Algorithm 20. Pack a vector of hint polynomials.
///
/// The format is not a bitmap. It is `omega` index bytes followed by `k`
/// cumulative counts: the indices of every set hint, concatenated in order, and
/// then for each polynomial the running total of how many have been written by
/// the end of it. That is what makes the size depend on `omega` rather than on
/// `k * 256 / 8`.
///
/// Returns `false` without writing anything if the total weight exceeds
/// `omega`, which is the condition signing restarts on.
#[must_use = "a false return means the hint weight exceeded omega"]
pub fn hint_pack(hints: &[[bool; N]], omega: usize, out: &mut [u8]) -> bool {
    let k = hints.len();
    assert_eq!(out.len(), omega + k, "output length");

    if hints.iter().flatten().filter(|h| **h).count() > omega {
        return false;
    }

    for byte in out.iter_mut() {
        *byte = 0;
    }
    let mut index = 0;
    for (i, poly) in hints.iter().enumerate() {
        for (j, set) in poly.iter().enumerate() {
            if *set {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[omega + i] = index as u8;
    }
    true
}

/// FIPS 204 Algorithm 21. The inverse of [`hint_pack`], rejecting
/// non-canonical encodings.
///
/// Three things are checked beyond "does it decode":
///
/// 1. The cumulative counts never decrease and never exceed `omega`.
/// 2. Indices within one polynomial strictly increase, which forbids both
///    repeats and any order other than the one [`hint_pack`] emits.
/// 3. Every index byte past the last used one is zero.
///
/// Dropping any of the three would leave several byte strings decoding to the
/// same hint vector, so a signature could be rewritten without invalidating it.
/// Whether that is exploitable depends on what the caller does with the bytes,
/// which is exactly why it is not this layer's call to make.
#[must_use = "a false return means the encoding was rejected"]
pub fn hint_unpack(data: &[u8], omega: usize, hints: &mut [[bool; N]]) -> bool {
    let k = hints.len();
    if data.len() != omega + k {
        return false;
    }

    for poly in hints.iter_mut() {
        *poly = [false; N];
    }

    let mut index = 0usize;
    for (i, poly) in hints.iter_mut().enumerate() {
        let end = data[omega + i] as usize;
        if end < index || end > omega {
            return false;
        }
        let mut last: Option<u8> = None;
        for &j in &data[index..end] {
            // Strictly increasing: rejects repeats and reordering together.
            if let Some(prev) = last {
                if j <= prev {
                    return false;
                }
            }
            poly[j as usize] = true;
            last = Some(j);
        }
        index = end;
    }

    // Unused index bytes must be zero, or the same hint has many spellings.
    data[index..omega].iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rounding::{GAMMA2_32, GAMMA2_88};

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u32) -> u32 {
            (self.next() % (n as u64)) as u32
        }
    }

    /// The reference, written from the definition and sharing nothing with the
    /// production path.
    ///
    /// This deliberately moves one bit at a time. It is the slowest possible
    /// way to do the job and the easiest to check by eye against the sentence
    /// "bits are emitted least-significant first, coefficient after
    /// coefficient, with no padding".
    fn reference_pack(values: &[i32], bits: u32) -> Vec<u8> {
        let mut out = vec![0u8; values.len() * bits as usize / 8];
        let mut pos = 0usize;
        for &v in values {
            for bit in 0..bits {
                if (v >> bit) & 1 == 1 {
                    out[pos / 8] |= 1 << (pos % 8);
                }
                pos += 1;
            }
        }
        out
    }

    /// The matching reference reader.
    fn reference_unpack(data: &[u8], bits: u32, count: usize) -> Vec<i32> {
        let mut out = Vec::with_capacity(count);
        let mut pos = 0usize;
        for _ in 0..count {
            let mut v = 0i32;
            for bit in 0..bits {
                if (data[pos / 8] >> (pos % 8)) & 1 == 1 {
                    v |= 1 << bit;
                }
                pos += 1;
            }
            out.push(v);
        }
        out
    }

    /// Every width ML-DSA actually uses, so nothing below is tested only at a
    /// convenient size.
    const WIDTHS: [u32; 7] = [3, 4, 6, 10, 13, 18, 20];

    /// The heart of it: the packer must agree with an independently written
    /// reference, not merely with its own reader.
    #[test]
    fn packing_matches_a_bit_at_a_time_reference() {
        let mut rng = Rng(0x0e0c_0de0);
        for bits in WIDTHS {
            let limit = 1u32 << bits;
            for trial in 0..8 {
                let mut p = Poly::ZERO;
                for c in p.c.iter_mut() {
                    *c = match trial {
                        0 => 0,
                        1 => (limit - 1) as i32,
                        2 => 1,
                        3 => (limit / 2) as i32,
                        _ => rng.below(limit) as i32,
                    };
                }
                let mut got = vec![0u8; packed_len(bits)];
                simple_bit_pack(&p, bits, &mut got);
                assert_eq!(
                    got,
                    reference_pack(&p.c, bits),
                    "packing disagrees with the reference at bits={bits} trial={trial}"
                );
            }
        }
    }

    /// And the reader, against the same reference, from reference-produced
    /// bytes — so a shared mistake in the writer cannot hide it.
    #[test]
    fn unpacking_matches_a_bit_at_a_time_reference() {
        let mut rng = Rng(0xdec0_de11);
        for bits in WIDTHS {
            let bytes: Vec<u8> = (0..packed_len(bits))
                .map(|_| rng.below(256) as u8)
                .collect();
            let mut p = Poly::ZERO;
            simple_bit_unpack(&bytes, bits, &mut p);
            assert_eq!(
                p.c.to_vec(),
                reference_unpack(&bytes, bits, N),
                "unpacking disagrees with the reference at bits={bits}"
            );
            // Nothing may exceed the declared width.
            for (i, &c) in p.c.iter().enumerate() {
                assert!(
                    c >= 0 && (c as u32) < (1u32 << bits),
                    "coefficient {i} out of range at bits={bits}: {c}"
                );
            }
        }
    }

    /// Alternating and walking-bit patterns, which catch byte-order errors that
    /// uniform random data can mask.
    #[test]
    fn packing_survives_adversarial_bit_patterns() {
        for bits in WIDTHS {
            let limit = 1u32 << bits;
            let mut patterns: Vec<Vec<i32>> = Vec::new();

            // Every single bit set, in turn, at every coefficient position.
            for bit in 0..bits {
                let mut v = vec![0i32; N];
                v[0] = 1 << bit;
                v[N - 1] = 1 << bit;
                v[N / 2] = 1 << bit;
                patterns.push(v);
            }
            // Alternating extremes.
            patterns.push(
                (0..N)
                    .map(|i| if i % 2 == 0 { 0 } else { (limit - 1) as i32 })
                    .collect(),
            );
            // A ramp, which makes an off-by-one coefficient index obvious.
            patterns.push((0..N).map(|i| (i as u32 % limit) as i32).collect());

            for (n, values) in patterns.iter().enumerate() {
                let mut p = Poly::ZERO;
                p.c.copy_from_slice(values);
                let mut got = vec![0u8; packed_len(bits)];
                simple_bit_pack(&p, bits, &mut got);
                assert_eq!(
                    got,
                    reference_pack(values, bits),
                    "pattern {n} at bits={bits}"
                );

                let mut back = Poly::ZERO;
                simple_bit_unpack(&got, bits, &mut back);
                assert_eq!(
                    back.c.to_vec(),
                    *values,
                    "round trip, pattern {n} at bits={bits}"
                );
            }
        }
    }

    /// The signed form, including the direction of the offset.
    ///
    /// `b - w` and `w + a` are both offset encodings onto the same range and
    /// only one interoperates, so this pins which by checking the packed bits
    /// against the reference applied to `b - w` explicitly.
    #[test]
    fn signed_packing_uses_b_minus_w_and_round_trips() {
        let mut rng = Rng(0x5137_ed00);
        // (a, b, bits) for each real use: eta=2, eta=4, t0, z at both gamma1.
        for (a, b, bits) in [
            (2i32, 2i32, ETA2_BITS),
            (4, 4, ETA4_BITS),
            ((1 << (D - 1)) - 1, 1 << (D - 1), T0_BITS),
            ((1 << 17) - 1, 1 << 17, z_bits(1 << 17)),
            ((1 << 19) - 1, 1 << 19, z_bits(1 << 19)),
        ] {
            let mut p = Poly::ZERO;
            for c in p.c.iter_mut() {
                *c = rng.below((a + b + 1) as u32) as i32 - a;
            }
            // Include both endpoints, which is where an offset error shows.
            p.c[0] = -a;
            p.c[1] = b;

            let mut got = vec![0u8; packed_len(bits)];
            bit_pack(&p, b, bits, &mut got);

            let shifted: Vec<i32> = p.c.iter().map(|c| b - c).collect();
            assert_eq!(
                got,
                reference_pack(&shifted, bits),
                "signed packing must store b - w, at a={a} b={b}"
            );

            let mut back = Poly::ZERO;
            bit_unpack(&got, b, bits, &mut back);
            assert_eq!(back.c, p.c, "signed round trip at a={a} b={b}");
        }
    }

    /// The widths, derived here and tabulated in FIPS 204.
    ///
    /// This is the one place a transcription earns its keep: as a check on a
    /// derivation rather than as the source of the number.
    #[test]
    fn the_derived_widths_match_the_tabulated_ones() {
        assert_eq!(bitlen(0), 0);
        assert_eq!(bitlen(1), 1);
        assert_eq!(bitlen(15), 4);
        assert_eq!(bitlen(16), 5);

        assert_eq!(T1_BITS, 10, "t1 is packed at ten bits");
        assert_eq!(T0_BITS, 13, "t0 is packed at thirteen bits");
        assert_eq!(ETA2_BITS, 3, "eta = 2 needs three bits");
        assert_eq!(ETA4_BITS, 4, "eta = 4 needs four bits");
        assert_eq!(w1_bits(GAMMA2_88), 6, "ML-DSA-44");
        assert_eq!(w1_bits(GAMMA2_32), 4, "ML-DSA-65 and ML-DSA-87");
        assert_eq!(z_bits(1 << 17), 18, "gamma1 = 2^17");
        assert_eq!(z_bits(1 << 19), 20, "gamma1 = 2^19");

        // And the sizes those widths imply, which are what the standard's
        // key and signature lengths are built from.
        assert_eq!(packed_len(T1_BITS), 320);
        assert_eq!(packed_len(T0_BITS), 416);
        assert_eq!(packed_len(ETA2_BITS), 96);
        assert_eq!(packed_len(ETA4_BITS), 128);
        assert_eq!(packed_len(w1_bits(GAMMA2_32)), 128);
        assert_eq!(packed_len(z_bits(1 << 19)), 640);
    }

    /// `w1` must fit the width chosen for it, for every possible input.
    ///
    /// The width comes from `bucket_count`, and `decompose` is what produces
    /// the values. If those two ever disagree the encoding silently truncates,
    /// so the link is asserted rather than assumed.
    #[test]
    fn every_w1_value_fits_its_width() {
        for gamma2 in [GAMMA2_88, GAMMA2_32] {
            let bits = w1_bits(gamma2);
            for r in (0..Q).step_by(1009) {
                let hi = crate::rounding::high_bits(r, gamma2);
                assert!(
                    hi >= 0 && (hi as u32) < (1u32 << bits),
                    "w1 = {hi} does not fit {bits} bits at gamma2={gamma2}"
                );
            }
        }
    }

    fn sample_hints(rng: &mut Rng, k: usize, weight: usize) -> Vec<[bool; N]> {
        let mut hints = vec![[false; N]; k];
        let mut placed = 0;
        while placed < weight {
            let i = rng.below(k as u32) as usize;
            let j = rng.below(N as u32) as usize;
            if !hints[i][j] {
                hints[i][j] = true;
                placed += 1;
            }
        }
        hints
    }

    #[test]
    fn hints_round_trip_at_every_parameter_set() {
        let mut rng = Rng(0x4141_4141);
        for (k, omega) in [(4usize, 80usize), (6, 55), (8, 75)] {
            for weight in [0, 1, 2, omega / 2, omega] {
                let hints = sample_hints(&mut rng, k, weight);
                let mut packed = vec![0u8; omega + k];
                assert!(
                    hint_pack(&hints, omega, &mut packed),
                    "k={k} weight={weight}"
                );

                let mut back = vec![[false; N]; k];
                assert!(
                    hint_unpack(&packed, omega, &mut back),
                    "unpack k={k} weight={weight}"
                );
                assert_eq!(back, hints, "k={k} weight={weight}");
            }
        }
    }

    /// Exceeding `omega` must be reported, not truncated.
    ///
    /// This is the condition ML-DSA's signing loop restarts on, so a silent
    /// truncation here would produce a signature that cannot verify rather than
    /// a retry.
    #[test]
    fn too_many_hints_is_refused() {
        let mut rng = Rng(0x9999);
        let (k, omega) = (6usize, 55usize);
        let hints = sample_hints(&mut rng, k, omega + 1);
        let mut packed = vec![0u8; omega + k];
        assert!(!hint_pack(&hints, omega, &mut packed));
    }

    /// The canonicity rules, each violated on its own.
    ///
    /// A signature scheme whose encoding has two spellings of one signature is
    /// malleable. Each of these byte strings decodes to a perfectly sensible
    /// hint vector and must still be refused, because none of them is what
    /// `hint_pack` would have emitted.
    #[test]
    fn non_canonical_hint_encodings_are_refused() {
        let mut rng = Rng(0x2b2b);
        let (k, omega) = (6usize, 55usize);
        let hints = sample_hints(&mut rng, k, 12);
        let mut good = vec![0u8; omega + k];
        assert!(hint_pack(&hints, omega, &mut good));
        let mut scratch = vec![[false; N]; k];
        assert!(
            hint_unpack(&good, omega, &mut scratch),
            "the baseline is valid"
        );

        let first_count = good[omega] as usize;
        assert!(
            first_count >= 2,
            "the fixture needs a polynomial with two hints"
        );

        // Indices swapped: same set, different order.
        let mut swapped = good.clone();
        swapped.swap(0, 1);
        assert!(
            !hint_unpack(&swapped, omega, &mut scratch),
            "out-of-order indices must be refused"
        );

        // A repeated index.
        let mut repeated = good.clone();
        repeated[1] = repeated[0];
        assert!(
            !hint_unpack(&repeated, omega, &mut scratch),
            "a repeated index must be refused"
        );

        // Nonzero padding past the last used index.
        let total = good[omega + k - 1] as usize;
        assert!(total < omega, "the fixture needs spare index bytes");
        let mut padded = good.clone();
        padded[total] = 0xff;
        assert!(
            !hint_unpack(&padded, omega, &mut scratch),
            "nonzero padding must be refused"
        );

        // A decreasing cumulative count.
        let mut backwards = good.clone();
        backwards[omega + k - 1] = 0;
        assert!(
            !hint_unpack(&backwards, omega, &mut scratch),
            "a decreasing count must be refused"
        );

        // A count past omega.
        let mut overlong = good.clone();
        overlong[omega + k - 1] = (omega + 1) as u8;
        assert!(
            !hint_unpack(&overlong, omega, &mut scratch),
            "a count beyond omega must be refused"
        );

        // And the wrong length entirely.
        assert!(!hint_unpack(&good[..good.len() - 1], omega, &mut scratch));
    }

    /// Whatever `hint_unpack` accepts must re-encode to exactly what it was
    /// given — the fixed-point property the DER reader is held to.
    ///
    /// This is stronger than the enumerated rejections above: those test the
    /// mistakes I thought of, and this tests the ones I did not.
    #[test]
    fn accepted_hint_encodings_are_a_fixed_point() {
        let mut rng = Rng(0x7e57_0001);
        let (k, omega) = (6usize, 55usize);
        let mut accepted = 0;

        for _ in 0..4000 {
            let mut candidate = vec![0u8; omega + k];
            // Mostly structured, so acceptance is not vanishingly rare, with
            // enough noise to reach cases the rules above do not name.
            let weight = rng.below(10) as usize;
            let hints = sample_hints(&mut rng, k, weight);
            // The weight is below omega by construction, so this cannot
            // fail; asserting says so rather than discarding the answer.
            assert!(hint_pack(&hints, omega, &mut candidate));
            for _ in 0..rng.below(3) {
                let at = rng.below(candidate.len() as u32) as usize;
                candidate[at] = rng.below(256) as u8;
            }

            let mut decoded = vec![[false; N]; k];
            if !hint_unpack(&candidate, omega, &mut decoded) {
                continue;
            }
            accepted += 1;
            let mut reencoded = vec![0u8; omega + k];
            assert!(hint_pack(&decoded, omega, &mut reencoded));
            assert_eq!(
                reencoded, candidate,
                "an accepted encoding must be the one hint_pack produces"
            );
        }

        // Without this the test could pass by rejecting everything, which is
        // the failure mode that made the PKIX fuzzer useless the first time.
        assert!(
            accepted > 500,
            "the generator must actually reach acceptance: {accepted} of 4000"
        );
    }
}
