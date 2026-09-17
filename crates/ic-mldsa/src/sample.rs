//! Sampling from seeds: FIPS 204 algorithms 29 through 34.
//!
//! Four distributions, for four jobs.
//!
//! [`sample_in_ball`] draws the challenge `c`: exactly `tau` coefficients are
//! `±1` and the rest are zero. [`rej_ntt_poly`] draws a uniform ring element
//! for the public matrix `A`. [`rej_bounded_poly`] draws the short secrets `s1`
//! and `s2` from `[-eta, eta]`. [`expand_mask_poly`] draws the masking vector
//! `y` from `(-gamma1, gamma1]`.
//!
//! # Which of these must be constant time
//!
//! Not all of them, and the distinction is not cosmetic.
//!
//! `rej_ntt_poly` rejects candidates and so runs for a data-dependent time.
//! That is fine: its seed `rho` is published in the verification key, and an
//! attacker who learns its timing learns something they were already given.
//!
//! `rej_bounded_poly` also rejects, and its seed is **secret**. FIPS 204 uses
//! rejection sampling here anyway, so the timing leak is in the standard's
//! design rather than in this implementation, and pretending otherwise by
//! writing a constant-time-looking loop would be worse than saying so. What
//! leaks is the number of rejected nibbles, which is a function of the SHAKE
//! output rather than of the sampled value; that is the argument the design
//! rests on, and it is not one this crate is in a position to strengthen.
//!
//! `expand_mask_poly` reads a fixed number of bytes and unpacks them. It is
//! constant time, and it must be — `y` is the mask that hides the secret.
//!
//! `sample_in_ball` runs a rejection loop over positions, but on a seed derived
//! from the message and the commitment, both public by the time it runs.
//!
//! # What the tests check
//!
//! No ACVP vector is wired in, so nothing here has been confirmed to agree with
//! another implementation. What is checked is everything that can be checked
//! without one:
//!
//! - Each sampler is rebuilt in the tests from the specification's pseudocode
//!   over the same SHAKE stream, and required to agree. SHAKE itself is
//!   validated against published FIPS 202 vectors, so what this isolates is the
//!   sampling logic — the rejection rule, the nibble order, the index order.
//! - The *exact* distribution is asserted where it is exactly known.
//!   `rej_bounded_poly` at `eta = 2` is uniform over five values and at
//!   `eta = 4` uniform over nine; a transposed index still yields plausible
//!   small numbers but not the right mass at each point.
//! - `sample_in_ball` is checked for exactly `tau` nonzero coefficients, all
//!   `±1`, over many seeds — its defining property.

use crate::encode::{bit_unpack, packed_len, z_bits};
use crate::poly::{Poly, N, Q};
use ic_core::traits::Xof;
use ic_hash::{Shake128, Shake256, XofReader};

/// Bytes squeezed per rejection round. One SHAKE-128 rate.
const SQUEEZE_CHUNK: usize = 168;

/// `CoeffFromThreeBytes` (FIPS 204 Algorithm 14).
///
/// Twenty-three bits, since `q < 2^23`: the top bit of the third byte is
/// discarded rather than causing a rejection of its own. Candidates at or above
/// `q` are rejected, which is what keeps the result uniform.
fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<i32> {
    let z = ((b2 & 0x7f) as i32) << 16 | (b1 as i32) << 8 | (b0 as i32);
    if z < Q {
        Some(z)
    } else {
        None
    }
}

/// `CoeffFromHalfByte` (FIPS 204 Algorithm 15).
///
/// The two `eta` values use genuinely different rules, not one rule with a
/// parameter. At `eta = 4` the nine values `0..=8` map straight across; at
/// `eta = 2` the fifteen values `0..15` fold modulo five, which is what keeps
/// the result uniform over five outcomes rather than biased toward the middle.
fn coeff_from_half_byte(b: u8, eta: i32) -> Option<i32> {
    match eta {
        2 => {
            if b < 15 {
                Some(2 - (b as i32 % 5))
            } else {
                None
            }
        }
        4 => {
            if b < 9 {
                Some(4 - b as i32)
            } else {
                None
            }
        }
        _ => panic!("eta must be 2 or 4"),
    }
}

/// `SampleInBall` (FIPS 204 Algorithm 29): the challenge polynomial.
///
/// Exactly `tau` coefficients are `±1`, the rest zero. The construction is a
/// partial Fisher-Yates shuffle: the sign bits come from the first eight bytes
/// of the stream, and each subsequent byte picks a swap target, rejected until
/// it lands at or below the current index.
///
/// The `c[i] = c[j]` before `c[j] = sign` is not redundant. It is what makes
/// this a shuffle rather than an overwrite, and dropping it would let two
/// draws collide and silently produce fewer than `tau` nonzero coefficients.
pub fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut x = Shake256::default();
    <Shake256 as Xof>::update(&mut x, seed);
    let mut reader = x.finalize_reader();

    let mut signs = [0u8; 8];
    reader.read(&mut signs);
    let mut h = u64::from_le_bytes(signs);

    let mut out = Poly::ZERO;
    let mut byte = [0u8; 1];
    for i in (N - tau)..N {
        // Reject until the target is within the prefix already built.
        loop {
            reader.read(&mut byte);
            if (byte[0] as usize) <= i {
                break;
            }
        }
        let j = byte[0] as usize;
        out.c[i] = out.c[j];
        out.c[j] = 1 - 2 * ((h & 1) as i32);
        h >>= 1;
    }
    out
}

/// `RejNTTPoly` (FIPS 204 Algorithm 30): a uniform ring element from a seed.
///
/// The result is already a transform-domain value and is never passed through
/// [`Poly::ntt`] — uniform in one domain is uniform in the other, so the
/// transform would be wasted work.
///
/// # Index order
///
/// `ExpandA` derives `A[r][s]` from `rho || s || r` — the **column** index
/// first, then the row. ML-KEM's `ExpandA` puts them the other way around. The
/// two schemes genuinely differ here, and taking the convention from the
/// neighbouring crate is exactly how a whole scheme ends up transposed and
/// self-consistent, so the caller passes them already in stream order and this
/// function does not reorder anything.
pub fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Poly {
    let mut x = Shake128::default();
    <Shake128 as Xof>::update(&mut x, rho);
    <Shake128 as Xof>::update(&mut x, &[s, r]);
    let mut reader = x.finalize_reader();

    let mut out = Poly::ZERO;
    let mut filled = 0usize;
    let mut buf = [0u8; SQUEEZE_CHUNK];

    while filled < N {
        reader.read(&mut buf);
        let mut offset = 0;
        while offset + 3 <= SQUEEZE_CHUNK && filled < N {
            if let Some(z) = coeff_from_three_bytes(buf[offset], buf[offset + 1], buf[offset + 2]) {
                out.c[filled] = z;
                filled += 1;
            }
            offset += 3;
        }
    }
    out
}

/// `RejBoundedPoly` (FIPS 204 Algorithm 31): a short secret from a seed.
///
/// The nonce is two bytes little-endian, and each stream byte yields two
/// candidates, **low nibble first**. Both of those are places where a
/// plausible-looking alternative produces a valid-shaped polynomial that no
/// other implementation agrees with.
pub fn rej_bounded_poly(rho: &[u8; 64], nonce: u16, eta: i32) -> Poly {
    let mut x = Shake256::default();
    <Shake256 as Xof>::update(&mut x, rho);
    <Shake256 as Xof>::update(&mut x, &nonce.to_le_bytes());
    let mut reader = x.finalize_reader();

    let mut out = Poly::ZERO;
    let mut filled = 0usize;
    let mut buf = [0u8; 136]; // one SHAKE-256 rate

    while filled < N {
        reader.read(&mut buf);
        for &b in buf.iter() {
            if filled >= N {
                break;
            }
            if let Some(z) = coeff_from_half_byte(b & 0x0f, eta) {
                out.c[filled] = z;
                filled += 1;
            }
            if filled >= N {
                break;
            }
            if let Some(z) = coeff_from_half_byte(b >> 4, eta) {
                out.c[filled] = z;
                filled += 1;
            }
        }
    }
    out
}

/// One polynomial of `ExpandMask` (FIPS 204 Algorithm 34).
///
/// No rejection: a fixed `32 * (1 + bitlen(gamma1 - 1))` bytes are squeezed and
/// unpacked. That is required, not incidental — `y` masks the secret, so its
/// sampling must not run for a value-dependent time.
pub fn expand_mask_poly(rho: &[u8; 64], index: u16, gamma1: i32) -> Poly {
    let bits = z_bits(gamma1);
    let mut buf = [0u8; 640]; // the largest case, gamma1 = 2^19
    let len = packed_len(bits);

    let mut x = Shake256::default();
    <Shake256 as Xof>::update(&mut x, rho);
    <Shake256 as Xof>::update(&mut x, &index.to_le_bytes());
    x.finalize_xof(&mut buf[..len]);

    let mut out = Poly::ZERO;
    bit_unpack(&buf[..len], gamma1, bits, &mut out);
    out
}

/// A reader over the stream [`rej_ntt_poly`] uses, so tests can replay it.
#[doc(hidden)]
pub fn matrix_xof(rho: &[u8; 32], s: u8, r: u8) -> XofReader {
    let mut x = Shake128::default();
    <Shake128 as Xof>::update(&mut x, rho);
    <Shake128 as Xof>::update(&mut x, &[s, r]);
    x.finalize_reader()
}

/// A reader over the stream [`rej_bounded_poly`] uses, so tests can replay it.
#[doc(hidden)]
pub fn bounded_xof(rho: &[u8; 64], nonce: u16) -> XofReader {
    let mut x = Shake256::default();
    <Shake256 as Xof>::update(&mut x, rho);
    <Shake256 as Xof>::update(&mut x, &nonce.to_le_bytes());
    x.finalize_reader()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed32(n: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = n.wrapping_mul(31).wrapping_add(i as u8);
        }
        s
    }

    fn seed64(n: u8) -> [u8; 64] {
        let mut s = [0u8; 64];
        for (i, b) in s.iter_mut().enumerate() {
            *b = n.wrapping_mul(17).wrapping_add(i as u8);
        }
        s
    }

    /// `SampleInBall`, rebuilt from the pseudocode over the same stream.
    ///
    /// Written to follow the standard's text line for line rather than the
    /// implementation above, so agreement means the logic is right and not just
    /// that one function calls another.
    fn reference_in_ball(seed: &[u8], tau: usize) -> Vec<i32> {
        let mut x = Shake256::default();
        <Shake256 as Xof>::update(&mut x, seed);
        let mut reader = x.finalize_reader();

        let mut bytes = [0u8; 8];
        reader.read(&mut bytes);
        let mut c = vec![0i32; N];

        for i in (256 - tau)..256 {
            let mut j;
            loop {
                let mut one = [0u8; 1];
                reader.read(&mut one);
                j = one[0] as usize;
                if j <= i {
                    break;
                }
            }
            c[i] = c[j];
            // Bit (i - (256 - tau)) of the eight sign bytes, LSB of byte 0 first.
            let bit = i - (256 - tau);
            let s = (bytes[bit / 8] >> (bit % 8)) & 1;
            c[j] = 1 - 2 * (s as i32);
        }
        c
    }

    #[test]
    fn sample_in_ball_matches_the_pseudocode() {
        for tau in [39usize, 49, 60] {
            for n in 0..6u8 {
                let seed = seed64(n);
                let got = sample_in_ball(&seed, tau);
                assert_eq!(
                    got.c.to_vec(),
                    reference_in_ball(&seed, tau),
                    "tau={tau} seed={n}"
                );
            }
        }
    }

    /// The defining property: exactly `tau` coefficients are nonzero and every
    /// one of them is `±1`.
    ///
    /// The swap step is what makes this hold. Overwriting instead would let two
    /// draws land on the same index and quietly produce a challenge of lower
    /// weight, which weakens the scheme without failing anything else.
    #[test]
    fn a_challenge_has_exactly_tau_signs() {
        for tau in [39usize, 49, 60] {
            for n in 0..40u8 {
                let c = sample_in_ball(&seed64(n), tau);
                let nonzero = c.c.iter().filter(|v| **v != 0).count();
                assert_eq!(nonzero, tau, "weight, tau={tau} seed={n}");
                for (i, &v) in c.c.iter().enumerate() {
                    assert!(v == 0 || v == 1 || v == -1, "coefficient {i} is {v}");
                }
            }
        }
    }

    /// Both signs must actually occur, or the sign bits are being dropped.
    #[test]
    fn challenge_signs_are_not_all_one_way() {
        let mut positive = 0;
        let mut negative = 0;
        for n in 0..40u8 {
            let c = sample_in_ball(&seed64(n), 49);
            positive += c.c.iter().filter(|v| **v == 1).count();
            negative += c.c.iter().filter(|v| **v == -1).count();
        }
        let total = positive + negative;
        assert_eq!(total, 40 * 49);
        // Far from a statistical test; this catches a sign bit ignored entirely.
        assert!(
            positive > total / 4 && negative > total / 4,
            "signs look degenerate: {positive} positive, {negative} negative"
        );
    }

    /// `RejNTTPoly`, rebuilt from the pseudocode over a replayed stream.
    fn reference_rej_ntt(rho: &[u8; 32], s: u8, r: u8) -> Vec<i32> {
        let mut reader = matrix_xof(rho, s, r);
        let mut out = Vec::with_capacity(N);
        let mut three = [0u8; 3];
        while out.len() < N {
            reader.read(&mut three);
            let z = ((three[2] & 0x7f) as i32) << 16 | (three[1] as i32) << 8 | three[0] as i32;
            if z < Q {
                out.push(z);
            }
        }
        out
    }

    /// Reading three bytes at a time and reading 168 at a time must give the
    /// same answer.
    ///
    /// This is the real content of the test: the production path buffers a
    /// whole sponge rate and walks it, and a chunk boundary that swallowed two
    /// bytes would show up here and essentially nowhere else, because the
    /// output would still be uniform and still be the right length.
    #[test]
    fn rej_ntt_poly_matches_the_pseudocode_across_chunk_boundaries() {
        for n in 0..4u8 {
            let rho = seed32(n);
            for (s, r) in [(0u8, 0u8), (1, 0), (0, 1), (4, 5), (7, 7)] {
                let got = rej_ntt_poly(&rho, s, r);
                assert_eq!(
                    got.c.to_vec(),
                    reference_rej_ntt(&rho, s, r),
                    "n={n} s={s} r={r}"
                );
                for (i, &c) in got.c.iter().enumerate() {
                    assert!((0..Q).contains(&c), "coefficient {i} out of range: {c}");
                }
            }
        }
    }

    /// The two index bytes must not be interchangeable.
    ///
    /// If they were, `A` would be symmetric and a transposed implementation
    /// would agree with this one, hiding the very error the index-order comment
    /// warns about.
    #[test]
    fn the_matrix_index_order_matters() {
        let rho = seed32(3);
        assert_ne!(
            rej_ntt_poly(&rho, 1, 2).c.to_vec(),
            rej_ntt_poly(&rho, 2, 1).c.to_vec(),
            "A[1][2] and A[2][1] must differ"
        );
    }

    /// `RejBoundedPoly`, rebuilt from the pseudocode over a replayed stream.
    fn reference_rej_bounded(rho: &[u8; 64], nonce: u16, eta: i32) -> Vec<i32> {
        let mut reader = bounded_xof(rho, nonce);
        let mut out = Vec::with_capacity(N);
        let mut one = [0u8; 1];
        while out.len() < N {
            reader.read(&mut one);
            let b = one[0];
            let lo = b % 16;
            let hi = b / 16;
            for half in [lo, hi] {
                if out.len() >= N {
                    break;
                }
                let z = if eta == 2 {
                    if half < 15 {
                        Some(2 - (half as i32 % 5))
                    } else {
                        None
                    }
                } else if half < 9 {
                    Some(4 - half as i32)
                } else {
                    None
                };
                if let Some(z) = z {
                    out.push(z);
                }
            }
        }
        out
    }

    #[test]
    fn rej_bounded_poly_matches_the_pseudocode() {
        for eta in [2i32, 4] {
            for n in 0..4u8 {
                let rho = seed64(n);
                for nonce in [0u16, 1, 5, 255, 256, 300] {
                    let got = rej_bounded_poly(&rho, nonce, eta);
                    assert_eq!(
                        got.c.to_vec(),
                        reference_rej_bounded(&rho, nonce, eta),
                        "eta={eta} n={n} nonce={nonce}"
                    );
                    for (i, &c) in got.c.iter().enumerate() {
                        assert!(
                            (-eta..=eta).contains(&c),
                            "coefficient {i} out of [-{eta},{eta}]: {c}"
                        );
                    }
                }
            }
        }
    }

    /// A two-byte little-endian nonce, not a one-byte one.
    ///
    /// ML-DSA-87 uses `l = 7` and `k = 8`, so nonces stay under 256 and a
    /// one-byte nonce would work by accident for every parameter set. It would
    /// still be wrong, and this is the only place it shows.
    #[test]
    fn the_nonce_is_two_bytes_little_endian() {
        let rho = seed64(1);
        assert_ne!(
            rej_bounded_poly(&rho, 1, 4).c.to_vec(),
            rej_bounded_poly(&rho, 256, 4).c.to_vec(),
            "nonce 1 and nonce 256 must differ in more than the low byte"
        );
        assert_ne!(
            rej_bounded_poly(&rho, 0x0102, 4).c.to_vec(),
            rej_bounded_poly(&rho, 0x0201, 4).c.to_vec(),
            "byte order must matter"
        );
    }

    /// The exact distribution, which a transposed or misfolded rule fails while
    /// still producing small plausible values.
    ///
    /// At `eta = 2` the rule folds fifteen half-bytes modulo five, so the five
    /// outcomes are equally likely. At `eta = 4` nine of sixteen map straight
    /// across, so the nine outcomes are equally likely. Neither is binomial —
    /// this is where ML-DSA differs from ML-KEM, and a sampler borrowed from
    /// next door would be peaked at zero instead of flat.
    #[test]
    fn the_bounded_distribution_is_flat_not_binomial() {
        for eta in [2i32, 4] {
            let outcomes = (2 * eta + 1) as usize;
            let mut counts = vec![0usize; outcomes];
            let mut total = 0usize;
            for n in 0..30u8 {
                let p = rej_bounded_poly(&seed64(n), n as u16, eta);
                for &c in p.c.iter() {
                    counts[(c + eta) as usize] += 1;
                    total += 1;
                }
            }
            let expected = total / outcomes;
            for (value, &count) in counts.iter().enumerate() {
                let v = value as i32 - eta;
                // Generous bounds: this must catch a peaked distribution, not
                // adjudicate a chi-squared test.
                assert!(
                    count > expected * 3 / 4 && count < expected * 5 / 4,
                    "eta={eta}: value {v} appeared {count} times, expected about {expected}"
                );
            }
        }
    }

    /// `ExpandMask` is bounded and uses a fixed-length read.
    #[test]
    fn expand_mask_is_in_range_and_deterministic() {
        for gamma1 in [1i32 << 17, 1 << 19] {
            for n in 0..4u8 {
                let rho = seed64(n);
                for index in [0u16, 1, 6, 259] {
                    let y = expand_mask_poly(&rho, index, gamma1);
                    assert_eq!(
                        y.c,
                        expand_mask_poly(&rho, index, gamma1).c,
                        "deterministic"
                    );
                    for (i, &c) in y.c.iter().enumerate() {
                        assert!(
                            c > -gamma1 && c <= gamma1,
                            "coefficient {i} out of (-gamma1, gamma1] at gamma1={gamma1}: {c}"
                        );
                    }
                }
            }
        }
    }

    /// `ExpandMask` must actually reach both ends of its range.
    ///
    /// An implementation that lost the top bit would stay comfortably inside
    /// the bound above and pass it, so the bound alone proves little.
    #[test]
    fn expand_mask_covers_its_range() {
        let gamma1 = 1i32 << 19;
        let mut lowest = gamma1;
        let mut highest = -gamma1;
        for n in 0..20u8 {
            let y = expand_mask_poly(&seed64(n), n as u16, gamma1);
            for &c in y.c.iter() {
                lowest = lowest.min(c);
                highest = highest.max(c);
            }
        }
        assert!(
            lowest < -gamma1 + gamma1 / 100,
            "the low end is never approached: {lowest}"
        );
        assert!(
            highest > gamma1 - gamma1 / 100,
            "the high end is never approached: {highest}"
        );
    }

    /// Different indices give different masks, so `y` is not reused across the
    /// vector — which would be a catastrophic failure, not a subtle one.
    #[test]
    fn each_mask_index_gives_a_different_polynomial() {
        let rho = seed64(7);
        let gamma1 = 1i32 << 19;
        let a = expand_mask_poly(&rho, 0, gamma1);
        for index in 1..8u16 {
            assert_ne!(
                a.c.to_vec(),
                expand_mask_poly(&rho, index, gamma1).c.to_vec(),
                "mask {index} repeats mask 0"
            );
        }
    }

    /// The rules for the two `eta` values are different rules, not one rule.
    #[test]
    fn the_half_byte_rules_are_distinct_and_correct() {
        // eta = 2: fifteen inputs fold onto five outputs, three each.
        let mut counts = [0usize; 5];
        for b in 0..16u8 {
            match coeff_from_half_byte(b, 2) {
                Some(z) => {
                    assert!((-2..=2).contains(&z));
                    counts[(z + 2) as usize] += 1;
                }
                None => assert_eq!(b, 15, "only 15 is rejected at eta = 2"),
            }
        }
        assert_eq!(
            counts, [3; 5],
            "each of the five outcomes must be equally likely"
        );

        // eta = 4: nine inputs map straight across, seven are rejected.
        let mut seen = Vec::new();
        for b in 0..16u8 {
            match coeff_from_half_byte(b, 4) {
                Some(z) => {
                    assert_eq!(z, 4 - b as i32);
                    seen.push(z);
                }
                None => assert!(b >= 9, "only 9..=15 are rejected at eta = 4"),
            }
        }
        assert_eq!(seen, vec![4, 3, 2, 1, 0, -1, -2, -3, -4]);
    }

    /// The three-byte rule discards the top bit rather than rejecting on it.
    #[test]
    fn the_three_byte_rule_masks_the_top_bit() {
        // q - 1 is accepted, q is not.
        let q = Q as u32;
        let le = (q - 1).to_le_bytes();
        assert_eq!(coeff_from_three_bytes(le[0], le[1], le[2]), Some(Q - 1));
        let le = q.to_le_bytes();
        assert_eq!(coeff_from_three_bytes(le[0], le[1], le[2]), None);
        // Setting the twenty-fourth bit must not change the verdict.
        assert_eq!(
            coeff_from_three_bytes(0x01, 0x00, 0x80),
            Some(1),
            "the top bit is discarded, not rejected on"
        );
    }
}
