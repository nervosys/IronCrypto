//! Sampling polynomials from a seed (FIPS 203 algorithms 7 and 8).
//!
//! Two distributions, for two different jobs.
//!
//! [`sample_ntt`] draws a uniform element of the ring, used for the public
//! matrix `A`. Uniform over `Z_q` cannot be taken directly from bits, because
//! `q = 3329` is not a power of two, so it rejects candidates at or above `q`.
//! That makes its output length data-dependent — it squeezes until it has 256
//! accepted values — which is fine because the seed is public. Nothing secret
//! passes through it.
//!
//! [`sample_poly_cbd`] draws from a centered binomial distribution, used for
//! the secret and the noise. It reads a fixed number of bits and counts them,
//! so it is constant time, which it must be: its input *is* the secret.
//!
//! # What the tests check
//!
//! Both are rebuilt in the tests from the specification's pseudocode over the
//! same SHAKE stream, and required to agree. SHAKE itself is validated against
//! published FIPS 202 vectors, so what is being checked here is the sampling
//! logic — the rejection rule, the bit ordering, the nibble split — rather than
//! the randomness underneath it.
//!
//! The distribution is checked too. A centered binomial sampler with a
//! transposed index still produces plausible-looking small values; what it does
//! not produce is the right *shape*, so the tests assert the exact probability
//! mass at each point.

use crate::poly::{Poly, N, Q};
use ic_core::traits::Xof;
#[cfg(test)]
use ic_hash::XofReader;
use ic_hash::{Shake128, Shake256};

/// Bytes squeezed per rejection-sampling round.
///
/// One sponge rate for SHAKE-128, so a round never straddles a permutation
/// boundary unnecessarily. The value does not affect the output — the stream is
/// continuous — only how often the loop asks for more.
const SQUEEZE_CHUNK: usize = 168;

/// `SampleNTT(rho || j || i)`: a uniform ring element, already in the transform
/// domain.
///
/// The name is not a mistake. The output is used directly as a transform-domain
/// value and never passed through [`crate::poly::Poly::ntt`]; sampling
/// uniformly in one domain is the same as sampling uniformly in the other, so
/// the transform would be wasted work.
pub fn sample_ntt(seed: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut x = Shake128::default();
    <Shake128 as Xof>::update(&mut x, seed);
    <Shake128 as Xof>::update(&mut x, &[i, j]);
    let mut reader = x.finalize_reader();

    let mut out = Poly::ZERO;
    let mut filled = 0usize;
    let mut buf = [0u8; SQUEEZE_CHUNK];

    while filled < N {
        reader.read(&mut buf);
        filled = rej_uniform(&mut out, filled, &buf);
    }
    out
}

/// Append the candidates in `buf` that are below `q` to `out`, which already
/// holds `filled` coefficients, stopping at `N`; return the new count.
///
/// Branches on the candidates, which are public: they come from the public
/// seed `rho`. `buf` should be a whole number of three-byte groups; a
/// trailing partial group is ignored, as a stream read in whole rate blocks
/// never has one.
pub(crate) fn rej_uniform(out: &mut Poly, mut filled: usize, buf: &[u8]) -> usize {
    for group in buf.chunks_exact(3) {
        if filled >= N {
            break;
        }
        // Three bytes carry two twelve-bit candidates: the first takes a
        // whole byte plus the low nibble of the second, the other takes the
        // high nibble plus the third byte.
        let b0 = group[0] as u16;
        let b1 = group[1] as u16;
        let b2 = group[2] as u16;

        let d1 = b0 | ((b1 & 0x0f) << 8);
        let d2 = (b1 >> 4) | (b2 << 4);

        if d1 < Q as u16 {
            out.c[filled] = d1 as i16;
            filled += 1;
        }
        if d2 < Q as u16 && filled < N {
            out.c[filled] = d2 as i16;
            filled += 1;
        }
    }
    filled
}

/// `PRF_eta(s, b)`: SHAKE-256 over the seed and one counter byte.
pub fn prf(eta: usize, seed: &[u8; 32], nonce: u8, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 64 * eta);
    let mut x = Shake256::default();
    <Shake256 as Xof>::update(&mut x, seed);
    <Shake256 as Xof>::update(&mut x, &[nonce]);
    x.finalize_xof(out);
}

/// `SamplePolyCBD_eta(B)`: a centered binomial sample.
///
/// Each coefficient is the difference of two counts of `eta` bits, so it lands
/// in `[-eta, eta]` with a binomial shape centred on zero. Small and centred is
/// what the security argument needs; the exact shape is what makes the noise
/// analysable.
///
/// Constant time: every bit is read and counted regardless of value.
///
/// For the two widths ML-KEM uses the bits are counted a word at a time, by
/// adding masked shifts of the word to itself, rather than one at a time
/// with a division and a remainder to find each. The counts are the same
/// sums; `cbd_matches_the_specification` holds both forms to the
/// specification's bit array.
pub fn sample_poly_cbd(eta: usize, data: &[u8], out: &mut Poly) {
    debug_assert_eq!(data.len(), 64 * eta);
    match eta {
        2 => {
            for (bytes, group) in data.chunks_exact(4).zip(out.c.chunks_exact_mut(8)) {
                let mut w = [0u8; 4];
                w.copy_from_slice(bytes);
                group.copy_from_slice(&cbd2(u32::from_le_bytes(w)));
            }
        }
        3 => {
            for (bytes, group) in data.chunks_exact(3).zip(out.c.chunks_exact_mut(4)) {
                let w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
                group.copy_from_slice(&cbd3(w));
            }
        }
        _ => cbd_bits(eta, data, out),
    }
}

/// Eight `eta = 2` coefficients from 32 bits: each is the count of two bits
/// less the count of the next two.
///
/// Public only so that `scripts/check-ct.py` can inspect it; not API.
#[doc(hidden)]
#[inline]
pub fn cbd2(w: u32) -> [i16; 8] {
    // Each two-bit field of `d` holds the sum of the two bits above it in `w`.
    let d = (w & 0x5555_5555) + ((w >> 1) & 0x5555_5555);
    core::array::from_fn(|k| {
        let x = (d >> (4 * k)) & 3;
        let y = (d >> (4 * k + 2)) & 3;
        x as i16 - y as i16
    })
}

/// Four `eta = 3` coefficients from the low 24 bits of `w`.
///
/// Public only so that `scripts/check-ct.py` can inspect it; not API.
#[doc(hidden)]
#[inline]
pub fn cbd3(w: u32) -> [i16; 4] {
    // Each three-bit field of `d` holds the sum of the three bits above it.
    let d = (w & 0x0024_9249) + ((w >> 1) & 0x0024_9249) + ((w >> 2) & 0x0024_9249);
    core::array::from_fn(|k| {
        let x = (d >> (6 * k)) & 7;
        let y = (d >> (6 * k + 3)) & 7;
        x as i16 - y as i16
    })
}

/// The width-generic form, one bit at a time.
fn cbd_bits(eta: usize, data: &[u8], out: &mut Poly) {
    for (i, coefficient) in out.c.iter_mut().enumerate() {
        let base = 2 * i * eta;
        let mut x = 0i16;
        let mut y = 0i16;
        for b in 0..eta {
            let xi = base + b;
            let yi = base + eta + b;
            x += ((data[xi / 8] >> (xi % 8)) & 1) as i16;
            y += ((data[yi / 8] >> (yi % 8)) & 1) as i16;
        }
        *coefficient = x - y;
    }
}

/// Sample noise directly from a seed and nonce, for the widths ML-KEM uses.
pub fn sample_noise(eta: usize, seed: &[u8; 32], nonce: u8) -> Poly {
    // eta is 2 or 3, so 128 or 192 bytes.
    let mut buf = [0u8; 192];
    let len = 64 * eta;
    prf(eta, seed, nonce, &mut buf[..len]);
    let mut out = Poly::ZERO;
    sample_poly_cbd(eta, &buf[..len], &mut out);
    out
}

/// A reader over the same stream `sample_ntt` uses, for tests that need to
/// replay it. Test-only: it was public, hidden from the docs, which made it API
/// that nothing outside this file ever called.
#[cfg(test)]
fn matrix_xof(seed: &[u8; 32], i: u8, j: u8) -> XofReader {
    let mut x = Shake128::default();
    <Shake128 as Xof>::update(&mut x, seed);
    <Shake128 as Xof>::update(&mut x, &[i, j]);
    x.finalize_reader()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203 algorithm 7, transcribed literally, squeezing three bytes at a
    /// time rather than in chunks.
    ///
    /// The chunk size is the one thing this does differently, and that is the
    /// point: if the two agree, the sampler is not accidentally depending on
    /// how much it squeezes at once.
    fn reference_sample_ntt(seed: &[u8; 32], i: u8, j: u8) -> Poly {
        let mut reader = matrix_xof(seed, i, j);
        let mut a = Poly::ZERO;
        let mut filled = 0usize;
        while filled < N {
            let mut c = [0u8; 3];
            reader.read(&mut c);
            let d1 = (c[0] as u16) + 256 * ((c[1] as u16) % 16);
            let d2 = ((c[1] as u16) / 16) + 16 * (c[2] as u16);
            if d1 < Q as u16 {
                a.c[filled] = d1 as i16;
                filled += 1;
            }
            if d2 < Q as u16 && filled < N {
                a.c[filled] = d2 as i16;
                filled += 1;
            }
        }
        a
    }

    /// FIPS 203 algorithm 8, via an explicit bit array.
    fn reference_cbd(eta: usize, data: &[u8]) -> Poly {
        let mut bits = Vec::with_capacity(data.len() * 8);
        for byte in data {
            for b in 0..8 {
                bits.push(((byte >> b) & 1) as i16);
            }
        }
        let mut f = Poly::ZERO;
        for i in 0..N {
            let mut x = 0i16;
            let mut y = 0i16;
            for j in 0..eta {
                x += bits[2 * i * eta + j];
                y += bits[2 * i * eta + eta + j];
            }
            f.c[i] = x - y;
        }
        f
    }

    #[test]
    fn uniform_sampling_matches_the_specification() {
        for seed_byte in [0u8, 1, 0x5a, 0xff] {
            let seed = [seed_byte; 32];
            for (i, j) in [(0u8, 0u8), (0, 1), (1, 0), (2, 3)] {
                let got = sample_ntt(&seed, i, j);
                let want = reference_sample_ntt(&seed, i, j);
                assert_eq!(got, want, "sample_ntt seed={seed_byte:#x} i={i} j={j}");
            }
        }
    }

    /// Every sampled coefficient must be a valid field element, which is the
    /// whole purpose of the rejection step.
    #[test]
    fn uniform_sampling_stays_below_q() {
        for seed_byte in 0..8u8 {
            let p = sample_ntt(&[seed_byte; 32], 0, 0);
            for c in p.c.iter() {
                assert!(*c >= 0 && *c < Q, "sampled {c}, outside [0, q)");
            }
        }
    }

    /// The index pair must actually separate the matrix entries, or the public
    /// matrix collapses and the scheme is broken in a way no round trip sees.
    #[test]
    fn the_matrix_indices_are_separated() {
        let seed = [0x33u8; 32];
        let a = sample_ntt(&seed, 0, 1);
        let b = sample_ntt(&seed, 1, 0);
        assert_ne!(a, b, "A[0][1] and A[1][0] must differ");
        assert_ne!(a, sample_ntt(&seed, 0, 0));
        assert_ne!(a, sample_ntt(&[0x34u8; 32], 0, 1), "the seed must matter");
    }

    #[test]
    fn cbd_matches_the_specification() {
        for eta in [2usize, 3] {
            for nonce in 0..4u8 {
                let seed = [0x77u8; 32];
                let mut buf = [0u8; 192];
                prf(eta, &seed, nonce, &mut buf[..64 * eta]);

                let mut got = Poly::ZERO;
                sample_poly_cbd(eta, &buf[..64 * eta], &mut got);
                let want = reference_cbd(eta, &buf[..64 * eta]);
                assert_eq!(got, want, "cbd eta={eta} nonce={nonce}");
            }
        }
    }

    /// The distribution's shape, not just its range. A transposed index still
    /// gives small values; it does not give the right probabilities.
    ///
    /// For eta, `P(x = k) = C(2*eta, eta + k) / 2^(2*eta)`.
    #[test]
    fn cbd_has_the_right_distribution() {
        for eta in [2usize, 3] {
            let mut counts = [0usize; 7]; // index = value + 3
            let rounds = 64u8;
            for nonce in 0..rounds {
                let p = sample_noise(eta, &[0x11u8; 32], nonce);
                for c in p.c.iter() {
                    assert!(
                        (-(eta as i16)..=eta as i16).contains(c),
                        "cbd produced {c}, outside [-{eta}, {eta}]"
                    );
                    counts[(*c + 3) as usize] += 1;
                }
            }

            let total = (rounds as usize) * N;
            // Binomial coefficients C(2*eta, eta + k).
            let binom: &[usize] = if eta == 2 {
                &[1, 4, 6, 4, 1] // k = -2..2 over 2^4
            } else {
                &[1, 6, 15, 20, 15, 6, 1] // k = -3..3 over 2^6
            };
            let denom = 1usize << (2 * eta);

            for (idx, weight) in binom.iter().enumerate() {
                let k = idx as i16 - eta as i16;
                let observed = counts[(k + 3) as usize] as f64 / total as f64;
                let expected = *weight as f64 / denom as f64;
                assert!(
                    (observed - expected).abs() < 0.02,
                    "eta={eta}, P(x={k}) was {observed:.4}, expected {expected:.4}"
                );
            }
            // And nothing outside the range.
            for k in [-3i16, 3] {
                if k.unsigned_abs() as usize > eta {
                    assert_eq!(counts[(k + 3) as usize], 0, "eta={eta} produced {k}");
                }
            }
        }
    }

    /// Squeezing in different chunk sizes must not change the sample, which is
    /// what makes the sponge stream continuous rather than block-aligned.
    #[test]
    fn the_squeeze_chunking_does_not_affect_the_result() {
        let seed = [0x99u8; 32];
        let mut one = matrix_xof(&seed, 1, 2);
        let mut a = [0u8; 300];
        one.read(&mut a);

        let mut two = matrix_xof(&seed, 1, 2);
        let mut b = [0u8; 300];
        two.read(&mut b[..7]);
        two.read(&mut b[7..200]);
        two.read(&mut b[200..]);
        assert_eq!(a, b, "the xof stream depends on how it is read");
    }

    #[test]
    fn the_noise_nonce_separates_samples() {
        let seed = [0x44u8; 32];
        let a = sample_noise(2, &seed, 0);
        let b = sample_noise(2, &seed, 1);
        assert_ne!(a, b, "the nonce must change the sample");
    }
}
