//! Shamir secret sharing over GF(2^8).
//!
//! A secret is split into `share_count` shares, any `threshold` of which
//! recover it, and any fewer of which reveal nothing about it: each byte of
//! the secret is the constant term of its own random polynomial of degree
//! `threshold - 1`, and share `i` holds every polynomial's value at `x = i`.
//! Recovery is Lagrange interpolation at zero.
//!
//! The field is the one AES uses, `x^8 + x^4 + x^3 + x + 1`, and the
//! arithmetic is [`crate::gf`]'s: branch-free and table-free, so neither the
//! coefficients nor the share bytes reach an address or a branch. Share
//! indices and counts are public.
//!
//! # What it does not do
//!
//! Shares carry no integrity. A corrupted share, or fewer than `threshold`
//! shares, recover a wrong secret rather than an error, because nothing in a
//! share says what the right answer is. Split a random key rather than data,
//! and use that key with an AEAD over the data: the AEAD is what detects a bad
//! recovery. The share's index and the threshold have to travel with it, in
//! whatever format the caller chooses; nothing here encodes them.
//!
//! # Verification
//!
//! Against an implementation written from Shamir's construction with its own
//! field arithmetic (`scripts/gen_shamir_vectors.py`), share for share, and by
//! recombining every subset of shares this crate's tests enumerate.

use crate::gf;
use ic_core::traits::{Algorithm, RandomSource, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// The most shares a split can make: the nonzero elements of GF(2^8).
pub const MAX_SHARES: u8 = 255;

/// Shamir secret sharing over GF(2^8), for the ontology and the self-test
/// table.
pub struct Shamir;

impl Algorithm for Shamir {
    const ID: &'static str = "shamir-gf256";
    const NAME: &'static str = "Shamir secret sharing over GF(2^8)";
}

/// Split `secret` into `share_count` shares, any `threshold` of which recover
/// it.
///
/// `out` is `share_count * secret.len()` bytes: share `i`, whose index is
/// `i + 1`, is `out[i * secret.len()..(i + 1) * secret.len()]`. `rng` supplies
/// `threshold - 1` fresh coefficients for every byte of the secret.
///
/// Requires `2 <= threshold <= share_count` (a threshold of one would make
/// every share the secret) and a non-empty secret. If `rng` fails, `out` is
/// wiped and the error returned.
pub fn split<R: RandomSource + ?Sized>(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
    rng: &mut R,
    out: &mut [u8],
) -> Result<()> {
    ensure!(!secret.is_empty(), InvalidLength, "shamir secret is empty");
    ensure!(
        threshold >= 2,
        InvalidParameter,
        "shamir threshold must be at least 2"
    );
    ensure!(
        share_count >= threshold,
        InvalidParameter,
        "shamir share count is below the threshold"
    );
    let len = secret.len();
    ensure!(
        out.len() == len * share_count as usize,
        InvalidLength,
        "shamir output must be share_count * secret.len() bytes"
    );

    let mut coefficients = [0u8; MAX_SHARES as usize - 1];
    let coefficients = &mut coefficients[..threshold as usize - 1];
    for (b, &s) in secret.iter().enumerate() {
        if let Err(e) = rng.fill(coefficients) {
            coefficients.zeroize();
            out.zeroize();
            return Err(e);
        }
        for i in 0..share_count as usize {
            // Horner's rule from the highest coefficient down, ending on the
            // secret byte as the constant term.
            let x = (i + 1) as u8;
            let mut y = 0u8;
            for &c in coefficients.iter().rev() {
                y = gf::mul(y, x) ^ c;
            }
            out[i * len + b] = gf::mul(y, x) ^ s;
        }
    }
    coefficients.zeroize();
    Ok(())
}

/// Recover a secret from shares given as `(index, bytes)`.
///
/// Pass at least `threshold` shares; more are fine. With fewer, the result is
/// a wrong secret rather than an error -- see the module note. Every share
/// must be `out.len()` bytes, and indices must be nonzero and distinct; at
/// least two shares are required.
pub fn combine(shares: &[(u8, &[u8])], out: &mut [u8]) -> Result<()> {
    ensure!(
        shares.len() >= 2,
        InvalidParameter,
        "shamir needs at least two shares"
    );
    for (n, (index, bytes)) in shares.iter().enumerate() {
        ensure!(
            *index != 0,
            InvalidParameter,
            "shamir share index 0 is the secret itself"
        );
        ensure!(
            bytes.len() == out.len(),
            InvalidLength,
            "shamir shares differ in length"
        );
        ensure!(
            shares[..n].iter().all(|(other, _)| other != index),
            InvalidParameter,
            "shamir share indices repeat"
        );
    }

    out.zeroize();
    for (i, (xi, yi)) in shares.iter().enumerate() {
        // The Lagrange basis polynomial for share i, evaluated at zero:
        // prod over j != i of x_j / (x_j - x_i), subtraction being XOR. It
        // depends only on the public indices.
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i != j {
                numerator = gf::mul(numerator, *xj);
                denominator = gf::mul(denominator, xj ^ xi);
            }
        }
        let basis = gf::mul(numerator, gf::inv(denominator));
        for (o, y) in out.iter_mut().zip(yi.iter()) {
            *o ^= gf::mul(*y, basis);
        }
    }
    Ok(())
}

/// A share, with its index, as [`split_vec`] returns them. Wiped on drop.
#[cfg(feature = "std")]
pub struct Share {
    /// The share's index, `1..=255`: its `x`.
    pub index: u8,
    /// The share's bytes, as long as the secret.
    pub value: std::vec::Vec<u8>,
}

#[cfg(feature = "std")]
impl Drop for Share {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// [`split`], returning the shares.
#[cfg(feature = "std")]
pub fn split_vec<R: RandomSource + ?Sized>(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
    rng: &mut R,
) -> Result<std::vec::Vec<Share>> {
    let len = secret.len();
    let mut all = ic_core::Zeroizing::new(std::vec![0u8; len * share_count as usize]);
    split(secret, threshold, share_count, rng, all.get_mut())?;
    Ok(all
        .get()
        .chunks(len)
        .enumerate()
        .map(|(i, bytes)| Share {
            index: (i + 1) as u8,
            value: bytes.to_vec(),
        })
        .collect())
}

/// [`combine`], returning the secret in a buffer wiped on drop.
#[cfg(feature = "std")]
pub fn combine_vec(shares: &[Share]) -> Result<ic_core::Zeroizing<std::vec::Vec<u8>>> {
    let len = shares.first().map_or(0, |s| s.value.len());
    let parts: std::vec::Vec<(u8, &[u8])> =
        shares.iter().map(|s| (s.index, &s.value[..])).collect();
    let mut out = ic_core::Zeroizing::new(std::vec![0u8; len]);
    combine(&parts, out.get_mut())?;
    Ok(out)
}

/// The deterministic coefficient stream `scripts/gen_shamir_vectors.py`
/// uses: `s = 29 * s + 7 mod 256`. For known-answer tests only.
pub(crate) struct Stream(pub(crate) u8);

impl RandomSource for Stream {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        for b in out.iter_mut() {
            self.0 = self.0.wrapping_mul(29).wrapping_add(7);
            *b = self.0;
        }
        Ok(())
    }
}

impl SelfTest for Shamir {
    /// A 3-of-5 split of 32 bytes under a fixed coefficient stream, compared
    /// with the reference implementation's first two shares, then recovered
    /// from shares 2, 4 and 5.
    fn self_test() -> Result<()> {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut shares = [0u8; 5 * 32];
        split(&secret, 3, 5, &mut Stream(0x11), &mut shares)?;
        let mut want = [0u8; 64];
        ic_core::codec::hex_decode(KAT_SHARES_1_2, &mut want)?;
        ensure!(
            ic_core::ct::verify(&shares[..64], &want),
            SelfTestFailed,
            "shamir: shares differ from the reference"
        );
        let mut recovered = [0u8; 32];
        combine(
            &[
                (2, &shares[32..64]),
                (4, &shares[96..128]),
                (5, &shares[128..]),
            ],
            &mut recovered,
        )?;
        ensure!(
            ic_core::ct::verify(&recovered, &secret),
            SelfTestFailed,
            "shamir: recovery differs"
        );
        Ok(())
    }
}

/// Shares 1 and 2 of the first case in `testvectors/shamir-gf256.json`.
const KAT_SHARES_1_2: &[u8] = b"5ff2a5a02b96c144f71a6d28237e898c4fa2f5f0fb065154278abd78732e191c69afee93f0ed7a6a5af11d0dc3b352b422ffbec32026b1218aa156eb93552fe4";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_test_passes() {
        Shamir::self_test().unwrap();
    }

    /// Every subset of `threshold` shares recovers the secret, as does every
    /// larger subset; a subset one short does not, for this split.
    #[test]
    fn every_threshold_subset_recovers_the_secret() {
        let secret = *b"a 24-byte secret for k=3";
        let (k, n) = (3u8, 6u8);
        let mut shares = [0u8; 6 * 24];
        split(&secret, k, n, &mut Stream(0x5d), &mut shares).unwrap();
        let share = |i: usize| ((i + 1) as u8, &shares[i * 24..(i + 1) * 24]);

        let mut subsets = 0;
        for mask in 1u32..(1 << n) {
            let picked: std::vec::Vec<_> = (0..n as usize)
                .filter(|i| mask & (1 << i) != 0)
                .map(share)
                .collect();
            if picked.len() < 2 {
                continue;
            }
            let mut out = [0u8; 24];
            combine(&picked, &mut out).unwrap();
            if picked.len() >= k as usize {
                assert_eq!(out, secret, "subset {mask:06b}");
                subsets += 1;
            } else {
                assert_ne!(out, secret, "subset {mask:06b}, below the threshold");
            }
        }
        // C(6,3) + C(6,4) + C(6,5) + C(6,6).
        assert_eq!(subsets, 20 + 15 + 6 + 1);
    }

    #[test]
    fn bad_parameters_and_shares_are_refused() {
        let mut out = [0u8; 10];
        let mut rng = Stream(1);
        assert!(split(b"", 2, 2, &mut rng, &mut []).is_err(), "empty secret");
        assert!(
            split(b"ab", 1, 5, &mut rng, &mut out).is_err(),
            "threshold 1"
        );
        assert!(
            split(b"ab", 3, 2, &mut rng, &mut out[..4]).is_err(),
            "count below threshold"
        );
        assert!(
            split(b"ab", 2, 5, &mut rng, &mut out[..9]).is_err(),
            "wrong output length"
        );

        let a = [1u8, 2];
        let b = [3u8, 4];
        let mut two = [0u8; 2];
        assert!(combine(&[(1, &a)], &mut two).is_err(), "one share");
        assert!(combine(&[(0, &a), (1, &b)], &mut two).is_err(), "index 0");
        assert!(
            combine(&[(1, &a), (1, &b)], &mut two).is_err(),
            "repeated index"
        );
        assert!(
            combine(&[(1, &a), (2, &b[..1])], &mut two).is_err(),
            "length mismatch"
        );
        combine(&[(1, &a), (2, &b)], &mut two).unwrap();
    }

    /// A failing random source leaves no partial shares behind.
    #[test]
    fn a_failing_rng_wipes_the_output() {
        struct Fails(u8);
        impl RandomSource for Fails {
            fn fill(&mut self, out: &mut [u8]) -> Result<()> {
                if self.0 == 0 {
                    return Err(ic_core::err!(EntropyFailure, "test"));
                }
                self.0 -= 1;
                out.fill(0x77);
                Ok(())
            }
        }
        let mut out = [0u8; 3 * 4];
        assert!(split(b"keys", 2, 3, &mut Fails(2), &mut out).is_err());
        assert_eq!(out, [0u8; 12]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn the_vec_forms_round_trip() {
        let shares = split_vec(b"vec secret", 2, 4, &mut Stream(9)).unwrap();
        assert_eq!(shares.len(), 4);
        assert_eq!(shares[3].index, 4);
        let recovered = combine_vec(&shares[2..]).unwrap();
        assert_eq!(&recovered.get()[..], b"vec secret");
    }
}
