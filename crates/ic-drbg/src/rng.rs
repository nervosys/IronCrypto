//! An OS-seeded, self-reseeding random number generator.
//!
//! This is the generator every other crate should reach for. It owns an
//! [`HmacDrbg`] seeded from [`ic_core::entropy`], tracks the reseed interval,
//! and pulls fresh entropy automatically when the interval is reached — so the
//! `CounterExhausted` failure mode never surfaces to ordinary callers.
//!
//! # What is checked about the entropy
//!
//! Very little can be, from here. The operating system owns the noise source
//! and conditions it; the health tests of SP 800-90B run on raw samples this
//! library never sees, and nothing below is one of them. What arrives is
//! checked for the one failure that is visible in it: a source that has
//! stopped. A seed with [`STUCK_RUN`] equal bytes in a row, or a second draw
//! that begins as the first did, is refused with `EntropyFailure` and puts
//! the module into its error state. A source that is merely weak, or one
//! that replays an earlier state as a restored virtual machine does, passes.

use crate::{HmacDrbgSha256, MIN_ENTROPY_LEN};
use ic_core::traits::{Drbg, RandomSource};
use ic_core::{ensure, Result, Zeroize};

/// The run of equal bytes at which a seed is taken to come from a source that
/// has stopped.
///
/// A working source produces such a run somewhere in a 48-byte seed with
/// probability about `2^-50`, so this refuses a constant source -- all
/// zeroes, all ones, one byte repeated -- and essentially never a good one.
/// The number is this library's choice. SP 800-90B's repetition count test
/// has the same shape, with a cutoff worked out from the measured entropy of
/// a raw noise source, which is not what the operating system hands over.
pub const STUCK_RUN: usize = 8;

/// Refuse a seed with [`STUCK_RUN`] equal bytes in a row.
fn not_stuck(seed: &[u8]) -> Result<()> {
    let mut run = 0usize;
    let mut last = None;
    for &byte in seed {
        run = if last == Some(byte) { run + 1 } else { 1 };
        last = Some(byte);
        ensure!(
            run < STUCK_RUN,
            EntropyFailure,
            "the entropy source returned a run of equal bytes; it is taken to have stopped"
        );
    }
    Ok(())
}

/// Draw from the operating system, and end the module if what comes back
/// is from a source that has stopped.
fn os_entropy(out: &mut [u8]) -> Result<()> {
    ic_core::entropy::fill(out)?;
    ic_core::module::conditional_self_test(not_stuck(out))
}

/// A ready-to-use CSPRNG: OS entropy in, approved DRBG output out.
pub struct Rng {
    drbg: HmacDrbgSha256,
    calls_since_reseed: u64,
}

impl Rng {
    /// Seed a generator from the operating system entropy source.
    ///
    /// Draws a 48-byte entropy input and a 16-byte nonce, matching the
    /// SP 800-90A requirement of `3/2 * security_strength` bits of entropy for
    /// a 256-bit instantiation.
    pub fn from_os() -> Result<Self> {
        ic_core::module::operational()?;
        let mut seed = [0u8; 48];
        let mut nonce = [0u8; 16];
        os_entropy(&mut seed)?;
        os_entropy(&mut nonce)?;
        // Two draws that begin alike are one draw made twice.
        ic_core::module::conditional_self_test(if ic_core::ct::verify(&seed[..16], &nonce) {
            Err(ic_core::err!(
                EntropyFailure,
                "the entropy source returned the same bytes twice"
            ))
        } else {
            Ok(())
        })?;
        let drbg = HmacDrbgSha256::instantiate(&seed, &nonce, b"IronCrypto/Rng")?;
        seed.zeroize();
        nonce.zeroize();
        Ok(Self {
            drbg,
            calls_since_reseed: 0,
        })
    }

    /// Seed a generator from caller-supplied entropy.
    ///
    /// Use this on platforms with no OS backend, or when entropy comes from a
    /// hardware source the library does not know about. `entropy` must carry at
    /// least 256 bits of real entropy.
    pub fn from_entropy(entropy: &[u8], personalization: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        let drbg = HmacDrbgSha256::instantiate(entropy, &[], personalization)?;
        Ok(Self {
            drbg,
            calls_since_reseed: 0,
        })
    }

    /// Fill `out` with random bytes, reseeding from the OS when due.
    pub fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        // Reseed well before the DRBG's own hard limit so the interval is a
        // maintenance event, not an error path.
        if self.calls_since_reseed >= crate::RESEED_INTERVAL / 2 {
            self.reseed_from_os()?;
        }
        self.calls_since_reseed = self.calls_since_reseed.saturating_add(1);
        self.drbg.generate(&[], out)
    }

    /// Generate a fixed-size array of random bytes.
    pub fn random_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.fill(&mut out)?;
        Ok(out)
    }

    /// Pull fresh entropy from the OS and reseed.
    pub fn reseed_from_os(&mut self) -> Result<()> {
        ic_core::module::operational()?;
        let mut seed = [0u8; MIN_ENTROPY_LEN];
        os_entropy(&mut seed)?;
        let r = self.drbg.reseed(&seed, b"");
        seed.zeroize();
        r?;
        self.calls_since_reseed = 0;
        Ok(())
    }
}

impl RandomSource for Rng {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        Rng::fill(self, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule, not a value: a run one short of the cutoff passes wherever
    /// it falls, and a run at the cutoff is refused wherever it falls.
    #[test]
    fn a_stopped_source_is_refused_and_a_working_one_is_not() {
        use ic_core::ErrorKind;
        // No two neighbours equal, so the only run is the one planted.
        let base: [u8; 48] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        not_stuck(&base).unwrap();
        not_stuck(&[]).unwrap();
        for start in [0, 1, 20, 48 - STUCK_RUN] {
            for value in [0x00, 0xff, 0x5a] {
                let mut seed = base;
                seed[start..start + STUCK_RUN - 1].fill(value);
                // Keep the planted run from joining a neighbour.
                if start > 0 {
                    seed[start - 1] = !value;
                }
                if start + STUCK_RUN - 1 < 48 {
                    seed[start + STUCK_RUN - 1] = !value;
                }
                not_stuck(&seed).unwrap();

                seed[start..start + STUCK_RUN].fill(value);
                assert_eq!(
                    not_stuck(&seed).unwrap_err().kind(),
                    ErrorKind::EntropyFailure,
                    "a run of {STUCK_RUN} at {start}"
                );
            }
        }
        for constant in [0x00u8, 0xff, 0x01] {
            assert!(not_stuck(&[constant; 48]).is_err());
            assert!(not_stuck(&[constant; 16]).is_err());
        }
        // Shorter than the cutoff, nothing can be said.
        not_stuck(&[0u8; STUCK_RUN - 1]).unwrap();
    }

    #[test]
    fn produces_distinct_nonzero_output() {
        let mut rng = Rng::from_os().unwrap();
        let a: [u8; 32] = rng.random_array().unwrap();
        let b: [u8; 32] = rng.random_array().unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn two_generators_diverge() {
        let mut a = Rng::from_os().unwrap();
        let mut b = Rng::from_os().unwrap();
        let x: [u8; 32] = a.random_array().unwrap();
        let y: [u8; 32] = b.random_array().unwrap();
        assert_ne!(x, y, "independently seeded generators must not agree");
    }

    #[test]
    fn manual_seeding_is_reproducible() {
        let mut a = Rng::from_entropy(&[0x11u8; 32], b"ctx").unwrap();
        let mut b = Rng::from_entropy(&[0x11u8; 32], b"ctx").unwrap();
        let x: [u8; 32] = a.random_array().unwrap();
        let y: [u8; 32] = b.random_array().unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn reseeding_diverges_the_stream() {
        let mut rng = Rng::from_entropy(&[0x22u8; 32], b"ctx").unwrap();
        let before: [u8; 32] = rng.random_array().unwrap();
        rng.reseed_from_os().unwrap();
        let after: [u8; 32] = rng.random_array().unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn rejects_insufficient_entropy() {
        assert!(Rng::from_entropy(&[0u8; 8], b"").is_err());
    }
}
