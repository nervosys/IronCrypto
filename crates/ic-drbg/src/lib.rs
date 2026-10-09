//! # ic-drbg — SP 800-90A deterministic random bit generators
//!
//! * [`HmacDrbg`] — HMAC_DRBG, generic over the HMAC instantiation.
//! * [`CtrDrbg`] — CTR_DRBG over AES-256 without a derivation function.
//! * [`Rng`] — an OS-seeded, auto-reseeding generator for everyday use.
//!
//! ## Why the indirection
//!
//! FIPS 140-3 does not let a module hand out raw OS bytes as key material. The
//! OS source is *entropy input* to an approved DRBG, and that DRBG is what
//! generates keys, nonces, and IVs. [`Rng`] wires that up so the correct thing
//! is also the easy thing:
//!
//! ```no_run
//! use ic_drbg::Rng;
//!
//! let mut rng = Rng::from_os()?;
//! let mut key = [0u8; 32];
//! rng.fill(&mut key)?;
//! # Ok::<(), ic_core::Error>(())
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

mod ctr;
mod hmac_drbg;
// Generated; long lines of hex are its content.
#[rustfmt::skip]
mod kat;
#[cfg(feature = "std")]
mod rng;

pub use ctr::CtrDrbg;
pub use hmac_drbg::{HmacDrbg, HmacDrbgSha256, HmacDrbgSha512};
#[cfg(feature = "std")]
pub use rng::Rng;

/// Maximum number of [`generate`][ic_core::traits::Drbg::generate] calls
/// between reseeds, per SP 800-90A Table 2 and Table 3.
///
/// The spec permits 2^48; this library uses a far smaller interval so that a
/// long-lived process reseeds on a human timescale rather than a geological
/// one. Exceeding it is an error, never a silent continuation.
pub const RESEED_INTERVAL: u64 = 1 << 20;

/// Minimum entropy input in bytes for a 256-bit security strength instantiation.
pub const MIN_ENTROPY_LEN: usize = 32;

/// Ontology identifiers for the DRBGs this crate provides.
pub const DRBG_IDS: &[&str] = &[
    "hmac-drbg-sha2-256",
    "hmac-drbg-sha2-512",
    "ctr-drbg-aes-256",
];

/// Run a known-answer case through all three functions of a DRBG:
/// instantiate, reseed, generate, generate, comparing the second output.
///
/// This is what SP 800-90A section 11.3 asks a health test to cover. A value
/// that only instantiated and generated would pass with a reseed that did
/// nothing.
fn known_answer_test<D: ic_core::traits::Drbg>(
    kat: &kat::Kat,
    id: &'static str,
) -> ic_core::Result<()> {
    fn decode<'a>(hex: &str, buf: &'a mut [u8; 160]) -> ic_core::Result<&'a [u8]> {
        let out = buf.get_mut(..hex.len() / 2).ok_or(ic_core::Error::new(
            ic_core::ErrorKind::Internal,
            "drbg kat",
        ))?;
        ic_core::codec::hex_decode(hex.as_bytes(), out)?;
        Ok(out)
    }
    let (mut a, mut b, mut c) = ([0u8; 160], [0u8; 160], [0u8; 160]);
    let mut drbg = D::instantiate(
        decode(kat.entropy, &mut a)?,
        decode(kat.nonce, &mut b)?,
        decode(kat.personalization, &mut c)?,
    )?;
    drbg.reseed(
        decode(kat.reseed_entropy, &mut a)?,
        decode(kat.reseed_additional, &mut b)?,
    )?;
    let mut got = [0u8; 512];
    drbg.generate(decode(kat.generate1_additional, &mut a)?, &mut got)?;
    drbg.generate(decode(kat.generate2_additional, &mut a)?, &mut got)?;

    let mut want = [0u8; 512];
    ic_core::codec::hex_decode(kat.returned.as_bytes(), &mut want)?;
    if !ic_core::ct::verify(&want, &got) {
        return Err(ic_core::Error::new(ic_core::ErrorKind::SelfTestFailed, id));
    }
    Ok(())
}
