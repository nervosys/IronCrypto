//! Operating-system entropy acquisition.
//!
//! IronCrypto never uses raw OS bytes as key material directly. The OS
//! source is treated as the *entropy input* to an SP 800-90A DRBG
//! (`ic-drbg`), which is the construction FIPS 140-3 expects. This module only
//! has to deliver full-entropy bytes and fail loudly when it cannot.
//!
//! Backends, chosen at compile time, with no third-party dependencies:
//!
//! | target | mechanism |
//! |---|---|
//! | Windows | `BCryptGenRandom` with the system-preferred RNG |
//! | Unix | `/dev/urandom` |
//! | other / `no_std` | [`ErrorKind::EntropyFailure`][crate::ErrorKind::EntropyFailure] |
//!
//! On a platform with no backend, supply your own entropy through
//! [`Drbg::instantiate`][crate::traits::Drbg::instantiate].

use crate::{traits::RandomSource, Result};

/// The system entropy source.
///
/// ```no_run
/// use ic_core::{entropy::OsEntropy, traits::RandomSource};
/// let mut seed = [0u8; 48];
/// OsEntropy.fill(&mut seed).expect("OS entropy unavailable");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl RandomSource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        fill_impl(out)
    }
}

/// Fill `out` with bytes from the operating system entropy source.
pub fn fill(out: &mut [u8]) -> Result<()> {
    fill_impl(out)
}

#[cfg(all(feature = "std", windows))]
fn fill_impl(out: &mut [u8]) -> Result<()> {
    // CNG's system-preferred RNG. This is the same DRBG the Windows FIPS
    // validated module exposes, reached without a handle via
    // `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            hAlgorithm: *mut core::ffi::c_void,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    // `cbBuffer` is a u32, so large requests are issued in chunks.
    for chunk in out.chunks_mut(u32::MAX as usize) {
        if chunk.is_empty() {
            continue;
        }
        // SAFETY: `chunk` is a valid, uniquely-borrowed buffer of `len` bytes,
        // and a null algorithm handle is required by the flag we pass.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(crate::err!(EntropyFailure, "BCryptGenRandom"));
        }
    }
    Ok(())
}

#[cfg(all(feature = "std", unix))]
fn fill_impl(out: &mut [u8]) -> Result<()> {
    use std::io::Read;

    if out.is_empty() {
        return Ok(());
    }
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|_| crate::err!(EntropyFailure, "/dev/urandom open"))?;
    f.read_exact(out)
        .map_err(|_| crate::err!(EntropyFailure, "/dev/urandom read"))?;
    Ok(())
}

#[cfg(not(all(feature = "std", any(windows, unix))))]
fn fill_impl(_out: &mut [u8]) -> Result<()> {
    Err(crate::err!(
        EntropyFailure,
        "no OS entropy backend for this target; seed the DRBG manually"
    ))
}

#[cfg(all(test, feature = "std", any(windows, unix)))]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_nonzero_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32], "entropy source returned all zeroes");
        assert_ne!(a, b, "entropy source repeated itself");
    }

    #[test]
    fn empty_request_succeeds() {
        fill(&mut []).unwrap();
    }
}
