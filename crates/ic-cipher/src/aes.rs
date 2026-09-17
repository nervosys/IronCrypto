//! FIPS 197 AES, with a portable constant-time backend and an optional
//! hardware-accelerated one.
//!
//! # Backend selection
//!
//! The backend is chosen once, when a key is expanded, and recorded in the
//! cipher value. On x86-64 with AES-NI that is the accelerated path; everywhere
//! else it is the portable one. Selection depends only on the CPU, never on key
//! material, so it leaks nothing.
//!
//! Detection is compile-time when the `aes` target feature is already enabled
//! for the build (`-C target-cpu=native`, say), and runtime otherwise via
//! `is_x86_feature_detected!`. Under `no_std` only the compile-time path is
//! available, because runtime detection needs `std`.
//!
//! `ic_ontology::runtime::backend()` reports which one is live, so an agent
//! deciding whether to push a gigabyte through AES-GCM can ask rather than
//! guess.
//!
//! # Trusting the accelerated path
//!
//! The portable backend is validated against the FIPS 197 and SP 800-38A
//! vectors. The accelerated backend is then validated *against the portable
//! one*, block for block, across every key length and every batch boundary. It
//! is not an independent reimplementation to be trusted on its own; it is an
//! optimization held to the output of something already known to be correct.

pub mod portable;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
pub mod x86;
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(feature = "std"),
    target_feature = "aes"
))]
pub mod x86;

use ic_core::traits::{Algorithm, BlockCipher, SelfTest};
use ic_core::{ensure, Result};

pub use portable::BLOCK_LEN;

/// Which implementation a cipher value is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Pure Rust, algebraic S-box, no hardware support required.
    Portable,
    /// x86-64 AES-NI.
    Aesni,
}

impl Backend {
    /// Stable identifier, matching `ic_ontology::runtime::Backend`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Portable => "portable-constant-time",
            Self::Aesni => "aes-ni",
        }
    }
}

/// Whether the AES-NI backend is usable on this CPU.
#[inline]
#[must_use]
pub fn aesni_available() -> bool {
    // Detection lives in `ic-core` so the ontology can report the same answer
    // without depending on this crate.
    ic_core::cpu::has_aes()
}

/// The backend this build will use for AES.
pub fn active_backend() -> Backend {
    if aesni_available() {
        Backend::Aesni
    } else {
        Backend::Portable
    }
}

/// The key schedule, in whichever representation the active backend wants.
///
/// The portable variant holds 240 bytes of round keys and the SIMD variant
/// holds register state, so the two differ in size. Boxing the larger one would
/// need an allocator, which this crate deliberately does not require, and a key
/// schedule is constructed once per key rather than passed around by value —
/// so the size difference is accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Keys {
    Portable(portable::Schedule),
    #[cfg(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"),
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            not(feature = "std"),
            target_feature = "aes"
        )
    ))]
    Aesni(x86::Keys),
}

/// Expand a key using whichever backend is active.
fn expand(key: &[u8]) -> Result<Keys> {
    // The portable schedule is always built: the accelerated backend consumes
    // its output rather than duplicating the expansion.
    let sched = portable::Schedule::expand(key)?;

    #[cfg(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"),
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            not(feature = "std"),
            target_feature = "aes"
        )
    ))]
    if aesni_available() {
        // SAFETY: `aesni_available()` established the `aes` target feature.
        let keys = unsafe { x86::Keys::load(&sched) };
        return Ok(Keys::Aesni(keys));
    }

    Ok(Keys::Portable(sched))
}

impl Keys {
    #[inline]
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match self {
            Keys::Portable(s) => portable::encrypt_block(s, block),
            #[cfg(any(
                all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"),
                all(
                    any(target_arch = "x86", target_arch = "x86_64"),
                    not(feature = "std"),
                    target_feature = "aes"
                )
            ))]
            // SAFETY: this variant is only constructed after a feature check.
            Keys::Aesni(k) => unsafe { x86::encrypt_block(k, block) },
        }
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match self {
            Keys::Portable(s) => portable::decrypt_block(s, block),
            #[cfg(any(
                all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"),
                all(
                    any(target_arch = "x86", target_arch = "x86_64"),
                    not(feature = "std"),
                    target_feature = "aes"
                )
            ))]
            // SAFETY: this variant is only constructed after a feature check.
            Keys::Aesni(k) => unsafe { x86::decrypt_block(k, block) },
        }
    }

    #[inline]
    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        match self {
            Keys::Portable(s) => {
                ensure!(
                    data.len() % BLOCK_LEN == 0,
                    InvalidLength,
                    "aes batch must be block-aligned"
                );
                for block in data.chunks_exact_mut(BLOCK_LEN) {
                    portable::encrypt_block(s, block)?;
                }
                Ok(())
            }
            #[cfg(any(
                all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"),
                all(
                    any(target_arch = "x86", target_arch = "x86_64"),
                    not(feature = "std"),
                    target_feature = "aes"
                )
            ))]
            // SAFETY: this variant is only constructed after a feature check.
            Keys::Aesni(k) => unsafe { x86::encrypt_blocks(k, data) },
        }
    }

    fn backend(&self) -> Backend {
        match self {
            Keys::Portable(_) => Backend::Portable,
            #[cfg(any(
                all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"),
                all(
                    any(target_arch = "x86", target_arch = "x86_64"),
                    not(feature = "std"),
                    target_feature = "aes"
                )
            ))]
            Keys::Aesni(_) => Backend::Aesni,
        }
    }
}

macro_rules! aes_variant {
    ($name:ident, $id:literal, $disp:literal, $keylen:literal, $kat_key:literal, $kat_ct:literal) => {
        #[doc = concat!("FIPS 197 ", $disp, ".")]
        #[derive(Clone)]
        pub struct $name(Keys);

        impl $name {
            /// Which backend this instance is using.
            pub fn backend(&self) -> Backend {
                self.0.backend()
            }

            /// Force the portable backend, whatever the CPU supports.
            ///
            /// Exists so the accelerated path can be differentially tested
            /// against the portable one in the same process.
            pub fn new_portable(key: &[u8]) -> Result<Self> {
                ensure!(key.len() == $keylen, InvalidLength, $id);
                Ok(Self(Keys::Portable(portable::Schedule::expand(key)?)))
            }
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = BLOCK_LEN;
            const KEY_LEN: usize = $keylen;

            fn new(key: &[u8]) -> Result<Self> {
                ensure!(key.len() == $keylen, InvalidLength, $id);
                Ok(Self(expand(key)?))
            }

            fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
                self.0.encrypt_block(block)
            }

            fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
                self.0.decrypt_block(block)
            }

            fn encrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
                self.0.encrypt_blocks(data)
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                // FIPS 197 Appendix C: plaintext 00112233..ff.
                let mut key = [0u8; $keylen];
                ic_core::codec::hex_decode($kat_key.as_bytes(), &mut key)?;
                let mut want = [0u8; 16];
                ic_core::codec::hex_decode($kat_ct.as_bytes(), &mut want)?;

                let cipher = <Self as BlockCipher>::new(&key)?;
                let mut block: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
                cipher.encrypt_block(&mut block)?;
                ensure!(ic_core::ct::verify(&want, &block), SelfTestFailed, $id);

                cipher.decrypt_block(&mut block)?;
                let plain: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
                ensure!(ic_core::ct::verify(&plain, &block), SelfTestFailed, $id);

                // The self-test must cover whichever backend is actually live,
                // and the portable one regardless, so a CPU-dependent fault
                // cannot pass unnoticed.
                let reference = Self::new_portable(&key)?;
                let mut a: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
                reference.encrypt_block(&mut a)?;
                ensure!(ic_core::ct::verify(&want, &a), SelfTestFailed, $id);
                Ok(())
            }
        }
    };
}

aes_variant!(
    Aes128,
    "aes-128",
    "AES-128",
    16,
    "000102030405060708090a0b0c0d0e0f",
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
aes_variant!(
    Aes192,
    "aes-192",
    "AES-192",
    24,
    "000102030405060708090a0b0c0d0e0f1011121314151617",
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
aes_variant!(
    Aes256,
    "aes-256",
    "AES-256",
    32,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8ea2b7ca516745bfeafc49904b496089"
);

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::{hex, unhex};

    fn enc<C: BlockCipher>(key: &str, pt: &str) -> String {
        let c = C::new(&unhex(key).unwrap()).unwrap();
        let mut b = unhex(pt).unwrap();
        c.encrypt_block(&mut b).unwrap();
        hex(&b)
    }

    #[test]
    fn fips197_appendix_c_vectors() {
        assert_eq!(
            enc::<Aes128>(
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff"
            ),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
        assert_eq!(
            enc::<Aes192>(
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "00112233445566778899aabbccddeeff"
            ),
            "dda97ca4864cdfe06eaf70a0ec0d7191"
        );
        assert_eq!(
            enc::<Aes256>(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00112233445566778899aabbccddeeff"
            ),
            "8ea2b7ca516745bfeafc49904b496089"
        );
    }

    /// NIST SP 800-38A F.1.1 uses this key/block pair; it exercises a schedule
    /// distinct from the FIPS 197 one.
    #[test]
    fn sp800_38a_ecb_vector() {
        assert_eq!(
            enc::<Aes128>(
                "2b7e151628aed2a6abf7158809cf4f3c",
                "6bc1bee22e409f96e93d7e117393172a"
            ),
            "3ad77bb40d7a3660a89ecaf32466ef97"
        );
    }

    #[test]
    fn decryption_inverts_encryption() {
        let key = [0x42u8; 32];
        let c = Aes256::new(&key).unwrap();
        let original: [u8; 16] = core::array::from_fn(|i| (i * 13) as u8);
        let mut block = original;
        c.encrypt_block(&mut block).unwrap();
        assert_ne!(block, original);
        c.decrypt_block(&mut block).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn rejects_wrong_key_and_block_lengths() {
        assert!(Aes128::new(&[0u8; 17]).is_err());
        assert!(Aes256::new(&[0u8; 16]).is_err());
        let c = Aes128::new(&[0u8; 16]).unwrap();
        assert!(c.encrypt_block(&mut [0u8; 15]).is_err());
        assert!(c.encrypt_blocks(&mut [0u8; 17]).is_err());
    }

    /// Whichever backend is active must agree with the portable one exactly.
    /// On a CPU without AES-NI this compares the portable backend with itself,
    /// which is vacuous but harmless; on one with it, this is the check that
    /// makes the acceleration trustworthy.
    #[test]
    fn active_backend_agrees_with_portable() {
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| (i * 11 + 3) as u8).collect();

            macro_rules! compare {
                ($ty:ty) => {{
                    let fast = <$ty>::new(&key).unwrap();
                    let slow = <$ty>::new_portable(&key).unwrap();
                    for seed in 0..32u8 {
                        let original: [u8; 16] = core::array::from_fn(|i| seed ^ (i as u8 * 17));
                        let mut a = original;
                        let mut b = original;
                        fast.encrypt_block(&mut a).unwrap();
                        slow.encrypt_block(&mut b).unwrap();
                        assert_eq!(a, b, "encrypt, key_len {}", key_len);

                        let mut a = original;
                        let mut b = original;
                        fast.decrypt_block(&mut a).unwrap();
                        slow.decrypt_block(&mut b).unwrap();
                        assert_eq!(a, b, "decrypt, key_len {}", key_len);
                    }
                }};
            }
            match key_len {
                16 => compare!(Aes128),
                24 => compare!(Aes192),
                _ => compare!(Aes256),
            }
        }
    }

    /// The batch path must produce the same bytes as repeated single-block
    /// calls, at every length including the ones that straddle the eight-block
    /// boundary.
    #[test]
    fn batch_matches_single_block() {
        let c = Aes256::new(&[0x2bu8; 32]).unwrap();
        for blocks in 0..20usize {
            let data: Vec<u8> = (0..blocks * BLOCK_LEN).map(|i| (i * 7) as u8).collect();

            let mut batched = data.clone();
            c.encrypt_blocks(&mut batched).unwrap();

            let mut singly = data.clone();
            for block in singly.chunks_exact_mut(BLOCK_LEN) {
                c.encrypt_block(block).unwrap();
            }
            assert_eq!(batched, singly, "{blocks} blocks");
        }
    }

    #[test]
    fn backend_is_reported_consistently() {
        let c = Aes128::new(&[0u8; 16]).unwrap();
        assert_eq!(c.backend(), active_backend());
        assert_eq!(
            Aes128::new_portable(&[0u8; 16]).unwrap().backend(),
            Backend::Portable
        );
        assert_eq!(Backend::Portable.id(), "portable-constant-time");
    }

    #[test]
    fn self_tests_pass() {
        Aes128::self_test().unwrap();
        Aes192::self_test().unwrap();
        Aes256::self_test().unwrap();
    }
}
