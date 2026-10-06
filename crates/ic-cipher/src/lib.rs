//! # ic-cipher — block ciphers, stream ciphers, and AEADs
//!
//! Pure-Rust, `no_std`, dependency-free implementations of AES (FIPS 197),
//! the SP 800-38A confidentiality modes, AES-GCM (SP 800-38D), and the
//! RFC 8439 ChaCha20-Poly1305 suite.
//!
//! ```
//! use ic_cipher::{Aes256Gcm, Opener, Sealer};
//!
//! // A session key, from a key exchange and a KDF in real use.
//! let key = [0x2a; 32];
//! let mut tx = Sealer::<Aes256Gcm>::new(&key, *b"c->s")?;
//! let mut rx = Opener::<Aes256Gcm>::new(&key, *b"c->s")?;
//! let mut buf = *b"ship it";
//! let mut tag = [0u8; 16];
//! let nonce = tx.seal(b"context", &mut buf, &mut tag)?;
//! rx.open(&nonce, b"context", &mut buf, &tag)?;
//! assert_eq!(&buf, b"ship it");
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! [`Sealer`] chooses every nonce itself and [`Opener`] refuses replays; see
//! [`sealer`] for when that is enough. The AEAD types underneath take a nonce
//! from the caller, which is what protocols with their own nonce rules (TLS,
//! QUIC, HPKE) need, and which is where nonce reuse comes from.
//!
//! ## Backend status
//!
//! AES computes its S-box algebraically and GHASH multiplies without tables, so
//! neither touches a key-dependent memory address — the cache-timing channel
//! that table-driven AES leaves open is closed by construction.
//!
//! Three backends sit behind the same traits, chosen by the CPU and never by
//! key material: AES-NI with PCLMULQDQ on x86-64, the ARMv8 crypto extensions
//! behind a feature, and a portable one everywhere else. The portable AES path
//! is bitsliced for encryption — four blocks at a time in transposed form, at
//! roughly the rate of RustCrypto's fixsliced implementation. Decryption is
//! not bitsliced and runs a byte at a time, which is correct and slow; the
//! modes that move volume (CTR, GCM, GCM-SIV) only encrypt.
//!
//! `ic_ontology::runtime::backend()` reports which one is active, so an agent
//! can decide whether a workload belongs here.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
// Every unsafe operation inside an unsafe fn must be marked explicitly, so the
// SIMD backends cannot smuggle one in under the function signature.
#![forbid(unsafe_op_in_unsafe_fn)]
// And unsafe may only appear where a CPU intrinsic is being called, which is
// what the allowances below mark. Everywhere else in this crate -- the modes,
// the key wrapping, the field arithmetic -- it is a compile error.
#![deny(unsafe_code)]
#![warn(clippy::all)]

// AES-NI and the ARMv8 crypto extensions, behind runtime detection.
#[allow(unsafe_code)]
pub mod aes;

// AVX2 for the ChaCha20 keystream, behind runtime detection.
#[allow(unsafe_code)]
pub mod chacha;
#[cfg(all(target_arch = "x86_64", feature = "std"))]
// The carry-less multiply instruction.
#[allow(unsafe_code)]
mod clmul;
// GHASH via CLMUL when the CPU has it.
#[allow(unsafe_code)]
pub mod gcm;
pub mod gcm_siv;
pub mod gf;
pub mod keywrap;
pub mod modes;
pub mod polyval;
pub mod sealer;
pub mod shamir;

pub use aes::{Aes128, Aes192, Aes256};
pub use chacha::{chacha20_xor, ChaCha20Poly1305, Poly1305};
pub use gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmLimits};
pub use gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
pub use keywrap::{Aes128Kw, Aes128Kwp, Aes192Kw, Aes192Kwp, Aes256Kw, Aes256Kwp};
pub use modes::{cbc_decrypt, cbc_encrypt, ctr_xor, pkcs7_pad, pkcs7_unpad};
pub use sealer::{Opener, Sealer};

/// Ontology identifiers for the AEADs this crate provides.
pub const AEAD_IDS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
];

/// Ontology identifiers for the raw block ciphers this crate provides.
pub const BLOCK_CIPHER_IDS: &[&str] = &["aes-128", "aes-192", "aes-256"];
