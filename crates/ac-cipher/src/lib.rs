//! # ac-cipher — block ciphers, stream ciphers, and AEADs
//!
//! Pure-Rust, `no_std`, dependency-free implementations of AES (FIPS 197),
//! the SP 800-38A confidentiality modes, AES-GCM (SP 800-38D), and the
//! RFC 8439 ChaCha20-Poly1305 suite.
//!
//! ```
//! use ac_cipher::Aes256Gcm;
//! use ac_core::traits::Aead;
//!
//! let cipher = Aes256Gcm::new(&[0x2a; 32])?;
//! let mut buf = *b"ship it";
//! let mut tag = [0u8; 16];
//! cipher.seal_detached(&[0u8; 12], b"context", &mut buf, &mut tag)?;
//! cipher.open_detached(&[0u8; 12], b"context", &mut buf, &tag)?;
//! assert_eq!(&buf, b"ship it");
//! # Ok::<(), ac_core::Error>(())
//! ```
//!
//! ## Backend status
//!
//! This is the **portable constant-time backend**. AES computes its S-box
//! algebraically and GHASH multiplies bit by bit, so neither touches a
//! key-dependent memory address — the cache-timing channel that table-driven
//! AES leaves open is closed by construction. The cost is throughput: expect
//! single-digit MB/s rather than the GB/s an AES-NI or bitsliced backend
//! delivers. Hardware backends are a planned addition behind the same traits,
//! and the ontology reports which backend is active via
//! `ac_ontology::runtime::backend()`, so an agent can decide whether a workload
//! belongs here.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
// Every unsafe operation inside an unsafe fn must be marked explicitly, so the
// SIMD backends cannot smuggle one in under the function signature.
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(clippy::all)]

pub mod aes;

pub mod chacha;
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod clmul;
pub mod gcm;
pub mod gcm_siv;
pub mod gf;
pub mod keywrap;
pub mod modes;
pub mod polyval;

pub use aes::{Aes128, Aes192, Aes256};
pub use chacha::{chacha20_xor, ChaCha20Poly1305, Poly1305};
pub use gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmLimits};
pub use gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
pub use keywrap::{Aes128Kw, Aes128Kwp, Aes192Kw, Aes192Kwp, Aes256Kw, Aes256Kwp};
pub use modes::{cbc_decrypt, cbc_encrypt, ctr_xor, pkcs7_pad, pkcs7_unpad};

/// Ontology identifiers for the AEADs this crate provides.
pub const AEAD_IDS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
];

/// Ontology identifiers for the raw block ciphers this crate provides.
pub const BLOCK_CIPHER_IDS: &[&str] = &["aes-128", "aes-192", "aes-256"];
