//! # ac-mac — message authentication codes
//!
//! * [`Hmac`] — FIPS 198-1, generic over any [`Digest`](ac_core::traits::Digest) in `ac-hash`.
//! * [`CmacAes128`] / [`CmacAes256`] — SP 800-38B CMAC over AES.
//! * [`Poly1305`] — re-exported from `ac-cipher` for one-time authentication.
//!
//! All verification goes through [`ac_core::ct::verify`], so tag comparison
//! cannot become a timing oracle.
//!
//! ```
//! use ac_mac::HmacSha256;
//! use ac_core::traits::Mac;
//!
//! let tag = HmacSha256::mac(b"key", b"message")?;
//! HmacSha256::verify(b"key", b"message", tag.as_ref())?;
//! assert!(HmacSha256::verify(b"key", b"tampered", tag.as_ref()).is_err());
//! # Ok::<(), ac_core::Error>(())
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::all)]

mod cmac;
mod hmac;
mod kmac;

pub use ac_cipher::Poly1305;
pub use cmac::{CmacAes128, CmacAes192, CmacAes256};
pub use hmac::{
    Hmac, HmacSha256, HmacSha384, HmacSha3_256, HmacSha3_512, HmacSha512, HmacSha512_256,
};
pub use kmac::{Kmac128, Kmac256};

/// Ontology identifiers for the MACs this crate provides.
pub const MAC_IDS: &[&str] = &[
    "hmac-sha2-256",
    "hmac-sha2-384",
    "hmac-sha2-512",
    "hmac-sha2-512-256",
    "hmac-sha3-256",
    "hmac-sha3-512",
    "cmac-aes-128",
    "cmac-aes-192",
    "cmac-aes-256",
    "poly1305",
];
