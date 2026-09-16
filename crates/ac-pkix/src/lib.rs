//! DER and PEM encoding for keys and signatures.
//!
//! Every other crate in this workspace speaks in raw byte arrays: a public key
//! is 65 bytes of SEC1 point, a signature is 64 bytes of `r || s`. That is the
//! right interface for the algorithms and the wrong one for the world, where
//! keys arrive as `-----BEGIN PUBLIC KEY-----` and signatures arrive inside
//! X.509 certificates. This crate is the translation layer, and nothing more:
//! it parses and serializes, and performs no cryptography.
//!
//! # Scope
//!
//! - [`der`]: a strict DER reader and writer. Strict is the point — see the
//!   module docs for what it refuses and why each refusal has a CVE behind it.
//! - [`PublicKeyInfo`]: `SubjectPublicKeyInfo` for RSA, P-256, P-384, Ed25519,
//!   and X25519, plus bare PKCS#1 `RSAPublicKey`.
//! - [`PrivateKeyInfo`]: PKCS#8 `PrivateKeyInfo`, and SEC1 `ECPrivateKey`.
//! - [`ecdsa_signature`]: conversion between fixed-width `r || s` and the
//!   `Ecdsa-Sig-Value` DER that X.509 and TLS carry.
//! - [`pem`]: RFC 7468 textual encoding.
//!
//! # What it does not do
//!
//! - **No certificate parsing.** Reading an X.509 certificate means parsing
//!   names, validity, extensions, and policy — a much larger surface, and one
//!   where a partial implementation is worse than none. Hand the
//!   `SubjectPublicKeyInfo` bytes from an existing X.509 parser to
//!   [`PublicKeyInfo::from_der`].
//! - **No encrypted PKCS#8.** `EncryptedPrivateKeyInfo` needs PBES2 and a
//!   password. Decrypt it elsewhere and pass the plaintext here.
//! - **No PKCS#8 attributes.** The optional `[0] attributes` field is refused
//!   rather than skipped, because skipping it would mean accepting a document
//!   this crate cannot re-emit unchanged. Key-file tooling does not produce
//!   them.
//! - **No key validation.** Parsing checks structure, not mathematics. A
//!   `SubjectPublicKeyInfo` whose point is off the curve parses cleanly and
//!   fails when something tries to verify with it, which is where that check
//!   belongs.
//!
//! # No allocation
//!
//! Parsing borrows from the input. Serializing writes into a caller-supplied
//! buffer and returns the length. The crate is `no_std` with no `alloc`.
//!
//! # Example
//!
//! ```
//! # fn main() -> ac_core::Result<()> {
//! use ac_pkix::{PublicKeyInfo, pem};
//!
//! // A public key as it would arrive from a file or a certificate.
//! let key = PublicKeyInfo::Ed25519(&[0x42; 32]);
//!
//! let mut der = [0u8; 128];
//! let n = key.to_der(&mut der)?;
//! assert_eq!(PublicKeyInfo::from_der(&der[..n])?, key);
//!
//! let mut text = [0u8; 256];
//! let n = pem::encode(pem::PUBLIC_KEY, &der[..n], &mut text)?;
//! assert!(core::str::from_utf8(&text[..n]).unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod der;
pub mod ecdsa_signature;
pub mod oid;
pub mod pem;
pub mod private_key;
pub mod public_key;

pub use oid::KeyAlgorithm;
pub use private_key::PrivateKeyInfo;
pub use public_key::{parse_rsa_public_key, write_rsa_public_key, PublicKeyInfo};
