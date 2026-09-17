//! The algorithm contracts every IronCrypto primitive implements.
//!
//! Two properties make these traits agent-friendly:
//!
//! 1. **Self-describing.** Every implementation carries an [`Algorithm::ID`]
//!    that resolves to an entry in the ontology, so a value at runtime can be
//!    traced back to its full machine-readable specification.
//! 2. **Total.** Nothing panics on bad input; sizes are surfaced as associated
//!    constants *and* as ontology metadata, so an agent can validate a call
//!    before making it.

use crate::Result;

/// Links a concrete implementation to its ontology entry.
///
/// `ID` is the stable ontology identifier (for example `"sha2-256"`), and is
/// the join key between runtime types and the machine-readable catalog exposed
/// by `ic-ontology`.
pub trait Algorithm {
    /// Stable ontology identifier for this algorithm.
    const ID: &'static str;
    /// Human-facing display name (for example `"SHA-256"`).
    const NAME: &'static str;
}

/// A cryptographic hash function with a fixed-length output.
pub trait Digest: Algorithm + Clone + Default {
    /// The fixed-size output buffer type, e.g. `[u8; 32]`.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// Output length in bytes.
    const OUTPUT_LEN: usize;
    /// Internal block (rate) length in bytes — required by HMAC and KMAC.
    const BLOCK_LEN: usize;

    /// Create a fresh, empty hasher.
    fn new() -> Self {
        Self::default()
    }

    /// Absorb more input. May be called any number of times.
    fn update(&mut self, data: &[u8]);

    /// Consume the hasher and produce the digest.
    fn finalize(self) -> Self::Output;

    /// One-shot convenience: hash `data` in a single call.
    fn digest(data: &[u8]) -> Self::Output {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// An extendable-output function (XOF) such as SHAKE128 / SHAKE256.
pub trait Xof: Algorithm + Clone + Default {
    /// Rate in bytes.
    const BLOCK_LEN: usize;

    /// Absorb more input.
    fn update(&mut self, data: &[u8]);

    /// Squeeze `out.len()` bytes of output, consuming the state.
    fn finalize_xof(self, out: &mut [u8]);
}

/// A keyed message authentication code.
pub trait Mac: Algorithm + Clone {
    /// The fixed-size tag type.
    type Tag: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// Tag length in bytes.
    const TAG_LEN: usize;

    /// Create a MAC instance from a key of any length the algorithm accepts.
    fn new(key: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Absorb more input.
    fn update(&mut self, data: &[u8]);

    /// Consume the instance and produce the tag.
    fn finalize(self) -> Self::Tag;

    /// One-shot authentication.
    fn mac(key: &[u8], data: &[u8]) -> Result<Self::Tag>
    where
        Self: Sized,
    {
        let mut m = Self::new(key)?;
        m.update(data);
        Ok(m.finalize())
    }

    /// Constant-time tag verification.
    ///
    /// Returns [`crate::ErrorKind::AuthenticationFailed`] on mismatch and
    /// never reveals *where* the tags diverged.
    fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()>
    where
        Self: Sized,
    {
        let expected = Self::mac(key, data)?;
        if crate::ct::verify(expected.as_ref(), tag) {
            Ok(())
        } else {
            Err(crate::err!(AuthenticationFailed, "mac tag"))
        }
    }
}

/// A fixed-width block cipher primitive (raw ECB core, for use inside modes).
pub trait BlockCipher: Algorithm {
    /// Block size in bytes.
    const BLOCK_LEN: usize;
    /// Accepted key length in bytes.
    const KEY_LEN: usize;

    /// Expand a key into a round-key schedule.
    fn new(key: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Encrypt a single block in place.
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()>;

    /// Decrypt a single block in place.
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()>;

    /// Encrypt a whole number of blocks in place.
    ///
    /// The default implementation loops over [`encrypt_block`][Self::encrypt_block].
    /// Backends with instruction-level parallelism override it: AES-NI has a
    /// pipelined round instruction, so encrypting eight independent blocks at
    /// once is several times faster than eight sequential calls. Counter-based
    /// modes route through here for exactly that reason.
    ///
    /// Returns [`crate::ErrorKind::InvalidLength`] if `data` is not a whole
    /// number of blocks.
    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        if data.len() % Self::BLOCK_LEN != 0 {
            return Err(crate::err!(InvalidLength, "batch must be block-aligned"));
        }
        for block in data.chunks_mut(Self::BLOCK_LEN) {
            self.encrypt_block(block)?;
        }
        Ok(())
    }
}

/// An authenticated cipher with associated data.
pub trait Aead: Algorithm {
    /// Key length in bytes.
    const KEY_LEN: usize;
    /// Nonce length in bytes.
    const NONCE_LEN: usize;
    /// Authentication tag length in bytes.
    const TAG_LEN: usize;

    /// Bind a key to a cipher instance.
    fn new(key: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Encrypt `in_out` in place and write the tag to `tag`.
    fn seal_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()>;

    /// Verify `tag` and decrypt `in_out` in place.
    ///
    /// On failure `in_out` is zeroized before returning, so a caller that
    /// ignores the error cannot expose unauthenticated plaintext.
    fn open_detached(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<()>;
}

/// A key derivation function that expands keying material to a requested length.
pub trait Kdf: Algorithm {
    /// Derive `out.len()` bytes from the supplied inputs.
    fn derive(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()>;
}

/// A deterministic random bit generator (SP 800-90A).
pub trait Drbg: Algorithm {
    /// Instantiate from entropy input, a nonce, and an optional personalization
    /// string.
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Reseed with fresh entropy and optional additional input.
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()>;

    /// Fill `out` with generated bits, honouring the reseed interval.
    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()>;
}

/// A source of random bytes suitable for key generation.
pub trait RandomSource {
    /// Fill `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}

/// A Diffie-Hellman style key agreement scheme.
pub trait KeyAgreement: Algorithm {
    /// Private key (scalar) length in bytes.
    const PRIVATE_KEY_LEN: usize;
    /// Public key (encoded point) length in bytes.
    const PUBLIC_KEY_LEN: usize;
    /// Shared secret length in bytes.
    const SHARED_SECRET_LEN: usize;

    /// Compute the public key for a private key.
    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()>;

    /// Compute the shared secret from our private key and their public key.
    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()>;
}

/// A digital signature scheme.
pub trait SignatureScheme: Algorithm {
    /// Seed / private key length in bytes.
    const PRIVATE_KEY_LEN: usize;
    /// Public key length in bytes.
    const PUBLIC_KEY_LEN: usize;
    /// Signature length in bytes.
    const SIGNATURE_LEN: usize;

    /// Derive the public key from a private key.
    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()>;

    /// Sign `message`, writing exactly [`Self::SIGNATURE_LEN`] bytes.
    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()>;

    /// Verify a signature, returning [`crate::ErrorKind::AuthenticationFailed`]
    /// when it does not check out.
    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;
}

/// A known-answer test an implementation runs to satisfy FIPS 140-3 CAST
/// requirements.
///
/// Implemented by every approved algorithm so `ic-fips` can enumerate and drive
/// the full self-test suite without hard-coding a list.
pub trait SelfTest {
    /// Run the algorithm's known-answer test.
    ///
    /// Returns [`crate::ErrorKind::SelfTestFailed`] if the computed value does
    /// not match the embedded vector.
    fn self_test() -> Result<()>;
}
