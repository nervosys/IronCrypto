//! HPKE, RFC 9180, in base mode with DHKEM(X25519, HKDF-SHA256) and
//! HKDF-SHA256 -- or, in [`p384`], DHKEM(P-384, HKDF-SHA384) and HKDF-SHA384 --
//! over AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305.
//!
//! HPKE encrypts to a recipient's public key: a fresh X25519 exchange makes a
//! shared secret, a key schedule turns it and the caller's `info` into an AEAD
//! key and a base nonce, and a [`Context`] then seals or opens a sequence of
//! messages under them. Encrypted Client Hello and MLS are built on it.
//!
//! ```
//! # fn main() -> ic_core::Result<()> {
//! use ic_hpke::{setup_receiver, setup_sender, Aead, KeyPair};
//! let mut rng = ic_drbg::Rng::from_os()?;
//! let recipient = KeyPair::generate(&mut rng)?;
//! let (enc, mut sender) = setup_sender(recipient.public(), b"app/v1", Aead::Aes128Gcm, &mut rng)?;
//! let mut receiver = setup_receiver(&enc, &recipient, b"app/v1", Aead::Aes128Gcm)?;
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; ic_hpke::TAG_LEN];
//! sender.seal_in_place(b"header", &mut message, &mut tag)?;
//! receiver.open_in_place(b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```
//!
//! # What is here, and what is not
//!
//! Base mode only: no PSK, auth or auth-PSK modes. Two KEMs: X25519, here,
//! and P-384 in [`p384`], each with its own KDF -- MLS cipher suites 1 and 7.
//! That is what Encrypted Client Hello and MLS use; the other modes and KEMs
//! are not implemented rather than half-implemented. The export interface is
//! here.
//!
//! # Sequence numbers
//!
//! Each seal or open uses the next sequence number, XORed into the base
//! nonce, and a context never reuses one. RFC 9180 allows up to `2^96 - 1`
//! messages; this counts in a `u64` and refuses with `CounterExhausted` once
//! it would wrap, which no real exchange reaches. A failed open does not
//! advance the sequence, so a forged message cannot desynchronize the two
//! sides.
//!
//! # Verification
//!
//! Checked against RFC 9180 appendix A.1.1, reproduced by an independent
//! implementation written from the specification
//! (`scripts/gen_hpke_vectors.py`), and against that implementation for the
//! other two AEADs, every sequence number it covers, and the exporter.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use ic_cipher::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use ic_core::traits::{Aead as AeadTrait, Algorithm, KeyAgreement, Mac, RandomSource, SelfTest};
use ic_core::{ensure, Result, Zeroize, Zeroizing};
use ic_ec::X25519;
use ic_mac::{HmacSha256, HmacSha384};

pub mod p384;

/// `DHKEM(X25519, HKDF-SHA256)`, RFC 9180 section 7.1.
pub const KEM_ID: u16 = 0x0020;
/// `HKDF-SHA256`, RFC 9180 section 7.2.
pub const KDF_ID: u16 = 0x0001;
/// Length of an encapsulated key, `Nenc`.
pub const ENC_LEN: usize = 32;
/// Length of a public key, `Npk`.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a private key, `Nsk`.
pub const PRIVATE_KEY_LEN: usize = 32;
/// Length of every AEAD tag here, `Nt`.
pub const TAG_LEN: usize = 16;
/// Length of every AEAD nonce here, `Nn`.
pub const NONCE_LEN: usize = 12;
/// The longest export: `255 * Nh`.
pub const MAX_EXPORT_LEN: usize = 255 * 32;

/// The HKDF hash: the KEM's own, and the key schedule's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kdf {
    /// HKDF-SHA256, identifier `0x0001`.
    Sha256,
    /// HKDF-SHA384, identifier `0x0002`.
    Sha384,
}

/// The longest `Nh` among the KDFs here.
pub(crate) const MAX_NH: usize = 48;

impl Kdf {
    pub(crate) const fn id(self) -> u16 {
        match self {
            Self::Sha256 => 0x0001,
            Self::Sha384 => 0x0002,
        }
    }

    /// The hash length, `Nh`.
    pub(crate) const fn nh(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// HMAC under `key` over the concatenation of `parts`, written to
    /// `out`, which is `Nh` bytes.
    fn hmac(self, key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<()> {
        ensure!(out.len() == self.nh(), Internal, "hpke hmac output length");
        match self {
            Self::Sha256 => {
                let mut mac = HmacSha256::new(key)?;
                for part in parts {
                    mac.update(part);
                }
                out.copy_from_slice(mac.finalize().as_ref());
            }
            Self::Sha384 => {
                let mut mac = HmacSha384::new(key)?;
                for part in parts {
                    mac.update(part);
                }
                out.copy_from_slice(mac.finalize().as_ref());
            }
        }
        Ok(())
    }
}

/// The AEADs this crate implements, RFC 9180 section 7.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aead {
    /// AES-128-GCM, identifier `0x0001`.
    Aes128Gcm,
    /// AES-256-GCM, identifier `0x0002`.
    Aes256Gcm,
    /// ChaCha20-Poly1305, identifier `0x0003`.
    ChaCha20Poly1305,
}

impl Aead {
    /// The AEAD's HPKE identifier.
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
        }
    }

    /// The AEAD an HPKE identifier names, if this crate implements it.
    ///
    /// `None` for anything else, the export-only `0xFFFF` included: a peer
    /// offering several suites is answered by taking the first one this
    /// returns `Some` for.
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(Self::Aes128Gcm),
            0x0002 => Some(Self::Aes256Gcm),
            0x0003 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The key length, `Nk`.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
}

/// The HPKE suite, for the ontology and the self-test table.
pub struct Hpke;

impl Algorithm for Hpke {
    const ID: &'static str = "hpke-x25519-sha256";
    const NAME: &'static str = "HPKE (DHKEM(X25519, HKDF-SHA256), base mode)";
}

/// An X25519 key pair: a recipient's long-lived key, or a sender's ephemeral.
pub struct KeyPair {
    private: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    public: [u8; PUBLIC_KEY_LEN],
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// A fresh key pair, RFC 9180's `GenerateKeyPair`: 32 random bytes as the
    /// private key.
    ///
    /// The pair is given a pairwise consistency test before it is returned,
    /// and withheld with `SelfTestFailed` if it fails -- which also puts the
    /// module into its error state.
    pub fn generate<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Self> {
        ic_core::module::operational()?;
        let key = Self::generate_untested(rng)?;
        // A failure means this module disagrees with itself, so it ends the
        // module and not only this call.
        ic_core::module::conditional_self_test(key.pairwise_consistency())?;
        Ok(key)
    }

    /// [`generate`](Self::generate) without the pairwise consistency test,
    /// for the ephemeral key of [`setup_sender`]. That key is used once, in
    /// the two scalar multiplications that follow, and testing it would add
    /// a third to every message sent.
    fn generate_untested<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut private = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        rng.fill(private.get_mut())?;
        Self::from_private(private.get())
    }

    /// The pairwise consistency test for a generated key pair: the public key
    /// is computed from the private key a second time and must be the one
    /// the pair holds.
    ///
    /// For a key-agreement key that recomputation is the test: there is no
    /// second operation, as a signature has verification, to apply in turn.
    /// It cannot catch a wrong scalar multiplication that is wrong the same
    /// way twice -- the known-answer tests are for that -- and does catch a
    /// fault between the first computation and the key's first use.
    fn pairwise_consistency(&self) -> Result<()> {
        let mut again = [0u8; PUBLIC_KEY_LEN];
        X25519::public_key(self.private.get(), &mut again)?;
        ensure!(
            ic_core::ct::verify(&again, &self.public),
            SelfTestFailed,
            "hpke key pair failed its pairwise consistency test; the key is withheld"
        );
        Ok(())
    }

    /// The key pair for a 32-byte X25519 private key, `DeserializePrivateKey`.
    ///
    /// Any 32 bytes are a valid X25519 private key, since X25519 clamps them;
    /// anything else is refused with `InvalidLength`.
    pub fn from_private(private: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(
            private.len() == PRIVATE_KEY_LEN,
            InvalidLength,
            "hpke x25519 private key must be 32 bytes"
        );
        let mut key = Self {
            private: Zeroizing::new([0u8; PRIVATE_KEY_LEN]),
            public: [0u8; PUBLIC_KEY_LEN],
        };
        key.private.get_mut().copy_from_slice(private);
        X25519::public_key(private, &mut key.public)?;
        Ok(key)
    }

    /// The key pair derived from `ikm`: RFC 9180 section 7.1.3's
    /// `DeriveKeyPair` for DHKEM(X25519).
    ///
    /// `dkp_prk = LabeledExtract("", "dkp_prk", ikm)` and
    /// `sk = LabeledExpand(dkp_prk, "sk", "", 32)`, under the KEM's suite
    /// identifier. Deterministic: the same `ikm` always gives the same pair,
    /// which is what MLS's TreeKEM relies on to turn a path secret into a node
    /// key. `ikm` must carry at least `Nsk` bytes of entropy, so shorter input
    /// is refused with `InvalidLength`; its length is the one thing here that
    /// can be checked.
    pub fn derive(ikm: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(
            ikm.len() >= PRIVATE_KEY_LEN,
            InvalidLength,
            "hpke DeriveKeyPair needs at least 32 bytes of ikm"
        );
        let kem = kem_suite_id(KEM_ID);
        let mut dkp_prk = Zeroizing::new([0u8; 32]);
        labeled_extract(
            Kdf::Sha256,
            &kem,
            b"",
            b"dkp_prk",
            &[ikm],
            dkp_prk.get_mut(),
        )?;
        let mut sk = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        labeled_expand(Kdf::Sha256, &kem, dkp_prk.get(), b"sk", &[], sk.get_mut())?;
        Self::from_private(sk.get())
    }

    /// The public key, `SerializePublicKey`.
    pub fn public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

/// The AEAD, keyed.
enum Cipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl Cipher {
    fn new(aead: Aead, key: &[u8]) -> Result<Self> {
        Ok(match aead {
            Aead::Aes128Gcm => Self::Aes128(Aes128Gcm::new(key)?),
            Aead::Aes256Gcm => Self::Aes256(Aes256Gcm::new(key)?),
            Aead::ChaCha20Poly1305 => Self::ChaCha(ChaCha20Poly1305::new(key)?),
        })
    }

    fn aead(&self) -> Aead {
        match self {
            Self::Aes128(_) => Aead::Aes128Gcm,
            Self::Aes256(_) => Aead::Aes256Gcm,
            Self::ChaCha(_) => Aead::ChaCha20Poly1305,
        }
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &mut [u8]) -> Result<()> {
        match self {
            Self::Aes128(c) => c.seal_detached(nonce, aad, in_out, tag),
            Self::Aes256(c) => c.seal_detached(nonce, aad, in_out, tag),
            Self::ChaCha(c) => c.seal_detached(nonce, aad, in_out, tag),
        }
    }

    fn open(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<()> {
        match self {
            Self::Aes128(c) => c.open_detached(nonce, aad, in_out, tag),
            Self::Aes256(c) => c.open_detached(nonce, aad, in_out, tag),
            Self::ChaCha(c) => c.open_detached(nonce, aad, in_out, tag),
        }
    }
}

/// An established HPKE context: the sender's or the receiver's side.
///
/// Seals or opens messages in order, each under the next sequence number. The
/// AEAD key, base nonce and exporter secret are wiped when it is dropped; the
/// AEAD types wipe their own key schedules.
pub struct Context {
    cipher: Cipher,
    kdf: Kdf,
    suite: [u8; 10],
    base_nonce: Zeroizing<[u8; NONCE_LEN]>,
    /// The first `Nh` bytes are the exporter secret.
    exporter_secret: Zeroizing<[u8; MAX_NH]>,
    seq: u64,
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("aead", &self.cipher.aead())
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl Context {
    /// Which AEAD this context uses.
    pub fn aead(&self) -> Aead {
        self.cipher.aead()
    }

    /// The sequence number the next seal or open will use.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// `ComputeNonce`: the base nonce XOR the sequence number, big-endian.
    fn nonce(&self) -> Result<[u8; NONCE_LEN]> {
        ensure!(
            self.seq != u64::MAX,
            CounterExhausted,
            "hpke sequence number exhausted; a context never reuses a nonce"
        );
        let mut nonce = *self.base_nonce.get();
        for (n, s) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(self.seq.to_be_bytes())
        {
            *n ^= s;
        }
        Ok(nonce)
    }

    /// Seal `in_out` in place under the next sequence number, writing the tag.
    pub fn seal_in_place(
        &mut self,
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Result<()> {
        ic_core::module::operational()?;
        let nonce = self.nonce()?;
        self.cipher.seal(&nonce, aad, in_out, tag)?;
        self.seq += 1;
        Ok(())
    }

    /// Open `in_out` in place under the next sequence number.
    ///
    /// On failure the sequence number does not advance, and `in_out` holds no
    /// unauthenticated plaintext: the AEAD wipes it.
    pub fn open_in_place(
        &mut self,
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<()> {
        ic_core::module::operational()?;
        let nonce = self.nonce()?;
        self.cipher.open(&nonce, aad, in_out, tag)?;
        self.seq += 1;
        Ok(())
    }

    /// Seal `plaintext`, returning the ciphertext with the tag appended.
    #[cfg(feature = "std")]
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<std::vec::Vec<u8>> {
        let mut out = std::vec::Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        let mut tag = [0u8; TAG_LEN];
        self.seal_in_place(aad, &mut out, &mut tag)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open a ciphertext with its tag appended, returning the plaintext.
    ///
    /// A ciphertext shorter than a tag is refused with `AuthenticationFailed`,
    /// like any other that does not authenticate, and does not advance the
    /// sequence number.
    #[cfg(feature = "std")]
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<std::vec::Vec<u8>> {
        ensure!(
            ciphertext.len() >= TAG_LEN,
            AuthenticationFailed,
            "hpke ciphertext shorter than its tag"
        );
        let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag);
        let mut out = body.to_vec();
        self.open_in_place(aad, &mut out, &tag_bytes)?;
        Ok(out)
    }

    /// The exporter, `Context.Export`: `out.len()` bytes bound to this context
    /// and to `exporter_context`.
    ///
    /// Up to `255 * Nh` bytes -- [`MAX_EXPORT_LEN`] for the X25519 suite,
    /// [`p384::MAX_EXPORT_LEN`] for P-384; longer is refused with
    /// `InvalidLength`.
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        labeled_expand(
            self.kdf,
            &self.suite,
            &self.exporter_secret.get()[..self.kdf.nh()],
            b"sec",
            &[exporter_context],
            out,
        )
    }
}

/// Set up a sender's context to `recipient_public`, with a fresh ephemeral key.
///
/// Returns the encapsulated key, which the recipient needs, and the context.
/// `SetupBaseS` in RFC 9180.
pub fn setup_sender<R: RandomSource + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aead: Aead,
    rng: &mut R,
) -> Result<([u8; ENC_LEN], Context)> {
    ic_core::module::operational()?;
    let ephemeral = KeyPair::generate_untested(rng)?;
    setup_sender_with_ephemeral(recipient_public, info, aead, &ephemeral)
}

/// [`setup_sender`] with the ephemeral key given rather than generated.
///
/// For replaying RFC 9180's test vectors, whose ephemeral keys are fixed. An
/// ephemeral key used twice gives two messages the same shared secret, so
/// anything else should call [`setup_sender`].
pub fn setup_sender_with_ephemeral(
    recipient_public: &[u8],
    info: &[u8],
    aead: Aead,
    ephemeral: &KeyPair,
) -> Result<([u8; ENC_LEN], Context)> {
    ic_core::module::operational()?;
    ensure!(
        recipient_public.len() == PUBLIC_KEY_LEN,
        InvalidLength,
        "hpke x25519 public key must be 32 bytes"
    );
    let mut dh = Zeroizing::new([0u8; 32]);
    X25519::agree(ephemeral.private.get(), recipient_public, dh.get_mut())?;
    let enc = ephemeral.public;
    let shared_secret = extract_and_expand(dh.get(), &enc, recipient_public)?;
    let context = key_schedule(KEM_ID, Kdf::Sha256, aead, shared_secret.get(), info)?;
    Ok((enc, context))
}

/// Set up a recipient's context from the sender's encapsulated key.
///
/// `SetupBaseR` in RFC 9180.
pub fn setup_receiver(enc: &[u8], recipient: &KeyPair, info: &[u8], aead: Aead) -> Result<Context> {
    ic_core::module::operational()?;
    ensure!(
        enc.len() == ENC_LEN,
        InvalidLength,
        "hpke enc must be 32 bytes"
    );
    let mut dh = Zeroizing::new([0u8; 32]);
    X25519::agree(recipient.private.get(), enc, dh.get_mut())?;
    let shared_secret = extract_and_expand(dh.get(), enc, &recipient.public)?;
    key_schedule(KEM_ID, Kdf::Sha256, aead, shared_secret.get(), info)
}

/// DHKEM(X25519)'s `ExtractAndExpand`, from the DH output and `enc || pkR`.
///
/// An all-zero DH output is refused here as well as in X25519, as RFC 9180
/// section 7.1.4 requires of the KEM: the second check is what holds if the
/// first ever changes.
fn extract_and_expand(dh: &[u8; 32], enc: &[u8], pk_r: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        !bool::from(ic_core::ct::is_zero(dh)),
        InvalidParameter,
        "hpke: all-zero x25519 output"
    );
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    dhkem_extract_and_expand(KEM_ID, Kdf::Sha256, dh, enc, pk_r, shared_secret.get_mut())?;
    Ok(shared_secret)
}

/// DHKEM's `ExtractAndExpand` for any KEM: `Nsecret` bytes, `out.len()`,
/// under the KEM's suite identifier and hash.
pub(crate) fn dhkem_extract_and_expand(
    kem_id: u16,
    kdf: Kdf,
    dh: &[u8],
    enc: &[u8],
    pk_r: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let kem_suite = kem_suite_id(kem_id);
    let mut eae_prk = Zeroizing::new([0u8; MAX_NH]);
    let eae_prk = &mut eae_prk.get_mut()[..kdf.nh()];
    labeled_extract(kdf, &kem_suite, b"", b"eae_prk", &[dh], eae_prk)?;
    labeled_expand(
        kdf,
        &kem_suite,
        eae_prk,
        b"shared_secret",
        &[enc, pk_r],
        out,
    )
}

/// `KeySchedule` in base mode: no PSK, so `psk` and `psk_id` are empty.
pub(crate) fn key_schedule(
    kem_id: u16,
    kdf: Kdf,
    aead: Aead,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Context> {
    const MODE_BASE: u8 = 0x00;
    let suite = suite_id(kem_id, kdf, aead);
    let nh = kdf.nh();

    let mut psk_id_hash = [0u8; MAX_NH];
    labeled_extract(
        kdf,
        &suite,
        b"",
        b"psk_id_hash",
        &[],
        &mut psk_id_hash[..nh],
    )?;
    let mut info_hash = [0u8; MAX_NH];
    labeled_extract(
        kdf,
        &suite,
        b"",
        b"info_hash",
        &[info],
        &mut info_hash[..nh],
    )?;
    let mut ksc = [0u8; 1 + 2 * MAX_NH];
    ksc[0] = MODE_BASE;
    ksc[1..1 + nh].copy_from_slice(&psk_id_hash[..nh]);
    ksc[1 + nh..1 + 2 * nh].copy_from_slice(&info_hash[..nh]);
    let ksc = &ksc[..1 + 2 * nh];

    let mut secret = Zeroizing::new([0u8; MAX_NH]);
    let secret = &mut secret.get_mut()[..nh];
    labeled_extract(kdf, &suite, shared_secret, b"secret", &[], secret)?;

    let mut key = Zeroizing::new([0u8; 32]);
    let key = &mut key.get_mut()[..aead.key_len()];
    labeled_expand(kdf, &suite, secret, b"key", &[ksc], key)?;
    let mut base_nonce = Zeroizing::new([0u8; NONCE_LEN]);
    labeled_expand(
        kdf,
        &suite,
        secret,
        b"base_nonce",
        &[ksc],
        base_nonce.get_mut(),
    )?;
    let mut exporter_secret = Zeroizing::new([0u8; MAX_NH]);
    labeled_expand(
        kdf,
        &suite,
        secret,
        b"exp",
        &[ksc],
        &mut exporter_secret.get_mut()[..nh],
    )?;

    let cipher = Cipher::new(aead, key)?;
    key.zeroize();
    Ok(Context {
        cipher,
        kdf,
        suite,
        base_nonce,
        exporter_secret,
        seq: 0,
    })
}

/// `"KEM" || I2OSP(kem_id, 2)`.
pub(crate) fn kem_suite_id(kem_id: u16) -> [u8; 5] {
    let [a, b] = kem_id.to_be_bytes();
    [b'K', b'E', b'M', a, b]
}

/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
fn suite_id(kem_id: u16, kdf: Kdf, aead: Aead) -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&kem_id.to_be_bytes());
    s[6..8].copy_from_slice(&kdf.id().to_be_bytes());
    s[8..].copy_from_slice(&aead.id().to_be_bytes());
    s
}

/// `LabeledExtract(salt, label, ikm)`: HKDF-Extract with key `salt` over
/// `"HPKE-v1" || suite_id || label || ikm`, the ikm given in parts so that no
/// concatenation is ever built. `out` is `Nh` bytes.
///
/// An empty salt is the HKDF default of `Nh` zero bytes, which HMAC's key
/// padding makes the same key.
pub(crate) fn labeled_extract(
    kdf: Kdf,
    suite: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[&[u8]],
    out: &mut [u8],
) -> Result<()> {
    let mut parts: [&[u8]; 8] = [b"HPKE-v1", suite, label, &[], &[], &[], &[], &[]];
    ensure!(
        ikm.len() <= 5,
        Internal,
        "hpke labeled extract: too many parts"
    );
    parts[3..3 + ikm.len()].copy_from_slice(ikm);
    kdf.hmac(salt, &parts[..3 + ikm.len()], out)
}

/// `LabeledExpand(prk, label, info, L)`: HKDF-Expand over
/// `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`, info in parts.
pub(crate) fn labeled_expand(
    kdf: Kdf,
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<()> {
    let nh = kdf.nh();
    ensure!(
        out.len() <= 255 * nh,
        InvalidLength,
        "hpke expand longer than 255 * Nh"
    );
    ensure!(
        info.len() <= 3,
        Internal,
        "hpke labeled expand: too many parts"
    );
    let length = (out.len() as u16).to_be_bytes();
    let mut previous = Zeroizing::new([0u8; MAX_NH]);
    for (i, chunk) in out.chunks_mut(nh).enumerate() {
        let counter = [i as u8 + 1];
        let prev: &[u8] = if i > 0 { &previous.get()[..nh] } else { &[] };
        let mut parts: [&[u8]; 9] = [prev, &length, b"HPKE-v1", suite, label, &[], &[], &[], &[]];
        parts[5..5 + info.len()].copy_from_slice(info);
        parts[5 + info.len()] = &counter;
        let mut block = [0u8; MAX_NH];
        kdf.hmac(prk, &parts[..6 + info.len()], &mut block[..nh])?;
        previous.get_mut()[..nh].copy_from_slice(&block[..nh]);
        block.zeroize();
        chunk.copy_from_slice(&previous.get()[..chunk.len()]);
    }
    Ok(())
}

impl SelfTest for Hpke {
    /// RFC 9180 appendix A.1.1: base mode, AES-128-GCM, the first encryption.
    ///
    /// The ciphertext depends on every stage -- the X25519 exchange, DHKEM's
    /// extract and expand, the key schedule and the AEAD -- so one comparison
    /// covers the construction. The receiver then opens it.
    fn self_test() -> Result<()> {
        let sk_e = hex32("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")?;
        let sk_r = hex32("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")?;
        let mut info = [0u8; 20];
        ic_core::codec::hex_decode(b"4f6465206f6e2061204772656369616e2055726e", &mut info)?;
        let mut message = [0u8; 29];
        ic_core::codec::hex_decode(
            b"4265617574792069732074727574682c20747275746820626561757479",
            &mut message,
        )?;
        let mut want = [0u8; 29 + TAG_LEN];
        ic_core::codec::hex_decode(
            b"f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            &mut want,
        )?;

        let ephemeral = KeyPair::from_private(&sk_e)?;
        let recipient = KeyPair::from_private(&sk_r)?;
        let (enc, mut sender) =
            setup_sender_with_ephemeral(recipient.public(), &info, Aead::Aes128Gcm, &ephemeral)?;
        let plaintext = message;
        let mut tag = [0u8; TAG_LEN];
        sender.seal_in_place(b"Count-0", &mut message, &mut tag)?;
        let sealed =
            ic_core::ct::verify(&want[..29], &message) && ic_core::ct::verify(&want[29..], &tag);
        ensure!(
            sealed,
            SelfTestFailed,
            "hpke: sealed ciphertext differs from RFC 9180 A.1.1"
        );

        let mut receiver = setup_receiver(&enc, &recipient, &info, Aead::Aes128Gcm)?;
        receiver.open_in_place(b"Count-0", &mut message, &tag)?;
        ensure!(
            ic_core::ct::verify(&plaintext, &message),
            SelfTestFailed,
            "hpke: opened plaintext differs"
        );
        Ok(())
    }
}

fn hex32(hex: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    ic_core::codec::hex_decode(hex.as_bytes(), &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(seed: u8) -> KeyPair {
        KeyPair::from_private(&[seed; 32]).unwrap()
    }

    /// The pairwise consistency test must actually reject a pair whose halves
    /// do not correspond, and a generated pair must pass it.
    #[test]
    fn the_pairwise_consistency_test_rejects_a_mismatched_pair() {
        let (a, b) = (pair(1), pair(2));
        a.pairwise_consistency().unwrap();
        b.pairwise_consistency().unwrap();
        let crossed = KeyPair {
            private: Zeroizing::new(*a.private.get()),
            public: b.public,
        };
        assert_eq!(
            crossed.pairwise_consistency().unwrap_err().kind(),
            ic_core::ErrorKind::SelfTestFailed
        );
        // One bit of the public key is enough.
        let mut flipped = pair(1);
        flipped.public[31] ^= 0x01;
        assert!(flipped.pairwise_consistency().is_err());

        let mut rng = Counter(0);
        let generated = KeyPair::generate(&mut rng).unwrap();
        generated.pairwise_consistency().unwrap();
        // The untested path makes the same key from the same randomness: the
        // test adds a check and changes nothing else.
        let mut rng = Counter(0);
        assert_eq!(
            KeyPair::generate_untested(&mut rng).unwrap().public,
            generated.public
        );
    }

    /// A source that counts, so two runs draw the same bytes.
    struct Counter(u8);
    impl RandomSource for Counter {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            for b in out {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }

    #[test]
    fn the_self_test_passes() {
        Hpke::self_test().unwrap();
    }

    #[test]
    fn identifiers_round_trip_and_unknown_ones_are_none() {
        for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
            assert_eq!(Aead::from_id(aead.id()), Some(aead));
        }
        for id in [0x0000, 0x0004, 0xFFFF] {
            assert_eq!(Aead::from_id(id), None, "{id:#06x}");
        }
    }

    /// Contexts stay in step over several messages, a tampered message is
    /// refused without advancing either side, and a different `info` gives a
    /// context that cannot open.
    #[test]
    fn contexts_stay_in_step_and_refuse_tampering() {
        let recipient = pair(3);
        for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
            let (enc, mut tx) =
                setup_sender_with_ephemeral(recipient.public(), b"info", aead, &pair(4)).unwrap();
            let mut rx = setup_receiver(&enc, &recipient, b"info", aead).unwrap();
            for i in 0..3u8 {
                let mut m = [i; 7];
                let mut tag = [0u8; TAG_LEN];
                tx.seal_in_place(&[i], &mut m, &mut tag).unwrap();
                let mut bad = m;
                bad[0] ^= 1;
                assert!(rx.open_in_place(&[i], &mut bad, &tag).is_err());
                assert_eq!(
                    rx.sequence(),
                    u64::from(i),
                    "a failed open must not advance"
                );
                rx.open_in_place(&[i], &mut m, &tag).unwrap();
                assert_eq!(m, [i; 7]);
            }
            let mut other = setup_receiver(&enc, &recipient, b"other", aead).unwrap();
            let mut m = [9u8; 4];
            let mut tag = [0u8; TAG_LEN];
            tx.seal_in_place(b"", &mut m, &mut tag).unwrap();
            assert!(other.open_in_place(b"", &mut m, &tag).is_err());
        }
    }

    /// RFC 9180 section 5.2: a context never reuses a nonce, so it refuses
    /// once the sequence number would wrap.
    #[test]
    fn an_exhausted_context_refuses_rather_than_reusing_a_nonce() {
        let recipient = pair(5);
        let (enc, mut tx) =
            setup_sender_with_ephemeral(recipient.public(), b"", Aead::Aes128Gcm, &pair(6))
                .unwrap();
        let mut rx = setup_receiver(&enc, &recipient, b"", Aead::Aes128Gcm).unwrap();
        tx.seq = u64::MAX - 1;
        rx.seq = u64::MAX - 1;
        let mut m = *b"last";
        let mut tag = [0u8; TAG_LEN];
        tx.seal_in_place(b"", &mut m, &mut tag).unwrap();
        rx.open_in_place(b"", &mut m, &tag).unwrap();
        assert_eq!(
            tx.seal_in_place(b"", &mut m, &mut tag).unwrap_err().kind(),
            ic_core::ErrorKind::CounterExhausted
        );
        assert_eq!(
            rx.open_in_place(b"", &mut m, &tag).unwrap_err().kind(),
            ic_core::ErrorKind::CounterExhausted
        );
    }

    /// RFC 9180 section 7.1.4: an all-zero DH output is refused. X25519
    /// refuses it first, for a low-order key; this module's own check is
    /// exercised directly.
    #[test]
    fn an_all_zero_shared_secret_is_refused() {
        let recipient = pair(7);
        assert!(setup_sender_with_ephemeral(&[0u8; 32], b"", Aead::Aes128Gcm, &pair(8)).is_err());
        assert!(setup_receiver(&[0u8; 32], &recipient, b"", Aead::Aes128Gcm).is_err());
        let err = extract_and_expand(&[0u8; 32], &[1u8; 32], &[2u8; 32]).unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::InvalidParameter);
        assert!(extract_and_expand(&[1u8; 32], &[1u8; 32], &[2u8; 32]).is_ok());
    }

    /// RFC 9180 appendix A.1.1's key derivation: `ikmE` and `ikmR` give the
    /// appendix's `skEm` and `skRm`, and with them `pkEm`. The two private keys
    /// are the ones `the_self_test_passes` and `tests/hpke.rs` already use, so
    /// the whole appendix case now runs from its seeds. The `ikm` values were
    /// confirmed by an independent derivation reaching the same keys.
    #[test]
    fn derive_key_pair_matches_rfc9180_a1_1() {
        let hex = |h: &str| {
            let mut out = [0u8; 32];
            ic_core::codec::hex_decode(h.as_bytes(), &mut out).unwrap();
            out
        };
        let e = KeyPair::derive(&hex(
            "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
        ))
        .unwrap();
        let r = KeyPair::derive(&hex(
            "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
        ))
        .unwrap();
        assert_eq!(
            *e.private.get(),
            hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
            "skEm"
        );
        assert_eq!(
            *e.public(),
            hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
            "pkEm"
        );
        assert_eq!(
            *r.private.get(),
            hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"),
            "skRm"
        );
        assert!(KeyPair::derive(&[7u8; 31]).is_err(), "31 bytes of ikm");
        assert!(KeyPair::derive(&[7u8; 64]).is_ok(), "longer ikm");
    }

    #[test]
    fn wrong_lengths_are_refused() {
        let recipient = pair(9);
        for len in [0usize, 31, 33] {
            let v = [9u8; 33];
            assert!(
                KeyPair::from_private(&v[..len]).is_err(),
                "private key of {len}"
            );
            assert!(
                setup_sender_with_ephemeral(&v[..len], b"", Aead::Aes128Gcm, &pair(1)).is_err(),
                "public key of {len}"
            );
            assert!(
                setup_receiver(&v[..len], &recipient, b"", Aead::Aes128Gcm).is_err(),
                "enc of {len}"
            );
        }
        let (_, ctx) =
            setup_sender_with_ephemeral(recipient.public(), b"", Aead::Aes128Gcm, &pair(1))
                .unwrap();
        let mut long = [0u8; MAX_EXPORT_LEN + 1];
        assert!(ctx.export(b"", &mut long).is_err());
        ctx.export(b"", &mut long[..MAX_EXPORT_LEN]).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn the_vec_forms_agree_with_the_in_place_ones() {
        let recipient = pair(11);
        let (enc, mut tx) = setup_sender_with_ephemeral(
            recipient.public(),
            b"i",
            Aead::ChaCha20Poly1305,
            &pair(12),
        )
        .unwrap();
        let mut rx = setup_receiver(&enc, &recipient, b"i", Aead::ChaCha20Poly1305).unwrap();
        let ct = tx.seal(b"a", b"payload").unwrap();
        assert_eq!(ct.len(), 7 + TAG_LEN);
        for short in 0..TAG_LEN {
            assert!(rx.open(b"a", &ct[..short]).is_err());
            assert_eq!(rx.sequence(), 0);
        }
        assert_eq!(rx.open(b"a", &ct).unwrap(), b"payload");
    }
}
