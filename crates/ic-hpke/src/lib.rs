//! HPKE, RFC 9180, in base mode with DHKEM(X25519, HKDF-SHA256) and
//! HKDF-SHA256, over AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305.
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
//! Base mode only: no PSK, auth or auth-PSK modes, and one KEM. That is what
//! Encrypted Client Hello and MLS use; the other modes and KEMs are not
//! implemented rather than half-implemented. The export interface is here.
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
use ic_mac::HmacSha256;

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
    pub fn generate<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut private = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        rng.fill(private.get_mut())?;
        Self::from_private(private.get())
    }

    /// The key pair for a 32-byte X25519 private key, `DeserializePrivateKey`.
    ///
    /// Any 32 bytes are a valid X25519 private key, since X25519 clamps them;
    /// anything else is refused with `InvalidLength`.
    pub fn from_private(private: &[u8]) -> Result<Self> {
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
        ensure!(
            ikm.len() >= PRIVATE_KEY_LEN,
            InvalidLength,
            "hpke DeriveKeyPair needs at least 32 bytes of ikm"
        );
        let kem = kem_suite_id();
        let mut dkp_prk = Zeroizing::new([0u8; 32]);
        labeled_extract(&kem, b"", b"dkp_prk", &[ikm], dkp_prk.get_mut())?;
        let mut sk = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        labeled_expand(&kem, dkp_prk.get(), b"sk", &[], sk.get_mut())?;
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
    base_nonce: Zeroizing<[u8; NONCE_LEN]>,
    exporter_secret: Zeroizing<[u8; 32]>,
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
    /// Up to [`MAX_EXPORT_LEN`] bytes; longer is refused with `InvalidLength`.
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<()> {
        labeled_expand(
            &suite_id(self.aead()),
            self.exporter_secret.get(),
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
    let ephemeral = KeyPair::generate(rng)?;
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
    ensure!(
        recipient_public.len() == PUBLIC_KEY_LEN,
        InvalidLength,
        "hpke x25519 public key must be 32 bytes"
    );
    let mut dh = Zeroizing::new([0u8; 32]);
    X25519::agree(ephemeral.private.get(), recipient_public, dh.get_mut())?;
    let enc = ephemeral.public;
    let shared_secret = extract_and_expand(dh.get(), &enc, recipient_public)?;
    let context = key_schedule(aead, shared_secret.get(), info)?;
    Ok((enc, context))
}

/// Set up a recipient's context from the sender's encapsulated key.
///
/// `SetupBaseR` in RFC 9180.
pub fn setup_receiver(enc: &[u8], recipient: &KeyPair, info: &[u8], aead: Aead) -> Result<Context> {
    ensure!(
        enc.len() == ENC_LEN,
        InvalidLength,
        "hpke enc must be 32 bytes"
    );
    let mut dh = Zeroizing::new([0u8; 32]);
    X25519::agree(recipient.private.get(), enc, dh.get_mut())?;
    let shared_secret = extract_and_expand(dh.get(), enc, &recipient.public)?;
    key_schedule(aead, shared_secret.get(), info)
}

/// DHKEM's `ExtractAndExpand`, from the DH output and `enc || pkR`.
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
    let kem_suite = kem_suite_id();
    let mut eae_prk = Zeroizing::new([0u8; 32]);
    labeled_extract(&kem_suite, b"", b"eae_prk", &[dh], eae_prk.get_mut())?;
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    labeled_expand(
        &kem_suite,
        eae_prk.get(),
        b"shared_secret",
        &[enc, pk_r],
        shared_secret.get_mut(),
    )?;
    Ok(shared_secret)
}

/// `KeySchedule` in base mode: no PSK, so `psk` and `psk_id` are empty.
fn key_schedule(aead: Aead, shared_secret: &[u8; 32], info: &[u8]) -> Result<Context> {
    const MODE_BASE: u8 = 0x00;
    let suite = suite_id(aead);

    let mut psk_id_hash = [0u8; 32];
    labeled_extract(&suite, b"", b"psk_id_hash", &[], &mut psk_id_hash)?;
    let mut info_hash = [0u8; 32];
    labeled_extract(&suite, b"", b"info_hash", &[info], &mut info_hash)?;
    let mut ksc = [0u8; 65];
    ksc[0] = MODE_BASE;
    ksc[1..33].copy_from_slice(&psk_id_hash);
    ksc[33..].copy_from_slice(&info_hash);

    let mut secret = Zeroizing::new([0u8; 32]);
    labeled_extract(&suite, shared_secret, b"secret", &[], secret.get_mut())?;

    let mut key = Zeroizing::new([0u8; 32]);
    let key = &mut key.get_mut()[..aead.key_len()];
    labeled_expand(&suite, secret.get(), b"key", &[&ksc], key)?;
    let mut base_nonce = Zeroizing::new([0u8; NONCE_LEN]);
    labeled_expand(
        &suite,
        secret.get(),
        b"base_nonce",
        &[&ksc],
        base_nonce.get_mut(),
    )?;
    let mut exporter_secret = Zeroizing::new([0u8; 32]);
    labeled_expand(
        &suite,
        secret.get(),
        b"exp",
        &[&ksc],
        exporter_secret.get_mut(),
    )?;

    let cipher = Cipher::new(aead, key)?;
    key.zeroize();
    Ok(Context {
        cipher,
        base_nonce,
        exporter_secret,
        seq: 0,
    })
}

/// `"KEM" || I2OSP(kem_id, 2)`.
fn kem_suite_id() -> [u8; 5] {
    let [a, b] = KEM_ID.to_be_bytes();
    [b'K', b'E', b'M', a, b]
}

/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
fn suite_id(aead: Aead) -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    s[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    s[8..].copy_from_slice(&aead.id().to_be_bytes());
    s
}

/// `LabeledExtract(salt, label, ikm)`: HKDF-Extract with key `salt` over
/// `"HPKE-v1" || suite_id || label || ikm`, the ikm given in parts so that no
/// concatenation is ever built.
///
/// An empty salt is the HKDF default of `Nh` zero bytes, which HMAC's key
/// padding makes the same key.
fn labeled_extract(
    suite: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[&[u8]],
    out: &mut [u8; 32],
) -> Result<()> {
    let mut mac = HmacSha256::new(salt)?;
    mac.update(b"HPKE-v1");
    mac.update(suite);
    mac.update(label);
    for part in ikm {
        mac.update(part);
    }
    out.copy_from_slice(mac.finalize().as_ref());
    Ok(())
}

/// `LabeledExpand(prk, label, info, L)`: HKDF-Expand over
/// `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`, info in parts.
fn labeled_expand(
    suite: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<()> {
    ensure!(
        out.len() <= MAX_EXPORT_LEN,
        InvalidLength,
        "hpke expand longer than 255 * Nh"
    );
    let length = (out.len() as u16).to_be_bytes();
    let mut previous = Zeroizing::new([0u8; 32]);
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new(prk)?;
        if i > 0 {
            mac.update(previous.get());
        }
        mac.update(&length);
        mac.update(b"HPKE-v1");
        mac.update(suite);
        mac.update(label);
        for part in info {
            mac.update(part);
        }
        mac.update(&[i as u8 + 1]);
        previous.get_mut().copy_from_slice(mac.finalize().as_ref());
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
