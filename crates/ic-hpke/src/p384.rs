//! HPKE base mode with DHKEM(P-384, HKDF-SHA384) and HKDF-SHA384: KEM
//! `0x0011`, KDF `0x0002`.
//!
//! With AES-256-GCM this is the HPKE of MLS's
//! `MLS_256_DHKEMP384_AES256GCM_SHA384_P384`, RFC 9420 cipher suite 7. The
//! [`Context`] it sets up is the same type the X25519 suite uses.
//!
//! ```
//! # fn main() -> ic_core::Result<()> {
//! use ic_hpke::{p384, Aead};
//! let mut rng = ic_drbg::Rng::from_os()?;
//! let recipient = p384::KeyPair::generate(&mut rng)?;
//! let (enc, mut tx) = p384::setup_sender(recipient.public(), b"app/v1", Aead::Aes256Gcm, &mut rng)?;
//! let mut rx = p384::setup_receiver(&enc, &recipient, b"app/v1", Aead::Aes256Gcm)?;
//!
//! let mut message = *b"hello";
//! let mut tag = [0u8; ic_hpke::TAG_LEN];
//! tx.seal_in_place(b"header", &mut message, &mut tag)?;
//! rx.open_in_place(b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"hello");
//! # Ok(())
//! # }
//! ```
//!
//! # Keys
//!
//! Public keys and encapsulations are SEC1 uncompressed points, `0x04 || X ||
//! Y`, 97 bytes, as RFC 9180 section 7.1.1 serializes them; a compressed point
//! is refused. Every peer key is checked to be on the curve and not the
//! identity before it is used, which is the validation section 7.1.4 requires
//! of the NIST curves. Private keys are 48-byte big-endian scalars in
//! `[1, n - 1]`.
//!
//! # FIPS
//!
//! Every primitive here is an approved one -- ECDH over P-384 (SP 800-56A),
//! HMAC-SHA384, AES-GCM (SP 800-38D) -- but HPKE as a whole is not an approved
//! scheme, and its key derivation is not SP 800-56C's as written: DHKEM's
//! extraction runs HMAC over `"HPKE-v1" || suite_id || label || Z`, where
//! SP 800-56C's two-step KDF extracts from `Z` alone. The ontology records it
//! as not approved for that reason. A validated module that offers it would
//! need its assessor to accept that construction.
//!
//! # Verification
//!
//! No published HPKE vector uses P-384. `testvectors/hpke-p384.json` comes from
//! `scripts/gen_hpke_p384_vectors.py`, an independent implementation of every
//! NIST-curve DHKEM that must first reproduce all the CFRG's published P-256
//! and P-521 base-mode vectors -- the same construction with other parameters
//! -- and exchange a message each way with pyca/cryptography's own HPKE.

use crate::{
    dhkem_extract_and_expand, kem_suite_id, key_schedule, labeled_expand, labeled_extract, Aead,
    Context, Kdf,
};
use ic_core::traits::{Algorithm, KeyAgreement, RandomSource, SelfTest};
use ic_core::{ensure, ErrorKind, Result, Zeroizing};
use ic_ec::p384::EcdhP384;

/// `DHKEM(P-384, HKDF-SHA384)`, RFC 9180 section 7.1.
pub const KEM_ID: u16 = 0x0011;
/// `HKDF-SHA384`, RFC 9180 section 7.2: the key schedule's KDF in this suite.
pub const KDF_ID: u16 = 0x0002;
/// Length of an encapsulated key, `Nenc`.
pub const ENC_LEN: usize = 97;
/// Length of a public key, `Npk`.
pub const PUBLIC_KEY_LEN: usize = 97;
/// Length of a private key, `Nsk`.
pub const PRIVATE_KEY_LEN: usize = 48;
/// Length of the KEM's shared secret, `Nsecret`.
pub const SHARED_SECRET_LEN: usize = 48;
/// The longest export: `255 * Nh`.
pub const MAX_EXPORT_LEN: usize = 255 * 48;

const KDF: Kdf = Kdf::Sha384;

/// The suite, for the ontology and the self-test table.
pub struct HpkeP384;

impl Algorithm for HpkeP384 {
    const ID: &'static str = "hpke-p384-sha384";
    const NAME: &'static str = "HPKE (DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, base mode)";
}

/// A P-384 key pair: a recipient's long-lived key, or a sender's ephemeral.
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
    /// A fresh key pair, `GenerateKeyPair`: a uniformly random scalar in
    /// `[1, n - 1]`, by drawing 48 bytes until they are one.
    ///
    /// A draw is out of range with probability below `2^-189`, so the loop
    /// is for correctness, not for anything a caller will see.
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
        EcdhP384::public_key(self.private.get(), &mut again)?;
        ensure!(
            ic_core::ct::verify(&again, &self.public),
            SelfTestFailed,
            "hpke key pair failed its pairwise consistency test; the key is withheld"
        );
        Ok(())
    }

    /// [`generate`](Self::generate) without the pairwise consistency test,
    /// for the ephemeral key of [`setup_sender`]. That key is used once, in
    /// the two scalar multiplications that follow, and testing it would add
    /// a third to every message sent.
    fn generate_untested<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut private = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        for _ in 0..64 {
            rng.fill(private.get_mut())?;
            match Self::from_private(private.get()) {
                Err(e) if e.kind() == ErrorKind::InvalidParameter => continue,
                other => return other,
            }
        }
        Err(ic_core::err!(
            EntropyFailure,
            "hpke p-384: 64 draws all out of range"
        ))
    }

    /// The key pair for a 48-byte private scalar, `DeserializePrivateKey`.
    ///
    /// Refuses a scalar of 0 or at least the group order with
    /// `InvalidParameter`, and any other length with `InvalidLength`.
    pub fn from_private(private: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(
            private.len() == PRIVATE_KEY_LEN,
            InvalidLength,
            "hpke p-384 private key must be 48 bytes"
        );
        let mut key = Self {
            private: Zeroizing::new([0u8; PRIVATE_KEY_LEN]),
            public: [0u8; PUBLIC_KEY_LEN],
        };
        key.private.get_mut().copy_from_slice(private);
        EcdhP384::public_key(private, &mut key.public)?;
        Ok(key)
    }

    /// The key pair derived from `ikm`: RFC 9180 section 7.1.3's
    /// `DeriveKeyPair` for the NIST curves.
    ///
    /// `dkp_prk = LabeledExtract("", "dkp_prk", ikm)`; then for `counter` from
    /// 0, `LabeledExpand(dkp_prk, "candidate", counter, 48)` until the
    /// candidate is a valid scalar. P-384's bitmask is `0xFF`, so nothing is
    /// masked. Deterministic, which is what MLS's TreeKEM needs. `ikm` must
    /// carry at least `Nsk` bytes of entropy, so shorter input is refused with
    /// `InvalidLength`.
    pub fn derive(ikm: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(
            ikm.len() >= PRIVATE_KEY_LEN,
            InvalidLength,
            "hpke p-384 DeriveKeyPair needs at least 48 bytes of ikm"
        );
        let kem = kem_suite_id(KEM_ID);
        let mut dkp_prk = Zeroizing::new([0u8; 48]);
        labeled_extract(KDF, &kem, b"", b"dkp_prk", &[ikm], dkp_prk.get_mut())?;
        derive_from_candidates(|counter, candidate| {
            labeled_expand(
                KDF,
                &kem,
                dkp_prk.get(),
                b"candidate",
                &[&[counter]],
                candidate,
            )
        })
    }

    /// The public key, `SerializePublicKey`: SEC1 uncompressed.
    pub fn public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

/// The rejection loop of `DeriveKeyPair`, over a candidate source.
///
/// Separate so that the loop can be tested with candidates that are out of
/// range, which the real source produces with probability below `2^-189`.
fn derive_from_candidates(
    mut candidate: impl FnMut(u8, &mut [u8]) -> Result<()>,
) -> Result<KeyPair> {
    let mut sk = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
    for counter in 0..=255u8 {
        candidate(counter, sk.get_mut())?;
        // P-384's bitmask is 0xFF: the whole first byte is kept.
        match KeyPair::from_private(sk.get()) {
            Err(e) if e.kind() == ErrorKind::InvalidParameter => continue,
            other => return other,
        }
    }
    Err(ic_core::err!(
        InvalidParameter,
        "hpke p-384 DeriveKeyPair: no valid candidate in 256"
    ))
}

/// `DeserializePublicKey`: 97 bytes, uncompressed. The curve check is
/// ECDH's, when the key is used.
///
/// ECDH's SEC1 decoder also refuses compressed and hybrid forms, so the form
/// byte is checked twice; removing this check leaves the tests passing, which
/// was confirmed. It stays so that this layer states RFC 9180's rule rather
/// than relying on what another crate's decoder happens to accept.
fn check_public(pk: &[u8], what: &'static str) -> Result<()> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(ic_core::Error::new(ErrorKind::InvalidLength, what));
    }
    if pk[0] != 0x04 {
        return Err(ic_core::Error::new(ErrorKind::InvalidParameter, what));
    }
    Ok(())
}

/// Set up a sender's context to `recipient_public`, with a fresh ephemeral
/// key. Returns the encapsulated key, which the recipient needs, and the
/// context. `SetupBaseS` in RFC 9180.
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
/// For replaying test vectors, whose ephemeral keys are fixed. An ephemeral
/// key used twice gives two messages the same shared secret, so anything else
/// should call [`setup_sender`].
pub fn setup_sender_with_ephemeral(
    recipient_public: &[u8],
    info: &[u8],
    aead: Aead,
    ephemeral: &KeyPair,
) -> Result<([u8; ENC_LEN], Context)> {
    ic_core::module::operational()?;
    check_public(
        recipient_public,
        "hpke p-384 public key must be 97 bytes, uncompressed",
    )?;
    let mut dh = Zeroizing::new([0u8; 48]);
    EcdhP384::agree(ephemeral.private.get(), recipient_public, dh.get_mut())?;
    let enc = ephemeral.public;
    let mut shared_secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    dhkem_extract_and_expand(
        KEM_ID,
        KDF,
        dh.get(),
        &enc,
        recipient_public,
        shared_secret.get_mut(),
    )?;
    let context = key_schedule(KEM_ID, KDF, aead, shared_secret.get(), info)?;
    Ok((enc, context))
}

/// Set up a recipient's context from the sender's encapsulated key.
/// `SetupBaseR` in RFC 9180.
pub fn setup_receiver(enc: &[u8], recipient: &KeyPair, info: &[u8], aead: Aead) -> Result<Context> {
    ic_core::module::operational()?;
    check_public(enc, "hpke p-384 enc must be 97 bytes, uncompressed")?;
    let mut dh = Zeroizing::new([0u8; 48]);
    EcdhP384::agree(recipient.private.get(), enc, dh.get_mut())?;
    let mut shared_secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    dhkem_extract_and_expand(
        KEM_ID,
        KDF,
        dh.get(),
        enc,
        &recipient.public,
        shared_secret.get_mut(),
    )?;
    key_schedule(KEM_ID, KDF, aead, shared_secret.get(), info)
}

impl SelfTest for HpkeP384 {
    /// The AES-256-GCM case of `testvectors/hpke-p384.json`, the suite MLS
    /// suite 7 uses: both keys by `DeriveKeyPair`, then the first encryption.
    ///
    /// No published P-384 vector exists; this value is the independent
    /// generator's, which reproduces the CFRG's P-256 and P-521 vectors and
    /// interoperates with pyca/cryptography's HPKE. Recorded in docs/FIPS.md.
    fn self_test() -> Result<()> {
        let mut ikm_e = [0u8; 48];
        ic_core::codec::hex_decode(
            b"a2d2043c7dae983f66605543f0c33a88839bc074187f0552be4f1fcd6e13b486c15cb771e080b0c3dca02c6d955a2909",
            &mut ikm_e,
        )?;
        let mut ikm_r = [0u8; 48];
        ic_core::codec::hex_decode(
            b"b8c741124c99f2340b9c329a486467fd585c8da73e11c1cd3152161609e2715071104b88e8d5c263fcd9cd10888eafc0",
            &mut ikm_r,
        )?;
        let mut info = [0u8; 20];
        ic_core::codec::hex_decode(b"4f6465206f6e2061204772656369616e2055726e", &mut info)?;
        let mut message = [0u8; 29];
        ic_core::codec::hex_decode(
            b"4265617574792069732074727574682c20747275746820626561757479",
            &mut message,
        )?;
        let mut want = [0u8; 29 + crate::TAG_LEN];
        ic_core::codec::hex_decode(
            b"ec2091e35993751068c27ce20e2bf8aa93fb0398eff2fca0d1ad6d36afe7c37ddf3e3832be2b43e49536b7bf72",
            &mut want,
        )?;

        let ephemeral = KeyPair::derive(&ikm_e)?;
        let recipient = KeyPair::derive(&ikm_r)?;
        let (enc, mut sender) =
            setup_sender_with_ephemeral(recipient.public(), &info, Aead::Aes256Gcm, &ephemeral)?;
        let plaintext = message;
        let mut tag = [0u8; crate::TAG_LEN];
        sender.seal_in_place(b"Count-0", &mut message, &mut tag)?;
        let sealed =
            ic_core::ct::verify(&want[..29], &message) && ic_core::ct::verify(&want[29..], &tag);
        ensure!(
            sealed,
            SelfTestFailed,
            "hpke p-384: sealed ciphertext differs from the vector"
        );
        let mut receiver = setup_receiver(&enc, &recipient, &info, Aead::Aes256Gcm)?;
        receiver.open_in_place(b"Count-0", &mut message, &tag)?;
        ensure!(
            ic_core::ct::verify(&plaintext, &message),
            SelfTestFailed,
            "hpke p-384: opened plaintext differs"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_passes() {
        HpkeP384::self_test().unwrap();
    }

    /// The pairwise consistency test must actually reject a pair whose halves
    /// do not correspond.
    #[test]
    fn the_pairwise_consistency_test_rejects_a_mismatched_pair() {
        let a = KeyPair::from_private(&[1u8; 48]).unwrap();
        let b = KeyPair::from_private(&[2u8; 48]).unwrap();
        a.pairwise_consistency().unwrap();
        b.pairwise_consistency().unwrap();
        let crossed = KeyPair {
            private: Zeroizing::new(*a.private.get()),
            public: b.public,
        };
        assert_eq!(
            crossed.pairwise_consistency().unwrap_err().kind(),
            ErrorKind::SelfTestFailed
        );
        let mut flipped = KeyPair::from_private(&[1u8; 48]).unwrap();
        flipped.public[96] ^= 0x01;
        assert!(flipped.pairwise_consistency().is_err());
    }

    /// The order of P-384, big-endian.
    const N: [u8; 48] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ];

    /// The rejection loop skips zero, the order and anything above it, and
    /// takes the first valid candidate -- the case the real candidate source
    /// all but never produces, so the published-style vectors cannot test it.
    #[test]
    fn derive_skips_out_of_range_candidates_in_order() {
        let mut n_minus_1 = N;
        n_minus_1[47] -= 1;
        let candidates = [[0u8; 48], N, [0xff; 48], n_minus_1, [1u8; 48]];
        let mut asked = Vec::new();
        let key = derive_from_candidates(|counter, out| {
            asked.push(counter);
            out.copy_from_slice(&candidates[counter as usize]);
            Ok(())
        })
        .unwrap();
        assert_eq!(asked, [0, 1, 2, 3], "stops at the first valid candidate");
        assert_eq!(
            key.public(),
            KeyPair::from_private(&n_minus_1).unwrap().public()
        );
    }

    #[test]
    fn derive_gives_up_after_256_candidates() {
        let mut asked = 0;
        let e = derive_from_candidates(|_, out| {
            asked += 1;
            out.copy_from_slice(&N);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidParameter);
        assert_eq!(asked, 256);
    }

    #[test]
    fn derive_needs_48_bytes_of_ikm() {
        assert_eq!(
            KeyPair::derive(&[7u8; 47]).unwrap_err().kind(),
            ErrorKind::InvalidLength
        );
        assert!(KeyPair::derive(&[7u8; 48]).is_ok());
    }

    #[test]
    fn compressed_and_invalid_public_keys_are_refused() {
        let ephemeral = KeyPair::derive(&[1u8; 48]).unwrap();
        let recipient = KeyPair::derive(&[2u8; 48]).unwrap();
        let mut compressed = [0u8; 49];
        EcdhP384::public_key_compressed(&[0x22u8; 48], &mut compressed).unwrap();
        assert!(
            setup_sender_with_ephemeral(&compressed, b"", Aead::Aes256Gcm, &ephemeral).is_err()
        );
        // Right length and prefix, off the curve.
        let mut off = *recipient.public();
        off[96] ^= 1;
        assert!(setup_sender_with_ephemeral(&off, b"", Aead::Aes256Gcm, &ephemeral).is_err());
        assert!(setup_receiver(&off, &recipient, b"", Aead::Aes256Gcm).is_err());
        // A hybrid-form prefix on a valid point.
        let mut hybrid = *recipient.public();
        hybrid[0] = 0x06;
        assert!(setup_sender_with_ephemeral(&hybrid, b"", Aead::Aes256Gcm, &ephemeral).is_err());
    }

    #[test]
    fn exports_reach_255_hash_lengths_and_no_further() {
        let mut rng = ic_drbg::Rng::from_entropy(&[3u8; 32], b"p384 export").unwrap();
        let recipient = KeyPair::generate(&mut rng).unwrap();
        let (_, tx) = setup_sender(recipient.public(), b"", Aead::Aes256Gcm, &mut rng).unwrap();
        let mut out = vec![0u8; MAX_EXPORT_LEN];
        tx.export(b"ctx", &mut out).unwrap();
        let mut over = vec![0u8; MAX_EXPORT_LEN + 1];
        assert!(tx.export(b"ctx", &mut over).is_err());
    }

    #[test]
    fn debug_shows_no_private_key() {
        let k = KeyPair::derive(&[5u8; 48]).unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("public") && !s.contains("private"), "{s}");
    }
}
