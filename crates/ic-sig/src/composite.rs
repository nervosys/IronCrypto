//! Composite ML-DSA: ML-DSA and EdDSA signatures over one message, both
//! required, per draft-ietf-lamps-pq-composite-sigs-19.
//!
//! Three of the draft's algorithms, the ones whose traditional half is EdDSA:
//!
//! | algorithm | OID | pre-hash |
//! |---|---|---|
//! | `id-MLDSA44-Ed25519-SHA512` | 1.3.6.1.5.5.7.6.39 | SHA-512 |
//! | `id-MLDSA65-Ed25519-SHA512` | 1.3.6.1.5.5.7.6.48 | SHA-512 |
//! | `id-MLDSA87-Ed448-SHAKE256` | 1.3.6.1.5.5.7.6.51 | SHAKE256, 64 bytes |
//!
//! Both components sign the message representative
//!
//! ```text
//! M' = "CompositeAlgorithmSignatures2025" || Label || len(ctx) || ctx || PH(M)
//! ```
//!
//! ML-DSA under the algorithm's label as its own context, EdDSA with none.
//! A signature verifies only if both halves do, so it stands while either
//! ML-DSA or the curve does.
//!
//! The encodings are concatenations (draft section 4): a public key is the
//! ML-DSA key then the EdDSA key, a private key the 32-byte ML-DSA seed then
//! the EdDSA seed, a signature the ML-DSA signature then the EdDSA one. Every
//! component is fixed length, so each total is exact and checked exactly.
//!
//! An Internet-Draft, not yet an RFC: the label, the prefix and the OIDs are
//! the draft's and change if it does. Checked against its Appendix E vectors.

use ic_core::traits::internal::{Digest, Xof};
use ic_core::traits::{RandomSource, SignatureScheme};
use ic_core::{ensure, err, Result, Zeroize, Zeroizing};

/// The prefix every message representative starts with (draft section 2.2).
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// The longest representative: prefix, the longest label, the context
/// length byte, a context of 255 bytes, a 64-byte digest.
const MAX_REPRESENTATIVE: usize = 32 + 30 + 1 + 255 + 64;

/// A composite ML-DSA algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Composite {
    /// `id-MLDSA44-Ed25519-SHA512`.
    MlDsa44Ed25519Sha512,
    /// `id-MLDSA65-Ed25519-SHA512`.
    MlDsa65Ed25519Sha512,
    /// `id-MLDSA87-Ed448-SHAKE256`.
    MlDsa87Ed448Shake256,
}

impl Composite {
    /// Every composite here.
    pub const ALL: [Composite; 3] = [
        Self::MlDsa44Ed25519Sha512,
        Self::MlDsa65Ed25519Sha512,
        Self::MlDsa87Ed448Shake256,
    ];

    /// The ontology identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::MlDsa44Ed25519Sha512 => "mldsa44-ed25519-sha512",
            Self::MlDsa65Ed25519Sha512 => "mldsa65-ed25519-sha512",
            Self::MlDsa87Ed448Shake256 => "mldsa87-ed448-shake256",
        }
    }

    /// The signature label, bound into every signature (draft section 6).
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::MlDsa44Ed25519Sha512 => b"COMPSIG-MLDSA44-Ed25519-SHA512",
            Self::MlDsa65Ed25519Sha512 => b"COMPSIG-MLDSA65-Ed25519-SHA512",
            Self::MlDsa87Ed448Shake256 => b"COMPSIG-MLDSA87-Ed448-SHAKE256",
        }
    }

    /// The object identifier's DER content bytes: 1.3.6.1.5.5.7.6.39, .48
    /// and .51.
    pub const fn oid(self) -> &'static [u8] {
        match self {
            Self::MlDsa44Ed25519Sha512 => &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x27],
            Self::MlDsa65Ed25519Sha512 => &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30],
            Self::MlDsa87Ed448Shake256 => &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x33],
        }
    }

    /// The composite whose object identifier this is.
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.oid() == oid)
    }

    /// Lengths of the ML-DSA and EdDSA public keys, private keys and
    /// signatures, in that order.
    const fn parts(self) -> [(usize, usize); 3] {
        use ic_mldsa::{sign as m65, sign44 as m44, sign87 as m87};
        match self {
            Self::MlDsa44Ed25519Sha512 => [
                (m44::PUBLIC_KEY_LEN, 32),
                (32, 32),
                (m44::SIGNATURE_LEN, 64),
            ],
            Self::MlDsa65Ed25519Sha512 => [
                (m65::PUBLIC_KEY_LEN, 32),
                (32, 32),
                (m65::SIGNATURE_LEN, 64),
            ],
            Self::MlDsa87Ed448Shake256 => [
                (m87::PUBLIC_KEY_LEN, 57),
                (32, 57),
                (m87::SIGNATURE_LEN, 114),
            ],
        }
    }

    /// The public key's length: 1344, 1984 or 2649 bytes.
    pub const fn public_key_len(self) -> usize {
        let (a, b) = self.parts()[0];
        a + b
    }

    /// The private key's length: 64, 64 or 89 bytes.
    pub const fn private_key_len(self) -> usize {
        let (a, b) = self.parts()[1];
        a + b
    }

    /// The signature's length: 2484, 3373 or 4741 bytes.
    pub const fn signature_len(self) -> usize {
        let (a, b) = self.parts()[2];
        a + b
    }

    /// `M'`, written into `out`; its length.
    fn representative(
        self,
        message: &[u8],
        context: &[u8],
        out: &mut [u8; MAX_REPRESENTATIVE],
    ) -> usize {
        let label = self.label();
        let mut at = 0;
        for part in [PREFIX, label, &[context.len() as u8], context] {
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        let digest = &mut out[at..at + 64];
        match self {
            Self::MlDsa44Ed25519Sha512 | Self::MlDsa65Ed25519Sha512 => {
                let mut h = ic_hash::Sha512::new();
                h.update(message);
                digest.copy_from_slice(h.finalize().as_ref());
            }
            Self::MlDsa87Ed448Shake256 => {
                let mut x = ic_hash::Shake256::default();
                x.update(message);
                x.finalize_xof(digest);
            }
        }
        at + 64
    }
}

/// Derive the public key of `private_key`.
pub fn public_key(algorithm: Composite, private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        private_key.len() == algorithm.private_key_len(),
        InvalidLength,
        "composite private key"
    );
    ensure!(
        out.len() == algorithm.public_key_len(),
        InvalidLength,
        "composite public key buffer"
    );
    let seed: &[u8; 32] = private_key[..32]
        .try_into()
        .map_err(|_| err!(Internal, "seed"))?;
    let trad = &private_key[32..];
    macro_rules! go {
        ($m:ident, $ed:ty) => {{
            use ic_mldsa::$m as m;
            let mut sk = Zeroizing::new([0u8; m::SECRET_KEY_LEN]);
            let pk: &mut [u8; m::PUBLIC_KEY_LEN] = (&mut out[..m::PUBLIC_KEY_LEN])
                .try_into()
                .map_err(|_| err!(Internal, "ml-dsa public key length"))?;
            ensure!(
                m::keygen(seed, pk, sk.get_mut()),
                Internal,
                "ml-dsa key generation failed"
            );
            <$ed as SignatureScheme>::public_key(trad, &mut out[m::PUBLIC_KEY_LEN..])
        }};
    }
    match algorithm {
        Composite::MlDsa44Ed25519Sha512 => go!(sign44, ic_ec::Ed25519),
        Composite::MlDsa65Ed25519Sha512 => go!(sign, ic_ec::Ed25519),
        Composite::MlDsa87Ed448Shake256 => go!(sign87, ic_ec::Ed448),
    }
}

/// Sign `message` under `context`, at most 255 bytes, empty unless a
/// protocol sets one. ML-DSA's half is hedged with randomness from `rng`.
pub fn sign(
    algorithm: Composite,
    private_key: &[u8],
    message: &[u8],
    context: &[u8],
    rng: &mut dyn RandomSource,
    signature: &mut [u8],
) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        context.len() <= 255,
        InvalidParameter,
        "composite context longer than 255 bytes"
    );
    ensure!(
        private_key.len() == algorithm.private_key_len(),
        InvalidLength,
        "composite private key"
    );
    ensure!(
        signature.len() == algorithm.signature_len(),
        InvalidLength,
        "composite signature buffer"
    );
    let seed: &[u8; 32] = private_key[..32]
        .try_into()
        .map_err(|_| err!(Internal, "seed"))?;
    let trad = &private_key[32..];
    let mut rep = [0u8; MAX_REPRESENTATIVE];
    let len = algorithm.representative(message, context, &mut rep);
    let rep = &rep[..len];
    macro_rules! go {
        ($m:ident, $ed:ty) => {{
            use ic_mldsa::$m as m;
            let mut sk = Zeroizing::new([0u8; m::SECRET_KEY_LEN]);
            let mut pk = [0u8; m::PUBLIC_KEY_LEN];
            ensure!(
                m::keygen(seed, &mut pk, sk.get_mut()),
                Internal,
                "ml-dsa key generation failed"
            );
            let mut randomness = Zeroizing::new([0u8; 32]);
            rng.fill(randomness.get_mut())?;
            let (first, second) = signature.split_at_mut(m::SIGNATURE_LEN);
            let first: &mut [u8; m::SIGNATURE_LEN] = first
                .try_into()
                .map_err(|_| err!(Internal, "ml-dsa signature length"))?;
            if !m::sign(sk.get(), rep, algorithm.label(), randomness.get(), first) {
                signature.zeroize();
                return Err(err!(Internal, "ml-dsa signing did not produce a signature"));
            }
            if let Err(e) = <$ed as SignatureScheme>::sign(trad, rep, second) {
                signature.zeroize();
                return Err(e);
            }
            Ok(())
        }};
    }
    match algorithm {
        Composite::MlDsa44Ed25519Sha512 => go!(sign44, ic_ec::Ed25519),
        Composite::MlDsa65Ed25519Sha512 => go!(sign, ic_ec::Ed25519),
        Composite::MlDsa87Ed448Shake256 => go!(sign87, ic_ec::Ed448),
    }
}

/// Verify `signature` over `message` under `context`. `Ok(())` only if both
/// halves verify; `AuthenticationFailed` if either does not, or if the
/// signature or the key is not exactly its algorithm's length.
pub fn verify(
    algorithm: Composite,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        context.len() <= 255,
        InvalidParameter,
        "composite context longer than 255 bytes"
    );
    let failed = || err!(AuthenticationFailed, "signature did not verify");
    if public_key.len() != algorithm.public_key_len()
        || signature.len() != algorithm.signature_len()
    {
        return Err(failed());
    }
    let mut rep = [0u8; MAX_REPRESENTATIVE];
    let len = algorithm.representative(message, context, &mut rep);
    let rep = &rep[..len];
    macro_rules! go {
        ($m:ident, $ed:ty) => {{
            use ic_mldsa::$m as m;
            let (pk, trad_pk) = public_key.split_at(m::PUBLIC_KEY_LEN);
            let (sig, trad_sig) = signature.split_at(m::SIGNATURE_LEN);
            let pk: &[u8; m::PUBLIC_KEY_LEN] = pk.try_into().map_err(|_| failed())?;
            let sig: &[u8; m::SIGNATURE_LEN] = sig.try_into().map_err(|_| failed())?;
            // Both are checked whatever the first says; nothing here is secret.
            let ml_dsa = m::verify(pk, rep, algorithm.label(), sig);
            let trad = <$ed as SignatureScheme>::verify(trad_pk, rep, trad_sig).is_ok();
            ensure!(
                ml_dsa && trad,
                AuthenticationFailed,
                "signature did not verify"
            );
            Ok(())
        }};
    }
    match algorithm {
        Composite::MlDsa44Ed25519Sha512 => go!(sign44, ic_ec::Ed25519),
        Composite::MlDsa65Ed25519Sha512 => go!(sign, ic_ec::Ed25519),
        Composite::MlDsa87Ed448Shake256 => go!(sign87, ic_ec::Ed448),
    }
}

/// A fixed source of "randomness", for the self-test's round trip only.
struct Fixed;

impl RandomSource for Fixed {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        out.fill(0x5a);
        Ok(())
    }
}

/// The known-answer test for one composite.
///
/// The private key of the draft's Appendix E vector must derive its public
/// key, compared by SHA-256 rather than embedded whole: the digest was taken
/// of the draft's key by `scripts/gen_composite_sig_vectors.py`'s output, and
/// the test in `ironcrypto/tests/composite_sig.rs` compares the whole key.
/// Then a signature made here must verify, and fail once corrupted.
pub fn self_test(algorithm: Composite) -> Result<()> {
    // draft-ietf-lamps-pq-composite-sigs-19, Appendix E: `sk`, and SHA-256
    // of `pk`.
    let (sk_hex, pk_digest_hex): (&[u8], &[u8; 64]) = match algorithm {
        Composite::MlDsa44Ed25519Sha512 => (
            &b"01d8df59152d8a44e39a25e6775ef18a0044b20e58c2c4346ac37c27d152176c5bea6c2454617bfb48479eb8b13b711a98116b73f7ecac30faf1dd9b4fa17d68"[..],
            b"aae6461ff512086b9908abcd71c671bbe54085efdaafcb02608346862392e15b",
        ),
        Composite::MlDsa65Ed25519Sha512 => (
            &b"23a578205289555e65ddf567601cb4715fb593a7796a8f71d668c3bca876d93760e9741f5fb8a68b3c490b93e4aa0e5d82206ef3b8e2242e1bcf4729f2e146aa"[..],
            b"10775911b6c3c2dbf3c98485be51c5cc2c1b9ca5d2047a7faedab1d6cd573c27",
        ),
        Composite::MlDsa87Ed448Shake256 => (
            &b"72fa1d691964729c9a94af91f6ba94483f7908d6cb79d190fe5b3dbb9b15a3d7c9135c4a75afa6b08928660ed66480121065b529fb9e1f02b1fe2e86de38889dd721c4e975dadec088868cba9684819b6778c1dfb8f2a51606"[..],
            b"0d84a7cf45eed8069156edbf5dc81cdefc4fb77bc8b62ad7a32a1c655b060208",
        ),
    };
    let mut sk = Zeroizing::new([0u8; 89]);
    let sk = &mut sk.get_mut()[..algorithm.private_key_len()];
    ic_core::codec::hex_decode(sk_hex, sk)?;
    let mut want = [0u8; 32];
    ic_core::codec::hex_decode(pk_digest_hex, &mut want)?;

    let mut pk = [0u8; 2649];
    let pk = &mut pk[..algorithm.public_key_len()];
    public_key(algorithm, sk, pk)?;
    let mut h = ic_hash::Sha256::new();
    h.update(pk);
    ensure!(
        ic_core::ct::verify(&want, h.finalize().as_ref()),
        SelfTestFailed,
        "composite public key"
    );

    let mut sig = [0u8; 4741];
    let sig = &mut sig[..algorithm.signature_len()];
    sign(algorithm, sk, b"self-test", b"", &mut Fixed, sig)?;
    verify(algorithm, pk, b"self-test", b"", sig)?;
    sig[0] ^= 1;
    ensure!(
        verify(algorithm, pk, b"self-test", b"", sig).is_err(),
        SelfTestFailed,
        "composite accepted a corrupted signature"
    );
    Ok(())
}
