//! A [`Signer`] for a private key held in memory.
//!
//! [`ic_core::sig::Signer`] is the interface a protocol signs through, so that
//! it need not know whether the key is in an HSM, a key service or this
//! process. [`SoftwareSigner`] is the last of those: it reads a PKCS#8 private
//! key and signs with it, in the encodings [`crate::verify`] accepts.
//!
//! ```
//! # fn main() -> ic_core::Result<()> {
//! use ic_core::sig::{SignatureAlgorithm, Signer};
//! use ic_sig::SoftwareSigner;
//!
//! // An Ed25519 key as PKCS#8, made here for the example.
//! let mut pkcs8 = [0u8; 64];
//! let n = ic_pkix::PrivateKeyInfo::Ed25519(&[7u8; 32]).to_der(&mut pkcs8)?;
//!
//! let signer = SoftwareSigner::from_pkcs8(&pkcs8[..n])?;
//! let algorithm = signer.algorithms()[0];
//! let mut rng = ic_drbg::Rng::from_os()?;
//! let mut signature = [0u8; 64];
//! let len = signer.sign(algorithm, b"message", &mut rng, &mut signature)?;
//!
//! // What it made verifies under the public key it reports.
//! ic_sig::verify_spki(algorithm, signer.public_key(), b"message", &signature[..len])?;
//! assert_eq!(algorithm, SignatureAlgorithm::Ed25519);
//! # Ok(())
//! # }
//! ```
//!
//! # What it reads
//!
//! PKCS#8 (`OneAsymmetricKey`) for RSA, ECDSA over P-256, P-384 and P-521,
//! Ed25519, ML-DSA and SLH-DSA. Three limits:
//!
//! - **An ML-DSA key must carry its seed.** RFC 9881 allows a key to be the
//!   seed, the expanded key, or both. The public key is derived from the
//!   seed, so a key with the expanded form alone is `Unsupported`.
//! - **HSS/LMS is not here.** This library verifies it and does not sign with
//!   it: a stateful key that signs twice from one state is broken, and
//!   keeping that state is a device's job.
//! - **X25519 is not a signing key**, and is `Unsupported`.
//!
//! # What is checked when a key is loaded
//!
//! The public half is computed from the private one, never taken from the
//! file. Where the file also states it -- an EC key's optional public key, an
//! RSA key's modulus, an ML-DSA key in both forms, an SLH-DSA key's root --
//! the two must agree, and a file in which they do not is refused with
//! `InvalidParameter`. Signing with a key whose halves disagree produces
//! signatures nobody can verify, and for RSA can leak the key.
//!
//! For SLH-DSA that check regenerates the key's root, which is as slow as
//! generating the key: from under a millisecond to a few hundred, by
//! parameter set.
//!
//! # Size
//!
//! Nothing here allocates, so the key and its `SubjectPublicKeyInfo` are in
//! the value itself: about eight kilobytes, whatever the algorithm. Box it,
//! or keep it in a static, where the stack is small.
//!
//! Loading a key takes stack of its own, beyond the value it returns and
//! beyond what the algorithm's key derivation uses. Measured on
//! `thumbv7em-none-eabihf` at `opt-level = "s"`, the loader's frame is about
//! 3 KB for an EC, Ed25519 or SLH-DSA key, 10 KB for ML-DSA, which holds a
//! public and an expanded private key at once, and 18 KB for RSA, whose key
//! is five kilobytes and is moved twice on the way in. Each family is loaded
//! by a function of its own, kept out of line: inlined into one, they shared
//! the largest frame, and every key paid for RSA's.

use ic_core::sig::{Custody, SignatureAlgorithm, Signer};
use ic_core::traits::{RandomSource, SignatureScheme};
use ic_core::{ensure, err, Result, Zeroize, Zeroizing};
use ic_pkix::cert::{write_ml_dsa_public_key, SignatureAlgorithm as CertAlgorithm};
use ic_pkix::der::{Reader, Writer, SEQUENCE};
use ic_pkix::{KeyAlgorithm, MlDsaParameterSet, MlDsaPrivateKey, PrivateKeyInfo, PublicKeyInfo};
use ic_slhdsa::ParameterSet;

/// The longest `SubjectPublicKeyInfo` held: ML-DSA-87's 2592-byte key and its
/// header.
const MAX_SPKI: usize = 2620;

/// The algorithms an RSA key signs with, PSS first: a protocol that takes the
/// first one its peer allows gets the padding with a security proof.
const RSA_ALGORITHMS: [SignatureAlgorithm; 6] = [
    SignatureAlgorithm::RsaPssSha256,
    SignatureAlgorithm::RsaPssSha384,
    SignatureAlgorithm::RsaPssSha512,
    SignatureAlgorithm::RsaPkcs1Sha256,
    SignatureAlgorithm::RsaPkcs1Sha384,
    SignatureAlgorithm::RsaPkcs1Sha512,
];

// The private half, by algorithm. Every variant wipes itself when dropped:
// `Zeroizing` does, and so does `RsaPrivateKey`.
#[allow(clippy::large_enum_variant)]
enum Key {
    P256(Zeroizing<[u8; 32]>),
    P384(Zeroizing<[u8; 48]>),
    P521(Zeroizing<[u8; 66]>),
    Ed25519(Zeroizing<[u8; 32]>),
    Rsa(ic_rsa::RsaPrivateKey),
    MlDsa44(Zeroizing<[u8; ic_mldsa::sign44::SECRET_KEY_LEN]>),
    MlDsa65(Zeroizing<[u8; ic_mldsa::sign::SECRET_KEY_LEN]>),
    MlDsa87(Zeroizing<[u8; ic_mldsa::sign87::SECRET_KEY_LEN]>),
    // `4n` bytes at the front of the buffer.
    SlhDsa(ParameterSet, Zeroizing<[u8; 128]>),
}

/// A private key in this process's memory, signing through [`Signer`].
///
/// See the [module documentation](self) for what it reads and checks.
pub struct SoftwareSigner {
    key: Key,
    // For every key but RSA, the one algorithm it signs with.
    algorithm: SignatureAlgorithm,
    spki: [u8; MAX_SPKI],
    spki_len: usize,
}

impl core::fmt::Debug for SoftwareSigner {
    /// The algorithm and nothing of the key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("algorithms", &self.algorithms())
            .finish_non_exhaustive()
    }
}

impl SoftwareSigner {
    fn new(key: Key, algorithm: SignatureAlgorithm, spki: [u8; MAX_SPKI], spki_len: usize) -> Self {
        Self {
            key,
            algorithm,
            spki,
            spki_len,
        }
    }

    /// Read a DER PKCS#8 private key.
    ///
    /// `MalformedEncoding` for a structure that is not PKCS#8;
    /// `Unsupported` for a well-formed key this cannot sign with;
    /// `InvalidParameter` for a key whose stated public half is not the one
    /// its private half gives, or whose private value is out of range.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        match PrivateKeyInfo::from_der(der)? {
            PrivateKeyInfo::Rsa {
                modulus,
                public_exponent,
                private_exponent,
                prime1,
                prime2,
                ..
            } => Self::rsa(modulus, public_exponent, private_exponent, prime1, prime2),
            PrivateKeyInfo::Ec {
                algorithm,
                private_key,
                public_key,
            } => Self::ec(algorithm, private_key, public_key),
            PrivateKeyInfo::Ed25519(seed) => Self::ed25519(seed),
            PrivateKeyInfo::Unsupported { .. } => Self::post_quantum(der),
            _ => Err(err!(Unsupported, "not a signing key")),
        }
    }

    #[inline(never)]
    fn rsa(n: &[u8], e: u64, d: &[u8], p: &[u8], q: &[u8]) -> Result<Self> {
        // From the primes where the file has them: the CRT values are then
        // derived here and cannot disagree with the primes, which is what the
        // classic fault attack on RSA signatures needs them to do.
        let key = if p.is_empty() || q.is_empty() {
            ic_rsa::RsaPrivateKey::from_components(n, e, d)
        } else {
            ic_rsa::RsaPrivateKey::from_primes(p, q, e)
        }
        .map_err(|_| {
            err!(
                Unsupported,
                "rsa private key is not one this library accepts"
            )
        })?;

        // The key built from the primes must be the one the file names.
        let size = key.size();
        let mut modulus = [0u8; 512];
        key.public_key().modulus_bytes(&mut modulus[..size])?;
        let stated: &[u8] = {
            let skip = n.iter().take_while(|b| **b == 0).count();
            &n[skip..]
        };
        ensure!(
            ic_core::ct::verify(&modulus[..size], stated),
            InvalidParameter,
            "rsa primes do not give the modulus in the key"
        );

        // Written straight into the value being returned: with the key at
        // five kilobytes, a buffer of its own for this was measurable.
        let mut signer = Self::new(
            Key::Rsa(key),
            SignatureAlgorithm::RsaPssSha256,
            [0u8; MAX_SPKI],
            0,
        );
        signer.spki_len = PublicKeyInfo::Rsa {
            modulus: &modulus[..size],
            exponent: e,
        }
        .to_der(&mut signer.spki)?;
        Ok(signer)
    }

    #[inline(never)]
    fn ec(algorithm: KeyAlgorithm, private: &[u8], stated: Option<&[u8]>) -> Result<Self> {
        macro_rules! curve {
            ($scheme:ty, $variant:ident, $alg:ident, $n:literal, $point:literal) => {{
                ensure!(private.len() == $n, InvalidLength, "ec private key length");
                // Deriving the public key also refuses a scalar of zero or
                // one at or above the group order.
                let mut point = [0u8; $point];
                <$scheme as SignatureScheme>::public_key(private, &mut point)
                    .map_err(|_| err!(InvalidParameter, "ec private key out of range"))?;
                if let Some(stated) = stated {
                    ensure!(
                        ic_core::ct::verify(&point, stated),
                        InvalidParameter,
                        "ec public key in the file is not this private key's"
                    );
                }
                let mut d = Zeroizing::new([0u8; $n]);
                d.get_mut().copy_from_slice(private);
                let mut spki = [0u8; MAX_SPKI];
                let len = PublicKeyInfo::Ec {
                    algorithm,
                    point: &point,
                }
                .to_der(&mut spki)?;
                Ok(Self::new(
                    Key::$variant(d),
                    SignatureAlgorithm::$alg,
                    spki,
                    len,
                ))
            }};
        }
        match algorithm {
            KeyAlgorithm::EcP256 => {
                curve!(ic_ec::p256::EcdsaP256Sha256, P256, EcdsaP256Sha256, 32, 65)
            }
            KeyAlgorithm::EcP384 => {
                curve!(ic_ec::p384::EcdsaP384Sha384, P384, EcdsaP384Sha384, 48, 97)
            }
            KeyAlgorithm::EcP521 => {
                curve!(ic_ec::p521::EcdsaP521Sha512, P521, EcdsaP521Sha512, 66, 133)
            }
            _ => Err(err!(Unsupported, "private key on an unsupported curve")),
        }
    }

    #[inline(never)]
    fn ed25519(seed: &[u8]) -> Result<Self> {
        ensure!(seed.len() == 32, InvalidLength, "ed25519 seed length");
        let mut public = [0u8; 32];
        <ic_ec::Ed25519 as SignatureScheme>::public_key(seed, &mut public)?;
        let mut held = Zeroizing::new([0u8; 32]);
        held.get_mut().copy_from_slice(seed);
        let mut spki = [0u8; MAX_SPKI];
        let len = PublicKeyInfo::Ed25519(&public).to_der(&mut spki)?;
        Ok(Self::new(
            Key::Ed25519(held),
            SignatureAlgorithm::Ed25519,
            spki,
            len,
        ))
    }

    /// The ML-DSA or SLH-DSA reading of a key `ic_pkix::PrivateKeyInfo` did
    /// not name.
    #[inline(never)]
    fn post_quantum(der: &[u8]) -> Result<Self> {
        // The algorithm identifier, to tell the two families apart.
        let mut outer = Reader::new(der);
        let mut body = outer.sequence()?;
        let _version = body.unsigned_integer_u64()?;
        let mut algorithm = body.sequence()?;
        let id = algorithm.oid()?;

        if let Some(set) = crate::slh_dsa_set_of_oid(id) {
            // RFC 9909 section 7: parameters absent, and the private key
            // octet string is the raw key, SK.seed || SK.prf || PK.seed ||
            // PK.root.
            ensure!(
                algorithm.finish().is_ok(),
                MalformedEncoding,
                "slh-dsa private key with parameters"
            );
            return Self::slh_dsa(set, id, body.octet_string()?);
        }
        if MlDsaParameterSet::from_oid(id).is_some() {
            return Self::ml_dsa(&MlDsaPrivateKey::from_der(der)?);
        }
        Err(err!(Unsupported, "private key algorithm not implemented"))
    }

    #[inline(never)]
    fn ml_dsa(key: &MlDsaPrivateKey<'_>) -> Result<Self> {
        let seed = key.seed().ok_or(err!(
            Unsupported,
            "ml-dsa private key without its seed: the public key cannot be derived"
        ))?;
        let seed: &[u8; 32] = seed
            .try_into()
            .map_err(|_| err!(InvalidLength, "ml-dsa seed length"))?;
        macro_rules! set {
            ($module:ident, $variant:ident) => {{
                use ic_mldsa::$module as m;
                let mut public = [0u8; m::PUBLIC_KEY_LEN];
                let mut secret = Zeroizing::new([0u8; m::SECRET_KEY_LEN]);
                ensure!(
                    m::keygen(seed, &mut public, secret.get_mut()),
                    SelfTestFailed,
                    "ml-dsa key pair failed its pairwise consistency test; the key is withheld"
                );
                // A key in both forms must be one key.
                if let Some(expanded) = key.expanded_key() {
                    ensure!(
                        ic_core::ct::verify(secret.get(), expanded),
                        InvalidParameter,
                        "ml-dsa expanded key is not the one its seed gives"
                    );
                }
                let mut spki = [0u8; MAX_SPKI];
                let len = write_ml_dsa_public_key(CertAlgorithm::$variant, &public, &mut spki)?;
                Ok(Self::new(
                    Key::$variant(secret),
                    SignatureAlgorithm::$variant,
                    spki,
                    len,
                ))
            }};
        }
        match key.parameter_set() {
            MlDsaParameterSet::MlDsa44 => set!(sign44, MlDsa44),
            MlDsaParameterSet::MlDsa65 => set!(sign, MlDsa65),
            MlDsaParameterSet::MlDsa87 => set!(sign87, MlDsa87),
        }
    }

    #[inline(never)]
    fn slh_dsa(set: ParameterSet, id: &[u8], secret: &[u8]) -> Result<Self> {
        let n = set.n();
        ensure!(
            secret.len() == set.secret_key_len(),
            MalformedEncoding,
            "slh-dsa private key length"
        );
        // The root is the public key, and it is in the private key as a
        // stated value. Recompute it: a key whose root is not its seeds'
        // signs things nobody can verify.
        let mut derived = Zeroizing::new([0u8; 128]);
        let mut public = [0u8; 64];
        ic_slhdsa::keygen_internal(
            set,
            &secret[..n],
            &secret[n..2 * n],
            &secret[2 * n..3 * n],
            &mut derived.get_mut()[..4 * n],
            &mut public[..2 * n],
        )?;
        ensure!(
            ic_core::ct::verify(&derived.get()[..4 * n], secret),
            InvalidParameter,
            "slh-dsa root is not the one the key's seeds give"
        );
        let algorithm = SignatureAlgorithm::from_id(set.id())
            .ok_or(err!(Internal, "an slh-dsa set without an algorithm"))?;

        let mut spki = [0u8; MAX_SPKI];
        let len = {
            let mut w = Writer::new(&mut spki);
            w.push_bit_string(&public[..2 * n])?;
            let start = w.len();
            w.push_oid(id)?;
            w.push_wrapper(SEQUENCE, start)?;
            w.push_wrapper(SEQUENCE, 0)?;
            w.finish()
        };
        Ok(Self::new(Key::SlhDsa(set, derived), algorithm, spki, len))
    }
}

impl Signer for SoftwareSigner {
    fn algorithms(&self) -> &[SignatureAlgorithm] {
        match self.key {
            Key::Rsa(_) => &RSA_ALGORITHMS,
            _ => core::slice::from_ref(&self.algorithm),
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.spki[..self.spki_len]
    }

    fn custody(&self) -> Custody {
        Custody::Software
    }

    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> Result<usize> {
        use SignatureAlgorithm as A;
        ic_core::module::operational()?;
        ensure!(
            self.algorithms().contains(&algorithm),
            InvalidParameter,
            "this key does not sign with that algorithm"
        );
        // Every length is checked before anything is drawn from `rng` or
        // written to `out`.
        match &self.key {
            Key::P256(d) => ecdsa::<ic_ec::p256::EcdsaP256Sha256, 64>(d.get(), message, out),
            Key::P384(d) => ecdsa::<ic_ec::p384::EcdsaP384Sha384, 96>(d.get(), message, out),
            Key::P521(d) => ecdsa::<ic_ec::p521::EcdsaP521Sha512, 132>(d.get(), message, out),
            Key::Ed25519(seed) => {
                ensure!(out.len() >= 64, InvalidLength, "signature buffer too short");
                <ic_ec::Ed25519 as SignatureScheme>::sign(seed.get(), message, &mut out[..64])?;
                Ok(64)
            }
            Key::Rsa(key) => {
                let size = key.size();
                ensure!(
                    out.len() >= size,
                    InvalidLength,
                    "signature buffer too short"
                );
                let out = &mut out[..size];
                match algorithm {
                    A::RsaPkcs1Sha256 => ic_rsa::Pkcs1Sha256::sign(key, message, out),
                    A::RsaPkcs1Sha384 => ic_rsa::Pkcs1Sha384::sign(key, message, out),
                    A::RsaPkcs1Sha512 => ic_rsa::Pkcs1Sha512::sign(key, message, out),
                    A::RsaPssSha256 => ic_rsa::PssSha256::sign(key, message, rng, out),
                    A::RsaPssSha384 => ic_rsa::PssSha384::sign(key, message, rng, out),
                    A::RsaPssSha512 => ic_rsa::PssSha512::sign(key, message, rng, out),
                    _ => Err(err!(InvalidParameter, "not an rsa signature algorithm")),
                }?;
                Ok(size)
            }
            Key::MlDsa44(sk) => ml_dsa_44(sk.get(), message, rng, out),
            Key::MlDsa65(sk) => ml_dsa_65(sk.get(), message, rng, out),
            Key::MlDsa87(sk) => ml_dsa_87(sk.get(), message, rng, out),
            Key::SlhDsa(set, sk) => {
                let len = set.signature_len();
                ensure!(
                    out.len() >= len,
                    InvalidLength,
                    "signature buffer too short"
                );
                // Pure SLH-DSA with an empty context, hedged: RFC 9909.
                ic_slhdsa::sign(
                    *set,
                    &sk.get()[..set.secret_key_len()],
                    message,
                    b"",
                    rng,
                    &mut out[..len],
                )
            }
        }
    }
}

/// Deterministic ECDSA, encoded as the DER `Ecdsa-Sig-Value` X.509 and TLS
/// carry. `N` is the fixed-width signature, twice the field size.
#[inline(never)]
fn ecdsa<S: SignatureScheme, const N: usize>(
    private: &[u8],
    message: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let mut fixed = Zeroizing::new([0u8; N]);
    S::sign(private, message, fixed.get_mut())?;
    // The DER form is at most seven bytes longer than the fixed one, and its
    // length depends on the signature, so it is made aside and then copied.
    let mut der = [0u8; 139];
    let len = ic_pkix::ecdsa_signature::to_der(fixed.get(), &mut der)?;
    ensure!(
        out.len() >= len,
        InvalidLength,
        "signature buffer too short"
    );
    out[..len].copy_from_slice(&der[..len]);
    Ok(len)
}

macro_rules! ml_dsa_signer {
    ($name:ident, $module:ident) => {
        #[inline(never)]
        fn $name(
            secret: &[u8; ic_mldsa::$module::SECRET_KEY_LEN],
            message: &[u8],
            rng: &mut dyn RandomSource,
            out: &mut [u8],
        ) -> Result<usize> {
            use ic_mldsa::$module as m;
            ensure!(
                out.len() >= m::SIGNATURE_LEN,
                InvalidLength,
                "signature buffer too short"
            );
            let out: &mut [u8; m::SIGNATURE_LEN] = (&mut out[..m::SIGNATURE_LEN])
                .try_into()
                .map_err(|_| err!(Internal, "ml-dsa signature length"))?;
            // Hedged, pure ML-DSA with an empty context: RFC 9881.
            let mut randomness = Zeroizing::new([0u8; 32]);
            rng.fill(randomness.get_mut())?;
            let signed = m::sign(secret, message, b"", randomness.get(), out);
            if !signed {
                out.zeroize();
                return Err(err!(Internal, "ml-dsa signing did not produce a signature"));
            }
            Ok(m::SIGNATURE_LEN)
        }
    };
}

ml_dsa_signer!(ml_dsa_44, sign44);
ml_dsa_signer!(ml_dsa_65, sign);
ml_dsa_signer!(ml_dsa_87, sign87);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_spki;
    use ic_core::ErrorKind;

    /// A source that counts what is drawn from it.
    struct Counting(u64, usize);
    impl RandomSource for Counting {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            for b in out.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 56) as u8;
            }
            self.1 += out.len();
            Ok(())
        }
    }

    fn kind<T>(r: Result<T>) -> ErrorKind {
        match r {
            Ok(_) => panic!("must be refused"),
            Err(e) => e.kind(),
        }
    }

    /// Sign under every algorithm the key lists, verify each under the key it
    /// reports, and hold the interface's promises about refusals.
    fn exercise(signer: &SoftwareSigner) {
        let signer: &dyn Signer = signer;
        assert_eq!(signer.custody(), Custody::Software);
        assert!(!signer.algorithms().is_empty());
        let mut rng = Counting(1, 0);
        for &algorithm in signer.algorithms() {
            let mut out = vec![0u8; algorithm.max_signature_len()];
            let len = signer
                .sign(algorithm, b"message", &mut rng, &mut out)
                .unwrap();
            assert!(len <= out.len());
            verify_spki(algorithm, signer.public_key(), b"message", &out[..len])
                .unwrap_or_else(|e| panic!("{}: {e:?}", algorithm.id()));
            assert_eq!(
                kind(verify_spki(
                    algorithm,
                    signer.public_key(),
                    b"massage",
                    &out[..len]
                )),
                ErrorKind::AuthenticationFailed
            );

            // Too short a buffer: refused, nothing written, nothing drawn.
            let drawn = rng.1;
            let mut short = vec![0xa5u8; len - 1];
            assert_eq!(
                kind(signer.sign(algorithm, b"message", &mut rng, &mut short)),
                ErrorKind::InvalidLength,
                "{}",
                algorithm.id()
            );
            assert!(short.iter().all(|b| *b == 0xa5), "{}", algorithm.id());
            assert_eq!(rng.1, drawn, "{}: randomness was consumed", algorithm.id());
        }
        // An algorithm the key does not list is refused, not substituted.
        for &other in SignatureAlgorithm::ALL {
            if !signer.algorithms().contains(&other) {
                let mut out = vec![0u8; other.max_signature_len()];
                assert_eq!(
                    kind(signer.sign(other, b"message", &mut rng, &mut out)),
                    ErrorKind::InvalidParameter,
                    "{}",
                    other.id()
                );
            }
        }
    }

    fn ec_pkcs8(algorithm: KeyAlgorithm, private: &[u8], public: Option<&[u8]>) -> Vec<u8> {
        let mut buf = [0u8; 300];
        let n = PrivateKeyInfo::Ec {
            algorithm,
            private_key: private,
            public_key: public,
        }
        .to_der(&mut buf)
        .unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn the_curves_and_ed25519_sign_what_verify_accepts() {
        for (algorithm, len) in [
            (KeyAlgorithm::EcP256, 32),
            (KeyAlgorithm::EcP384, 48),
            (KeyAlgorithm::EcP521, 66),
        ] {
            let mut private = vec![0u8; len];
            private[len - 1] = 7;
            private[1] = 0x31;
            let signer = SoftwareSigner::from_pkcs8(&ec_pkcs8(algorithm, &private, None)).unwrap();
            assert_eq!(signer.algorithms().len(), 1);
            exercise(&signer);

            // Out of range: zero is no private key.
            assert_eq!(
                kind(SoftwareSigner::from_pkcs8(&ec_pkcs8(
                    algorithm,
                    &vec![0u8; len],
                    None
                ))),
                ErrorKind::InvalidParameter
            );
        }
        let mut buf = [0u8; 64];
        let n = PrivateKeyInfo::Ed25519(&[9u8; 32])
            .to_der(&mut buf)
            .unwrap();
        let signer = SoftwareSigner::from_pkcs8(&buf[..n]).unwrap();
        assert_eq!(signer.algorithms(), [SignatureAlgorithm::Ed25519]);
        exercise(&signer);
    }

    /// A stated public key must be the private key's. One that is another
    /// key's is refused when the file is read, not discovered at the far end.
    #[test]
    fn a_public_key_that_is_not_the_private_keys_is_refused() {
        let mut a = [0u8; 32];
        a[31] = 5;
        let mut b = [0u8; 32];
        b[31] = 6;
        let point = |d: &[u8]| {
            let mut p = [0u8; 65];
            <ic_ec::p256::EcdsaP256Sha256 as SignatureScheme>::public_key(d, &mut p).unwrap();
            p
        };
        let right = ec_pkcs8(KeyAlgorithm::EcP256, &a, Some(&point(&a)));
        let signer = SoftwareSigner::from_pkcs8(&right).unwrap();
        exercise(&signer);
        let wrong = ec_pkcs8(KeyAlgorithm::EcP256, &a, Some(&point(&b)));
        assert_eq!(
            kind(SoftwareSigner::from_pkcs8(&wrong)),
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn ml_dsa_signs_from_its_seed_and_refuses_a_key_without_one() {
        for set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let seed = [3u8; 32];
            let mut buf = vec![0u8; 8000];
            let n = MlDsaPrivateKey::Seed { set, seed: &seed }
                .to_der(&mut buf)
                .unwrap();
            let signer = SoftwareSigner::from_pkcs8(&buf[..n]).unwrap();
            exercise(&signer);

            // The expanded key alone: well formed, and not enough.
            let (mut pk, mut sk) = (vec![0u8; 2592], vec![0u8; 4896]);
            let sk_len = match set {
                MlDsaParameterSet::MlDsa44 => {
                    let (p, s) = (&mut pk[..1312], &mut sk[..2560]);
                    assert!(ic_mldsa::sign44::keygen(
                        &seed,
                        p.try_into().unwrap(),
                        s.try_into().unwrap()
                    ));
                    2560
                }
                MlDsaParameterSet::MlDsa65 => {
                    let (p, s) = (&mut pk[..1952], &mut sk[..4032]);
                    assert!(ic_mldsa::sign::keygen(
                        &seed,
                        p.try_into().unwrap(),
                        s.try_into().unwrap()
                    ));
                    4032
                }
                MlDsaParameterSet::MlDsa87 => {
                    assert!(ic_mldsa::sign87::keygen(
                        &seed,
                        (&mut pk[..]).try_into().unwrap(),
                        (&mut sk[..]).try_into().unwrap()
                    ));
                    4896
                }
            };
            let n = MlDsaPrivateKey::ExpandedKey {
                set,
                expanded_key: &sk[..sk_len],
            }
            .to_der(&mut buf)
            .unwrap();
            assert_eq!(
                kind(SoftwareSigner::from_pkcs8(&buf[..n])),
                ErrorKind::Unsupported
            );

            // Both forms, agreeing, is read; disagreeing, refused.
            let n = MlDsaPrivateKey::Both {
                set,
                seed: &seed,
                expanded_key: &sk[..sk_len],
            }
            .to_der(&mut buf)
            .unwrap();
            SoftwareSigner::from_pkcs8(&buf[..n]).unwrap();
            sk[100] ^= 1;
            let n = MlDsaPrivateKey::Both {
                set,
                seed: &seed,
                expanded_key: &sk[..sk_len],
            }
            .to_der(&mut buf)
            .unwrap();
            assert_eq!(
                kind(SoftwareSigner::from_pkcs8(&buf[..n])),
                ErrorKind::InvalidParameter
            );
        }
    }

    /// An SLH-DSA key as RFC 9909 section 7 encodes it.
    fn slh_dsa_pkcs8(id: &[u8], secret: &[u8], with_parameters: bool) -> Vec<u8> {
        let mut buf = [0u8; 200];
        let mut w = Writer::new(&mut buf);
        w.push_octet_string(secret).unwrap();
        let start = w.len();
        if with_parameters {
            w.push_null().unwrap();
        }
        w.push_oid(id).unwrap();
        w.push_wrapper(SEQUENCE, start).unwrap();
        w.push_unsigned_u64(0).unwrap();
        w.push_wrapper(SEQUENCE, 0).unwrap();
        let n = w.finish();
        buf[..n].to_vec()
    }

    #[test]
    fn slh_dsa_signs_and_a_key_with_the_wrong_root_is_refused() {
        use ic_pkix::oid;
        for (set, id) in [
            (ParameterSet::Sha2_128f, oid::SLH_DSA_SHA2_128F),
            (ParameterSet::Shake_192f, oid::SLH_DSA_SHAKE_192F),
            (ParameterSet::Sha2_256f, oid::SLH_DSA_SHA2_256F),
        ] {
            let n = set.n();
            let seed = [6u8; 32];
            let (mut sk, mut pk) = (vec![0u8; 4 * n], vec![0u8; 2 * n]);
            ic_slhdsa::keygen_internal(set, &seed[..n], &seed[..n], &seed[..n], &mut sk, &mut pk)
                .unwrap();
            let signer = SoftwareSigner::from_pkcs8(&slh_dsa_pkcs8(id, &sk, false)).unwrap();
            assert_eq!(signer.algorithms()[0].id(), set.id());
            exercise(&signer);

            // The root is a stated value; one that is not the seeds' is
            // refused. So is a seed changed under an unchanged root.
            let mut wrong_root = sk.clone();
            wrong_root[4 * n - 1] ^= 1;
            let mut wrong_seed = sk.clone();
            wrong_seed[0] ^= 1;
            for bad in [wrong_root, wrong_seed] {
                assert_eq!(
                    kind(SoftwareSigner::from_pkcs8(&slh_dsa_pkcs8(id, &bad, false))),
                    ErrorKind::InvalidParameter
                );
            }
            // RFC 9909: parameters are absent, and the key is 4n bytes.
            assert_eq!(
                kind(SoftwareSigner::from_pkcs8(&slh_dsa_pkcs8(id, &sk, true))),
                ErrorKind::MalformedEncoding
            );
            assert_eq!(
                kind(SoftwareSigner::from_pkcs8(&slh_dsa_pkcs8(
                    id,
                    &sk[1..],
                    false
                ))),
                ErrorKind::MalformedEncoding
            );
        }
    }

    #[test]
    fn keys_that_do_not_sign_are_refused_as_what_they_are() {
        let mut buf = [0u8; 64];
        let n = PrivateKeyInfo::X25519(&[3u8; 32]).to_der(&mut buf).unwrap();
        assert_eq!(
            kind(SoftwareSigner::from_pkcs8(&buf[..n])),
            ErrorKind::Unsupported
        );
        // An algorithm nobody here implements.
        assert_eq!(
            kind(SoftwareSigner::from_pkcs8(&slh_dsa_pkcs8(
                &[0x2a, 0x03, 0x04],
                &[1, 2, 3],
                false
            ))),
            ErrorKind::Unsupported
        );
        assert_eq!(
            kind(SoftwareSigner::from_pkcs8(&[0x30, 0x00])),
            ErrorKind::MalformedEncoding
        );
        // The key is not printed.
        let n = PrivateKeyInfo::Ed25519(&[0xabu8; 32])
            .to_der(&mut buf)
            .unwrap();
        let shown = format!("{:?}", SoftwareSigner::from_pkcs8(&buf[..n]).unwrap());
        assert!(shown.contains("Ed25519") && !shown.contains("171") && !shown.contains("ab, ab"));
    }
}
