//! Encrypted PKCS#8: `EncryptedPrivateKeyInfo` under PBES2, with
//! PBKDF2-HMAC-SHA-256 and AES-256-CBC.
//!
//! A private key file that only a passphrase unlocks, in the form OpenSSL
//! writes and reads (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). [`encrypt`] and
//! [`decrypt`] work on PKCS#8 DER; [`PrivateKeyInfo::to_encrypted_der`] and
//! [`PrivateKeyInfo::from_encrypted_der`] go to and from a parsed key.
//!
//! This is the one module in the crate that performs cryptography. The rest of
//! the crate only translates; a key file under a passphrase cannot be read
//! without decrypting it, so the decryption lives beside the parser that needs
//! its output.
//!
//! # The format
//!
//! RFC 5958 §3 and RFC 8018 §6.2 and A.2-A.4, exactly as OpenSSL 3 writes them
//! with `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256`:
//!
//! ```text
//! EncryptedPrivateKeyInfo ::= SEQUENCE {
//!   encryptionAlgorithm SEQUENCE {
//!     id-PBES2,
//!     SEQUENCE {
//!       keyDerivationFunc SEQUENCE {
//!         id-PBKDF2,
//!         SEQUENCE { salt OCTET STRING (16 bytes), iterationCount INTEGER,
//!                    prf SEQUENCE { id-hmacWithSHA256, NULL } } },
//!       encryptionScheme SEQUENCE { id-aes256-CBC, iv OCTET STRING (16 bytes) } } },
//!   encryptedData OCTET STRING }
//! ```
//!
//! The key is 32 bytes of PBKDF2-HMAC-SHA-256 over the passphrase and the
//! salt; the plaintext, the PKCS#8 `PrivateKeyInfo`, is padded as PKCS#7 and
//! encrypted under AES-256-CBC. Salt and IV are drawn afresh for every
//! encryption. Writing is checked byte for byte against OpenSSL's output for
//! the same salt and IV, and reading against keys OpenSSL encrypted
//! (`scripts/gen_pkcs8_pbes2_vectors.py`).
//!
//! # Why CBC
//!
//! AES-256-CBC is not authenticated, and this library's rule is never to use
//! an unauthenticated mode alone. The format dictates it here. RFC 8018 offers
//! no AEAD, and OpenSSL refuses one for PKCS#8 ("AEAD ciphers not supported"),
//! so a key encrypted under AES-GCM could not be opened by anything else. What
//! stands in for a tag is weak: a wrong passphrase fails the padding check, or
//! the DER parse after it, and the padding alone lets about one wrong
//! passphrase in 256 through to the parse. A file someone can modify can be
//! made to decrypt to different bytes. Keep the file where only its owner can
//! write it. Under a format of this library's own, `ic_kdf::passphrase` seals
//! with an AEAD and authenticates its parameters.
//!
//! # Limits
//!
//! Both directions refuse an iteration count under [`MIN_ITERATIONS`]
//! (600 000, the floor this library holds PBKDF2-HMAC-SHA-256 to for
//! passwords) or over [`MAX_ITERATIONS`], which stops a hostile file from
//! making [`decrypt`] spend minutes before failing. OpenSSL's default is 2048,
//! so a key OpenSSL encrypted without `-iter` is refused: re-encrypt it with
//! `-iter 600000` or more. Only HMAC-SHA-256 as the PRF and AES-256-CBC as the
//! cipher are read; anything else is
//! [`Unsupported`](ic_core::ErrorKind::Unsupported).
//!
//! The passphrase is bytes, as RFC 8018 §3 leaves it; OpenSSL passes its
//! passphrase's bytes unchanged, so a UTF-8 passphrase interoperates.

use crate::der::{self, Reader, Writer};
use crate::oid;
use crate::PrivateKeyInfo;
use ic_cipher::{cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad, Aes256};
use ic_core::traits::{BlockCipher, RandomSource};
use ic_core::{ensure, Result, Zeroize, Zeroizing};
use ic_mac::HmacSha256;

/// The least iteration count written or read.
pub const MIN_ITERATIONS: u32 = 600_000;
/// The greatest iteration count written or read.
pub const MAX_ITERATIONS: u32 = 10_000_000;
/// The iteration count to pass when there is no reason to choose another.
pub const DEFAULT_ITERATIONS: u32 = MIN_ITERATIONS;
/// Bytes of salt written.
pub const SALT_LEN: usize = 16;

const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const BLOCK_LEN: usize = 16;

/// Bytes the encrypted form adds to a plaintext, at most: up to 16 of padding
/// and at most 128 of DER around the ciphertext (106 for a ciphertext under
/// 64 KiB).
pub const OVERHEAD: usize = BLOCK_LEN + 128;

/// The output buffer [`encrypt`] needs for a plaintext of `plaintext_len`
/// bytes: an upper bound, not the exact length written.
pub const fn encrypted_len(plaintext_len: usize) -> usize {
    plaintext_len + OVERHEAD
}

/// Encrypt the PKCS#8 `PrivateKeyInfo` DER `plaintext` under `passphrase`,
/// writing an `EncryptedPrivateKeyInfo` to `out` and returning its length.
///
/// `iterations` must lie in [`MIN_ITERATIONS`] to [`MAX_ITERATIONS`]. Salt and
/// IV come from `rng`, salt first. `out` needs [`encrypted_len`] bytes. The
/// plaintext is not parsed; [`PrivateKeyInfo::to_encrypted_der`] encrypts a key
/// it has just serialized. On any error `out` holds no plaintext.
pub fn encrypt(
    plaintext: &[u8],
    passphrase: &[u8],
    iterations: u32,
    rng: &mut impl RandomSource,
    out: &mut [u8],
) -> Result<usize> {
    ensure!(
        plaintext.len() <= out.len(),
        InvalidLength,
        "pbes2 output buffer is too small"
    );
    out[..plaintext.len()].copy_from_slice(plaintext);
    seal_front(plaintext.len(), passphrase, iterations, rng, out)
}

/// Decrypt an `EncryptedPrivateKeyInfo` under `passphrase`, writing the PKCS#8
/// `PrivateKeyInfo` DER to the front of `out` and returning its length.
///
/// `out` needs as many bytes as the ciphertext. A wrong passphrase is
/// [`AuthenticationFailed`](ic_core::ErrorKind::AuthenticationFailed) when the
/// padding is wrong, which is all but about one attempt in 256. The plaintext
/// is not parsed here, so the rest show up when it is
/// ([`PrivateKeyInfo::from_encrypted_der`] parses it). On any error `out`
/// holds no plaintext.
pub fn decrypt(encrypted: &[u8], passphrase: &[u8], out: &mut [u8]) -> Result<usize> {
    ic_core::module::operational()?;
    open(&parse(encrypted, MIN_ITERATIONS)?, passphrase, out)
}

impl<'a> PrivateKeyInfo<'a> {
    /// Serialize as a PKCS#8 `EncryptedPrivateKeyInfo` under `passphrase`,
    /// returning the length written. See [`encrypt`] for `iterations`, `rng`
    /// and the size of `out`. RSA is refused, as by
    /// [`to_der`](PrivateKeyInfo::to_der).
    pub fn to_encrypted_der(
        &self,
        passphrase: &[u8],
        iterations: u32,
        rng: &mut impl RandomSource,
        out: &mut [u8],
    ) -> Result<usize> {
        let n = self.to_der(out)?;
        seal_front(n, passphrase, iterations, rng, out)
    }

    /// Decrypt and parse a PKCS#8 `EncryptedPrivateKeyInfo`. The plaintext key
    /// is written to `out`, which the result borrows: wipe `out` when done with
    /// the key. See [`decrypt`].
    pub fn from_encrypted_der(
        encrypted: &[u8],
        passphrase: &[u8],
        out: &'a mut [u8],
    ) -> Result<Self> {
        let n = decrypt(encrypted, passphrase, out)?;
        // Parsed twice: once to wipe `out` on failure, which needs it
        // mutable, then for the result, which borrows it.
        if let Err(e) = PrivateKeyInfo::from_der(&out[..n]) {
            out[..n].zeroize();
            return Err(e);
        }
        let out: &'a [u8] = out;
        PrivateKeyInfo::from_der(&out[..n])
    }
}

/// [`encrypt`], with the plaintext already in `out[..plaintext_len]`.
fn seal_front(
    plaintext_len: usize,
    passphrase: &[u8],
    iterations: u32,
    rng: &mut impl RandomSource,
    out: &mut [u8],
) -> Result<usize> {
    // Refused in the error state before a salt is drawn.
    let sealed = ic_core::module::operational()
        .and_then(|()| check_iterations(iterations))
        .and_then(|()| {
            let mut salt = [0u8; SALT_LEN];
            let mut iv = [0u8; IV_LEN];
            rng.fill(&mut salt)?;
            rng.fill(&mut iv)?;
            seal_with(plaintext_len, passphrase, &salt, iterations, &iv, out)
        });
    // A failure part way can leave plaintext anywhere in `out`.
    if sealed.is_err() {
        out.zeroize();
    }
    sealed
}

fn check_iterations(iterations: u32) -> Result<()> {
    ensure!(
        (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations),
        InvalidParameter,
        "pbes2 iteration count outside 600 000 to 10 000 000"
    );
    Ok(())
}

/// Encrypt `out[..plaintext_len]` in place, with salt and IV given, and wrap
/// it. No iteration floor beyond PBKDF2's own, for the self-test.
fn seal_with(
    plaintext_len: usize,
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    iterations: u32,
    iv: &[u8; IV_LEN],
    out: &mut [u8],
) -> Result<usize> {
    let padded = (plaintext_len / BLOCK_LEN + 1) * BLOCK_LEN;
    ensure!(
        padded <= out.len(),
        InvalidLength,
        "pbes2 output buffer is too small"
    );
    // The ciphertext is the last thing in the encoding, and the writer builds
    // from the end, so the plaintext moves to the end and is encrypted there.
    let tail = out.len() - padded;
    out.copy_within(..plaintext_len, tail);
    out[..plaintext_len.min(tail)].zeroize();

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    ic_kdf::pbkdf2::<HmacSha256>(passphrase, salt, iterations, &mut key[..])?;
    let aes = Aes256::new(&key[..])?;

    let mut w = Writer::new(out);
    let body = w.claim(padded)?;
    pkcs7_pad(body, plaintext_len)?;
    cbc_encrypt(&aes, iv, body)?;
    w.push_header(der::OCTET_STRING, padded)?;

    // The AlgorithmIdentifier, last field first: the writer runs backwards.
    let alg = w.len();
    let scheme = w.len();
    w.push_octet_string(iv)?;
    w.push_oid(oid::AES256_CBC)?;
    w.push_wrapper(der::SEQUENCE, scheme)?;
    let kdf = w.len();
    let prf = w.len();
    w.push_null()?;
    w.push_oid(oid::HMAC_WITH_SHA256)?;
    w.push_wrapper(der::SEQUENCE, prf)?;
    w.push_unsigned_u64(u64::from(iterations))?;
    w.push_octet_string(salt)?;
    w.push_wrapper(der::SEQUENCE, kdf)?; // PBKDF2-params
    w.push_oid(oid::PBKDF2)?;
    w.push_wrapper(der::SEQUENCE, kdf)?;
    w.push_wrapper(der::SEQUENCE, alg)?; // PBES2-params
    w.push_oid(oid::PBES2)?;
    w.push_wrapper(der::SEQUENCE, alg)?;
    w.push_wrapper(der::SEQUENCE, 0)?;
    Ok(w.finish())
}

/// Decrypt parsed parameters into the front of `out`.
fn open(params: &Params<'_>, passphrase: &[u8], out: &mut [u8]) -> Result<usize> {
    let ct = params.ciphertext;
    ensure!(
        !ct.is_empty() && ct.len().is_multiple_of(BLOCK_LEN),
        MalformedEncoding,
        "pbes2 ciphertext is not whole blocks"
    );
    ensure!(
        ct.len() <= out.len(),
        InvalidLength,
        "pbes2 output buffer is too small"
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    ic_kdf::pbkdf2::<HmacSha256>(passphrase, params.salt, params.iterations, &mut key[..])?;
    let body = &mut out[..ct.len()];
    body.copy_from_slice(ct);
    let opened = Aes256::new(&key[..])
        .and_then(|aes| cbc_decrypt(&aes, params.iv, body))
        .and_then(|()| pkcs7_unpad(body));
    match opened {
        Ok(len) => {
            body[len..].zeroize();
            Ok(len)
        }
        Err(_) => {
            body.zeroize();
            Err(ic_core::Error::new(
                ic_core::ErrorKind::AuthenticationFailed,
                "pbes2: wrong passphrase or corrupt key",
            ))
        }
    }
}

/// The parts of an `EncryptedPrivateKeyInfo` that decryption needs.
struct Params<'a> {
    salt: &'a [u8],
    iterations: u32,
    iv: &'a [u8],
    ciphertext: &'a [u8],
}

/// Parse, refusing an iteration count under `floor` or over
/// [`MAX_ITERATIONS`].
fn parse(input: &[u8], floor: u32) -> Result<Params<'_>> {
    let mut outer = Reader::new(input);
    let mut epki = outer.sequence()?;
    outer.finish()?;

    let mut alg = epki.sequence()?;
    let ciphertext = epki.octet_string()?;
    epki.finish()?;
    ensure!(
        alg.oid()? == oid::PBES2,
        Unsupported,
        "encrypted pkcs#8: only PBES2 is supported"
    );
    let mut pbes2 = alg.sequence()?;
    alg.finish()?;

    let mut kdf = pbes2.sequence()?;
    let mut scheme = pbes2.sequence()?;
    pbes2.finish()?;

    ensure!(
        kdf.oid()? == oid::PBKDF2,
        Unsupported,
        "pbes2: only PBKDF2 is supported"
    );
    let mut kdf_params = kdf.sequence()?;
    kdf.finish()?;
    // The salt's other choice, an AlgorithmIdentifier, is a SEQUENCE and
    // fails here as the wrong tag.
    let salt = kdf_params.octet_string()?;
    let iterations = kdf_params.unsigned_integer_u64()?;
    ensure!(
        iterations >= u64::from(floor) && iterations <= u64::from(MAX_ITERATIONS),
        InvalidParameter,
        "pbes2 iteration count outside 600 000 to 10 000 000"
    );
    if kdf_params.peek_tag() == Some(der::INTEGER) {
        ensure!(
            kdf_params.unsigned_integer_u64()? == KEY_LEN as u64,
            MalformedEncoding,
            "pbkdf2 key length is not aes-256's"
        );
    }
    // An absent prf is the default, hmacWithSHA1.
    ensure!(
        kdf_params.peek_tag() == Some(der::SEQUENCE),
        Unsupported,
        "pbkdf2: only hmacWithSHA256 is supported"
    );
    let mut prf = kdf_params.sequence()?;
    kdf_params.finish()?;
    ensure!(
        prf.oid()? == oid::HMAC_WITH_SHA256,
        Unsupported,
        "pbkdf2: only hmacWithSHA256 is supported"
    );
    if !prf.is_empty() {
        prf.null()?;
    }
    prf.finish()?;

    ensure!(
        scheme.oid()? == oid::AES256_CBC,
        Unsupported,
        "pbes2: only aes256-CBC is supported"
    );
    let iv = scheme.octet_string()?;
    scheme.finish()?;
    ensure!(iv.len() == IV_LEN, MalformedEncoding, "aes-cbc iv length");

    Ok(Params {
        salt,
        iterations: iterations as u32,
        iv,
        ciphertext,
    })
}

/// The known-answer test: one encryption at a fixed salt and IV, and its
/// decryption.
///
/// The plaintext is RFC 8410 §10.3's example Ed25519 key. The expected
/// encoding was not produced by this code; see [`SELF_TEST_ANSWER`], and
/// docs/FIPS.md for the record. It runs at 1000 iterations, PBKDF2's floor,
/// to keep start-up short; the public functions refuse under
/// [`MIN_ITERATIONS`].
pub fn self_test() -> Result<()> {
    const PASSPHRASE: &[u8] = b"IronCrypto pbes2 self-test";
    let mut plaintext = [0u8; 48];
    ic_core::codec::hex_decode(
        b"302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad\
          3afe7c28cbf1d4fbe097a88f44755842",
        &mut plaintext,
    )?;
    let mut salt = [0u8; SALT_LEN];
    ic_core::codec::hex_decode(b"000102030405060708090a0b0c0d0e0f", &mut salt)?;
    let mut iv = [0u8; IV_LEN];
    ic_core::codec::hex_decode(b"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", &mut iv)?;
    let mut want = [0u8; SELF_TEST_LEN];
    ic_core::codec::hex_decode(SELF_TEST_ANSWER, &mut want)?;

    let mut got = [0u8; 48 + OVERHEAD];
    got[..48].copy_from_slice(&plaintext);
    let n = seal_with(48, PASSPHRASE, &salt, 1000, &iv, &mut got)?;
    ensure!(
        n == SELF_TEST_LEN && ic_core::ct::verify(&want, &got[..n]),
        SelfTestFailed,
        "pbes2"
    );

    // decrypt() refuses 1000 iterations; the floor is the only difference.
    let mut back = [0u8; SELF_TEST_LEN];
    let len = open(&parse(&want, 1000)?, PASSPHRASE, &mut back)?;
    ensure!(
        ic_core::ct::verify(&plaintext, &back[..len]),
        SelfTestFailed,
        "pbes2"
    );
    Ok(())
}

/// The self-test's expected encoding. Computed a second time with pyca
/// `cryptography` 50 (PBKDF2HMAC, AES-CBC, PKCS7) over a DER layout written
/// separately, and decrypted by OpenSSL 3.5.9 to the RFC 8410 key.
const SELF_TEST_LEN: usize = 166;
const SELF_TEST_ANSWER: &[u8] = b"3081a3305f06092a864886f70d01050d3052303106092a864886f70d01050c30\
      240410000102030405060708090a0b0c0d0e0f020203e8300c06082a864886f7\
      0d02090500301d060960864801650304012a0410f0f1f2f3f4f5f6f7f8f9fafb\
      fcfdfeff0440c2de1238be4a9ea0ce2899306f69762316dd5f36525e577564e1\
      85d2bdd97ae425468ed06848c7fce67657c751a1636be362a5ceb306c85578cd\
      6194b78fdc83";

#[cfg(test)]
mod tests {
    use super::*;

    /// Replays fixed bytes, as salt then IV.
    struct Replay<'a>(&'a [u8]);

    impl RandomSource for Replay<'_> {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            ensure!(out.len() <= self.0.len(), Internal, "replay exhausted");
            out.copy_from_slice(&self.0[..out.len()]);
            self.0 = &self.0[out.len()..];
            Ok(())
        }
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn writing_refuses_iterations_outside_the_range() {
        let mut out = [0u8; 48 + OVERHEAD];
        let salt_iv = [7u8; 32];
        for it in [1000, MIN_ITERATIONS - 1, MAX_ITERATIONS + 1] {
            let err = encrypt(&[1u8; 48], b"pw", it, &mut Replay(&salt_iv), &mut out).unwrap_err();
            assert_eq!(err.kind(), ic_core::ErrorKind::InvalidParameter, "{it}");
            assert!(out.iter().all(|b| *b == 0), "plaintext left in out at {it}");
        }
    }

    #[test]
    fn a_small_buffer_is_refused_and_left_clear() {
        // Room for the plaintext, which is copied in, but not its padding.
        let mut out = [0u8; 50];
        let salt_iv = [7u8; 32];
        let err = encrypt(
            &[1u8; 48],
            b"pw",
            MIN_ITERATIONS,
            &mut Replay(&salt_iv),
            &mut out,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::InvalidLength);
        assert!(out.iter().all(|b| *b == 0));
    }
}
