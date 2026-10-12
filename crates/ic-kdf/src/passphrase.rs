//! Sealing a secret under a passphrase: Argon2id and XChaCha20-Poly1305 in
//! one versioned container.
//!
//! For keeping a key at rest when the only thing a person can supply is a
//! passphrase -- a CA's signing key, an agent's identity key. One call seals,
//! one opens; nothing to compose, and the parameters travel with the
//! ciphertext so a container still opens after the defaults change.
//!
//! # The format, version 1
//!
//! ```text
//! offset  length
//!      0       4  magic, "ICPW"
//!      4       1  version, 1
//!      5       1  key derivation, 1 = Argon2id (RFC 9106, version 0x13)
//!      6       1  cipher, 1 = XChaCha20-Poly1305
//!      7       4  Argon2 memory in KiB, big-endian
//!     11       4  Argon2 passes, big-endian
//!     15       4  Argon2 lanes, big-endian
//!     19      16  salt
//!     35      24  nonce
//!     59       n  ciphertext, as long as the plaintext
//!   59+n      16  tag
//! ```
//!
//! The key is 32 bytes of Argon2id over the passphrase and the salt. The
//! whole 59-byte header is the cipher's associated data, so changing any
//! parameter, or the salt, or a reserved identifier, makes the tag fail
//! rather than producing a different plaintext. Salt and nonce are drawn
//! afresh for every seal. `scripts/gen_passphrase_vectors.py` is a second
//! implementation of this layout, over libsodium and the Argon2 reference
//! code, and the tests require both to agree.
//!
//! # Limits
//!
//! [`seal`] and [`open`] both refuse parameters outside [`MIN_MEMORY_KIB`],
//! [`MIN_WORK_KIB`] and the maxima below: the floor so that a weak container
//! is never made or trusted, the ceiling so that a container someone else
//! wrote cannot make [`open`] allocate without bound before its tag is
//! checked. [`Argon2Params::INTERACTIVE`] and [`Argon2Params::RECOMMENDED`]
//! are both inside them.
//!
//! Not FIPS-approved: neither Argon2id nor XChaCha20-Poly1305 is. Under a FIPS
//! obligation, the approved choice is PBKDF2 with HMAC-SHA-256 and
//! AES-256-GCM, which this format does not offer.

use crate::argon2::{argon2, Argon2Params, Variant};
use ic_cipher::XChaCha20Poly1305;
use ic_core::traits::{Aead, RandomSource};
use ic_core::{ensure, Result, Zeroizing};

/// The first four bytes of every container.
pub const MAGIC: [u8; 4] = *b"ICPW";
/// The format version this writes and reads.
pub const VERSION: u8 = 1;
/// Bytes before the ciphertext.
pub const HEADER_LEN: usize = 59;
/// Bytes a container adds to its plaintext: the header and the tag.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// The least memory accepted: 19 MiB, the floor OWASP gives for Argon2id.
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
/// The least memory times passes accepted: 19 MiB over two passes, or the
/// same work spent another way. RFC 9106's two recommended settings, 2 GiB
/// over one pass and 64 MiB over three, are both above it.
pub const MIN_WORK_KIB: u64 = 2 * MIN_MEMORY_KIB as u64;
/// The most memory accepted: 4 GiB.
pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
/// The most passes accepted.
pub const MAX_PASSES: u32 = 32;
/// The most lanes accepted.
pub const MAX_LANES: u32 = 64;

const KDF_ARGON2ID: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Whether `params` are inside the floor and the ceiling.
fn check_params(params: &Argon2Params) -> Result<()> {
    params.validate()?;
    ensure!(
        params.memory_kib >= MIN_MEMORY_KIB
            && u64::from(params.memory_kib) * u64::from(params.passes) >= MIN_WORK_KIB,
        InvalidParameter,
        "passphrase: argon2 parameters below the floor"
    );
    ensure!(
        params.memory_kib <= MAX_MEMORY_KIB
            && params.passes <= MAX_PASSES
            && params.lanes <= MAX_LANES,
        InvalidParameter,
        "passphrase: argon2 parameters above the ceiling"
    );
    Ok(())
}

fn header(
    params: &Argon2Params,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&MAGIC);
    h[4] = VERSION;
    h[5] = KDF_ARGON2ID;
    h[6] = AEAD_XCHACHA20_POLY1305;
    h[7..11].copy_from_slice(&params.memory_kib.to_be_bytes());
    h[11..15].copy_from_slice(&params.passes.to_be_bytes());
    h[15..19].copy_from_slice(&params.lanes.to_be_bytes());
    h[19..35].copy_from_slice(salt);
    h[35..59].copy_from_slice(nonce);
    h
}

fn derive(passphrase: &[u8], params: &Argon2Params, salt: &[u8]) -> Result<XChaCha20Poly1305> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2(Variant::Argon2id, params, passphrase, salt, key.get_mut())?;
    XChaCha20Poly1305::new(&key[..])
}

/// Seal `plaintext` under `passphrase`, writing the container to the front
/// of `out` and returning its length, `plaintext.len() + OVERHEAD`.
///
/// The salt and nonce come from `rng`; pass `ic_drbg::Rng`. A buffer too
/// short is refused before anything is drawn or derived.
pub fn seal<R: RandomSource + ?Sized>(
    passphrase: &[u8],
    params: &Argon2Params,
    rng: &mut R,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    ic_core::module::operational()?;
    check_params(params)?;
    ensure!(
        out.len() >= plaintext.len() + OVERHEAD,
        InvalidLength,
        "passphrase: output buffer"
    );
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut salt)?;
    rng.fill(&mut nonce)?;
    seal_with(passphrase, params, &salt, &nonce, plaintext, out)
}

/// [`seal`] with the salt and nonce given and no floor: for the self-test,
/// which cannot afford 38 MiB of Argon2, and for this module's tests.
pub(crate) fn seal_with(
    passphrase: &[u8],
    params: &Argon2Params,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let total = plaintext.len() + OVERHEAD;
    ensure!(
        out.len() >= total,
        InvalidLength,
        "passphrase: output buffer"
    );
    let header = header(params, salt, nonce);
    let cipher = derive(passphrase, params, salt)?;
    let (head, rest) = out.split_at_mut(HEADER_LEN);
    head.copy_from_slice(&header);
    let (body, tag) = rest[..plaintext.len() + TAG_LEN].split_at_mut(plaintext.len());
    body.copy_from_slice(plaintext);
    cipher.seal_detached(nonce, &header, body, tag)?;
    Ok(total)
}

/// The parameters a container was sealed with, read from its header without
/// deriving anything.
///
/// For deciding whether to reseal under stronger ones. The header is not
/// authenticated until [`open`] succeeds, so treat these as a claim.
pub fn params_of(sealed: &[u8]) -> Result<Argon2Params> {
    ensure!(
        sealed.len() >= OVERHEAD,
        MalformedEncoding,
        "passphrase: too short to be a container"
    );
    ensure!(
        sealed[..4] == MAGIC,
        MalformedEncoding,
        "passphrase: not a container"
    );
    ensure!(
        sealed[4] == VERSION,
        Unsupported,
        "passphrase: container version"
    );
    ensure!(
        sealed[5] == KDF_ARGON2ID && sealed[6] == AEAD_XCHACHA20_POLY1305,
        Unsupported,
        "passphrase: container algorithms"
    );
    let word = |at: usize| {
        u32::from_be_bytes([sealed[at], sealed[at + 1], sealed[at + 2], sealed[at + 3]])
    };
    Ok(Argon2Params {
        memory_kib: word(7),
        passes: word(11),
        lanes: word(15),
    })
}

/// Open a container sealed by [`seal`], writing the plaintext to the front of
/// `out` and returning its length, `sealed.len() - OVERHEAD`.
///
/// A wrong passphrase and a changed container are the same error,
/// `AuthenticationFailed`, and leave `out` zeroed. A header this version does
/// not read, or parameters outside the limits, is refused before anything is
/// derived.
pub fn open(passphrase: &[u8], sealed: &[u8], out: &mut [u8]) -> Result<usize> {
    ic_core::module::operational()?;
    let params = params_of(sealed)?;
    check_params(&params)?;
    let len = sealed.len() - OVERHEAD;
    ensure!(out.len() >= len, InvalidLength, "passphrase: output buffer");
    let (header, rest) = sealed.split_at(HEADER_LEN);
    let (ciphertext, tag) = rest.split_at(len);
    let cipher = derive(passphrase, &params, &header[19..35])?;
    let body = &mut out[..len];
    body.copy_from_slice(ciphertext);
    cipher.open_detached(&header[35..59], header, body, tag)?;
    Ok(len)
}

/// The known-answer test: the first case of `testvectors/passphrase.json`,
/// which libsodium and the Argon2 reference code sealed, at parameters far
/// under the floor so that it is cheap enough to run at start-up.
pub fn self_test() -> Result<()> {
    let params = Argon2Params {
        memory_kib: 8,
        passes: 1,
        lanes: 1,
    };
    let mut salt = [0u8; SALT_LEN];
    ic_core::codec::hex_decode(b"478dda73d3df495d3f929fafbfe96178", &mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    ic_core::codec::hex_decode(
        b"4f8673a91b50f53a5ee19da0805e7e45621e67e226639dc7",
        &mut nonce,
    )?;
    let mut want = [0u8; 19 + OVERHEAD];
    ic_core::codec::hex_decode(
        b"49435057010101000000080000000100000001478dda73d3df495d3f929fafbfe96178\
          4f8673a91b50f53a5ee19da0805e7e45621e67e226639dc7e2702fb70258d6df040e35\
          5e99421fee9ed792301afb714463eaf09b6bc17c47eb0662",
        &mut want,
    )?;
    let mut got = [0u8; 19 + OVERHEAD];
    seal_with(
        b"IronCrypto passphrase self-test",
        &params,
        &salt,
        &nonce,
        b"self-test plaintext",
        &mut got,
    )?;
    ensure!(
        ic_core::ct::verify(&want, &got),
        SelfTestFailed,
        "passphrase"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: Argon2Params = Argon2Params {
        memory_kib: 8,
        passes: 1,
        lanes: 1,
    };

    #[test]
    fn the_self_test_passes() {
        self_test().unwrap();
    }

    /// Every header byte is bound to the tag: change any one and the
    /// container no longer opens, even where the change leaves it
    /// well-formed. Opened through the floorless path's inverse, built here,
    /// because the public one would refuse these parameters first.
    #[test]
    fn every_header_byte_is_authenticated() {
        let mut sealed = [0u8; 5 + OVERHEAD];
        seal_with(b"pw", &TINY, &[1; 16], &[2; 24], b"hello", &mut sealed).unwrap();
        // A ceiling of its own, as `open` has: flipping a high byte of a
        // parameter would otherwise ask for millions of passes.
        let open_tiny = |c: &[u8]| -> Result<()> {
            let params = params_of(c)?;
            ensure!(
                params.memory_kib <= 64 && params.passes <= 4 && params.lanes <= 4,
                InvalidParameter,
                "above this test's ceiling"
            );
            let cipher = derive(b"pw", &params, &c[19..35])?;
            let mut body = [0u8; 5];
            body.copy_from_slice(&c[HEADER_LEN..HEADER_LEN + 5]);
            cipher.open_detached(
                &c[35..59],
                &c[..HEADER_LEN],
                &mut body,
                &c[HEADER_LEN + 5..],
            )
        };
        open_tiny(&sealed).unwrap();
        for at in 0..HEADER_LEN {
            let mut c = sealed;
            c[at] ^= 1;
            assert!(
                open_tiny(&c).is_err(),
                "header byte {at} is not authenticated"
            );
        }
    }

    #[test]
    fn the_limits_are_enforced_on_both_sides() {
        let mut rng = Fixed;
        let mut out = [0u8; 64 + OVERHEAD];
        let below = [
            Argon2Params {
                memory_kib: MIN_MEMORY_KIB - 1,
                passes: 4,
                lanes: 1,
            },
            Argon2Params {
                memory_kib: MIN_MEMORY_KIB,
                passes: 1,
                lanes: 1,
            },
        ];
        let above = [
            Argon2Params {
                memory_kib: MAX_MEMORY_KIB + 1,
                passes: 1,
                lanes: 1,
            },
            Argon2Params {
                memory_kib: MIN_MEMORY_KIB,
                passes: MAX_PASSES + 1,
                lanes: 1,
            },
            Argon2Params {
                memory_kib: MIN_MEMORY_KIB,
                passes: 2,
                lanes: MAX_LANES + 1,
            },
        ];
        for p in below.iter().chain(&above) {
            assert!(
                seal(b"pw", p, &mut rng, b"x", &mut out).is_err(),
                "{p:?} sealed"
            );
            // A container that claims them is refused before derivation:
            // the header is built by hand, with no valid tag behind it.
            let mut forged = [0u8; OVERHEAD];
            forged[..HEADER_LEN].copy_from_slice(&header(p, &[0; 16], &[0; 24]));
            let err = open(b"pw", &forged, &mut out).unwrap_err();
            assert_eq!(err.kind(), ic_core::ErrorKind::InvalidParameter, "{p:?}");
        }
        for p in [Argon2Params::INTERACTIVE, Argon2Params::RECOMMENDED] {
            check_params(&p).unwrap();
        }
    }

    #[test]
    fn malformed_containers_are_refused_by_kind() {
        let mut out = [0u8; 8];
        let mut good = [0u8; OVERHEAD];
        good[..HEADER_LEN].copy_from_slice(&header(&Argon2Params::INTERACTIVE, &[0; 16], &[0; 24]));
        let kind = |c: &[u8]| open(b"pw", c, &mut [0u8; 8]).unwrap_err().kind();
        assert_eq!(
            kind(&good[..OVERHEAD - 1]),
            ic_core::ErrorKind::MalformedEncoding
        );
        let mut c = good;
        c[0] = b'X';
        assert_eq!(kind(&c), ic_core::ErrorKind::MalformedEncoding);
        for at in 4..7 {
            let mut c = good;
            c[at] = 2;
            assert_eq!(kind(&c), ic_core::ErrorKind::Unsupported, "byte {at}");
        }
        assert!(params_of(&good).is_ok());
        let _ = &mut out;
    }

    /// A random source that returns a fixed pattern, never called where it
    /// should not be.
    struct Fixed;
    impl RandomSource for Fixed {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            out.fill(0x5a);
            Ok(())
        }
    }
}
