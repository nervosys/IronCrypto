//! HSS/LMS signature verification: RFC 8554, with the parameter sets of
//! RFC 9858, as NIST SP 800-208 approves them.
//!
//! LMS is a hash-based signature scheme. Its security rests on a hash
//! function alone, which is why CNSA 2.0 names it for signing firmware and
//! software: a quantum computer that breaks RSA and elliptic curves does not
//! break it. HSS stacks LMS trees so that a key can sign more messages.
//!
//! ```
//! # fn main() -> ic_core::Result<()> {
//! # let (public_key, message, signature) = ic_lms::example();
//! ic_lms::verify(&public_key, &message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Verification only, and why
//!
//! This crate does not sign. An LMS private key is a set of one-time keys, and
//! signing twice with the same one lets a forger combine the two signatures
//! into a third: the scheme fails completely, not gradually. Keeping the count
//! of used keys correct across crashes, backups, restores and copies is a
//! property of a device, not of a function, and SP 800-208 requires that key
//! generation and signing happen inside a hardware cryptographic module for
//! that reason. A library function that signed would be an invitation to do it
//! wrong. Verifying has no state and no secret, and is all a system that checks
//! signed firmware needs.
//!
//! # What is accepted
//!
//! All four hash functions -- SHA-256, SHA-256/192, SHAKE256/256 and
//! SHAKE256/192 -- at every Winternitz width (1, 2, 4, 8) and tree height (5,
//! 10, 15, 20, 25): the sixteen LM-OTS and twenty LMS parameter sets of the two
//! RFCs. An HSS hierarchy has from one to eight levels. Within one tree the
//! LM-OTS and LMS parameter sets must use the same hash function, as every
//! pairing the RFCs define does; different levels of a hierarchy may differ.
//!
//! [`verify`] takes an HSS public key and signature, which is the form RFC
//! 8554 section 6 defines for use and the one protocols carry. A lone LMS
//! tree is an HSS hierarchy of one level. [`verify_lms`] takes a bare LMS
//! public key and signature, without the HSS framing.
//!
//! # Failure
//!
//! A public key that is not a well-formed key for a parameter set here is
//! refused as such: `MalformedEncoding`, or `Unsupported` for a typecode this
//! crate does not know. Everything wrong with a signature -- its length, its
//! typecodes, a leaf number past the tree, the keys it carries for lower
//! levels, the hashes themselves -- is `AuthenticationFailed`, undistinguished,
//! since the signature is the attacker's to choose. Nothing here allocates or
//! panics, and the work is bounded by the parameter sets: at most 8670 hash
//! calls per level, for W=8.
//!
//! # Verification of this crate
//!
//! All six published cases -- RFC 8554 appendix F's two and RFC 9858 appendix
//! A's four -- read from the RFCs' text, plus cases for the parameter sets they
//! do not cover, from an independent implementation that first reproduces RFC
//! 9858's keys and signatures from their published seeds. See
//! `scripts/gen_lms_vectors.py`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use ic_core::traits::{Algorithm, Digest, SelfTest, Xof};
use ic_core::{ensure, err, Result};
use ic_hash::{Sha256, Shake256};

/// The most levels an HSS hierarchy has, RFC 8554 section 6.
pub const MAX_LEVELS: usize = 8;

/// Length of the tree identifier `I`.
const I_LEN: usize = 16;
/// The longest hash output among the parameter sets.
const MAX_N: usize = 32;

const D_PBLC: [u8; 2] = [0x80, 0x80];
const D_MESG: [u8; 2] = [0x81, 0x81];
const D_LEAF: [u8; 2] = [0x82, 0x82];
const D_INTR: [u8; 2] = [0x83, 0x83];

/// HSS/LMS, for the ontology and the self-test table.
pub struct HssLms;

impl Algorithm for HssLms {
    const ID: &'static str = "hss-lms";
    const NAME: &'static str = "HSS/LMS hash-based signatures (verification)";
}

/// A hash function of RFC 8554 or RFC 9858.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-256, 32 bytes.
    Sha256,
    /// SHA-256 truncated to its first 24 bytes.
    Sha256_192,
    /// The first 32 bytes of SHAKE256.
    Shake256_256,
    /// The first 24 bytes of SHAKE256.
    Shake256_192,
}

impl Hash {
    /// The output length in bytes, `n` and `m` in the RFCs.
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 | Self::Shake256_256 => 32,
            Self::Sha256_192 | Self::Shake256_192 => 24,
        }
    }

    /// The hash's name, as the parameter-set names spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha256_192 => "sha256/192",
            Self::Shake256_256 => "shake256/256",
            Self::Shake256_192 => "shake256/192",
        }
    }

    fn start(self) -> Hasher {
        match self {
            Self::Sha256 | Self::Sha256_192 => Hasher::Sha(Sha256::new(), self.output_len()),
            Self::Shake256_256 | Self::Shake256_192 => {
                Hasher::Shake(Shake256::default(), self.output_len())
            }
        }
    }

    /// Hash the concatenation of `parts` into `out`, which is `output_len()` bytes.
    fn digest(self, parts: &[&[u8]], out: &mut [u8]) {
        let mut h = self.start();
        for part in parts {
            h.update(part);
        }
        h.finish(out);
    }
}

/// A hash in progress, for inputs assembled a piece at a time.
enum Hasher {
    Sha(Sha256, usize),
    Shake(Shake256, usize),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha(h, _) => h.update(data),
            Self::Shake(h, _) => Xof::update(h, data),
        }
    }

    fn finish(self, out: &mut [u8]) {
        match self {
            Self::Sha(h, n) => out[..n].copy_from_slice(&h.finalize().as_ref()[..n]),
            Self::Shake(h, n) => h.finalize_xof(&mut out[..n]),
        }
    }
}

/// An LM-OTS parameter set: RFC 8554 table 1 and RFC 9858 table 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lmots {
    hash: Hash,
    /// Winternitz width in bits.
    w: u32,
    /// Number of hash chains.
    p: usize,
    /// Left shift of the checksum.
    ls: u32,
}

impl Lmots {
    fn from_typecode(typecode: u32) -> Option<Self> {
        let hash = match typecode {
            0x01..=0x04 => Hash::Sha256,
            0x05..=0x08 => Hash::Sha256_192,
            0x09..=0x0c => Hash::Shake256_256,
            0x0d..=0x10 => Hash::Shake256_192,
            _ => return None,
        };
        // The four widths repeat in each block of four typecodes.
        let (w, p32, ls32, p24, ls24) = match (typecode - 1) % 4 {
            0 => (1, 265, 7, 200, 8),
            1 => (2, 133, 6, 101, 6),
            2 => (4, 67, 4, 51, 4),
            _ => (8, 34, 0, 26, 0),
        };
        let (p, ls) = if hash.output_len() == 32 {
            (p32, ls32)
        } else {
            (p24, ls24)
        };
        Some(Self { hash, w, p, ls })
    }

    /// Length of an LM-OTS signature: the typecode, `C`, and `p` chain values.
    fn signature_len(&self) -> usize {
        4 + self.hash.output_len() * (self.p + 1)
    }
}

/// An LMS parameter set: RFC 8554 table 2 and RFC 9858 table 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lms {
    hash: Hash,
    /// Tree height.
    h: u32,
}

impl Lms {
    fn from_typecode(typecode: u32) -> Option<Self> {
        let hash = match typecode {
            0x05..=0x09 => Hash::Sha256,
            0x0a..=0x0e => Hash::Sha256_192,
            0x0f..=0x13 => Hash::Shake256_256,
            0x14..=0x18 => Hash::Shake256_192,
            _ => return None,
        };
        let h = 5 * ((typecode - 0x05) % 5 + 1);
        Some(Self { hash, h })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// `coef(S, i, w)`, RFC 8554 section 3.1.3: the i-th w-bit value of `S`.
fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let w = w as usize;
    let byte = s[i * w / 8] as u32;
    let shift = 8 - (w * (i % (8 / w)) + w);
    (byte >> shift) & ((1 << w) - 1)
}

/// `Cksm(S)`, RFC 8554 algorithm 2.
fn checksum(s: &[u8], w: u32, ls: u32) -> u16 {
    let digits = s.len() * 8 / w as usize;
    let mut sum = 0u32;
    for i in 0..digits {
        sum += (1 << w) - 1 - coef(s, i, w);
    }
    // At most 265 digits of at most 255 fits sixteen bits before the shift,
    // and the shift is the one the tables give for that width.
    (sum << ls) as u16
}

/// One tree's public key, parsed: RFC 8554 section 5.3.
#[derive(Debug, Clone, Copy)]
struct TreeKey<'a> {
    lms_type: u32,
    lmots_type: u32,
    lms: Lms,
    lmots: Lmots,
    id: &'a [u8],
    root: &'a [u8],
}

/// Why a public key was not accepted.
enum KeyError {
    Malformed,
    UnknownTypecode,
    MixedHashes,
}

impl<'a> TreeKey<'a> {
    fn parse(key: &'a [u8]) -> core::result::Result<Self, KeyError> {
        let lms_type = u32_at(key, 0).ok_or(KeyError::Malformed)?;
        let lmots_type = u32_at(key, 4).ok_or(KeyError::Malformed)?;
        let lms = Lms::from_typecode(lms_type).ok_or(KeyError::UnknownTypecode)?;
        let lmots = Lmots::from_typecode(lmots_type).ok_or(KeyError::UnknownTypecode)?;
        if lms.hash != lmots.hash {
            return Err(KeyError::MixedHashes);
        }
        if key.len() != 8 + I_LEN + lms.hash.output_len() {
            return Err(KeyError::Malformed);
        }
        Ok(Self {
            lms_type,
            lmots_type,
            lms,
            lmots,
            id: &key[8..8 + I_LEN],
            root: &key[8 + I_LEN..],
        })
    }

    /// Length of a signature under this key.
    fn signature_len(&self) -> usize {
        4 + self.lmots.signature_len() + 4 + self.lms.hash.output_len() * self.lms.h as usize
    }

    /// RFC 8554 algorithms 6a and 4b: whether `signature` is this key's over
    /// `message`. `None` for anything wrong with the signature.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Option<()> {
        let hash = self.lms.hash;
        let n = hash.output_len();
        let (w, p) = (self.lmots.w, self.lmots.p);

        // Algorithm 6a, step 2: the leaf number, the LM-OTS signature, the
        // LMS typecode and the path. The length is checked as a whole, which
        // covers every "at least" along the way.
        if signature.len() != self.signature_len() {
            return None;
        }
        let q = u32_at(signature, 0)?;
        if u32_at(signature, 4)? != self.lmots_type {
            return None;
        }
        let ots_end = 4 + self.lmots.signature_len();
        if u32_at(signature, ots_end)? != self.lms_type {
            return None;
        }
        if q >= 1u32 << self.lms.h {
            return None;
        }
        let c = &signature[8..8 + n];
        let y = &signature[8 + n..ots_end];
        let path = &signature[ots_end + 4..];
        let q_bytes = q.to_be_bytes();

        // Algorithm 4b, step 3. Q, then Q || Cksm(Q).
        let mut q_and_checksum = [0u8; MAX_N + 2];
        hash.digest(
            &[self.id, &q_bytes, &D_MESG, c, message],
            &mut q_and_checksum[..n],
        );
        let sum = checksum(&q_and_checksum[..n], w, self.lmots.ls);
        q_and_checksum[n..n + 2].copy_from_slice(&sum.to_be_bytes());
        let digits = &q_and_checksum[..n + 2];

        // Kc = H(I || q || D_PBLC || z[0] || ... || z[p-1]), with each z fed
        // to the hash as it is finished rather than kept.
        let mut kc_hash = hash.start();
        kc_hash.update(self.id);
        kc_hash.update(&q_bytes);
        kc_hash.update(&D_PBLC);
        let last = (1u32 << w) - 1;
        let mut tmp = [0u8; MAX_N];
        for i in 0..p {
            tmp[..n].copy_from_slice(&y[i * n..(i + 1) * n]);
            let i_bytes = (i as u16).to_be_bytes();
            for j in coef(digits, i, w)..last {
                let mut next = [0u8; MAX_N];
                hash.digest(
                    &[self.id, &q_bytes, &i_bytes, &[j as u8], &tmp[..n]],
                    &mut next[..n],
                );
                tmp = next;
            }
            kc_hash.update(&tmp[..n]);
        }
        let mut kc = [0u8; MAX_N];
        kc_hash.finish(&mut kc[..n]);

        // Algorithm 6a, step 4: up the tree from the leaf.
        let mut node = (1u32 << self.lms.h) + q;
        hash.digest(
            &[self.id, &node.to_be_bytes(), &D_LEAF, &kc[..n]],
            &mut tmp[..n],
        );
        for sibling in path.chunks_exact(n) {
            let parent = (node / 2).to_be_bytes();
            let mut next = [0u8; MAX_N];
            if node & 1 == 1 {
                hash.digest(
                    &[self.id, &parent, &D_INTR, sibling, &tmp[..n]],
                    &mut next[..n],
                );
            } else {
                hash.digest(
                    &[self.id, &parent, &D_INTR, &tmp[..n], sibling],
                    &mut next[..n],
                );
            }
            tmp = next;
            node /= 2;
        }
        // Neither side is secret; the comparison is constant-time because
        // there is no reason for it not to be.
        ic_core::ct::verify(&tmp[..n], self.root).then_some(())
    }
}

fn key_error(e: KeyError) -> ic_core::Error {
    match e {
        KeyError::Malformed => err!(MalformedEncoding, "lms public key is malformed"),
        KeyError::UnknownTypecode => err!(Unsupported, "lms public key has an unknown typecode"),
        KeyError::MixedHashes => err!(
            Unsupported,
            "lms public key pairs parameter sets of different hashes"
        ),
    }
}

fn rejected() -> ic_core::Error {
    err!(AuthenticationFailed, "signature did not verify")
}

/// What a public key says about itself, for a caller that has a policy on
/// parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    /// Levels in the HSS hierarchy; 1 for a bare LMS key.
    pub levels: u32,
    /// The top tree's LMS typecode.
    pub lms_typecode: u32,
    /// The top tree's LM-OTS typecode.
    pub lmots_typecode: u32,
    /// The top tree's hash function.
    pub hash: Hash,
    /// The top tree's height: it has `2^height` one-time keys.
    pub height: u32,
    /// The top tree's Winternitz width in bits.
    pub width: u32,
}

/// Read the parameters from an HSS public key without verifying anything.
///
/// Only the top tree's are in a public key; lower levels declare theirs in
/// each signature.
pub fn parameters(public_key: &[u8]) -> Result<Parameters> {
    let (levels, key) = split_hss_key(public_key)?;
    Ok(Parameters {
        levels,
        lms_typecode: key.lms_type,
        lmots_typecode: key.lmots_type,
        hash: key.lms.hash,
        height: key.lms.h,
        width: key.lmots.w,
    })
}

/// An HSS public key's level count and top tree key.
fn split_hss_key(public_key: &[u8]) -> Result<(u32, TreeKey<'_>)> {
    let levels = u32_at(public_key, 0)
        .ok_or_else(|| err!(MalformedEncoding, "hss public key is malformed"))?;
    ensure!(
        (1..=MAX_LEVELS as u32).contains(&levels),
        MalformedEncoding,
        "hss public key must have 1 to 8 levels"
    );
    let key = TreeKey::parse(&public_key[4..]).map_err(key_error)?;
    Ok((levels, key))
}

/// Verify an HSS signature: RFC 8554 section 6.3.
///
/// `public_key` is `u32(L) || lms_public_key`, and `signature` is
/// `u32(L - 1)`, then for each level above the last an LMS signature over the
/// next level's public key followed by that key, then the LMS signature over
/// `message`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    ic_core::module::operational()?;
    let (levels, mut key) = split_hss_key(public_key)?;
    let signed_keys = u32_at(signature, 0).ok_or_else(rejected)?;
    ensure!(
        signed_keys.checked_add(1) == Some(levels),
        AuthenticationFailed,
        "signature did not verify"
    );
    let mut rest = &signature[4..];
    for _ in 0..signed_keys {
        // This level's signature has the length its key dictates; what
        // follows is the next level's public key, whose own typecode says how
        // long it is. Both are the signer's bytes, so every failure is one.
        let sig_len = key.signature_len();
        let sig = rest.get(..sig_len).ok_or_else(rejected)?;
        rest = &rest[sig_len..];
        let next_type = u32_at(rest, 0).ok_or_else(rejected)?;
        let next_lms = Lms::from_typecode(next_type).ok_or_else(rejected)?;
        let next_len = 8 + I_LEN + next_lms.hash.output_len();
        let next_bytes = rest.get(..next_len).ok_or_else(rejected)?;
        rest = &rest[next_len..];
        let next = TreeKey::parse(next_bytes).map_err(|_| rejected())?;
        key.verify(next_bytes, sig).ok_or_else(rejected)?;
        key = next;
    }
    key.verify(message, rest).ok_or_else(rejected)
}

/// Verify a bare LMS signature under a bare LMS public key: RFC 8554
/// algorithm 6, without the HSS framing.
pub fn verify_lms(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    ic_core::module::operational()?;
    let key = TreeKey::parse(public_key).map_err(key_error)?;
    key.verify(message, signature).ok_or_else(rejected)
}

/// RFC 9858 appendix A.1: LMS_SHA256_M24_H5 with LMOTS_SHA256_N24_W8, one of
/// SP 800-208's SHA-256/192 parameter sets.
const SELF_TEST_KEY: &str = "000000010000000a00000008202122232425262728292a2b2c2d2e2f2c571450aed99cfb4f4ac285da14882796618314508b12d2";
const SELF_TEST_MESSAGE: &str = "54657374206d65737361676520666f72205348413235362d3139320a";
const SELF_TEST_SIGNATURE: &str = "\
              0000000000000005000000080b5040a18c1b5cabcbc85b047402ec6294a30dd8da8fc3dae13b9f08\
              75f09361dc77fcc4481ea463c073716249719193614b835b4694c059f12d3aedd34f3db93f3580fb\
              88743b8b3d0648c0537b7a50e433d7ea9d6672fffc5f42770feab4f98eb3f3b23fd2061e4d0b38f8\
              32860ae76673ad1a1a52a9005dcf1bfb56fe16ff723627612f9a48f790f3c47a67f870b81e919d99\
              919c8db48168838cece0abfb683da48b9209868be8ec10c63d8bf80d36498dfc205dc45d0dd87057\
              2d6d8f1d90177cf5137b8bbf7bcb67a46f86f26cfa5a44cbcaa4e18da099a98b0b3f96d5ac8ac375\
              d8da2a7c248004ba11d7ac775b9218359cddab4cf8ccc6d54cb7e1b35a36ddc9265c087063d2fc67\
              42a7177876476a324b03295bfed99f2eaf1f38970583c1b2b616aad0f31cd7a4b1bb0a51e477e94a\
              01bbb4d6f8866e2528a159df3d6ce244d2b6518d1f0212285a3c2d4a927054a1e1620b5b02aab0c8\
              c10ed48ae518ea73cba81fcfff88bff461dac51e7ab4ca75f47a6259d24820b9995792d139f61ae2\
              a8186ae4e3c9bfe0af2cc717f424f41aa67f03faedb0665115f2067a46843a4cbbd297d5e83bc1aa\
              fc18d1d03b3d894e8595a6526073f02ab0f08b99fd9eb208b59ff6317e5545e6f9ad5f9c183abd04\
              3d5acd6eb2dd4da3f02dbc3167b468720a4b8b92ddfe7960998bb7a0ecf2a26a37598299413f7b2a\
              ecd39a30cec527b4d9710c4473639022451f50d01c0457125da0fa4429c07dad859c846cbbd93ab5\
              b91b01bc770b089cfede6f651e86dd7c15989c8b5321dea9ca608c71fd862323072b827cee7a7e28\
              e4e2b999647233c3456944bb7aef9187c96b3f5b79fb98bc76c3574dd06f0e95685e5b3aef3a54c4\
              155fe3ad817749629c30adbe897c4f4454c86c490000000ae9ca10eaa811b22ae07fb195e3590a33\
              4ea64209942fbae338d19f152182c807d3c40b189d3fcbea942f44682439b191332d33ae0b761a2a\
              8f984b56b2ac2fd4ab08223a69ed1f7719c7aa7e9eee96504b0e60c6bb5c942d695f0493eb25f80a\
              5871cffd131d0e04ffe5065bc7875e82d34b40b69dd9f3c1";

fn self_test_case() -> Result<([u8; 52], [u8; 28], [u8; 784])> {
    let mut key = [0u8; 52];
    let mut message = [0u8; 28];
    let mut signature = [0u8; 784];
    ic_core::codec::hex_decode(SELF_TEST_KEY.as_bytes(), &mut key)?;
    ic_core::codec::hex_decode(SELF_TEST_MESSAGE.as_bytes(), &mut message)?;
    ic_core::codec::hex_decode(SELF_TEST_SIGNATURE.as_bytes(), &mut signature)?;
    Ok((key, message, signature))
}

/// A public key, message and signature that verify, for the documentation
/// example: RFC 9858 appendix A.1.
#[doc(hidden)]
pub fn example() -> ([u8; 52], [u8; 28], [u8; 784]) {
    self_test_case().expect("the embedded test case is well-formed hex")
}

impl SelfTest for HssLms {
    /// RFC 9858 appendix A.1 verifies, and does not with one bit of the
    /// message changed.
    fn self_test() -> Result<()> {
        let (key, mut message, signature) = self_test_case()?;
        ensure!(
            verify(&key, &message, &signature).is_ok(),
            SelfTestFailed,
            "hss-lms: RFC 9858 A.1 did not verify"
        );
        message[0] ^= 1;
        ensure!(
            verify(&key, &message, &signature).is_err(),
            SelfTestFailed,
            "hss-lms: a changed message verified"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::ErrorKind;

    #[test]
    fn self_test_passes() {
        HssLms::self_test().unwrap();
    }

    /// The parameter tables, against RFC 8554 table 1 and RFC 9858 table 1:
    /// name, n, w, p, ls and the signature length `4 + n * (p + 1)`.
    #[test]
    fn lmots_parameters_are_the_rfcs_tables() {
        let table: [(u32, Hash, u32, usize, u32, usize); 16] = [
            (0x01, Hash::Sha256, 1, 265, 7, 8516),
            (0x02, Hash::Sha256, 2, 133, 6, 4292),
            (0x03, Hash::Sha256, 4, 67, 4, 2180),
            (0x04, Hash::Sha256, 8, 34, 0, 1124),
            (0x05, Hash::Sha256_192, 1, 200, 8, 4828),
            (0x06, Hash::Sha256_192, 2, 101, 6, 2452),
            (0x07, Hash::Sha256_192, 4, 51, 4, 1252),
            (0x08, Hash::Sha256_192, 8, 26, 0, 652),
            (0x09, Hash::Shake256_256, 1, 265, 7, 8516),
            (0x0a, Hash::Shake256_256, 2, 133, 6, 4292),
            (0x0b, Hash::Shake256_256, 4, 67, 4, 2180),
            (0x0c, Hash::Shake256_256, 8, 34, 0, 1124),
            (0x0d, Hash::Shake256_192, 1, 200, 8, 4828),
            (0x0e, Hash::Shake256_192, 2, 101, 6, 2452),
            (0x0f, Hash::Shake256_192, 4, 51, 4, 1252),
            (0x10, Hash::Shake256_192, 8, 26, 0, 652),
        ];
        for (code, hash, w, p, ls, sig_len) in table {
            let got = Lmots::from_typecode(code).unwrap();
            assert_eq!(got, Lmots { hash, w, p, ls }, "typecode {code:#x}");
            assert_eq!(got.signature_len(), sig_len, "typecode {code:#x}");
        }
        assert!(Lmots::from_typecode(0).is_none());
        assert!(Lmots::from_typecode(0x11).is_none());
    }

    #[test]
    fn lms_parameters_are_the_rfcs_tables() {
        let hashes = [
            (0x05, Hash::Sha256),
            (0x0a, Hash::Sha256_192),
            (0x0f, Hash::Shake256_256),
            (0x14, Hash::Shake256_192),
        ];
        for (base, hash) in hashes {
            for (i, h) in [5u32, 10, 15, 20, 25].into_iter().enumerate() {
                assert_eq!(
                    Lms::from_typecode(base + i as u32),
                    Some(Lms { hash, h }),
                    "typecode {:#x}",
                    base + i as u32
                );
            }
        }
        assert!(Lms::from_typecode(0x04).is_none());
        assert!(Lms::from_typecode(0x19).is_none());
    }

    /// RFC 8554 appendix B computes p and ls from n and w. The tables above
    /// were typed from the RFCs; this derives them again.
    #[test]
    fn p_and_ls_follow_from_n_and_w() {
        for code in 0x01..=0x10u32 {
            let set = Lmots::from_typecode(code).unwrap();
            let (n, w) = (set.hash.output_len() as u32, set.w);
            let u = (8 * n).div_ceil(w);
            let max_sum = ((1u32 << w) - 1) * u;
            let sum_bits = 32 - max_sum.leading_zeros();
            let v = sum_bits.div_ceil(w);
            assert_eq!(set.p as u32, u + v, "p for typecode {code:#x}");
            assert_eq!(set.ls, 16 - v * w, "ls for typecode {code:#x}");
        }
    }

    /// RFC 8554 section 3.1.3's worked example of coef: for S = 0x1234,
    /// coef(S, 7, 1) is 0 and coef(S, 0, 4) is 1, and its figure shows the
    /// four-bit values as 1, 2, 3, 4. The last two lines are the same string
    /// read at the other two widths, worked by hand.
    #[test]
    fn coef_matches_the_rfcs_example() {
        let s = [0x12, 0x34];
        assert_eq!(coef(&s, 7, 1), 0);
        assert_eq!(coef(&s, 0, 4), 1);
        assert_eq!([1, 2, 3].map(|i| coef(&s, i, 4)), [2, 3, 4]);
        assert_eq!(coef(&s, 1, 8), 0x34);
        assert_eq!(coef(&s, 3, 2), 2);
    }

    #[test]
    fn a_public_key_reports_its_parameters() {
        let (key, _, _) = example();
        assert_eq!(
            parameters(&key).unwrap(),
            Parameters {
                levels: 1,
                lms_typecode: 0x0a,
                lmots_typecode: 0x08,
                hash: Hash::Sha256_192,
                height: 5,
                width: 8,
            }
        );
        assert_eq!(Hash::Sha256_192.id(), "sha256/192");
    }

    #[test]
    fn a_bad_public_key_is_refused_as_what_it_is() {
        let (key, message, signature) = example();
        let kind = |k: &[u8]| verify(k, &message, &signature).unwrap_err().kind();
        // Too short, too long, empty.
        assert_eq!(kind(&key[..51]), ErrorKind::MalformedEncoding);
        assert_eq!(kind(&[]), ErrorKind::MalformedEncoding);
        let mut long = key.to_vec();
        long.push(0);
        assert_eq!(kind(&long), ErrorKind::MalformedEncoding);
        // No levels, and more than eight.
        for levels in [0u8, 9] {
            let mut k = key;
            k[3] = levels;
            assert_eq!(kind(&k), ErrorKind::MalformedEncoding);
        }
        // A typecode nobody defines.
        let mut k = key;
        k[7] = 0x40;
        assert_eq!(kind(&k), ErrorKind::Unsupported);
        // LMS over SHA-256/192 paired with LM-OTS over SHAKE256/192: the same
        // lengths, and no table pairs them.
        let mut k = key;
        k[11] = 0x10;
        assert_eq!(kind(&k), ErrorKind::Unsupported);
        // The right key with the wrong level count is a signature failure:
        // the signature's count no longer matches.
        let mut k = key;
        k[3] = 2;
        assert_eq!(kind(&k), ErrorKind::AuthenticationFailed);
    }

    /// A leaf number past the tree is refused before it is used. No such
    /// signature could verify -- the hashes would not match -- so what this
    /// pins is that it is refused rather than computed with: `2^h + q`
    /// overflows for a large q, and overflow is a panic in this workspace's
    /// builds. Removing the range check fails this test and no other.
    #[test]
    fn a_leaf_number_past_the_tree_is_refused_not_computed() {
        let (key, message, signature) = example();
        for q in [32u32, 1 << 25, u32::MAX - 31, u32::MAX] {
            let mut bad = signature;
            bad[4..8].copy_from_slice(&q.to_be_bytes());
            assert_eq!(
                verify(&key, &message, &bad).unwrap_err().kind(),
                ErrorKind::AuthenticationFailed,
                "q = {q}"
            );
        }
    }

    #[test]
    fn verify_lms_takes_the_bare_forms() {
        let (key, message, signature) = example();
        verify_lms(&key[4..], &message, &signature[4..]).unwrap();
        assert!(verify_lms(&key, &message, &signature).is_err());
        assert!(verify_lms(&key[4..], b"other", &signature[4..]).is_err());
    }
}
