//! SLH-DSA, the stateless hash-based digital signature standard: FIPS 205.
//!
//! SLH-DSA is SPHINCS+ as NIST standardised it. Like LMS its security rests on
//! a hash function alone, so a quantum computer that breaks RSA, elliptic
//! curves or a lattice assumption does not break it. Unlike LMS it keeps no
//! state: a key can sign up to 2^64 messages with no counter to protect, which
//! is why this crate signs as well as verifies. The price is size and time --
//! signatures of 7,856 to 49,856 bytes, and signing that takes thousands to
//! millions of hash calls.
//!
//! ```
//! # fn main() -> ic_core::Result<()> {
//! use ic_slhdsa::ParameterSet;
//! let set = ParameterSet::Sha2_128f;
//! let mut rng = ic_drbg::Rng::from_os()?;
//!
//! let mut public = [0u8; 32];
//! let mut secret = ic_core::Zeroizing::new([0u8; 64]);
//! ic_slhdsa::keygen(set, &mut rng, secret.get_mut(), &mut public)?;
//!
//! let mut signature = vec![0u8; set.signature_len()];
//! ic_slhdsa::sign(set, secret.get(), b"message", b"", &mut rng, &mut signature)?;
//! ic_slhdsa::verify(set, &public, b"message", b"", &signature)?;
//! assert!(ic_slhdsa::verify(set, &public, b"other", b"", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # What is here
//!
//! All twelve parameter sets of FIPS 205 table 2, in [`ParameterSet`]: SHA-2
//! and SHAKE, at security categories 1, 3 and 5, each in a small-signature
//! (`s`) and a fast-signing (`f`) form. Key generation, signing -- hedged by
//! default, deterministic on request -- and verification, for the pure
//! interface of FIPS 205 section 10 with its context string.
//!
//! HashSLH-DSA, the pre-hash interface, is not implemented. The parameter sets
//! of SP 800-230, which trade the signature limit for size, are not either.
//!
//! # Choosing a parameter set
//!
//! The `f` sets sign tens of times faster than the `s` sets and their
//! signatures are about twice as long. Verification is fast for both, and
//! faster for `s`. A signer that signs rarely and a verifier on a small device
//! want `s`; a signer under load wants `f`.
//!
//! # Buffers, not allocation
//!
//! Nothing here allocates. Keys and signatures are written into the caller's
//! buffers, whose lengths [`ParameterSet`] gives; a buffer of the wrong length
//! is refused with `InvalidLength`. A message is hashed in the pieces it
//! arrives in, so signing a long message copies nothing.
//!
//! # Secrets and timing
//!
//! The secret is `SK.seed` and `SK.prf`. Everything derived from them is
//! derived by hashing, and what a signature reveals of those derived values
//! is decided by the message digest, which is public. So control flow here
//! depends on the message and never on the key, and no table is indexed by a
//! secret. The values derived from the seed are wiped as each is finished
//! with.
//!
//! # Verification of this crate
//!
//! NIST's ACVP vectors for FIPS 205: every key-generation case for all twelve
//! sets, signature generation for all twelve in both variants, and signature
//! verification including NIST's invalid cases. `docs/FIPS.md` says which
//! cases are bundled and which were run once from the full files.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use ic_core::traits::{Algorithm, Digest, Mac, RandomSource, SelfTest, Xof};
use ic_core::{ensure, Result, Zeroize, Zeroizing};
use ic_hash::{Sha256, Sha512, Shake256};
use ic_mac::{HmacSha256, HmacSha512};

/// The longest security parameter `n`, in bytes.
const MAX_N: usize = 32;
/// The longest message digest `m`, in bytes.
const MAX_M: usize = 49;
/// WOTS+ uses 16-step chains throughout: `lg_w = 4`, `w = 16`.
const LG_W: u32 = 4;
const W: u32 = 16;
/// `len_2`, the number of checksum chains, for `lg_w = 4`.
const LEN2: usize = 3;
/// The most WOTS+ chains: `len = 2n + 3` at `n = 32`.
const MAX_LEN: usize = 2 * MAX_N + LEN2;
/// The most FORS trees, `k`.
const MAX_K: usize = 35;
/// The tallest tree anything here builds: a FORS tree of height `a = 14`.
const MAX_HEIGHT: usize = 14;

// Address types, FIPS 205 section 4.2.
const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// SLH-DSA, for the ontology and the self-test table.
pub struct SlhDsa;

impl Algorithm for SlhDsa {
    const ID: &'static str = "slh-dsa";
    const NAME: &'static str = "SLH-DSA (FIPS 205)";
}

/// A parameter set of FIPS 205 table 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ParameterSet {
    /// SLH-DSA-SHA2-128s: category 1, 7,856-byte signatures.
    Sha2_128s,
    /// SLH-DSA-SHAKE-128s: category 1, 7,856-byte signatures.
    Shake_128s,
    /// SLH-DSA-SHA2-128f: category 1, 17,088-byte signatures.
    Sha2_128f,
    /// SLH-DSA-SHAKE-128f: category 1, 17,088-byte signatures.
    Shake_128f,
    /// SLH-DSA-SHA2-192s: category 3, 16,224-byte signatures.
    Sha2_192s,
    /// SLH-DSA-SHAKE-192s: category 3, 16,224-byte signatures.
    Shake_192s,
    /// SLH-DSA-SHA2-192f: category 3, 35,664-byte signatures.
    Sha2_192f,
    /// SLH-DSA-SHAKE-192f: category 3, 35,664-byte signatures.
    Shake_192f,
    /// SLH-DSA-SHA2-256s: category 5, 29,792-byte signatures.
    Sha2_256s,
    /// SLH-DSA-SHAKE-256s: category 5, 29,792-byte signatures.
    Shake_256s,
    /// SLH-DSA-SHA2-256f: category 5, 49,856-byte signatures.
    Sha2_256f,
    /// SLH-DSA-SHAKE-256f: category 5, 49,856-byte signatures.
    Shake_256f,
}

/// The numbers a parameter set fixes: FIPS 205 table 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Params {
    /// Security parameter in bytes.
    n: usize,
    /// Total hypertree height.
    h: u32,
    /// Hypertree layers.
    d: u32,
    /// Height of each XMSS tree, `h / d`.
    hp: u32,
    /// Height of each FORS tree.
    a: u32,
    /// Number of FORS trees.
    k: usize,
    /// Message digest length in bytes.
    m: usize,
    /// SHAKE rather than SHA-2.
    shake: bool,
}

impl ParameterSet {
    /// Every parameter set, in the order of FIPS 205 table 2.
    pub const ALL: &'static [ParameterSet] = &[
        Self::Sha2_128s,
        Self::Shake_128s,
        Self::Sha2_128f,
        Self::Shake_128f,
        Self::Sha2_192s,
        Self::Shake_192s,
        Self::Sha2_192f,
        Self::Shake_192f,
        Self::Sha2_256s,
        Self::Shake_256s,
        Self::Sha2_256f,
        Self::Shake_256f,
    ];

    /// The parameter set's name, lower-cased: `slh-dsa-sha2-128s`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Sha2_128s => "slh-dsa-sha2-128s",
            Self::Shake_128s => "slh-dsa-shake-128s",
            Self::Sha2_128f => "slh-dsa-sha2-128f",
            Self::Shake_128f => "slh-dsa-shake-128f",
            Self::Sha2_192s => "slh-dsa-sha2-192s",
            Self::Shake_192s => "slh-dsa-shake-192s",
            Self::Sha2_192f => "slh-dsa-sha2-192f",
            Self::Shake_192f => "slh-dsa-shake-192f",
            Self::Sha2_256s => "slh-dsa-sha2-256s",
            Self::Shake_256s => "slh-dsa-shake-256s",
            Self::Sha2_256f => "slh-dsa-sha2-256f",
            Self::Shake_256f => "slh-dsa-shake-256f",
        }
    }

    /// The parameter set a name denotes, if it is one of these.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.id() == id)
    }

    const fn params(self) -> Params {
        let shake = matches!(
            self,
            Self::Shake_128s
                | Self::Shake_128f
                | Self::Shake_192s
                | Self::Shake_192f
                | Self::Shake_256s
                | Self::Shake_256f
        );
        // n, h, d, h', a, k, m: FIPS 205 table 2.
        let (n, h, d, hp, a, k, m) = match self {
            Self::Sha2_128s | Self::Shake_128s => (16, 63, 7, 9, 12, 14, 30),
            Self::Sha2_128f | Self::Shake_128f => (16, 66, 22, 3, 6, 33, 34),
            Self::Sha2_192s | Self::Shake_192s => (24, 63, 7, 9, 14, 17, 39),
            Self::Sha2_192f | Self::Shake_192f => (24, 66, 22, 3, 8, 33, 42),
            Self::Sha2_256s | Self::Shake_256s => (32, 64, 8, 8, 14, 22, 47),
            Self::Sha2_256f | Self::Shake_256f => (32, 68, 17, 4, 9, 35, 49),
        };
        Params {
            n,
            h,
            d,
            hp,
            a,
            k,
            m,
            shake,
        }
    }

    /// The security parameter `n` in bytes: 16, 24 or 32.
    pub const fn n(self) -> usize {
        self.params().n
    }

    /// NIST's security category: 1, 3 or 5.
    pub const fn category(self) -> u8 {
        match self.params().n {
            16 => 1,
            24 => 3,
            _ => 5,
        }
    }

    /// Length of a public key, `2n`.
    pub const fn public_key_len(self) -> usize {
        2 * self.params().n
    }

    /// Length of a private key, `4n`.
    pub const fn secret_key_len(self) -> usize {
        4 * self.params().n
    }

    /// Length of a signature: `(1 + k(1 + a) + h + d * len) * n`.
    pub const fn signature_len(self) -> usize {
        let p = self.params();
        (1 + p.k * (1 + p.a as usize) + p.h as usize + p.d as usize * p.len()) * p.n
    }
}

impl Params {
    /// The number of WOTS+ chains, `len = 2n + 3`.
    const fn len(&self) -> usize {
        2 * self.n + LEN2
    }

    /// Length of a FORS signature: `k` secret values, each with its path.
    const fn fors_len(&self) -> usize {
        self.k * (1 + self.a as usize) * self.n
    }

    /// Length of one XMSS signature: a WOTS+ signature and its path.
    const fn xmss_len(&self) -> usize {
        (self.len() + self.hp as usize) * self.n
    }
}

/// A hash address, FIPS 205 section 4.2: 32 bytes naming where in the
/// structure a hash call is made.
#[derive(Clone, Copy)]
struct Adrs([u8; 32]);

impl Adrs {
    const fn new() -> Self {
        Self([0u8; 32])
    }

    fn set_layer(&mut self, layer: u32) {
        self.0[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// The tree address is twelve bytes; no tree index here exceeds 64 bits.
    fn set_tree(&mut self, tree: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    fn set_type_and_clear(&mut self, kind: u32) {
        self.0[16..20].copy_from_slice(&kind.to_be_bytes());
        self.0[20..32].fill(0);
    }

    fn set_key_pair(&mut self, index: u32) {
        self.0[20..24].copy_from_slice(&index.to_be_bytes());
    }

    fn key_pair(&self) -> u32 {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
    }

    /// The chain address and the tree height share a word.
    fn set_chain(&mut self, index: u32) {
        self.0[24..28].copy_from_slice(&index.to_be_bytes());
    }

    fn set_tree_height(&mut self, height: u32) {
        self.set_chain(height);
    }

    /// The hash address and the tree index share a word.
    fn set_hash(&mut self, index: u32) {
        self.0[28..32].copy_from_slice(&index.to_be_bytes());
    }

    fn set_tree_index(&mut self, index: u32) {
        self.set_hash(index);
    }

    /// The compressed form the SHA-2 functions hash, FIPS 205 section 11.2:
    /// `ADRS[3] || ADRS[8..16] || ADRS[19] || ADRS[20..32]`.
    fn compressed(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        c[0] = self.0[3];
        c[1..9].copy_from_slice(&self.0[8..16]);
        c[9] = self.0[19];
        c[10..22].copy_from_slice(&self.0[20..32]);
        c
    }
}

/// A tweakable hash in progress: `PK.seed` and the address absorbed, the
/// message to follow.
// The variants differ in size, and the remedy clippy suggests is a `Box`,
// which this crate does not have: it never allocates. The value lives on the
// stack for one hash call.
#[allow(clippy::large_enum_variant)]
enum Tweaked {
    Shake(Shake256),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Tweaked {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Shake(h) => Xof::update(h, data),
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    /// Finish into `out`, which is `n` bytes: the hash truncated.
    fn finish(self, out: &mut [u8]) {
        match self {
            Self::Shake(h) => h.finalize_xof(out),
            Self::Sha256(h) => out.copy_from_slice(&h.finalize().as_ref()[..out.len()]),
            Self::Sha512(h) => out.copy_from_slice(&h.finalize().as_ref()[..out.len()]),
        }
    }
}

/// A parameter set bound to a key's public seed: the hash functions of FIPS
/// 205 section 11.
struct Ctx<'a> {
    p: Params,
    pk_seed: &'a [u8],
    /// SHA-256 having absorbed `PK.seed || toByte(0, 64 - n)`: one block,
    /// shared by every F, PRF and (at n = 16) H and T call.
    sha256_seeded: Sha256,
    /// SHA-512 having absorbed `PK.seed || toByte(0, 128 - n)`.
    sha512_seeded: Sha512,
}

impl<'a> Ctx<'a> {
    fn new(p: Params, pk_seed: &'a [u8]) -> Self {
        let zeros = [0u8; 128];
        let mut sha256_seeded = Sha256::new();
        let mut sha512_seeded = Sha512::new();
        if !p.shake {
            sha256_seeded.update(pk_seed);
            sha256_seeded.update(&zeros[..64 - p.n]);
            sha512_seeded.update(pk_seed);
            sha512_seeded.update(&zeros[..128 - p.n]);
        }
        Self {
            p,
            pk_seed,
            sha256_seeded,
            sha512_seeded,
        }
    }

    /// Begin a tweakable hash at `adrs`. `wide` selects H and T_l, which use
    /// SHA-512 in the SHA-2 sets above category 1; F and PRF always use
    /// SHA-256.
    fn tweak(&self, adrs: &Adrs, wide: bool) -> Tweaked {
        if self.p.shake {
            let mut h = Shake256::default();
            Xof::update(&mut h, self.pk_seed);
            Xof::update(&mut h, &adrs.0);
            Tweaked::Shake(h)
        } else if wide && self.p.n > 16 {
            let mut h = self.sha512_seeded.clone();
            h.update(&adrs.compressed());
            Tweaked::Sha512(h)
        } else {
            let mut h = self.sha256_seeded.clone();
            h.update(&adrs.compressed());
            Tweaked::Sha256(h)
        }
    }

    /// `F(PK.seed, ADRS, M1)`.
    fn f(&self, adrs: &Adrs, m1: &[u8], out: &mut [u8]) {
        let mut h = self.tweak(adrs, false);
        h.update(m1);
        h.finish(out);
    }

    /// `H(PK.seed, ADRS, left || right)`.
    fn h(&self, adrs: &Adrs, left: &[u8], right: &[u8], out: &mut [u8]) {
        let mut h = self.tweak(adrs, true);
        h.update(left);
        h.update(right);
        h.finish(out);
    }

    /// `PRF(PK.seed, SK.seed, ADRS)`.
    fn prf(&self, sk_seed: &[u8], adrs: &Adrs, out: &mut [u8]) {
        self.f(adrs, sk_seed, out);
    }

    /// `PRF_msg(SK.prf, opt_rand, M)`, the message randomizer `R`.
    fn prf_msg(
        &self,
        sk_prf: &[u8],
        opt_rand: &[u8],
        message: &[&[u8]],
        out: &mut [u8],
    ) -> Result<()> {
        let n = self.p.n;
        if self.p.shake {
            let mut h = Shake256::default();
            Xof::update(&mut h, sk_prf);
            Xof::update(&mut h, opt_rand);
            for part in message {
                Xof::update(&mut h, part);
            }
            h.finalize_xof(&mut out[..n]);
        } else if n == 16 {
            let mut mac = HmacSha256::new(sk_prf)?;
            mac.update(opt_rand);
            for part in message {
                mac.update(part);
            }
            out[..n].copy_from_slice(&mac.finalize().as_ref()[..n]);
        } else {
            let mut mac = HmacSha512::new(sk_prf)?;
            mac.update(opt_rand);
            for part in message {
                mac.update(part);
            }
            out[..n].copy_from_slice(&mac.finalize().as_ref()[..n]);
        }
        Ok(())
    }

    /// `H_msg(R, PK.seed, PK.root, M)`, the `m`-byte message digest.
    fn h_msg(&self, r: &[u8], pk_root: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let m = self.p.m;
        if self.p.shake {
            let mut h = Shake256::default();
            Xof::update(&mut h, r);
            Xof::update(&mut h, self.pk_seed);
            Xof::update(&mut h, pk_root);
            for part in message {
                Xof::update(&mut h, part);
            }
            h.finalize_xof(&mut out[..m]);
            return;
        }
        // MGF1(R || PK.seed || Hash(R || PK.seed || PK.root || M), m), with
        // SHA-256 at category 1 and SHA-512 above it.
        macro_rules! mgf1 {
            ($hash:ty, $len:expr) => {{
                let mut inner = <$hash>::new();
                inner.update(r);
                inner.update(self.pk_seed);
                inner.update(pk_root);
                for part in message {
                    inner.update(part);
                }
                let digest = inner.finalize();
                for (counter, chunk) in out[..m].chunks_mut($len).enumerate() {
                    let mut block = <$hash>::new();
                    block.update(r);
                    block.update(self.pk_seed);
                    block.update(digest.as_ref());
                    block.update(&(counter as u32).to_be_bytes());
                    chunk.copy_from_slice(&block.finalize().as_ref()[..chunk.len()]);
                }
            }};
        }
        if self.p.n == 16 {
            mgf1!(Sha256, 32)
        } else {
            mgf1!(Sha512, 64)
        }
    }

    /// `chain(X, i, s, PK.seed, ADRS)`, FIPS 205 algorithm 5, in place.
    fn chain(&self, x: &mut [u8], start: u32, steps: u32, adrs: &mut Adrs) {
        let n = self.p.n;
        for j in start..start + steps {
            adrs.set_hash(j);
            let mut next = [0u8; MAX_N];
            self.f(adrs, &x[..n], &mut next[..n]);
            x[..n].copy_from_slice(&next[..n]);
        }
    }

    /// The base-16 digits a WOTS+ key signs: the message, then its checksum.
    /// FIPS 205 algorithm 7, lines 1 to 7.
    fn wots_digits(&self, message: &[u8], digits: &mut [u32; MAX_LEN]) {
        let len1 = 2 * self.p.n;
        base_2b(message, LG_W, &mut digits[..len1]);
        let mut csum: u32 = 0;
        for d in &digits[..len1] {
            csum += W - 1 - d;
        }
        // len_2 * lg_w is 12 bits, so the checksum is shifted to the top of
        // two bytes.
        csum <<= 4;
        base_2b(
            &(csum as u16).to_be_bytes(),
            LG_W,
            &mut digits[len1..len1 + LEN2],
        );
    }

    /// `wots_pkGen`, FIPS 205 algorithm 6. `adrs` is a WOTS_HASH address
    /// naming the key pair.
    fn wots_pk_gen(&self, sk_seed: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(WOTS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        let mut compress = self.tweak(&pk_adrs, true);
        let mut value = Zeroizing::new([0u8; MAX_N]);
        for i in 0..self.p.len() as u32 {
            sk_adrs.set_chain(i);
            self.prf(sk_seed, &sk_adrs, &mut value.get_mut()[..n]);
            adrs.set_chain(i);
            self.chain(value.get_mut(), 0, W - 1, adrs);
            compress.update(&value.get()[..n]);
        }
        compress.finish(&mut out[..n]);
    }

    /// `wots_sign`, FIPS 205 algorithm 7, writing `len * n` bytes.
    fn wots_sign(&self, message: &[u8], sk_seed: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;
        let mut digits = [0u32; MAX_LEN];
        self.wots_digits(message, &mut digits);
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(WOTS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        for (i, chunk) in out[..self.p.len() * n].chunks_exact_mut(n).enumerate() {
            sk_adrs.set_chain(i as u32);
            self.prf(sk_seed, &sk_adrs, chunk);
            adrs.set_chain(i as u32);
            self.chain(chunk, 0, digits[i], adrs);
        }
    }

    /// `wots_pkFromSig`, FIPS 205 algorithm 8.
    fn wots_pk_from_sig(&self, sig: &[u8], message: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;
        let mut digits = [0u32; MAX_LEN];
        self.wots_digits(message, &mut digits);
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        let mut compress = self.tweak(&pk_adrs, true);
        for (i, chunk) in sig[..self.p.len() * n].chunks_exact(n).enumerate() {
            let mut value = [0u8; MAX_N];
            value[..n].copy_from_slice(chunk);
            adrs.set_chain(i as u32);
            self.chain(&mut value, digits[i], W - 1 - digits[i], adrs);
            compress.update(&value[..n]);
        }
        compress.finish(&mut out[..n]);
    }

    /// The node at index `i` and height `z` of a Merkle tree whose leaves
    /// `leaf` computes: `xmss_node` and `fors_node`, FIPS 205 algorithms 9 and
    /// 15, without the recursion.
    ///
    /// Leaves are visited left to right, and two nodes of equal height are
    /// merged as soon as both exist, so at most `z + 1` nodes are held.
    /// `internal` prepares `adrs` for an interior hash; the height and index
    /// are set here.
    fn tree_node(
        &self,
        i: u32,
        z: u32,
        adrs: &mut Adrs,
        mut leaf: impl FnMut(&Self, u32, &mut Adrs, &mut [u8]),
        internal: impl Fn(&mut Adrs),
        out: &mut [u8],
    ) {
        let n = self.p.n;
        // One flat buffer of `MAX_HEIGHT + 1` node slots, so that it can be
        // wiped: FORS nodes are a hash away from secret values.
        let mut stack = Zeroizing::new([0u8; MAX_N * (MAX_HEIGHT + 1)]);
        let mut heights = [0u32; MAX_HEIGHT + 1];
        let mut held = 0usize;
        for j in 0..1u32 << z {
            let mut index = (i << z) + j;
            let mut height = 0u32;
            let mut node = [0u8; MAX_N];
            leaf(self, index, adrs, &mut node[..n]);
            while held > 0 && heights[held - 1] == height {
                index >>= 1;
                height += 1;
                internal(adrs);
                adrs.set_tree_height(height);
                adrs.set_tree_index(index);
                let mut parent = [0u8; MAX_N];
                let left = &stack.get()[(held - 1) * MAX_N..(held - 1) * MAX_N + n];
                self.h(adrs, left, &node[..n], &mut parent[..n]);
                node = parent;
                held -= 1;
            }
            stack.get_mut()[held * MAX_N..held * MAX_N + n].copy_from_slice(&node[..n]);
            heights[held] = height;
            held += 1;
            node.zeroize();
        }
        out[..n].copy_from_slice(&stack.get()[..n]);
    }

    /// `xmss_node`, FIPS 205 algorithm 9.
    fn xmss_node(&self, sk_seed: &[u8], i: u32, z: u32, adrs: &mut Adrs, out: &mut [u8]) {
        self.tree_node(
            i,
            z,
            adrs,
            |ctx, index, adrs, node| {
                adrs.set_type_and_clear(WOTS_HASH);
                adrs.set_key_pair(index);
                ctx.wots_pk_gen(sk_seed, adrs, node);
            },
            |adrs| adrs.set_type_and_clear(TREE),
            out,
        );
    }

    /// `xmss_sign`, FIPS 205 algorithm 10, writing a WOTS+ signature and then
    /// its authentication path.
    fn xmss_sign(&self, message: &[u8], sk_seed: &[u8], idx: u32, adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;
        let wots_len = self.p.len() * n;
        let (sig, auth) = out[..self.p.xmss_len()].split_at_mut(wots_len);
        for (j, node) in auth.chunks_exact_mut(n).enumerate() {
            let sibling = (idx >> j) ^ 1;
            self.xmss_node(sk_seed, sibling, j as u32, adrs, node);
        }
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair(idx);
        self.wots_sign(message, sk_seed, adrs, sig);
    }

    /// `xmss_pkFromSig`, FIPS 205 algorithm 11.
    fn xmss_pk_from_sig(
        &self,
        idx: u32,
        sig: &[u8],
        message: &[u8],
        adrs: &mut Adrs,
        out: &mut [u8],
    ) {
        let n = self.p.n;
        let wots_len = self.p.len() * n;
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair(idx);
        let mut node = [0u8; MAX_N];
        self.wots_pk_from_sig(&sig[..wots_len], message, adrs, &mut node);
        adrs.set_type_and_clear(TREE);
        let auth = &sig[wots_len..self.p.xmss_len()];
        self.climb(idx, idx, auth, adrs, &mut node);
        out[..n].copy_from_slice(&node[..n]);
    }

    /// From a node up its authentication path: FIPS 205 algorithm 11, lines 8
    /// to 18, and algorithm 17, lines 8 to 18, which are the same walk.
    ///
    /// `position` says, bit by bit, whether the node is a left or right child
    /// at each height; `index` is the node's tree index, which the address
    /// carries.
    fn climb(
        &self,
        position: u32,
        mut index: u32,
        auth: &[u8],
        adrs: &mut Adrs,
        node: &mut [u8; MAX_N],
    ) {
        let n = self.p.n;
        for (height, sibling) in auth.chunks_exact(n).enumerate() {
            adrs.set_tree_height(height as u32 + 1);
            index >>= 1;
            adrs.set_tree_index(index);
            let mut parent = [0u8; MAX_N];
            if (position >> height) & 1 == 0 {
                self.h(adrs, &node[..n], sibling, &mut parent[..n]);
            } else {
                self.h(adrs, sibling, &node[..n], &mut parent[..n]);
            }
            *node = parent;
        }
    }

    /// `ht_sign`, FIPS 205 algorithm 12.
    fn ht_sign(
        &self,
        message: &[u8],
        sk_seed: &[u8],
        mut idx_tree: u64,
        mut idx_leaf: u32,
        out: &mut [u8],
    ) {
        let n = self.p.n;
        let xmss_len = self.p.xmss_len();
        let mut root = [0u8; MAX_N];
        root[..n].copy_from_slice(&message[..n]);
        for (layer, sig) in out[..self.p.d as usize * xmss_len]
            .chunks_exact_mut(xmss_len)
            .enumerate()
        {
            if layer > 0 {
                idx_leaf = (idx_tree & ((1 << self.p.hp) - 1)) as u32;
                idx_tree >>= self.p.hp;
            }
            let mut adrs = Adrs::new();
            adrs.set_layer(layer as u32);
            adrs.set_tree(idx_tree);
            let signed = root;
            self.xmss_sign(&signed[..n], sk_seed, idx_leaf, &mut adrs, sig);
            if layer + 1 < self.p.d as usize {
                self.xmss_pk_from_sig(idx_leaf, sig, &signed[..n], &mut adrs, &mut root);
            }
        }
    }

    /// `ht_verify`, FIPS 205 algorithm 13: the root the signature leads to.
    fn ht_root(
        &self,
        message: &[u8],
        sig: &[u8],
        mut idx_tree: u64,
        mut idx_leaf: u32,
        out: &mut [u8],
    ) {
        let n = self.p.n;
        let mut node = [0u8; MAX_N];
        node[..n].copy_from_slice(&message[..n]);
        for (layer, xmss) in sig.chunks_exact(self.p.xmss_len()).enumerate() {
            if layer > 0 {
                idx_leaf = (idx_tree & ((1 << self.p.hp) - 1)) as u32;
                idx_tree >>= self.p.hp;
            }
            let mut adrs = Adrs::new();
            adrs.set_layer(layer as u32);
            adrs.set_tree(idx_tree);
            let signed = node;
            self.xmss_pk_from_sig(idx_leaf, xmss, &signed[..n], &mut adrs, &mut node);
        }
        out[..n].copy_from_slice(&node[..n]);
    }

    /// `fors_skGen`, FIPS 205 algorithm 14.
    fn fors_sk(&self, sk_seed: &[u8], adrs: &Adrs, idx: u32, out: &mut [u8]) {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_key_pair(adrs.key_pair());
        sk_adrs.set_tree_index(idx);
        self.prf(sk_seed, &sk_adrs, out);
    }

    /// `fors_node`, FIPS 205 algorithm 15.
    fn fors_node(&self, sk_seed: &[u8], i: u32, z: u32, adrs: &mut Adrs, out: &mut [u8]) {
        self.tree_node(
            i,
            z,
            adrs,
            |ctx, index, adrs, node| {
                let n = ctx.p.n;
                let mut sk = Zeroizing::new([0u8; MAX_N]);
                ctx.fors_sk(sk_seed, adrs, index, &mut sk.get_mut()[..n]);
                adrs.set_tree_height(0);
                adrs.set_tree_index(index);
                ctx.f(adrs, &sk.get()[..n], node);
            },
            |_| {},
            out,
        );
    }

    /// The `k` indices a message digest selects, one leaf in each FORS tree.
    fn fors_indices(&self, md: &[u8], indices: &mut [u32; MAX_K]) {
        base_2b(md, self.p.a, &mut indices[..self.p.k]);
    }

    /// `fors_sign`, FIPS 205 algorithm 16.
    fn fors_sign(&self, md: &[u8], sk_seed: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;
        let a = self.p.a;
        let mut indices = [0u32; MAX_K];
        self.fors_indices(md, &mut indices);
        let per_tree = (1 + a as usize) * n;
        for (i, tree) in out[..self.p.fors_len()]
            .chunks_exact_mut(per_tree)
            .enumerate()
        {
            let (sk, auth) = tree.split_at_mut(n);
            let base = (i as u32) << a;
            self.fors_sk(sk_seed, adrs, base + indices[i], sk);
            for (j, node) in auth.chunks_exact_mut(n).enumerate() {
                let sibling = (indices[i] >> j) ^ 1;
                self.fors_node(
                    sk_seed,
                    ((i as u32) << (a - j as u32)) + sibling,
                    j as u32,
                    adrs,
                    node,
                );
            }
        }
    }

    /// `fors_pkFromSig`, FIPS 205 algorithm 17.
    fn fors_pk_from_sig(&self, sig: &[u8], md: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;
        let a = self.p.a;
        let mut indices = [0u32; MAX_K];
        self.fors_indices(md, &mut indices);
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(FORS_ROOTS);
        pk_adrs.set_key_pair(adrs.key_pair());
        let mut compress = self.tweak(&pk_adrs, true);
        let per_tree = (1 + a as usize) * n;
        for (i, tree) in sig[..self.p.fors_len()].chunks_exact(per_tree).enumerate() {
            let (sk, auth) = tree.split_at(n);
            let index = ((i as u32) << a) + indices[i];
            adrs.set_tree_height(0);
            adrs.set_tree_index(index);
            let mut node = [0u8; MAX_N];
            self.f(adrs, sk, &mut node[..n]);
            self.climb(indices[i], index, auth, adrs, &mut node);
            compress.update(&node[..n]);
        }
        compress.finish(&mut out[..n]);
    }

    /// Split a message digest into the FORS message and the hypertree
    /// indices: FIPS 205 algorithm 19, lines 6 to 10.
    fn split_digest<'d>(&self, digest: &'d [u8]) -> (&'d [u8], u64, u32) {
        let p = &self.p;
        let md_len = (p.k * p.a as usize).div_ceil(8);
        let tree_bits = p.h - p.hp;
        let tree_len = (tree_bits as usize).div_ceil(8);
        let leaf_len = (p.hp as usize).div_ceil(8);
        let (md, rest) = digest.split_at(md_len);
        let mut idx_tree = 0u64;
        for b in &rest[..tree_len] {
            idx_tree = (idx_tree << 8) | u64::from(*b);
        }
        // h - h' is 54 to 64 bits. At 64, in the 256f sets, every bit counts
        // and there is nothing to mask -- and no `1 << 64` to compute.
        if tree_bits < 64 {
            idx_tree &= (1u64 << tree_bits) - 1;
        }
        let mut idx_leaf = 0u32;
        for b in &rest[tree_len..tree_len + leaf_len] {
            idx_leaf = (idx_leaf << 8) | u32::from(*b);
        }
        idx_leaf &= (1u32 << p.hp) - 1;
        (md, idx_tree, idx_leaf)
    }
}

/// `base_2b`, FIPS 205 algorithm 4: the first `out.len() * b` bits of `x` as
/// `b`-bit integers, most significant first.
fn base_2b(x: &[u8], b: u32, out: &mut [u32]) {
    let mut input = 0usize;
    let mut bits = 0u32;
    let mut total = 0u32;
    for digit in out.iter_mut() {
        while bits < b {
            total = (total << 8) | u32::from(x[input]);
            input += 1;
            bits += 8;
        }
        bits -= b;
        *digit = (total >> bits) & ((1 << b) - 1);
        // Keep only the bits not yet consumed, so `total` never overflows.
        total &= (1 << bits) - 1;
    }
}

fn check_len(got: usize, want: usize, what: &'static str) -> Result<()> {
    if got == want {
        Ok(())
    } else {
        Err(ic_core::Error::new(ic_core::ErrorKind::InvalidLength, what))
    }
}

/// `slh_keygen_internal`, FIPS 205 algorithm 18: the key pair for three given
/// `n`-byte values.
///
/// For regenerating a key pair from stored seeds and for known-answer tests.
/// Applications generating a new key call [`keygen`], which draws the three
/// values itself, as FIPS 205 section 9 asks.
pub fn keygen_internal(
    set: ParameterSet,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    secret_key: &mut [u8],
    public_key: &mut [u8],
) -> Result<()> {
    let p = set.params();
    let n = p.n;
    check_len(sk_seed.len(), n, "slh-dsa SK.seed must be n bytes")?;
    check_len(sk_prf.len(), n, "slh-dsa SK.prf must be n bytes")?;
    check_len(pk_seed.len(), n, "slh-dsa PK.seed must be n bytes")?;
    check_len(
        secret_key.len(),
        4 * n,
        "slh-dsa secret key buffer must be 4n bytes",
    )?;
    check_len(
        public_key.len(),
        2 * n,
        "slh-dsa public key buffer must be 2n bytes",
    )?;

    let ctx = Ctx::new(p, pk_seed);
    let mut adrs = Adrs::new();
    adrs.set_layer(p.d - 1);
    let mut root = [0u8; MAX_N];
    ctx.xmss_node(sk_seed, 0, p.hp, &mut adrs, &mut root);

    secret_key[..n].copy_from_slice(sk_seed);
    secret_key[n..2 * n].copy_from_slice(sk_prf);
    secret_key[2 * n..3 * n].copy_from_slice(pk_seed);
    secret_key[3 * n..].copy_from_slice(&root[..n]);
    public_key[..n].copy_from_slice(pk_seed);
    public_key[n..].copy_from_slice(&root[..n]);
    Ok(())
}

/// `slh_keygen`, FIPS 205 algorithm 21: a fresh key pair.
///
/// `secret_key` is `4n` bytes and `public_key` `2n`. On failure both are
/// wiped.
pub fn keygen<R: RandomSource + ?Sized>(
    set: ParameterSet,
    rng: &mut R,
    secret_key: &mut [u8],
    public_key: &mut [u8],
) -> Result<()> {
    let n = set.n();
    let mut seeds = Zeroizing::new([0u8; 3 * MAX_N]);
    let result = rng.fill(&mut seeds.get_mut()[..3 * n]).and_then(|()| {
        let s = seeds.get();
        keygen_internal(
            set,
            &s[..n],
            &s[n..2 * n],
            &s[2 * n..3 * n],
            secret_key,
            public_key,
        )
    });
    if result.is_err() {
        secret_key.zeroize();
        public_key.zeroize();
    }
    result
}

/// `slh_sign_internal`, FIPS 205 algorithm 19, over a message given in parts.
///
/// `additional_randomness` is `addrnd`: `n` bytes for the hedged variant,
/// `None` for the deterministic one, which uses `PK.seed` in its place.
fn sign_parts(
    set: ParameterSet,
    secret_key: &[u8],
    message: &[&[u8]],
    additional_randomness: Option<&[u8]>,
    signature: &mut [u8],
) -> Result<usize> {
    let p = set.params();
    let n = p.n;
    check_len(
        secret_key.len(),
        4 * n,
        "slh-dsa secret key must be 4n bytes",
    )?;
    check_len(
        signature.len(),
        set.signature_len(),
        "slh-dsa signature buffer must be exactly the signature length",
    )?;
    let (sk_seed, rest) = secret_key.split_at(n);
    let (sk_prf, rest) = rest.split_at(n);
    let (pk_seed, pk_root) = rest.split_at(n);
    let opt_rand = match additional_randomness {
        Some(r) => {
            check_len(r.len(), n, "slh-dsa additional randomness must be n bytes")?;
            r
        }
        None => pk_seed,
    };
    let ctx = Ctx::new(p, pk_seed);

    let (r, rest) = signature.split_at_mut(n);
    let (sig_fors, sig_ht) = rest.split_at_mut(p.fors_len());
    ctx.prf_msg(sk_prf, opt_rand, message, r)?;

    let mut digest = [0u8; MAX_M];
    ctx.h_msg(r, pk_root, message, &mut digest);
    let (md, idx_tree, idx_leaf) = ctx.split_digest(&digest[..p.m]);

    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair(idx_leaf);
    ctx.fors_sign(md, sk_seed, &mut adrs, sig_fors);
    let mut pk_fors = [0u8; MAX_N];
    ctx.fors_pk_from_sig(sig_fors, md, &mut adrs, &mut pk_fors);
    ctx.ht_sign(&pk_fors[..n], sk_seed, idx_tree, idx_leaf, sig_ht);
    Ok(set.signature_len())
}

/// `slh_verify_internal`, FIPS 205 algorithm 20, over a message in parts.
fn verify_parts(
    set: ParameterSet,
    public_key: &[u8],
    message: &[&[u8]],
    signature: &[u8],
) -> Result<()> {
    let p = set.params();
    let n = p.n;
    check_len(
        public_key.len(),
        2 * n,
        "slh-dsa public key must be 2n bytes",
    )?;
    ensure!(
        signature.len() == set.signature_len(),
        AuthenticationFailed,
        "signature did not verify"
    );
    let (pk_seed, pk_root) = public_key.split_at(n);
    let ctx = Ctx::new(p, pk_seed);
    let (r, rest) = signature.split_at(n);
    let (sig_fors, sig_ht) = rest.split_at(p.fors_len());

    let mut digest = [0u8; MAX_M];
    ctx.h_msg(r, pk_root, message, &mut digest);
    let (md, idx_tree, idx_leaf) = ctx.split_digest(&digest[..p.m]);

    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair(idx_leaf);
    let mut pk_fors = [0u8; MAX_N];
    ctx.fors_pk_from_sig(sig_fors, md, &mut adrs, &mut pk_fors);
    let mut root = [0u8; MAX_N];
    ctx.ht_root(&pk_fors[..n], sig_ht, idx_tree, idx_leaf, &mut root);
    // Neither side is secret; constant-time because there is no reason not.
    ensure!(
        ic_core::ct::verify(&root[..n], pk_root),
        AuthenticationFailed,
        "signature did not verify"
    );
    Ok(())
}

/// The pure-signing message `M' = 0 || |ctx| || ctx || M`, FIPS 205 algorithm
/// 22 line 8, as the parts it is hashed in.
fn pure_message<'a>(
    prefix: &'a mut [u8; 2],
    context: &'a [u8],
    message: &'a [u8],
) -> Result<[&'a [u8]; 3]> {
    ensure!(
        context.len() <= 255,
        InvalidLength,
        "slh-dsa context string is at most 255 bytes"
    );
    *prefix = [0, context.len() as u8];
    Ok([&prefix[..], context, message])
}

/// Sign `message` under `context`, hedged: `slh_sign`, FIPS 205 algorithm 22.
///
/// Draws `n` bytes from `rng` as the additional randomness, which is the
/// default the standard recommends. `signature` must be exactly
/// [`ParameterSet::signature_len`] bytes; its length is returned. `context` is
/// at most 255 bytes and is empty by default.
pub fn sign<R: RandomSource + ?Sized>(
    set: ParameterSet,
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    rng: &mut R,
    signature: &mut [u8],
) -> Result<usize> {
    let mut prefix = [0u8; 2];
    let parts = pure_message(&mut prefix, context, message)?;
    let n = set.n();
    let mut additional = Zeroizing::new([0u8; MAX_N]);
    rng.fill(&mut additional.get_mut()[..n])?;
    sign_parts(
        set,
        secret_key,
        &parts,
        Some(&additional.get()[..n]),
        signature,
    )
}

/// Sign `message` under `context`, deterministically: the variant of `slh_sign`
/// with no additional randomness.
///
/// The same key and message always give the same signature. For platforms
/// with no random bit generator; where side channels are a concern, prefer
/// [`sign`].
pub fn sign_deterministic(
    set: ParameterSet,
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &mut [u8],
) -> Result<usize> {
    let mut prefix = [0u8; 2];
    let parts = pure_message(&mut prefix, context, message)?;
    sign_parts(set, secret_key, &parts, None, signature)
}

/// Verify a pure SLH-DSA signature: `slh_verify`, FIPS 205 algorithm 24.
///
/// `Ok(())` means valid. A signature of the wrong length, or one that does not
/// verify, is `AuthenticationFailed`; a public key of the wrong length or a
/// context over 255 bytes is `InvalidLength`.
pub fn verify(
    set: ParameterSet,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<()> {
    let mut prefix = [0u8; 2];
    let parts = pure_message(&mut prefix, context, message)?;
    verify_parts(set, public_key, &parts, signature)
}

/// `slh_sign_internal`, FIPS 205 algorithm 19, on a message taken as it is.
///
/// The interface NIST's validation testing drives. It signs `message` with no
/// domain separation or context, and takes the additional randomness as an
/// argument; applications call [`sign`] or [`sign_deterministic`].
pub fn sign_internal(
    set: ParameterSet,
    secret_key: &[u8],
    message: &[u8],
    additional_randomness: Option<&[u8]>,
    signature: &mut [u8],
) -> Result<usize> {
    sign_parts(
        set,
        secret_key,
        &[message],
        additional_randomness,
        signature,
    )
}

/// Hedged [`sign`] with the additional randomness given rather than drawn.
///
/// For reproducing NIST's hedged test cases, which fix the randomness. A
/// caller that passes the same value twice has made signing deterministic.
pub fn sign_with_randomness(
    set: ParameterSet,
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    additional_randomness: &[u8],
    signature: &mut [u8],
) -> Result<usize> {
    let mut prefix = [0u8; 2];
    let parts = pure_message(&mut prefix, context, message)?;
    sign_parts(
        set,
        secret_key,
        &parts,
        Some(additional_randomness),
        signature,
    )
}

/// `slh_verify_internal`, FIPS 205 algorithm 20, on a message taken as it is.
///
/// The counterpart of [`sign_internal`]; applications call [`verify`].
pub fn verify_internal(
    set: ParameterSet,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify_parts(set, public_key, &[message], signature)
}

impl SelfTest for SlhDsa {
    /// A NIST ACVP key-generation case for SLH-DSA-SHA2-128f, then a
    /// signature under that key that must verify and must not with the
    /// message changed.
    ///
    /// Key generation covers PRF, F, the WOTS+ chains and the tree hash; the
    /// round trip covers H_msg, PRF_msg, FORS and the hypertree. The signature
    /// itself is not pinned here -- it is 17,088 bytes -- and is compared with
    /// NIST's in `ironcrypto/tests/slh_dsa.rs`.
    fn self_test() -> Result<()> {
        let set = ParameterSet::Sha2_128f;
        let mut seeds = [0u8; 48];
        ic_core::codec::hex_decode(SELF_TEST_SEEDS.as_bytes(), &mut seeds)?;
        let mut want_pk = [0u8; 32];
        ic_core::codec::hex_decode(SELF_TEST_PK.as_bytes(), &mut want_pk)?;

        let mut sk = Zeroizing::new([0u8; 64]);
        let mut pk = [0u8; 32];
        keygen_internal(
            set,
            &seeds[..16],
            &seeds[16..32],
            &seeds[32..],
            sk.get_mut(),
            &mut pk,
        )?;
        ensure!(
            ic_core::ct::verify(&pk, &want_pk),
            SelfTestFailed,
            "slh-dsa: key generation differs from the ACVP vector"
        );

        let mut sig = [0u8; 17088];
        sign_deterministic(set, sk.get(), b"self-test", b"", &mut sig)?;
        ensure!(
            verify(set, &pk, b"self-test", b"", &sig).is_ok(),
            SelfTestFailed,
            "slh-dsa: a signature did not verify"
        );
        ensure!(
            verify(set, &pk, b"self-tesu", b"", &sig).is_err(),
            SelfTestFailed,
            "slh-dsa: a changed message verified"
        );
        Ok(())
    }
}

/// `SK.seed || SK.prf || PK.seed` of the first SLH-DSA-SHA2-128f case in
/// NIST's ACVP SLH-DSA-keyGen-FIPS205 file, and the public key it gives.
const SELF_TEST_SEEDS: &str = "c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659c3b4a868f1bd5debc12d4c9fad66aabd0a94";
const SELF_TEST_PK: &str = "a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfabd39";

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::ErrorKind;

    #[test]
    fn self_test_passes() {
        SlhDsa::self_test().unwrap();
    }

    /// FIPS 205 table 2: public-key and signature sizes, and the digest
    /// length m, which must be exactly the bytes the digest is split into.
    #[test]
    fn sizes_are_table_2s() {
        let table = [
            (ParameterSet::Sha2_128s, 32, 7856, 1),
            (ParameterSet::Sha2_128f, 32, 17088, 1),
            (ParameterSet::Sha2_192s, 48, 16224, 3),
            (ParameterSet::Sha2_192f, 48, 35664, 3),
            (ParameterSet::Sha2_256s, 64, 29792, 5),
            (ParameterSet::Sha2_256f, 64, 49856, 5),
        ];
        for (set, pk, sig, category) in table {
            assert_eq!(set.public_key_len(), pk, "{}", set.id());
            assert_eq!(set.secret_key_len(), 2 * pk, "{}", set.id());
            assert_eq!(set.signature_len(), sig, "{}", set.id());
            assert_eq!(set.category(), category);
        }
        for set in ParameterSet::ALL {
            let p = set.params();
            assert_eq!(p.h, p.d * p.hp, "{}: h = d * h'", set.id());
            let split = (p.k * p.a as usize).div_ceil(8)
                + ((p.h - p.hp) as usize).div_ceil(8)
                + (p.hp as usize).div_ceil(8);
            assert_eq!(p.m, split, "{}: m", set.id());
            assert!(p.n <= MAX_N && p.m <= MAX_M && p.k <= MAX_K);
            assert!(p.a as usize <= MAX_HEIGHT && p.hp as usize <= MAX_HEIGHT);
            assert_eq!(ParameterSet::from_id(set.id()), Some(*set));
        }
        // SHA-2 and SHAKE sets of one size share every number.
        for pair in ParameterSet::ALL.chunks(2) {
            let (a, b) = (pair[0].params(), pair[1].params());
            assert!(!a.shake && b.shake);
            assert_eq!(Params { shake: true, ..a }, b);
        }
    }

    /// `base_2b` against FIPS 205 algorithm 4 run by hand on 0x1234_5678:
    /// four-bit digits are the hex digits, and six-bit digits are the first
    /// 24 bits regrouped.
    #[test]
    fn base_2b_regroups_bits_most_significant_first() {
        let x = [0x12, 0x34, 0x56, 0x78];
        let mut hex = [0u32; 8];
        base_2b(&x, 4, &mut hex);
        assert_eq!(hex, [1, 2, 3, 4, 5, 6, 7, 8]);
        // 000100 100011 010001 010110
        let mut six = [0u32; 4];
        base_2b(&x, 6, &mut six);
        assert_eq!(six, [0b000100, 0b100011, 0b010001, 0b010110]);
        // Fourteen-bit digits, the widest FORS uses: 00010010001101 00010101100111
        let mut wide = [0u32; 2];
        base_2b(&x, 14, &mut wide);
        assert_eq!(wide, [0b00010010001101, 0b00010101100111]);
    }

    /// The compressed address is the bytes FIPS 205 section 11.2 names.
    #[test]
    fn the_compressed_address_keeps_the_right_bytes() {
        let mut adrs = Adrs::new();
        adrs.set_layer(0x0102_0304);
        adrs.set_tree(0x1112_1314_1516_1718);
        adrs.set_type_and_clear(0x2122_2324);
        adrs.set_key_pair(0x3132_3334);
        adrs.set_chain(0x4142_4344);
        adrs.set_hash(0x5152_5354);
        let c = adrs.compressed();
        assert_eq!(c[0], 0x04);
        assert_eq!(c[1..9], [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
        assert_eq!(c[9], 0x24);
        assert_eq!(c[10..14], [0x31, 0x32, 0x33, 0x34]);
        assert_eq!(c[14..18], [0x41, 0x42, 0x43, 0x44]);
        assert_eq!(c[18..22], [0x51, 0x52, 0x53, 0x54]);
        // Changing the type clears the three words after it.
        adrs.set_type_and_clear(TREE);
        assert_eq!(adrs.0[20..32], [0u8; 12]);
        assert_eq!(adrs.key_pair(), 0);
    }

    /// The fast sets, both hash families, at each size: sign, verify, and
    /// refuse what should be refused.
    #[test]
    fn fast_sets_sign_and_verify() {
        for set in [
            ParameterSet::Sha2_128f,
            ParameterSet::Shake_128f,
            ParameterSet::Sha2_192f,
            ParameterSet::Shake_192f,
            ParameterSet::Sha2_256f,
            ParameterSet::Shake_256f,
        ] {
            let n = set.n();
            let seed: Vec<u8> = (0..3 * n as u8).collect();
            let mut sk = vec![0u8; set.secret_key_len()];
            let mut pk = vec![0u8; set.public_key_len()];
            keygen_internal(
                set,
                &seed[..n],
                &seed[n..2 * n],
                &seed[2 * n..],
                &mut sk,
                &mut pk,
            )
            .unwrap();
            let mut sig = vec![0u8; set.signature_len()];
            assert_eq!(
                sign_deterministic(set, &sk, b"message", b"ctx", &mut sig).unwrap(),
                set.signature_len()
            );
            verify(set, &pk, b"message", b"ctx", &sig).unwrap();

            let refused = |pk: &[u8], m: &[u8], c: &[u8], s: &[u8]| {
                assert_eq!(
                    verify(set, pk, m, c, s).unwrap_err().kind(),
                    ErrorKind::AuthenticationFailed,
                    "{}",
                    set.id()
                );
            };
            refused(&pk, b"massage", b"ctx", &sig);
            refused(&pk, b"message", b"", &sig);
            refused(&pk, b"message", b"ctx", &sig[1..]);
            // One bit changed in R, in the FORS signature, and in the last
            // byte of the hypertree signature.
            for at in [0, n, sig.len() - 1] {
                let mut bad = sig.clone();
                bad[at] ^= 1;
                refused(&pk, b"message", b"ctx", &bad);
            }
            let mut other = pk.clone();
            other[2 * n - 1] ^= 1;
            refused(&other, b"message", b"ctx", &sig);

            // Deterministic signing repeats; hedged signing with different
            // randomness does not, and both verify.
            let mut again = vec![0u8; set.signature_len()];
            sign_deterministic(set, &sk, b"message", b"ctx", &mut again).unwrap();
            assert_eq!(sig, again);
            sign_with_randomness(set, &sk, b"message", b"ctx", &vec![7u8; n], &mut again).unwrap();
            assert_ne!(sig, again);
            verify(set, &pk, b"message", b"ctx", &again).unwrap();
        }
    }

    #[test]
    fn wrong_lengths_are_refused_before_any_work() {
        let set = ParameterSet::Sha2_128f;
        let mut sk = [0u8; 64];
        let mut pk = [0u8; 32];
        let seed = [1u8; 16];
        let kind = |r: Result<()>| r.unwrap_err().kind();
        assert_eq!(
            kind(keygen_internal(
                set,
                &seed[..15],
                &seed,
                &seed,
                &mut sk,
                &mut pk
            )),
            ErrorKind::InvalidLength
        );
        assert_eq!(
            kind(keygen_internal(
                set,
                &seed,
                &seed,
                &seed,
                &mut sk[..63],
                &mut pk
            )),
            ErrorKind::InvalidLength
        );
        keygen_internal(set, &seed, &seed, &seed, &mut sk, &mut pk).unwrap();
        let mut sig = vec![0u8; set.signature_len()];
        let len = |r: Result<usize>| r.unwrap_err().kind();
        assert_eq!(
            len(sign_deterministic(set, &sk[..63], b"m", b"", &mut sig)),
            ErrorKind::InvalidLength
        );
        assert_eq!(
            len(sign_deterministic(set, &sk, b"m", b"", &mut sig[1..])),
            ErrorKind::InvalidLength
        );
        assert_eq!(
            len(sign_deterministic(set, &sk, b"m", &[0u8; 256], &mut sig)),
            ErrorKind::InvalidLength
        );
        assert_eq!(
            len(sign_with_randomness(
                set, &sk, b"m", b"", &[0u8; 15], &mut sig
            )),
            ErrorKind::InvalidLength
        );
        sign_deterministic(set, &sk, b"m", &[0u8; 255], &mut sig).unwrap();
        verify(set, &pk, b"m", &[0u8; 255], &sig).unwrap();
        assert_eq!(
            kind(verify(set, &pk[..31], b"m", b"", &sig)),
            ErrorKind::InvalidLength
        );
        assert_eq!(
            kind(verify(set, &pk, b"m", &[0u8; 256], &sig)),
            ErrorKind::InvalidLength
        );
    }

    /// The internal interface signs the message as given; the pure interface
    /// signs it under a two-byte prefix and the context. So a pure signature
    /// with an empty context is an internal signature over `00 00 || M`, and
    /// neither verifies as the other over `M`.
    #[test]
    fn the_pure_interface_is_the_internal_one_with_a_prefix() {
        let set = ParameterSet::Shake_128f;
        let seed = [9u8; 16];
        let mut sk = [0u8; 64];
        let mut pk = [0u8; 32];
        keygen_internal(set, &seed, &seed, &seed, &mut sk, &mut pk).unwrap();
        let mut pure = vec![0u8; set.signature_len()];
        sign_deterministic(set, &sk, b"M", b"", &mut pure).unwrap();
        let mut internal = vec![0u8; set.signature_len()];
        sign_internal(set, &sk, b"\0\0M", None, &mut internal).unwrap();
        assert_eq!(pure, internal);
        verify_internal(set, &pk, b"\0\0M", &pure).unwrap();
        assert!(verify_internal(set, &pk, b"M", &pure).is_err());
    }
}
