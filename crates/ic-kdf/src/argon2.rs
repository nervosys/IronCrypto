//! RFC 9106 Argon2, the memory-hard password hash.
//!
//! **Not FIPS-approved**, and that is the whole tension: PBKDF2 is the only
//! approved password KDF, and it is not memory-hard, so a GPU or FPGA attacks
//! it far faster than a CPU can defend it. Argon2 forces an attacker to spend
//! *memory* as well as time, which is what closes that gap. If you have a FIPS
//! obligation you are stuck with PBKDF2; if you do not, use this.
//!
//! # Which variant
//!
//! * [`Variant::Argon2id`] — the default, and what RFC 9106 recommends. Its
//!   first half-pass indexes data-independently (resisting side-channel
//!   attacks on the memory access pattern) and the rest indexes
//!   data-dependently (resisting time-memory trade-offs). Use this unless you
//!   have a specific reason not to.
//! * [`Variant::Argon2i`] — data-independent throughout. Only for threat models
//!   where an attacker can observe memory access patterns *and* the extra
//!   trade-off resistance is unwanted.
//! * [`Variant::Argon2d`] — data-dependent throughout. Maximum trade-off
//!   resistance, no side-channel resistance. Intended for settings with no
//!   untrusted co-tenant, such as cryptocurrency proof-of-work.
//!
//! # Parameters
//!
//! ```
//! use ic_kdf::argon2::{Argon2Params, Variant, argon2};
//!
//! let params = Argon2Params::RECOMMENDED;   // 2 GiB, t=1, p=4
//! let params = Argon2Params::INTERACTIVE;   // 64 MiB, t=3, p=4
//!
//! let mut key = [0u8; 32];
//! argon2(Variant::Argon2id, &params, b"password", b"a 16-byte salt..", &mut key)?;
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! Memory is the parameter that matters; raising `t` on a small `m` buys far
//! less than raising `m`.

pub mod phc;

// Argon2's compression function with AVX2, behind runtime detection. The
// only unsafe code in this crate; see `avx2` for what it computes and how
// it is checked.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[allow(unsafe_code)]
mod avx2;

use alloc::vec::Vec;
use ic_core::{ensure, Result, Zeroize};
use ic_hash::{blake2b_long, Blake2b};

/// Bytes in one Argon2 memory block.
const BLOCK_LEN: usize = 1024;

/// 64-bit words in one memory block.
const BLOCK_WORDS: usize = BLOCK_LEN / 8;

/// Argon2 synchronization points per pass.
const SLICES: usize = 4;

/// Which version of Argon2 to run.
///
/// RFC 9106 specifies 1.3, which is what to make new hashes with. 1.0 is the
/// version the Password Hashing Competition selected; it differs only in
/// overwriting memory blocks on later passes where 1.3 XORs into them. It is
/// here so that hashes made with it still verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum Version {
    /// Version 1.0, `v=16` in a PHC string.
    V0x10 = 0x10,
    /// Version 1.3, `v=19` in a PHC string, RFC 9106's.
    #[default]
    V0x13 = 0x13,
}

impl Version {
    /// The number a PHC string carries.
    pub const fn number(self) -> u32 {
        self as u32
    }

    /// The version a PHC string's number names.
    pub fn from_number(number: u32) -> Result<Self> {
        match number {
            0x10 => Ok(Self::V0x10),
            0x13 => Ok(Self::V0x13),
            _ => Err(ic_core::err!(Unsupported, "argon2 version")),
        }
    }
}

/// Which Argon2 variant to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Data-dependent indexing throughout.
    Argon2d,
    /// Data-independent indexing throughout.
    Argon2i,
    /// Data-independent for the first half-pass, data-dependent thereafter.
    Argon2id,
}

impl Variant {
    /// The type constant that goes into `H0`.
    const fn type_id(self) -> u32 {
        match self {
            Self::Argon2d => 0,
            Self::Argon2i => 1,
            Self::Argon2id => 2,
        }
    }

    /// Stable identifier used by the ontology and the CLI.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Argon2d => "argon2d",
            Self::Argon2i => "argon2i",
            Self::Argon2id => "argon2id",
        }
    }

    /// Whether this pass and slice index data-independently.
    fn independent(self, pass: u32, slice: usize) -> bool {
        match self {
            Self::Argon2d => false,
            Self::Argon2i => true,
            // Argon2id: the first two slices of the first pass only.
            Self::Argon2id => pass == 0 && slice < 2,
        }
    }
}

/// Cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory in kibibytes.
    pub memory_kib: u32,
    /// Number of passes over the memory.
    pub passes: u32,
    /// Degree of parallelism (lanes).
    pub lanes: u32,
}

impl Argon2Params {
    /// RFC 9106's first recommendation: 2 GiB, one pass, four lanes.
    ///
    /// Use this for offline key derivation where a second of latency and two
    /// gibibytes of resident memory are acceptable.
    pub const RECOMMENDED: Argon2Params = Argon2Params {
        memory_kib: 2 * 1024 * 1024,
        passes: 1,
        lanes: 4,
    };

    /// RFC 9106's second recommendation: 64 MiB, three passes, four lanes.
    ///
    /// For interactive logins, where the 2 GiB option would be a denial of
    /// service against your own server.
    pub const INTERACTIVE: Argon2Params = Argon2Params {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 4,
    };

    /// The parameters the `argon2` crate and OWASP give as a default for
    /// password storage: 19 MiB, two passes, one lane. The least this
    /// library's passphrase sealing accepts.
    pub const DEFAULT: Argon2Params = Argon2Params {
        memory_kib: 19 * 1024,
        passes: 2,
        lanes: 1,
    };

    /// How many [`Block`]s a run with these parameters uses: the memory
    /// rounded down to a whole number of blocks per slice of every lane, and
    /// at least eight per lane.
    pub const fn block_count(&self) -> usize {
        let lanes = if self.lanes == 0 {
            1
        } else {
            self.lanes as usize
        };
        let memory = self.memory_kib as usize;
        let floor = 8 * lanes;
        let memory = if memory < floor { floor } else { memory };
        (memory / (SLICES * lanes)) * (SLICES * lanes)
    }

    /// Check the parameters against RFC 9106's limits.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.lanes >= 1 && self.lanes <= 0x00FF_FFFF,
            InvalidParameter,
            "argon2 lanes must be 1..=2^24-1"
        );
        ensure!(
            self.passes >= 1,
            InvalidParameter,
            "argon2 passes must be at least 1"
        );
        ensure!(
            self.memory_kib >= 8 * self.lanes,
            InvalidParameter,
            "argon2 memory must be at least 8 KiB per lane"
        );
        Ok(())
    }
}

/// One 1024-byte memory block, as 128 little-endian words.
///
/// Public so that a caller can provide the memory itself, through
/// [`argon2_with_memory`] and [`fill_memory`]: an array of these on the
/// stack or in a static, where there is no allocator. A plain array rather
/// than a type of its own, because an array of zeros can be allocated as
/// pages the operating system has already zeroed, and filled lazily, where
/// any other type is written out in full first: at 256 MiB that was 40 ms,
/// a third of the hash.
pub type Block = [u64; BLOCK_WORDS];

/// A block of zeros.
pub const ZERO_BLOCK: Block = [0u64; BLOCK_WORDS];

/// Bytes in a block.
pub const BLOCK_SIZE: usize = BLOCK_LEN;

fn block_from_bytes(bytes: &[u8; BLOCK_LEN]) -> Block {
    let mut b = ZERO_BLOCK;
    for (i, word) in b.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *word = u64::from_le_bytes(w);
    }
    b
}

fn block_to_bytes(block: &Block) -> [u8; BLOCK_LEN] {
    let mut out = [0u8; BLOCK_LEN];
    for (chunk, word) in out.chunks_exact_mut(8).zip(block.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Block `i` of a flat arena, as a reference to its 128 words.
///
/// The arena is held flat, as `u64`s, because a `Vec<u64>` of zeros is
/// allocated zeroed by the operating system, lazily, and a vector of 128-word
/// arrays is written out in full first. An index past the end, which the
/// algorithm never produces, reads as zeros rather than panicking.
#[inline(always)]
fn chunk(memory: &[u64], i: usize) -> &Block {
    memory
        .get(i * BLOCK_WORDS..)
        .and_then(|rest| rest.first_chunk::<BLOCK_WORDS>())
        .unwrap_or(&ZERO_BLOCK)
}

/// Block `i` of a flat arena, mutably.
#[inline(always)]
fn chunk_mut(memory: &mut [u64], i: usize) -> Option<&mut Block> {
    memory
        .get_mut(i * BLOCK_WORDS..)
        .and_then(|rest| rest.first_chunk_mut::<BLOCK_WORDS>())
}

fn block_xor(a: &Block, b: &Block) -> Block {
    let mut out = ZERO_BLOCK;
    for ((slot, x), y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *slot = x ^ y;
    }
    out
}

/// Argon2's modified BLAKE2b mixing function.
///
/// The extra `2 * lo(a) * lo(b)` term is what distinguishes it from plain
/// BLAKE2b: it makes the round function non-linear over 64-bit words, which is
/// what forces an attacker to actually perform the multiplications rather than
/// shortcutting them.
#[inline(always)]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    #[inline(always)]
    fn mix(x: u64, y: u64) -> u64 {
        x.wrapping_add(y).wrapping_add(
            2u64.wrapping_mul(x & 0xFFFF_FFFF)
                .wrapping_mul(y & 0xFFFF_FFFF),
        )
    }

    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The permutation `P` over sixteen words.
#[inline]
fn permute(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// `G(x, y)` written to `out`, or XORed into it when `xor` is set: with
/// AVX2 where the CPU has it, and the scalar definition otherwise.
#[inline]
fn compress_into(x: &Block, y: &Block, out: &mut Block, xor: bool) {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if have_avx2() {
        // SAFETY: `have_avx2` confirmed the CPU supports AVX2.
        #[allow(unsafe_code)]
        unsafe {
            avx2::compress(x, y, out, xor)
        };
        return;
    }
    let g = compress(x, y);
    if xor {
        for (o, m) in out.iter_mut().zip(g.iter()) {
            *o ^= m;
        }
    } else {
        *out = g;
    }
}

/// Whether this CPU has AVX2, asked once. Tests can turn it off, to run the
/// scalar form on a machine that has AVX2.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn have_avx2() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(0);
    if tests::scalar_only() {
        return false;
    }
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = std::is_x86_feature_detected!("avx2");
            CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
            have
        }
    }
}

/// The compression function `G`, the definition the AVX2 form is held to.
///
/// `R = X ^ Y`, then `P` over each row, then `P` over each column, then XOR
/// with `R` again. The row-then-column structure is what makes every output
/// word depend on every input word.
fn compress(x: &Block, y: &Block) -> Block {
    let r = block_xor(x, y);
    let mut q = r;

    // Rows: eight groups of sixteen consecutive words.
    for row in 0..8 {
        let mut v = [0u64; 16];
        v.copy_from_slice(&q[row * 16..row * 16 + 16]);
        permute(&mut v);
        q[row * 16..row * 16 + 16].copy_from_slice(&v);
    }

    // Columns: word pairs strided across the rows.
    for col in 0..8 {
        let mut v = [0u64; 16];
        for i in 0..8 {
            v[i * 2] = q[i * 16 + col * 2];
            v[i * 2 + 1] = q[i * 16 + col * 2 + 1];
        }
        permute(&mut v);
        for i in 0..8 {
            q[i * 16 + col * 2] = v[i * 2];
            q[i * 16 + col * 2 + 1] = v[i * 2 + 1];
        }
    }

    block_xor(&q, &r)
}

/// Map `(j1, j2)` onto a reference block, per RFC 9106 §3.4.1.2, as its
/// lane and its position within that lane.
#[allow(clippy::too_many_arguments)]
fn reference_index(
    j1: u32,
    j2: u32,
    pass: u32,
    lane: u32,
    slice: usize,
    index: usize,
    lanes: u32,
    lane_len: usize,
    segment_len: usize,
) -> (usize, usize) {
    // Which lane the reference comes from. On the very first segment there is
    // nothing in the other lanes yet, so it must be our own.
    let ref_lane = if pass == 0 && slice == 0 {
        lane
    } else {
        j2 % lanes
    };

    // How many finished blocks are visible to this position.
    let same_lane = ref_lane == lane;
    let mut reference_area = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * segment_len + index - 1
        } else {
            slice * segment_len - usize::from(index == 0)
        }
    } else if same_lane {
        lane_len - segment_len + index - 1
    } else {
        lane_len - segment_len - usize::from(index == 0)
    };
    if reference_area == usize::MAX {
        reference_area = 0;
    }

    // A non-uniform map that favours recent blocks, which is what makes a
    // time-memory trade-off expensive.
    let x = ((j1 as u64) * (j1 as u64)) >> 32;
    let y = ((reference_area as u64) * x) >> 32;
    let z = (reference_area as u64) - 1 - y;

    let start = if pass == 0 || slice == SLICES - 1 {
        0
    } else {
        (slice + 1) * segment_len
    };
    let position = (start as u64 + z) % (lane_len as u64);
    (ref_lane as usize, position as usize)
}

/// Run Argon2 version 1.3 and write `out.len()` bytes of tag.
///
/// `out` must be at least 4 bytes. `salt` must be at least 8 bytes; RFC 9106
/// recommends 16, which is what [`Argon2Params`] documentation assumes.
pub fn argon2(
    variant: Variant,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<()> {
    ic_core::module::operational()?;
    argon2_full(variant, params, password, salt, &[], &[], out)
}

/// Argon2 version 1.3 with the optional secret and associated-data inputs.
///
/// The `secret` is a site-wide pepper: an attacker who steals the password
/// database but not the secret cannot mount an offline attack at all. Very few
/// deployments use it, and those that do usually should.
pub fn argon2_full(
    variant: Variant,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    out: &mut [u8],
) -> Result<()> {
    argon2_versioned(
        variant,
        Version::V0x13,
        params,
        password,
        salt,
        secret,
        associated_data,
        out,
    )
}

/// Argon2 at either version, allocating its own memory.
///
/// Version 1.0 is for verifying hashes made before 1.3; make new ones with
/// [`Version::V0x13`]. The memory is wiped before this returns.
#[allow(clippy::too_many_arguments)]
pub fn argon2_versioned(
    variant: Variant,
    version: Version,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    out: &mut [u8],
) -> Result<()> {
    ic_core::module::operational()?;
    params.validate()?;
    // The parameters can come from a stored hash, so an allocation that
    // fails is an error to return, not a reason to abort. The reservation
    // asks the allocator whether the size is possible and is given back
    // untouched; the arena is then allocated zeroed, which for an array of
    // zeros means pages the operating system zeroes when first written,
    // across the lane threads, rather than here, on one.
    let words = params
        .block_count()
        .checked_mul(BLOCK_WORDS)
        .ok_or(ic_core::err!(InvalidParameter, "argon2 memory: too large"))?;
    let mut probe: Vec<u64> = Vec::new();
    probe
        .try_reserve_exact(words)
        .map_err(|_| ic_core::err!(InvalidParameter, "argon2 memory: allocation failed"))?;
    drop(probe);
    let mut memory: Vec<u64> = alloc::vec![0u64; words];
    run(
        variant,
        version,
        params,
        password,
        salt,
        secret,
        associated_data,
        &mut memory,
        out,
    )
}

/// Argon2 in memory the caller provides, without allocating.
///
/// For targets with no allocator, or callers who keep an arena between
/// hashes. `memory` must hold at least [`Argon2Params::block_count`] blocks;
/// only that many are used, and they are wiped before this returns, since
/// they hold password-derived material.
#[allow(clippy::too_many_arguments)]
pub fn argon2_with_memory(
    variant: Variant,
    version: Version,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    memory: &mut [Block],
    out: &mut [u8],
) -> Result<()> {
    run(
        variant,
        version,
        params,
        password,
        salt,
        secret,
        associated_data,
        memory.as_flattened_mut(),
        out,
    )
}

/// Hash, finalize and wipe, over a flat arena.
#[allow(clippy::too_many_arguments)]
fn run(
    variant: Variant,
    version: Version,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    memory: &mut [u64],
    out: &mut [u8],
) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        out.len() >= 4 && u32::try_from(out.len()).is_ok(),
        InvalidLength,
        "argon2 tag must be 4 bytes to 2^32 - 1"
    );
    let geometry = Geometry::new(variant, version, params, memory.len() / BLOCK_WORDS)?;
    let memory = &mut memory[..geometry.total * BLOCK_WORDS];
    let result = fill(
        &geometry,
        params,
        password,
        salt,
        secret,
        associated_data,
        out.len() as u32,
        memory,
    )
    .and_then(|()| {
        // The final block is the XOR of the last block of every lane.
        let mut final_block = *chunk(memory, geometry.lane_len - 1);
        for lane in 1..geometry.lanes {
            final_block = block_xor(
                &final_block,
                chunk(memory, lane * geometry.lane_len + geometry.lane_len - 1),
            );
        }
        let mut bytes = block_to_bytes(&final_block);
        let r = blake2b_long(&[&bytes], out);
        bytes.zeroize();
        final_block.zeroize();
        r
    });
    // Wipe the arena whatever happened: it is full of password-derived material.
    wipe(memory, geometry.lanes);
    result
}

/// Zero the arena, a share per thread where the fill used threads.
fn wipe(memory: &mut [u64], lanes: usize) {
    #[cfg(feature = "std")]
    if lanes > 1 && !tests::sequential_only() {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        if threads > 1 {
            let chunk = memory.len().div_ceil(threads.min(lanes)).max(1);
            std::thread::scope(|scope| {
                for part in memory.chunks_mut(chunk) {
                    scope.spawn(move || part.zeroize());
                }
            });
            return;
        }
    }
    let _ = lanes;
    memory.zeroize();
}

/// Fill `memory` as Argon2 would, and stop before computing a tag.
///
/// For constructions that use Argon2's memory itself rather than its output.
/// The blocks are left as filled, in the reference layout: lane by lane, each
/// lane [`Argon2Params::block_count`]` / lanes` blocks long. They hold
/// password-derived material, and wiping them is the caller's part. The tag
/// length that goes into the first hash is zero, as the reference
/// implementation and the `argon2` crate have it.
#[allow(clippy::too_many_arguments)]
pub fn fill_memory(
    variant: Variant,
    version: Version,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    memory: &mut [Block],
) -> Result<()> {
    ic_core::module::operational()?;
    let geometry = Geometry::new(variant, version, params, memory.len())?;
    fill(
        &geometry,
        params,
        password,
        salt,
        secret,
        associated_data,
        0,
        memory[..geometry.total].as_flattened_mut(),
    )
}

/// The shape of one run: what every segment needs to know.
struct Geometry {
    variant: Variant,
    version: Version,
    lanes: usize,
    passes: u32,
    total: usize,
    lane_len: usize,
    segment_len: usize,
}

impl Geometry {
    fn new(
        variant: Variant,
        version: Version,
        params: &Argon2Params,
        provided: usize,
    ) -> Result<Self> {
        params.validate()?;
        let total = params.block_count();
        ensure!(
            provided >= total,
            InvalidLength,
            "argon2 memory: fewer blocks than the parameters need"
        );
        let lanes = params.lanes as usize;
        let lane_len = total / lanes;
        Ok(Self {
            variant,
            version,
            lanes,
            passes: params.passes,
            total,
            lane_len,
            segment_len: lane_len / SLICES,
        })
    }
}

/// `H0`, the first two blocks of every lane, and every pass.
#[allow(clippy::too_many_arguments)]
fn fill(
    g: &Geometry,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    tag_len: u32,
    memory: &mut [u64],
) -> Result<()> {
    ensure!(
        salt.len() >= 8,
        InvalidParameter,
        "argon2 salt must be >= 8 bytes"
    );
    let len32 = |n: usize, what: &'static str| {
        u32::try_from(n).map_err(|_| ic_core::Error::new(ic_core::ErrorKind::InvalidLength, what))
    };
    let password_len = len32(password.len(), "argon2 password longer than 2^32 - 1")?;
    let salt_len = len32(salt.len(), "argon2 salt longer than 2^32 - 1")?;
    let secret_len = len32(secret.len(), "argon2 secret longer than 2^32 - 1")?;
    let ad_len = len32(associated_data.len(), "argon2 data longer than 2^32 - 1")?;

    // H0: a 64-byte seed over every input and every parameter.
    //
    // This is plain BLAKE2b-512, *not* the variable-length `H'` used for the
    // memory blocks and the final tag. `H'` prefixes its output length to the
    // input, which would corrupt the seed.
    let mut h0 = [0u8; 72];
    {
        let mut hasher = Blake2b::new(64)?;
        let le = |v: u32| v.to_le_bytes();
        hasher.update(&le(params.lanes));
        hasher.update(&le(tag_len));
        hasher.update(&le(params.memory_kib));
        hasher.update(&le(params.passes));
        hasher.update(&le(g.version as u32));
        hasher.update(&le(g.variant.type_id()));
        hasher.update(&le(password_len));
        hasher.update(password);
        hasher.update(&le(salt_len));
        hasher.update(salt);
        hasher.update(&le(secret_len));
        hasher.update(secret);
        hasher.update(&le(ad_len));
        hasher.update(associated_data);

        let mut seed = [0u8; 64];
        hasher.finalize_into(&mut seed)?;
        h0[..64].copy_from_slice(&seed);
        seed.zeroize();
    }

    // The first two blocks of each lane come straight from H0.
    for lane in 0..g.lanes {
        for index in 0..2u32 {
            h0[64..68].copy_from_slice(&index.to_le_bytes());
            h0[68..72].copy_from_slice(&(lane as u32).to_le_bytes());
            let mut block = [0u8; BLOCK_LEN];
            blake2b_long(&[&h0], &mut block)?;
            if let Some(slot) = chunk_mut(memory, lane * g.lane_len + index as usize) {
                *slot = block_from_bytes(&block);
            }
            block.zeroize();
        }
    }
    h0.zeroize();

    for pass in 0..g.passes {
        for slice in 0..SLICES {
            fill_slice(g, pass, slice, memory);
        }
    }
    Ok(())
}

/// Every lane's segment of one slice.
///
/// Within a slice no lane reads another lane's current segment -- RFC 9106
/// section 3.4 is built that way so that lanes can run in parallel -- so each
/// segment is split off mutably and the rest of memory is read through a
/// shared view. With `std` and more than one lane, the segments are filled
/// on threads; otherwise one after another, through the same function.
fn fill_slice(g: &Geometry, pass: u32, slice: usize, memory: &mut [u64]) {
    #[cfg(feature = "std")]
    if g.lanes > 1 && !tests::sequential_only() {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        if threads > 1 {
            fill_slice_threaded(g, pass, slice, memory, threads);
            return;
        }
    }
    let start = slice * g.segment_len;
    for lane in 0..g.lanes {
        let at = lane * g.lane_len + start;
        let (head, rest) = memory.split_at_mut(at * BLOCK_WORDS);
        let (segment, tail) = rest.split_at_mut(g.segment_len * BLOCK_WORDS);
        let outside = Around {
            head,
            tail,
            tail_from: at + g.segment_len,
            lane_len: g.lane_len,
        };
        fill_segment(g, pass, slice, lane, segment, &outside);
    }
}

#[cfg(feature = "std")]
fn fill_slice_threaded(g: &Geometry, pass: u32, slice: usize, memory: &mut [u64], threads: usize) {
    // Split memory into each lane's segment and the gaps between them:
    // gap[k] runs from the end of segment k-1 to the start of segment k.
    let start = slice * g.segment_len;
    let mut segments: std::vec::Vec<&mut [u64]> = std::vec::Vec::with_capacity(g.lanes);
    let mut gaps: std::vec::Vec<&[u64]> = std::vec::Vec::with_capacity(g.lanes + 1);
    let mut rest: &mut [u64] = memory;
    let mut consumed = 0;
    for lane in 0..g.lanes {
        let at = lane * g.lane_len + start - consumed;
        let (gap, after) = rest.split_at_mut(at * BLOCK_WORDS);
        let (segment, after) = after.split_at_mut(g.segment_len * BLOCK_WORDS);
        gaps.push(gap);
        segments.push(segment);
        consumed += at + g.segment_len;
        rest = after;
    }
    gaps.push(rest);
    let outside = Gaps {
        gaps: &gaps,
        start,
        end: start + g.segment_len,
    };

    let per_thread = g.lanes.div_ceil(threads.min(g.lanes));
    std::thread::scope(|scope| {
        let mut lane = 0;
        let mut segments = segments.into_iter();
        loop {
            let batch: std::vec::Vec<&mut [u64]> = segments.by_ref().take(per_thread).collect();
            if batch.is_empty() {
                break;
            }
            let first = lane;
            lane += batch.len();
            let outside = &outside;
            scope.spawn(move || {
                for (i, segment) in batch.into_iter().enumerate() {
                    fill_segment(g, pass, slice, first + i, segment, outside);
                }
            });
        }
    });
}

/// Read access to every block outside the segment being filled.
trait Outside: Sync {
    /// The block at `position` in `lane`. Never asked for a block inside any
    /// lane's current segment.
    fn block(&self, lane: usize, position: usize) -> &Block;
}

/// One segment's surroundings, for one lane at a time.
struct Around<'a> {
    head: &'a [u64],
    tail: &'a [u64],
    tail_from: usize,
    lane_len: usize,
}

impl Outside for Around<'_> {
    fn block(&self, lane: usize, position: usize) -> &Block {
        let index = lane * self.lane_len + position;
        if index * BLOCK_WORDS < self.head.len() {
            chunk(self.head, index)
        } else {
            chunk(self.tail, index.wrapping_sub(self.tail_from))
        }
    }
}

/// Every lane's surroundings at once, for lanes filled in parallel.
#[cfg(feature = "std")]
struct Gaps<'a> {
    gaps: &'a [&'a [u64]],
    start: usize,
    end: usize,
}

#[cfg(feature = "std")]
impl Outside for Gaps<'_> {
    fn block(&self, lane: usize, position: usize) -> &Block {
        let (gap, offset) = if position < self.start {
            // Gap `lane` ends where this lane's segment starts.
            let len = self.gaps.get(lane).map_or(0, |g| g.len() / BLOCK_WORDS);
            (lane, len.wrapping_sub(self.start - position))
        } else if position >= self.end {
            (lane + 1, position - self.end)
        } else {
            // Inside another lane's current segment, which the algorithm
            // never reads. Not reachable; answered without panicking.
            return &ZERO_BLOCK;
        };
        self.gaps.get(gap).map_or(&ZERO_BLOCK, |g| chunk(g, offset))
    }
}

/// Fill one lane's segment of one slice.
fn fill_segment<O: Outside>(
    g: &Geometry,
    pass: u32,
    slice: usize,
    lane: usize,
    segment: &mut [u64],
    outside: &O,
) {
    let seg_start = slice * g.segment_len;
    let independent = g.variant.independent(pass, slice);
    let mut addresses = [0u64; BLOCK_WORDS];
    let mut address_counter = 0u64;

    // A block in this lane's segment, or anywhere outside it. Borrowed,
    // not copied: at a kilobyte a block, copying two per position doubled
    // the memory traffic, which is what bounds a large run.
    #[inline(always)]
    fn read<'s, O: Outside>(
        segment: &'s [u64],
        outside: &'s O,
        own: usize,
        seg_start: usize,
        lane: usize,
        position: usize,
    ) -> &'s Block {
        match position.checked_sub(seg_start) {
            Some(i) if lane == own && i * BLOCK_WORDS < segment.len() => chunk(segment, i),
            _ => outside.block(lane, position),
        }
    }

    let first = if pass == 0 && slice == 0 { 2 } else { 0 };
    for index in first..g.segment_len {
        let position = slice * g.segment_len + index;
        let previous = if position == 0 {
            g.lane_len - 1
        } else {
            position - 1
        };
        let (j1, j2) = if independent {
            // Refresh the address block every 128 positions.
            if index % BLOCK_WORDS == 0 || address_counter == 0 {
                address_counter += 1;
                let mut input = ZERO_BLOCK;
                input[0] = pass as u64;
                input[1] = lane as u64;
                input[2] = slice as u64;
                input[3] = g.total as u64;
                input[4] = g.passes as u64;
                input[5] = g.variant.type_id() as u64;
                input[6] = address_counter;
                let zero = ZERO_BLOCK;
                let mut tmp = ZERO_BLOCK;
                compress_into(&zero, &input, &mut tmp, false);
                let mut block = ZERO_BLOCK;
                compress_into(&zero, &tmp, &mut block, false);
                addresses.copy_from_slice(&block);
            }
            let word = addresses[index % BLOCK_WORDS];
            (word as u32, (word >> 32) as u32)
        } else {
            let word = read(segment, outside, lane, seg_start, lane, previous)[0];
            (word as u32, (word >> 32) as u32)
        };

        let (ref_lane, ref_position) = reference_index(
            j1,
            j2,
            pass,
            lane as u32,
            slice,
            index,
            g.lanes as u32,
            g.lane_len,
            g.segment_len,
        );
        // Version 1.0 overwrote on every pass; 1.3 XORs into the block on
        // every pass after the first, which is the one difference.
        let xor = pass != 0 && g.version == Version::V0x13;
        let mut mixed = if xor {
            *chunk(segment, index)
        } else {
            ZERO_BLOCK
        };
        compress_into(
            read(segment, outside, lane, seg_start, lane, previous),
            read(segment, outside, lane, seg_start, ref_lane, ref_position),
            &mut mixed,
            xor,
        );
        if let Some(slot) = chunk_mut(segment, index) {
            *slot = mixed;
        }
    }
}

#[cfg(not(test))]
mod tests {
    /// Outside tests, lanes run on threads whenever they can.
    #[cfg(feature = "std")]
    pub(super) fn sequential_only() -> bool {
        false
    }

    /// Outside tests, AVX2 is used whenever the CPU has it.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    pub(super) fn scalar_only() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// Set by a test to run the one-lane-at-a-time path with several lanes,
    /// which otherwise only a target without `std` takes.
    static SEQUENTIAL: AtomicBool = AtomicBool::new(false);

    pub(super) fn sequential_only() -> bool {
        SEQUENTIAL.load(Ordering::Relaxed)
    }

    /// Set by a test to run the scalar compression on a CPU with AVX2.
    static SCALAR: AtomicBool = AtomicBool::new(false);

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    pub(super) fn scalar_only() -> bool {
        SCALAR.load(Ordering::Relaxed)
    }

    /// The AVX2 compression against the scalar definition, block for block,
    /// in both modes, over inputs from a fixed generator. Skipped on a CPU
    /// without AVX2, where nothing would run it.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn avx2_compression_matches_the_scalar_definition() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let mut x = ZERO_BLOCK;
            let mut y = ZERO_BLOCK;
            let mut out = ZERO_BLOCK;
            for w in 0..BLOCK_WORDS {
                x[w] = next();
                y[w] = next();
                out[w] = next();
            }
            let want = compress(&x, &y);
            let mut got = ZERO_BLOCK;
            // SAFETY: AVX2 was detected above.
            #[allow(unsafe_code)]
            unsafe {
                avx2::compress(&x, &y, &mut got, false)
            };
            assert_eq!(got, want);
            let mut want_xor = out;
            for (o, m) in want_xor.iter_mut().zip(want.iter()) {
                *o ^= m;
            }
            // SAFETY: this test returns early unless `is_x86_feature_detected!("avx2")` held
            // at the top of it, so the CPU has AVX2.
            #[allow(unsafe_code)]
            unsafe {
                avx2::compress(&x, &y, &mut out, true)
            };
            assert_eq!(out, want_xor);
        }
    }

    /// RFC 9106's vectors through the scalar compression, which on this
    /// machine nothing else would run.
    #[test]
    fn the_scalar_compression_matches_the_rfc() {
        SCALAR.store(true, Ordering::Relaxed);
        let got = rfc_tag(Variant::Argon2id);
        SCALAR.store(false, Ordering::Relaxed);
        assert_eq!(
            got,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// The two paths must agree. RFC 9106's vectors have four lanes, so they
    /// run threaded by default; here they run one lane at a time as well.
    /// Other tests running meanwhile may take either path, which is harmless
    /// since both must give the same answer.
    #[test]
    fn the_sequential_path_matches_the_rfc_too() {
        SEQUENTIAL.store(true, Ordering::Relaxed);
        let got = [
            rfc_tag(Variant::Argon2d),
            rfc_tag(Variant::Argon2i),
            rfc_tag(Variant::Argon2id),
        ];
        SEQUENTIAL.store(false, Ordering::Relaxed);
        let threaded = [
            rfc_tag(Variant::Argon2d),
            rfc_tag(Variant::Argon2i),
            rfc_tag(Variant::Argon2id),
        ];
        assert_eq!(got, threaded);
        assert_eq!(
            got[2],
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }
    use ic_core::codec::hex;

    /// RFC 9106 §5 uses one input set for all three variants.
    fn rfc_inputs() -> ([u8; 32], [u8; 16], [u8; 8], [u8; 12], Argon2Params) {
        (
            [0x01u8; 32],
            [0x02u8; 16],
            [0x03u8; 8],
            [0x04u8; 12],
            Argon2Params {
                memory_kib: 32,
                passes: 3,
                lanes: 4,
            },
        )
    }

    fn rfc_tag(variant: Variant) -> String {
        let (password, salt, secret, ad, params) = rfc_inputs();
        let mut out = [0u8; 32];
        argon2_full(variant, &params, &password, &salt, &secret, &ad, &mut out).unwrap();
        hex(&out)
    }

    /// RFC 9106 §5.3, the recommended variant.
    #[test]
    fn rfc9106_argon2id_vector() {
        assert_eq!(
            rfc_tag(Variant::Argon2id),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// RFC 9106 §5.1.
    #[test]
    fn rfc9106_argon2d_vector() {
        assert_eq!(
            rfc_tag(Variant::Argon2d),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
    }

    /// RFC 9106 §5.2.
    #[test]
    fn rfc9106_argon2i_vector() {
        assert_eq!(
            rfc_tag(Variant::Argon2i),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
    }

    #[test]
    fn is_deterministic() {
        let params = Argon2Params {
            memory_kib: 32,
            passes: 2,
            lanes: 1,
        };
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        argon2(Variant::Argon2id, &params, b"pw", b"salt-8-b", &mut a).unwrap();
        argon2(Variant::Argon2id, &params, b"pw", b"salt-8-b", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn every_input_changes_the_tag() {
        let params = Argon2Params {
            memory_kib: 32,
            passes: 1,
            lanes: 1,
        };
        let base = {
            let mut o = [0u8; 32];
            argon2(Variant::Argon2id, &params, b"pw", b"salt-8-b", &mut o).unwrap();
            o
        };

        let mut changed = [0u8; 32];
        argon2(Variant::Argon2id, &params, b"px", b"salt-8-b", &mut changed).unwrap();
        assert_ne!(base, changed, "password");

        argon2(Variant::Argon2id, &params, b"pw", b"salt-8-c", &mut changed).unwrap();
        assert_ne!(base, changed, "salt");

        let more = Argon2Params {
            passes: 2,
            ..params
        };
        argon2(Variant::Argon2id, &more, b"pw", b"salt-8-b", &mut changed).unwrap();
        assert_ne!(base, changed, "passes");

        let bigger = Argon2Params {
            memory_kib: 64,
            ..params
        };
        argon2(Variant::Argon2id, &bigger, b"pw", b"salt-8-b", &mut changed).unwrap();
        assert_ne!(base, changed, "memory");

        argon2(Variant::Argon2d, &params, b"pw", b"salt-8-b", &mut changed).unwrap();
        assert_ne!(base, changed, "variant");
    }

    /// The tag length is bound into H0, so a short tag is not a prefix of a
    /// long one.
    #[test]
    fn tag_length_is_bound_in() {
        let params = Argon2Params {
            memory_kib: 32,
            passes: 1,
            lanes: 1,
        };
        let mut short = [0u8; 16];
        let mut long = [0u8; 64];
        argon2(Variant::Argon2id, &params, b"pw", b"salt-8-b", &mut short).unwrap();
        argon2(Variant::Argon2id, &params, b"pw", b"salt-8-b", &mut long).unwrap();
        assert_ne!(&long[..16], &short[..]);
    }

    #[test]
    fn parallelism_is_honoured() {
        let one = Argon2Params {
            memory_kib: 64,
            passes: 1,
            lanes: 1,
        };
        let four = Argon2Params { lanes: 4, ..one };
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        argon2(Variant::Argon2id, &one, b"pw", b"salt-8-b", &mut a).unwrap();
        argon2(Variant::Argon2id, &four, b"pw", b"salt-8-b", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let ok = Argon2Params {
            memory_kib: 32,
            passes: 1,
            lanes: 1,
        };
        let mut out = [0u8; 32];

        assert!(
            argon2(Variant::Argon2id, &ok, b"pw", b"short", &mut out).is_err(),
            "salt"
        );
        assert!(
            argon2(Variant::Argon2id, &ok, b"pw", b"salt-8-b", &mut [0u8; 3]).is_err(),
            "tag too short"
        );

        let no_passes = Argon2Params { passes: 0, ..ok };
        assert!(no_passes.validate().is_err());

        let no_lanes = Argon2Params { lanes: 0, ..ok };
        assert!(no_lanes.validate().is_err());

        let too_little = Argon2Params {
            memory_kib: 4,
            lanes: 4,
            passes: 1,
        };
        assert!(too_little.validate().is_err());
    }

    #[test]
    fn recommended_parameters_validate() {
        Argon2Params::RECOMMENDED.validate().unwrap();
        Argon2Params::INTERACTIVE.validate().unwrap();
    }

    #[test]
    fn variant_identifiers() {
        assert_eq!(Variant::Argon2id.id(), "argon2id");
        assert_eq!(Variant::Argon2id.type_id(), 2);
        assert_eq!(Variant::Argon2i.type_id(), 1);
        assert_eq!(Variant::Argon2d.type_id(), 0);
    }

    /// Argon2id must index independently only for the first two slices of the
    /// first pass; that split is the entire difference from the other two.
    #[test]
    fn argon2id_switches_indexing_halfway() {
        assert!(Variant::Argon2id.independent(0, 0));
        assert!(Variant::Argon2id.independent(0, 1));
        assert!(!Variant::Argon2id.independent(0, 2));
        assert!(!Variant::Argon2id.independent(1, 0));

        assert!(Variant::Argon2i.independent(5, 3));
        assert!(!Variant::Argon2d.independent(0, 0));
    }
}
