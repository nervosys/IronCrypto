//! Eight-block-at-a-time ChaCha20, on AVX2.
//!
//! # The layout, which is the whole idea
//!
//! The obvious way to vectorise ChaCha is to put one block's sixteen state
//! words into four registers and shuffle between rounds, because the column
//! rounds and the diagonal rounds touch different groupings. That works and it
//! spends a good deal of its time shuffling.
//!
//! This does the other thing: sixteen registers, one per *state word*, each
//! holding that word for eight different blocks. Every quarter-round is then
//! elementwise -- add, xor, rotate -- with no shuffle anywhere in the twenty
//! rounds, because lane `i` only ever touches lane `i`. The blocks differ only
//! in their counter, which is the one register that starts with eight distinct
//! values.
//!
//! The cost is moved to the end, where the sixteen by-word registers have to
//! become eight by-block outputs. That is done here by storing each register
//! and gathering, rather than by a register transpose. A transpose would be
//! faster and is where this kind of code goes wrong; the rounds dominate either
//! way, so the simpler form is worth more than the last few percent.
//!
//! # Safety
//!
//! `unsafe` because `#[target_feature]` requires it: the caller must not invoke
//! this without AVX2. [`super::chacha20_xor`] checks once and caches. The
//! intrinsics are safe once the feature is enabled in scope, so only the
//! raw-pointer loads and stores are inside an `unsafe` block.
//!
//! # Constant-time properties
//!
//! Unchanged from the scalar path, and for the same reason: ChaCha has no
//! data-dependent branch and no table. It adds, xors and rotates fixed
//! distances regardless of the key.

use core::arch::x86_64::*;

/// Blocks produced per iteration.
pub const LANES: usize = 8;

/// Bytes produced per iteration.
pub const STRIDE: usize = LANES * 64;

#[inline(always)]
fn rotl(x: __m256i, n: i32) -> __m256i {
    // Two of the four distances are byte permutations, which is one
    // instruction instead of shift-shift-or. The other two are the shifts.
    // `n` is a literal at every call site, so this match disappears.
    match n {
        16 => unsafe {
            _mm256_shuffle_epi8(
                x,
                _mm256_set_epi8(
                    13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11,
                    10, 5, 4, 7, 6, 1, 0, 3, 2,
                ),
            )
        },
        8 => unsafe {
            _mm256_shuffle_epi8(
                x,
                _mm256_set_epi8(
                    14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8,
                    11, 6, 5, 4, 7, 2, 1, 0, 3,
                ),
            )
        },
        12 => unsafe { _mm256_or_si256(_mm256_slli_epi32(x, 12), _mm256_srli_epi32(x, 20)) },
        7 => unsafe { _mm256_or_si256(_mm256_slli_epi32(x, 7), _mm256_srli_epi32(x, 25)) },
        _ => unreachable!(),
    }
}

/// [`eight_blocks`]' keystream, word `i` of the eight blocks in row `i`.
/// Wiped by sixteen 32-byte volatile stores, once per message. A first
/// form -- a byte array, gathered from by byte slices and wiped eight bytes
/// at a time -- measured 4 to 7 percent slower on 1 KiB messages without
/// AVX-512; this one, the original layout and gather with a wider wipe,
/// measured at parity.
#[repr(C, align(32))]
pub(crate) struct Words(pub(crate) [[u32; LANES]; 16]);

impl Words {
    pub(crate) const fn new() -> Self {
        Words([[0; LANES]; 16])
    }
}

impl ic_core::Zeroize for Words {
    fn zeroize(&mut self) {
        for row in self.0.iter_mut() {
            // SAFETY: a row is 32 bytes, 32-byte aligned (`repr(align(32))`
            // and a row size of 32), valid and uniquely borrowed, and
            // `[u64; 4]` has the same size and a smaller alignment.
            unsafe { core::ptr::write_volatile(row.as_mut_ptr().cast::<[u64; 4]>(), [0; 4]) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// XOR `data` with the keystream for `LANES` blocks starting at `counter`.
///
/// `words` is where the keystream is stored word by word and gathered from
/// (see the module note): it is left holding the keystream, and the caller
/// wipes it once its last group is done (`chacha::xor_keystream` holds it
/// in a `Scratch`), rather than every call paying for a wipe.
///
/// # Safety
///
/// The CPU must support AVX2. `data` must be exactly [`STRIDE`] bytes.
#[target_feature(enable = "avx2")]
pub unsafe fn eight_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
    data: &mut [u8],
    words: &mut Words,
) {
    debug_assert_eq!(data.len(), STRIDE);

    let k = |i: usize| -> u32 {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
    };
    let n = |i: usize| -> u32 {
        u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ])
    };

    // The starting state, one register per word. Everything is the same across
    // lanes except word 12, the counter.
    let splat = |v: u32| _mm256_set1_epi32(v as i32);
    let start: [__m256i; 16] = [
        splat(0x6170_7865),
        splat(0x3320_646e),
        splat(0x7962_2d32),
        splat(0x6b20_6574),
        splat(k(0)),
        splat(k(1)),
        splat(k(2)),
        splat(k(3)),
        splat(k(4)),
        splat(k(5)),
        splat(k(6)),
        splat(k(7)),
        {
            _mm256_setr_epi32(
                counter as i32,
                counter.wrapping_add(1) as i32,
                counter.wrapping_add(2) as i32,
                counter.wrapping_add(3) as i32,
                counter.wrapping_add(4) as i32,
                counter.wrapping_add(5) as i32,
                counter.wrapping_add(6) as i32,
                counter.wrapping_add(7) as i32,
            )
        },
        splat(n(0)),
        splat(n(1)),
        splat(n(2)),
    ];

    let mut v = start;

    macro_rules! quarter {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {{
            v[$a] = _mm256_add_epi32(v[$a], v[$b]);
            v[$d] = rotl(_mm256_xor_si256(v[$d], v[$a]), 16);
            v[$c] = _mm256_add_epi32(v[$c], v[$d]);
            v[$b] = rotl(_mm256_xor_si256(v[$b], v[$c]), 12);
            v[$a] = _mm256_add_epi32(v[$a], v[$b]);
            v[$d] = rotl(_mm256_xor_si256(v[$d], v[$a]), 8);
            v[$c] = _mm256_add_epi32(v[$c], v[$d]);
            v[$b] = rotl(_mm256_xor_si256(v[$b], v[$c]), 7);
        }};
    }

    for _ in 0..10 {
        // Columns.
        quarter!(0, 4, 8, 12);
        quarter!(1, 5, 9, 13);
        quarter!(2, 6, 10, 14);
        quarter!(3, 7, 11, 15);
        // Diagonals.
        quarter!(0, 5, 10, 15);
        quarter!(1, 6, 11, 12);
        quarter!(2, 7, 8, 13);
        quarter!(3, 4, 9, 14);
    }

    // Feed-forward, then back to block order. See the module note: stored and
    // gathered rather than transposed in registers.
    let words = &mut words.0;
    for i in 0..16 {
        let sum = _mm256_add_epi32(v[i], start[i]);
        // SAFETY: `words[i]` is eight `u32`, which is the width of the store.
        unsafe { _mm256_storeu_si256(words[i].as_mut_ptr() as *mut __m256i, sum) };
    }

    for (lane, block) in data.chunks_exact_mut(64).enumerate() {
        for (word, out) in block.chunks_exact_mut(4).enumerate() {
            let ks = words[word][lane].to_le_bytes();
            for (d, k) in out.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
    }
}

/// One double round on two blocks side by side.
///
/// The other layout: each register holds one *row* of the 4x4 state, for two
/// blocks, one in each 128-bit lane. The column round is then elementwise;
/// the diagonal round rotates rows 1 to 3 by one, two and three words
/// (`vpshufd`, within each lane), runs the same elementwise steps, and
/// rotates them back. Six shuffles per double round, which the by-word
/// layout above does not pay -- but this needs only four registers where
/// that needs sixteen, and it produces two blocks rather than eight. For a
/// message of a block or three that is the whole point: the eight-block
/// kernel would compute five to seven blocks that nothing uses.
///
/// A macro rather than a function so that the intrinsics expand inside the
/// caller's `#[target_feature(enable = "avx2")]`.
macro_rules! double_round {
    ($v:expr) => {{
        macro_rules! steps {
            () => {{
                $v[0] = _mm256_add_epi32($v[0], $v[1]);
                $v[3] = rotl(_mm256_xor_si256($v[3], $v[0]), 16);
                $v[2] = _mm256_add_epi32($v[2], $v[3]);
                $v[1] = rotl(_mm256_xor_si256($v[1], $v[2]), 12);
                $v[0] = _mm256_add_epi32($v[0], $v[1]);
                $v[3] = rotl(_mm256_xor_si256($v[3], $v[0]), 8);
                $v[2] = _mm256_add_epi32($v[2], $v[3]);
                $v[1] = rotl(_mm256_xor_si256($v[1], $v[2]), 7);
            }};
        }
        // Columns.
        steps!();
        // Diagonals: word j of row i moves to column j - i, and back.
        $v[1] = _mm256_shuffle_epi32($v[1], 0b00_11_10_01);
        $v[2] = _mm256_shuffle_epi32($v[2], 0b01_00_11_10);
        $v[3] = _mm256_shuffle_epi32($v[3], 0b10_01_00_11);
        steps!();
        $v[1] = _mm256_shuffle_epi32($v[1], 0b10_01_00_11);
        $v[2] = _mm256_shuffle_epi32($v[2], 0b01_00_11_10);
        $v[3] = _mm256_shuffle_epi32($v[3], 0b00_11_10_01);
    }};
}

/// Store a finished pair of blocks, in block order: the low lanes of the
/// four rows are the first block, the high lanes the second.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn store_pair(v: &[__m256i; 4], out: &mut [u8]) {
    debug_assert!(out.len() >= 128);
    let p = out.as_mut_ptr() as *mut __m256i;
    // SAFETY: `out` holds at least 128 bytes, four unaligned 32-byte stores.
    unsafe {
        _mm256_storeu_si256(p, _mm256_permute2x128_si256(v[0], v[1], 0x20));
        _mm256_storeu_si256(p.add(1), _mm256_permute2x128_si256(v[2], v[3], 0x20));
        _mm256_storeu_si256(p.add(2), _mm256_permute2x128_si256(v[0], v[1], 0x31));
        _mm256_storeu_si256(p.add(3), _mm256_permute2x128_si256(v[2], v[3], 0x31));
    }
}

/// How many blocks [`short_blocks`] computes: two, or four.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pairs {
    /// Blocks `counter` and `counter + 1`: 128 bytes.
    One,
    /// Blocks `counter` to `counter + 3`: 256 bytes, as two independent
    /// pairs whose rounds the CPU overlaps.
    Two,
}

/// The four starting rows of the pair of blocks at `counter` and
/// `counter + 1`, one block in each 128-bit lane.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn start(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [__m256i; 4] {
    let k = |i: usize| -> i32 {
        u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]) as i32
    };
    let n = |i: usize| -> i32 {
        u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]) as i32
    };
    [
        _mm256_setr_epi32(
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
        ),
        _mm256_setr_epi32(k(0), k(1), k(2), k(3), k(0), k(1), k(2), k(3)),
        _mm256_setr_epi32(k(4), k(5), k(6), k(7), k(4), k(5), k(6), k(7)),
        _mm256_setr_epi32(
            counter as i32,
            n(0),
            n(1),
            n(2),
            counter.wrapping_add(1) as i32,
            n(0),
            n(1),
            n(2),
        ),
    ]
}

/// Ten times, written out: the twenty rounds with no loop, so the kernels
/// below are straight-line code with no branch at all.
macro_rules! ten {
    ($($e:tt)*) => {
        $($e)* $($e)* $($e)* $($e)* $($e)* $($e)* $($e)* $($e)* $($e)* $($e)*
    };
}

/// Blocks `counter` and `counter + 1`, in order, into `out`.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn pair(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 128]) {
    // SAFETY: AVX2, as the caller guarantees.
    let a0 = unsafe { start(key, nonce, counter) };
    let mut a = a0;
    ten! { double_round!(a); }
    for (x, s) in a.iter_mut().zip(a0) {
        *x = _mm256_add_epi32(*x, s);
    }
    // SAFETY: AVX2 is enabled here; `out` is 128 bytes.
    unsafe { store_pair(&a, out) };
}

/// Blocks `counter` to `counter + 3`, in order, into `out`: two independent
/// pairs, a double round of each in turn, which the CPU overlaps.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn two_pairs(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 256]) {
    // SAFETY: AVX2, as the caller guarantees.
    let a0 = unsafe { start(key, nonce, counter) };
    // SAFETY: as above.
    let b0 = unsafe { start(key, nonce, counter.wrapping_add(2)) };
    let (mut a, mut b) = (a0, b0);
    ten! { double_round!(a); double_round!(b); }
    for (x, s) in a.iter_mut().zip(a0) {
        *x = _mm256_add_epi32(*x, s);
    }
    for (x, s) in b.iter_mut().zip(b0) {
        *x = _mm256_add_epi32(*x, s);
    }
    // SAFETY: AVX2 is enabled here; each half of `out` is 128 bytes.
    unsafe {
        store_pair(&a, &mut out[..128]);
        store_pair(&b, &mut out[128..]);
    }
}

/// Keystream blocks from `counter`, in order, into the front of `out`: 128
/// bytes for [`Pairs::One`], all 256 for [`Pairs::Two`]. The counter of each
/// later block wraps rather than stopping, so a caller that uses fewer blocks
/// than this computes must check its own count, as `xor_keystream` does.
///
/// For the short messages the eight-block kernel is too wide for: an AEAD
/// takes its Poly1305 key from block 0 and the first three blocks of message
/// keystream from the same call.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn short_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
    pairs: Pairs,
    out: &mut [u8; 256],
) {
    match pairs {
        Pairs::One => {
            if let Some(first) = out.first_chunk_mut::<128>() {
                // SAFETY: AVX2, as the caller guarantees.
                unsafe { pair(key, nonce, counter, first) };
            }
        }
        // SAFETY: AVX2, as the caller guarantees.
        Pairs::Two => unsafe { two_pairs(key, nonce, counter, out) },
    }
}
