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

/// XOR `data` with the keystream for `LANES` blocks starting at `counter`.
///
/// # Safety
///
/// The CPU must support AVX2. `data` must be exactly [`STRIDE`] bytes.
#[target_feature(enable = "avx2")]
pub unsafe fn eight_blocks(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
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
    let mut words = [[0u32; LANES]; 16];
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
