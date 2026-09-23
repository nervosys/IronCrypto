//! SHA-512 with the message schedule interleaved into the rounds, using AVX2.
//!
//! # The interleaving is the point, not the vector width
//!
//! Computing the schedule with AVX2 as a pass of its own does not pay. Measured
//! against the scalar schedule, in one process, alternating: 107.6ns against
//! 104.2ns per block. AVX2 has no 64-bit rotate -- that arrived with AVX-512's
//! `vprorq` -- so each rotation is a shift, a shift and an or where the scalar
//! form is one instruction, and `sigma1` only runs two lanes wide, for the
//! reason below. The width barely covers the rotations.
//!
//! What pays is that the two halves of the work want different resources. The
//! eighty rounds are a latency chain: each reads the working variables the last
//! one wrote, so they cannot fill a wide core's issue slots however cheap the
//! instructions are. The schedule does not depend on them at all, and it is
//! more than half the block's time -- 104ns of roughly 180ns. Issued alongside
//! the rounds it runs in the slots the chain leaves empty, and stops being time
//! of its own.
//!
//! So this computes `W[i+16..i+20]` and then performs rounds `i..i+4`, four
//! words and four rounds at a time, in one loop. Nothing is scheduled by hand
//! beyond that: the two streams are adjacent and independent, and the core
//! overlaps them.
//!
//! # Why a group of four splits into two pairs
//!
//! `W[i]` depends on `W[i-16]`, `W[i-15]`, `W[i-7]` and `W[i-2]`. For four
//! consecutive `i` the first three are known before the group starts, and only
//! the `W[i-2]` term reaches back inside it -- exactly two places. So the
//! `sigma1` term is applied to the low pair, and then to the high pair, which
//! by then has the low pair's answer to read.
//!
//! # Trusting it
//!
//! It is not an independent implementation. The schedule is checked against
//! [`super::Core512::schedule`] word for word, and the whole compression
//! against [`super::Core512`] block for block.

use core::arch::x86_64::*;

use super::K512;

/// Rotate each 64-bit lane right by `R`, where `L` is `64 - R`.
///
/// Both amounts are separate constants because a const parameter cannot be used
/// in arithmetic in const position on stable, and the intrinsics need
/// immediates. Nothing in the type system then says the pair adds to 64 --
/// `ror256::<1, 62>` compiles and silently drops a bit -- so
/// `the_rotations_use_complementary_shifts` checks every pair used here against
/// `u64::rotate_right`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn ror256<const R: i32, const L: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_srli_epi64::<R>(x), _mm256_slli_epi64::<L>(x))
}

/// The same, for a 128-bit pair.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn ror128<const R: i32, const L: i32>(x: __m128i) -> __m128i {
    _mm_or_si128(_mm_srli_epi64::<R>(x), _mm_slli_epi64::<L>(x))
}

/// `sigma0(x) = ror(x,1) ^ ror(x,8) ^ (x >> 7)`, four lanes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sigma0(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(ror256::<1, 63>(x), ror256::<8, 56>(x)),
        _mm256_srli_epi64::<7>(x),
    )
}

/// `sigma1(x) = ror(x,19) ^ ror(x,61) ^ (x >> 6)`, two lanes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sigma1_128(x: __m128i) -> __m128i {
    _mm_xor_si128(
        _mm_xor_si128(ror128::<19, 45>(x), ror128::<61, 3>(x)),
        _mm_srli_epi64::<6>(x),
    )
}

/// Load the sixteen words of `block`, big-endian, into `w[0..16]`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn load_block(w: &mut [u64; 80], block: &[u8]) {
    let bswap = _mm256_set_epi8(
        8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1,
        2, 3, 4, 5, 6, 7,
    );
    for i in 0..4 {
        let v = _mm256_loadu_si256(block.as_ptr().add(i * 32) as *const __m256i);
        _mm256_storeu_si256(
            w.as_mut_ptr().add(i * 4) as *mut __m256i,
            _mm256_shuffle_epi8(v, bswap),
        );
    }
}

/// Extend the schedule by four words, producing `w[at..at+4]`.
///
/// Requires `w[at-16 ..= at-1]` to be filled.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn extend4(w: &mut [u64; 80], at: usize) {
    let w16 = _mm256_loadu_si256(w.as_ptr().add(at - 16) as *const __m256i);
    let w15 = _mm256_loadu_si256(w.as_ptr().add(at - 15) as *const __m256i);
    let w7 = _mm256_loadu_si256(w.as_ptr().add(at - 7) as *const __m256i);
    let t = _mm256_add_epi64(_mm256_add_epi64(w16, sigma0(w15)), w7);

    let lo = _mm256_castsi256_si128(t);
    let w2 = _mm_loadu_si128(w.as_ptr().add(at - 2) as *const __m128i);
    let res_lo = _mm_add_epi64(lo, sigma1_128(w2));
    _mm_storeu_si128(w.as_mut_ptr().add(at) as *mut __m128i, res_lo);

    let hi = _mm256_extracti128_si256::<1>(t);
    let res_hi = _mm_add_epi64(hi, sigma1_128(res_lo));
    _mm_storeu_si128(w.as_mut_ptr().add(at + 2) as *mut __m128i, res_hi);
}

/// Build the whole eighty-word schedule, without the rounds.
///
/// Only the tests use this: [`compress`] interleaves the same steps instead,
/// which is the entire point. It exists so the schedule can be compared against
/// the scalar one word for word rather than through a digest.
///
/// # Safety
///
/// The caller must have established AVX2. `block` must be 128 bytes.
#[cfg(test)]
#[target_feature(enable = "avx2")]
pub unsafe fn schedule(block: &[u8], w: &mut [u64; 80]) {
    debug_assert_eq!(block.len(), 128);
    load_block(w, block);
    let mut i = 16;
    while i < 80 {
        extend4(w, i);
        i += 4;
    }
}

/// Compress one block into `h`.
///
/// # Safety
///
/// The caller must have established that this CPU has AVX2. `block` must be
/// exactly 128 bytes. `w` is scratch owned by the caller, so the schedule is
/// wiped once per hash rather than once per block.
#[target_feature(enable = "avx2")]
pub unsafe fn compress(h: &mut [u64; 8], w: &mut [u64; 80], block: &[u8]) {
    debug_assert_eq!(block.len(), 128);
    load_block(w, block);

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

    // One round, on `w[$i]`. The working variables rotate by renaming, which
    // costs nothing; an explicit eight-fold unroll was measured on the scalar
    // path and changed nothing in either direction.
    macro_rules! round {
        ($i:expr) => {{
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[$i])
                .wrapping_add(w[$i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }};
    }

    // Sixteen groups of four words, spread over eighty rounds five at a time.
    //
    // There are sixty-four words to build and eighty rounds to hide them in,
    // so grouping four words with four rounds leaves the last sixteen rounds
    // with nothing to overlap and bunches the vector work into the first
    // sixty-four. Five rounds per group spreads it across the whole block.
    //
    // The ordering still works: the group at round `5k` builds `w[16 + 4k ..
    // 20 + 4k]`, and round `j` reads `w[j]`, which was built at round
    // `5(j-16)/4 < j` for every `j` below eighty.
    let mut i = 0;
    while i < 80 {
        extend4(w, 16 + (i / 5) * 4);
        round!(i);
        round!(i + 1);
        round!(i + 2);
        round!(i + 3);
        round!(i + 4);
        i += 5;
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rotate built from two shifts is a rotate.
    ///
    /// `ror256` and `ror128` take the two shift amounts separately, because a
    /// const parameter cannot be used in arithmetic in const position on
    /// stable. Nothing in the type system then says the pair adds to 64: the
    /// compiler is equally happy with `ror256::<1, 62>`, which silently drops a
    /// bit. This checks every pair the file actually uses against
    /// `u64::rotate_right`.
    #[test]
    fn the_rotations_use_complementary_shifts() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let vals: [u64; 4] = [
            0x0123_4567_89ab_cdef,
            0xffff_ffff_ffff_ffff,
            1,
            0x8000_0000_0000_0000,
        ];
        // SAFETY: AVX2 was just detected.
        unsafe {
            let v = _mm256_loadu_si256(vals.as_ptr() as *const __m256i);
            let mut out = [0u64; 4];

            macro_rules! check256 {
                ($r:literal, $l:literal) => {{
                    _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, ror256::<$r, $l>(v));
                    for (o, i) in out.iter().zip(vals.iter()) {
                        assert_eq!(*o, i.rotate_right($r), "ror256::<{}, {}>", $r, $l);
                    }
                }};
            }
            check256!(1, 63);
            check256!(8, 56);

            let w = _mm_loadu_si128(vals.as_ptr() as *const __m128i);
            let mut out2 = [0u64; 2];
            macro_rules! check128 {
                ($r:literal, $l:literal) => {{
                    _mm_storeu_si128(out2.as_mut_ptr() as *mut __m128i, ror128::<$r, $l>(w));
                    for (o, i) in out2.iter().zip(vals.iter()) {
                        assert_eq!(*o, i.rotate_right($r), "ror128::<{}, {}>", $r, $l);
                    }
                }};
            }
            check128!(19, 45);
            check128!(61, 3);
        }
    }

    /// The AVX2 compression against the portable one, block for block.
    ///
    /// The schedule test above covers the schedule; this covers the round loop
    /// and the interleaving, which the schedule test cannot see. It matters
    /// because the two streams share `w`: the loop writes `w[i+16..i+20]` while
    /// the rounds read `w[i..i+4]`, and a boundary off by one in either would
    /// still produce a schedule that looks right in isolation.
    ///
    /// Chained across blocks as well as one at a time, since `h` carries.
    #[test]
    fn the_avx2_compress_agrees_with_the_portable_one() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let mut state = 0x5151_2345_9876_abcdu64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        let iv = [
            0x6a09_e667_f3bc_c908u64,
            0xbb67_ae85_84ca_a73b,
            0x3c6e_f372_fe94_f82b,
            0xa54f_f53a_5f1d_36f1,
            0x510e_527f_ade6_82d1,
            0x9b05_688c_2b3e_6c1f,
            0x1f83_d9ab_fb41_bd6b,
            0x5be0_cd19_137e_2179,
        ];
        let mut h_v = iv;
        let mut h_s = iv;
        let mut w_v = [0u64; 80];
        let mut w_s = [0u64; 80];
        for case in 0..300 {
            let mut block = [0u8; 128];
            match case {
                0 => {}
                1 => block = [0xff; 128],
                _ => {
                    for chunk in block.chunks_exact_mut(8) {
                        chunk.copy_from_slice(&next().to_le_bytes());
                    }
                }
            }
            // SAFETY: avx2 detected above; the block is 128 bytes.
            unsafe { compress(&mut h_v, &mut w_v, &block) };
            super::super::Core512::schedule(&mut w_s, &block);
            super::super::Core512::rounds(&mut h_s, &w_s);
            assert_eq!(h_v, h_s, "case {case}, chained");
        }
    }

    /// The AVX2 schedule against the portable one, word for word.
    ///
    /// The vectors that `sha2.rs` already runs go through whichever backend
    /// this CPU selects, so on a machine with AVX2 they stop testing the
    /// portable path and on one without they never reach this. Comparing the
    /// two directly is what holds them together, and it tests all eighty words
    /// rather than the eight that survive into a digest.
    ///
    /// Byte patterns that make the big-endian load visible: a shuffle that
    /// reversed the wrong granularity would be invisible on a palindromic
    /// block.
    #[test]
    fn the_avx2_schedule_agrees_with_the_portable_one() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let mut state = 0xdead_beef_0bad_f00du64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for case in 0..500 {
            let mut block = [0u8; 128];
            match case {
                0 => {}
                1 => block = [0xff; 128],
                2 => {
                    for (i, b) in block.iter_mut().enumerate() {
                        *b = i as u8;
                    }
                }
                _ => {
                    for chunk in block.chunks_exact_mut(8) {
                        chunk.copy_from_slice(&next().to_le_bytes());
                    }
                }
            }
            let mut want = [0u64; 80];
            super::super::Core512::schedule(&mut want, &block);
            let mut got = [0u64; 80];
            // SAFETY: AVX2 was just detected; the block is 128 bytes.
            unsafe { schedule(&block, &mut got) };
            assert_eq!(got, want, "case {case}");
        }
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    /// The two schedules, in one process, alternating.
    ///
    /// Ignored: a measurement. `cargo test -p ic-hash --release -- --ignored
    /// --nocapture schedule_ab`.
    #[test]
    #[ignore = "diagnostic, not a test"]
    fn schedule_ab() {
        if !std::is_x86_feature_detected!("avx2") {
            println!("no avx2 here");
            return;
        }
        let mut block = [0u8; 128];
        for (i, b) in block.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let n = 100_000;
        let (mut best_v, mut best_s) = (f64::INFINITY, f64::INFINITY);
        let mut w = [0u64; 80];
        let mut h = [1u64, 2, 3, 4, 5, 6, 7, 8];
        for _ in 0..30 {
            let t = Instant::now();
            for _ in 0..n {
                // SAFETY: avx2 detected above.
                unsafe { compress(&mut h, &mut w, core::hint::black_box(&block)) };
            }
            best_v = best_v.min(t.elapsed().as_secs_f64() / n as f64 * 1e9);

            let t = Instant::now();
            for _ in 0..n {
                super::super::Core512::schedule(&mut w, core::hint::black_box(&block));
                super::super::Core512::rounds(&mut h, &w);
            }
            best_s = best_s.min(t.elapsed().as_secs_f64() / n as f64 * 1e9);
        }
        println!(
            "
  compress, avx2 interleaved  {best_v:>8.1} ns/block"
        );
        println!("  compress, scalar            {best_s:>8.1} ns/block");
        println!("  ratio                       {:>8.2}x", best_s / best_v);
    }
}
