//! The ARMv8 SHA-256 and SHA-512 block structure, shared by the real backend
//! and its model.
//!
//! # Why this is a macro
//!
//! The same arrangement as `ic_cipher`'s `aes::armv8_rounds`, for the same
//! reason. `super::aarch64` issues `SHA256H`, `SHA256H2`, `SHA256SU0`,
//! `SHA256SU1` and their SHA-512 counterparts; `super::armv8_model` emulates
//! those instructions from the pseudocode in the Arm Architecture Reference
//! Manual. Both expand the composition below, so the model checks the
//! structure the backend actually runs rather than a second transcription of
//! it. Writing them separately would risk a correct model beside an incorrect
//! backend, with a green test.
//!
//! Each macro takes `$ops`, the name of a module in scope providing the
//! operations. The real one is a set of `#[target_feature]` functions over
//! `uint32x4_t` / `uint64x2_t`; the model's is ordinary functions over
//! `[u32; 4]` / `[u64; 2]`. Lane 0 is the lowest-numbered element in both.
//!
//! # Constant time
//!
//! Every index and every branch below is a function of the round number alone.
//! The instructions themselves have data-independent timing; there is no
//! table indexed by message or state.

/// Four SHA-256 rounds on `m[$j]`, then the schedule update for the vector it
/// consumed, while one is still needed.
///
/// `$m` is the four-vector message window, `$k` the round constants, `$q` the
/// quad index (rounds `4q..4q+4`), and `$j` its position in the window. Kept as
/// a macro so every window index is a literal and the vectors stay in
/// registers.
macro_rules! armv8_sha256_quad {
    ($ops:ident, $m:ident, $k:expr, $abcd:ident, $efgh:ident, $q:expr, $j:literal) => {{
        let q: usize = $q;
        let wk = $ops::add(
            $m[$j],
            $ops::from_words([$k[4 * q], $k[4 * q + 1], $k[4 * q + 2], $k[4 * q + 3]]),
        );
        // W[16..64] in groups of four: SU0 adds sigma0 of the next four words,
        // SU1 adds W[t-7] and sigma1 of W[t-2]. Only the first twelve quads
        // have a successor to compute.
        if q < 12 {
            $m[$j] = $ops::sha256su1(
                $ops::sha256su0($m[$j], $m[($j + 1) % 4]),
                $m[($j + 2) % 4],
                $m[($j + 3) % 4],
            );
        }
        let abcd_in = $abcd;
        $abcd = $ops::sha256h($abcd, $efgh, wk);
        $efgh = $ops::sha256h2($efgh, abcd_in, wk);
    }};
}

/// Compress whole 64-byte blocks of `$data` into the SHA-256 state `$h`.
///
/// `$h: &mut [u32; 8]`, `$data: &[u8]` a whole number of blocks, `$k` the
/// sixty-four round constants.
macro_rules! armv8_sha256_blocks {
    ($ops:ident, $h:expr, $data:expr, $k:expr) => {{
        let h: &mut [u32; 8] = $h;
        let data: &[u8] = $data;
        // Lane 0 of ABCD is A, lane 0 of EFGH is E: the order SHA256H's
        // pseudocode reads them in, and the order the state is stored in.
        let mut abcd = $ops::from_words([h[0], h[1], h[2], h[3]]);
        let mut efgh = $ops::from_words([h[4], h[5], h[6], h[7]]);
        for block in data.chunks_exact(64) {
            let (abcd_in, efgh_in) = (abcd, efgh);
            let mut m = [
                $ops::load_be(&block[0..16]),
                $ops::load_be(&block[16..32]),
                $ops::load_be(&block[32..48]),
                $ops::load_be(&block[48..64]),
            ];
            for g in 0..4 {
                armv8_sha256_quad!($ops, m, $k, abcd, efgh, 4 * g, 0);
                armv8_sha256_quad!($ops, m, $k, abcd, efgh, 4 * g + 1, 1);
                armv8_sha256_quad!($ops, m, $k, abcd, efgh, 4 * g + 2, 2);
                armv8_sha256_quad!($ops, m, $k, abcd, efgh, 4 * g + 3, 3);
            }
            abcd = $ops::add(abcd, abcd_in);
            efgh = $ops::add(efgh, efgh_in);
        }
        let lo = $ops::to_words(abcd);
        let hi = $ops::to_words(efgh);
        h[..4].copy_from_slice(&lo);
        h[4..].copy_from_slice(&hi);
    }};
}

/// Two SHA-512 rounds on `s[$j]`, with the schedule update before it for
/// every pair after the eighth.
///
/// `$ab`, `$cd`, `$ef`, `$gh` name the four state vectors *in the roles they
/// play this pair*; successive pairs pass them rotated by one, which is how
/// the working variables move without any copies. `$p` is the pair index
/// (rounds `2p..2p+2`).
macro_rules! armv8_sha512_pair {
    ($ops:ident, $s:ident, $k:expr, $p:expr, $j:literal, $ab:ident, $cd:ident, $ef:ident, $gh:ident) => {{
        let p: usize = $p;
        if p >= 8 {
            // W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16], two
            // at a time: SU0 takes W[t-16..] and W[t-15..], SU1 W[t-2..] and
            // W[t-7..], the last straddling two vectors.
            $s[$j] = $ops::sha512su1(
                $ops::sha512su0($s[$j], $s[($j + 1) % 8]),
                $s[($j + 7) % 8],
                $ops::ext1($s[($j + 4) % 8], $s[($j + 5) % 8]),
            );
        }
        let kw = $ops::add($s[$j], $ops::from_words([$k[2 * p], $k[2 * p + 1]]));
        // SHA512H wants the two schedule words swapped, with h added to the
        // one used first.
        let sum = $ops::add($ops::ext1(kw, kw), $gh);
        let t = $ops::sha512h(sum, $ops::ext1($ef, $gh), $ops::ext1($cd, $ef));
        $gh = $ops::sha512h2(t, $cd, $ab);
        $cd = $ops::add($cd, t);
    }};
}

/// Compress whole 128-byte blocks of `$data` into the SHA-512 state `$h`.
///
/// `$h: &mut [u64; 8]`, `$data: &[u8]` a whole number of blocks, `$k` the
/// eighty round constants.
macro_rules! armv8_sha512_blocks {
    ($ops:ident, $h:expr, $data:expr, $k:expr) => {{
        let h: &mut [u64; 8] = $h;
        let data: &[u8] = $data;
        let mut ab = $ops::from_words([h[0], h[1]]);
        let mut cd = $ops::from_words([h[2], h[3]]);
        let mut ef = $ops::from_words([h[4], h[5]]);
        let mut gh = $ops::from_words([h[6], h[7]]);
        for block in data.chunks_exact(128) {
            let (ab_in, cd_in, ef_in, gh_in) = (ab, cd, ef, gh);
            let mut s = [
                $ops::load_be(&block[0..16]),
                $ops::load_be(&block[16..32]),
                $ops::load_be(&block[32..48]),
                $ops::load_be(&block[48..64]),
                $ops::load_be(&block[64..80]),
                $ops::load_be(&block[80..96]),
                $ops::load_be(&block[96..112]),
                $ops::load_be(&block[112..128]),
            ];
            // Forty pairs: five passes over the eight-vector window, the roles
            // rotating with period four.
            for g in 0..5 {
                armv8_sha512_pair!($ops, s, $k, 8 * g, 0, ab, cd, ef, gh);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 1, 1, gh, ab, cd, ef);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 2, 2, ef, gh, ab, cd);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 3, 3, cd, ef, gh, ab);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 4, 4, ab, cd, ef, gh);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 5, 5, gh, ab, cd, ef);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 6, 6, ef, gh, ab, cd);
                armv8_sha512_pair!($ops, s, $k, 8 * g + 7, 7, cd, ef, gh, ab);
            }
            ab = $ops::add(ab, ab_in);
            cd = $ops::add(cd, cd_in);
            ef = $ops::add(ef, ef_in);
            gh = $ops::add(gh, gh_in);
        }
        for (i, v) in [ab, cd, ef, gh].into_iter().enumerate() {
            h[2 * i..2 * i + 2].copy_from_slice(&$ops::to_words(v));
        }
    }};
}

pub(super) use {armv8_sha256_blocks, armv8_sha256_quad, armv8_sha512_blocks, armv8_sha512_pair};
