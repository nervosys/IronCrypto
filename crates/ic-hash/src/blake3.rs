//! BLAKE3: a hash, a keyed hash, a key derivation function and an
//! extendable output, from one tree of BLAKE2s-like compressions.
//!
//! **Not FIPS-approved**, and no standards body defines it: the
//! specification is its authors' (O'Connor, Aumasson, Neves and
//! Wilcox-O'Hearn, 2020). Under a FIPS policy use SHA-2 or SHA-3.
//!
//! ```
//! use ic_hash::Blake3;
//! let digest = Blake3::hash(b"message");
//! let mac = Blake3::keyed_hash(&[7u8; 32], b"message");
//! let mut key = [0u8; 32];
//! Blake3::derive_key("example.com 2026-10-12 session keys", b"input key material", &mut key);
//! # let _ = (digest, mac);
//! ```
//!
//! This is the portable, serial form: a transcription of the authors'
//! reference implementation (`reference_impl/reference_impl.rs`, section 5.1
//! of the specification), with the same names, so the two read side by side.
//! It computes the same tree as the SIMD and multi-threaded implementations,
//! one chunk at a time, so it is not their speed on large inputs.

use ic_core::{Result, Zeroize};

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// The IV, SHA-256's, as BLAKE2s's is.
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The mixing function, G, on a column or a diagonal.
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline(always)]
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

/// Seven rounds, the message permuted between each.
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let [counter_low, counter_high] = crate::blake2::counter_words(counter);
    #[rustfmt::skip]
    let mut state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low, counter_high, block_len, flags,
    ];
    let mut block = *block_words;
    for r in 0..7 {
        round(&mut state, &block);
        if r < 6 {
            permute(&mut block);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    block.zeroize();
    state
}

fn first_8_words(compression_output: &[u32; 16]) -> [u32; 8] {
    let mut out = [0u32; 8];
    out.copy_from_slice(&compression_output[..8]);
    out
}

fn words_from_le_bytes(bytes: &[u8], words: &mut [u32]) {
    for (four, word) in bytes.chunks_exact(4).zip(words) {
        *word = u32::from_le_bytes([four[0], four[1], four[2], four[3]]);
    }
}

/// A node just before the choice between a chaining value and, with ROOT,
/// output bytes.
#[derive(Clone)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Drop for Output {
    fn drop(&mut self) {
        self.input_chaining_value.zeroize();
        self.block_words.zeroize();
    }
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let mut words = compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let cv = first_8_words(&words);
        words.zeroize();
        cv
    }

    /// The 64-byte output block numbered `counter`.
    fn root_block(&self, counter: u64) -> [u8; 2 * OUT_LEN] {
        let mut words = compress(
            &self.input_chaining_value,
            &self.block_words,
            counter,
            self.block_len,
            self.flags | ROOT,
        );
        let mut out = [0u8; 2 * OUT_LEN];
        for (word, o) in words.iter().zip(out.chunks_exact_mut(4)) {
            o.copy_from_slice(&word.to_le_bytes());
        }
        words.zeroize();
        out
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl Drop for ChunkState {
    fn drop(&mut self) {
        self.chaining_value.zeroize();
        self.block.zeroize();
    }
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // A full buffer with more input coming is not the chunk's end.
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [0u32; 16];
                words_from_le_bytes(&self.block, &mut block_words);
                let mut words = compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.chaining_value = first_8_words(&words);
                words.zeroize();
                block_words.zeroize();
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = core::cmp::min(BLOCK_LEN - self.block_len as usize, input.len());
            self.block[self.block_len as usize..][..take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        words_from_le_bytes(&self.block, &mut block_words);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left: [u32; 8], right: [u32; 8], key_words: [u32; 8], flags: u32) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

/// An incremental BLAKE3 hasher, in any of its three modes.
#[derive(Clone)]
pub struct Blake3 {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    // Room for 54 subtree chaining values: 2^54 chunks is 2^64 bytes.
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: u8,
    flags: u32,
}

impl Drop for Blake3 {
    fn drop(&mut self) {
        self.key_words.zeroize();
        for cv in self.cv_stack.iter_mut() {
            cv.zeroize();
        }
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    /// The default output length in bytes.
    pub const OUT_LEN: usize = OUT_LEN;
    /// The key length of the keyed mode.
    pub const KEY_LEN: usize = KEY_LEN;

    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    /// A hasher for the plain hash function.
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// A hasher for the keyed hash, BLAKE3's MAC and PRF.
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let mut key_words = [0u32; 8];
        words_from_le_bytes(key, &mut key_words);
        let h = Self::new_internal(key_words, KEYED_HASH);
        key_words.zeroize();
        h
    }

    /// A hasher for the key derivation function. The context string should
    /// be hard-coded, globally unique and specific to the application, as
    /// "example.com 2026-10-12 session keys"; the key material is what is
    /// then fed to [`update`](Self::update).
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self::new_internal(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context.as_bytes());
        // A step inside the constructor, not output, so not refused.
        let mut context_key = [0u8; OUT_LEN];
        context_hasher.finalize_xof().fill_inner(&mut context_key);
        let mut key_words = [0u32; 8];
        words_from_le_bytes(&context_key, &mut key_words);
        let h = Self::new_internal(key_words, DERIVE_KEY_MATERIAL);
        context_key.zeroize();
        key_words.zeroize();
        h
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    /// Section 5.1.2: each completed subtree is merged as the chunk count's
    /// trailing zero bits say.
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop_stack();
            new_cv = parent_output(left, new_cv, self.key_words, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Absorb more input. May be called any number of times.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // A complete chunk with more input coming is not the root.
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }
            let take = core::cmp::min(CHUNK_LEN - self.chunk_state.len(), input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    fn root_output(&self) -> Output {
        let mut output = self.chunk_state.output();
        let mut remaining = self.cv_stack_len as usize;
        while remaining > 0 {
            remaining -= 1;
            output = parent_output(
                self.cv_stack[remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            );
        }
        output
    }

    /// The 32-byte digest. The hasher is left as it was, so more input may
    /// follow. Refuses with `ModuleErrorState` once the module has failed.
    pub fn finalize(&self) -> Result<[u8; OUT_LEN]> {
        let mut out = [0u8; OUT_LEN];
        self.finalize_xof().fill(&mut out)?;
        Ok(out)
    }

    /// The extendable output: as many bytes as wanted, of which the first 32
    /// are [`finalize`](Self::finalize)'s.
    pub fn finalize_xof(&self) -> Blake3Reader {
        Blake3Reader {
            output: self.root_output(),
            counter: 0,
            block: [0u8; 2 * OUT_LEN],
            used: 2 * OUT_LEN,
        }
    }

    /// One-shot hash.
    pub fn hash(data: &[u8]) -> Result<[u8; OUT_LEN]> {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    /// One-shot keyed hash.
    pub fn keyed_hash(key: &[u8; KEY_LEN], data: &[u8]) -> Result<[u8; OUT_LEN]> {
        let mut h = Self::new_keyed(key);
        h.update(data);
        h.finalize()
    }

    /// One-shot key derivation, any output length.
    pub fn derive_key(context: &str, key_material: &[u8], out: &mut [u8]) -> Result<()> {
        let mut h = Self::new_derive_key(context);
        h.update(key_material);
        h.finalize_xof().fill(out)
    }
}

/// BLAKE3's extendable output, read in order.
pub struct Blake3Reader {
    output: Output,
    counter: u64,
    block: [u8; 2 * OUT_LEN],
    used: usize,
}

impl Drop for Blake3Reader {
    fn drop(&mut self) {
        self.block.zeroize();
    }
}

impl Blake3Reader {
    /// Write the next `out.len()` bytes of output.
    ///
    /// Every output of BLAKE3 comes through here, and refuses here with
    /// `ModuleErrorState` once the module has failed.
    pub fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        self.fill_inner(out);
        Ok(())
    }

    fn fill_inner(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.used == self.block.len() {
                self.block = self.output.root_block(self.counter);
                self.counter = self.counter.wrapping_add(1);
                self.used = 0;
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::hex;

    /// The empty input, as the BLAKE3 specification's test vectors give it.
    #[test]
    fn empty_input() {
        assert_eq!(
            hex(&Blake3::hash(b"").unwrap()),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    /// Reading the output in pieces gives the same bytes as reading it whole.
    #[test]
    fn reader_pieces_match_one_read() {
        let h = {
            let mut h = Blake3::new();
            h.update(b"abc");
            h
        };
        let mut whole = [0u8; 300];
        h.finalize_xof().fill(&mut whole).unwrap();
        let mut r = h.finalize_xof();
        let mut pieces = [0u8; 300];
        for c in pieces.chunks_mut(37) {
            r.fill(c).unwrap();
        }
        assert_eq!(whole, pieces);
        assert_eq!(whole[..32], h.finalize().unwrap());
    }

    /// Streaming matches one-shot across block, chunk and subtree boundaries.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let expected = Blake3::hash(&data);
        for split in [
            0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3072, 4097, 5000,
        ] {
            let mut h = Blake3::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), expected, "split at {split}");
        }
    }
}
