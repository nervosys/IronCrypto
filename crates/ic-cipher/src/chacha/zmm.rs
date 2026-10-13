//! Sixteen-block-at-a-time ChaCha20, on AVX-512F.
//!
//! # The layout
//!
//! The AVX2 kernel's, widened: sixteen `zmm` registers, one per state word,
//! each holding that word for sixteen blocks, so every quarter-round is
//! elementwise and no shuffle appears in the twenty rounds. AVX-512 adds two
//! things that matter here. `vprold` rotates in one instruction, where AVX2
//! needs a byte shuffle or two shifts and an or. And the quarter-round needs
//! no temporary at all -- each step is `a += b`, `d ^= a`, `d <<<= n` in
//! place -- so the whole state fits in `zmm0`..`zmm15` with nothing spilled.
//!
//! At the end the by-word registers become by-block output with two
//! transposes, both in registers: a 4x4 transpose of 32-bit words inside each
//! 128-bit lane (`vpunpck*`), then a 4x4 transpose of 128-bit lanes
//! (`vshufi32x4`). Between them the words pass through a 1 KiB scratch
//! buffer, because the second transpose regroups registers the first one
//! produced in different passes, and sixteen registers leave no room to hold
//! them all at once. The assembly wipes that buffer itself before it returns.
//!
//! The starting state is read as sixteen words and broadcast on load, rather
//! than kept as sixteen 64-byte rows: the rows would be 1 KiB of key material
//! to build and wipe for every message.
//!
//! # Why `asm!`
//!
//! As in `gcm_x86`: the AVX-512 intrinsics were stabilised in Rust 1.89 and
//! this workspace promises 1.87, which cannot even name a `zmm` register as an
//! operand. So one group is one self-contained `asm!` block that names
//! `zmm0`..`zmm15` itself, declares all of them clobbered, and passes
//! everything through memory, in a function that is never inlined. The twenty
//! rounds are unrolled in the text, so the block has no branch at all; the
//! loop over groups is ordinary Rust in the caller.
//!
//! # Trusting it
//!
//! `chacha::tests::the_wide_keystreams_match_the_block_function` compares it
//! with the one-block function, which the RFC 8439 vectors do validate, at
//! every length from 0 to 2100 bytes and at several counters, on unaligned
//! buffers, checking the bytes either side are untouched. The RFC vectors
//! alone are shorter than one group and never reach this code.
//!
//! # Constant-time properties
//!
//! Adds, xors, fixed rotations, broadcasts and fixed shuffles; no branch and
//! no data-dependent address. `ct_chacha20_zmm_group` in `scripts/ct-audit`
//! holds the compiled function to that.
//!
//! # Safety
//!
//! [`group`] is the only unsafe entry: the CPU must have AVX-512F, which
//! `chacha::zmm_available` establishes, and its arguments are fixed-size
//! references, so every address the assembly forms is inside them.

use core::arch::asm;

use ic_core::Zeroize;

/// Blocks produced per call.
pub const LANES: usize = 16;

/// Bytes produced per call.
pub const STRIDE: usize = LANES * 64;

/// The sixteen words of the starting state, for the block at `counter`.
///
/// The kernel broadcasts each to all sixteen lanes as it loads it, and adds
/// the lane number to the counter, so this is all it reads. Holds the key, so
/// it is wiped on drop.
#[repr(C, align(64))]
pub struct Start([u32; 16]);

impl Start {
    /// The state for sixteen blocks from `counter`.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Start {
        let mut s = Start([0u32; 16]);
        s.0[..4].copy_from_slice(&super::SIGMA);
        for i in 0..8 {
            s.0[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        for i in 0..3 {
            s.0[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        s.0[12] = counter;
        s
    }

    /// Point the counter at block `counter`; the kernel covers it and the
    /// fifteen after it.
    ///
    /// The kernel adds the lane numbers with wrapping, because the caller has
    /// already established that the counters it will use fit; see
    /// `xor_keystream`.
    pub fn set_counter(&mut self, counter: u32) {
        self.0[12] = counter;
    }
}

impl Drop for Start {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `0, 1, ..., 15`: what each lane adds to the counter.
#[repr(C, align(64))]
struct LaneOffsets([u32; 16]);

static LANE_OFFSETS: LaneOffsets =
    LaneOffsets([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

/// Where the keystream words wait between the two transposes: on the stack
/// of [`group`], and wiped by its assembly before it returns.
#[repr(C, align(64))]
struct Scratch([u8; STRIDE]);

/// One step of four quarter-rounds, interleaved instruction by instruction so
/// that four independent chains are in flight. Each tuple is `(a, b, c, d)`.
macro_rules! qr4 {
    ($(($a:literal, $b:literal, $c:literal, $d:literal)),*) => {
        concat!(
            $("vpaddd zmm", $a, ", zmm", $a, ", zmm", $b, "\n",)*
            $("vpxord zmm", $d, ", zmm", $d, ", zmm", $a, "\n",)*
            $("vprold zmm", $d, ", zmm", $d, ", 16\n",)*
            $("vpaddd zmm", $c, ", zmm", $c, ", zmm", $d, "\n",)*
            $("vpxord zmm", $b, ", zmm", $b, ", zmm", $c, "\n",)*
            $("vprold zmm", $b, ", zmm", $b, ", 12\n",)*
            $("vpaddd zmm", $a, ", zmm", $a, ", zmm", $b, "\n",)*
            $("vpxord zmm", $d, ", zmm", $d, ", zmm", $a, "\n",)*
            $("vprold zmm", $d, ", zmm", $d, ", 8\n",)*
            $("vpaddd zmm", $c, ", zmm", $c, ", zmm", $d, "\n",)*
            $("vpxord zmm", $b, ", zmm", $b, ", zmm", $c, "\n",)*
            $("vprold zmm", $b, ", zmm", $b, ", 7\n",)*
        )
    };
}

/// A column round and a diagonal round.
macro_rules! double_round {
    () => {
        concat!(
            qr4!((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)),
            qr4!((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)),
        )
    };
}

/// Load the starting state, word `w` broadcast into `zmm{w}`; the counter
/// word then gets each lane's offset added.
macro_rules! load_start {
    ($($w:literal),*) => {
        concat!(
            $("vpbroadcastd zmm", $w, ", dword ptr [{s} + ", $w, " * 4]\n",)*
            "vpaddd zmm12, zmm12, zmmword ptr [{o}]\n",
        )
    };
}

/// Add the starting state back, and park the result in the scratch buffer.
macro_rules! feed_forward {
    ($($w:literal),*) => {
        concat!(
            "vpaddd zmm12, zmm12, zmmword ptr [{o}]\n",
            $("vpaddd zmm", $w, ", zmm", $w, ", dword ptr [{s} + ", $w, " * 4] {{1to16}}\n",)*
            $("vmovdqa64 zmmword ptr [{k} + ", $w, " * 64], zmm", $w, "\n",)*
        )
    };
}

/// Words `4g..4g+3`, transposed in each 128-bit lane: afterwards the register
/// stored at `64 * (4g + e)` holds, in lane `q`, those four words of block
/// `4q + e`.
macro_rules! transpose_words {
    ($g:literal) => {
        concat!(
            "vmovdqa64 zmm0, zmmword ptr [{k} + ",
            $g,
            " * 256]\n",
            "vmovdqa64 zmm1, zmmword ptr [{k} + ",
            $g,
            " * 256 + 64]\n",
            "vmovdqa64 zmm2, zmmword ptr [{k} + ",
            $g,
            " * 256 + 128]\n",
            "vmovdqa64 zmm3, zmmword ptr [{k} + ",
            $g,
            " * 256 + 192]\n",
            "vpunpckldq zmm4, zmm0, zmm1\n",
            "vpunpckhdq zmm5, zmm0, zmm1\n",
            "vpunpckldq zmm6, zmm2, zmm3\n",
            "vpunpckhdq zmm7, zmm2, zmm3\n",
            "vpunpcklqdq zmm0, zmm4, zmm6\n",
            "vpunpckhqdq zmm1, zmm4, zmm6\n",
            "vpunpcklqdq zmm2, zmm5, zmm7\n",
            "vpunpckhqdq zmm3, zmm5, zmm7\n",
            "vmovdqa64 zmmword ptr [{k} + ",
            $g,
            " * 256], zmm0\n",
            "vmovdqa64 zmmword ptr [{k} + ",
            $g,
            " * 256 + 64], zmm1\n",
            "vmovdqa64 zmmword ptr [{k} + ",
            $g,
            " * 256 + 128], zmm2\n",
            "vmovdqa64 zmmword ptr [{k} + ",
            $g,
            " * 256 + 192], zmm3\n",
        )
    };
}

/// Blocks `e`, `4 + e`, `8 + e` and `12 + e`: gather lane `q` of the four
/// registers `transpose_words!` left for `e`, one per word group, into whole
/// blocks, xor them into the data and store.
macro_rules! transpose_lanes_xor {
    ($e:literal) => {
        concat!(
            "vmovdqa64 zmm0, zmmword ptr [{k} + ",
            $e,
            " * 64]\n",
            "vmovdqa64 zmm1, zmmword ptr [{k} + 256 + ",
            $e,
            " * 64]\n",
            "vmovdqa64 zmm2, zmmword ptr [{k} + 512 + ",
            $e,
            " * 64]\n",
            "vmovdqa64 zmm3, zmmword ptr [{k} + 768 + ",
            $e,
            " * 64]\n",
            // [A0 A1 B0 B1], [A2 A3 B2 B3], [C0 C1 D0 D1], [C2 C3 D2 D3].
            "vshufi32x4 zmm4, zmm0, zmm1, 0x44\n",
            "vshufi32x4 zmm5, zmm0, zmm1, 0xee\n",
            "vshufi32x4 zmm6, zmm2, zmm3, 0x44\n",
            "vshufi32x4 zmm7, zmm2, zmm3, 0xee\n",
            // [Aq Bq Cq Dq]: block 4q + e.
            "vshufi32x4 zmm0, zmm4, zmm6, 0x88\n",
            "vshufi32x4 zmm1, zmm4, zmm6, 0xdd\n",
            "vshufi32x4 zmm2, zmm5, zmm7, 0x88\n",
            "vshufi32x4 zmm3, zmm5, zmm7, 0xdd\n",
            "vpxord zmm0, zmm0, zmmword ptr [{p} + ",
            $e,
            " * 64]\n",
            "vpxord zmm1, zmm1, zmmword ptr [{p} + 256 + ",
            $e,
            " * 64]\n",
            "vpxord zmm2, zmm2, zmmword ptr [{p} + 512 + ",
            $e,
            " * 64]\n",
            "vpxord zmm3, zmm3, zmmword ptr [{p} + 768 + ",
            $e,
            " * 64]\n",
            "vmovdqu64 zmmword ptr [{p} + ",
            $e,
            " * 64], zmm0\n",
            "vmovdqu64 zmmword ptr [{p} + 256 + ",
            $e,
            " * 64], zmm1\n",
            "vmovdqu64 zmmword ptr [{p} + 512 + ",
            $e,
            " * 64], zmm2\n",
            "vmovdqu64 zmmword ptr [{p} + 768 + ",
            $e,
            " * 64], zmm3\n",
        )
    };
}

/// Overwrite the scratch buffer with `zmm0`, which `vzeroall` has cleared.
macro_rules! wipe_scratch {
    ($($w:literal),*) => {
        concat!($("vmovdqa64 zmmword ptr [{k} + ", $w, " * 64], zmm0\n",)*)
    };
}

/// XOR `data` with the keystream for the sixteen blocks `start` describes.
///
/// # Safety
///
/// The CPU must support AVX-512F.
#[inline(never)]
pub unsafe fn group(start: &Start, data: &mut [u8; STRIDE]) {
    // Uninitialised: the assembly writes every byte before it reads one.
    let mut scratch = core::mem::MaybeUninit::<Scratch>::uninit();
    // SAFETY: the caller has established AVX-512F. Every address is one of
    // four objects plus a constant below its size: `start` (64 bytes),
    // `LANE_OFFSETS` and `scratch`, the last two 64-byte aligned as the
    // aligned moves need, and `data`, 1 KiB, read and written unaligned. The
    // block uses `zmm0`..`zmm15` only and declares all sixteen clobbered (an
    // `xmm` clobber covers the whole register), so on Windows the
    // callee-saved `xmm6`..`xmm15` are saved by this function's prologue. It
    // ends with `vzeroall`, which clears every register it used, and then
    // overwrites the scratch buffer with zeros, so no keystream is left
    // behind in either. It pushes nothing and touches no flags.
    // `zmm16`..`zmm31` and the mask registers are not used, and this function
    // is never inlined, so no caller value can be live in them across it.
    unsafe {
        asm!(
            load_start!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            double_round!(),
            feed_forward!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            transpose_words!(0),
            transpose_words!(1),
            transpose_words!(2),
            transpose_words!(3),
            transpose_lanes_xor!(0),
            transpose_lanes_xor!(1),
            transpose_lanes_xor!(2),
            transpose_lanes_xor!(3),
            "vzeroall",
            wipe_scratch!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            s = in(reg) start.0.as_ptr(),
            o = in(reg) LANE_OFFSETS.0.as_ptr(),
            k = in(reg) scratch.as_mut_ptr() as *mut u8,
            p = in(reg) data.as_mut_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack, preserves_flags),
        );
    }
}
