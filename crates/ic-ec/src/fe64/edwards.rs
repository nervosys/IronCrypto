//! Edwards-curve group operations on [`super::Fe64`], each one straight-line
//! assembly block over a workspace.
//!
//! The formulas are exactly those of `ed25519::Projective::double`,
//! `Completed::to_extended` and `to_projective`, and `Ext::add_niels`,
//! `sub_niels`, `add_affine_niels` and `sub_affine_niels`, operation for
//! operation; the tests in `ed25519::fast` compare every block against those
//! methods. They exist for the reason `super::ladder_step` does: one block
//! per field operation leaves a quarter of the instructions as compiler
//! glue, and these chains of operations are what signing and verification
//! are made of.
//!
//! # Bounds
//!
//! The additions and subtractions fold their carry once, not twice
//! (`fe_add_once!`, `fe_sub_once!`), wherever their operands allow it: an
//! addition needs the two below `2^257 - 38` together, a subtraction its
//! second operand below `2^256 - 38`. Products and squares are below
//! `2^255 + 19 * 77`, and every coordinate of the accumulator these blocks
//! are given is one -- the output of a conversion, or the identity's 0 and
//! 1 -- and every addition here is of products, or of a product and a sum
//! of two. The one exception is in [`dbl`], which subtracts a sum, and
//! there the full fold stays. Operands of the addition (`y + x`, `y - x`,
//! `2d t`, `Z`) are only ever multiplied, which takes any 256-bit value.
//!
//! Nothing here branches or indexes memory by data. Which block runs is the
//! caller's choice; on the signing path that choice is fixed (a mixed
//! addition every step), and only verification, on public data, chooses by
//! the scalar.

#[cfg(feature = "std")]
use crate::ed25519::AffineNiels;
use core::arch::asm;

/// Slots, each a field element, as limb indices into [`Ws`].
pub mod slot {
    /// The accumulator, `(X : Y : Z : T)` or projective `(X : Y : Z)`.
    pub const X: usize = 0;
    /// See [`X`].
    pub const Y: usize = 4;
    /// See [`X`].
    pub const Z: usize = 8;
    /// See [`X`].
    pub const T: usize = 12;
    /// The operand of an addition: `Y + X`.
    pub const YPX: usize = 32;
    /// `Y - X`.
    pub const YMX: usize = 36;
    /// `Z`, for a Niels point; unused for an affine one.
    pub const NZ: usize = 40;
    /// `2d * T`.
    pub const T2D: usize = 44;
}

/// The workspace: sixteen field elements -- the accumulator, a completed
/// point, an operand and four temporaries -- 512 bytes.
pub struct Ws(pub [u64; 64]);

// Byte offsets used in the assembly text: X 0, Y 32, Z 64, T 96; completed
// CX 128, CY 160, CZ 192, CT 224; operand YPX 256, YMX 288, NZ 320, T2D 352;
// temporaries A 384, B 416, C 448, D 480.

/// Two workspaces side by side, the second at byte offset 512: for running
/// two independent accumulators through one block, operation by operation.
pub struct Ws2(pub [u64; 128]);

/// Run one block of the text macros over `ws2`.
macro_rules! block2 {
    ($ws:expr, $($text:expr),+ $(,)?) => {{
        let ws: &mut Ws2 = $ws;
        // SAFETY: as in `block!`, over 1024 bytes.
        unsafe {
            asm!(
                ".p2align 6",
                $($text),+,
                in("rdi") ws.0.as_mut_ptr(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(nostack),
            );
        }
    }};
}

/// [`madd`] then [`to_ext`] on both halves of `ws`, the two interleaved
/// operation by operation.
///
/// Each half is one dependency chain -- a field multiplication is some 45
/// cycles from first instruction to result, and the next operation waits on
/// it -- and the out-of-order core cannot look far enough ahead across a
/// 350-instruction block to find the next chain's work by itself. Placed
/// side by side, each operation has an independent one to overlap with.
#[inline(never)]
pub fn madd_ext2(ws: &mut Ws2) {
    block2!(
        ws,
        fe_add_once!(384, 32, 0),
        fe_add_once!(896, 544, 512),
        fe_sub_once!(416, 32, 0),
        fe_sub_once!(928, 544, 512),
        fe_mul!(384, 384, 256),
        fe_mul!(896, 896, 768),
        fe_mul!(416, 416, 288),
        fe_mul!(928, 928, 800),
        fe_mul!(448, 96, 352),
        fe_mul!(960, 608, 864),
        fe_add_once!(480, 64, 64),
        fe_add_once!(992, 576, 576),
        fe_sub_once!(128, 384, 416),
        fe_sub_once!(640, 896, 928),
        fe_add_once!(160, 384, 416),
        fe_add_once!(672, 896, 928),
        fe_add_once!(192, 480, 448),
        fe_add_once!(704, 992, 960),
        fe_sub_once!(224, 480, 448),
        fe_sub_once!(736, 992, 960),
        fe_mul!(0, 128, 224),
        fe_mul!(512, 640, 736),
        fe_mul!(32, 160, 192),
        fe_mul!(544, 672, 704),
        fe_mul!(64, 192, 224),
        fe_mul!(576, 704, 736),
        fe_mul!(96, 128, 160),
        fe_mul!(608, 640, 672),
    );
}

/// Run one block of the text macros over `ws`.
macro_rules! block {
    ($ws:expr, $($text:expr),+ $(,)?) => {{
        let ws: &mut Ws = $ws;
        // SAFETY: every access is to `ws`, a live exclusive borrow of 512
        // bytes, at constant offsets below 512; the registers used are
        // declared as clobbered, `rdi` is not written, and nothing is pushed.
        // `MULX`, `ADCX` and `ADOX` need BMI2 and ADX: the Fe64 paths that
        // call these are reached only through `dispatch!`, after
        // `available()`.
        unsafe {
            asm!(
                ".p2align 6",
                $($text),+,
                in("rdi") ws.0.as_mut_ptr(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(nostack),
            );
        }
    }};
}

/// Doubling of the projective accumulator, to the completed point.
#[inline(never)]
pub fn dbl(ws: &mut Ws) {
    block!(
        ws,
        fe_sqr!(384, 0),             // A = X^2
        fe_sqr!(416, 32),            // B = Y^2
        fe_sqr!(448, 64),            // C = Z^2
        fe_add_once!(448, 448, 448), // C = 2 Z^2
        fe_add_once!(480, 0, 32),    // D = X + Y
        fe_sqr!(480, 480),           // D = (X + Y)^2
        fe_add_once!(160, 416, 384), // CY = B + A
        fe_sub_once!(192, 416, 384), // CZ = B - A
        // CY is a sum and may be within 38 of 2^256: the full fold.
        fe_sub!(128, 480, 160),      // CX = D - CY
        fe_sub_once!(224, 448, 192), // CT = C - CZ
    );
}

/// The completed point to the extended accumulator: four multiplications.
#[inline(never)]
pub fn to_ext(ws: &mut Ws) {
    block!(
        ws,
        fe_mul!(0, 128, 224),  // X = CX * CT
        fe_mul!(32, 160, 192), // Y = CY * CZ
        fe_mul!(64, 192, 224), // Z = CZ * CT
        fe_mul!(96, 128, 160), // T = CX * CY
    );
}

/// The completed point to the projective accumulator: three.
#[inline(never)]
pub fn to_proj(ws: &mut Ws) {
    block!(
        ws,
        fe_mul!(0, 128, 224),  // X = CX * CT
        fe_mul!(32, 160, 192), // Y = CY * CZ
        fe_mul!(64, 192, 224), // Z = CZ * CT
    );
}

/// Accumulator plus the operand, as an affine Niels point; to completed.
#[inline(never)]
pub fn madd(ws: &mut Ws) {
    block!(
        ws,
        fe_add_once!(384, 32, 0),    // A = Y + X
        fe_sub_once!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 256),      // A = A * YPX
        fe_mul!(416, 416, 288),      // B = B * YMX
        fe_mul!(448, 96, 352),       // C = T * T2D
        fe_add_once!(480, 64, 64),   // D = 2 Z
        fe_sub_once!(128, 384, 416), // CX = A - B
        fe_add_once!(160, 384, 416), // CY = A + B
        fe_add_once!(192, 480, 448), // CZ = D + C
        fe_sub_once!(224, 480, 448), // CT = D - C
    );
}

/// Accumulator minus the operand, as an affine Niels point; to completed.
#[inline(never)]
pub fn msub(ws: &mut Ws) {
    block!(
        ws,
        fe_add_once!(384, 32, 0),    // A = Y + X
        fe_sub_once!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 288),      // A = A * YMX
        fe_mul!(416, 416, 256),      // B = B * YPX
        fe_mul!(448, 96, 352),       // C = T * T2D
        fe_add_once!(480, 64, 64),   // D = 2 Z
        fe_sub_once!(128, 384, 416), // CX = A - B
        fe_add_once!(160, 384, 416), // CY = A + B
        fe_sub_once!(192, 480, 448), // CZ = D - C
        fe_add_once!(224, 480, 448), // CT = D + C
    );
}

/// Accumulator plus the operand, as a Niels point with `Z`; to completed.
#[inline(never)]
pub fn nadd(ws: &mut Ws) {
    block!(
        ws,
        fe_add_once!(384, 32, 0),    // A = Y + X
        fe_sub_once!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 256),      // A = A * YPX
        fe_mul!(416, 416, 288),      // B = B * YMX
        fe_mul!(448, 96, 352),       // C = T * T2D
        fe_mul!(480, 64, 320),       // D = Z * NZ
        fe_add_once!(480, 480, 480), // D = 2 D
        fe_sub_once!(128, 384, 416), // CX = A - B
        fe_add_once!(160, 384, 416), // CY = A + B
        fe_add_once!(192, 480, 448), // CZ = D + C
        fe_sub_once!(224, 480, 448), // CT = D - C
    );
}

/// Accumulator minus the operand, as a Niels point with `Z`; to completed.
#[inline(never)]
pub fn nsub(ws: &mut Ws) {
    block!(
        ws,
        fe_add_once!(384, 32, 0),    // A = Y + X
        fe_sub_once!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 288),      // A = A * YMX
        fe_mul!(416, 416, 256),      // B = B * YPX
        fe_mul!(448, 96, 352),       // C = T * T2D
        fe_mul!(480, 64, 320),       // D = Z * NZ
        fe_add_once!(480, 480, 480), // D = 2 D
        fe_sub_once!(128, 384, 416), // CX = A - B
        fe_add_once!(160, 384, 416), // CY = A + B
        fe_sub_once!(192, 480, 448), // CZ = D - C
        fe_add_once!(224, 480, 448), // CT = D + C
    );
}

/// A window's entries as the twelve limbs each that [`select`] reads.
#[cfg(feature = "std")]
pub fn limbs(table: &[AffineNiels<super::Fe64>; 8]) -> &[[u64; 12]; 8] {
    const _: () = assert!(core::mem::size_of::<[AffineNiels<super::Fe64>; 8]>() == 768);
    const _: () = assert!(core::mem::align_of::<AffineNiels<super::Fe64>>() == 8);
    // SAFETY: `AffineNiels` is `repr(C)` over three `Fe64`s, each a
    // `repr(transparent)` `[u64; 4]`: twelve `u64`s in field order, aligned
    // as `u64`, without padding (the size and alignment are asserted above).
    // An array of eight is then exactly an array of eight `[u64; 12]`, and
    // the borrow's lifetime carries over.
    unsafe { &*(table as *const [AffineNiels<super::Fe64>; 8]).cast::<[[u64; 12]; 8]>() }
}

/// One entry of [`select`]'s scan: the four limbs at byte `$off` of entry
/// `$n` (1 to 8, each 96 bytes from `rsi`) into four registers when `rcx`,
/// the magnitude, equals `$n`. The `CMOV`s read memory whichever way they go.
macro_rules! sel_entry {
    ($n:literal, $base:literal, $off:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal) => {
        concat!(
            "cmp rcx, ",
            $n,
            "\n",
            "cmove ",
            $r0,
            ", qword ptr [rsi + ",
            $base,
            " + ",
            $off,
            "]\n",
            "cmove ",
            $r1,
            ", qword ptr [rsi + ",
            $base,
            " + ",
            $off,
            " + 8]\n",
            "cmove ",
            $r2,
            ", qword ptr [rsi + ",
            $base,
            " + ",
            $off,
            " + 16]\n",
            "cmove ",
            $r3,
            ", qword ptr [rsi + ",
            $base,
            " + ",
            $off,
            " + 24]\n",
        )
    };
}

/// One field element of [`select`]: every entry's limbs at byte `$off`,
/// scanned in order, into four registers already holding the identity's.
macro_rules! sel_pass {
    ($off:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal) => {
        concat!(
            sel_entry!("1", "0", $off, $r0, $r1, $r2, $r3),
            sel_entry!("2", "96", $off, $r0, $r1, $r2, $r3),
            sel_entry!("3", "192", $off, $r0, $r1, $r2, $r3),
            sel_entry!("4", "288", $off, $r0, $r1, $r2, $r3),
            sel_entry!("5", "384", $off, $r0, $r1, $r2, $r3),
            sel_entry!("6", "480", $off, $r0, $r1, $r2, $r3),
            sel_entry!("7", "576", $off, $r0, $r1, $r2, $r3),
            sel_entry!("8", "672", $off, $r0, $r1, $r2, $r3),
        )
    };
}

/// Signing's table read: `digit` times a window's point, for `digit` in
/// `[-8, 8]`, into an operand's slots.
///
/// `table` holds the multiples `1..=8` as affine Niels points, twelve limbs
/// each, `y + x`, `y - x`, `2d x y`; [`limbs`] gives a window's that way.
/// `dst` is an operand's sixteen limbs as the workspaces lay them out:
/// `y + x` at 0, `y - x` at 4, `2d x y` at 12.
///
/// Every entry is read, and the one wanted kept by `CMOV` on a comparison of
/// the magnitude with its index; the identity `(1, 1, 0)` stands when the
/// digit is zero. A negative digit then swaps the first two elements and
/// negates the third, by `CMOV` again. Nothing branches on the digit or
/// indexes memory by it. The values are those of
/// `basepoint_table::Window::select`, limb for limb: the negation is
/// `Fe64::neg`'s subtraction from zero.
#[inline(never)]
pub fn select(dst: &mut [u64; 16], table: &[[u64; 12]; 8], digit: i8) {
    // SAFETY: reads the 768 bytes of `table` and writes the 128 bytes of
    // `dst`, both live borrows, at constant offsets within them; registers
    // only otherwise, all declared, and nothing pushed. Integer instructions
    // present on every x86-64 CPU.
    unsafe {
        asm!(
            ".p2align 6",
            // rdx = all ones when the digit is negative; rcx = |digit|.
            "mov rdx, rcx",
            "sar rdx, 63",
            "xor rcx, rdx",
            "sub rcx, rdx",
            // y + x and y - x, from the identity's (1, 0, 0, 0).
            "mov r8d, 1",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "mov r12d, 1",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            sel_pass!("0", "r8", "r9", "r10", "r11"),
            sel_pass!("32", "r12", "r13", "r14", "r15"),
            // Negative: swap them.
            "test rdx, rdx",
            "mov rax, r8",
            "cmovnz r8, r12",
            "cmovnz r12, rax",
            "mov rax, r9",
            "cmovnz r9, r13",
            "cmovnz r13, rax",
            "mov rax, r10",
            "cmovnz r10, r14",
            "cmovnz r14, rax",
            "mov rax, r11",
            "cmovnz r11, r15",
            "cmovnz r15, rax",
            "mov qword ptr [rdi], r8",
            "mov qword ptr [rdi + 8], r9",
            "mov qword ptr [rdi + 16], r10",
            "mov qword ptr [rdi + 24], r11",
            "mov qword ptr [rdi + 32], r12",
            "mov qword ptr [rdi + 40], r13",
            "mov qword ptr [rdi + 48], r14",
            "mov qword ptr [rdi + 56], r15",
            // 2d x y, from the identity's zero.
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            sel_pass!("64", "r8", "r9", "r10", "r11"),
            // Its negation, 0 - t with the borrow folded twice as
            // `Fe64::sub` does.
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "sub r12, r8",
            "sbb r13, r9",
            "sbb r14, r10",
            "sbb r15, r11",
            "sbb rax, rax",
            "and eax, 38",
            "sub r12, rax",
            "sbb r13, 0",
            "sbb r14, 0",
            "sbb r15, 0",
            "sbb rax, rax",
            "and eax, 38",
            "sub r12, rax",
            "test rdx, rdx",
            "cmovnz r8, r12",
            "cmovnz r9, r13",
            "cmovnz r10, r14",
            "cmovnz r11, r15",
            "mov qword ptr [rdi + 96], r8",
            "mov qword ptr [rdi + 104], r9",
            "mov qword ptr [rdi + 112], r10",
            "mov qword ptr [rdi + 120], r11",
            in("rdi") dst.as_mut_ptr(),
            in("rsi") table.as_ptr(),
            inout("rcx") i64::from(digit) => _,
            out("rax") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(nostack),
        );
    }
}

/// Proof that the CPU has AVX2 and the OS saves its registers, for the
/// blocks below that read a table in vector registers.
#[derive(Clone, Copy)]
pub struct Avx2(());

impl Avx2 {
    /// `Some` on a CPU with AVX2. Asked once and cached; depends only on the
    /// CPU, never on data.
    #[inline]
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    pub fn get() -> Option<Avx2> {
        crate::avx512::avx2().then_some(Avx2(()))
    }
}

/// [`Ws2`] and, from byte 1024, what `madd_ext2_scan` and `scan` need to
/// read a window: `ctl[0]` its address, `ctl[1]` and `ctl[2]` the digits for
/// halves 0 and 1, as sign-extended `i64`s. The blocks write the digits'
/// sign masks into `ctl[3]` and `ctl[4]`.
#[repr(C)]
pub struct Ws2Scan {
    /// The two workspaces.
    pub two: Ws2,
    /// The controls above.
    pub ctl: [u64; 8],
}

const _: () = assert!(core::mem::size_of::<Ws2>() == 1024);
const _: () = assert!(core::mem::size_of::<Ws2Scan>() == 1088);

/// A radix-32 window's sixteen entries as the twelve limbs each that
/// [`madd_ext2_scan`] and [`scan`] read.
#[cfg(feature = "std")]
pub fn limbs16(table: &[AffineNiels<super::Fe64>; 16]) -> &[[u64; 12]; 16] {
    const _: () = assert!(core::mem::size_of::<[AffineNiels<super::Fe64>; 16]>() == 1536);
    const _: () = assert!(core::mem::align_of::<AffineNiels<super::Fe64>>() == 8);
    // SAFETY: as in `limbs`: `AffineNiels` is `repr(C)` over three `Fe64`s,
    // each a `repr(transparent)` `[u64; 4]`, without padding.
    unsafe { &*(table as *const [AffineNiels<super::Fe64>; 16]).cast::<[[u64; 12]; 16]>() }
}

/// The start of a table read: the window's address into `rsi`, the two
/// digits' magnitudes broadcast into `ymm6` and `ymm7` and their sign masks
/// stored at `ctl[3]` and `ctl[4]`, the running index (from one) in `ymm8`
/// and its step in `ymm9`, and the identity `(1, 1, 0)` in both halves'
/// registers, `ymm0`-`ymm2` and `ymm3`-`ymm5`.
macro_rules! scan_setup {
    () => {
        concat!(
            "mov rsi, qword ptr [rdi + 1024]\n",
            "mov rax, qword ptr [rdi + 1032]\n",
            "mov rdx, rax\n",
            "sar rdx, 63\n",
            "xor rax, rdx\n",
            "sub rax, rdx\n",
            "mov qword ptr [rdi + 1048], rdx\n",
            "vmovq xmm6, rax\n",
            "vpbroadcastq ymm6, xmm6\n",
            "mov rax, qword ptr [rdi + 1040]\n",
            "mov rdx, rax\n",
            "sar rdx, 63\n",
            "xor rax, rdx\n",
            "sub rax, rdx\n",
            "mov qword ptr [rdi + 1056], rdx\n",
            "vmovq xmm7, rax\n",
            "vpbroadcastq ymm7, xmm7\n",
            "vpcmpeqq ymm9, ymm9, ymm9\n",
            "vpsrlq ymm9, ymm9, 63\n",
            "vmovdqa ymm8, ymm9\n",
            "mov eax, 1\n",
            "vmovq xmm0, rax\n",
            "vmovdqa ymm1, ymm0\n",
            "vpxor xmm2, xmm2, xmm2\n",
            "vmovdqa ymm3, ymm0\n",
            "vmovdqa ymm4, ymm0\n",
            "vpxor xmm5, xmm5, xmm5\n",
        )
    };
}

/// One entry of a table read: the entry at byte `$off` from `rsi`, loaded
/// once and blended into each half's registers where that half's magnitude
/// equals the running index, which then steps.
macro_rules! scan_entry {
    ($off:literal) => {
        concat!(
            "vpcmpeqq ymm10, ymm6, ymm8\n",
            "vpcmpeqq ymm11, ymm7, ymm8\n",
            "vpaddq ymm8, ymm8, ymm9\n",
            "vmovdqu ymm12, ymmword ptr [rsi + ",
            $off,
            "]\n",
            "vmovdqu ymm13, ymmword ptr [rsi + ",
            $off,
            " + 32]\n",
            "vmovdqu ymm14, ymmword ptr [rsi + ",
            $off,
            " + 64]\n",
            "vpblendvb ymm0, ymm0, ymm12, ymm10\n",
            "vpblendvb ymm1, ymm1, ymm13, ymm10\n",
            "vpblendvb ymm2, ymm2, ymm14, ymm10\n",
            "vpblendvb ymm3, ymm3, ymm12, ymm11\n",
            "vpblendvb ymm4, ymm4, ymm13, ymm11\n",
            "vpblendvb ymm5, ymm5, ymm14, ymm11\n",
        )
    };
}

/// Entries 1-4, 5-8, 9-12 or 13-16 of a window (`$q` 0 to 3). `rsi` is
/// reloaded first, since the field operations between the quarters use it.
macro_rules! scan_quarter {
    (0) => {
        concat!(
            "mov rsi, qword ptr [rdi + 1024]\n",
            scan_entry!("0"),
            scan_entry!("96"),
            scan_entry!("192"),
            scan_entry!("288"),
        )
    };
    (1) => {
        concat!(
            "mov rsi, qword ptr [rdi + 1024]\n",
            scan_entry!("384"),
            scan_entry!("480"),
            scan_entry!("576"),
            scan_entry!("672"),
        )
    };
    (2) => {
        concat!(
            "mov rsi, qword ptr [rdi + 1024]\n",
            scan_entry!("768"),
            scan_entry!("864"),
            scan_entry!("960"),
            scan_entry!("1056"),
        )
    };
    (3) => {
        concat!(
            "mov rsi, qword ptr [rdi + 1024]\n",
            scan_entry!("1152"),
            scan_entry!("1248"),
            scan_entry!("1344"),
            scan_entry!("1440"),
        )
    };
}

/// The end of a table read: for a negative digit, `y + x` and `y - x`
/// swapped (masked `XOR`s); then both halves' entries stored into their
/// operand slots, `y + x` at 256, `y - x` at 288, `2d x y` at 352 (half 1 at
/// 512 more).
macro_rules! scan_store {
    () => {
        concat!(
            "vpbroadcastq ymm10, qword ptr [rdi + 1048]\n",
            "vpxor ymm12, ymm0, ymm1\n",
            "vpand ymm12, ymm12, ymm10\n",
            "vpxor ymm0, ymm0, ymm12\n",
            "vpxor ymm1, ymm1, ymm12\n",
            "vmovdqu ymmword ptr [rdi + 256], ymm0\n",
            "vmovdqu ymmword ptr [rdi + 288], ymm1\n",
            "vmovdqu ymmword ptr [rdi + 352], ymm2\n",
            "vpbroadcastq ymm11, qword ptr [rdi + 1056]\n",
            "vpxor ymm12, ymm3, ymm4\n",
            "vpand ymm12, ymm12, ymm11\n",
            "vpxor ymm3, ymm3, ymm12\n",
            "vpxor ymm4, ymm4, ymm12\n",
            "vmovdqu ymmword ptr [rdi + 768], ymm3\n",
            "vmovdqu ymmword ptr [rdi + 800], ymm4\n",
            "vmovdqu ymmword ptr [rdi + 864], ymm5\n",
        )
    };
}

/// `2d x y` at `[$t]` negated in place when the sign mask at `[$sign]` is
/// set: `0 - t` with the borrow folded twice, as [`select`] negates, then
/// `CMOV`s.
macro_rules! scan_negate {
    ($t:literal, $sign:literal) => {
        concat!(
            "mov r8, qword ptr [rdi + ",
            $t,
            "]\n",
            "mov r9, qword ptr [rdi + ",
            $t,
            " + 8]\n",
            "mov r10, qword ptr [rdi + ",
            $t,
            " + 16]\n",
            "mov r11, qword ptr [rdi + ",
            $t,
            " + 24]\n",
            "xor r12d, r12d\n",
            "xor r13d, r13d\n",
            "xor r14d, r14d\n",
            "xor r15d, r15d\n",
            "sub r12, r8\n",
            "sbb r13, r9\n",
            "sbb r14, r10\n",
            "sbb r15, r11\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "sub r12, rax\n",
            "sbb r13, 0\n",
            "sbb r14, 0\n",
            "sbb r15, 0\n",
            "sbb rax, rax\n",
            "and eax, 38\n",
            "sub r12, rax\n",
            "mov rdx, qword ptr [rdi + ",
            $sign,
            "]\n",
            "test rdx, rdx\n",
            "cmovnz r8, r12\n",
            "cmovnz r9, r13\n",
            "cmovnz r10, r14\n",
            "cmovnz r11, r15\n",
            "mov qword ptr [rdi + ",
            $t,
            "], r8\n",
            "mov qword ptr [rdi + ",
            $t,
            " + 8], r9\n",
            "mov qword ptr [rdi + ",
            $t,
            " + 16], r10\n",
            "mov qword ptr [rdi + ",
            $t,
            " + 24], r11\n",
        )
    };
}

/// Run one block over a [`Ws2Scan`]: the text macros, with the vector
/// registers the table reads use declared clobbered.
macro_rules! block_scan {
    ($ws:expr, $($text:expr),+ $(,)?) => {{
        let ws: *mut Ws2Scan = $ws;
        // SAFETY: the field operations access the 1024 bytes of `ws.two` at
        // constant offsets, and the table read the 64 bytes of `ws.ctl` and
        // the 1536 bytes at `ctl[0]`, which the caller sets to a borrowed
        // window; every register used is declared clobbered and nothing is
        // pushed. The enclosing function enables AVX2, and is reached only
        // with an `Avx2`, which proves the CPU has it; BMI2 and ADX are the
        // caller's dispatch's, as for every block here.
        unsafe {
            asm!(
                ".p2align 6",
                $($text),+,
                "vzeroupper",
                in("rdi") ws.cast::<u64>(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                out("ymm0") _,
                out("ymm1") _,
                out("ymm2") _,
                out("ymm3") _,
                out("ymm4") _,
                out("ymm5") _,
                out("ymm6") _,
                out("ymm7") _,
                out("ymm8") _,
                out("ymm9") _,
                out("ymm10") _,
                out("ymm11") _,
                out("ymm12") _,
                out("ymm13") _,
                out("ymm14") _,
                options(nostack),
            );
        }
    }};
}

/// Signing's table read for a pair of digits: `d0` and `d1` times `table`'s
/// point, for each in `[-16, 16]`, into halves 0 and 1's operands, `y + x`,
/// `y - x` and `2d x y` as [`select`] lays them out (and as it would compute
/// them, for a window of sixteen).
///
/// `table` holds the multiples `1..=16`. Every entry is read, each half's
/// wanted one kept by `VPBLENDVB` under a mask from comparing its magnitude
/// with the entry's index; the identity `(1, 1, 0)` stands for zero. A
/// negative digit swaps the first two by masked `XOR`s and negates the third
/// by [`select`]'s subtraction and `CMOV`s. Nothing branches on a digit or
/// indexes memory by it.
pub fn scan(t: Avx2, ws: &mut Ws2Scan, table: &[[u64; 12]; 16], d0: i8, d1: i8) {
    set_scan(ws, table, d0, d1);
    // SAFETY: `t` proves AVX2; `ctl[0]` is `table`, borrowed for the call.
    unsafe { scan_avx2(t, ws) }
}

/// [`madd_ext2`] on `ws.two`, with [`scan`]'s read of the next window run
/// inside it: the operands the addition reads are replaced, after its last
/// read of them, by `d0` and `d1` times `table`'s point.
///
/// Signing's loop alternated a table read and an addition, and the two did
/// not overlap: the addition is some 1400 instructions, beyond the reach of
/// the out-of-order window, and the next read was behind it; measured apart
/// they summed to the whole loop. The read depends only on the digits, not
/// on the accumulator, so here it sits inside the addition's block, in vector
/// registers the field arithmetic does not use, and runs on the vector units
/// while the integer ones multiply. What made a wider window affordable: a
/// sixteen-entry read costs the addition a few percent, where a separate
/// eight-entry one cost a fifth of it.
pub fn madd_ext2_scan(t: Avx2, ws: &mut Ws2Scan, table: &[[u64; 12]; 16], d0: i8, d1: i8) {
    set_scan(ws, table, d0, d1);
    // SAFETY: `t` proves AVX2; `ctl[0]` is `table`, borrowed for the call.
    unsafe { madd_ext2_scan_avx2(t, ws) }
}

fn set_scan(ws: &mut Ws2Scan, table: &[[u64; 12]; 16], d0: i8, d1: i8) {
    ws.ctl[0] = table.as_ptr() as u64;
    ws.ctl[1] = i64::from(d0) as u64;
    ws.ctl[2] = i64::from(d1) as u64;
}

/// [`scan`]'s block.
///
/// # Safety
///
/// `ctl[0]` must be the address of a window, 1536 readable bytes.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe fn scan_avx2(_: Avx2, ws: &mut Ws2Scan) {
    block_scan!(
        ws,
        scan_setup!(),
        scan_quarter!(0),
        scan_quarter!(1),
        scan_quarter!(2),
        scan_quarter!(3),
        scan_store!(),
        scan_negate!(352, 1048),
        scan_negate!(864, 1056),
    );
}

/// [`madd_ext2_scan`]'s block: [`madd_ext2`]'s operations, with the read's
/// quarters between the first ones and its stores after the last
/// multiplication that reads an operand.
///
/// # Safety
///
/// `ctl[0]` must be the address of a window, 1536 readable bytes.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe fn madd_ext2_scan_avx2(_: Avx2, ws: &mut Ws2Scan) {
    block_scan!(
        ws,
        scan_setup!(),
        scan_quarter!(0),
        fe_add_once!(384, 32, 0),
        scan_quarter!(1),
        fe_add_once!(896, 544, 512),
        scan_quarter!(2),
        fe_sub_once!(416, 32, 0),
        scan_quarter!(3),
        fe_sub_once!(928, 544, 512),
        fe_mul!(384, 384, 256),
        fe_mul!(896, 896, 768),
        fe_mul!(416, 416, 288),
        fe_mul!(928, 928, 800),
        fe_mul!(448, 96, 352),
        fe_mul!(960, 608, 864),
        // The operands have been read; the next ones replace them.
        scan_store!(),
        fe_add_once!(480, 64, 64),
        fe_add_once!(992, 576, 576),
        scan_negate!(352, 1048),
        fe_sub_once!(128, 384, 416),
        fe_sub_once!(640, 896, 928),
        fe_add_once!(160, 384, 416),
        fe_add_once!(672, 896, 928),
        scan_negate!(864, 1056),
        fe_add_once!(192, 480, 448),
        fe_add_once!(704, 992, 960),
        fe_sub_once!(224, 480, 448),
        fe_sub_once!(736, 992, 960),
        fe_mul!(0, 128, 224),
        fe_mul!(512, 640, 736),
        fe_mul!(32, 160, 192),
        fe_mul!(544, 672, 704),
        fe_mul!(64, 192, 224),
        fe_mul!(576, 704, 736),
        fe_mul!(96, 128, 160),
        fe_mul!(608, 640, 672),
    );
}

/// The radix-32 table read and step for `ct_probes`, which are compiled to
/// be read and never run; `unsafe` because they need AVX2 and do not ask.
#[cfg(feature = "ct-probes")]
pub mod probes {
    use super::{Avx2, Ws2Scan};

    /// `edwards::scan`.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX2.
    #[inline(always)]
    pub unsafe fn scan(ws: &mut Ws2Scan, table: &[[u64; 12]; 16], d0: i8, d1: i8) {
        super::scan(Avx2(()), ws, table, d0, d1)
    }

    /// `edwards::madd_ext2_scan`.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX2.
    #[inline(always)]
    pub unsafe fn madd_ext2_scan(ws: &mut Ws2Scan, table: &[[u64; 12]; 16], d0: i8, d1: i8) {
        super::madd_ext2_scan(Avx2(()), ws, table, d0, d1)
    }
}
