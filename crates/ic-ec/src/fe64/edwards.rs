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
//! Nothing here branches or indexes memory by data. Which block runs is the
//! caller's choice; on the signing path that choice is fixed (a mixed
//! addition every step), and only verification, on public data, chooses by
//! the scalar.

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
        fe_add!(384, 32, 0),
        fe_add!(896, 544, 512),
        fe_sub!(416, 32, 0),
        fe_sub!(928, 544, 512),
        fe_mul!(384, 384, 256),
        fe_mul!(896, 896, 768),
        fe_mul!(416, 416, 288),
        fe_mul!(928, 928, 800),
        fe_mul!(448, 96, 352),
        fe_mul!(960, 608, 864),
        fe_add!(480, 64, 64),
        fe_add!(992, 576, 576),
        fe_sub!(128, 384, 416),
        fe_sub!(640, 896, 928),
        fe_add!(160, 384, 416),
        fe_add!(672, 896, 928),
        fe_add!(192, 480, 448),
        fe_add!(704, 992, 960),
        fe_sub!(224, 480, 448),
        fe_sub!(736, 992, 960),
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
        fe_sqr!(384, 0),        // A = X^2
        fe_sqr!(416, 32),       // B = Y^2
        fe_sqr!(448, 64),       // C = Z^2
        fe_add!(448, 448, 448), // C = 2 Z^2
        fe_add!(480, 0, 32),    // D = X + Y
        fe_sqr!(480, 480),      // D = (X + Y)^2
        fe_add!(160, 416, 384), // CY = B + A
        fe_sub!(192, 416, 384), // CZ = B - A
        fe_sub!(128, 480, 160), // CX = D - CY
        fe_sub!(224, 448, 192), // CT = C - CZ
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
        fe_add!(384, 32, 0),    // A = Y + X
        fe_sub!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 256), // A = A * YPX
        fe_mul!(416, 416, 288), // B = B * YMX
        fe_mul!(448, 96, 352),  // C = T * T2D
        fe_add!(480, 64, 64),   // D = 2 Z
        fe_sub!(128, 384, 416), // CX = A - B
        fe_add!(160, 384, 416), // CY = A + B
        fe_add!(192, 480, 448), // CZ = D + C
        fe_sub!(224, 480, 448), // CT = D - C
    );
}

/// Accumulator minus the operand, as an affine Niels point; to completed.
#[inline(never)]
pub fn msub(ws: &mut Ws) {
    block!(
        ws,
        fe_add!(384, 32, 0),    // A = Y + X
        fe_sub!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 288), // A = A * YMX
        fe_mul!(416, 416, 256), // B = B * YPX
        fe_mul!(448, 96, 352),  // C = T * T2D
        fe_add!(480, 64, 64),   // D = 2 Z
        fe_sub!(128, 384, 416), // CX = A - B
        fe_add!(160, 384, 416), // CY = A + B
        fe_sub!(192, 480, 448), // CZ = D - C
        fe_add!(224, 480, 448), // CT = D + C
    );
}

/// Accumulator plus the operand, as a Niels point with `Z`; to completed.
#[inline(never)]
pub fn nadd(ws: &mut Ws) {
    block!(
        ws,
        fe_add!(384, 32, 0),    // A = Y + X
        fe_sub!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 256), // A = A * YPX
        fe_mul!(416, 416, 288), // B = B * YMX
        fe_mul!(448, 96, 352),  // C = T * T2D
        fe_mul!(480, 64, 320),  // D = Z * NZ
        fe_add!(480, 480, 480), // D = 2 D
        fe_sub!(128, 384, 416), // CX = A - B
        fe_add!(160, 384, 416), // CY = A + B
        fe_add!(192, 480, 448), // CZ = D + C
        fe_sub!(224, 480, 448), // CT = D - C
    );
}

/// Accumulator minus the operand, as a Niels point with `Z`; to completed.
#[inline(never)]
pub fn nsub(ws: &mut Ws) {
    block!(
        ws,
        fe_add!(384, 32, 0),    // A = Y + X
        fe_sub!(416, 32, 0),    // B = Y - X
        fe_mul!(384, 384, 288), // A = A * YMX
        fe_mul!(416, 416, 256), // B = B * YPX
        fe_mul!(448, 96, 352),  // C = T * T2D
        fe_mul!(480, 64, 320),  // D = Z * NZ
        fe_add!(480, 480, 480), // D = 2 D
        fe_sub!(128, 384, 416), // CX = A - B
        fe_add!(160, 384, 416), // CY = A + B
        fe_sub!(192, 480, 448), // CZ = D - C
        fe_add!(224, 480, 448), // CT = D + C
    );
}
