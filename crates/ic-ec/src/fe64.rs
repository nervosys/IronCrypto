//! GF(2^255 - 19) in four 64-bit limbs, on `MULX`, `ADCX` and `ADOX`.
//!
//! # Why a third field
//!
//! The five-limb field in `field.rs` is portable Rust, and on x86-64 it is
//! limited by its shape rather than by its instructions: five `u128`
//! accumulators and two five-limb operands do not fit in sixteen registers,
//! so the schoolbook spills, and twenty-five products are made where sixteen
//! would do. Its own notes record what was tried there and why it stopped.
//!
//! Radix 2^64 is what the fastest x86-64 Curve25519 code uses (s2n-bignum,
//! which Graviola is built on; the `amd64-64` code in SUPERCOP; Oliveira et
//! al.'s ADX implementation): sixteen 64x64 products for a multiplication,
//! ten for a squaring, and `ADCX`/`ADOX` to carry two independent addition
//! chains through one sequence of products. Rust cannot ask for two carry
//! chains -- the intrinsics exist, but LLVM lowers both to `ADC` on the one
//! flag -- so the multiplication and squaring are written as inline assembly.
//!
//! # What the measurements showed
//!
//! On a Zen 5 core, four independent `ADC` chains run at four instructions a
//! cycle, `ADCX` and `ADOX` interleaved at two (the two flags are renamed
//! apart), and `MULX` at about one and a half: a multiplication here is
//! nowhere near a throughput limit. It is one dependency chain some 45 cycles
//! long, and what a group operation costs is how much of the next operation
//! the core can find to overlap with it. Two things followed:
//!
//! - One assembly block per field operation left a quarter of a ladder step's
//!   instructions as compiler glue -- results moved to the stack to be
//!   addressed, operands loaded for the additions -- so X25519's step
//!   ([`ladder_step`]) and the Edwards group operations (`edwards`) are each
//!   one block over a workspace. That took the ladder from 19 to 15
//!   microseconds.
//! - Where four multiplications are independent, four lanes do them at once:
//!   `crate::f51x4`, on AVX-512 IFMA.
//!
//! # Representation
//!
//! A value is any 256-bit integer, congruent to the element it stands for.
//! Nothing here keeps it below `p`: every operation accepts any four limbs and
//! returns four limbs, and only [`Fe64::to_bytes`] reduces fully. That is what
//! makes addition three instructions plus a fold rather than a carry
//! propagation with a bound to track. Reduction uses `2^256 = 38 (mod p)`.
//!
//! # Constant time
//!
//! Every routine is straight-line: no branch, no table, no data-dependent
//! address. The carry folds are `sbb`/`and` masks inside the assembly, so
//! they are not left for the compiler to turn into a branch, and a mask built
//! in Rust from a secret bit goes through [`mask`]. `scripts/check-ct.py`
//! holds the compiled probes for these routines to having no branches at
//! all. That the instructions themselves -- `MULX`, `ADCX`, `ADOX`, `ADC`,
//! `SBB`, `CMOV`, `IMUL` by a constant -- take the same time for every
//! operand is a property of the CPU, which the gate does not check.
//!
//! # When it is used
//!
//! Only when [`available`] says the CPU has BMI2 and ADX; the five-limb
//! field is the fallback and the reference, and the tests here compare the
//! two on every operation.

use core::arch::asm;
use ic_core::ct::Choice;

#[macro_use]
mod text;
// The Edwards blocks serve the basepoint and double-scalar multiplications,
// which need the `std` tables; and the compiled-code probes.
#[cfg(any(feature = "std", feature = "ct-probes"))]
pub mod edwards;
mod inv;

/// Slots in the X25519 workspace, as limb indices; see [`ladder_step`].
mod slot {
    pub const X1: usize = 0;
    pub const XM: usize = 4;
    pub const ZM: usize = 8;
    pub const XN: usize = 12;
    pub const ZN: usize = 16;
    /// Workspace length in limbs.
    pub const LEN: usize = 76;
}

/// One step of the X25519 ladder, in the form `x25519::ladder_in` documents,
/// as a single straight-line assembly block over `ws`.
///
/// `ws` holds field elements in 32-byte slots: `x1`, then the two points
/// `(xm, zm)` and `(xn, zn)`, which are read and replaced, then scratch.
/// `swap`, 0 or 1 and secret, chooses the point to double by two `CMOV`
/// selections; nothing branches on it or indexes by it.
///
/// The same operations, in the same order, as the generic step in
/// `x25519::ladder_in` -- which the tests compare this against, on the RFC
/// 7748 vectors and on random inputs.
#[inline(never)]
pub fn ladder_step(ws: &mut [u64; slot::LEN], swap: u64) {
    // Byte offsets: x1 0, xm 32, zm 64, xn 96, zn 128, then scratch -- sm
    // 160, dm 192, sn 224, dn 256, s 288, d 320, dmsn 352, dnsm 384, ss 416,
    // dd 448, t1 480, t2 512, e 544, t3 576.
    //
    // The additions and subtractions fold their carry once, not twice:
    // every operand they see is a product or square, below 2^255 + 19 * 77,
    // or one of the starting values 0, 1 and x1 < 2^255, which is the bound
    // `fe_add_once!` and `fe_sub_once!` state. The test
    // `the_block_ladder_agrees_with_the_generic_one` covers it.
    //
    // SAFETY: every access is to `ws`, a live exclusive borrow of 608 bytes,
    // at constant offsets below 608; registers are declared as clobbered,
    // `rdi` is not written, and nothing is pushed (`nostack`). `MULX`, `ADCX`
    // and `ADOX` need BMI2 and ADX, which the one caller, `x25519_ladder`, is
    // reached only after `available()` has confirmed.
    unsafe {
        asm!(
            fe_sub_once!(192, 32, 64),   // dm = xm - zm
            fe_add_once!(224, 96, 128),  // sn = xn + zn
            fe_sub_once!(256, 96, 128),  // dn = xn - zn
            fe_add_once!(160, 32, 64),   // sm = xm + zm
            // The doubling's input: m's sum and difference when swap is
            // set, n's when it is not.
            "test rsi, rsi\n",
            fe_cmovnz!(288, 224, 160), // s
            fe_cmovnz!(320, 256, 192), // d
            fe_mul!(352, 192, 224),    // dmsn = dm * sn
            fe_mul!(384, 160, 256),    // dnsm = sm * dn
            fe_sqr!(448, 320),         // dd = d^2
            fe_sqr!(416, 288),         // ss = s^2
            fe_sub_once!(480, 352, 384),    // t1 = dmsn - dnsm
            fe_add_once!(512, 352, 384),    // t2 = dmsn + dnsm
            fe_sqr!(480, 480),         // t1 = t1^2
            fe_sqr!(32, 512),          // xm = t2^2
            fe_sub_once!(544, 416, 448),    // e = ss - dd
            fe_mul121666_add!(576, 544, 448), // t3 = 121666 e + dd
            fe_mul!(96, 416, 448),     // xn = ss * dd
            fe_mul!(128, 544, 576),    // zn = e * t3
            fe_mul!(64, 480, 0),       // zm = x1 * t1
            in("rdi") ws.as_mut_ptr(),
            inout("rsi") swap => _,
            out("rax") _,
            out("rcx") _,
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

/// The doubling half of [`ladder_step`] alone, on the point in `xn`, `zn`:
/// what the ladder does at a bit it knows is zero, and at the top bit it
/// knows is one.
///
/// The operations and slots of [`ladder_step`]'s doubling, in its order;
/// both inputs are products or squares, or the starting values `x1 < 2^255`
/// and 1, which is the bound the one-fold additions need.
#[inline(never)]
pub fn ladder_double(ws: &mut [u64; slot::LEN]) {
    // SAFETY: as in `ladder_step`: constant offsets below 608 into a live
    // exclusive borrow of `ws`, every register written declared, nothing
    // pushed, and the one caller, `x25519_ladder`, reached only after
    // `available()`.
    unsafe {
        asm!(
            fe_add_once!(288, 96, 128),       // s = xn + zn
            fe_sub_once!(320, 96, 128),       // d = xn - zn
            fe_sqr!(448, 320),                // dd = d^2
            fe_sqr!(416, 288),                // ss = s^2
            fe_sub_once!(544, 416, 448),      // e = ss - dd
            fe_mul121666_add!(576, 544, 448), // t3 = 121666 e + dd
            fe_mul!(96, 416, 448),            // xn = ss * dd
            fe_mul!(128, 544, 576),           // zn = e * t3
            in("rdi") ws.as_mut_ptr(),
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
}

/// X25519's ladder on this field, for a clamped scalar, then the inversion.
/// The caller must have checked [`available`].
///
/// RFC 7748's clamping fixes four bits, and this takes them as fixed. Bit
/// 254 is one: the generic ladder's first step, from `(1 : 0)` and
/// `(x1 : 1)`, only ever doubles `(x1 : 1)` and leaves the sum `(x1 : 1)`,
/// so that step is the doubling alone. Bits 2 to 0 are zero: the last three
/// steps double the point the ladder has reached and nothing else, so after
/// bit 3 the result is selected and doubled three times. [`ladder_step`]
/// runs at the 251 bits from 253 to 3, the same in number and order for
/// every scalar; only the selection inside it reads the scalar.
///
/// The bits it reads are those positions of `scalar`, so a scalar not
/// clamped gives the result for its clamped form. The callers clamp first;
/// the tests compare this with the generic ladder on clamped scalars.
pub fn x25519_ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    use ic_core::Zeroize;
    let mut ws = [0u64; slot::LEN];
    let put = |ws: &mut [u64; slot::LEN], at: usize, v: Fe64| {
        ws[at..at + 4].copy_from_slice(&v.0);
    };
    let get = |ws: &[u64; slot::LEN], at: usize| -> Fe64 {
        let mut v = [0u64; 4];
        v.copy_from_slice(&ws[at..at + 4]);
        Fe64(v)
    };
    let x1 = Fe64::from_bytes(u);
    put(&mut ws, slot::X1, x1);
    // Bit 254: m is the sum, (x1 : 1), and n twice that.
    put(&mut ws, slot::XM, x1);
    put(&mut ws, slot::ZM, Fe64::ONE);
    put(&mut ws, slot::XN, x1);
    put(&mut ws, slot::ZN, Fe64::ONE);
    ladder_double(&mut ws);

    let mut prev = 1u64;
    for pos in (3..254).rev() {
        let bit = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);
        ladder_step(&mut ws, bit ^ prev);
        prev = bit;
    }

    // The point the generic ladder carries into bit 2, then bits 2 to 0.
    let m = mask(prev);
    let x = Fe64::select_mask(&get(&ws, slot::XN), &get(&ws, slot::XM), m);
    let z = Fe64::select_mask(&get(&ws, slot::ZN), &get(&ws, slot::ZM), m);
    put(&mut ws, slot::XN, x);
    put(&mut ws, slot::ZN, z);
    ladder_double(&mut ws);
    ladder_double(&mut ws);
    ladder_double(&mut ws);
    let (x, z) = (get(&ws, slot::XN), get(&ws, slot::ZN));
    ws.zeroize();
    x.mul(&z.invert()).to_bytes()
}

/// A field element modulo 2^255 - 19, as four little-endian 64-bit limbs.
///
/// Any 256-bit value; see the module note.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Fe64(pub(crate) [u64; 4]);

/// Whether this CPU can run the code in this module.
///
/// Every function here that multiplies executes `MULX`, `ADCX` and `ADOX`,
/// and nothing may call one unless this returned `true`. The callers are the
/// dispatch points in `x25519.rs` and `ed25519.rs`, which ask once per scalar
/// multiplication; it depends only on the CPU, never on data.
#[inline]
#[must_use]
pub fn available() -> bool {
    ic_core::cpu::has_bmi2_adx()
}

/// The all-ones mask when `bit` is 1, zero when it is 0, through a barrier.
///
/// `0 - bit`, computed in an assembly block the optimizer cannot see into, so
/// it cannot learn that the result is one of two values and turn what uses it
/// into a branch. [`Choice`] does the same job with `black_box`, which LLVM
/// lowers to an empty assembly block that clobbers *all memory*: in the ladder
/// that forced every live field element out to the stack and back three times
/// per step. This one touches no memory (`nomem`), so it costs one `neg`.
#[inline(always)]
pub fn mask(bit: u64) -> u64 {
    let mut m = bit;
    // SAFETY: one register instruction, present on every x86-64 CPU.
    unsafe {
        asm!("neg {m}", m = inout(reg) m, options(pure, nomem, nostack));
    }
    m
}

/// `a + b + carry`, with the carry out.
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    // Wrapping, though it cannot wrap, so an overflow-checked build adds no
    // branch on secret data.
    let t = (a as u128)
        .wrapping_add(b as u128)
        .wrapping_add(carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// Fold a carry word `c` that fell off the top, `x + c * 2^256 = x + 38c`.
///
/// Twice, since the first addition can itself carry; the second cannot,
/// because a carry out of the first leaves the low limb below `38c`.
/// Branch-free: the carry is multiplied in, not tested.
#[inline(always)]
const fn fold(w: [u64; 4], c: u64) -> [u64; 4] {
    let (w0, k) = adc(w[0], c.wrapping_mul(38), 0);
    let (w1, k) = adc(w[1], 0, k);
    let (w2, k) = adc(w[2], 0, k);
    let (w3, k) = adc(w[3], 0, k);
    let (w0, _) = adc(w0, k.wrapping_mul(38), 0);
    [w0, w1, w2, w3]
}

impl Fe64 {
    /// The additive identity.
    pub const ZERO: Fe64 = Fe64([0; 4]);
    /// The multiplicative identity.
    pub const ONE: Fe64 = Fe64([1, 0, 0, 0]);

    /// A constant written as five 51-bit limbs, the form `ed25519.rs` gives
    /// its constants in. Also the conversion from the five-limb field, whose
    /// limbs are below 2^52.
    pub const fn from_limbs51(l: [u64; 5]) -> Fe64 {
        // Each limb below 2^52 shifted to its place; the sum is below 2^257,
        // and what falls off the top is folded back. Wrapping, though nothing
        // wraps, so an overflow-checked build adds no branch: the four-lane
        // field unpacks secret values through here.
        let mut acc = (l[0] as u128).wrapping_add((l[1] as u128) << 51);
        let w0 = acc as u64;
        acc >>= 64;
        acc = acc.wrapping_add((l[2] as u128) << 38);
        let w1 = acc as u64;
        acc >>= 64;
        acc = acc.wrapping_add((l[3] as u128) << 25);
        let w2 = acc as u64;
        acc >>= 64;
        acc = acc.wrapping_add((l[4] as u128) << 12);
        let w3 = acc as u64;
        Fe64(fold([w0, w1, w2, w3], (acc >> 64) as u64))
    }

    /// Decode 32 little-endian bytes, ignoring the top bit as RFC 7748
    /// requires. Values from `p` to `2^255 - 1` are accepted unreduced, which
    /// the representation allows.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe64 {
        let load = |i: usize| -> u64 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            u64::from_le_bytes(v)
        };
        Fe64([load(0), load(1), load(2), load(3) & (u64::MAX >> 1)])
    }

    /// Multiplicative inverse, with `invert(0) == 0`, by constant-time
    /// divsteps rather than Fermat's exponentiation; see `fe64/inv.rs`.
    pub fn invert(&self) -> Fe64 {
        Fe64(inv::invert(self.canonical()))
    }

    /// Encode as 32 little-endian bytes, fully reduced modulo p.
    pub fn to_bytes(self) -> [u8; 32] {
        let r = self.canonical();
        let mut out = [0u8; 32];
        for (chunk, limb) in out.chunks_exact_mut(8).zip(r) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// The limbs of the representative below p.
    fn canonical(self) -> [u64; 4] {
        // Fold bit 255 as 19: x = (x mod 2^255) + 19 * bit, below 2^255 + 19.
        let w = self.0;
        let top = w[3] >> 63;
        let (x0, k) = adc(w[0], top.wrapping_mul(19), 0);
        let (x1, k) = adc(w[1], 0, k);
        let (x2, k) = adc(w[2], 0, k);
        let (x3, _) = adc(w[3] & (u64::MAX >> 1), 0, k);
        // Now x < 2p. x >= p exactly when x + 19 reaches 2^255, and then
        // x - p is x + 19 with that bit cleared.
        let (y0, k) = adc(x0, 19, 0);
        let (y1, k) = adc(x1, 0, k);
        let (y2, k) = adc(x2, 0, k);
        let (y3, _) = adc(x3, 0, k);
        // Through the barrier: a plain `wrapping_neg` here is the pattern
        // LLVM turned into a jump in `scalar::conditional_subtract_l`.
        let ge = mask(y3 >> 63);
        let y3 = y3 & (u64::MAX >> 1);
        [
            (y0 & ge) | (x0 & !ge),
            (y1 & ge) | (x1 & !ge),
            (y2 & ge) | (x2 & !ge),
            (y3 & ge) | (x3 & !ge),
        ]
    }

    /// Field addition.
    #[inline(always)]
    pub fn add(&self, other: &Fe64) -> Fe64 {
        let [mut r0, mut r1, mut r2, mut r3] = self.0;
        let [b0, b1, b2, b3] = other.0;
        // SAFETY: integer instructions on registers only (`nomem`), present
        // on every x86-64 CPU; no memory is read or written.
        unsafe {
            asm!(
                "add {r0}, {b0}",
                "adc {r1}, {b1}",
                "adc {r2}, {b2}",
                "adc {r3}, {b3}",
                // A carry out is 2^256 = 38; fold it, then fold again.
                "sbb {t}, {t}",
                "and {t}, 38",
                "add {r0}, {t}",
                "adc {r1}, 0",
                "adc {r2}, 0",
                "adc {r3}, 0",
                "sbb {t}, {t}",
                "and {t}, 38",
                "add {r0}, {t}",
                r0 = inout(reg) r0,
                r1 = inout(reg) r1,
                r2 = inout(reg) r2,
                r3 = inout(reg) r3,
                b0 = in(reg) b0,
                b1 = in(reg) b1,
                b2 = in(reg) b2,
                b3 = in(reg) b3,
                t = out(reg) _,
                options(pure, nomem, nostack),
            );
        }
        Fe64([r0, r1, r2, r3])
    }

    /// Field subtraction.
    #[inline(always)]
    pub fn sub(&self, other: &Fe64) -> Fe64 {
        let [mut r0, mut r1, mut r2, mut r3] = self.0;
        let [b0, b1, b2, b3] = other.0;
        // SAFETY: as in `add`.
        unsafe {
            asm!(
                "sub {r0}, {b0}",
                "sbb {r1}, {b1}",
                "sbb {r2}, {b2}",
                "sbb {r3}, {b3}",
                // A borrow added 2^256 = 38; take it back out, twice.
                "sbb {t}, {t}",
                "and {t}, 38",
                "sub {r0}, {t}",
                "sbb {r1}, 0",
                "sbb {r2}, 0",
                "sbb {r3}, 0",
                "sbb {t}, {t}",
                "and {t}, 38",
                "sub {r0}, {t}",
                r0 = inout(reg) r0,
                r1 = inout(reg) r1,
                r2 = inout(reg) r2,
                r3 = inout(reg) r3,
                b0 = in(reg) b0,
                b1 = in(reg) b1,
                b2 = in(reg) b2,
                b3 = in(reg) b3,
                t = out(reg) _,
                options(pure, nomem, nostack),
            );
        }
        Fe64([r0, r1, r2, r3])
    }

    /// Field negation.
    #[inline(always)]
    pub fn neg(&self) -> Fe64 {
        Fe64::ZERO.sub(self)
    }

    /// Field multiplication.
    ///
    /// The 512-bit product row by row, each row's low halves on the `CF`
    /// chain (`ADCX`) and high halves on the `OF` chain (`ADOX`), then the top
    /// four limbs times 38 folded into the bottom four the same way.
    #[inline(always)]
    pub fn mul(&self, other: &Fe64) -> Fe64 {
        let (r0, r1, r2, r3);
        // SAFETY: reads the four limbs at each of two valid, aligned
        // `[u64; 4]` borrows and nothing else (`readonly`); writes only
        // registers, all declared. `MULX`/`ADCX`/`ADOX` need BMI2 and ADX,
        // which every caller has established through `available()`.
        unsafe {
            asm!(
                // Row 0: a * b0 into r8..r12.
                "mov rdx, qword ptr [rdi]",
                "mulx r9, r8, qword ptr [rsi]",
                "mulx r10, rax, qword ptr [rsi + 8]",
                "add r9, rax",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "adc r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                // Row 1: a * b1 into r9..r13. r13 starts at zero and stands
                // in as the zero both chains end on.
                "mov rdx, qword ptr [rdi + 8]",
                "xor r13d, r13d",
                "mulx rcx, rax, qword ptr [rsi]",
                "adcx r9, rax",
                "adox r10, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adcx r10, rax",
                "adox r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adcx r11, rax",
                "adox r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adcx r12, rax",
                "adox rcx, r13",
                "adcx r13, rcx",
                // Row 2: a * b2 into r10..r14.
                "mov rdx, qword ptr [rdi + 16]",
                "xor r14d, r14d",
                "mulx rcx, rax, qword ptr [rsi]",
                "adcx r10, rax",
                "adox r11, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adcx r11, rax",
                "adox r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adcx r12, rax",
                "adox r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adcx r13, rax",
                "adox rcx, r14",
                "adcx r14, rcx",
                // Row 3: a * b3 into r11..r15.
                "mov rdx, qword ptr [rdi + 24]",
                "xor r15d, r15d",
                "mulx rcx, rax, qword ptr [rsi]",
                "adcx r11, rax",
                "adox r12, rcx",
                "mulx rcx, rax, qword ptr [rsi + 8]",
                "adcx r12, rax",
                "adox r13, rcx",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adcx r13, rax",
                "adox r14, rcx",
                "mulx rcx, rax, qword ptr [rsi + 24]",
                "adcx r14, rax",
                "adox rcx, r15",
                "adcx r15, rcx",
                // Reduce: r8..r11 += 38 * r12..r15, with rsi as zero.
                "mov edx, 38",
                "xor esi, esi",
                "mulx rcx, rax, r12",
                "adcx r8, rax",
                "adox r9, rcx",
                "mulx rcx, rax, r13",
                "adcx r9, rax",
                "adox r10, rcx",
                "mulx rcx, rax, r14",
                "adcx r10, rax",
                "adox r11, rcx",
                "mulx r12, rax, r15",
                "adcx r11, rax",
                "adox r12, rsi",
                "adcx r12, rsi",
                // r12 is now below 39. Take everything from bit 255 up, at
                // most 77, and fold it as 19 times itself: the result is
                // below 2^255 + 19 * 77, so this addition cannot carry out.
                "shld r12, r11, 1",
                "btr r11, 63",
                "imul r12, r12, 19",
                "add r8, r12",
                "adc r9, rsi",
                "adc r10, rsi",
                "adc r11, rsi",
                inout("rsi") self.0.as_ptr() => _,
                inout("rdi") other.0.as_ptr() => _,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") r0,
                out("r9") r1,
                out("r10") r2,
                out("r11") r3,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Fe64([r0, r1, r2, r3])
    }

    /// Field squaring.
    ///
    /// The six products off the diagonal once, doubled on the `CF` chain
    /// while the four on it are added on the `OF` chain: ten products where
    /// [`Fe64::mul`] makes sixteen.
    #[inline(always)]
    pub fn square(&self) -> Fe64 {
        let (r0, r1, r2, r3);
        // SAFETY: as in `mul`, with one input.
        unsafe {
            asm!(
                // a0 * (a1, a2, a3) into r9..r12.
                "mov rdx, qword ptr [rsi]",
                "mulx r10, r9, qword ptr [rsi + 8]",
                "mulx r11, rax, qword ptr [rsi + 16]",
                "add r10, rax",
                "mulx r12, rax, qword ptr [rsi + 24]",
                "adc r11, rax",
                "adc r12, 0",
                // a1 * (a2, a3) into r11..r13; rdi is zero from here on.
                "mov rdx, qword ptr [rsi + 8]",
                "xor edi, edi",
                "mulx rcx, rax, qword ptr [rsi + 16]",
                "adcx r11, rax",
                "adox r12, rcx",
                "mulx r13, rax, qword ptr [rsi + 24]",
                "adcx r12, rax",
                "adox r13, rdi",
                "adcx r13, rdi",
                // a2 * a3 into r13..r14.
                "mov rdx, qword ptr [rsi + 16]",
                "mulx r14, rax, qword ptr [rsi + 24]",
                "add r13, rax",
                "adc r14, rdi",
                // Double the off-diagonal sum (CF) and add the squares (OF).
                "mov rdx, qword ptr [rsi]",
                "mulx rcx, r8, rdx",
                "xor r15d, r15d",
                "adcx r9, r9",
                "adox r9, rcx",
                "mov rdx, qword ptr [rsi + 8]",
                "mulx rcx, rax, rdx",
                "adcx r10, r10",
                "adox r10, rax",
                "adcx r11, r11",
                "adox r11, rcx",
                "mov rdx, qword ptr [rsi + 16]",
                "mulx rcx, rax, rdx",
                "adcx r12, r12",
                "adox r12, rax",
                "adcx r13, r13",
                "adox r13, rcx",
                "mov rdx, qword ptr [rsi + 24]",
                "mulx rcx, rax, rdx",
                "adcx r14, r14",
                "adox r14, rax",
                "adcx r15, r15",
                "adox r15, rcx",
                // Reduce, exactly as `mul` does, with rdi as zero.
                "mov edx, 38",
                "xor edi, edi",
                "mulx rcx, rax, r12",
                "adcx r8, rax",
                "adox r9, rcx",
                "mulx rcx, rax, r13",
                "adcx r9, rax",
                "adox r10, rcx",
                "mulx rcx, rax, r14",
                "adcx r10, rax",
                "adox r11, rcx",
                "mulx r12, rax, r15",
                "adcx r11, rax",
                "adox r12, rdi",
                "adcx r12, rdi",
                "shld r12, r11, 1",
                "btr r11, 63",
                "imul r12, r12, 19",
                "add r8, r12",
                "adc r9, rdi",
                "adc r10, rdi",
                "adc r11, rdi",
                inout("rsi") self.0.as_ptr() => _,
                out("rdi") _,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") r0,
                out("r9") r1,
                out("r10") r2,
                out("r11") r3,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(pure, readonly, nostack),
            );
        }
        Fe64([r0, r1, r2, r3])
    }

    /// Multiplication by the Montgomery ladder constant `a24 = 121666`.
    #[inline(always)]
    pub fn mul121666(&self) -> Fe64 {
        let [a0, a1, a2, a3] = self.0;
        let (r0, r1, r2, r3);
        // SAFETY: registers only (`nomem`); `MULX` needs BMI2, established by
        // every caller through `available()`.
        unsafe {
            asm!(
                "mulx {h0}, {r0}, {a0}",
                "mulx {h1}, {r1}, {a1}",
                "add {r1}, {h0}",
                "mulx {h0}, {r2}, {a2}",
                "adc {r2}, {h1}",
                "mulx {h1}, {r3}, {a3}",
                "adc {r3}, {h0}",
                "adc {h1}, 0",
                // The fifth limb is below 2^17; fold it as 38 times itself.
                "imul {h1}, {h1}, 38",
                "add {r0}, {h1}",
                "adc {r1}, 0",
                "adc {r2}, 0",
                "adc {r3}, 0",
                "sbb {h1}, {h1}",
                "and {h1}, 38",
                "add {r0}, {h1}",
                a0 = in(reg) a0,
                a1 = in(reg) a1,
                a2 = in(reg) a2,
                a3 = in(reg) a3,
                r0 = out(reg) r0,
                r1 = out(reg) r1,
                r2 = out(reg) r2,
                r3 = out(reg) r3,
                h0 = out(reg) _,
                h1 = out(reg) _,
                in("rdx") 121_666u64,
                options(pure, nomem, nostack),
            );
        }
        Fe64([r0, r1, r2, r3])
    }

    /// `b` where `mask` is all ones, `a` where it is zero.
    #[inline(always)]
    pub fn select_mask(a: &Fe64, b: &Fe64, mask: u64) -> Fe64 {
        Fe64(core::array::from_fn(|i| {
            a.0[i] ^ (mask & (a.0[i] ^ b.0[i]))
        }))
    }

    /// Constant-time conditional move: `a = b` when `choice` is true.
    #[inline(always)]
    pub fn cmov(a: &mut Fe64, b: &Fe64, choice: Choice) {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        for i in 0..4 {
            a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fe;

    /// The comparison below is only a comparison if it runs. On the machines
    /// this is developed and benchmarked on it must; elsewhere the five-limb
    /// field is the only one in use, and there is nothing to compare.
    fn skip() -> bool {
        if available() {
            return false;
        }
        std::eprintln!("fe64: CPU lacks BMI2/ADX; four-limb field not exercised");
        true
    }

    /// xorshift64*, enough to walk the limb space.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        /// Limbs biased toward the edges: all-ones, zero and single bits are
        /// where carries and folds go wrong, and uniform limbs rarely make
        /// them.
        fn limb(&mut self) -> u64 {
            let r = self.next();
            match r % 8 {
                0 => u64::MAX,
                1 => 0,
                2 => 1u64 << (self.next() % 64),
                3 => u64::MAX - (self.next() % 64),
                _ => self.next(),
            }
        }
        fn fe(&mut self) -> Fe64 {
            Fe64([self.limb(), self.limb(), self.limb(), self.limb()])
        }
    }

    /// The same value in the five-limb field, through the integer: bytes of
    /// `x mod 2^256` reduced by the reference, so this does not trust
    /// `Fe64::to_bytes`.
    fn reference(x: &Fe64) -> Fe {
        // x = lo + 2^255 * top, and 2^255 = 19 (mod p).
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(x.0) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        let top = bytes[31] >> 7;
        let lo = Fe::from_bytes(&bytes);
        lo.add(&Fe::from_u64(19 * top as u64))
    }

    /// Values at the edges of both representations: 0, 1, p - 1, p, p + 1,
    /// 2p - 1, 2^255 - 1, 2^255, 2^256 - 1, 2^256 - 38 (which is 0 after one
    /// fold), and every value whose fold carries.
    fn edges() -> std::vec::Vec<Fe64> {
        const M: u64 = u64::MAX;
        let p = [M - 18, M, M, M >> 1];
        std::vec![
            Fe64([0, 0, 0, 0]),
            Fe64([1, 0, 0, 0]),
            Fe64([p[0] - 1, p[1], p[2], p[3]]),
            Fe64(p),
            Fe64([p[0] + 1, p[1], p[2], p[3]]),
            // 2p - 1 = 2^256 - 39.
            Fe64([M - 38, M, M, M]),
            Fe64([M, M, M, M >> 1]),
            Fe64([0, 0, 0, 1 << 63]),
            Fe64([M, M, M, M]),
            Fe64([M - 37, M, M, M]),
            Fe64([M - 36, M, M, M]),
            Fe64([38, 0, 0, 0]),
            Fe64([19, 0, 0, 1 << 63]),
            Fe64([M, 0, M, 0]),
            Fe64([0, M, 0, M]),
        ]
    }

    #[test]
    fn this_machine_runs_the_four_limb_field() {
        // Every x86-64 CPU since Broadwell and Zen has BMI2 and ADX. A
        // developer or CI machine without them would silently skip the
        // comparisons below, so say so loudly: set IC_EC_NO_ADX_OK=1 to
        // accept that on an old machine.
        if std::env::var_os("IC_EC_NO_ADX_OK").is_none() {
            assert!(
                available(),
                "this CPU has no BMI2/ADX, so the four-limb field is untested"
            );
        }
    }

    #[test]
    fn encoding_agrees_with_the_reference() {
        if skip() {
            return;
        }
        let mut rng = Rng(0x0123_4567_89ab_cdef);
        let mut cases = edges();
        for _ in 0..20_000 {
            cases.push(rng.fe());
        }
        for x in &cases {
            assert_eq!(x.to_bytes(), reference(x).to_bytes(), "to_bytes {x:x?}");
            // And decoding: the top bit is ignored, and an unreduced value
            // below 2^255 decodes to itself.
            let mut b = [0u8; 32];
            for (chunk, limb) in b.chunks_exact_mut(8).zip(x.0) {
                chunk.copy_from_slice(&limb.to_le_bytes());
            }
            assert_eq!(
                Fe64::from_bytes(&b).to_bytes(),
                Fe::from_bytes(&b).to_bytes(),
                "from_bytes {b:02x?}"
            );
        }
    }

    /// The differential test: every operation against the five-limb field,
    /// on edge values crossed with each other and on two million random
    /// pairs.
    #[test]
    fn every_operation_agrees_with_the_five_limb_field() {
        if skip() {
            return;
        }
        let check = |x: &Fe64, y: &Fe64| {
            let (rx, ry) = (reference(x), reference(y));
            assert_eq!(
                x.mul(y).to_bytes(),
                rx.mul(&ry).to_bytes(),
                "mul {x:x?} {y:x?}"
            );
            assert_eq!(
                x.add(y).to_bytes(),
                rx.add(&ry).to_bytes(),
                "add {x:x?} {y:x?}"
            );
            assert_eq!(
                x.sub(y).to_bytes(),
                rx.sub(&ry).to_bytes(),
                "sub {x:x?} {y:x?}"
            );
        };
        let check1 = |x: &Fe64| {
            let rx = reference(x);
            assert_eq!(
                x.square().to_bytes(),
                rx.square().to_bytes(),
                "square {x:x?}"
            );
            assert_eq!(x.neg().to_bytes(), rx.neg().to_bytes(), "neg {x:x?}");
            assert_eq!(
                x.mul121666().to_bytes(),
                rx.mul121666().to_bytes(),
                "mul121666 {x:x?}"
            );
        };

        let edges = edges();
        for x in &edges {
            check1(x);
            for y in &edges {
                check(x, y);
            }
        }

        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let n = if cfg!(debug_assertions) {
            200_000
        } else {
            2_000_000
        };
        for _ in 0..n {
            let (x, y) = (rng.fe(), rng.fe());
            check(&x, &y);
            check1(&x);
        }
    }

    /// Outputs are fed back as inputs in every chain of operations, so
    /// products of products are compared too: a fold that leaves an
    /// unreduced-but-valid value is fine, one that loses a carry shows up
    /// two steps later.
    #[test]
    fn chained_operations_agree() {
        if skip() {
            return;
        }
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let (mut x, mut y) = (rng.fe(), rng.fe());
        let (mut rx, mut ry) = (reference(&x), reference(&y));
        for i in 0..200_000 {
            match i % 5 {
                0 => {
                    x = x.mul(&y);
                    rx = rx.mul(&ry);
                }
                1 => {
                    y = y.square();
                    ry = ry.square();
                }
                2 => {
                    x = x.sub(&y);
                    rx = rx.sub(&ry);
                }
                3 => {
                    y = y.add(&x).mul121666();
                    ry = ry.add(&rx).mul121666();
                }
                _ => {
                    // Re-seed occasionally so the walk does not settle.
                    let z = rng.fe();
                    x = x.add(&z);
                    rx = rx.add(&reference(&z));
                }
            }
            assert_eq!(x.to_bytes(), rx.to_bytes(), "step {i}");
            assert_eq!(y.to_bytes(), ry.to_bytes(), "step {i}");
        }
    }

    /// The divstep inversion against Fermat's on the five-limb field: the
    /// two share no code. Edge values, unreduced representatives of them,
    /// and a hundred thousand random values.
    #[test]
    fn inversion_agrees_with_fermat() {
        if skip() {
            return;
        }
        let mut cases = edges();
        let mut rng = Rng(0x0bad_cafe_dead_beef);
        let n = if cfg!(debug_assertions) {
            5_000
        } else {
            100_000
        };
        for _ in 0..n {
            cases.push(rng.fe());
        }
        for x in &cases {
            let got = x.invert();
            let want = reference(x).invert();
            assert_eq!(got.to_bytes(), want.to_bytes(), "invert {x:x?}");
            // And it is an inverse, except of zero.
            let one = x.mul(&got).to_bytes();
            let zero = bool::from(ic_core::ct::is_zero(&x.to_bytes()));
            let mut expect = [0u8; 32];
            expect[0] = u8::from(!zero);
            assert_eq!(one, expect, "x * x^-1 for {x:x?}");
        }
    }

    #[test]
    fn conversion_from_five_limbs_is_exact() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for _ in 0..10_000 {
            // Limbs up to 2^52 - 1, the most the five-limb field holds.
            let l: [u64; 5] = core::array::from_fn(|_| rng.next() >> 12);
            assert_eq!(
                Fe64::from_limbs51(l).to_bytes(),
                Fe::from_limbs51(l).to_bytes(),
                "{l:x?}"
            );
        }
    }

    /// Where an X25519 agreement on this field spends its time: the ladder
    /// steps against the inversion and the encodings around them; and the
    /// ladder against the 255-step form it replaced, timed alternately.
    #[test]
    #[ignore = "diagnostic"]
    fn where_x25519_spends_its_time() {
        use std::time::Instant;
        if skip() {
            return;
        }
        let time = |label: &str, n: u32, f: &mut dyn FnMut()| {
            let mut best = f64::INFINITY;
            for _ in 0..9 {
                let s = Instant::now();
                for _ in 0..n {
                    f();
                }
                best = best.min(s.elapsed().as_secs_f64() / n as f64 * 1e9);
            }
            std::println!("{label:<32} {best:>9.1} ns");
        };
        let mut ws = [7u64; slot::LEN];
        time("251 ladder steps", 2000, &mut || {
            for i in 0..251u64 {
                ladder_step(core::hint::black_box(&mut ws), i & 1);
            }
        });
        time("ladder_double", 200_000, &mut || {
            ladder_double(core::hint::black_box(&mut ws));
        });
        let x = Fe64([1, 2, 3, 4]);
        time("invert", 20_000, &mut || {
            core::hint::black_box(core::hint::black_box(x).invert());
        });
        time("100 mul", 20_000, &mut || {
            let mut y = x;
            for _ in 0..100 {
                y = y.mul(&x);
            }
            core::hint::black_box(y);
        });
        time("100 square", 20_000, &mut || {
            let mut y = x;
            for _ in 0..100 {
                y = y.square();
            }
            core::hint::black_box(y);
        });

        // The 255-step ladder, for the alternating comparison.
        fn all_steps(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
            let mut ws = [0u64; slot::LEN];
            let x1 = Fe64::from_bytes(u);
            ws[slot::X1..slot::X1 + 4].copy_from_slice(&x1.0);
            ws[slot::XM..slot::XM + 4].copy_from_slice(&x1.0);
            ws[slot::ZM] = 1;
            ws[slot::XN] = 1;
            let mut prev = 0u64;
            for pos in (0..255).rev() {
                let bit = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);
                ladder_step(&mut ws, bit ^ prev);
                prev = bit;
            }
            let m = mask(prev);
            let g = |at: usize| Fe64([ws[at], ws[at + 1], ws[at + 2], ws[at + 3]]);
            let x = Fe64::select_mask(&g(slot::XN), &g(slot::XM), m);
            let z = Fe64::select_mask(&g(slot::ZN), &g(slot::ZM), m);
            x.mul(&z.invert()).to_bytes()
        }
        let mut k = [0x5au8; 32];
        k[0] &= 248;
        k[31] = (k[31] & 127) | 64;
        let u = [9u8; 32];
        assert_eq!(all_steps(&k, &u), x25519_ladder(&k, &u));
        let mut best = [f64::INFINITY; 2];
        for _ in 0..40 {
            for (i, f) in [
                all_steps as fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
                x25519_ladder,
            ]
            .into_iter()
            .enumerate()
            {
                let s = Instant::now();
                for _ in 0..100 {
                    core::hint::black_box(f(core::hint::black_box(&k), &u));
                }
                best[i] = best[i].min(s.elapsed().as_secs_f64() / 100.0 * 1e9);
            }
        }
        std::println!("{:<32} {:>9.1} ns", "x25519, 255 steps", best[0]);
        std::println!("{:<32} {:>9.1} ns", "x25519_ladder", best[1]);
    }

    #[test]
    fn select_and_cmov_are_conditional() {
        let (x, y) = (Fe64([1, 2, 3, 4]), Fe64([5, 6, 7, 8]));
        assert_eq!(Fe64::select_mask(&x, &y, mask(0)).0, x.0);
        assert_eq!(Fe64::select_mask(&x, &y, mask(1)).0, y.0);
        let mut c = x;
        Fe64::cmov(&mut c, &y, Choice::FALSE);
        assert_eq!(c.0, x.0);
        Fe64::cmov(&mut c, &y, Choice::TRUE);
        assert_eq!(c.0, y.0);
    }
}
