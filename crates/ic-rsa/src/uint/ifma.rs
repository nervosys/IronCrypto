//! Montgomery multiplication on AVX-512 IFMA, in radix `2^52`.
//!
//! # Why this exists
//!
//! On x86-64 the scalar multiply-accumulate is bounded by the integer ports:
//! [`super::x86`] runs at about 1.4 cycles a word-product on Zen 5, however the
//! carry chains are arranged, which leaves RSA-2048 signing at parity with the
//! fastest assembly around and no further. `VPMADD52LUQ` and `VPMADD52HUQ`
//! multiply eight pairs of 52-bit lanes and add the low or high 52 bits of each
//! product into 64-bit accumulators, two instructions a cycle. Twelve spare
//! bits in each lane mean a column can absorb hundreds of products before
//! anything has to carry, so the vector work has no carry chain at all.
//!
//! # The algorithm
//!
//! Almost-Montgomery multiplication, word-serial over `b`, with `W` limbs of 52
//! bits and `R' = 2^(52W)`, where `52W` exceeds the modulus width by 16 bits or
//! more:
//!
//! ```text
//! for i in 0..W:
//!     acc += a * b[i]                       (low halves at lane j, high at j+1)
//!     u    = acc[0] * k0 mod 2^52           (k0 = -m^-1 mod 2^52)
//!     acc += m * u                          (acc[0] becomes 0 mod 2^52)
//!     acc  = acc / 2^52                     (drop lane 0, carry into lane 1)
//! ```
//!
//! Lanes are never normalised inside the loop: every lane stays below `2^61`.
//! The accumulator is split across register sets -- low and high halves, and
//! for the 1024-bit kernel also `a * b[i]` and `m * u` -- because each set is a
//! dependency chain of its multiply-adds plus a lane shift, and a multiply-add
//! takes four cycles and the shift five.
//!
//! The serial dependency is `u`, which needs lane 0 exactly, carries and all.
//! Reading it back from the vector unit each row would put a broadcast, two
//! multiply-adds, a shift and an extraction on that path. Instead the scalar
//! registers track the next two columns: column `i + 1` is what the vector
//! held for it before row `i`, plus the four products of row `i` that land
//! there, plus the carry out of column `i`, which is `(x0 + 2^52 - 1) >> 52`
//! because `x0 + (m0 u mod 2^52)` is a multiple of `2^52`; column `i + 2`
//! likewise, without the carry. Only the vector's part of column `i + 2` is
//! read back, a row and a half before it is needed. The products use `a[j]`
//! and `m[j]` shifted left by twelve, so one `MULX` gives the high 52 bits in
//! its high word and the low 52 bits, shifted, in its low word. About eleven
//! cycles a row remain on the critical path.
//!
//! Inputs below `2^(B+1)`, for a `B`-bit modulus, give an output below
//! `2^(B+1)`, because `R'` is at least `2^(B+16)`; so outputs chain into
//! inputs without the conditional subtraction the 64-bit form needs, and
//! nothing here compares or branches on a value. The exponentiation converts
//! out at the end with one more multiplication by one, which lands at or below
//! `m`, and one masked subtraction.
//!
//! # Constant time
//!
//! Every branch is on the width, which is public. Every address is a base
//! pointer plus a constant, or the row pointer into `b`, which advances one
//! word per row whatever the values. IFMA, `MULX`, `IMUL` and the lane moves
//! have data-independent latency.
//!
//! # Safety
//!
//! [`Ctx::amm`] is the only way into the assembly, and it takes fixed-size
//! arrays and a context that can only be built for a width with a kernel, on
//! a CPU with the instructions. The comment on the assembly says which words
//! each address reaches.

use core::arch::asm;

use super::{Limbs, Uint};
use ic_core::Zeroize;

/// The low 52 bits.
const MASK: u64 = (1 << 52) - 1;

/// The widest vector this module handles, in words: five registers of eight.
const MAX_WORDS: usize = 40;

/// Where the kernel writes its output columns in the context buffer: past the
/// widest modulus and the four words after it, `k0` and `a[0..3]`, each
/// shifted left by twelve.
const LANES: usize = MAX_WORDS + 4;

/// Whether this CPU has AVX-512F, IFMA and BMI2, asked once.
pub(crate) fn available() -> bool {
    if super::adx_forced() {
        return false;
    }
    #[cfg(feature = "std")]
    {
        use core::sync::atomic::{AtomicU8, Ordering};
        // 0 not yet asked, 1 yes, 2 no.
        static CACHED: AtomicU8 = AtomicU8::new(0);
        match CACHED.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                // `--cfg ic_no_avx512` reports this false, for measuring the AVX2 paths.
                let have = !cfg!(ic_no_avx512)
                    && std::is_x86_feature_detected!("avx512f")
                    && std::is_x86_feature_detected!("avx512ifma")
                    && std::is_x86_feature_detected!("bmi2");
                CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
                have
            }
        }
    }
    // Without `std` there is no detection; this module is compiled only for
    // `scripts/ct-audit` to read, and nothing selects it.
    #[cfg(not(feature = "std"))]
    false
}

/// `(W, K)`: 52-bit limbs and eight-lane registers for a modulus of `limbs`
/// 64-bit words, where there is a kernel for it.
///
/// 1024, 1536 and 2048 bits: the primes of RSA-2048, -3072 and -4096, and the
/// modulus of RSA-2048. Each has at least 16 bits of headroom in `52W`.
fn geometry(limbs: usize) -> Option<(usize, usize)> {
    match limbs {
        16 => Some((20, 3)),
        24 => Some((30, 4)),
        32 => Some((40, 5)),
        _ => None,
    }
}

/// Whether [`Ctx::new`] will accept a modulus of `limbs` words on this CPU.
pub(crate) fn handles(limbs: usize) -> bool {
    geometry(limbs).is_some() && available()
}

/// A modulus prepared for the kernels, and the kernels' scratch.
pub(crate) struct Ctx {
    /// The modulus in radix `2^52`, zero-padded to `8K` words; then
    /// `k0 << 12`; then `a[0..3] << 12` for the call in progress; and from
    /// `LANES`, the kernel's output columns. The kernel reaches all of it
    /// through one pointer, which is what lets it fit the registers.
    k: [u64; LANES + MAX_WORDS],
    /// 52-bit limbs, `W`.
    words: usize,
    /// Registers per value, `K`.
    regs: usize,
    /// 64-bit limbs of the modulus.
    limbs: usize,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl Ctx {
    /// Prepare `n`, `limbs` words, with `n0inv = -n^-1 mod 2^64`. `None` when
    /// there is no kernel for the width or the CPU cannot run it.
    pub(crate) fn new(n: &Uint, limbs: usize, n0inv: u64) -> Option<Ctx> {
        let (words, regs) = geometry(limbs)?;
        if !available() {
            return None;
        }
        let mut k = [0u64; LANES + MAX_WORDS];
        to_radix52(&n.0[..limbs], &mut k[..words]);
        let top = 8 * regs;
        // k0 = -n^-1 mod 2^52 is the low 52 bits of -n^-1 mod 2^64, and the
        // kernel wants it shifted left by twelve.
        k[top] = (n0inv & MASK) << 12;
        Some(Ctx {
            k,
            words,
            regs,
            limbs,
        })
    }

    /// Set the context's geometry to that of a modulus of `limbs` words, for
    /// `scripts/ct-audit` to read the products at a fixed width. The buffer
    /// is left as it is.
    ///
    /// # Safety
    ///
    /// Asks nothing of the CPU: [`Ctx::amm`] after it needs AVX-512F, IFMA
    /// and BMI2.
    #[cfg(feature = "ct-probes")]
    pub(crate) unsafe fn set_width_for_probe(&mut self, limbs: usize) {
        if let Some((words, regs)) = geometry(limbs) {
            (self.words, self.regs, self.limbs) = (words, regs, limbs);
        }
    }

    /// 52-bit limbs per value.
    pub(crate) fn words(&self) -> usize {
        self.words
    }

    /// Convert `x`, below `2^(64 * limbs)`, into radix `2^52`.
    pub(crate) fn import(&self, x: &Uint, out: &mut Limbs) {
        out.fill(0);
        to_radix52(&x.0[..self.limbs], &mut out[..self.words]);
    }

    /// Convert a normalised value below `2^(64 * limbs)` back to 64-bit words.
    pub(crate) fn export(&self, x: &Limbs, out: &mut Uint) {
        *out = Uint::ZERO;
        from_radix52(&x[..self.words], &mut out.0[..self.limbs]);
    }

    /// `a * b / 2^(52W) mod m`, almost: congruent, and below `2^(B+1)` when
    /// both inputs are. Inputs must be normalised, every limb below `2^52`,
    /// and zero above `W`. The output is too.
    pub(crate) fn amm(&mut self, a: &Limbs, b: &Limbs, out: &mut Limbs) {
        // Read before the kernel runs: it is handed a pointer into `self`, so
        // a field read after it is a reload the compiler cannot fold.
        let words = self.words;
        let top = 8 * self.regs;
        for (slot, &limb) in self.k[top + 1..top + 4].iter_mut().zip(a) {
            *slot = limb << 12;
        }
        let (a, b, k) = (a.as_ptr(), b.as_ptr(), self.k.as_mut_ptr());
        // SAFETY: `Ctx::new` returned this context only after `available()`
        // said the CPU has AVX-512F, IFMA and BMI2, and only with `regs` in
        // 3..=5 and `words` in `20..=8 * regs`. The kernel for `regs` reads
        // `8 * regs <= 40` words of `a` (64 long), `8 * regs + 4 <= LANES`
        // words of `k`, and `words` of `b` (64 long), and writes `8 * regs`
        // words of `k` from `LANES`, which `k` has room for.
        let s = unsafe {
            match self.regs {
                3 => amm3(a, b, k, words),
                4 => amm4(a, b, k, words),
                _ => amm5(a, b, k, words),
            }
        };
        // Column 0 is the scalar's; the rest are the vector's. Carry them into
        // 52-bit limbs. Every lane is below 2^61 and the value below 2^(52W),
        // so nothing carries out of the top.
        self.k[LANES] = s;
        let mut carry = 0u64;
        for (o, &v) in out.iter_mut().zip(&self.k[LANES..]).take(words) {
            let v = v + carry;
            *o = v & MASK;
            carry = v >> 52;
        }
        out[words..].fill(0);
    }
}

/// Bits `52j .. 52j + 52` of `x` into `out[j]`.
fn to_radix52(x: &[u64], out: &mut [u64]) {
    for (j, o) in out.iter_mut().enumerate() {
        let bit = 52 * j;
        let (w, sh) = (bit / 64, bit % 64);
        let lo = x.get(w).copied().unwrap_or(0) >> sh;
        let hi = match sh {
            0 => 0,
            _ => x.get(w + 1).copied().unwrap_or(0) << (64 - sh),
        };
        *o = (lo | hi) & MASK;
    }
}

/// The inverse of [`to_radix52`], for a value that fits `out`.
fn from_radix52(x: &[u64], out: &mut [u64]) {
    for (j, &v) in x.iter().enumerate() {
        let bit = 52 * j;
        let (w, sh) = (bit / 64, bit % 64);
        if let Some(o) = out.get_mut(w) {
            *o |= v << sh;
        }
        if sh > 12 {
            if let Some(o) = out.get_mut(w + 1) {
                *o |= v >> (64 - sh);
            }
        }
    }
}

/// One kernel per register count.
///
/// The lists name registers by number: `zero` every accumulator; `extract`
/// the first register of each accumulator set, whose lane 2 is read back;
/// `luq_b`/`luq_u` the low-half multiply-adds by `b[i]` and by `u`, as
/// `(register, word offset / 8)`; `shift` each one-lane shift as
/// `(register, the register above it)`, `zmm13` holding zero; `huq_b`/`huq_u`
/// the high halves; `sum` how the sets fold into the first; `store` where the
/// folded registers go.
macro_rules! kernel {
    (
        $name:ident, $regs:literal,
        zero: [$($z:literal),+],
        extract: [$($e:literal),+],
        luq_b: [$(($lb:literal, $lbc:literal)),+],
        luq_u: [$(($lu:literal, $luc:literal)),+],
        shift: [$(($sd:literal, $sn:literal)),+],
        huq_b: [$(($hb:literal, $hbc:literal)),+],
        huq_u: [$(($hu:literal, $huc:literal)),+],
        sum: [$(($fd:literal, $fs:literal)),+],
        store: [$(($st:literal, $stc:literal)),+]
    ) => {
        /// See the module docs.
        ///
        /// # Safety
        ///
        /// The CPU must have AVX-512F, IFMA and BMI2. `a` must be readable for
        /// `8 * regs` words; `k` readable for `8 * regs + 4` words, laid out
        /// as [`Ctx::k`] describes, and writable for `8 * regs` words from
        /// `LANES`; `b` readable for `words` words; and
        /// `3 <= words <= 8 * regs`.
        #[inline(never)]
        unsafe fn $name(a: *const u64, b: *const u64, k: *mut u64, words: usize) -> u64 {
            let s: u64;
            // SAFETY: memory operands are `[a + 64c]` and `[k + 64c]` for
            // `c < regs` (words `0..8 * regs`); `[k + 64 * regs + 8j]` for
            // `j < 4` (`k0` and the shifted words); `[b]`, advanced one word
            // per row for `words` rows (words `0..words`); and
            // `[k + 8 * LANES + 64c]` for `c < regs`. Nothing is pushed. Every general
            // register written is an operand or declared clobbered, and
            // `xmm0`-`xmm15` are declared clobbered, which in LLVM's model
            // covers the `zmm0`-`zmm15` they alias. `vzeroupper` leaves the
            // upper halves clean for whatever SSE code runs next.
            unsafe {
                asm!(
                    $( concat!("vpxorq zmm", $z, ", zmm", $z, ", zmm", $z), )+
                    "vpxorq zmm13, zmm13, zmm13",
                    "xor {s:e}, {s:e}",
                    "xor {r:e}, {r:e}",
                    "2:",
                    // x3 = the vector's part of column i + 2: lane 2 of every
                    // accumulator set, before this row touches them.
                    "xor {x3:e}, {x3:e}",
                    $(
                        concat!("vextracti32x4 xmm12, zmm", $e, ", 1"),
                        "vmovq {x4}, xmm12",
                        "add {x3}, {x4}",
                    )+
                    "mov rdx, [{b}]",
                    "vpbroadcastq zmm14, rdx",
                    // s = x0 = column i + lo(a0 b); r = column i + 1 so far,
                    // plus hi(a0 b) + lo(a1 b); x3 += hi(a1 b) + lo(a2 b).
                    "mulx {x2}, {x1}, [{k} + {ash}]",
                    "shr {x1}, 12",
                    "add {s}, {x1}",
                    "add {r}, {x2}",
                    "mulx {x2}, {x1}, [{k} + {ash} + 8]",
                    "shr {x1}, 12",
                    "add {r}, {x1}",
                    "add {x3}, {x2}",
                    "mulx {x2}, {x1}, [{k} + {ash} + 16]",
                    "shr {x1}, 12",
                    "add {x3}, {x1}",
                    // rdx = u << 12 = x0 * (k0 << 12) mod 2^64, which is
                    // (x0 * k0 mod 2^52) << 12 with no masking; the vector
                    // side gets u itself. r += the carry out of column i.
                    "mov rdx, {s}",
                    "imul rdx, [{k} + {koff}]",
                    "mov {u}, rdx",
                    "shr {u}, 12",
                    "vpbroadcastq zmm15, {u}",
                    "mov {x4}, {s}",
                    "add {x4}, {mask}",
                    "shr {x4}, 52",
                    "add {r}, {x4}",
                    // With rdx = u << 12, MULX by m[j] gives hi(m[j] u) in its
                    // high word and lo(m[j] u) << 12 in its low word.
                    // s = column i + 1 = r + lo(m1 u) + hi(m0 u);
                    // r = column i + 2 so far = x3 + hi(m1 u) + lo(m2 u).
                    "mulx {x4}, {s}, [{k} + 8]",
                    "mulx {x2}, {x1}, [{k}]",
                    "shr {s}, 12",
                    "add {s}, {r}",
                    "add {s}, {x2}",
                    "add {x3}, {x4}",
                    "mulx {x2}, {x1}, [{k} + 16]",
                    "shr {x1}, 12",
                    "add {x3}, {x1}",
                    "mov {r}, {x3}",
                    // The vector side: low halves, shift, high halves.
                    $( concat!("vpmadd52luq zmm", $lb, ", zmm14, [{a} + 64*", $lbc, "]"), )+
                    $( concat!("vpmadd52luq zmm", $lu, ", zmm15, [{k} + 64*", $luc, "]"), )+
                    $( concat!("valignq zmm", $sd, ", zmm", $sn, ", zmm", $sd, ", 1"), )+
                    $( concat!("vpmadd52huq zmm", $hb, ", zmm14, [{a} + 64*", $hbc, "]"), )+
                    $( concat!("vpmadd52huq zmm", $hu, ", zmm15, [{k} + 64*", $huc, "]"), )+
                    "lea {b}, [{b} + 8]",
                    "dec {rows}",
                    "jnz 2b",
                    $( concat!("vpaddq zmm", $fd, ", zmm", $fd, ", zmm", $fs), )+
                    $( concat!("vmovdqu64 [{k} + {loff} + 64*", $stc, "], zmm", $st), )+
                    "vzeroupper",
                    a = in(reg) a,
                    k = in(reg) k,
                    b = inout(reg) b => _,
                    rows = inout(reg) words => _,
                    loff = const 8 * LANES,
                    mask = in(reg) MASK,
                    koff = const 64 * $regs,
                    ash = const 64 * $regs + 8,
                    s = out(reg) s,
                    r = out(reg) _,
                    u = out(reg) _,
                    x1 = out(reg) _,
                    x2 = out(reg) _,
                    x3 = out(reg) _,
                    x4 = out(reg) _,
                    out("rdx") _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                    options(nostack),
                );
            }
            s
        }
    };
}

// 1024 bits: four accumulator sets of three registers, so that each set's
// chain per row is one multiply-add and one shift.
kernel!(amm3, 3,
    zero: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    extract: [0, 3, 6, 9],
    luq_b: [(0, 0), (1, 1), (2, 2)],
    luq_u: [(3, 0), (4, 1), (5, 2)],
    shift: [(0, 1), (1, 2), (2, 13), (3, 4), (4, 5), (5, 13),
            (6, 7), (7, 8), (8, 13), (9, 10), (10, 11), (11, 13)],
    huq_b: [(6, 0), (7, 1), (8, 2)],
    huq_u: [(9, 0), (10, 1), (11, 2)],
    sum: [(0, 3), (6, 9), (0, 6), (1, 4), (7, 10), (1, 7), (2, 5), (8, 11), (2, 8)],
    store: [(0, 0), (1, 1), (2, 2)]);

// 1536 and 2048 bits: two sets, low and high halves. Four would need more
// registers than the sixteen this can name.
kernel!(amm4, 4,
    zero: [0, 1, 2, 3, 5, 6, 7, 8],
    extract: [0, 5],
    luq_b: [(0, 0), (1, 1), (2, 2), (3, 3)],
    luq_u: [(0, 0), (1, 1), (2, 2), (3, 3)],
    shift: [(0, 1), (1, 2), (2, 3), (3, 13), (5, 6), (6, 7), (7, 8), (8, 13)],
    huq_b: [(5, 0), (6, 1), (7, 2), (8, 3)],
    huq_u: [(5, 0), (6, 1), (7, 2), (8, 3)],
    sum: [(0, 5), (1, 6), (2, 7), (3, 8)],
    store: [(0, 0), (1, 1), (2, 2), (3, 3)]);

kernel!(amm5, 5,
    zero: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    extract: [0, 5],
    luq_b: [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)],
    luq_u: [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)],
    shift: [(0, 1), (1, 2), (2, 3), (3, 4), (4, 13), (5, 6), (6, 7), (7, 8), (8, 9), (9, 13)],
    huq_b: [(5, 0), (6, 1), (7, 2), (8, 3), (9, 4)],
    huq_u: [(5, 0), (6, 1), (7, 2), (8, 3), (9, 4)],
    sum: [(0, 5), (1, 6), (2, 7), (3, 8), (4, 9)],
    store: [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)]);
