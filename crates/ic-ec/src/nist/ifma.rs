//! P-256 and P-384 scalar multiplication on AVX-512 IFMA.
//!
//! # Why
//!
//! On the MULX/ADX path a field multiplication is one carry chain through
//! the integer multiplier, and a point doubling's multiplications mostly
//! wait on one another. `VPMADD52LUQ`/`VPMADD52HUQ` multiply four 52-bit
//! lanes at once, and the point formulas have independent multiplications to
//! fill them: a doubling's are four rounds of at most four, an addition's
//! five rounds of at most four. So here a round of a formula is one vector
//! multiplication, four field elements to a `ymm` register, and a whole
//! formula is one `asm!` block, generated with its schedule and register
//! allocation by `scripts/gen_nist_ifma.py` (`super::ifma_kernels`), whose
//! notes say how the limbs are bounded and how the emitted code is checked.
//!
//! Where a computation is many independent additions -- `k * G` over the
//! generator's table -- the lanes hold four accumulators instead, a
//! coordinate to a vector, and every lane runs the same formula
//! ([`table_mul`]).
//!
//! # Representation
//!
//! P-256 is five limbs of 52 bits, Montgomery with R = 2^260; P-384 is eight
//! limbs of 48 bits, plain, reduced by p's own shape. A lane vector is
//! [`Lanes`]: limb `k` of the four lanes in one register's worth of words. A
//! Jacobian point is `(X, Y, Z)` in lanes 0 to 2. Points cross from the
//! `Fp` form (`super::point::Point`) through the `from_fp` kernel and back
//! through `to_fp`, which multiply by a constant that moves between the two
//! forms; the result is reduced below p here, by masked subtraction.
//!
//! # What runs here
//!
//! The three scalar multiplications that dominate ECDH and ECDSA signing,
//! each the same algorithm as its `Fp` counterpart, with the same argument
//! for which additions may be incomplete:
//!
//! - [`mul_scalar`] for [`Point::mul_scalar`]: ECDH from key bytes. Five-bit
//!   signed windows over sixteen Jacobian multiples, built here.
//! - [`comb_mul`] for `gentable::Comb::mul`: ECDH with a prepared key. Its
//!   affine windows stay in the `Fp` form and are read with the existing
//!   masked scan; the mixed addition converts the entry in its first round.
//! - [`table_mul`] for `gentable::mul`: `k * G` in signing, four digits at a
//!   time.
//!
//! The additions that must be complete -- where an accumulator could equal
//! the entry added -- are made in the `Fp` form by `Point::add`, after
//! converting back: one per multiplication on P-256 and P-384 (one per tooth
//! for the comb).
//!
//! # Constant time
//!
//! The kernels are fixed instruction sequences. Everything a digit decides
//! is a mask: the window entry by a masked scan over every entry, its sign,
//! whether it is zero and whether the accumulator is still the identity by
//! masks the kernels apply with `VPBLENDVB`. The loops run over public
//! counts. The accumulator's being the identity is tracked from the digits
//! rather than tested on `Z`: in [`mul_scalar`], before digit `i` it is
//! `32 S` times the point, `S` the integer the digits above spell, which is
//! zero exactly when every digit above is (`|d| <= 16 < 32`); and below the
//! complete position no addition cancels to the identity, by the argument on
//! [`Point::mul_scalar`]. The others are argued where they are.
//!
//! Kernels read the output of the one before where it was written: the
//! buffers alternate ([`Pair`]) rather than being copied, because a copy is
//! a store at a width the next kernel's loads do not forward from. The
//! working state is wiped before return.

use ic_core::ct::Choice;
use ic_core::Zeroize;

use super::arith::{masks_for, select_ct, Field};
use super::gentable::{
    comb_span, digit_count, signed_digits_w, AffineWindow, ENTRIES, TEETH, WIDTH,
};
use super::ifma_kernels as k;
use super::point::{Curve, Point};

/// Proof that this CPU runs the kernels: AVX2, AVX-512F, -DQ, -VL and IFMA,
/// with the OS saving their state. Only [`Ifma::get`] makes one.
#[derive(Clone, Copy)]
pub(crate) struct Ifma(());

impl Ifma {
    /// The token, where `crate::avx512` says yes; never under
    /// `--cfg ic_no_avx512`.
    #[inline]
    pub(crate) fn get() -> Option<Ifma> {
        if crate::avx512::ifma() {
            Some(Ifma(()))
        } else {
            None
        }
    }
}

/// Four field elements, limb `k` of each lane at `self.0[k]`. `pub` only so
/// that `ct_probes` can name it.
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct Lanes<const L: usize>([[u64; 4]; L]);

/// Spill space for a kernel.
#[repr(C, align(32))]
pub(crate) struct Spill<const N: usize>([u64; N]);

/// What a lane vector needs to be for the code below.
pub(crate) trait Vector: Copy {
    /// All limbs zero.
    fn zero() -> Self;
    /// Lane `lane` set to `limbs`.
    fn set(&mut self, lane: usize, limbs: &[u64]);
    /// Lane `lane`'s limbs into `out`.
    fn get(&self, lane: usize, out: &mut [u64]);
    /// Every word.
    fn words_mut(&mut self) -> &mut [u64];
    /// The first word, for a kernel.
    fn ptr(&self) -> *const u64;
    /// The first word, for a kernel.
    fn mut_ptr(&mut self) -> *mut u64;
    /// The OR over `w` of each entry masked by its mask, into `out`: a table
    /// scan, every entry read.
    fn scan(t: Ifma, w: &[Self; ENTRIES], masks: &[u64; ENTRIES], out: &mut Self);
}

impl<const L: usize> Vector for Lanes<L> {
    fn zero() -> Self {
        Lanes([[0; 4]; L])
    }
    fn set(&mut self, lane: usize, limbs: &[u64]) {
        for (row, x) in self.0.iter_mut().zip(limbs) {
            row[lane] = *x;
        }
    }
    fn get(&self, lane: usize, out: &mut [u64]) {
        for (row, x) in self.0.iter().zip(out.iter_mut()) {
            *x = row[lane];
        }
    }
    fn words_mut(&mut self) -> &mut [u64] {
        self.0.as_flattened_mut()
    }
    fn ptr(&self) -> *const u64 {
        self.0.as_ptr().cast()
    }
    fn mut_ptr(&mut self) -> *mut u64 {
        self.0.as_mut_ptr().cast()
    }
    fn scan(_: Ifma, w: &[Self; ENTRIES], masks: &[u64; ENTRIES], out: &mut Self) {
        // SAFETY: the token says the CPU has AVX2.
        unsafe { scan_avx2(w, masks, out) }
    }
}

/// [`Vector::scan`] in AVX2: per entry, one broadcast of its mask and an AND
/// and an OR per limb register. Masks and data only: no branch, and every
/// address is the table's, entry by entry.
#[target_feature(enable = "avx2")]
unsafe fn scan_avx2<const L: usize>(
    w: &[Lanes<L>; ENTRIES],
    masks: &[u64; ENTRIES],
    out: &mut Lanes<L>,
) {
    use core::arch::x86_64::*;
    let mut acc = [_mm256_setzero_si256(); L];
    for (entry, &m) in w.iter().zip(masks) {
        let mv = _mm256_set1_epi64x(m as i64);
        for (a, row) in acc.iter_mut().zip(entry.0.iter()) {
            // SAFETY: `row` is four words of a 32-byte-aligned `Lanes`.
            let x = unsafe { _mm256_load_si256(row.as_ptr().cast()) };
            *a = _mm256_or_si256(*a, _mm256_and_si256(x, mv));
        }
    }
    for (row, a) in out.0.iter_mut().zip(acc) {
        // SAFETY: as above, written.
        unsafe { _mm256_store_si256(row.as_mut_ptr().cast(), a) };
    }
}

/// What a kernel's spill space needs to be.
pub(crate) trait Scratch {
    /// Zeroed.
    fn zero() -> Self;
    /// The first word, for a kernel.
    fn mut_ptr(&mut self) -> *mut u64;
    /// Every word.
    fn words_mut(&mut self) -> &mut [u64];
}

impl<const N: usize> Scratch for Spill<N> {
    fn zero() -> Self {
        Spill([0; N])
    }
    fn mut_ptr(&mut self) -> *mut u64 {
        self.0.as_mut_ptr()
    }
    fn words_mut(&mut self) -> &mut [u64] {
        &mut self.0
    }
}

/// A generated kernel: inputs through `a` and `b`, masks through `m`, the
/// result through `o`, spills through `t`.
pub(crate) type Kernel = unsafe fn(*const u64, *const u64, *const u64, *mut u64, *mut u64);

/// A curve with kernels: the generated ones, and the conversions between
/// their limbs and the `Fp` form.
///
/// # Safety
///
/// Implementations promise that each kernel is the curve's own from
/// `super::ifma_kernels`, and that `V` and `S` are as wide as those kernels
/// read and write: `V` four lanes of `LIMBS` limbs, `S` the curve's spill
/// words. The calls below rely on it.
pub(crate) unsafe trait LaneCurve: Curve {
    /// A lane vector.
    type V: Vector;
    /// A kernel's spill space.
    type S: Scratch;
    /// Limbs per element.
    const LIMBS: usize;
    /// One doubling, `(X, Y, Z)` in lanes 0 to 2.
    const DOUBLE: Kernel;
    /// One addition of two such points, under three masks.
    const ADD: Kernel;
    /// One mixed addition of an affine point in the `Fp` form.
    const MADD: Kernel;
    /// Four mixed additions, a coordinate to a vector, masks a lane to a
    /// vector. Only the generator table, which needs `std`, uses it.
    #[cfg(feature = "std")]
    const MADD4: Kernel;
    /// A Jacobian point in the `Fp` form into lanes.
    const FROM_FP: Kernel;
    /// Lanes back to the `Fp` form, not yet below p.
    const TO_FP: Kernel;
    /// The same for four points, a coordinate to a vector.
    #[cfg(feature = "std")]
    const TO_FP4: Kernel;
    /// `x`'s `Fp` form, as limbs, into `out`.
    fn to_limbs(x: &Self::Field, out: &mut [u64]);
    /// The `Fp` element `limbs` stand for in the `Fp` form, reduced below p.
    fn from_limbs(limbs: &[u64]) -> Self::Field;
}

/// Masks for the kernels that take three words: negate the operand, the
/// operand is the identity (keep the accumulator), the accumulator is the
/// identity.
type Masks = [u64; 3];

const NONE: Masks = [0; 3];

/// `N` lane vectors twice over: a kernel reads one set and writes the other,
/// which the next one reads. Which set is current is a count of kernels
/// run, so public; it is used as an index, not tested.
struct Pair<V: Vector, const N: usize> {
    v: [[V; N]; 2],
    cur: usize,
}

impl<V: Vector, const N: usize> Pair<V, N> {
    fn new() -> Self {
        Pair {
            v: [[V::zero(); N]; 2],
            cur: 0,
        }
    }

    fn cur(&self) -> &[V; N] {
        &self.v[self.cur & 1]
    }

    /// The current set's first word and the other's, for a kernel from one
    /// into the other; the other becomes current.
    fn step(&mut self) -> (*const u64, *mut u64) {
        let i = self.cur & 1;
        let base = self.v.as_mut_ptr();
        self.cur ^= 1;
        // `[V; N]` is `N` lane vectors end to end, so its address is its
        // first vector's first word. `i` and `i ^ 1` are 0 and 1.
        (
            base.wrapping_add(i).cast_const().cast(),
            base.wrapping_add(i ^ 1).cast(),
        )
    }

    fn wipe(&mut self) {
        for v in self.v.iter_mut().flatten() {
            v.words_mut().zeroize();
        }
    }
}

/// Run a kernel. `b` may be null where the kernel reads no `b`.
///
/// # Safety
///
/// `f` must be one of `C`'s kernels; `a` and `b` must point to as many
/// whole lane vectors as it reads through them, `o` to as many as it
/// writes, `m` to as many words as it reads, and `o` must not overlap the
/// others.
#[inline(always)]
unsafe fn run<C: LaneCurve>(
    _: Ifma,
    f: Kernel,
    a: *const u64,
    b: *const u64,
    m: &[u64],
    o: *mut u64,
    s: &mut C::S,
) {
    // SAFETY: the caller's contract, with the token for the CPU and `s` the
    // curve's spill space.
    unsafe { f(a, b, m.as_ptr(), o, s.mut_ptr()) }
}

/// A point into lanes.
fn load<C: LaneCurve>(t: Ifma, p: &Point<C>, s: &mut C::S) -> C::V {
    let mut j = C::V::zero();
    let mut limbs = [0u64; 8];
    for (lane, x) in [p.x(), p.y(), p.z()].iter().enumerate() {
        C::to_limbs(x, &mut limbs);
        j.set(lane, &limbs[..C::LIMBS]);
    }
    let mut o = C::V::zero();
    // SAFETY: one lane vector in, one out.
    unsafe {
        run::<C>(
            t,
            C::FROM_FP,
            j.ptr(),
            core::ptr::null(),
            &NONE,
            o.mut_ptr(),
            s,
        )
    };
    j.words_mut().zeroize();
    o
}

/// Lanes back to a point.
fn store<C: LaneCurve>(t: Ifma, v: &C::V, s: &mut C::S) -> Point<C> {
    let mut o = C::V::zero();
    // SAFETY: one lane vector in, one out.
    unsafe {
        run::<C>(
            t,
            C::TO_FP,
            v.ptr(),
            core::ptr::null(),
            &NONE,
            o.mut_ptr(),
            s,
        )
    };
    let mut limbs = [0u64; 8];
    let mut c = [C::Field::ZERO; 3];
    for (lane, x) in c.iter_mut().enumerate() {
        o.get(lane, &mut limbs[..C::LIMBS]);
        *x = C::from_limbs(&limbs[..C::LIMBS]);
    }
    o.words_mut().zeroize();
    limbs.zeroize();
    Point::from_coordinates(c[0], c[1], c[2])
}

/// `|digit|` times the window's base, by a masked scan over every entry, and
/// the digit's masks: negative, zero. A zero digit reads all zeros.
fn select<V: Vector>(t: Ifma, w: &[V; ENTRIES], digit: i8, out: &mut V) -> (u64, u64) {
    let negative = u64::from((digit as u8) >> 7);
    let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u32;
    let masks = masks_for::<ENTRIES>(magnitude, 1);
    V::scan(t, w, &masks, out);
    (negative.wrapping_neg(), zero_mask(digit))
}

/// All ones when `digit` is zero.
fn zero_mask(digit: i8) -> u64 {
    (u64::from(digit as u8).wrapping_sub(1) >> 63).wrapping_neg()
}

/// `WIDTH` doublings of the current accumulator.
fn doublings<C: LaneCurve>(t: Ifma, acc: &mut Pair<C::V, 1>, s: &mut C::S) {
    for _ in 0..WIDTH {
        let (a, o) = acc.step();
        // SAFETY: one lane vector of one set in, one of the other out.
        unsafe { run::<C>(t, C::DOUBLE, a, core::ptr::null(), &NONE, o, s) };
    }
}

/// `scalar * p`, as [`Point::mul_scalar`]: the same digits, window and
/// additions, with the same argument for the incomplete ones, in lanes.
pub(crate) fn mul_scalar<C: LaneCurve>(t: Ifma, p: &Point<C>, scalar: &C::Scalar) -> Point<C> {
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), WIDTH);
    let n = digit_count(bytes.as_ref().len(), WIDTH);
    let mut s = C::S::zero();
    let base = load(t, p, &mut s);

    // 1..=16 times the base, as `gentable::Window::new`: entry `2j - 1` is
    // entry `j - 1` doubled, entry `2j` that plus the base -- never equal
    // inputs, since the base has prime order above 16.
    let mut w = [C::V::zero(); ENTRIES];
    w[0] = base;
    for j in 1..ENTRIES / 2 {
        let (done, rest) = w.split_at_mut(2 * j - 1);
        // SAFETY: lane vectors of the window, distinct.
        unsafe {
            run::<C>(
                t,
                C::DOUBLE,
                done[j - 1].ptr(),
                core::ptr::null(),
                &NONE,
                rest[0].mut_ptr(),
                &mut s,
            );
            run::<C>(
                t,
                C::ADD,
                rest[0].ptr(),
                base.ptr(),
                &NONE,
                rest[1].mut_ptr(),
                &mut s,
            );
        }
    }
    let (done, rest) = w.split_at_mut(ENTRIES - 1);
    // SAFETY: as above.
    unsafe {
        run::<C>(
            t,
            C::DOUBLE,
            done[ENTRIES / 2 - 1].ptr(),
            core::ptr::null(),
            &NONE,
            rest[0].mut_ptr(),
            &mut s,
        );
    }

    let mut acc = Pair::<C::V, 1>::new();
    // The top digit: the accumulator is the identity, so the addition
    // returns the entry (mask 2).
    let mut e = C::V::zero();
    let (neg, zero) = select(t, &w, digits[n - 1], &mut e);
    let (a, o) = acc.step();
    // SAFETY: one lane vector of each set, the entry another.
    unsafe { run::<C>(t, C::ADD, a, e.ptr(), &[neg, zero, u64::MAX], o, &mut s) };
    // All ones while every digit added so far was zero.
    let mut acc_inf = zero;
    for i in (1..n - 1).rev() {
        // The scan first: it does not depend on the accumulator, so the core
        // can run it beside the doublings.
        let (neg, zero) = select(t, &w, digits[i], &mut e);
        doublings::<C>(t, &mut acc, &mut s);
        let (a, o) = acc.step();
        // SAFETY: as above.
        unsafe { run::<C>(t, C::ADD, a, e.ptr(), &[neg, zero, acc_inf], o, &mut s) };
        acc_inf &= zero;
    }
    doublings::<C>(t, &mut acc, &mut s);

    // The last addition is the complete one, in the `Fp` form.
    let mut sum = store(t, &acc.cur()[0], &mut s);
    Point::cmov(
        &mut sum,
        &Point::identity(),
        Choice::from_u8((acc_inf & 1) as u8),
    );
    let (neg, _) = select(t, &w, digits[0], &mut e);
    let mut entry = store(t, &e, &mut s);
    entry.conditional_negate(Choice::from_u8((neg & 1) as u8));
    let mut out = sum.add(&entry);
    // A base at infinity: every multiple of it is.
    Point::cmov(&mut out, &Point::identity(), p.is_identity());

    e.words_mut().zeroize();
    for v in w.iter_mut() {
        v.words_mut().zeroize();
    }
    acc.wipe();
    s.words_mut().zeroize();
    out
}

/// An affine point in the `Fp` form into lanes 0 and 1, as `MADD` reads it.
fn operand<C: LaneCurve>(x: &C::Field, y: &C::Field, q: &mut C::V) {
    let mut limbs = [0u64; 8];
    C::to_limbs(x, &mut limbs);
    q.set(0, &limbs[..C::LIMBS]);
    C::to_limbs(y, &mut limbs);
    q.set(1, &limbs[..C::LIMBS]);
    limbs.zeroize();
}

/// `scalar * Q` over a prepared key's windows, as `gentable::Comb::mul`:
/// the same digits and order, five doublings per step and one mixed
/// addition per digit in lanes, until the steps whose additions must be
/// complete, which are made in the `Fp` form -- on P-256 and P-384 the last
/// step's four. The accumulator starts as the identity; as in `mul_scalar`
/// that is tracked from the digits, and `Comb::mul`'s argument is that no
/// incomplete addition meets equal or opposite points.
pub(crate) fn comb_mul<C: LaneCurve>(
    t: Ifma,
    windows: &[AffineWindow<C, ENTRIES>; TEETH],
    scalar: &C::Scalar,
) -> Point<C> {
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), WIDTH);
    let n = digit_count(C::SCALAR_BYTES, WIDTH);
    let m = comb_span::<C>();
    // Steps `j` at or below this one add completely: `5 (n - j)` reaches the
    // order's width. Public, from the curve.
    let last = (0..m)
        .rev()
        .find(|&j| WIDTH * (n - j) >= C::ORDER_BITS)
        .unwrap_or(0);
    let mut s = C::S::zero();
    let mut acc = Pair::<C::V, 1>::new();
    let mut q = C::V::zero();
    let mut acc_inf = u64::MAX;
    for j in (last + 1..m).rev() {
        if j + 1 < m {
            doublings::<C>(t, &mut acc, &mut s);
        }
        for (c, window) in windows.iter().enumerate() {
            let i = c * m + j;
            if i >= n {
                // Past the top digit: a public position.
                continue;
            }
            let (x, y) = window.select(digits[i]);
            operand::<C>(&x, &y, &mut q);
            let zero = zero_mask(digits[i]);
            let (a, o) = acc.step();
            // SAFETY: one lane vector of each set, the operand another.
            unsafe { run::<C>(t, C::MADD, a, q.ptr(), &[0, zero, acc_inf], o, &mut s) };
            acc_inf &= zero;
        }
    }
    // The doublings before the first complete step, in lanes; then the
    // rest in the `Fp` form.
    if last + 1 < m {
        doublings::<C>(t, &mut acc, &mut s);
    }
    let mut p = store(t, &acc.cur()[0], &mut s);
    Point::cmov(
        &mut p,
        &Point::identity(),
        Choice::from_u8((acc_inf & 1) as u8),
    );
    for j in (0..=last).rev() {
        if j < last {
            for _ in 0..WIDTH {
                p = p.double();
            }
        }
        for (c, window) in windows.iter().enumerate() {
            let i = c * m + j;
            if i < n {
                p = window.add_to(&p, digits[i], true);
            }
        }
    }
    q.words_mut().zeroize();
    acc.wipe();
    s.words_mut().zeroize();
    p
}

/// `scalar * G` over the generator's table, as `gentable::mul`, in four
/// accumulators at once: digit `i` goes to accumulator `i % 4`, and one
/// `MADD4` adds four digits' entries to the four, one per lane, every lane
/// the same formula. The windows whose additions must be complete are added
/// in the `Fp` form at the end.
///
/// # Why four accumulators may still use the incomplete addition
///
/// `gentable::mul`'s argument holds lane by lane: before digit `i` is added,
/// accumulator `i % 4` is `L * G` with `L` a sum of `d_j 2^(w j)` over some
/// of the digits below `i`, so `|L| < 2^(w i) / 1.8` still, and the entry is
/// `d_i 2^(w i) G`. Below the complete windows the two differ as integers,
/// and by less than `n`, so they are different points, and `L + d_i 2^(w i)`
/// is not zero either, so no addition cancels to the identity unseen. The
/// four sums are over disjoint sets of digits: two of them are equal, or
/// opposite, only if a signed-digit sum over distinct positions, below `n` in
/// magnitude, is zero -- only if both are the identity, which the addition
/// handles. So they are combined with `Point::add_unequal`.
#[cfg(feature = "std")]
pub(crate) fn table_mul<C: LaneCurve, const E: usize>(
    t: Ifma,
    windows: &super::gentable::Windows<C, E>,
    scalar: &C::Scalar,
) -> Point<C> {
    let window = |i| super::gentable::window(windows, i);
    let width = super::gentable::width::<E>();
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), width);
    let n = digit_count(bytes.as_ref().len(), width);
    // The first window whose addition must be complete. Public, from the
    // curve and the width.
    let first_complete = (0..n)
        .find(|&i| width * (i + 1) >= C::ORDER_BITS)
        .unwrap_or(n);
    let mut s = C::S::zero();
    let mut acc = Pair::<C::V, 3>::new();
    let mut q = [C::V::zero(); 2];
    let mut acc_inf = [u64::MAX; 4];
    let mut limbs = [0u64; 8];
    for start in (0..first_complete).step_by(4) {
        // Masks a lane to a vector: negate (never: the table's scan already
        // negates), keep the accumulator, the accumulator is the identity.
        let mut masks = [[0u64; 4]; 3];
        for (lane, inf) in acc_inf.iter_mut().enumerate() {
            let i = start + lane;
            let keep = if i < first_complete {
                let (x, y) = window(i).select(digits[i]);
                C::to_limbs(&x, &mut limbs);
                q[0].set(lane, &limbs[..C::LIMBS]);
                C::to_limbs(&y, &mut limbs);
                q[1].set(lane, &limbs[..C::LIMBS]);
                zero_mask(digits[i])
            } else {
                // Past the last incomplete window: a public position.
                u64::MAX
            };
            masks[1][lane] = keep;
            masks[2][lane] = *inf;
            *inf &= keep;
        }
        let (a, o) = acc.step();
        // SAFETY: three lane vectors of each set, two of operands, and the
        // twelve words of masks the kernel reads.
        unsafe { run::<C>(t, C::MADD4, a, q[0].ptr(), masks.as_flattened(), o, &mut s) };
    }
    // The four accumulators to the `Fp` form, and summed.
    let mut f = [C::V::zero(); 3];
    // SAFETY: three lane vectors in, three out.
    unsafe {
        run::<C>(
            t,
            C::TO_FP4,
            acc.cur()[0].ptr(),
            core::ptr::null(),
            &NONE,
            f[0].mut_ptr(),
            &mut s,
        )
    };
    let mut parts = [Point::<C>::identity(); 4];
    for (lane, (p, inf)) in parts.iter_mut().zip(acc_inf).enumerate() {
        let mut c = [C::Field::ZERO; 3];
        for (x, v) in c.iter_mut().zip(f.iter()) {
            v.get(lane, &mut limbs[..C::LIMBS]);
            *x = C::from_limbs(&limbs[..C::LIMBS]);
        }
        *p = Point::from_coordinates(c[0], c[1], c[2]);
        Point::cmov(p, &Point::identity(), Choice::from_u8((inf & 1) as u8));
    }
    let mut sum = parts[0]
        .add_unequal(&parts[1])
        .add_unequal(&parts[2].add_unequal(&parts[3]));
    for (i, digit) in digits.iter().enumerate().take(n).skip(first_complete) {
        sum = window(i).add_to(&sum, *digit, true);
    }
    for v in q.iter_mut().chain(f.iter_mut()) {
        v.words_mut().zeroize();
    }
    acc.wipe();
    limbs.zeroize();
    s.words_mut().zeroize();
    sum
}

/// The value five 52-bit limbs spell (P-256's), as five words: a 128-bit
/// accumulator, each limb added at its fixed offset, a word taken off at a
/// time. Limbs below 2^52, the top one any size: none overlaps the next.
#[inline(always)]
fn pack52(l: &[u64; 5]) -> [u64; 5] {
    let mut out = [0u64; 5];
    // Limb k starts at bit 52 k: word 0 at 0 and 52, then 40, 28, 16 into
    // words 1 to 3.
    let mut acc = u128::from(l[0]) + (u128::from(l[1]) << 52);
    out[0] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[2]) << 40);
    out[1] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[3]) << 28);
    out[2] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[4]) << 16);
    out[3] = acc as u64;
    out[4] = (acc >> 64) as u64;
    out
}

/// The value eight 48-bit limbs spell (P-384's), as seven words, the same
/// way. Limbs up to 2^50, so neighbours overlap: the accumulator adds.
#[inline(always)]
fn pack48(l: &[u64; 8]) -> [u64; 7] {
    let mut out = [0u64; 7];
    // Limb k starts at bit 48 k: 0 and 48 in word 0, 32 in word 1, 16 in
    // word 2, 0 and 48 in word 3, 32 in word 4, 16 in word 5.
    let mut acc = u128::from(l[0]) + (u128::from(l[1]) << 48);
    out[0] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[2]) << 32);
    out[1] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[3]) << 16);
    out[2] = acc as u64;
    acc = (acc >> 64) + u128::from(l[4]) + (u128::from(l[5]) << 48);
    out[3] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[6]) << 32);
    out[4] = acc as u64;
    acc = (acc >> 64) + (u128::from(l[7]) << 16);
    out[5] = acc as u64;
    out[6] = (acc >> 64) as u64;
    out
}

/// `v mod p` for `v < (TIMES + 1) p`, by `TIMES` masked subtractions; `p`
/// has `W - 1` words.
#[inline(always)]
fn reduce<const W: usize, const TIMES: usize>(mut v: [u64; W], p: &[u64]) -> [u64; W] {
    for _ in 0..TIMES {
        let mut d = [0u64; W];
        let mut borrow = 0u64;
        for (i, (di, vi)) in d.iter_mut().zip(v.iter()).enumerate() {
            let pi = if i + 1 < W { p[i] } else { 0 };
            let (x, b1) = vi.overflowing_sub(pi);
            let (x, b2) = x.overflowing_sub(borrow);
            *di = x;
            borrow = u64::from(b1 | b2);
        }
        // No borrow: v was at least p; keep the difference.
        v = select_ct(borrow.wrapping_sub(1), d, v);
    }
    v
}

/// Split the words of an `Fp` element's form into `limbs` limbs of `width`
/// bits, the top one taking what is left.
fn to_limbs_impl(w: &[u64], out: &mut [u64], limbs: usize, width: usize) {
    let mask = (1u64 << width) - 1;
    for (k, o) in out.iter_mut().enumerate().take(limbs) {
        let bit = width * k;
        let (word, shift) = (bit / 64, bit % 64);
        let lo = w[word] >> shift;
        // The bits past the word's end come from the next word, where there
        // is one and the limb reaches it. Public positions.
        let hi = match w.get(word + 1) {
            Some(next) if shift + width > 64 => next << (64 - shift),
            _ => 0,
        };
        *o = if k + 1 == limbs {
            lo | hi
        } else {
            (lo | hi) & mask
        };
    }
}

/// The kernel table for a curve.
macro_rules! lane_curve {
    ($curve:ty, $field:path, $p:expr, $words:literal, $limbs:expr, $width:literal, $spill:expr,
     $subtractions:expr, $pack:path,
     $double:path, $add:path, $madd:path, $madd4:path, $from_fp:path, $to_fp:path, $to_fp4:path) => {
        // SAFETY: the kernels are this curve's, `Lanes<$limbs>` is four lanes
        // of its limb count and `Spill<$spill>` its spill words.
        unsafe impl LaneCurve for $curve {
            type V = Lanes<{ $limbs }>;
            type S = Spill<{ $spill }>;
            const LIMBS: usize = $limbs;
            const DOUBLE: Kernel = $double;
            const ADD: Kernel = $add;
            const MADD: Kernel = $madd;
            #[cfg(feature = "std")]
            const MADD4: Kernel = $madd4;
            const FROM_FP: Kernel = $from_fp;
            const TO_FP: Kernel = $to_fp;
            #[cfg(feature = "std")]
            const TO_FP4: Kernel = $to_fp4;
            fn to_limbs(x: &Self::Field, out: &mut [u64]) {
                to_limbs_impl(&x.0, out, $limbs, $width);
            }
            fn from_limbs(limbs: &[u64]) -> Self::Field {
                let mut l = [0u64; $limbs];
                l.copy_from_slice(&limbs[..$limbs]);
                // A `to_fp` output is below `($subtractions + 1) p`, by the
                // generator's bounds, which its simulation checks.
                let v = reduce::<{ $words + 1 }, { $subtractions }>($pack(&l), &$p);
                l.zeroize();
                let mut out = [0u64; $words];
                out.copy_from_slice(&v[..$words]);
                $field(out)
            }
        }
    };
}

lane_curve!(
    crate::p256::P256,
    crate::p256::Fp,
    crate::nist::p256_field::P,
    4,
    k::P256_LIMBS,
    52,
    k::P256_SPILL_WORDS,
    k::P256_TO_FP_SUBTRACTIONS,
    pack52,
    k::p256_double,
    k::p256_add,
    k::p256_madd,
    k::p256_madd4,
    k::p256_from_fp,
    k::p256_to_fp,
    k::p256_to_fp4
);

lane_curve!(
    crate::p384::P384,
    crate::p384::Fp,
    crate::p384::P,
    6,
    k::P384_LIMBS,
    48,
    k::P384_SPILL_WORDS,
    k::P384_TO_FP_SUBTRACTIONS,
    pack48,
    k::p384_double,
    k::p384_add,
    k::p384_madd,
    k::p384_madd4,
    k::p384_from_fp,
    k::p384_to_fp,
    k::p384_to_fp4
);

/// For `scripts/ct-audit`: every kernel, the secret digit's read of a
/// window of lane vectors, and the conversion of a result back to the `Fp`
/// form, as functions it can compile and read. `unsafe` where they need
/// AVX-512 IFMA; nothing runs them.
#[cfg(feature = "ct-probes")]
pub mod probes {
    use super::*;

    pub use super::Lanes;
    /// A P-256 lane vector.
    pub type P256 = Lanes<{ k::P256_LIMBS }>;
    /// A P-384 lane vector.
    pub type P384 = Lanes<{ k::P384_LIMBS }>;
    /// Words of P-256 spill space.
    pub const P256_SPILL: usize = k::P256_SPILL_WORDS;
    /// Words of P-384 spill space.
    pub const P384_SPILL: usize = k::P384_SPILL_WORDS;

    macro_rules! kernels {
        ($($name:ident = $kernel:path, $v:ty, $spill:expr;)*) => {$(
            /// The kernel, with room for whatever it reads and writes:
            /// three lane vectors through `a` and `o`, two through `b`,
            /// twelve words of masks.
            ///
            /// # Safety
            ///
            /// The CPU must have AVX-512 IFMA (`Ifma::get`).
            #[inline(always)]
            pub unsafe fn $name(a: &[$v; 3], b: &[$v; 2], m: &[u64; 12], o: &mut [$v; 3], t: &mut [u64; $spill]) {
                // SAFETY: every buffer is as large as any kernel reads or
                // writes, and `o` and `t` are exclusive; the caller's for
                // the CPU.
                unsafe { $kernel(a.as_ptr().cast(), b.as_ptr().cast(), m.as_ptr(), o.as_mut_ptr().cast(), t.as_mut_ptr()) }
            }
        )*};
    }

    kernels! {
        p256_double = k::p256_double, P256, P256_SPILL;
        p256_add = k::p256_add, P256, P256_SPILL;
        p256_madd = k::p256_madd, P256, P256_SPILL;
        p256_madd4 = k::p256_madd4, P256, P256_SPILL;
        p256_from_fp = k::p256_from_fp, P256, P256_SPILL;
        p256_to_fp = k::p256_to_fp, P256, P256_SPILL;
        p256_to_fp4 = k::p256_to_fp4, P256, P256_SPILL;
        p384_double = k::p384_double, P384, P384_SPILL;
        p384_add = k::p384_add, P384, P384_SPILL;
        p384_madd = k::p384_madd, P384, P384_SPILL;
        p384_madd4 = k::p384_madd4, P384, P384_SPILL;
        p384_from_fp = k::p384_from_fp, P384, P384_SPILL;
        p384_to_fp = k::p384_to_fp, P384, P384_SPILL;
        p384_to_fp4 = k::p384_to_fp4, P384, P384_SPILL;
    }

    /// The read each digit of `mul_scalar` makes, the digit secret: the
    /// entry for `|digit|` by a masked scan over all sixteen, and the
    /// digit's sign and zero masks.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX2 (`Ifma::get` implies it).
    #[inline(always)]
    pub unsafe fn p256_select(w: &[P256; ENTRIES], digit: i8, out: &mut P256) -> [u64; 2] {
        let (neg, zero) = select(Ifma(()), w, digit, out);
        [neg, zero]
    }

    /// See [`p256_select`].
    ///
    /// # Safety
    ///
    /// As [`p256_select`].
    #[inline(always)]
    pub unsafe fn p384_select(w: &[P384; ENTRIES], digit: i8, out: &mut P384) -> [u64; 2] {
        let (neg, zero) = select(Ifma(()), w, digit, out);
        [neg, zero]
    }

    /// A `to_fp` result's limbs, a secret-derived coordinate, reduced to
    /// the `Fp` form.
    #[inline(always)]
    pub fn p256_from_limbs(limbs: &[u64; 5]) -> [u64; 4] {
        <crate::p256::P256 as LaneCurve>::from_limbs(limbs).0
    }

    /// See [`p256_from_limbs`].
    #[inline(always)]
    pub fn p384_from_limbs(limbs: &[u64; 8]) -> [u64; 6] {
        <crate::p384::P384 as LaneCurve>::from_limbs(limbs).0
    }
}

#[cfg(test)]
mod tests;
