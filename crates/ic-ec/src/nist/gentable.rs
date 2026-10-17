//! A precomputed table for multiplying a NIST curve's generator.
//!
//! # Why
//!
//! [`Point::mul_scalar`][super::point::Point::mul_scalar] handles an arbitrary
//! point: it builds `1..=16` times the point per call and walks the scalar five
//! bits at a time, which is what ECDH needs. Every digit still costs five
//! doublings, and for an arbitrary point nothing can remove them.
//!
//! ECDSA signing does not need it. `R = k*G` multiplies the generator, which is
//! the same point in every signature, so its multiples can be computed once.
//! Measured on P-256 before this existed: one scalar multiplication cost 146.8
//! microseconds and a whole signature 159.5, so the ladder was essentially the
//! entire operation and everything else -- RFC 6979, the inversion -- was
//! thirteen microseconds of it.
//!
//! # The shape
//!
//! The scalar is recoded into signed digits of `W` bits, each in
//! `[-2^(W-1), 2^(W-1))`, and window `i` stores `1..=2^(W-1)` times
//! `2^(W*i) * G`, affine. Then `k*G` is one addition per digit and no
//! doublings at all: the digit's multiple, negated in `y` when the digit is
//! negative, added to the accumulator. The lookup reads every entry of the
//! window and selects with conditional moves rather than indexing -- a table
//! indexed by a secret is a cache-timing channel.
//!
//! `W` is per curve, trading storage for additions: 6 for P-256 (43
//! additions, 88 KiB), 5 for P-384 (77, 118 KiB), 4 for P-521 (133, 150 KiB).
//! This replaced a radix-16 comb with two passes and four doublings between
//! them, 65 additions on P-256 in a complete projective formula; the
//! additions here are Jacobian with an affine operand, seven multiplications
//! and four squarings, and all but the last may be incomplete -- see
//! [`mul`] for why.
//!
//! # Where it lives
//!
//! Behind `std`, in a `static` per curve: one `OnceLock` per window, filled in
//! order on first use, or earlier through [`crate::prepare`]. `no_std`
//! multiplies the generator with [`Point::mul_scalar`], which uses this
//! module's [`Window`] and [`signed_digits_w`] against the point it is given,
//! one window built per call: five bits per addition, without the storage.
//!
//! The storage is static, not heap. It used to be a `Vec`, and a caller that
//! forbids allocation after start-up -- a TLS engine running in caller-owned
//! memory -- met that allocation in the middle of its first handshake. A
//! single `OnceLock` holding every window would avoid the heap, but its value
//! is built on the stack and then moved in, which is the whole table's worth
//! of stack; that overflowed once, and is why the `Vec` was there. A lock per
//! window needs neither: each window is built where it is stored, and at most
//! one window's worth of stack is in use at a time. `tests/cold_tables.rs`
//! checks that a first use allocates nothing.

use ic_core::ct::Choice;

use super::arith::masks_for;
use super::arith::Field;
use super::point::AffinePoint;
use super::point::Curve;
use super::point::Point;

/// The window width of [`Point::mul_scalar`]: five bits, signed digits in
/// `[-16, 16]`.
pub(super) const WIDTH: usize = 5;

/// Entries per window of [`Point::mul_scalar`]: the multiples `1..=16`.
pub(crate) const ENTRIES: usize = 1 << (WIDTH - 1);

/// `1..=16` times some fixed point, for [`Point::mul_scalar`].
pub(crate) struct Window<C: Curve>([Point<C>; ENTRIES]);

impl<C: Curve> Window<C> {
    /// Even multiples by doubling, odd ones by adding `base` to the even one
    /// below: `2k * base` and `base` are never the same point when `base` has
    /// prime order above 8, so [`Point::add_unequal`] is enough, and it also
    /// handles a `base` at infinity.
    pub(crate) fn new(base: &Point<C>) -> Self {
        Self(multiples(base))
    }

    /// `digit * base` for `digit` in `[-16, 16]`, without indexing by it.
    pub(crate) fn select(&self, digit: i8) -> Point<C> {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;

        // From all zeros, which is a point at infinity (Z = 0) and so the
        // answer for a zero digit, which matches no entry.
        let masks = masks_for::<ENTRIES>(magnitude as u32, 1);
        let mut out = match C::scan_point(&self.0, &masks) {
            Some([x, y, z]) => Point::from_coordinates(x, y, z),
            None => {
                let mut out = Point::zero();
                for (entry, mask) in self.0.iter().zip(masks) {
                    Point::or_masked(&mut out, entry, mask);
                }
                out
            }
        };
        out.conditional_negate(negative);
        out
    }
}

/// How many windows a [`Comb`] keeps.
pub(crate) const TEETH: usize = 4;

/// Digits of [`Point::mul_scalar`]'s recoding per window of a [`Comb`]: the
/// curve's digit count split [`TEETH`] ways, rounded up.
pub(crate) const fn comb_span<C: Curve>() -> usize {
    digit_count(C::SCALAR_BYTES, WIDTH).div_ceil(TEETH)
}

/// `1..=16` times each of `Q`, `2^(5m) * Q`, `2^(10m) * Q` and
/// `2^(15m) * Q`, affine, where `m` is [`comb_span`]: what a prepared ECDH
/// public key holds, so that a multiplication by it needs a quarter of the
/// doublings [`Point::mul_scalar`] does.
///
/// The scalar is recoded exactly as for [`Point::mul_scalar`], into signed
/// digits `d_i` of five bits, and digit `i = c*m + j` is window `c`'s digit
/// `j`: `k * Q` is the sum over `c` of `(sum_j d_(c*m+j) * 2^(5j)) * 2^(5cm) * Q`.
/// Horner's rule over `j`, shared by the four windows, makes that five
/// doublings per `j` and one mixed addition per digit -- the additions of
/// [`Point::mul_scalar`], and about a quarter of its doublings.
///
/// The windows are a public point's, built once; each digit's entry is read
/// by masks over the whole window, as everywhere else.
pub(crate) struct Comb<C: Curve> {
    windows: [AffineWindow<C, ENTRIES>; TEETH],
}

impl<C: Curve> Comb<C> {
    /// The windows of `q`, which must not be the identity: a point of prime
    /// order `n`, as every other point of a NIST curve is.
    pub(crate) fn new(q: &Point<C>) -> Self {
        let m = comb_span::<C>();
        let mut bases = [*q; TEETH];
        for c in 1..TEETH {
            let mut b = bases[c - 1];
            for _ in 0..WIDTH * m {
                b = b.double();
            }
            bases[c] = b;
        }
        Self {
            windows: AffineWindow::new_many(&bases),
        }
    }

    /// The windows, for the tests of `Curve::comb_mul_fast`.
    #[cfg(test)]
    pub(crate) fn windows(&self) -> &[AffineWindow<C, ENTRIES>; TEETH] {
        &self.windows
    }

    /// The window of `Q` itself, for the compiled-code probes.
    #[cfg(feature = "ct-probes")]
    pub(crate) fn first_window(&self) -> &AffineWindow<C, ENTRIES> {
        &self.windows[0]
    }

    /// `scalar * Q`, constant time in the scalar: [`Curve::comb_mul_fast`]
    /// where the curve has it, else [`Self::mul_generic`].
    pub(crate) fn mul(&self, scalar: &C::Scalar) -> Point<C> {
        if let Some(p) = C::comb_mul_fast(&self.windows, scalar) {
            return p;
        }
        self.mul_generic(scalar)
    }

    /// `scalar * Q`, constant time in the scalar, on the `Fp` form.
    ///
    /// # Which additions can be incomplete
    ///
    /// Before window `c`'s digit at step `j` is added, the accumulator is
    /// `A * Q`, where `A` is the sum of `d_i * 32^(i - j)` over the digits
    /// already added: those at a higher step, and those of the windows below
    /// `c` at step `j`. The entry is `E * Q` with `E = d * 32^(c*m)`. Every
    /// added digit sits at a position `i - j` other than `c*m` -- a higher
    /// step puts it at `c'*m + (j' - j)` with `0 < j' - j < m`, and a lower
    /// window at `c'*m` with `c' < c` -- so `A` is `H * 32^(c*m + 1) + L`,
    /// with `H` an integer and `|L| < (16/31) * 32^(c*m)`. `A = E` would make
    /// `32 * H - d = L / 32^(c*m)`, an integer of magnitude below one, so
    /// `d = 32 * H`, which for `|d| <= 16` is `d = 0`: a zero digit, which
    /// [`AffineWindow::add_to`] keeps out of the formula. So `A` and `E`
    /// differ as integers whenever `d` is not zero.
    ///
    /// They are then different points if `|A| + |E| < n`. The highest
    /// position in `A` is `N - 1 - j`, for `N` digits, so
    /// `|A| < (16/31) * 2^(5(N - j))`, which is below `2^(ORDER_BITS - 1) / 1.9`
    /// once `5(N - j) < ORDER_BITS`; and `|E| <= 2^(5(TEETH - 1)m + 4)`, far
    /// below that on every curve here (the test
    /// `comb_entries_are_small_against_the_order` holds it). `n` exceeds
    /// `2^(ORDER_BITS - 1)`, so those steps use the incomplete mixed
    /// addition. The steps where `5(N - j) >= ORDER_BITS` -- the last on
    /// P-256 and P-384, the last two on P-521 -- use the complete one. They
    /// need it: `the_comb_is_right_where_only_the_complete_addition_is`
    /// finds scalars on every curve where an incomplete addition at the last
    /// position meets equal inputs, and fails if that position is made
    /// incomplete.
    pub(crate) fn mul_generic(&self, scalar: &C::Scalar) -> Point<C> {
        let bytes = scalar.to_bytes();
        debug_assert_eq!(bytes.as_ref().len(), C::SCALAR_BYTES);
        let digits = signed_digits_w(bytes.as_ref(), WIDTH);
        let n = digit_count(C::SCALAR_BYTES, WIDTH);
        let m = comb_span::<C>();

        let mut acc = Point::identity();
        for j in (0..m).rev() {
            if j + 1 < m {
                for _ in 0..WIDTH {
                    acc = acc.double();
                }
            }
            let complete = WIDTH * (n - j) >= C::ORDER_BITS;
            for (c, window) in self.windows.iter().enumerate() {
                // Past the top digit: a public position, always zero.
                let i = c * m + j;
                if i < n {
                    acc = window.add_to(&acc, digits[i], complete);
                }
            }
        }
        acc
    }
}

/// `1..=E` times `base`, Jacobian: even multiples by doubling, odd ones by
/// one incomplete addition; see [`Window::new`].
fn multiples<C: Curve, const E: usize>(base: &Point<C>) -> [Point<C>; E] {
    let mut entries = [Point::identity(); E];
    entries[0] = *base;
    for i in 1..E {
        // entries[i] = (i + 1) * base
        entries[i] = if i % 2 == 1 {
            entries[i / 2].double()
        } else {
            entries[i - 1].add_unequal(base)
        };
    }
    entries
}

/// `a == b`, as a [`Choice`], without a comparison the compiler could turn
/// into a branch: the xor is zero exactly when they are equal, and zero minus
/// one is the only value here with the top bit set.
#[inline]
fn equal(a: u8, b: u8) -> Choice {
    Choice::from_u8((((a ^ b) as u32).wrapping_sub(1) >> 31) as u8)
}

/// `1..=E` times one power of the generator, affine, for [`mul`], or of a
/// prepared ECDH public key, for [`Comb`]: an affine entry makes the
/// accumulator's addition three multiplications cheaper.
pub struct AffineWindow<C: Curve, const E: usize>([AffinePoint<C>; E]);

impl<C: Curve, const E: usize> AffineWindow<C, E> {
    /// The window for `base`, a point of prime order `n` (any point but the
    /// identity), so none of its multiples `1..=E` is the identity.
    /// Normalised with one inversion
    /// for the whole window (Montgomery's trick): the product of every `Z`,
    /// inverted once, then unwound.
    #[cfg(feature = "std")]
    pub(crate) fn new(base: &Point<C>) -> Self {
        let [window] = Self::new_many(&[*base]);
        window
    }

    /// The windows for each of `bases`, normalised with a single inversion
    /// between them all: Montgomery's trick over the `N * E` values of `Z`,
    /// where [`Self::new`] on each would invert `N` times. A field inversion
    /// costs on the order of fifty multiplications; the trick spends three
    /// multiplications per value to save all but one.
    ///
    /// Everything here is a public point's, so nothing depends on a secret,
    /// and nothing branches on a value: the same operations run for any bases.
    /// Each must satisfy the requirement of [`Self::new`], so that no `Z` is
    /// zero and the product is invertible.
    pub(crate) fn new_many<const N: usize>(bases: &[Point<C>; N]) -> [Self; N] {
        let points: [[Point<C>; E]; N] = core::array::from_fn(|w| multiples(&bases[w]));
        let mut prefix = [[C::Field::ONE; E]; N];
        let mut acc = C::Field::ONE;
        for (row, pts) in prefix.iter_mut().zip(points.iter()) {
            for (p, point) in row.iter_mut().zip(pts.iter()) {
                *p = acc;
                acc = acc.mul(&point.z());
            }
        }
        // acc = the product of every z; walk back, peeling one z at a time.
        let mut inv = acc.invert();
        let mut out = [AffinePoint {
            x: C::Field::ZERO,
            y: C::Field::ZERO,
        }; E];
        let mut windows: [Self; N] = core::array::from_fn(|_| Self(out));
        for w in (0..N).rev() {
            for i in (0..E).rev() {
                let z_inv = inv.mul(&prefix[w][i]);
                inv = inv.mul(&points[w][i].z());
                let z_inv2 = z_inv.square();
                out[i] = AffinePoint {
                    x: points[w][i].x().mul(&z_inv2),
                    y: points[w][i].y().mul(&z_inv2.mul(&z_inv)),
                };
            }
            windows[w] = Self(out);
        }
        windows
    }

    /// `|digit| * base`'s coordinates, negated in `y` for a negative digit,
    /// without indexing by the digit. A zero digit matches no entry and
    /// selects `(0, 0)`, which the caller discards.
    pub(crate) fn select(&self, digit: i8) -> (C::Field, C::Field) {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;
        // A zero digit matches no entry and leaves (0, 0), which the caller
        // discards.
        let masks = masks_for::<E>(magnitude as u32, 1);
        let (x, mut y) = match C::scan_affine(&self.0, &masks) {
            Some(p) => (p.x, p.y),
            None => {
                let mut x = C::Field::ZERO;
                let mut y = C::Field::ZERO;
                for (entry, mask) in self.0.iter().zip(masks) {
                    C::Field::or_masked(&mut x, &entry.x, mask);
                    C::Field::or_masked(&mut y, &entry.y, mask);
                }
                (x, y)
            }
        };
        let ny = y.neg();
        C::Field::cmov(&mut y, &ny, negative);
        (x, y)
    }

    /// `acc + digit * base`, in constant time. With `complete` false, `acc`
    /// must not equal `digit * base`; see [`mul`].
    pub(super) fn add_to(&self, acc: &Point<C>, digit: i8, complete: bool) -> Point<C> {
        let (x, y) = self.select(digit);
        // A zero digit adds the identity, which has no affine form: the
        // addition is made anyway, of zeros, and discarded. All ones for a
        // zero digit: `digit as u8` is below 256, so subtracting one sets the
        // top bit only from zero.
        let zero = ((digit as u8 as u64).wrapping_sub(1) >> 63).wrapping_neg();
        if complete {
            let mut out = acc.add(&Point::from_affine(&AffinePoint { x, y }));
            Point::cmov(&mut out, acc, equal(digit as u8, 0));
            out
        } else {
            acc.add_affine_unequal_or_keep(&x, &y, zero)
        }
    }

    /// `acc + digit * base` for a public digit, as in verification.
    #[cfg(feature = "std")]
    fn add_to_vartime(&self, acc: &Point<C>, digit: i8) -> Point<C> {
        if digit == 0 {
            return *acc;
        }
        let entry = &self.0[digit.unsigned_abs() as usize - 1];
        if digit > 0 {
            acc.add_affine_vartime(&entry.x, &entry.y)
        } else {
            acc.add_affine_vartime(&entry.x, &entry.y.neg())
        }
    }
}

/// One curve's windows: `2^(W*i) * G` and its multiples `1..=E`, for each
/// `i`, where `E = 2^(W-1)`.
#[cfg(feature = "std")]
pub type Windows<C, const E: usize> = [std::sync::OnceLock<AffineWindow<C, E>>];

/// The window width that goes with `E` entries.
#[cfg(feature = "std")]
pub(crate) const fn width<const E: usize>() -> usize {
    E.trailing_zeros() as usize + 1
}

/// Fill every window, in order, sharing the doublings between them.
///
/// Costs about one variable-base scalar multiplication plus one inversion per
/// window, once. `built` makes it run once: a second caller waits for the
/// first rather than repeating the work.
#[cfg(feature = "std")]
pub fn prepare<C: Curve, const E: usize>(windows: &Windows<C, E>, built: &std::sync::OnceLock<()>) {
    built.get_or_init(|| {
        let mut base = Point::<C>::generator();
        for (i, slot) in windows.iter().enumerate() {
            if i > 0 {
                for _ in 0..width::<E>() {
                    base = base.double();
                }
            }
            slot.get_or_init(|| AffineWindow::new(&base));
        }
    });
}

/// Window `i`, built by itself if [`prepare`] somehow had not: slower, and
/// the same answer rather than a panic.
#[cfg(feature = "std")]
pub(crate) fn window<C: Curve, const E: usize>(
    windows: &Windows<C, E>,
    i: usize,
) -> &AffineWindow<C, E> {
    windows[i].get_or_init(|| {
        let mut base = Point::<C>::generator();
        for _ in 0..width::<E>() * i {
            base = base.double();
        }
        AffineWindow::new(&base)
    })
}

/// `scalar * G`, constant time in the scalar.
///
/// # Which additions can be incomplete
///
/// The digits are added least significant first, so before digit `i` the
/// accumulator is `L * G` with `L` the integer the digits below `i` spell,
/// `|L| < 2^(W*i) / 1.8`, and the entry is `d * 2^(W*i) * G`. They are equal
/// only if `L = d * 2^(W*i) mod n`. For `d != 0` the right side is at least
/// `2^(W*i)` in magnitude, more than `|L|`, so the two differ as integers; and
/// their difference is below `0.6 * 2^(W*(i+1))`, which is below `n`
/// whenever `W*(i+1) < ORDER_BITS`, since `n > 2^(ORDER_BITS-1)`. So up to
/// there the points differ, and [`Point::add_affine_unequal`] is exact; it
/// also handles an accumulator at infinity, and `d = 0` is discarded by the
/// caller. The windows above that bound -- one on P-256 and P-384, three on
/// P-521 -- use the complete addition.
#[cfg(feature = "std")]
pub fn mul<C: Curve, const E: usize>(
    windows: &Windows<C, E>,
    built: &std::sync::OnceLock<()>,
    scalar: &C::Scalar,
) -> Point<C> {
    prepare(windows, built);
    if let Some(p) = C::table_mul_fast(windows, scalar) {
        return p;
    }
    mul_generic(windows, scalar)
}

/// [`mul`] on the `Fp` form, after [`prepare`].
#[cfg(feature = "std")]
pub(crate) fn mul_generic<C: Curve, const E: usize>(
    windows: &Windows<C, E>,
    scalar: &C::Scalar,
) -> Point<C> {
    let w = width::<E>();
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), w);
    let n = digit_count(bytes.as_ref().len(), w);
    debug_assert!(n <= windows.len());

    let mut acc = Point::identity();
    for (i, digit) in digits.iter().take(n).enumerate() {
        let complete = w * (i + 1) >= C::ORDER_BITS;
        acc = window(windows, i).add_to(&acc, *digit, complete);
    }
    acc
}

/// `scalar * G` for a public scalar, as in verification: the entry is read by
/// index and zero digits are skipped.
#[cfg(feature = "std")]
pub fn mul_vartime<C: Curve, const E: usize>(
    windows: &Windows<C, E>,
    built: &std::sync::OnceLock<()>,
    scalar: &C::Scalar,
) -> Point<C> {
    prepare(windows, built);
    let w = width::<E>();
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), w);
    let n = digit_count(bytes.as_ref().len(), w);
    let mut acc = Point::identity();
    for (i, digit) in digits.iter().take(n).enumerate() {
        acc = window(windows, i).add_to_vartime(&acc, *digit);
    }
    acc
}

/// Digits of `W` bits in a `len`-byte scalar, plus one for the carry out of
/// the top.
pub(crate) const fn digit_count(len: usize, w: usize) -> usize {
    8 * len / w + 1
}

/// The widest digit expansion [`signed_digits_w`] produces: P-521's 66 bytes
/// at four bits.
const MAX_DIGITS_W: usize = 8 * 66 / 4 + 1;

/// The scalar as signed digits of `w` bits, each in `[-2^(w-1), 2^(w-1))`
/// but the top one, in `[0, 2^(w-1)]`, least significant first; `bytes` is
/// big-endian.
///
/// Branch-free in the scalar: each window's bits are read at a public
/// position, the carry is `(v + 2^(w-1)) >> w`, and the digit is `v` less the
/// carry shifted back. The top window absorbs the last carry.
pub(crate) fn signed_digits_w(bytes: &[u8], w: usize) -> [i8; MAX_DIGITS_W] {
    // Little-endian words, with room above the top for windows that run past
    // it.
    let mut limbs = [0u64; 10];
    for (i, byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (*byte as u64) << (8 * (i % 8));
    }
    let n = digit_count(bytes.len(), w);
    let mask = (1u64 << w) - 1;
    let half = 1i16 << (w - 1);
    let mut digits = [0i8; MAX_DIGITS_W];
    let mut carry = 0i16;
    for (i, digit) in digits.iter_mut().take(n).enumerate() {
        let bit = w * i;
        let (word, shift) = (bit / 64, bit % 64);
        // The window's bits, which may straddle two words. `shift` is public.
        let lo = limbs[word] >> shift;
        let hi = if shift + w > 64 {
            limbs[word + 1] << (64 - shift)
        } else {
            0
        };
        let v = ((lo | hi) & mask) as i16 + carry;
        if i + 1 == n {
            // The top window holds at most w - 1 of the scalar's bits, so
            // with the carry it is at most 2^(w-1): a magnitude the table
            // has, kept rather than recoded, because there is no digit above
            // to take a carry.
            *digit = v as i8;
        } else {
            carry = (v + half) >> w;
            *digit = (v - (carry << w)) as i8;
        }
    }
    digits
}

/// A curve that knows how to multiply its own generator.
///
/// The trait exists on every target; only the implementation differs. Under
/// `std` it is the table; under `no_std` it is [`Point::mul_scalar`] on the
/// generator, four bits at a time with no stored window, so callers need no
/// conditional bound and the generic code has one shape.
///
/// It is separate from [`Curve`] because the table's storage is a `static`,
/// which has to live in a concrete function body: a `static` inside a generic
/// function is shared across every instantiation, which would hand P-384 the
/// P-256 table.
pub trait HasGeneratorTable: Curve + Sized + 'static {
    /// `scalar * G`, constant time in the scalar.
    fn mul_generator(scalar: &Self::Scalar) -> super::point::Point<Self>;

    /// `scalar * G` for a public scalar: variable time.
    fn mul_generator_vartime(scalar: &Self::Scalar) -> super::point::Point<Self>;

    /// `G, 3G, .., 127G`, affine, for verification's joint chain
    /// (`nist::verify`); built on first use, or by
    /// [`Self::prepare_generator_table`]. Public values, read by index.
    #[cfg(feature = "std")]
    fn odd_generator_multiples() -> &'static [super::point::AffinePoint<Self>; super::verify::G_ODD];

    /// Build the table now rather than on first use. Nothing under `no_std`.
    fn prepare_generator_table();

    /// `scalar * G` by the table on the `Fp` form, whatever the CPU: what
    /// the tests compare a curve's own (`Curve::table_mul_fast`) with.
    #[cfg(all(test, feature = "std"))]
    fn table_mul_generic_for_tests(scalar: &Self::Scalar) -> super::point::Point<Self>;

    /// Window `i`'s entry for `digit`, as a multiplication reads it: for
    /// the tests' timing.
    #[cfg(all(test, feature = "std"))]
    fn table_select_for_tests(i: usize, digit: i8) -> (Self::Field, Self::Field);
}

/// Implement [`HasGeneratorTable`] for a curve, with its own storage, in
/// windows of `$entries = 2^(W-1)` multiples.
macro_rules! generator_table_for {
    ($curve:ty, $entries:literal) => {
        /// This curve's generator table, and whether it has been filled.
        #[cfg(feature = "std")]
        fn generator_table() -> (
            &'static $crate::nist::gentable::Windows<$curve, $entries>,
            &'static std::sync::OnceLock<()>,
        ) {
            const USED: usize = $crate::nist::gentable::digit_count(
                <$curve as $crate::nist::point::Curve>::SCALAR_BYTES,
                ($entries as usize).trailing_zeros() as usize + 1,
            );
            #[allow(clippy::declare_interior_mutable_const)]
            const EMPTY: std::sync::OnceLock<
                $crate::nist::gentable::AffineWindow<$curve, $entries>,
            > = std::sync::OnceLock::new();
            static WINDOWS: [std::sync::OnceLock<
                $crate::nist::gentable::AffineWindow<$curve, $entries>,
            >; USED] = [EMPTY; USED];
            static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            (&WINDOWS, &BUILT)
        }

        impl $crate::nist::gentable::HasGeneratorTable for $curve {
            #[cfg(feature = "std")]
            fn mul_generator(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                let (windows, built) = generator_table();
                $crate::nist::gentable::mul(windows, built, scalar)
            }

            #[cfg(not(feature = "std"))]
            fn mul_generator(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                $crate::nist::point::Point::<Self>::generator().mul_scalar(scalar)
            }

            #[cfg(feature = "std")]
            fn mul_generator_vartime(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                let (windows, built) = generator_table();
                $crate::nist::gentable::mul_vartime(windows, built, scalar)
            }

            #[cfg(not(feature = "std"))]
            fn mul_generator_vartime(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                $crate::nist::point::Point::<Self>::generator().mul_scalar_vartime(scalar)
            }

            #[cfg(feature = "std")]
            fn odd_generator_multiples(
            ) -> &'static [$crate::nist::point::AffinePoint<Self>; $crate::nist::verify::G_ODD]
            {
                static ODD: std::sync::OnceLock<
                    [$crate::nist::point::AffinePoint<$curve>; $crate::nist::verify::G_ODD],
                > = std::sync::OnceLock::new();
                ODD.get_or_init(|| {
                    $crate::nist::verify::odd_multiples_affine_vartime(
                        &$crate::nist::point::Point::<Self>::generator(),
                    )
                })
            }

            fn prepare_generator_table() {
                #[cfg(feature = "std")]
                {
                    let (windows, built) = generator_table();
                    $crate::nist::gentable::prepare(windows, built);
                    Self::odd_generator_multiples();
                }
            }

            #[cfg(all(test, feature = "std"))]
            fn table_mul_generic_for_tests(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                let (windows, built) = generator_table();
                $crate::nist::gentable::prepare(windows, built);
                $crate::nist::gentable::mul_generic(windows, scalar)
            }

            #[cfg(all(test, feature = "std"))]
            fn table_select_for_tests(
                i: usize,
                digit: i8,
            ) -> (
                <Self as $crate::nist::point::Curve>::Field,
                <Self as $crate::nist::point::Curve>::Field,
            ) {
                let (windows, built) = generator_table();
                $crate::nist::gentable::prepare(windows, built);
                $crate::nist::gentable::window(windows, i).select(digit)
            }
        }
    };
}

pub(crate) use generator_table_for;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// The recoding, read back: every width, scalars at the edges and a
    /// spread between, each digit in range and the digits summing to the
    /// scalar. Arithmetic in i128 over 15-byte scalars, independently of the
    /// curve code; 120 bits leaves every width's top window partly full.
    #[test]
    fn signed_digits_sum_to_the_scalar() {
        let mut cases: std::vec::Vec<[u8; 15]> = std::vec![[0; 15], [0xff; 15], [0x80; 15]];
        let mut x = [0u8; 15];
        for i in 0..200u32 {
            for (j, b) in x.iter_mut().enumerate() {
                *b = (i.wrapping_mul(2654435761) >> (j % 24)) as u8 ^ (j as u8).wrapping_mul(37);
            }
            cases.push(x);
        }
        for w in 4..=6 {
            for bytes in &cases {
                let digits = signed_digits_w(bytes, w);
                let n = digit_count(bytes.len(), w);
                let half = 1i128 << (w - 1);
                let mut sum = 0i128;
                for (i, d) in digits.iter().take(n).enumerate() {
                    let d = *d as i128;
                    if i + 1 == n {
                        assert!(0 <= d && d <= half, "top digit {d} at width {w}");
                    } else {
                        assert!(-half <= d && d < half, "digit {d} at width {w}");
                    }
                    sum += d << (w * i);
                }
                assert!(digits[n..].iter().all(|d| *d == 0));
                let want = bytes.iter().fold(0i128, |acc, b| (acc << 8) | *b as i128);
                assert_eq!(sum, want, "width {w}");
            }
        }
    }
}
