//! Arithmetic modulo the Curve25519 group order.
//!
//! `L = 2^252 + 27742317777372353535851937790883648493`
//!
//! Ed25519 signing needs `(r + h*a) mod L` where every operand is secret, so
//! reduction must be constant-time.
//!
//! Two implementations of the same two functions. The portable one works in
//! 21-bit limbs and folds the part above `2^252` down by the digits of `-c`
//! ([`reduce_wide_portable`]); it is what every target but x86-64 runs, and
//! it needs nothing wider than a 32x32-bit product. On x86-64 (outside
//! `ic_limb32` and `ic_ec_portable`, as for the four-limb field) the scalars
//! are four 64-bit limbs instead, multiplied with 128-bit products, and
//! reduced by Barrett's method ([`w64`]): a fifth of the time. The tests hold
//! the two to the same answers, and to long division.

// On x86-64 the portable functions are the tests' oracle, not the path.
#![cfg_attr(
    all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))),
    allow(dead_code)
)]

/// The group order `L`, little-endian.
pub const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `L` as nine 32-bit little-endian limbs (the top limb is always zero).
const L_LIMBS: [u32; 9] = [
    0x5cf5_d3ed,
    0x5812_631a,
    0xa2f7_9cd6,
    0x14de_f9de,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x1000_0000,
    0x0000_0000,
];

/// Subtract `L` from `r` when `r >= L`, in constant time.
fn conditional_subtract_l(r: &mut [u32; 9]) {
    let mut diff = [0u32; 9];
    let mut borrow = 0u64;
    for i in 0..9 {
        let d = (r[i] as u64)
            .wrapping_sub(L_LIMBS[i] as u64)
            .wrapping_sub(borrow);
        diff[i] = d as u32;
        borrow = (d >> 63) & 1;
    }
    // `borrow == 0` means r >= L, so the difference is the value we want.
    //
    // Both barriers are load-bearing. Without them LLVM, under LTO, saw that
    // the mask is one of two values, recognised the masked merge below as a
    // select, and compiled it as a jump on the sign of the top limb's
    // difference: a branch on whether the secret nonce or S was at least L.
    // Valgrind found it (docs/CTGRIND.md); `ct_ed25519_reduce_wide` in
    // scripts/check-ct.py now holds the compiled code to having none. The
    // input barrier hides that the borrow is 0 or 1, and the output barrier
    // that the mask is 0 or all ones, as `ic_core::ct::Choice::mask` does.
    let keep = core::hint::black_box(borrow as u32) ^ 1;
    let mask = core::hint::black_box(keep.wrapping_neg());
    for i in 0..9 {
        r[i] ^= mask & (r[i] ^ diff[i]);
    }
}

/// The balanced base-2^21 digits of `-c`, where `L = 2^252 + c`.
///
/// `c` is 125 bits against `L`'s 253, and that is the whole reason this
/// reduction is cheap: `2^252 = L - c`, so `2^252 ≡ -c`, and folding a high
/// limb down multiplies it by something a fifth of the modulus rather than
/// something the size of it.
///
/// Derived, not transcribed: these are the balanced base-2^21 digits of
/// `-(L - 2^252)`, and `the_folding_constants_are_the_digits_of_minus_c`
/// recomputes them from `L` and checks. They agree with the constants ref10
/// publishes, which is the cross-check that the derivation is the right one.
const NEG_C_DIGITS: [i64; 6] = [666_643, 470_296, 654_183, -997_805, 136_657, -683_901];

/// Limbs in the working representation: 21 bits each, covering 512 bits.
const LIMBS: usize = 25;

/// Carry `limbs[i]` into `limbs[i + 1]`, keeping the representation balanced.
#[inline]
fn carry(limbs: &mut [i64; LIMBS], i: usize) {
    let c = (limbs[i] + (1 << 20)) >> 21;
    limbs[i] -= c << 21;
    limbs[i + 1] += c;
}

/// [`carry`] at limbs `0..n`, in order.
///
/// `n` is a constant at every call, and the calls are written out below it
/// rather than looped: as a loop, LLVM kept it rolled on the 32-bit targets,
/// and a rolled loop is a conditional jump the compiled-code gate cannot tell
/// from a secret one.
#[inline(always)]
fn carry_through(limbs: &mut [i64; LIMBS], n: usize) {
    macro_rules! carries {
        ($($k:literal)*) => {$(
            if $k < n {
                carry(limbs, $k);
            }
        )*};
    }
    carries!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23);
}

/// One round of `reduce_wide`'s folding: carry every limb, then push each
/// limb at or above `2^252` down twelve places, times the digits of `-c`.
#[inline(always)]
fn fold_round(limbs: &mut [i64; LIMBS]) {
    carry_through(limbs, LIMBS - 1);
    // Positions 24 down to 12, written out: as a loop LLVM kept it rolled.
    macro_rules! fold_down {
        ($($i:literal)*) => {$({
            let t = limbs[$i];
            limbs[$i] = 0;
            for (j, d) in NEG_C_DIGITS.iter().enumerate() {
                limbs[$i - 12 + j] += d * t;
            }
        })*};
    }
    fold_down!(24 23 22 21 20 19 18 17 16 15 14 13 12);
}

/// Reduce a 512-bit little-endian integer modulo `L`.
///
/// This used to be long division, one bit at a time: 512 rounds of shifting a
/// nine-limb accumulator and conditionally subtracting `L`, some fifteen
/// thousand operations. Signing does three of these -- two to turn a hash into
/// a scalar and one inside `mul_add` -- and they were about a third of its
/// time.
///
/// Folding instead. A limb at position `21i` for `i >= 12` carries a factor of
/// `2^252`, which is congruent to `-c`, so it can be pushed down twelve places
/// and multiplied by the six digits of `-c`. Thirteen such folds clear
/// everything above `2^252`, and the carries between them keep every limb
/// inside an `i64`.
///
/// Constant time: the loops are fixed, the folding is data-independent, and
/// the final subtractions are masked. The scalar being reduced is secret when
/// signing.
pub fn reduce_wide(input: &[u8; 64]) -> [u8; 32] {
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    {
        w64::reduce_wide(input)
    }
    #[cfg(not(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable)))))]
    {
        reduce_wide_portable(input)
    }
}

/// [`reduce_wide`] in 21-bit limbs, by folding; see there.
fn reduce_wide_portable(input: &[u8; 64]) -> [u8; 32] {
    // Unpack into 21-bit limbs, eight bytes at a time.
    //
    // A limb spans at most four bytes, so one unaligned 64-bit read and a
    // shift produces it. Doing this a bit at a time -- 525 iterations with a
    // bounds test each -- cost more than the folding it feeds.
    //
    // The array is built limb by limb, each index a literal, rather than
    // filled by a loop from a padded copy of the input: on the 32-bit targets
    // the loop stayed rolled and the copy and the zeroing became `memcpy` and
    // `memset` calls, none of which the compiled-code gate can read. Reads
    // past byte 63 are of zero, which is what the padding used to supply.
    #[inline(always)]
    fn limb(input: &[u8; 64], i: usize) -> i64 {
        let bit = i * 21;
        let mut v = 0u64;
        for k in 0..8 {
            let byte = input.get(bit / 8 + k).copied().unwrap_or(0);
            v |= (byte as u64) << (8 * k);
        }
        ((v >> (bit % 8)) & ((1 << 21) - 1)) as i64
    }
    macro_rules! unpack {
        ($($i:literal)*) => { [$(limb(input, $i)),*] };
    }
    let mut limbs: [i64; LIMBS] =
        unpack!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24);

    // Fold everything at or above 2^252 down, in rounds of carry-then-fold.
    //
    // The two steps have to alternate rather than interleave. A carry pass
    // writes into the limb above, so carrying inside the folding loop puts
    //a value back into a position the downward loop has already passed and will
    // never fold again. Carrying first bounds every limb below 2^21, which is
    // what keeps the products inside an i64: a digit is under 2^20, so a limb
    // receives at most six contributions under 2^41 each.
    //
    // Three rounds suffice -- a fold divides the excess above 2^252 by roughly
    // 2^127, so 2^512 comes down to 2^252 + 2^133 and then to nothing -- and
    // four are run because the count is fixed rather than tested, this being
    // constant-time code. `folding_agrees_with_long_division` covers the
    // largest input there is, which is where too few rounds would show.
    //
    // The four rounds are written out rather than looped. The loop count is
    // public, but LLVM kept the nest rolled, and a compiled loop is a
    // conditional jump that `scripts/check-ct.py` cannot tell from a secret
    // one; written out, `ct_ed25519_reduce_wide` has no jump at all.
    fold_round(&mut limbs);
    fold_round(&mut limbs);
    fold_round(&mut limbs);
    fold_round(&mut limbs);
    // Folding subtracts `c` times the high part, so the residue is congruent
    // to the input but may be negative -- it lies in roughly `(-L, L)`. Two
    // copies of `L` are added to put it safely above zero; the conditional
    // subtractions at the end take them off again.
    //
    // `L = 2^252 + c`, and `2^252` is exactly limb 12, so adding `L` is one
    // increment there and the digits of `c` at the bottom. `c`'s digits are
    // the negation of the folding constants, which is where they come from.
    for _ in 0..2 {
        limbs[12] += 1;
        for (j, d) in NEG_C_DIGITS.iter().enumerate() {
            limbs[j] -= d;
        }
    }
    carry_through(&mut limbs, 13);

    // Now non-negative. Settle into 21-bit limbs.
    let mut u = [0u64; 14];
    let mut borrow: i64 = 0;
    for (slot, &l) in u.iter_mut().zip(limbs.iter().take(14)) {
        let v = l + borrow;
        let m = v & ((1 << 21) - 1);
        borrow = (v - m) >> 21;
        *slot = m as u64;
    }
    debug_assert!(borrow >= 0, "reduction left a negative value");

    // Pack the 21-bit limbs into eight 32-bit words, each from the at most
    // three limbs it overlaps, with every index a literal. This used to merge
    // them into a zeroed byte buffer, which on the 32-bit targets compiled to
    // a `memset` call the compiled-code gate cannot read. Bits from 256 up are
    // dropped, as the buffer's truncation to 32 bytes dropped them: at most a
    // couple of multiples of L remain, well below 2^256.
    #[inline(always)]
    fn word(u: &[u64; 14], w: usize) -> u32 {
        let bit = 32 * w;
        let (i, s) = (bit / 21, bit % 21);
        ((u[i] >> s) | (u[i + 1] << (21 - s)) | (u[i + 2] << (42 - s))) as u32
    }
    macro_rules! pack {
        ($($w:literal)*) => { [$(word(&u, $w)),*, 0] };
    }
    let mut r: [u32; 9] = pack!(0 1 2 3 4 5 6 7);

    // At most a couple of multiples of L remain.
    conditional_subtract_l(&mut r);
    conditional_subtract_l(&mut r);
    conditional_subtract_l(&mut r);
    conditional_subtract_l(&mut r);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

/// Reduce a 256-bit little-endian integer modulo `L`.
#[cfg(test)]
pub fn reduce(input: &[u8; 32]) -> [u8; 32] {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(input);
    reduce_wide(&wide)
}

/// Compute `(a * b + c) mod L` for little-endian 32-byte scalars.
pub fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    {
        w64::mul_add(a, b, c)
    }
    #[cfg(not(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable)))))]
    {
        mul_add_portable(a, b, c)
    }
}

/// [`mul_add`] in 32-bit limbs, reduced by [`reduce_wide_portable`].
fn mul_add_portable(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let al = to_limbs(a);
    let bl = to_limbs(b);

    // Schoolbook 8x8 -> 16 limbs of 32 bits, starting from `c` rather than
    // adding it afterwards. Every limb stays below 2^32 between steps, so
    // each step is at most (2^32 - 1) + (2^32 - 1)^2 + (2^32 - 1) = 2^64 - 1
    // and fits a u64; `c` in the bottom eight limbs is under that bound
    // already.
    //
    // The rows are written out, and `c` enters here, for the reason the
    // folding rounds in `reduce_wide` are written out: the row loop and a
    // byte-wise carry loop that used to add `c` stayed rolled, and a rolled
    // loop is a jump the compiled-code gate cannot tell from a secret one.
    let cl = to_limbs(c);
    let mut prod = [0u64; 16];
    for i in 0..8 {
        prod[i] = cl[i] as u64;
    }
    #[inline(always)]
    fn row(prod: &mut [u64; 16], i: usize, ai: u32, bl: &[u32; 8]) {
        let mut carry = 0u64;
        for j in 0..8 {
            let t = prod[i + j] + (ai as u64) * (bl[j] as u64) + carry;
            prod[i + j] = t & 0xFFFF_FFFF;
            carry = t >> 32;
        }
        prod[i + 8] = carry;
    }
    row(&mut prod, 0, al[0], &bl);
    row(&mut prod, 1, al[1], &bl);
    row(&mut prod, 2, al[2], &bl);
    row(&mut prod, 3, al[3], &bl);
    row(&mut prod, 4, al[4], &bl);
    row(&mut prod, 5, al[5], &bl);
    row(&mut prod, 6, al[6], &bl);
    row(&mut prod, 7, al[7], &bl);

    let mut wide = [0u8; 64];
    for i in 0..16 {
        wide[i * 4..i * 4 + 4].copy_from_slice(&(prod[i] as u32).to_le_bytes());
    }
    reduce_wide_portable(&wide)
}

/// [`reduce_wide`] and [`mul_add`] on four 64-bit limbs, for x86-64.
///
/// Barrett reduction (Menezes, van Oorschot and Vanstone, *Handbook of
/// Applied Cryptography*, algorithm 14.42) with `b = 2^64` and `k = 4`, `L`
/// having four limbs: `q = floor(floor(x / b^3) * mu / b^5)` with `mu =
/// floor(b^8 / L)` is in general at most two below `floor(x / L)`. For this
/// `L` it is at most one: write `x = X b^3 + x0`; then `x / L - X mu / b^5 =
/// x0 / L + X e / b^5`, where `e = b^8 / L - mu` is the fraction dropped
/// from `mu`, and that is below `2^-60 + e`. `e` is about 0.225
/// (`barrett_constant_is_the_quotient` checks it is below `1 - 2^-59`), so
/// the two quotients' floors differ by at most one, `x - q L` lies in `[0,
/// 2L)`, and one masked subtraction of `L` finishes it. A second was
/// measured never to act, over every input the tests try, before the
/// argument was written down. `2L` is below
/// `2^254`, so that difference is computed modulo `2^256`, which `L`'s form
/// makes cheap: its limbs are `l0`, `l1`, 0 and `2^60`, and modulo `2^256`
/// the last contributes only `q0 << 252`.
///
/// Every operand is secret when signing. The products and carries are the
/// same instructions for every value, the loops have constant counts, and
/// the final choice is a mask through [`crate::fe64::mask`], which the
/// optimiser cannot see is one of two values; `ct_ed25519_reduce_wide` and
/// `ct_ed25519_mul_add` in `scripts/check-ct.py` hold the compiled code to
/// having no branch.
#[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
mod w64 {
    /// `L`, little-endian 64-bit limbs.
    pub(super) const L64: [u64; 4] = [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0, 1 << 60];

    /// `floor(2^512 / L)`, 260 bits. `barrett_constant_is_the_quotient`
    /// recomputes it from `L` by long division.
    pub(super) const MU: [u64; 5] = [
        0xed9c_e5a3_0a2c_131b,
        0x2106_215d_0863_29a7,
        0xffff_ffff_ffff_ffeb,
        0xffff_ffff_ffff_ffff,
        0xf,
    ];

    /// `a * b + c`, low limbs first.
    #[inline(always)]
    fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
        // At most (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1: no overflow.
        let t = u128::from(a) * u128::from(b) + u128::from(c) + u128::from(carry);
        (t as u64, (t >> 64) as u64)
    }

    /// `x mod L` for `x` below `2^512`, eight limbs.
    #[inline(always)]
    pub(super) fn reduce(x: &[u64; 8]) -> [u64; 4] {
        // q1 = floor(x / b^3), five limbs; q2 = q1 * mu, ten; q3 = q2's top
        // five, of which the product with L below needs only four.
        let mut q2 = [0u64; 10];
        for i in 0..5 {
            let mut carry = 0;
            for j in 0..5 {
                (q2[i + j], carry) = mac(x[3 + i], MU[j], q2[i + j], carry);
            }
            q2[i + 5] = carry;
        }
        let q = [q2[5], q2[6], q2[7], q2[8]];

        // q L mod 2^256: q * (l0 + l1 b), then q0 * 2^252.
        let mut ql = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0;
            for j in 0..2 {
                if i + j < 4 {
                    (ql[i + j], carry) = mac(q[i], L64[j], ql[i + j], carry);
                }
            }
            if i + 2 < 4 {
                ql[i + 2] = ql[i + 2].wrapping_add(carry);
            }
        }
        ql[3] = ql[3].wrapping_add(q[0] << 60);

        // r = x - q L, exactly, since it lies in [0, 2L) below 2^256.
        let mut r = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (d, b1) = x[i].overflowing_sub(ql[i]);
            let (d, b2) = d.overflowing_sub(u64::from(borrow));
            r[i] = d;
            borrow = b1 | b2;
        }
        subtract_l_if_above(r)
    }

    /// `r - L` if `r >= L`, else `r`, by a mask.
    #[inline(always)]
    fn subtract_l_if_above(r: [u64; 4]) -> [u64; 4] {
        let mut d = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (v, b1) = r[i].overflowing_sub(L64[i]);
            let (v, b2) = v.overflowing_sub(u64::from(borrow));
            d[i] = v;
            borrow = b1 | b2;
        }
        // All ones when r < L: keep r.
        let keep = crate::fe64::mask(u64::from(borrow));
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = d[i] ^ ((d[i] ^ r[i]) & keep);
        }
        out
    }

    fn limbs<const N: usize>(bytes: &[u8]) -> [u64; N] {
        let mut out = [0u64; N];
        for (i, limb) in out.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            *limb = u64::from_le_bytes(w);
        }
        out
    }

    fn bytes(r: &[u64; 4]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&r[i].to_le_bytes());
        }
        out
    }

    pub(super) fn reduce_wide(input: &[u8; 64]) -> [u8; 32] {
        bytes(&reduce(&limbs::<8>(input)))
    }

    pub(super) fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
        let a = limbs::<4>(a);
        let b = limbs::<4>(b);
        let c = limbs::<4>(c);
        // a b + c, from c rather than adding it after: below 2^512.
        let mut p = [c[0], c[1], c[2], c[3], 0, 0, 0, 0];
        for i in 0..4 {
            let mut carry = 0;
            for j in 0..4 {
                (p[i + j], carry) = mac(a[i], b[j], p[i + j], carry);
            }
            // No earlier row reached limb i + 4: it is still zero.
            p[i + 4] = carry;
        }
        bytes(&reduce(&p))
    }
}

fn to_limbs(bytes: &[u8; 32]) -> [u32; 8] {
    let mut l = [0u32; 8];
    for i in 0..8 {
        l[i] = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    l
}

/// Constant-time check that a little-endian scalar is canonical, i.e. `< L`.
///
/// RFC 8032 §5.1.7 requires verifiers to reject signatures whose `S` is not
/// canonical; skipping this is what makes an implementation malleable.
#[must_use = "a false return means the scalar encoding was non-canonical"]
pub fn is_canonical(s: &[u8; 32]) -> bool {
    let mut borrow = 0u16;
    for i in 0..32 {
        let d = (s[i] as u16).wrapping_sub(L[i] as u16).wrapping_sub(borrow);
        borrow = (d >> 8) & 1;
    }
    borrow == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_u64(v: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&v.to_le_bytes());
        b
    }

    #[test]
    fn small_values_are_unchanged() {
        for v in [0u64, 1, 2, 1000, u32::MAX as u64] {
            assert_eq!(reduce(&from_u64(v)), from_u64(v), "{v}");
        }
    }

    #[test]
    fn l_reduces_to_zero() {
        assert_eq!(reduce(&L), [0u8; 32]);
    }

    #[test]
    fn l_plus_one_reduces_to_one() {
        let mut l1 = L;
        // L ends in 0xed, so adding one cannot carry.
        l1[0] += 1;
        assert_eq!(reduce(&l1), from_u64(1));
    }

    #[test]
    fn maximum_wide_value_reduces_into_range() {
        let r = reduce_wide(&[0xffu8; 64]);
        assert!(is_canonical(&r), "reduction must land below L");
    }

    #[test]
    fn mul_add_matches_small_arithmetic() {
        let a = from_u64(1_000_003);
        let b = from_u64(7_919);
        let c = from_u64(65_537);
        let expected = from_u64(1_000_003u64 * 7_919 + 65_537);
        assert_eq!(mul_add(&a, &b, &c), expected);
    }

    #[test]
    fn mul_add_is_zero_for_multiples_of_l() {
        // L * 1 + 0 == 0 (mod L)
        assert_eq!(mul_add(&L, &from_u64(1), &[0u8; 32]), [0u8; 32]);
        // 0 * x + L == 0 (mod L)
        assert_eq!(mul_add(&[0u8; 32], &from_u64(5), &L), [0u8; 32]);
    }

    #[test]
    fn mul_add_result_is_always_canonical() {
        let a = [0xAAu8; 32];
        let b = [0x55u8; 32];
        let c = [0xF0u8; 32];
        assert!(is_canonical(&mul_add(&a, &b, &c)));
    }

    #[test]
    fn canonical_test_matches_the_boundary() {
        assert!(!is_canonical(&L), "L itself is not canonical");
        let mut below = L;
        below[0] -= 1;
        assert!(is_canonical(&below));
        assert!(is_canonical(&[0u8; 32]));
        assert!(!is_canonical(&[0xffu8; 32]));
    }

    /// Reduction must be a ring homomorphism: reducing before or after
    /// multiplying gives the same answer.
    #[test]
    fn reduction_commutes_with_multiplication() {
        let a = [0x37u8; 32];
        let b = [0x91u8; 32];
        let direct = mul_add(&a, &b, &[0u8; 32]);
        let pre = mul_add(&reduce(&a), &reduce(&b), &[0u8; 32]);
        assert_eq!(direct, pre);
    }

    /// The long division the folding replaced, kept as an oracle.
    ///
    /// Transcribed unchanged from the previous revision. It is obviously
    /// correct -- it is school long division with a conditional subtract at
    /// every bit -- and unusably slow, which is the combination an oracle
    /// wants.
    fn reduce_wide_by_long_division(input: &[u8; 64]) -> [u8; 32] {
        let mut r = [0u32; 9];
        for bit_index in (0..512).rev() {
            let mut carry = 0u32;
            for limb in r.iter_mut() {
                let next = *limb >> 31;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            r[0] |= ((input[bit_index / 8] >> (bit_index % 8)) & 1) as u32;
            conditional_subtract_l(&mut r);
        }
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&r[i].to_le_bytes());
        }
        out
    }

    /// The folding constants are the digits of `-c`, recomputed from `L`.
    ///
    /// They are the one part of this that looks like magic numbers, so they
    /// are checked against the definition rather than against a reference.
    #[test]
    fn the_folding_constants_are_the_digits_of_minus_c() {
        // c = L - 2^252, from L's own bytes.
        let mut c = [0u8; 32];
        c.copy_from_slice(&L);
        // Clear bit 252, which is L's leading term.
        c[31] &= !0x10;
        // Balanced base-2^21 digits of -c, low to high.
        let mut v: i128 = 0;
        for (i, b) in c.iter().enumerate().take(16) {
            v |= (*b as i128) << (8 * i);
        }
        let mut v = -v;
        let mut got = [0i64; 6];
        for slot in got.iter_mut() {
            let mut d = (v & ((1 << 21) - 1)) as i64;
            if d >= 1 << 20 {
                d -= 1 << 21;
            }
            *slot = d;
            v = (v - d as i128) >> 21;
        }
        assert_eq!(v, 0, "c did not fit in six digits");
        assert_eq!(got, NEG_C_DIGITS);
    }

    /// The folding reduction against the long division, over random inputs.
    ///
    /// Every bit pattern the folding can be handed, including the ones that
    /// make a limb go negative and borrow: the balanced representation is
    /// where this would go wrong, and it goes wrong on particular inputs
    /// rather than on all of them.
    #[test]
    fn folding_agrees_with_long_division() {
        let mut state = 0x2f6d_9c1b_a473_e850u64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for case in 0..3_000 {
            let mut input = [0u8; 64];
            match case {
                0 => {}
                1 => input = [0xff; 64],
                2 => input[0] = 1,
                3 => input[63] = 0x80,
                _ => {
                    for chunk in input.chunks_exact_mut(8) {
                        chunk.copy_from_slice(&next().to_le_bytes());
                    }
                    // Sometimes only the low half, so the fold has little to do.
                    if case % 5 == 0 {
                        input[32..].fill(0);
                    }
                }
            }
            let want = reduce_wide_by_long_division(&input);
            assert_eq!(reduce_wide(&input), want, "case {case}, input {input:?}");
            assert_eq!(
                reduce_wide_portable(&input),
                want,
                "case {case}, input {input:?}"
            );
        }
    }

    /// A xorshift generator for the comparisons below; any fixed sequence
    /// would do, this one is the folding test's.
    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    /// `k * L + delta` for small `k` and signed `delta`, as 64 bytes,
    /// computed in 32-bit limbs from `L`'s bytes: the inputs that sit at the
    /// edges of every final subtraction.
    fn near_multiple(k: u32, delta: i64) -> [u8; 64] {
        let mut acc = [0u64; 17];
        for i in 0..8 {
            let li = u64::from(u32::from_le_bytes([
                L[4 * i],
                L[4 * i + 1],
                L[4 * i + 2],
                L[4 * i + 3],
            ]));
            acc[i] += li * u64::from(k);
        }
        // delta, two's complement over 512 bits.
        let d = delta as u64;
        acc[0] += d & 0xffff_ffff;
        acc[1] += d >> 32;
        let fill = if delta < 0 { 0xffff_ffff } else { 0 };
        for limb in acc.iter_mut().take(16).skip(2) {
            *limb += fill;
        }
        let mut out = [0u8; 64];
        let mut carry = 0u64;
        for i in 0..16 {
            let v = acc[i] + carry;
            out[4 * i..4 * i + 4].copy_from_slice(&(v as u32).to_le_bytes());
            carry = v >> 32;
        }
        out
    }

    /// Inputs where the 64-bit reduction can go wrong: the boundaries of `L`
    /// and its small multiples, of `2^252` to `2^256` and of the whole range,
    /// and values with every limb at an extreme.
    fn edges() -> Vec<[u8; 64]> {
        let mut out = Vec::new();
        for k in 0..=40u32 {
            for delta in [-2i64, -1, 0, 1, 2] {
                if k == 0 && delta < 0 {
                    continue;
                }
                out.push(near_multiple(k, delta));
            }
        }
        for bit in [
            251usize, 252, 253, 254, 255, 256, 257, 315, 316, 383, 384, 447, 448, 510, 511,
        ] {
            let mut p = [0u8; 64];
            p[bit / 8] = 1 << (bit % 8);
            out.push(p);
            // 2^bit - 1.
            let mut m = [0u8; 64];
            for b in 0..bit {
                m[b / 8] |= 1 << (b % 8);
            }
            out.push(m);
        }
        out.push([0xff; 64]);
        for limb in 0..8 {
            let mut v = [0u8; 64];
            v[8 * limb..8 * limb + 8].fill(0xff);
            out.push(v);
            let mut w = [0xffu8; 64];
            w[8 * limb..8 * limb + 8].fill(0);
            out.push(w);
        }
        out
    }

    /// `floor(2^512 / L)` by long division, one bit at a time, against the
    /// Barrett constant.
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    #[test]
    fn barrett_constant_is_the_quotient() {
        let l = w64::L64;
        let mut r = [0u64; 5];
        let mut q = [0u64; 9];
        for bit in (0..=512).rev() {
            // r = 2 r + (the dividend's bit), the dividend being 2^512.
            let mut carry = u64::from(bit == 512);
            for limb in r.iter_mut() {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            // r >= L: subtract, and set the quotient bit.
            let mut d = [0u64; 5];
            let mut borrow = false;
            for i in 0..5 {
                let li = if i < 4 { l[i] } else { 0 };
                let (v, b1) = r[i].overflowing_sub(li);
                let (v, b2) = v.overflowing_sub(u64::from(borrow));
                d[i] = v;
                borrow = b1 | b2;
            }
            if !borrow {
                r = d;
                q[bit / 64] |= 1 << (bit % 64);
            }
        }
        assert_eq!(q[..5], w64::MU);
        assert!(q[5..].iter().all(|&w| w == 0));
        // The fraction mu drops, r / L, is below 1 - 2^-59, which is what
        // lets one final subtraction suffice (see `w64`): r < L - L / 2^59.
        let mut bound = [0u64; 5];
        let mut borrow = false;
        for i in 0..5 {
            let li = if i < 4 { l[i] } else { 0 };
            let shifted = if i < 4 {
                (li >> 59) | (if i < 3 { l[i + 1] << 5 } else { 0 })
            } else {
                0
            };
            let (v, b1) = li.overflowing_sub(shifted);
            let (v, b2) = v.overflowing_sub(u64::from(borrow));
            bound[i] = v;
            borrow = b1 | b2;
        }
        assert!(!borrow);
        let below = (0..5)
            .rev()
            .find(|&i| r[i] != bound[i])
            .is_some_and(|i| r[i] < bound[i]);
        assert!(below, "2^512 mod L is too close to L for one subtraction");
        // And L64 is L.
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[8 * i..8 * i + 8].copy_from_slice(&l[i].to_le_bytes());
        }
        assert_eq!(bytes, L);
    }

    /// The reduction and `mul_add` against the portable ones and long
    /// division at every edge, then over random inputs. On x86-64 the public
    /// functions are the 64-bit ones; elsewhere this compares the portable
    /// ones with themselves, and the long division still checks them.
    fn compare_with_portable(rounds: u32) {
        let mut checked = 0u32;
        for input in edges() {
            let want = reduce_wide_by_long_division(&input);
            assert_eq!(reduce_wide(&input), want, "edge {input:?}");
            assert_eq!(reduce_wide_portable(&input), want, "edge {input:?}");
            checked += 1;
        }
        // mul_add at the edges of each operand.
        let mut operands: Vec<[u8; 32]> = Vec::new();
        for v in [0u64, 1, 2] {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&v.to_le_bytes());
            operands.push(b);
        }
        let mut lm1 = L;
        lm1[0] -= 1;
        operands.extend([
            L,
            lm1,
            [0xff; 32],
            {
                let mut t = [0xffu8; 32];
                t[31] = 0x7f;
                t
            },
            {
                let mut t = [0u8; 32];
                t[31] = 0x10;
                t
            },
        ]);
        for a in &operands {
            for b in &operands {
                for c in &operands {
                    assert_eq!(
                        mul_add(a, b, c),
                        mul_add_portable(a, b, c),
                        "{a:?} {b:?} {c:?}"
                    );
                    checked += 1;
                }
            }
        }
        let mut next = xorshift(0x7c3a_91d4_0be2_5f68);
        for case in 0..rounds {
            let mut input = [0u8; 64];
            for chunk in input.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            // Sometimes shorter, so that small quotients are covered too.
            match case % 4 {
                1 => input[32..].fill(0),
                2 => input[40..].fill(0),
                _ => {}
            }
            assert_eq!(
                reduce_wide(&input),
                reduce_wide_portable(&input),
                "{input:?}"
            );
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            let mut c = [0u8; 32];
            a.copy_from_slice(&input[..32]);
            b.copy_from_slice(&input[32..]);
            for chunk in c.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            assert_eq!(
                mul_add(&a, &b, &c),
                mul_add_portable(&a, &b, &c),
                "{a:?} {b:?} {c:?}"
            );
            checked += 1;
        }
        assert!(checked > rounds);
    }

    #[test]
    fn the_64_bit_scalar_arithmetic_agrees_with_the_portable() {
        compare_with_portable(if cfg!(debug_assertions) {
            20_000
        } else {
            200_000
        });
    }

    /// The same over four million random inputs; run in release.
    #[test]
    #[ignore = "slow; run with --release -- --ignored"]
    fn the_64_bit_scalar_arithmetic_agrees_over_millions() {
        compare_with_portable(4_000_000);
    }
}
