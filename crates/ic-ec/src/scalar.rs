//! Arithmetic modulo the Curve25519 group order.
//!
//! `L = 2^252 + 27742317777372353535851937790883648493`
//!
//! Ed25519 signing needs `(r + h*a) mod L` where every operand is secret, so
//! reduction must be constant-time. This module uses a fixed 512-iteration
//! shift-and-conditional-subtract loop: slower than a Barrett or Montgomery
//! reduction, but with no data-dependent control flow and short enough to
//! audit by reading it.

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
    let mask = ((borrow as u32) ^ 1).wrapping_neg();
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
    // Unpack into 21-bit limbs.
    let mut limbs = [0i64; LIMBS];
    for (i, slot) in limbs.iter_mut().enumerate() {
        let bit = i * 21;
        let mut v = 0u64;
        for j in 0..21 {
            let b = bit + j;
            if b < 512 {
                v |= (((input[b / 8] >> (b % 8)) & 1) as u64) << j;
            }
        }
        *slot = v as i64;
    }

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
    for _round in 0..4 {
        for k in 0..LIMBS - 1 {
            carry(&mut limbs, k);
        }
        for i in (12..LIMBS).rev() {
            let t = limbs[i];
            limbs[i] = 0;
            for (j, d) in NEG_C_DIGITS.iter().enumerate() {
                limbs[i - 12 + j] += d * t;
            }
        }
    }
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
    for k in 0..13 {
        carry(&mut limbs, k);
    }

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

    // Pack the 21-bit limbs into the 32-byte little-endian encoding.
    let mut out = [0u8; 32];
    for (i, &v) in u.iter().enumerate() {
        for j in 0..21 {
            if (v >> j) & 1 == 1 {
                let b = i * 21 + j;
                if b < 256 {
                    out[b / 8] |= 1 << (b % 8);
                }
            }
        }
    }

    // At most a couple of multiples of L remain.
    let mut r = [0u32; 9];
    for i in 0..8 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&out[i * 4..i * 4 + 4]);
        r[i] = u32::from_le_bytes(b);
    }
    conditional_subtract_l(&mut r);
    conditional_subtract_l(&mut r);
    conditional_subtract_l(&mut r);
    conditional_subtract_l(&mut r);
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

/// Reduce a 256-bit little-endian integer modulo `L`.
pub fn reduce(input: &[u8; 32]) -> [u8; 32] {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(input);
    reduce_wide(&wide)
}

/// Compute `(a * b + c) mod L` for little-endian 32-byte scalars.
pub fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let al = to_limbs(a);
    let bl = to_limbs(b);

    // Schoolbook 8x8 -> 16 limbs.
    let mut prod = [0u64; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let t = prod[i + j] + (al[i] as u64) * (bl[j] as u64) + carry;
            prod[i + j] = t & 0xFFFF_FFFF;
            carry = t >> 32;
        }
        prod[i + 8] += carry;
    }

    let mut wide = [0u8; 64];
    for i in 0..16 {
        wide[i * 4..i * 4 + 4].copy_from_slice(&(prod[i] as u32).to_le_bytes());
    }

    // Add `c`, propagating the carry across the full 512-bit width.
    let mut carry = 0u16;
    for i in 0..64 {
        let ci = if i < 32 { c[i] as u16 } else { 0 };
        let t = wide[i] as u16 + ci + carry;
        wide[i] = t as u8;
        carry = t >> 8;
    }

    reduce_wide(&wide)
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
            assert_eq!(
                reduce_wide(&input),
                reduce_wide_by_long_division(&input),
                "case {case}, input {input:?}"
            );
        }
    }
}
