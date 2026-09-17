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

/// Reduce a 512-bit little-endian integer modulo `L`.
pub fn reduce_wide(input: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u32; 9];
    for bit_index in (0..512).rev() {
        // r <<= 1
        let mut carry = 0u32;
        for limb in r.iter_mut() {
            let next = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // Bring in the next input bit.
        r[0] |= ((input[bit_index / 8] >> (bit_index % 8)) & 1) as u32;
        conditional_subtract_l(&mut r);
    }

    let mut out = [0u8; 32];
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
}
