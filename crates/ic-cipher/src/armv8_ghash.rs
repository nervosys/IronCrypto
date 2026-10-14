//! The `PMULL` GHASH structure, shared by the real backend and its model.
//!
//! The arrangement of `aes::armv8_rounds`: `crate::pmull` expands these over
//! the real instructions and `crate::armv8_ghash_model` over a software model
//! of them, so the model checks the composition the backend runs.
//!
//! # The representation
//!
//! GCM numbers a field element's bits from the most significant bit of the
//! first byte: that bit is the coefficient of `x^0`. Reversing the bits of every
//! byte (`RBIT`) and reading the sixteen bytes as a little-endian 128-bit
//! integer then puts the coefficient of `x^i` at bit `i`, which is the order
//! `PMULL` multiplies polynomials in. So unlike the x86 backend there is no
//! byte swap and no one-bit correction afterwards: the product is the plain
//! polynomial product, reduced modulo `x^128 + x^7 + x^2 + x + 1` in the
//! ordinary way, and bit-reversed back on the way out.
//!
//! # The reduction
//!
//! With the 256-bit product as `hi * x^128 + lo` and `x^128 = x^7 + x^2 + x + 1`
//! (`0x87`) modulo the field polynomial, the top 64 bits of `hi` are folded
//! down first -- `hi[1] * 0x87` lands at `x^64` upward, across the top of `lo`
//! and the bottom of `hi[0]` -- and then `hi[0] * 0x87`, now at most 71 bits,
//! lands entirely in `lo`. Two multiplies by a constant, no shifts by data, no
//! branches.
//!
//! # The operations
//!
//! `$ops` names a module providing, over a 128-bit vector `V` with 64-bit lane
//! 0 the low half:
//!
//! - `load(&[u8; 16]) -> V` and `store(V) -> [u8; 16]`, bit-reversing each byte;
//! - `pmull(a, b)`, lane 0 times lane 0, and `pmull2(a, b)`, lane 1 times
//!   lane 1, each the 128-bit carry-less product;
//! - `ext8(a, b) -> [a[1], b[0]]`, `xor(a, b)`, `zero()`, and `poly()`, which
//!   is `0x87` in both lanes.
//!
//! # Constant time
//!
//! `PMULL` has data-independent timing on every core that implements it, and
//! nothing here branches on or indexes by a field element.

/// The unreduced product `a * b` as `(lo, mid, hi)`, `mid` not yet folded in.
///
/// Returned unfolded so a caller summing several products folds and reduces
/// once; every step after the multiplies is linear over GF(2).
macro_rules! armv8_ghash_product {
    ($ops:ident, $a:expr, $b:expr) => {{
        let a = $a;
        let b = $b;
        let swapped = $ops::ext8(b, b);
        (
            $ops::pmull(a, b),
            $ops::xor($ops::pmull(a, swapped), $ops::pmull2(a, swapped)),
            $ops::pmull2(a, b),
        )
    }};
}

/// Fold `mid` into the 256-bit product and reduce it to one field element.
macro_rules! armv8_ghash_reduce {
    ($ops:ident, $lo:expr, $mid:expr, $hi:expr) => {{
        let zero = $ops::zero();
        let poly = $ops::poly();
        // mid * x^64: its low half to the top of `lo`, its high half to the
        // bottom of `hi`.
        let lo = $ops::xor($lo, $ops::ext8(zero, $mid));
        let hi = $ops::xor($hi, $ops::ext8($mid, zero));
        // hi[1] * x^192 = hi[1] * 0x87 * x^64.
        let t = $ops::pmull2(hi, poly);
        let lo = $ops::xor(lo, $ops::ext8(zero, t));
        let hi = $ops::xor(hi, $ops::ext8(t, zero));
        // hi[0] * x^128 = hi[0] * 0x87, at most 71 bits.
        $ops::xor(lo, $ops::pmull(hi, poly))
    }};
}

/// `x *= h` in GCM's field, both in GCM byte order.
macro_rules! armv8_ghash_mul {
    ($ops:ident, $x:expr, $h:expr) => {{
        let x: &mut [u8; 16] = $x;
        let h: &[u8; 16] = $h;
        let (lo, mid, hi) = armv8_ghash_product!($ops, $ops::load(x), $ops::load(h));
        *x = $ops::store(armv8_ghash_reduce!($ops, lo, mid, hi));
    }};
}

/// Absorb whole groups of eight blocks into the accumulator `$acc`.
///
/// `$powers[i]` is `H^(i+1)` in GCM byte order. Each group is
/// `Y' = (Y ^ X0)*H^8 ^ X1*H^7 ^ .. ^ X7*H`: eight independent products,
/// summed unreduced and reduced once, as the x86 `clmul::absorb8` does.
macro_rules! armv8_ghash_absorb8 {
    ($ops:ident, $acc:expr, $powers:expr, $blocks:expr) => {{
        let acc: &mut [u8; 16] = $acc;
        let powers: &[[u8; 16]; 8] = $powers;
        let blocks: &[u8] = $blocks;
        let zero = $ops::zero();
        let mut h = [zero; 8];
        for (slot, p) in h.iter_mut().zip(powers) {
            *slot = $ops::load(p);
        }
        let mut y = $ops::load(acc);
        for group in blocks.chunks_exact(128) {
            let (mut lo, mut mid, mut hi) = (zero, zero, zero);
            for (i, block) in group.chunks_exact(16).enumerate() {
                let mut x = match block.first_chunk::<16>() {
                    Some(b) => $ops::load(b),
                    None => zero,
                };
                if i == 0 {
                    x = $ops::xor(x, y);
                }
                // The oldest block takes the highest power.
                let (l, m, u) = armv8_ghash_product!($ops, x, h[7 - i]);
                lo = $ops::xor(lo, l);
                mid = $ops::xor(mid, m);
                hi = $ops::xor(hi, u);
            }
            y = armv8_ghash_reduce!($ops, lo, mid, hi);
        }
        *acc = $ops::store(y);
    }};
}

pub(crate) use {armv8_ghash_absorb8, armv8_ghash_mul, armv8_ghash_product, armv8_ghash_reduce};
