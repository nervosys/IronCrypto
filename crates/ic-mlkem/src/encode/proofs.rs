//! Bounded proofs of ML-KEM's compression and packing, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-mlkem
//! ```
//!
//! The tests check `Compress_d` and `Decompress_d` at every `x` and `d` by
//! running them; these prove the same, against FIPS 203's definition written
//! out again from the integers (not the code's own `+ q/2` and shift), and add
//! the error bound and the packing round trips.

use super::*;

const MODULUS: u64 = 3329;

/// `Compress_d(x) = round(2^d x / q) mod 2^d` (FIPS 203 equation 4.7), with
/// the rounding written as `floor(2^d x / q + 1/2)` and so as
/// `floor((2^(d+1) x + q) / 2q)`. For every `x` in `[0, q)` and every `d` in
/// `1..=12`.
#[kani::proof]
fn compress_is_fips_203_equation_4_7() {
    let x: i16 = kani::any();
    let d: u32 = kani::any();
    kani::assume(0 <= x && x < Q);
    kani::assume((1..=12).contains(&d));
    let rounded = (((x as u64) << (d + 1)) + MODULUS) / (2 * MODULUS);
    assert_eq!(compress(x, d) as u64, rounded & ((1u64 << d) - 1));
}

/// `Decompress_d(y) = round(q y / 2^d)` (equation 4.8), the rounding written
/// as the defining inequalities rather than a shift: `r` is the integer with
/// `r <= q y / 2^d + 1/2 < r + 1`. For every `y` below `2^d`, every `d` in
/// `1..=12`; the result is a residue in `[0, q)`.
#[kani::proof]
fn decompress_is_fips_203_equation_4_8() {
    let d: u32 = kani::any();
    let y: u16 = kani::any();
    kani::assume((1..=12).contains(&d));
    kani::assume((y as u32) < (1u32 << d));
    let r = decompress(y, d) as i64;
    let two_d = 1i64 << d;
    // 2^(d+1) r <= 2 q y + 2^d < 2^(d+1) (r + 1)
    assert!((two_d * 2) * r <= 2 * (MODULUS as i64) * (y as i64) + two_d);
    assert!(2 * (MODULUS as i64) * (y as i64) + two_d < (two_d * 2) * (r + 1));
    assert!(0 <= r && r < MODULUS as i64);
}

/// The error bound decryption rests on (FIPS 203 section 4.2.1):
/// `|Decompress_d(Compress_d(x)) - x mod+- q| <= ceil(q / 2^(d+1))`, for every
/// `x` in `[0, q)` and every `d` in `1..=11`.
#[kani::proof]
fn compression_error_is_within_the_bound() {
    let x: i16 = kani::any();
    let d: u32 = kani::any();
    kani::assume(0 <= x && x < Q);
    kani::assume((1..=11).contains(&d));
    let back = decompress(compress(x, d), d) as i32;
    // Centre the difference modulo q.
    let mut e = back - x as i32;
    if e > 1664 {
        e -= 3329;
    }
    if e < -1664 {
        e += 3329;
    }
    let bound = (3329 + (1i32 << (d + 1)) - 1) >> (d + 1);
    assert!(e.abs() <= bound);
}

/// `reduce_12` is `x mod q` of the low twelve bits, in `[0, q)`, for every
/// `u16`: the reduction `ByteDecode_12` applies. A field already below `q` is
/// unchanged.
#[kani::proof]
fn reduce_12_is_the_low_twelve_bits_mod_q() {
    let x: u16 = kani::any();
    let r = reduce_12(x);
    let v = (x & 0x0fff) as i32;
    assert_eq!(r as i32, v % 3329);
    assert!(0 <= r && r < Q);
    if v < 3329 {
        assert_eq!(r as i32, v);
    }
}

/// Packing eight `D`-bit fields and unpacking them returns the fields, and
/// the packed bytes above the low `D` are zero; unpacking and repacking
/// returns the bytes; bits above `D` in an input are dropped, not smeared.
fn packing_is_a_bijection<const D: usize>() {
    let v: [i16; 8] = kani::any();
    let mask = (1i16 << D) - 1;

    let masked: [i16; 8] = core::array::from_fn(|i| v[i] & mask);
    let bytes = pack8::<D>(&masked);
    let back = unpack8::<D>(&bytes);
    for i in 0..8 {
        assert_eq!(back[i] as i16, masked[i]);
    }
    for b in &bytes[D..] {
        assert_eq!(*b, 0);
    }
    // High bits are ignored.
    assert_eq!(pack8::<D>(&v), bytes);

    let raw: [u8; 16] = kani::any();
    let mut input = raw;
    for b in &mut input[D..] {
        *b = 0;
    }
    let fields = unpack8::<D>(&input);
    let as_i16: [i16; 8] = core::array::from_fn(|i| fields[i] as i16);
    assert_eq!(pack8::<D>(&as_i16), input);
}

#[kani::proof]
#[kani::unwind(17)]
fn packing_is_a_bijection_at_1_bit() {
    packing_is_a_bijection::<1>();
}

#[kani::proof]
#[kani::unwind(17)]
fn packing_is_a_bijection_at_4_bits() {
    packing_is_a_bijection::<4>();
}

#[kani::proof]
#[kani::unwind(17)]
fn packing_is_a_bijection_at_5_bits() {
    packing_is_a_bijection::<5>();
}

#[kani::proof]
#[kani::unwind(17)]
fn packing_is_a_bijection_at_10_bits() {
    packing_is_a_bijection::<10>();
}

#[kani::proof]
#[kani::unwind(17)]
fn packing_is_a_bijection_at_11_bits() {
    packing_is_a_bijection::<11>();
}

#[kani::proof]
#[kani::unwind(17)]
fn packing_is_a_bijection_at_12_bits() {
    packing_is_a_bijection::<12>();
}
