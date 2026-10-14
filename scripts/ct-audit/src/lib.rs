//! Stable symbols for inspecting the actual library implementations after LTO.
//! Fixed public parameters remove control flow that is unrelated to secrets.
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub fn ct_reduce_q(r: i32) -> i32 {
    ic_mldsa::rounding::reduce_q(r)
}

#[no_mangle]
pub fn ct_power2round(r: i32) -> (i32, i32) {
    ic_mldsa::rounding::power2round(r)
}

#[no_mangle]
pub fn ct_decompose_32(r: i32) -> (i32, i32) {
    ic_mldsa::rounding::decompose(r, ic_mldsa::rounding::GAMMA2_32)
}

#[no_mangle]
pub fn ct_decompose_88(r: i32) -> (i32, i32) {
    ic_mldsa::rounding::decompose(r, ic_mldsa::rounding::GAMMA2_88)
}

macro_rules! compress {
    ($name:ident, $d:expr) => {
        #[no_mangle]
        pub fn $name(x: i16) -> u16 {
            ic_mlkem::encode::compress(x, $d)
        }
    };
}

compress!(ct_compress_1, 1);
compress!(ct_compress_4, 4);
compress!(ct_compress_5, 5);
compress!(ct_compress_10, 10);
compress!(ct_compress_11, 11);

// ML-KEM's secret-handling scalar helpers: the noise sampler a word at a
// time, the decapsulation key's twelve-bit decode and its reduction, and the
// two reductions every NTT coefficient passes through.
#[no_mangle]
pub fn ct_cbd2(w: u32) -> [i16; 8] {
    ic_mlkem::sample::cbd2(w)
}

#[no_mangle]
pub fn ct_cbd3(w: u32) -> [i16; 4] {
    ic_mlkem::sample::cbd3(w)
}

#[no_mangle]
pub fn ct_reduce_12(x: u16) -> i16 {
    ic_mlkem::encode::reduce_12(x)
}

#[no_mangle]
pub fn ct_unpack8_12(bytes: &[u8; 16]) -> [u16; 8] {
    ic_mlkem::encode::unpack8::<12>(bytes)
}

#[no_mangle]
pub fn ct_pack8_12(v: &[i16; 8]) -> [u8; 16] {
    ic_mlkem::encode::pack8::<12>(v)
}

#[no_mangle]
pub fn ct_barrett_reduce(a: i16) -> i16 {
    ic_mlkem::poly::barrett_reduce(a)
}

#[no_mangle]
pub fn ct_montgomery_reduce(a: i32) -> i16 {
    ic_mlkem::poly::montgomery_reduce(a)
}

#[no_mangle]
pub fn ct_select_u32(flag: u8, a: u32, b: u32) -> u32 {
    ic_core::ct::select_u32(ic_core::ct::Choice::from_u8(flag), a, b)
}

#[no_mangle]
pub fn ct_select_u64(flag: u8, a: u64, b: u64) -> u64 {
    ic_core::ct::select_u64(ic_core::ct::Choice::from_u8(flag), a, b)
}

#[no_mangle]
pub fn ct_select_u8(flag: u8, a: u8, b: u8) -> u8 {
    ic_core::ct::select_u8(ic_core::ct::Choice::from_u8(flag), a, b)
}

#[no_mangle]
pub fn ct_eq_4(a: &[u8; 4], b: &[u8; 4]) -> bool {
    ic_core::ct::verify(a, b)
}

#[no_mangle]
pub fn ct_zero_4(a: &[u8; 4]) -> u8 {
    ic_core::ct::is_zero(a).unwrap_u8()
}

#[no_mangle]
pub fn ct_lt_be_4(a: &[u8; 4], b: &[u8; 4]) -> u8 {
    ic_core::ct::lt_be(a, b).unwrap_u8()
}

#[no_mangle]
pub fn ct_cmov_4(flag: u8, dst: &mut [u8; 4], src: &[u8; 4]) {
    ic_core::ct::cmov(ic_core::ct::Choice::from_u8(flag), dst, src);
}

#[no_mangle]
pub fn ct_cswap_4(flag: u8, a: &mut [u8; 4], b: &mut [u8; 4]) {
    ic_core::ct::cswap(ic_core::ct::Choice::from_u8(flag), a, b);
}

#[no_mangle]
pub fn ct_hex_encode(input: &[u8; 1], output: &mut [u8; 2]) {
    let _ = ic_core::codec::hex_encode(input, output);
}

#[no_mangle]
pub fn ct_base64_encode(input: &[u8; 3], output: &mut [u8; 4]) {
    let _ = ic_core::codec::base64_encode(input, output);
}

// P-256: the field and scalar operations that hashing to the curve, the OPRF,
// ECDH and ECDSA are composed of.
macro_rules! p256_probes {
    ($reduce:ident, $add:ident, $sub:ident, $mul:ident, $neg:ident, $cmov:ident, $eq:ident, $odd:ident,
     $m:ident :: { $r:ident, $a:ident, $s:ident, $mu:ident, $n:ident, $c:ident, $e:ident, $o:ident }) => {
        #[no_mangle]
        pub fn $reduce(a: &[u8; 32]) -> [u8; 32] {
            ic_ec::ct_probes::$r(a)
        }
        #[no_mangle]
        pub fn $add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            ic_ec::ct_probes::$a(a, b)
        }
        #[no_mangle]
        pub fn $sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            ic_ec::ct_probes::$s(a, b)
        }
        #[no_mangle]
        pub fn $mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            ic_ec::ct_probes::$mu(a, b)
        }
        #[no_mangle]
        pub fn $neg(a: &[u8; 32]) -> [u8; 32] {
            ic_ec::ct_probes::$n(a)
        }
        #[no_mangle]
        pub fn $cmov(flag: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            ic_ec::ct_probes::$c(flag, a, b)
        }
        #[no_mangle]
        pub fn $eq(a: &[u8; 32], b: &[u8; 32]) -> u8 {
            ic_ec::ct_probes::$e(a, b)
        }
        #[no_mangle]
        pub fn $odd(a: &[u8; 32]) -> u8 {
            ic_ec::ct_probes::$o(a)
        }
    };
}

p256_probes!(
    ct_p256_fp_reduce, ct_p256_fp_add, ct_p256_fp_sub, ct_p256_fp_mul, ct_p256_fp_neg,
    ct_p256_fp_cmov, ct_p256_fp_eq, ct_p256_fp_is_odd,
    m::{ fp_reduce, fp_add, fp_sub, fp_mul, fp_neg, fp_cmov, fp_eq, fp_is_odd }
);
p256_probes!(
    ct_p256_fn_reduce, ct_p256_fn_add, ct_p256_fn_sub, ct_p256_fn_mul, ct_p256_fn_neg,
    ct_p256_fn_cmov, ct_p256_fn_eq, ct_p256_fn_is_odd,
    m::{ fn_reduce, fn_add, fn_sub, fn_mul, fn_neg, fn_cmov, fn_eq, fn_is_odd }
);

// Ed25519's scalar arithmetic modulo L: the nonce and S are secret.
#[no_mangle]
pub fn ct_ed25519_reduce_wide(x: &[u8; 64]) -> [u8; 32] {
    ic_ec::ct_probes::ed25519_reduce_wide(x)
}

#[no_mangle]
pub fn ct_ed25519_mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    ic_ec::ct_probes::ed25519_mul_add(a, b, c)
}

// The x86-64 Curve25519 backends. x86-64 only, which is the only target they
// compile for; scripts/check-ct.py requires these there and nowhere else.
#[cfg(target_arch = "x86_64")]
mod x86 {
    use ic_ec::ct_probes::x86 as p;

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_fe64_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::fe64_mul(a, b) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_fe64_square(a: &[u8; 32]) -> [u8; 32] {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::fe64_square(a) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_fe64_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::fe64_add(a, b) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_fe64_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::fe64_sub(a, b) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_fe64_mul121666(a: &[u8; 32]) -> [u8; 32] {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::fe64_mul121666(a) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_fe64_invert(a: &[u8; 32]) -> [u8; 32] {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::fe64_invert(a) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_x25519_fe64_step(ws: &mut [u64; 76], swap: u64) {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::x25519_step(ws, swap) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_x25519_fe64_double(ws: &mut [u64; 76]) {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::x25519_double(ws) }
    }

    #[no_mangle]
    pub fn ct_ed25519_fe64_select(dst: &mut [u64; 16], table: &[[u64; 12]; 8], digit: i8) {
        p::ed25519_select(dst, table, digit)
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_ed25519_fe64_madd_ext2(ws: &mut p::Ws2) {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ed25519_madd_ext2(ws) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_ed25519_fe64_scan(
        ws: &mut p::Ws2Scan,
        table: &[[u64; 12]; 16],
        d0: i8,
        d1: i8,
    ) {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::wide::scan(ws, table, d0, d1) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_ed25519_fe64_madd_ext2_scan(
        ws: &mut p::Ws2Scan,
        table: &[[u64; 12]; 16],
        d0: i8,
        d1: i8,
    ) {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::wide::madd_ext2_scan(ws, table, d0, d1) }
    }

    #[no_mangle]
    pub fn ct_ed25519_digits32(scalar: &[u8; 32]) -> [i8; 52] {
        p::ed25519_digits32(scalar)
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_ed25519_fe64_dbl_nadd(ws: &mut p::Ws) {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ed25519_dbl_nadd(ws) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_x25519_ifma_step(
        s: &p::ifma::Lanes,
        x1: &[u64; 4],
        swap: u64,
    ) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::ladder_step(s, x1, swap) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_ed25519_ifma_select(t: &[p::ifma::Lanes; 8], digit: i8) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::select(t, digit) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_ed25519_ifma_add(a: &p::ifma::Lanes, n: &p::ifma::Lanes) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::add(a, n) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_ed25519_ifma_double(a: &p::ifma::Lanes) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::double(a) }
    }
}

// RSA's windowed-exponentiation table read (ic-rsa) at 2048 bits: the masked
// scan, written through `out`. Compiled on every target; check-ct.py requires it
// on x86-64 only.
#[no_mangle]
pub fn ct_rsa_select_2048(table: &[[u64; 64]; 16], digit: u64, out: &mut [u64; 64]) {
    ic_rsa::ct_probes::select_2048(table, digit, out)
}

// The same read from the five-bit window's table of 32 entries: without
// `std`, as here, the SSE2 scan of every entry at every position.
#[no_mangle]
pub fn ct_rsa_select32_2048(table: &[[u64; 64]; 32], digit: u64, out: &mut [u64; 64]) {
    ic_rsa::ct_probes::select32_2048(table, digit, out)
}

// x86-64: P-256's MULX/ADX field sequences and the point formulas made of
// them. Compiled to be read, never run: they need BMI2 and ADX.
#[cfg(target_arch = "x86_64")]
mod x86_p256 {
    use core::mem::MaybeUninit;

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_fp_mul_adx(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        unsafe { ic_ec::ct_probes::fp_mul_adx(a, b) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_fp_square_adx(a: &[u64; 4]) -> [u64; 4] {
        unsafe { ic_ec::ct_probes::fp_square_adx(a) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_point_double_adx(buf: &mut [MaybeUninit<u64>; 60]) {
        unsafe { ic_ec::ct_probes::point_double_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_point_add_adx(buf: &mut [MaybeUninit<u64>; 96]) {
        unsafe { ic_ec::ct_probes::point_add_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_point_add_affine_adx(buf: &mut [MaybeUninit<u64>; 80]) {
        unsafe { ic_ec::ct_probes::point_add_affine_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_point_double_in_place_adx(buf: &mut [MaybeUninit<u64>; 48]) {
        unsafe { ic_ec::ct_probes::point_double_in_place_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_fp_mul_adx(buf: &mut [MaybeUninit<u64>; 24]) {
        unsafe { ic_ec::ct_probes::p384_fp_mul_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_fp_sqr_adx(buf: &mut [MaybeUninit<u64>; 18]) {
        unsafe { ic_ec::ct_probes::p384_fp_sqr_adx(buf) }
    }

    /// P-384's field inversion by divsteps: ECDH's shared secret and every
    /// public key pass through it, on a secret-derived Z.
    #[no_mangle]
    pub fn ct_p384_fp_invert(a: &[u64; 6]) -> [u64; 6] {
        ic_ec::ct_probes::p384_fp_invert(a)
    }

    /// P-256's field inversion by divsteps.
    #[no_mangle]
    pub fn ct_p256_fp_invert(a: &[u64; 4]) -> [u64; 4] {
        ic_ec::ct_probes::p256_fp_invert(a)
    }

    /// P-256's scalar inversion by divsteps: ECDSA's secret nonce.
    #[no_mangle]
    pub fn ct_p256_fn_invert(a: &[u64; 4]) -> [u64; 4] {
        ic_ec::ct_probes::p256_fn_invert(a)
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_fn_mul_adx(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], u64) {
        unsafe { ic_ec::ct_probes::p384_fn_mul_adx(a, b) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_point_double_adx(buf: &mut [MaybeUninit<u64>; 96]) {
        unsafe { ic_ec::ct_probes::p384_point_double_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_point_add_adx(buf: &mut [MaybeUninit<u64>; 150]) {
        unsafe { ic_ec::ct_probes::p384_point_add_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_point_add_affine_adx(buf: &mut [MaybeUninit<u64>; 126]) {
        unsafe { ic_ec::ct_probes::p384_point_add_affine_adx(buf) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_point_double_in_place_adx(buf: &mut [MaybeUninit<u64>; 78]) {
        unsafe { ic_ec::ct_probes::p384_point_double_in_place_adx(buf) }
    }

    /// The secret digit's read of a window of a prepared P-384 key, for
    /// ECDH: every entry under a mask, and the conditional negation. Its loop
    /// over the sixteen entries is excused by rule in check-ct.py, up to a
    /// ceiling. The additions that follow are the formulas probed above.
    #[no_mangle]
    pub fn ct_p384_comb_select(
        comb: &ic_ec::ct_probes::P384Comb,
        digit: i8,
        out: &mut [[u64; 6]; 2],
    ) {
        ic_ec::ct_probes::p384_comb_select(comb, digit, out)
    }

    /// One digit's addition in P-384's multiplication on MULX/ADX, the
    /// digit secret: the entry's read from an affine window, as in
    /// `ct_p384_comb_select`, the mixed addition, and the masks that select
    /// the identity cases. Its loop over the sixteen entries is excused by
    /// rule in check-ct.py, up to a ceiling; the doublings between digits
    /// are `ct_p384_point_double_in_place_adx`.
    ///
    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p384_ladder_add(
        comb: &ic_ec::ct_probes::P384Comb,
        digit: i8,
        buf: &mut [MaybeUninit<u64>; 126],
    ) {
        unsafe { ic_ec::ct_probes::p384_ladder_add(comb, digit, buf) }
    }

    /// The same for P-256: the entry's read from the Jacobian window, the
    /// addition, and the masks; the doublings are
    /// `ct_p256_point_double_in_place_adx`.
    ///
    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_ladder_add(
        window: &ic_ec::ct_probes::P256Window,
        digit: i8,
        buf: &mut [MaybeUninit<u64>; 96],
    ) {
        unsafe { ic_ec::ct_probes::p256_ladder_add(window, digit, buf) }
    }

    /// One digit of P-256's multiplication of the generator on MULX/ADX, as
    /// signing makes it, the digit secret: the entry's read from a window
    /// of thirty-two affine multiples, the mixed addition, and the masks.
    ///
    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_p256_table_add(
        table: &ic_ec::ct_probes::P256Table,
        digit: i8,
        buf: &mut [MaybeUninit<u64>; 80],
    ) {
        unsafe { ic_ec::ct_probes::p256_table_add(table, digit, buf) }
    }
}

// x86-64: P-256's and P-384's point formulas on AVX-512 IFMA, each one
// generated block of assembly; the secret digit's read of a window of lane
// vectors; and the conversion of a result back to the `Fp` form. Compiled to
// be read, never run: the kernels need AVX-512 IFMA, the scan AVX2.
#[cfg(target_arch = "x86_64")]
mod x86_nist_ifma {
    use ic_ec::ct_probes::nist_ifma as p;

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_double(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_double(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_add(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_add(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_madd(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_madd(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_madd4(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_madd4(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_from_fp(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_from_fp(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_to_fp(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_to_fp(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_to_fp4(
        a: &[p::P256; 3],
        b: &[p::P256; 2],
        m: &[u64; 12],
        o: &mut [p::P256; 3],
        t: &mut [u64; p::P256_SPILL],
    ) {
        unsafe { p::p256_to_fp4(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_p256_ifma_select(w: &[p::P256; 16], digit: i8, out: &mut p::P256) -> [u64; 2] {
        unsafe { p::p256_select(w, digit, out) }
    }

    #[no_mangle]
    pub fn ct_p256_ifma_from_limbs(limbs: &[u64; 5]) -> [u64; 4] {
        p::p256_from_limbs(limbs)
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_double(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_double(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_add(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_add(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_madd(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_madd(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_madd4(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_madd4(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_from_fp(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_from_fp(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_to_fp(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_to_fp(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX-512 IFMA.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_to_fp4(
        a: &[p::P384; 3],
        b: &[p::P384; 2],
        m: &[u64; 12],
        o: &mut [p::P384; 3],
        t: &mut [u64; p::P384_SPILL],
    ) {
        unsafe { p::p384_to_fp4(a, b, m, o, t) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_p384_ifma_select(w: &[p::P384; 16], digit: i8, out: &mut p::P384) -> [u64; 2] {
        unsafe { p::p384_select(w, digit, out) }
    }

    #[no_mangle]
    pub fn ct_p384_ifma_from_limbs(limbs: &[u64; 8]) -> [u64; 6] {
        p::p384_from_limbs(limbs)
    }
}

// x86-64: the sixteen-block AVX-512 ChaCha20 keystream and the four-lane AVX2
// Poly1305. Compiled to be read, never run: they need AVX-512F and AVX2.
#[cfg(target_arch = "x86_64")]
mod x86_chacha {
    use ic_cipher::ct_probes as p;

    /// # Safety
    /// Requires AVX-512F.
    #[no_mangle]
    pub unsafe fn ct_chacha20_zmm_group(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8; 1024],
    ) {
        unsafe { p::chacha20_zmm_group(key, nonce, counter, data) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_poly1305_avx2_step(
        h: &[[u64; 4]; 5],
        r4: &[u32; 5],
        blocks: &[u8; 64],
    ) -> [[u64; 4]; 5] {
        unsafe { p::poly1305_avx2_step(h, r4, blocks) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_poly1305_avx2_finish(h: &[[u64; 4]; 5], powers: &[[u32; 5]; 4]) -> [u64; 5] {
        unsafe { p::poly1305_avx2_finish(h, powers) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_chacha20_avx2_pair(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        out: &mut [u8; 128],
    ) {
        unsafe { p::chacha20_avx2_pair(key, nonce, counter, out) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_chacha20_avx2_two_pairs(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        out: &mut [u8; 256],
    ) {
        unsafe { p::chacha20_avx2_two_pairs(key, nonce, counter, out) }
    }

    #[no_mangle]
    pub fn ct_poly1305_short(key: &[u8; 32], aad: &[u8; 13], ct: &[u8; 64]) -> [u8; 16] {
        p::poly1305_short(key, aad, ct)
    }
}

// x86-64: HMAC-SHA256's SHA-NI compositions, which hold key-derived chaining
// values: the two key-pad blocks together, and the inner hash's last blocks
// with the outer block built from its digest in registers, here over one
// whole block and one padding block. Compiled to be read, never run.
#[cfg(target_arch = "x86_64")]
mod x86_hmac {
    use ic_hash::ct_probes as h;

    /// # Safety
    /// Requires SHA-NI and SSE4.1.
    #[no_mangle]
    pub unsafe fn ct_hmac_sha256_pads(inner: &mut [u32; 8], outer: &mut [u32; 8], ipad: &[u8; 64]) {
        unsafe { h::hmac_sha256_pads(inner, outer, ipad) }
    }

    /// # Safety
    /// Requires SHA-NI and SSE4.1.
    #[no_mangle]
    pub unsafe fn ct_hmac_sha256_tail(
        inner: &[u32; 8],
        block: &[u8; 64],
        tail: &[u8; 64],
        outer: &mut [u32; 8],
    ) {
        unsafe { h::hmac_sha256_tail(inner, block, tail, outer) }
    }
}

// RSA's Montgomery products at 2048 bits: the portable CIOS product on every
// target, and on x86-64 the MULX/ADCX/ADOX product and the AVX-512 IFMA
// almost-Montgomery product. Their loops run over the public width; on x86-64
// check-ct.py excuses those loops' branches by rule, per probe, up to a ceiling.
#[no_mangle]
pub fn ct_rsa_cios_2048(
    a: &[u64; 32],
    b: &[u64; 32],
    n: &[u64; 32],
    n0inv: u64,
    out: &mut [u64; 32],
) {
    ic_rsa::ct_probes::cios_2048(a, b, n, n0inv, out)
}

#[cfg(target_arch = "x86_64")]
mod x86_rsa {
    use ic_rsa::ct_probes::x86 as p;
    use ic_rsa::uint::{Modulus, Uint};

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_rsa_adx_mont_mul_2048(
        a: &[u64; 32],
        b: &[u64; 32],
        n: &[u64; 32],
        n0inv: u64,
        out: &mut [u64; 32],
    ) {
        unsafe { p::adx_mont_mul_2048(a, b, n, n0inv, out) }
    }

    /// Compiled to be read, never run: it needs AVX-512F, IFMA and BMI2.
    #[no_mangle]
    pub fn ct_rsa_ifma_amm_2048(
        ctx: &mut p::IfmaCtx,
        a: &[u64; 40],
        b: &[u64; 40],
        out: &mut [u64; 40],
    ) {
        p::ifma_amm_2048(ctx, a, b, out)
    }

    // The whole IFMA exponentiation, modulus, base and secret exponent to the
    // reduced result, at 1024 bits (RSA-2048's primes) and 2048 bits (its
    // modulus). The exponent length is an argument, as it is to `pow`.

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_rsa_adx_mont_sqr_2048(
        a: &[u64; 32],
        n: &[u64; 32],
        n0inv: u64,
        out: &mut [u64; 32],
    ) {
        unsafe { p::adx_mont_sqr_2048(a, n, n0inv, out) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_rsa_adx_mont_mul_1536(
        a: &[u64; 24],
        b: &[u64; 24],
        n: &[u64; 24],
        n0inv: u64,
        out: &mut [u64; 24],
    ) {
        unsafe { p::adx_mont_mul_1536(a, b, n, n0inv, out) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_rsa_adx_mont_sqr_1536(
        a: &[u64; 24],
        n: &[u64; 24],
        n0inv: u64,
        out: &mut [u64; 24],
    ) {
        unsafe { p::adx_mont_sqr_1536(a, n, n0inv, out) }
    }

    // The exponentiation's table read on AVX2, from the five-bit window's 32
    // entries at each width an RSA prime has: the masks from the secret
    // digit, then every entry read whole into the accumulators.

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_rsa_select32_avx2_1024(
        table: &[[u64; 64]; 32],
        digit: u64,
        out: &mut [u64; 64],
    ) {
        unsafe { p::select32_avx2_1024(table, digit, out) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_rsa_select32_avx2_1536(
        table: &[[u64; 64]; 32],
        digit: u64,
        out: &mut [u64; 64],
    ) {
        unsafe { p::select32_avx2_1536(table, digit, out) }
    }

    /// # Safety
    /// Requires AVX2.
    #[no_mangle]
    pub unsafe fn ct_rsa_select32_avx2_2048(
        table: &[[u64; 64]; 32],
        digit: u64,
        out: &mut [u64; 64],
    ) {
        unsafe { p::select32_avx2_2048(table, digit, out) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_rsa_adx_mont_mul_1024(
        a: &[u64; 16],
        b: &[u64; 16],
        n: &[u64; 16],
        n0inv: u64,
        out: &mut [u64; 16],
    ) {
        unsafe { p::adx_mont_mul_1024(a, b, n, n0inv, out) }
    }

    /// # Safety
    /// Requires BMI2 and ADX.
    #[no_mangle]
    pub unsafe fn ct_rsa_adx_mont_sqr_1024(
        a: &[u64; 16],
        n: &[u64; 16],
        n0inv: u64,
        out: &mut [u64; 16],
    ) {
        unsafe { p::adx_mont_sqr_1024(a, n, n0inv, out) }
    }

    /// # Safety
    /// Requires AVX-512F, IFMA and BMI2.
    #[no_mangle]
    pub unsafe fn ct_rsa_ifma_pow_1024(
        m: &Modulus,
        base: &Uint,
        exp: &Uint,
        exp_bits: usize,
        out: &mut [u64; 24],
    ) {
        unsafe { p::ifma_pow_1024(m, base, exp, exp_bits, out) }
    }

    /// # Safety
    /// Requires AVX-512F, IFMA and BMI2.
    #[no_mangle]
    pub unsafe fn ct_rsa_ifma_pow_2048(
        m: &Modulus,
        base: &Uint,
        exp: &Uint,
        exp_bits: usize,
        out: &mut [u64; 40],
    ) {
        unsafe { p::ifma_pow_2048(m, base, exp, exp_bits, out) }
    }
}

// x86-64: AES-GCM's eight-block (AES-NI, PCLMULQDQ) and sixteen-block (VAES,
// VPCLMULQDQ on ymm) loops at AES-256, sealing and opening a fixed three
// groups, one group alone, and the twist of a power of H. Compiled to be
// read, never run. The loops' back edges are excused by the counter-loop
// rule, one per probe that loops.
#[cfg(target_arch = "x86_64")]
mod x86_gcm {
    use core::arch::x86_64::__m128i;
    use ic_cipher::ct_probes as p;

    /// # Safety
    /// Requires AES-NI, PCLMULQDQ and SSSE3.
    #[no_mangle]
    pub unsafe fn ct_gcm_clmul8_seal(
        data: &mut [u8; 384],
        rk: &[__m128i; 15],
        pw: &p::Powers,
        pk: &p::Powers,
        st: &mut [u8; 32],
    ) {
        unsafe { p::gcm_clmul8_seal(data, rk, pw, pk, st) }
    }

    /// # Safety
    /// Requires AES-NI, PCLMULQDQ and SSSE3.
    #[no_mangle]
    pub unsafe fn ct_gcm_clmul8_open(
        data: &mut [u8; 384],
        rk: &[__m128i; 15],
        pw: &p::Powers,
        pk: &p::Powers,
        st: &mut [u8; 32],
    ) {
        unsafe { p::gcm_clmul8_open(data, rk, pw, pk, st) }
    }

    /// # Safety
    /// Requires AES-NI, PCLMULQDQ and SSSE3.
    #[no_mangle]
    pub unsafe fn ct_gcm_clmul8_group(
        data: &mut [u8; 128],
        rk: &[__m128i; 15],
        pw: &p::Powers,
        pk: &p::Powers,
        st: &mut [u8; 32],
    ) {
        unsafe { p::gcm_clmul8_group(data, rk, pw, pk, st) }
    }

    /// # Safety
    /// Requires AVX2, VAES and VPCLMULQDQ.
    #[no_mangle]
    pub unsafe fn ct_gcm_vaes256_seal(
        data: &mut [u8; 768],
        rk: &[__m128i; 15],
        pw: &p::Powers,
        pk: &p::Powers,
        st: &mut [u8; 32],
    ) {
        unsafe { p::gcm_vaes256_seal(data, rk, pw, pk, st) }
    }

    /// # Safety
    /// Requires AVX2, VAES and VPCLMULQDQ.
    #[no_mangle]
    pub unsafe fn ct_gcm_vaes256_open(
        data: &mut [u8; 768],
        rk: &[__m128i; 15],
        pw: &p::Powers,
        pk: &p::Powers,
        st: &mut [u8; 32],
    ) {
        unsafe { p::gcm_vaes256_open(data, rk, pw, pk, st) }
    }

    /// # Safety
    /// Requires AVX2, VAES and VPCLMULQDQ.
    #[no_mangle]
    pub unsafe fn ct_gcm_vaes256_group(
        data: &mut [u8; 256],
        rk: &[__m128i; 15],
        pw: &p::Powers,
        pk: &p::Powers,
        st: &mut [u8; 32],
    ) {
        unsafe { p::gcm_vaes256_group(data, rk, pw, pk, st) }
    }

    #[no_mangle]
    pub fn ct_gcm_twist(h: &[u8; 16]) -> [u8; 16] {
        p::gcm_twist(h)
    }
}

// aarch64: the ARMv8 AES backend at AES-256 (one block each way and a batch
// of four, each after loading the key: the decryption probe is the one that
// derives the inverse cipher's keys), the PMULL GHASH multiply and its
// eight-block absorb over three groups, and SHA-256 compression over four
// blocks and SHA-512 over two. Compiled to be read, never run. Their loops' branches are excused
// by the AArch64 counter-loop rule, per probe, up to AARCH64_EXCUSE_CEILINGS.
#[cfg(target_arch = "aarch64")]
mod armv8 {
    use ic_cipher::ct_probes as c;
    use ic_hash::ct_probes as h;

    /// # Safety
    /// Requires the AES instructions.
    #[no_mangle]
    pub unsafe fn ct_aes256_armv8_encrypt(round_keys: &[u8; 240], block: &mut [u8; 16]) {
        unsafe { c::aes256_armv8_encrypt(round_keys, block) }
    }

    /// # Safety
    /// Requires the AES instructions.
    #[no_mangle]
    pub unsafe fn ct_aes256_armv8_decrypt(round_keys: &[u8; 240], block: &mut [u8; 16]) {
        unsafe { c::aes256_armv8_decrypt(round_keys, block) }
    }

    /// # Safety
    /// Requires the AES instructions.
    #[no_mangle]
    pub unsafe fn ct_aes256_armv8_encrypt4(round_keys: &[u8; 240], data: &mut [u8; 64]) {
        unsafe { c::aes256_armv8_encrypt4(round_keys, data) }
    }

    /// # Safety
    /// Requires PMULL.
    #[no_mangle]
    pub unsafe fn ct_ghash_pmull_mul(x: &mut [u8; 16], hk: &[u8; 16]) {
        unsafe { c::ghash_pmull_mul(x, hk) }
    }

    /// # Safety
    /// Requires PMULL.
    #[no_mangle]
    pub unsafe fn ct_ghash_pmull_absorb8(
        acc: &mut [u8; 16],
        powers: &[[u8; 16]; 8],
        blocks: &[u8; 384],
    ) {
        unsafe { c::ghash_pmull_absorb8(acc, powers, blocks) }
    }

    /// # Safety
    /// Requires the SHA-256 instructions.
    #[no_mangle]
    pub unsafe fn ct_sha256_armv8_compress(state: &mut [u32; 8], blocks: &[u8; 256]) {
        unsafe { h::sha256_armv8_compress(state, blocks) }
    }

    /// # Safety
    /// Requires the SHA-512 instructions.
    #[no_mangle]
    pub unsafe fn ct_sha512_armv8_compress(state: &mut [u64; 8], blocks: &[u8; 256]) {
        unsafe { h::sha512_armv8_compress(state, blocks) }
    }
}
