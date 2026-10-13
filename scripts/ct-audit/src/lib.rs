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
