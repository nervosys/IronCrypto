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

    #[no_mangle]
    pub fn ct_fe64_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        p::fe64_mul(a, b)
    }

    #[no_mangle]
    pub fn ct_fe64_square(a: &[u8; 32]) -> [u8; 32] {
        p::fe64_square(a)
    }

    #[no_mangle]
    pub fn ct_fe64_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        p::fe64_add(a, b)
    }

    #[no_mangle]
    pub fn ct_fe64_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        p::fe64_sub(a, b)
    }

    #[no_mangle]
    pub fn ct_fe64_mul121666(a: &[u8; 32]) -> [u8; 32] {
        p::fe64_mul121666(a)
    }

    #[no_mangle]
    pub fn ct_fe64_invert(a: &[u8; 32]) -> [u8; 32] {
        p::fe64_invert(a)
    }

    #[no_mangle]
    pub fn ct_x25519_fe64_step(ws: &mut [u64; 76], swap: u64) {
        p::x25519_step(ws, swap)
    }

    #[no_mangle]
    pub fn ct_ed25519_fe64_madd_ext2(ws: &mut p::Ws2) {
        p::ed25519_madd_ext2(ws)
    }

    #[no_mangle]
    pub fn ct_ed25519_fe64_dbl_nadd(ws: &mut p::Ws) {
        p::ed25519_dbl_nadd(ws)
    }

    #[no_mangle]
    pub fn ct_x25519_ifma_step(s: &p::ifma::Lanes, x1: &[u64; 4], swap: u64) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::ladder_step(s, x1, swap) }
    }

    #[no_mangle]
    pub fn ct_ed25519_ifma_select(t: &[p::ifma::Lanes; 8], digit: i8) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::select(t, digit) }
    }

    #[no_mangle]
    pub fn ct_ed25519_ifma_add(a: &p::ifma::Lanes, n: &p::ifma::Lanes) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::add(a, n) }
    }

    #[no_mangle]
    pub fn ct_ed25519_ifma_double(a: &p::ifma::Lanes) -> p::ifma::Lanes {
        // SAFETY: never executed; compiled to be read.
        unsafe { p::ifma::double(a) }
    }
}
