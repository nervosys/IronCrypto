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
pub fn ct_hex_encode(input: &[u8; 1], output: &mut [u8; 2]) {
    let _ = ic_core::codec::hex_encode(input, output);
}

#[no_mangle]
pub fn ct_base64_encode(input: &[u8; 3], output: &mut [u8; 4]) {
    let _ = ic_core::codec::base64_encode(input, output);
}
