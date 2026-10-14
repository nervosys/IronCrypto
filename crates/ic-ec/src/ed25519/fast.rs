//! The basepoint multiplication and the double-scalar multiplication on the
//! four-limb field, as sequences of `fe64::edwards` blocks.
//!
//! The same algorithms as `basepoint_table::mul_generic` and
//! `double_scalar_mul_vartime_generic`, step for step: the same recodings, the
//! same tables, the same additions in the same order. Only the arithmetic
//! between them moved, from one assembly block per field operation to one per
//! group operation, with the point held in a workspace throughout. The tests
//! below hold the two to the same points.
//!
//! Signing's path takes the same blocks in the same order for every scalar --
//! a constant-time table scan, a mixed addition, a conversion, sixty-four
//! times -- and the scan and the conditional negation are the generic ones.
//! Verification's path chooses blocks by the scalars' recodings, which are
//! public.
//!
//! One exception to "the same algorithm": on a CPU with AVX2, signing takes
//! [`mul_base_wide`], signed radix-32 digits against tables of sixteen
//! multiples, read in vector registers inside the additions. It is tested
//! against the same generic multiplication, by the point it produces.

// The scalar's digits are read two by two, as `mul_generic` pairs them.
#![allow(clippy::needless_range_loop)]

use std::sync::OnceLock;

use super::basepoint_table::{self, window};
use super::{
    basepoint, odd_multiples, signed_digits, signed_digits32, wnaf, AffineNiels, Ext, Niels,
    DIGITS32,
};
use crate::fe64::edwards::{self as e, slot, Avx2, Ws, Ws2, Ws2Scan};
use crate::fe64::Fe64;
use ic_core::Zeroize;

/// Radix-32 windows: one per pair of digits, as the radix-16 tables pair
/// them.
const WIDE: usize = DIGITS32 / 2;

/// `1..=16` times `32^(2j) * B` in affine Niels form: 1536 bytes, the
/// sixteen entries [`e::scan`] reads.
#[repr(transparent)]
pub(super) struct Wide([AffineNiels<Fe64>; 16]);

impl Wide {
    fn new(base: &Ext<Fe64>) -> Self {
        let mut multiples = [*base; 16];
        for i in 1..16 {
            multiples[i] = multiples[i - 1].add(base);
        }
        Self(core::array::from_fn(|i| multiples[i].to_affine_niels()))
    }
}

/// The radix-32 windows, filled only on the CPUs whose signing reads them;
/// 39 KiB. A `OnceLock` each, as `basepoint_table` holds its windows, so
/// that filling them needs one window of stack.
static WIDE_WINDOWS: [OnceLock<Wide>; WIDE] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const NONE: OnceLock<Wide> = OnceLock::new();
    [NONE; WIDE]
};

/// Fill [`WIDE_WINDOWS`] in order, ten doublings between windows.
pub(super) fn prepare_wide() {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let mut base = basepoint::<Fe64>();
        for (i, slot) in WIDE_WINDOWS.iter().enumerate() {
            if i > 0 {
                for _ in 0..10 {
                    base = base.double();
                }
            }
            slot.get_or_init(|| Wide::new(&base));
        }
    });
}

/// Radix-32 window `j`. Filled by [`prepare_wide`]; were it somehow not,
/// built here on its own, more slowly and with the same result.
fn wide(j: usize) -> &'static [[u64; 12]; 16] {
    let w = WIDE_WINDOWS[j].get_or_init(|| {
        let mut base = basepoint::<Fe64>();
        for _ in 0..10 * j {
            base = base.double();
        }
        Wide::new(&base)
    });
    e::limbs16(&w.0)
}

fn put(ws: &mut Ws, at: usize, v: &Fe64) {
    ws.0[at..at + 4].copy_from_slice(&v.0);
}

fn get(ws: &Ws, at: usize) -> Fe64 {
    let mut v = [0u64; 4];
    v.copy_from_slice(&ws.0[at..at + 4]);
    Fe64(v)
}

fn put_affine(ws: &mut Ws, n: &AffineNiels<Fe64>) {
    put(ws, slot::YPX, &n.ypx);
    put(ws, slot::YMX, &n.ymx);
    put(ws, slot::T2D, &n.t2d);
}

fn put_niels(ws: &mut Ws, n: &Niels<Fe64>) {
    put(ws, slot::YPX, &n.ypx);
    put(ws, slot::YMX, &n.ymx);
    put(ws, slot::NZ, &n.z);
    put(ws, slot::T2D, &n.t2d);
}

fn get_ext(ws: &Ws) -> Ext<Fe64> {
    Ext {
        x: get(ws, slot::X),
        y: get(ws, slot::Y),
        z: get(ws, slot::Z),
        t: get(ws, slot::T),
    }
}

/// The operand slots of half `H` of a two-accumulator workspace.
fn operand<const H: usize>(two: &mut Ws2) -> &mut [u64; 16] {
    let at = H * 64 + slot::YPX;
    // Sixteen limbs at a constant offset inside 128: the conversion cannot
    // fail, and the optimiser removes the check.
    (&mut two.0[at..at + 16]).try_into().expect("sixteen limbs")
}

/// A workspace holding the identity, `(0 : 1 : 1 : 0)`.
fn identity() -> Ws {
    let mut ws = Ws([0; 64]);
    put(&mut ws, slot::Y, &Fe64::ONE);
    put(&mut ws, slot::Z, &Fe64::ONE);
    ws
}

/// `scalar * B`, constant time: [`mul_base_wide`] on a CPU with AVX2,
/// [`mul_base_narrow`] on one without.
pub(super) fn mul_base(scalar: &[u8; 32]) -> Ext<Fe64> {
    match Avx2::get() {
        Some(t) => mul_base_wide(t, scalar),
        None => mul_base_narrow(scalar),
    }
}

/// `scalar * B`, constant time: `basepoint_table::mul_generic`'s digits,
/// tables and scan, on blocks, with its two halves run side by side.
///
/// `mul_generic` sums the odd-numbered digits' table entries, multiplies by
/// sixteen, then adds the even-numbered ones. Those two sums do not depend on
/// each other, so here they are two accumulators advanced together by
/// [`e::madd_ext2`], which interleaves their field operations; then the odd
/// sum is multiplied by sixteen and the even one added once, as a Niels
/// point. The same blocks run in the same order for every scalar.
pub(super) fn mul_base_narrow(scalar: &[u8; 32]) -> Ext<Fe64> {
    basepoint_table::prepare::<Fe64>();
    let digits = signed_digits(scalar);
    let mut two = Ws2([0; 128]);
    for half in [0, 64] {
        two.0[half + slot::Y..half + slot::Y + 4].copy_from_slice(&Fe64::ONE.0);
        two.0[half + slot::Z..half + slot::Z + 4].copy_from_slice(&Fe64::ONE.0);
    }
    for j in 0..32 {
        let table = window::<Fe64>(j).entries();
        e::select(operand::<0>(&mut two), e::limbs(table), digits[2 * j + 1]);
        e::select(operand::<1>(&mut two), e::limbs(table), digits[2 * j]);
        e::madd_ext2(&mut two);
    }
    combine(&mut two, 4)
}

/// `scalar * B`, constant time, in signed radix 32 with the table reads
/// inside the additions.
///
/// [`mul_base_narrow`]'s shape -- two accumulators, the odd-numbered digits'
/// and the even-numbered ones', advanced together, then the odd sum scaled
/// and the even one added -- with digits of five bits rather than four:
/// 52 of them, 26 steps of two additions instead of 32, and five doublings
/// at the end instead of four. A wider digit doubles each table read, which
/// is why the radix-16 form stopped at 16: read apart from the addition, the
/// eight entries already cost a fifth as much as it. Here
/// [`e::madd_ext2_scan`] reads the next step's entries while the addition
/// runs, in vector registers on otherwise idle units, and sixteen entries
/// cost it a few percent. The tables are 39 KiB against the radix-16 form's
/// 24.
///
/// The same blocks run in the same order for every scalar; the digits
/// decide only masks.
pub(super) fn mul_base_wide(t: Avx2, scalar: &[u8; 32]) -> Ext<Fe64> {
    prepare_wide();
    let digits = signed_digits32(scalar);
    let mut scan = Ws2Scan {
        two: Ws2([0; 128]),
        ctl: [0; 8],
    };
    for half in [0, 64] {
        let two = &mut scan.two.0;
        two[half + slot::Y..half + slot::Y + 4].copy_from_slice(&Fe64::ONE.0);
        two[half + slot::Z..half + slot::Z + 4].copy_from_slice(&Fe64::ONE.0);
    }
    e::scan(t, &mut scan, wide(0), digits[1], digits[0]);
    for j in 1..WIDE {
        e::madd_ext2_scan(t, &mut scan, wide(j), digits[2 * j + 1], digits[2 * j]);
    }
    e::madd_ext2(&mut scan.two);
    scan.ctl.zeroize();
    combine(&mut scan.two, 5)
}

/// `2^doublings * odd + even`, the two halves of `two`, which is wiped.
fn combine(two: &mut Ws2, doublings: usize) -> Ext<Fe64> {
    let mut ws = Ws([0; 64]);
    ws.0.copy_from_slice(&two.0[..64]);
    let mut even = Ws([0; 64]);
    even.0.copy_from_slice(&two.0[64..]);
    let even_niels = get_ext(&even).to_niels();
    for _ in 1..doublings {
        e::dbl(&mut ws);
        e::to_proj(&mut ws);
    }
    e::dbl(&mut ws);
    e::to_ext(&mut ws);
    put_niels(&mut ws, &even_niels);
    e::nadd(&mut ws);
    e::to_ext(&mut ws);
    let out = get_ext(&ws);
    // The workspaces held the secret scalar's multiples on the way.
    ws.0.zeroize();
    even.0.zeroize();
    two.0.zeroize();
    out
}

/// `[k]A + [s]B`, variable time; `double_scalar_mul_vartime_generic` on
/// blocks.
pub(super) fn double_mul(a: &Ext<Fe64>, k: &[u8; 32], s: &[u8; 32]) -> Ext<Fe64> {
    basepoint_table::prepare::<Fe64>();
    let odd_a = odd_multiples(a);
    let naf_a = wnaf(k, 5);
    let naf_b = wnaf(s, 8);

    let mut i = 257;
    while i > 0 && naf_a[i] == 0 && naf_b[i] == 0 {
        i -= 1;
    }

    // The accumulator is projective between steps, and extended only where
    // an addition is about to read T.
    let mut ws = identity();
    loop {
        e::dbl(&mut ws);
        if naf_a[i] != 0 {
            e::to_ext(&mut ws);
            put_niels(&mut ws, &odd_a[(naf_a[i].unsigned_abs() as usize) / 2]);
            if naf_a[i] > 0 {
                e::nadd(&mut ws);
            } else {
                e::nsub(&mut ws);
            }
        }
        if naf_b[i] != 0 {
            e::to_ext(&mut ws);
            put_affine(
                &mut ws,
                basepoint_table::odd_multiple::<Fe64>((naf_b[i].unsigned_abs() as usize) / 2),
            );
            if naf_b[i] > 0 {
                e::madd(&mut ws);
            } else {
                e::msub(&mut ws);
            }
        }
        if i == 0 {
            e::to_ext(&mut ws);
            return get_ext(&ws);
        }
        e::to_proj(&mut ws);
        i -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::super::basepoint_table::mul_generic;
    use super::super::{basepoint, double_scalar_mul_vartime_generic, Completed};
    use super::*;

    fn skip() -> bool {
        !crate::fe64::available()
    }

    fn sample_points(n: usize) -> std::vec::Vec<Ext<Fe64>> {
        let mut out = std::vec::Vec::new();
        let mut p = basepoint::<Fe64>();
        for _ in 0..n {
            out.push(p);
            p = p.double().add(&basepoint::<Fe64>());
        }
        out
    }

    fn put_ext(ws: &mut Ws, p: &Ext<Fe64>) {
        put(ws, slot::X, &p.x);
        put(ws, slot::Y, &p.y);
        put(ws, slot::Z, &p.z);
        put(ws, slot::T, &p.t);
    }

    fn get_completed(ws: &Ws) -> Completed<Fe64> {
        Completed {
            x: get(ws, 16),
            y: get(ws, 20),
            z: get(ws, 24),
            t: get(ws, 28),
        }
    }

    #[test]
    #[ignore = "diagnostic"]
    fn where_signing_spends_its_time() {
        use std::time::Instant;
        basepoint_table::prepare::<Fe64>();
        let n = 20_000u32;
        let time = |label: &str, f: &mut dyn FnMut()| {
            let mut best = f64::INFINITY;
            for _ in 0..7 {
                let s = Instant::now();
                for _ in 0..n {
                    f();
                }
                best = best.min(s.elapsed().as_secs_f64() / n as f64 * 1e9);
            }
            std::println!("{label:<32} {best:>9.1} ns");
        };
        let digits = signed_digits(&[0x5au8; 32]);
        time("64 selects", &mut || {
            for i in 0..64 {
                core::hint::black_box(
                    window::<Fe64>(i / 2).select(core::hint::black_box(digits[i])),
                );
            }
        });
        let mut dst = [0u64; 16];
        time("64 selects, assembly", &mut || {
            for i in 0..64 {
                e::select(
                    &mut dst,
                    e::limbs(window::<Fe64>(i / 2).entries()),
                    core::hint::black_box(digits[i]),
                );
            }
        });
        let mut two = Ws2([7; 128]);
        time("32 madd_ext2", &mut || {
            for _ in 0..32 {
                e::madd_ext2(&mut two);
            }
        });
        let mut one = Ws([7; 64]);
        time("64 madd + to_ext", &mut || {
            for _ in 0..64 {
                e::madd(&mut one);
                e::to_ext(&mut one);
            }
        });
        time("mul_base", &mut || {
            core::hint::black_box(mul_base(core::hint::black_box(&[0x5au8; 32])));
        });
        time("mul_base_narrow", &mut || {
            core::hint::black_box(mul_base_narrow(core::hint::black_box(&[0x5au8; 32])));
        });
        if let Some(t) = Avx2::get() {
            let wide_digits = signed_digits32(&[0x5au8; 32]);
            let mut scan = Ws2Scan {
                two: Ws2([7; 128]),
                ctl: [0; 8],
            };
            time("25 madd_ext2_scan", &mut || {
                for j in 1..WIDE {
                    e::madd_ext2_scan(
                        t,
                        &mut scan,
                        wide(j),
                        core::hint::black_box(wide_digits[2 * j + 1]),
                        wide_digits[2 * j],
                    );
                }
            });
            time("mul_base_wide", &mut || {
                core::hint::black_box(mul_base_wide(t, core::hint::black_box(&[0x5au8; 32])));
            });
            // Alternated, best of many batches each, for an A/B under load.
            let mut best = [f64::INFINITY; 2];
            let mut narrow = || {
                core::hint::black_box(mul_base_narrow(core::hint::black_box(&[0x5au8; 32])));
            };
            let mut wide = || {
                core::hint::black_box(mul_base_wide(t, core::hint::black_box(&[0x5au8; 32])));
            };
            for _ in 0..300 {
                let pair: [&mut dyn FnMut(); 2] = [&mut narrow, &mut wide];
                for (i, f) in pair.into_iter().enumerate() {
                    let s = Instant::now();
                    for _ in 0..100 {
                        f();
                    }
                    best[i] = best[i].min(s.elapsed().as_secs_f64() / 100.0 * 1e9);
                }
            }
            std::println!(
                "alternated: narrow {:.1} ns, wide {:.1} ns, ratio {:.3}",
                best[0],
                best[1],
                best[0] / best[1]
            );
        }
        time("mul_generic", &mut || {
            core::hint::black_box(mul_generic::<Fe64>(core::hint::black_box(&[0x5au8; 32])));
        });
        let p = mul_base(&[0x5au8; 32]);
        time("compress", &mut || {
            core::hint::black_box(core::hint::black_box(&p).compress());
        });
        let msg = [0x42u8; 17];
        time("hash_to_scalar (2 parts)", &mut || {
            core::hint::black_box(super::super::hash_to_scalar(&[
                core::hint::black_box(&[0x5au8; 32]),
                &msg,
            ]));
        });
        time("hash_to_scalar (3 parts)", &mut || {
            core::hint::black_box(super::super::hash_to_scalar(&[
                core::hint::black_box(&[0x5au8; 32]),
                &[0x33u8; 32],
                &msg,
            ]));
        });
        time("scalar::reduce_wide", &mut || {
            core::hint::black_box(crate::scalar::reduce_wide(core::hint::black_box(
                &[0x9cu8; 64],
            )));
        });
        time("sha-512, 81 bytes", &mut || {
            use ic_core::traits::internal::Digest;
            let mut h = ic_hash::Sha512::new();
            h.update(core::hint::black_box(&[0x5au8; 81]));
            core::hint::black_box(h.finalize());
        });
        time("scalar::mul_add", &mut || {
            core::hint::black_box(crate::scalar::mul_add(
                core::hint::black_box(&[0x0au8; 32]),
                &[0x0bu8; 32],
                &[0x0cu8; 32],
            ));
        });
        let k = [0x3cu8; 32];
        let mut s2 = [0x77u8; 32];
        s2[31] = 0x0f;
        let a = mul_base(&[0x29u8; 32]);
        time("double_mul (vartime)", &mut || {
            core::hint::black_box(double_mul(
                core::hint::black_box(&a),
                core::hint::black_box(&k),
                &s2,
            ));
        });
        let mut one = Ws([7; 64]);
        time("253 dbl + to_proj", &mut || {
            for _ in 0..253 {
                e::dbl(&mut one);
                e::to_proj(&mut one);
            }
        });
        time("70 dbl+to_ext+nadd+to_proj", &mut || {
            for _ in 0..70 {
                e::dbl(&mut one);
                e::to_ext(&mut one);
                e::nadd(&mut one);
                e::to_proj(&mut one);
            }
        });
        time("odd_multiples (A table)", &mut || {
            core::hint::black_box(odd_multiples(core::hint::black_box(&a)));
        });
        let enc = a.compress();
        time("decompress", &mut || {
            core::hint::black_box(Ext::<Fe64>::decompress(core::hint::black_box(&enc)));
        });
        time("has_small_order", &mut || {
            core::hint::black_box(core::hint::black_box(&a).has_small_order());
        });
        let key = super::super::Ed25519Key::from_seed(&[7u8; 32]).unwrap();
        let mut sig = [0u8; 64];
        time("Ed25519Key::sign", &mut || {
            key.sign(core::hint::black_box(&msg), &mut sig).unwrap();
        });
    }

    /// Every block against the method it transcribes, compared as points.
    #[test]
    fn each_block_is_the_formula_it_transcribes() {
        if skip() {
            return;
        }
        let pts = sample_points(12);
        let mut checked = 0;
        for p in &pts {
            // dbl, to_ext, to_proj.
            let mut ws = Ws([0; 64]);
            put_ext(&mut ws, p);
            e::dbl(&mut ws);
            let want = p.to_projective().double();
            let got = get_completed(&ws);
            assert!(got.to_extended().eq_projective(&want.to_extended()), "dbl");
            e::to_ext(&mut ws);
            assert!(get_ext(&ws).eq_projective(&want.to_extended()), "to_ext");
            put_ext(&mut ws, p);
            e::dbl(&mut ws);
            e::to_proj(&mut ws);
            let proj = want.to_projective();
            assert_eq!(get(&ws, slot::X).to_bytes(), proj.x.to_bytes(), "to_proj");
            assert_eq!(get(&ws, slot::Z).to_bytes(), proj.z.to_bytes(), "to_proj");
            for q in &pts {
                let an = q.to_affine_niels();
                let n = q.to_niels();
                type Case = (&'static str, fn(&mut Ws), Completed<Fe64>, bool);
                let cases: [Case; 4] = [
                    ("madd", e::madd, p.add_affine_niels(&an), true),
                    ("msub", e::msub, p.sub_affine_niels(&an), true),
                    ("nadd", e::nadd, p.add_niels(&n), false),
                    ("nsub", e::nsub, p.sub_niels(&n), false),
                ];
                for (name, f, want, affine) in cases {
                    put_ext(&mut ws, p);
                    if affine {
                        put_affine(&mut ws, &an);
                    } else {
                        put_niels(&mut ws, &n);
                    }
                    f(&mut ws);
                    let got = get_completed(&ws);
                    assert!(
                        got.to_extended().eq_projective(&want.to_extended()),
                        "{name}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 12 * 12 * 4);
    }

    /// The assembly table read against the generic one, limb for limb, for
    /// every digit of every window, into a workspace whose other limbs it
    /// must leave alone.
    #[test]
    fn the_assembly_select_is_the_generic_one() {
        if skip() {
            return;
        }
        basepoint_table::prepare::<Fe64>();
        let mut checked = 0;
        for j in 0..32 {
            let w = window::<Fe64>(j);
            for digit in -8i8..=8 {
                let want = w.select(digit);
                let mut dst = [0x5a5a_5a5a_5a5a_5a5au64; 16];
                e::select(&mut dst, e::limbs(w.entries()), digit);
                assert_eq!(dst[0..4], want.ypx.0, "y + x, window {j}, digit {digit}");
                assert_eq!(dst[4..8], want.ymx.0, "y - x, window {j}, digit {digit}");
                assert_eq!(dst[12..16], want.t2d.0, "2dxy, window {j}, digit {digit}");
                assert!(
                    dst[8..12].iter().all(|&l| l == 0x5a5a_5a5a_5a5a_5a5a),
                    "the Z slot was written"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 32 * 17);
    }

    /// The block paths against the generic ones on the same field, and those
    /// against the portable field.
    #[test]
    fn the_block_paths_agree_with_the_generic_ones() {
        use ic_core::traits::internal::Digest;
        if skip() {
            return;
        }
        let mut checked = 0;
        for i in 0u32..64 {
            let mut s = ic_hash::Sha256::digest(&i.to_le_bytes());
            s[31] &= 0x7f;
            if i == 0 {
                s = [0; 32];
            }
            if i == 1 {
                s = [0xff; 32];
                s[31] = 0x7f;
            }
            let fast = mul_base(&s);
            let slow = mul_generic::<Fe64>(&s);
            let portable = mul_generic::<crate::field::Fe>(&s);
            assert_eq!(fast.compress(), slow.compress(), "mul_base {i}");
            assert_eq!(fast.compress(), portable.compress(), "mul_base {i}");

            let mut k = ic_hash::Sha256::digest(&(i + 1000).to_le_bytes());
            // Below 2^255, as every scalar the base multiplication sees is.
            k[31] &= 0x7f;
            let a = mul_base(&k);
            let fast = double_mul(&a, &k, &s);
            let slow = double_scalar_mul_vartime_generic(&a, &k, &s);
            let portable =
                double_scalar_mul_vartime_generic(&a.convert::<crate::field::Fe>(), &k, &s);
            assert_eq!(fast.compress(), slow.compress(), "double_mul {i}");
            assert_eq!(fast.compress(), portable.compress(), "double_mul {i}");
            checked += 1;
        }
        assert_eq!(checked, 64);
    }

    /// `d` times a radix-32 window's point as the generic code would select
    /// it: every entry by `cmov`, then the conditional negation.
    fn select16(table: &Wide, d: i8) -> AffineNiels<Fe64> {
        let negative = u64::from((d as u8) >> 7);
        let magnitude = u64::from(d.unsigned_abs());
        let mut out = AffineNiels::IDENTITY;
        for (i, entry) in table.0.iter().enumerate() {
            out.cmov(entry, u64::from(magnitude == i as u64 + 1));
        }
        out.conditional_negate(negative);
        out
    }

    fn wide_table(j: usize) -> &'static Wide {
        prepare_wide();
        WIDE_WINDOWS[j].get().expect("filled")
    }

    /// The radix-32 digits: in range, and summing to the scalar.
    #[test]
    fn the_radix_32_digits_represent_the_scalar() {
        use ic_core::traits::internal::Digest;
        let mut scalars = std::vec::Vec::new();
        scalars.push([0u8; 32]);
        let mut top = [0xffu8; 32];
        top[31] = 0x7f;
        scalars.push(top);
        // Every five-bit field 16 or 31: the carries ripple the whole way.
        for fill in [0x10u8, 0x1f, 0x84, 0x42, 0x21, 0xef] {
            let mut s = [fill; 32];
            s[31] &= 0x7f;
            scalars.push(s);
        }
        scalars.push(crate::scalar::L);
        for i in 0u32..2000 {
            let mut s = ic_hash::Sha256::digest(&i.to_le_bytes());
            s[31] &= 0x7f;
            scalars.push(s);
        }
        for s in &scalars {
            let d = signed_digits32(s);
            assert!(d.iter().all(|&x| (-16..=16).contains(&x)), "{s:?}: {d:?}");
            assert!((0..=1).contains(&d[DIGITS32 - 1]), "{s:?}: {d:?}");
            // Back to five-bit fields by carrying, then to bytes.
            let mut v = d.map(i64::from);
            for i in 0..DIGITS32 - 1 {
                let c = v[i].div_euclid(32);
                v[i] -= c * 32;
                v[i + 1] += c;
            }
            let mut back = [0u8; 33];
            for (i, &f) in v.iter().enumerate() {
                assert!((0..32).contains(&f) || i == DIGITS32 - 1, "{s:?}");
                let bit = 5 * i;
                let w = (f as u16) << (bit % 8);
                back[bit / 8] |= w as u8;
                if bit / 8 + 1 < 33 {
                    back[bit / 8 + 1] |= (w >> 8) as u8;
                }
            }
            assert_eq!(&back[..32], s, "{d:?}");
            assert_eq!(back[32], 0);
        }
    }

    /// The AVX2 table read against the generic selection, limb for limb, for
    /// every pair of digits in every window, into a workspace whose other
    /// limbs it must leave alone.
    #[test]
    fn the_wide_scan_is_the_generic_select() {
        let Some(t) = Avx2::get() else {
            return;
        };
        if skip() {
            return;
        }
        let mut checked = 0;
        for j in 0..WIDE {
            let table = wide_table(j);
            for d0 in -16i8..=16 {
                for d1 in -16i8..=16 {
                    let mut scan = Ws2Scan {
                        two: Ws2([0x5a5a_5a5a_5a5a_5a5a; 128]),
                        ctl: [0; 8],
                    };
                    e::scan(t, &mut scan, wide(j), d0, d1);
                    for (h, d) in [(0usize, d0), (1, d1)] {
                        let want = select16(table, d);
                        let at = 64 * h + slot::YPX;
                        let got = &scan.two.0[at..at + 16];
                        assert_eq!(got[0..4], want.ypx.0, "y + x, {j} {d}");
                        assert_eq!(got[4..8], want.ymx.0, "y - x, {j} {d}");
                        assert_eq!(got[12..16], want.t2d.0, "2dxy, {j} {d}");
                        assert!(got[8..12].iter().all(|&l| l == 0x5a5a_5a5a_5a5a_5a5a));
                        let rest = scan.two.0[64 * h..at]
                            .iter()
                            .chain(&scan.two.0[at + 16..64 * h + 64]);
                        assert!(rest.into_iter().all(|&l| l == 0x5a5a_5a5a_5a5a_5a5a));
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, WIDE * 33 * 33);
    }

    /// The addition with the read inside it against the addition, then the
    /// read: the whole workspace, limb for limb, over points and digits.
    #[test]
    fn the_wide_step_is_the_addition_then_the_read() {
        let Some(t) = Avx2::get() else {
            return;
        };
        if skip() {
            return;
        }
        let pts = sample_points(8);
        let mut checked = 0;
        for (n, p) in pts.iter().enumerate() {
            let q = &pts[(n + 3) % pts.len()];
            for (j, (d0, d1)) in [
                (0usize, (0i8, 0i8)),
                (1, (16, -16)),
                (7, (-1, 9)),
                (25, (1, -7)),
            ] {
                let mut a = Ws2Scan {
                    two: Ws2([0; 128]),
                    ctl: [0; 8],
                };
                for (h, point, operand) in [(0usize, p, q), (1, q, p)] {
                    let mut half = Ws([0; 64]);
                    put_ext(&mut half, point);
                    put_affine(&mut half, &operand.to_affine_niels());
                    a.two.0[64 * h..64 * h + 64].copy_from_slice(&half.0);
                }
                let mut b = Ws2Scan {
                    two: Ws2(a.two.0),
                    ctl: [0; 8],
                };
                e::madd_ext2_scan(t, &mut a, wide(j), d0, d1);
                e::madd_ext2(&mut b.two);
                e::scan(t, &mut b, wide(j), d0, d1);
                assert_eq!(a.two.0, b.two.0, "point {n}, window {j}, digits {d0} {d1}");
                checked += 1;
            }
        }
        assert_eq!(checked, 8 * 4);
    }

    /// Both basepoint multiplications on this field, the radix-32 one where
    /// the CPU has AVX2, against the generic one.
    #[test]
    fn narrow_and_wide_agree() {
        use ic_core::traits::internal::Digest;
        if skip() {
            return;
        }
        for i in 0u32..48 {
            let mut s = ic_hash::Sha256::digest(&(i + 5000).to_le_bytes());
            s[31] &= 0x7f;
            if i == 0 {
                s = [0x10; 32];
                s[31] = 0x70;
            }
            if i == 1 {
                // L - 1, the largest reduced scalar.
                s = crate::scalar::L;
                s[0] -= 1;
            }
            let want = mul_generic::<Fe64>(&s).compress();
            assert_eq!(mul_base_narrow(&s).compress(), want, "narrow {i}");
            if let Some(t) = Avx2::get() {
                assert_eq!(mul_base_wide(t, &s).compress(), want, "wide {i}");
            }
        }
    }
}
