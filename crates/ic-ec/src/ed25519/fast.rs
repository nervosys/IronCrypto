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

// The scalar's digits are read two by two, as `mul_generic` pairs them.
#![allow(clippy::needless_range_loop)]

use super::basepoint_table::{self, window};
use super::{odd_multiples, signed_digits, wnaf, AffineNiels, Ext, Niels};
use crate::fe64::edwards::{self as e, slot, Ws, Ws2};
use crate::fe64::Fe64;
use ic_core::Zeroize;

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

/// `scalar * B`, constant time: `basepoint_table::mul_generic`'s digits,
/// tables and scan, on blocks, with its two halves run side by side.
///
/// `mul_generic` sums the odd-numbered digits' table entries, multiplies by
/// sixteen, then adds the even-numbered ones. Those two sums do not depend on
/// each other, so here they are two accumulators advanced together by
/// [`e::madd_ext2`], which interleaves their field operations; then the odd
/// sum is multiplied by sixteen and the even one added once, as a Niels
/// point. The same blocks run in the same order for every scalar.
pub(super) fn mul_base(scalar: &[u8; 32]) -> Ext<Fe64> {
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

    // 16 * odd + even.
    let mut ws = Ws([0; 64]);
    ws.0.copy_from_slice(&two.0[..64]);
    let mut even = Ws([0; 64]);
    even.0.copy_from_slice(&two.0[64..]);
    let even = get_ext(&even).to_niels();
    for _ in 0..3 {
        e::dbl(&mut ws);
        e::to_proj(&mut ws);
    }
    e::dbl(&mut ws);
    e::to_ext(&mut ws);
    put_niels(&mut ws, &even);
    e::nadd(&mut ws);
    e::to_ext(&mut ws);
    let out = get_ext(&ws);
    // The workspaces held the secret scalar's multiples on the way.
    ws.0.zeroize();
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
}
