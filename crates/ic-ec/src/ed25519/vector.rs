//! The basepoint multiplication and the double-scalar multiplication on four
//! lanes at once, with AVX-512 IFMA; see `crate::f51x4`.
//!
//! The same algorithms as `basepoint_table::mul_generic` and
//! `double_scalar_mul_vartime_generic`: the same recodings and the same
//! tables, held here in the four-lane form, and the same group operations.
//! Two things differ in form, neither in result. Every operation ends in
//! extended coordinates, because the vector multiplication computes all four
//! coordinates in one go and dropping `T` would save nothing. And the
//! basepoint multiplication runs its two halves -- the odd-numbered digits
//! and the even-numbered ones -- as two accumulators advanced together,
//! since they are independent until the end; that is the order of additions
//! `mul_generic` uses, regrouped.
//!
//! Signing's path performs the same operations in the same order for every
//! scalar: sixty-four constant-time selections and additions, four
//! doublings, one more addition. Verification's chooses its operations by
//! the scalars' recodings, which are public.

use std::sync::OnceLock;

use super::basepoint_table::{self, window};
use super::{odd_multiples, signed_digits, wnaf, Ext};
use crate::f51x4::{Ifma, N4, P4};
use crate::fe64::Fe64;

/// `2`, the `2 Z` of an affine operand.
const TWO: Fe64 = Fe64([2, 0, 0, 0]);

#[allow(clippy::declare_interior_mutable_const)]
const NO_WINDOW: OnceLock<[N4; 8]> = OnceLock::new();
/// `basepoint_table`'s windows, as operands.
static WINDOWS: [OnceLock<[N4; 8]>; 32] = [NO_WINDOW; 32];

#[allow(clippy::declare_interior_mutable_const)]
const NO_ODD: OnceLock<N4> = OnceLock::new();
/// `basepoint_table`'s odd multiples, as operands.
static ODD: [OnceLock<N4>; 64] = [NO_ODD; 64];

fn window4(t: Ifma, j: usize) -> &'static [N4; 8] {
    WINDOWS[j].get_or_init(|| {
        let w = window::<Fe64>(j);
        core::array::from_fn(|i| {
            let e = &w.entries()[i];
            t.operand(&e.ymx, &e.ypx, &e.t2d, &TWO)
        })
    })
}

fn odd4(t: Ifma, i: usize) -> &'static N4 {
    ODD[i].get_or_init(|| {
        let e = basepoint_table::odd_multiple::<Fe64>(i);
        t.operand(&e.ymx, &e.ypx, &e.t2d, &TWO)
    })
}

fn to_ext(t: Ifma, p: &P4) -> Ext<Fe64> {
    let [x, y, z, tt] = t.coordinates(p);
    Ext { x, y, z, t: tt }
}

fn identity(t: Ifma) -> P4 {
    t.point(&Fe64::ZERO, &Fe64::ONE, &Fe64::ONE, &Fe64::ZERO)
}

/// `scalar * B`, constant time.
pub(super) fn mul_base(t: Ifma, scalar: &[u8; 32]) -> Ext<Fe64> {
    basepoint_table::prepare::<Fe64>();
    let digits = signed_digits(scalar);
    // Odd-numbered digits into one accumulator, even-numbered into the
    // other, each step of the two independent of the other.
    let mut odd = identity(t);
    let mut even = identity(t);
    for j in 0..32 {
        let table = window4(t, j);
        odd = t.add(&odd, &t.select(table, digits[2 * j + 1]));
        even = t.add(&even, &t.select(table, digits[2 * j]));
    }
    // 16 * odd + even.
    for _ in 0..4 {
        odd = t.double(&odd);
    }
    let e = to_ext(t, &even);
    let operand = t.operand(
        &e.y.sub(&e.x),
        &e.y.add(&e.x),
        &e.t.mul(&<Fe64 as super::EdField>::D2),
        &e.z.add(&e.z),
    );
    to_ext(t, &t.add(&odd, &operand))
}

/// `[k]A + [s]B`, variable time.
pub(super) fn double_mul(t: Ifma, a: &Ext<Fe64>, k: &[u8; 32], s: &[u8; 32]) -> Ext<Fe64> {
    basepoint_table::prepare::<Fe64>();
    let odd_a = odd_multiples(a);
    let plus: [N4; 8] = core::array::from_fn(|i| {
        let n = &odd_a[i];
        t.operand(&n.ymx, &n.ypx, &n.t2d, &n.z.add(&n.z))
    });
    let minus: [N4; 8] = core::array::from_fn(|i| t.negate(&plus[i]));
    let naf_a = wnaf(k, 5);
    let naf_b = wnaf(s, 8);

    let mut i = 257;
    while i > 0 && naf_a[i] == 0 && naf_b[i] == 0 {
        i -= 1;
    }
    let mut acc = identity(t);
    loop {
        acc = t.double(&acc);
        let da = naf_a[i];
        if da > 0 {
            acc = t.add(&acc, &plus[(da as usize) / 2]);
        } else if da < 0 {
            acc = t.add(&acc, &minus[(da.unsigned_abs() as usize) / 2]);
        }
        let db = naf_b[i];
        if db != 0 {
            let n = odd4(t, (db.unsigned_abs() as usize) / 2);
            acc = if db > 0 {
                t.add(&acc, n)
            } else {
                t.add(&acc, &t.negate(n))
            };
        }
        if i == 0 {
            return to_ext(t, &acc);
        }
        i -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::super::basepoint_table::mul_generic;
    use super::super::{basepoint, double_scalar_mul_vartime_generic};
    use super::*;

    fn token() -> Option<Ifma> {
        Ifma::get()
    }

    #[test]
    #[ignore = "diagnostic"]
    fn backend_costs() {
        use std::time::Instant;
        let Some(t) = token() else { return };
        basepoint_table::prepare::<Fe64>();
        let time = |label: &str, n: u32, f: &mut dyn FnMut()| {
            let mut best = f64::INFINITY;
            for _ in 0..9 {
                let s = Instant::now();
                for _ in 0..n {
                    f();
                }
                best = best.min(s.elapsed().as_secs_f64() / n as f64 * 1e6);
            }
            std::println!("{label:<34} {best:>8.2} us");
        };
        let s = [0x5au8; 32];
        let k = [0x3cu8; 32];
        let a = mul_base(t, &[0x77u8; 32]);
        time("mul_base, IFMA", 5000, &mut || {
            core::hint::black_box(mul_base(t, core::hint::black_box(&s)));
        });
        time("mul_base, blocks", 5000, &mut || {
            core::hint::black_box(super::super::fast::mul_base(core::hint::black_box(&s)));
        });
        time("double_mul, IFMA", 2000, &mut || {
            core::hint::black_box(double_mul(t, &a, &k, core::hint::black_box(&s)));
        });
        time("double_mul, blocks", 2000, &mut || {
            core::hint::black_box(super::super::fast::double_mul(
                &a,
                &k,
                core::hint::black_box(&s),
            ));
        });
        let mut sk = [0x77u8; 32];
        sk[0] &= 248;
        sk[31] = 0x40;
        let u = [9u8; 32];
        time("x25519 ladder, IFMA", 2000, &mut || {
            core::hint::black_box(t.x25519_ladder(core::hint::black_box(&sk), &u));
        });
        time("x25519 ladder, blocks", 2000, &mut || {
            core::hint::black_box(crate::fe64::x25519_ladder(core::hint::black_box(&sk), &u));
        });
        let p = t.point(&a.x, &a.y, &a.z, &a.t);
        let mut q = p;
        time("1000 lane doublings", 200, &mut || {
            for _ in 0..1000 {
                q = t.double(&q);
            }
        });
        let n = t.operand(&a.y, &a.x, &a.t, &a.z);
        time("1000 lane additions", 200, &mut || {
            for _ in 0..1000 {
                q = t.add(&q, &n);
            }
        });
        core::hint::black_box(q);
    }

    /// The four-lane group operations against the four-limb ones.
    #[test]
    fn the_lane_operations_are_the_formulas() {
        let Some(t) = token() else { return };
        let mut p = basepoint::<Fe64>();
        let b = basepoint::<Fe64>();
        for _ in 0..32 {
            let p4 = t.point(&p.x, &p.y, &p.z, &p.t);
            let d = to_ext(t, &t.double(&p4));
            assert!(d.eq_projective(&p.double()), "double");
            for q in [b, p, p.double()] {
                let n = q.to_niels();
                let op = t.operand(&n.ymx, &n.ypx, &n.t2d, &n.z.add(&n.z));
                let sum = to_ext(t, &t.add(&p4, &op));
                assert!(sum.eq_projective(&p.add(&q)), "add");
                let diff = to_ext(t, &t.add(&p4, &t.negate(&op)));
                assert!(diff.eq_projective(&p.add(&q.negate())), "sub");
            }
            p = p.double().add(&b);
        }
    }

    /// The constant-time selection against the generic one, every digit.
    #[test]
    fn selection_agrees_for_every_digit() {
        let Some(t) = token() else { return };
        basepoint_table::prepare::<Fe64>();
        let p = basepoint::<Fe64>().double();
        for j in [0usize, 7, 31] {
            for digit in -8i8..=8 {
                let n = t.select(window4(t, j), digit);
                let g = window::<Fe64>(j).select(digit);
                let p4 = t.point(&p.x, &p.y, &p.z, &p.t);
                let got = to_ext(t, &t.add(&p4, &n));
                let want = p.add_affine_niels(&g).to_extended();
                assert!(got.eq_projective(&want), "window {j} digit {digit}");
            }
        }
    }

    #[test]
    fn the_lane_paths_agree_with_the_generic_ones() {
        use ic_core::traits::internal::Digest;
        let Some(t) = token() else { return };
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
            let got = mul_base(t, &s);
            let want = mul_generic::<crate::field::Fe>(&s);
            assert_eq!(got.compress(), want.compress(), "mul_base {i}");

            let mut k = ic_hash::Sha256::digest(&(i + 1000).to_le_bytes());
            // Below 2^255, as every scalar the base multiplication sees is.
            k[31] &= 0x7f;
            let a = mul_base(t, &k);
            let got = double_mul(t, &a, &k, &s);
            let want = double_scalar_mul_vartime_generic(&a.convert::<crate::field::Fe>(), &k, &s);
            assert_eq!(got.compress(), want.compress(), "double_mul {i}");
        }
    }
}
