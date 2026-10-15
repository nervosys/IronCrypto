//! The IFMA path against the `Fp` form: the field kernels lane by lane
//! against the generic word loop and the MULX code, the point kernels
//! against the `Fp` formulas coordinate for coordinate, and the three
//! multiplications whole against their `Fp` counterparts. Each test returns
//! early, and says so, on a CPU without the instructions.

use super::*;
use crate::nist::arith::{compute_neg_inv, compute_r2, mont_mul as word_loop_mul};
use crate::nist::gentable::{Comb, HasGeneratorTable};
use crate::p256::P256;
use crate::p384::P384;

/// The token, or a note that the tests have nothing to run here.
fn token() -> Option<Ifma> {
    let t = Ifma::get();
    if t.is_none() {
        std::println!("no AVX-512 IFMA on this CPU: nothing to compare");
    }
    t
}

/// `release` under `--release`, `debug` otherwise: the full counts run
/// optimised, as `f51x4`'s and `fe64`'s tests do.
fn count(release: usize, debug: usize) -> usize {
    if cfg!(debug_assertions) {
        debug
    } else {
        release
    }
}

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// What the lane tests need of a curve beyond `LaneCurve`.
trait TestCurve: LaneCurve + HasGeneratorTable {
    /// The largest value each limb of a lane vector may hold.
    const CONTRACT: &'static [u64];
    /// p.
    const P: &'static [u64];
    /// The lane-wise product and linear-combination kernels.
    const MUL: Kernel;
    const LIN: Kernel;
    /// The lane integer of `a * b`, as the `mul` kernel defines it, reduced:
    /// by the generic word loop, and by the MULX code.
    fn mul_word_loop(a: &[u64], b: &[u64]) -> std::vec::Vec<u64>;
    fn mul_mulx(a: &[u64], b: &[u64]) -> std::vec::Vec<u64>;
    /// A lane's limbs to the reduced integer they spell.
    fn reduced(limbs: &[u64]) -> std::vec::Vec<u64>;
}

fn generic_mm<const N: usize>(a: [u64; N], b: [u64; N], p: [u64; N]) -> [u64; N] {
    let (d, t, take) = word_loop_mul(a, b, p, compute_neg_inv(p[0]));
    if take == 1 {
        d
    } else {
        t
    }
}

impl TestCurve for P256 {
    const CONTRACT: &'static [u64] = &k::P256_CONTRACT;
    const P: &'static [u64] = &crate::nist::p256_field::P;
    const MUL: Kernel = k::p256_mul;
    const LIN: Kernel = k::p256_lin;

    // The kernel's product is a b 2^-260 (R = 2^260); the word loop's and
    // the MULX code's are a b 2^-256, so one more multiplication by 2^252
    // makes theirs 2^-260 too.
    fn mul_word_loop(a: &[u64], b: &[u64]) -> std::vec::Vec<u64> {
        let p = crate::nist::p256_field::P;
        let x = generic_mm(a.try_into().unwrap(), b.try_into().unwrap(), p);
        generic_mm(x, [0, 0, 0, 1 << 60], p).to_vec()
    }
    fn mul_mulx(a: &[u64], b: &[u64]) -> std::vec::Vec<u64> {
        use crate::nist::p256_field::active::mul;
        mul(
            mul(a.try_into().unwrap(), b.try_into().unwrap()),
            [0, 0, 0, 1 << 60],
        )
        .to_vec()
    }
    fn reduced(limbs: &[u64]) -> std::vec::Vec<u64> {
        reduce::<5, 4>(
            pack52(limbs.try_into().unwrap()),
            &crate::nist::p256_field::P,
        )[..4]
            .to_vec()
    }
}

impl TestCurve for P384 {
    const CONTRACT: &'static [u64] = &k::P384_CONTRACT;
    const P: &'static [u64] = &crate::p384::P;
    const MUL: Kernel = k::p384_mul;
    const LIN: Kernel = k::p384_lin;

    // The kernel's product is a b mod p; two Montgomery products, the
    // second by R^2, make the word loop's and the MULX code's that too.
    fn mul_word_loop(a: &[u64], b: &[u64]) -> std::vec::Vec<u64> {
        let p = crate::p384::P;
        let x = generic_mm(a.try_into().unwrap(), b.try_into().unwrap(), p);
        generic_mm(x, compute_r2(p), p).to_vec()
    }
    fn mul_mulx(a: &[u64], b: &[u64]) -> std::vec::Vec<u64> {
        use crate::p384::Fp;
        let x = Fp(a.try_into().unwrap()).mul(&Fp(b.try_into().unwrap()));
        x.mul(&Fp(compute_r2(crate::p384::P))).0.to_vec()
    }
    fn reduced(limbs: &[u64]) -> std::vec::Vec<u64> {
        reduce::<7, 4>(pack48(limbs.try_into().unwrap()), &crate::p384::P)[..6].to_vec()
    }
}

/// `a + b` modulo p, on reduced words, the plain way.
fn add_mod(a: &[u64], b: &[u64], p: &[u64]) -> std::vec::Vec<u64> {
    let n = p.len();
    let mut s = std::vec![0u64; n + 1];
    let mut c = 0u128;
    for i in 0..n {
        let x = u128::from(a[i]) + u128::from(b[i]) + c;
        s[i] = x as u64;
        c = x >> 64;
    }
    s[n] = c as u64;
    let mut pp = p.to_vec();
    pp.push(0);
    let ge = s
        .iter()
        .rev()
        .zip(pp.iter().rev())
        .find(|(x, y)| x != y)
        .is_none_or(|(x, y)| x > y);
    if ge {
        s = sub_words(&s, &pp);
    }
    s.truncate(n);
    s
}

/// `a - b` modulo p, on reduced words.
fn sub_mod(a: &[u64], b: &[u64], p: &[u64]) -> std::vec::Vec<u64> {
    add_mod(a, &sub_words(p, b), p)
}

fn sub_words(a: &[u64], b: &[u64]) -> std::vec::Vec<u64> {
    let mut out = std::vec![0u64; a.len()];
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (x, b1) = a[i].overflowing_sub(b[i]);
        let (x, b2) = x.overflowing_sub(borrow);
        out[i] = x;
        borrow = u64::from(b1 | b2);
    }
    out
}

/// A random lane vector inside the contract; with `edges`, each lane at an
/// edge of it: every limb at its largest, every limb zero, or a mix.
fn lane_vector<C: TestCurve>(rng: &mut Rng, edges: bool) -> C::V {
    let mut v = C::V::zero();
    for lane in 0..4 {
        let pick = if edges { rng.next() % 4 } else { 3 };
        let limbs: std::vec::Vec<u64> = C::CONTRACT
            .iter()
            .map(|&max| match pick {
                0 => max,
                1 => 0,
                2 => [0, max, max / 2, 1][(rng.next() % 4) as usize],
                _ => rng.next() % (max + 1),
            })
            .collect();
        v.set(lane, &limbs);
    }
    v
}

fn limbs_of_lane<C: TestCurve>(v: &C::V, l: usize) -> std::vec::Vec<u64> {
    let mut out = std::vec![0u64; C::LIMBS];
    v.get(l, &mut out);
    out
}

fn check_limbs<C: TestCurve>(v: &C::V, what: &str) {
    for l in 0..4 {
        for (x, max) in limbs_of_lane::<C>(v, l).iter().zip(C::CONTRACT) {
            assert!(x <= max, "{what}: a limb outside the contract");
        }
    }
}

/// The product and linear-combination kernels, lane by lane, against the
/// generic word loop and the MULX code: `iters` calls of four lanes each.
fn field_kernels<C: TestCurve>(iters: usize, seed: u64) -> usize {
    let Some(t) = token() else { return 0 };
    let mut rng = Rng(seed);
    let mut s = C::S::zero();
    let mut checked = 0;
    for i in 0..iters {
        let a = lane_vector::<C>(&mut rng, i % 8 == 0);
        let b = lane_vector::<C>(&mut rng, i % 8 == 1);
        let mut o = C::V::zero();
        // SAFETY: two lane vectors in, one out, test kernels of this curve.
        unsafe { run::<C>(t, C::MUL, a.ptr(), b.ptr(), &NONE, o.mut_ptr(), &mut s) };
        check_limbs::<C>(&o, "mul");
        let mut l2 = C::V::zero();
        // SAFETY: as above.
        unsafe { run::<C>(t, C::LIN, a.ptr(), b.ptr(), &NONE, l2.mut_ptr(), &mut s) };
        check_limbs::<C>(&l2, "lin");
        let p = C::P;
        for l in 0..4 {
            let (x, y) = (
                C::reduced(&limbs_of_lane::<C>(&a, l)),
                C::reduced(&limbs_of_lane::<C>(&b, l)),
            );
            let got = C::reduced(&limbs_of_lane::<C>(&o, l));
            assert_eq!(got, C::mul_word_loop(&x, &y), "mul against the word loop");
            assert_eq!(got, C::mul_mulx(&x, &y), "mul against MULX");
            // (a0 - b0, a1 + b1, 3 a2 - 8 b2, b3 - a3), lane by lane.
            let want = match l {
                0 => sub_mod(&x, &y, p),
                1 => add_mod(&x, &y, p),
                2 => {
                    let x3 = add_mod(&add_mod(&x, &x, p), &x, p);
                    let mut y8 = y.clone();
                    for _ in 0..3 {
                        y8 = add_mod(&y8, &y8, p);
                    }
                    sub_mod(&x3, &y8, p)
                }
                _ => sub_mod(&y, &x, p),
            };
            assert_eq!(
                C::reduced(&limbs_of_lane::<C>(&l2, l)),
                want,
                "lin lane {l}"
            );
            checked += 1;
        }
    }
    checked
}

/// Lane integers at the edges, as words: 0, 1, 2, p - 2, p - 1, p, p + 1,
/// 2p - 1, 2p, the `Fp` width's all-ones and the power of two above it, and
/// the contract's largest value, each kept where the contract holds it.
fn edge_values<C: TestCurve>() -> std::vec::Vec<std::vec::Vec<u64>> {
    let words = C::P.len() + 1;
    let word = |v: u64| {
        let mut w = std::vec![0u64; words];
        w[0] = v;
        w
    };
    let add = |a: &[u64], b: &[u64]| {
        let mut out = std::vec![0u64; words];
        let mut c = 0u128;
        for i in 0..words {
            let x = u128::from(a[i]) + u128::from(b[i]) + c;
            out[i] = x as u64;
            c = x >> 64;
        }
        out
    };
    let mut p = C::P.to_vec();
    p.push(0);
    let width = 64 * C::P.len();
    let mut ones = std::vec![u64::MAX; C::P.len()];
    ones.push(0);
    let mut top = std::vec![0u64; words];
    top[width / 64] = 1;
    let two_p = add(&p, &p);
    let mut out = std::vec![
        word(0),
        word(1),
        word(2),
        sub_words(&p, &word(2)),
        sub_words(&p, &word(1)),
        p.clone(),
        add(&p, &word(1)),
        sub_words(&two_p, &word(1)),
        two_p,
        ones,
        top,
    ];
    // The contract's largest value, limb by limb.
    let w = if C::LIMBS == 5 { 52 } else { 48 };
    let mut max = std::vec![0u64; words];
    for (k, &m) in C::CONTRACT.iter().enumerate() {
        let mut limb = std::vec![0u64; words];
        let (q, r) = (w * k / 64, w * k % 64);
        let wide = u128::from(m) << r;
        limb[q] = wide as u64;
        if q + 1 < words {
            limb[q + 1] = (wide >> 64) as u64;
        }
        max = add(&max, &limb);
    }
    out.push(max);
    out
}

/// A value's lane limbs, if the contract can hold it: limb `k` the bits
/// from `width k`, the top one the rest.
fn split<C: TestCurve>(v: &[u64]) -> Option<std::vec::Vec<u64>> {
    let w = if C::LIMBS == 5 { 52 } else { 48 };
    let bit = |i: usize| (v[i / 64] >> (i % 64)) & 1;
    let total = 64 * v.len();
    let mut limbs = std::vec![0u64; C::LIMBS];
    for (k, limb) in limbs.iter_mut().enumerate() {
        let end = if k + 1 == C::LIMBS {
            total
        } else {
            w * (k + 1)
        };
        for i in (w * k..end).rev() {
            if *limb >> 63 != 0 {
                return None;
            }
            *limb = (*limb << 1) | bit(i);
        }
    }
    limbs
        .iter()
        .zip(C::CONTRACT)
        .all(|(x, m)| x <= m)
        .then_some(limbs)
}

/// Every pair of edge values through the product and the combinations,
/// four pairs at a time, against the word loop and the MULX code.
fn field_edges<C: TestCurve>() -> usize {
    let Some(t) = token() else { return 0 };
    let values: std::vec::Vec<_> = edge_values::<C>()
        .iter()
        .filter_map(|v| split::<C>(v))
        .collect();
    let pairs: std::vec::Vec<_> = values
        .iter()
        .flat_map(|a| values.iter().map(move |b| (a, b)))
        .collect();
    let mut s = C::S::zero();
    let mut checked = 0;
    for chunk in pairs.chunks(4) {
        let (mut a, mut b) = (C::V::zero(), C::V::zero());
        for (lane, (x, y)) in chunk.iter().enumerate() {
            a.set(lane, x);
            b.set(lane, y);
        }
        let (mut o, mut l2) = (C::V::zero(), C::V::zero());
        // SAFETY: two lane vectors in, one out, test kernels of this curve.
        unsafe {
            run::<C>(t, C::MUL, a.ptr(), b.ptr(), &NONE, o.mut_ptr(), &mut s);
            run::<C>(t, C::LIN, a.ptr(), b.ptr(), &NONE, l2.mut_ptr(), &mut s);
        }
        check_limbs::<C>(&o, "mul");
        check_limbs::<C>(&l2, "lin");
        for lane in 0..chunk.len() {
            let x = C::reduced(&limbs_of_lane::<C>(&a, lane));
            let y = C::reduced(&limbs_of_lane::<C>(&b, lane));
            let got = C::reduced(&limbs_of_lane::<C>(&o, lane));
            assert_eq!(
                got,
                C::mul_word_loop(&x, &y),
                "edge mul against the word loop"
            );
            assert_eq!(got, C::mul_mulx(&x, &y), "edge mul against MULX");
            let p = C::P;
            let want = match lane {
                0 => sub_mod(&x, &y, p),
                1 => add_mod(&x, &y, p),
                2 => {
                    let x3 = add_mod(&add_mod(&x, &x, p), &x, p);
                    let mut y8 = y.clone();
                    for _ in 0..3 {
                        y8 = add_mod(&y8, &y8, p);
                    }
                    sub_mod(&x3, &y8, p)
                }
                _ => sub_mod(&y, &x, p),
            };
            assert_eq!(
                C::reduced(&limbs_of_lane::<C>(&l2, lane)),
                want,
                "edge lin lane {lane}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 100, "only {checked} edge pairs");
    checked
}

#[test]
fn field_kernels_agree_on_every_pair_of_edge_values() {
    let n = field_edges::<P256>() + field_edges::<P384>();
    std::println!("{n} edge pairs compared");
}

#[test]
fn p256_field_kernels_agree_with_the_word_loop_and_mulx() {
    let n = field_kernels::<P256>(count(1 << 20, 1 << 12), 1);
    std::println!("P-256: {n} products and combinations compared");
}

#[test]
fn p384_field_kernels_agree_with_the_word_loop_and_mulx() {
    let n = field_kernels::<P384>(count(1 << 19, 1 << 11), 2);
    std::println!("P-384: {n} products and combinations compared");
}

/// A random field element, or now and then 0, 1, p - 1 or p - 2.
fn element<C: TestCurve>(rng: &mut Rng) -> C::Field {
    match rng.next() % 16 {
        0 => C::Field::ZERO,
        1 => C::Field::ONE,
        2 => C::Field::ONE.neg(),
        3 => C::Field::ONE.double().neg(),
        _ => {
            let mut b = C::Field::zero_bytes();
            for x in b.as_mut() {
                *x = rng.next() as u8;
            }
            C::Field::from_bytes_reduced(&b)
        }
    }
}

fn arbitrary_point<C: TestCurve>(rng: &mut Rng) -> Point<C> {
    Point::from_coordinates(element::<C>(rng), element::<C>(rng), element::<C>(rng))
}

fn same<C: Curve>(a: &Point<C>, b: &Point<C>) -> bool {
    a.x() == b.x() && a.y() == b.y() && a.z() == b.z()
}

/// Every point kernel against the `Fp` formula it implements, on arbitrary
/// coordinates (the formulas are polynomials; nothing needs a curve point)
/// with 0, 1, p - 1 and p - 2 mixed in, coordinate for coordinate after the
/// round trip through the `Fp` form, under every mask.
fn point_kernels<C: TestCurve>(iters: usize, seed: u64) -> usize {
    let Some(t) = token() else { return 0 };
    let mut rng = Rng(seed);
    let mut s = C::S::zero();
    let mut checked = 0;
    for _ in 0..iters {
        let p = arbitrary_point::<C>(&mut rng);
        let q = arbitrary_point::<C>(&mut rng);
        let (lp, lq) = (load(t, &p, &mut s), load(t, &q, &mut s));
        assert!(same(&store(t, &lp, &mut s), &p), "round trip");
        let mut o = C::V::zero();
        // SAFETY: lane vectors of this curve, one out.
        unsafe {
            run::<C>(
                t,
                C::DOUBLE,
                lp.ptr(),
                core::ptr::null(),
                &NONE,
                o.mut_ptr(),
                &mut s,
            )
        };
        assert!(same(&store(t, &o, &mut s), &p.double_formula()), "double");
        let all = u64::MAX;
        for (m, want) in [
            ([0, 0, 0], p.add_formula_generic(&q).0),
            ([all, 0, 0], p.add_formula_generic(&q.neg()).0),
            ([0, all, 0], p),
            ([all, all, all], p),
            ([0, 0, all], q),
            ([all, 0, all], q.neg()),
        ] {
            // SAFETY: as above.
            unsafe { run::<C>(t, C::ADD, lp.ptr(), lq.ptr(), &m, o.mut_ptr(), &mut s) };
            assert!(same(&store(t, &o, &mut s), &want), "add, masks {m:?}");
        }
        let (x, y) = (q.x(), q.y());
        let mut lop = C::V::zero();
        operand::<C>(&x, &y, &mut lop);
        let lifted = Point::from_coordinates(x, y, C::Field::ONE);
        let neg = Point::from_coordinates(x, y.neg(), C::Field::ONE);
        for (m, want) in [
            ([0, 0, 0], p.add_affine_formula_generic(&x, &y).0),
            ([all, 0, 0], p.add_affine_formula_generic(&x, &y.neg()).0),
            ([0, all, 0], p),
            ([0, all, all], p),
            ([0, 0, all], lifted),
            ([all, 0, all], neg),
        ] {
            // SAFETY: as above.
            unsafe { run::<C>(t, C::MADD, lp.ptr(), lop.ptr(), &m, o.mut_ptr(), &mut s) };
            assert!(same(&store(t, &o, &mut s), &want), "madd, masks {m:?}");
        }
        checked += 1;
    }
    checked
}

/// The four-lane mixed addition against four of the `Fp` formula, a random
/// mask per lane.
fn madd4_kernel<C: TestCurve>(iters: usize, seed: u64) -> usize {
    let Some(t) = token() else { return 0 };
    let mut rng = Rng(seed);
    let mut s = C::S::zero();
    let mut checked = 0;
    for _ in 0..iters {
        let ps: [Point<C>; 4] = core::array::from_fn(|_| arbitrary_point::<C>(&mut rng));
        let qs: [(C::Field, C::Field); 4] =
            core::array::from_fn(|_| (element::<C>(&mut rng), element::<C>(&mut rng)));
        let mut a = [C::V::zero(); 3];
        let mut q = [C::V::zero(); 2];
        let mut masks = [[0u64; 4]; 3];
        for lane in 0..4 {
            let l = load(t, &ps[lane], &mut s);
            for (k, v) in a.iter_mut().enumerate() {
                v.set(lane, &limbs_of_lane::<C>(&l, k));
            }
            let mut op = C::V::zero();
            operand::<C>(&qs[lane].0, &qs[lane].1, &mut op);
            q[0].set(lane, &limbs_of_lane::<C>(&op, 0));
            q[1].set(lane, &limbs_of_lane::<C>(&op, 1));
            for m in masks.iter_mut() {
                m[lane] = (rng.next() & 1).wrapping_neg();
            }
        }
        let mut o = [C::V::zero(); 3];
        // SAFETY: three lane vectors and two in, three out, twelve words of
        // masks.
        unsafe {
            run::<C>(
                t,
                C::MADD4,
                a.as_ptr().cast(),
                q.as_ptr().cast(),
                masks.as_flattened(),
                o.as_mut_ptr().cast(),
                &mut s,
            )
        };
        let mut f = [C::V::zero(); 3];
        // SAFETY: as above.
        unsafe {
            run::<C>(
                t,
                C::TO_FP4,
                o.as_ptr().cast(),
                core::ptr::null(),
                &NONE,
                f.as_mut_ptr().cast(),
                &mut s,
            )
        };
        for lane in 0..4 {
            let c: std::vec::Vec<C::Field> = f
                .iter()
                .map(|v| C::from_limbs(&limbs_of_lane::<C>(v, lane)))
                .collect();
            let got = Point::from_coordinates(c[0], c[1], c[2]);
            let (x, y) = qs[lane];
            let y = if masks[0][lane] != 0 { y.neg() } else { y };
            let want = if masks[1][lane] != 0 {
                ps[lane]
            } else if masks[2][lane] != 0 {
                Point::from_coordinates(x, y, C::Field::ONE)
            } else {
                ps[lane].add_affine_formula_generic(&x, &y).0
            };
            assert!(same(&got, &want), "madd4 lane {lane}");
            checked += 1;
        }
    }
    checked
}

#[test]
fn p256_point_kernels_agree_with_the_formulas() {
    let n = point_kernels::<P256>(count(50_000, 2_000), 3)
        + madd4_kernel::<P256>(count(12_500, 500), 4);
    std::println!("P-256: {n} point operations compared");
}

#[test]
fn p384_point_kernels_agree_with_the_formulas() {
    let n =
        point_kernels::<P384>(count(20_000, 1_000), 5) + madd4_kernel::<P384>(count(5_000, 250), 6);
    std::println!("P-384: {n} point operations compared");
}

/// Scalars at the edges of the recodings and of the order, then random
/// ones: 0 .. 40, n - 40 .. n - 1, every byte one value, and powers of two.
fn scalars<C: TestCurve>(random: usize, seed: u64) -> std::vec::Vec<C::Scalar> {
    let mut out = std::vec::Vec::new();
    let mut k = C::Scalar::ZERO;
    let mut m = C::Scalar::ZERO;
    for _ in 0..=40 {
        out.push(k);
        out.push(m);
        k = k.add(&C::Scalar::ONE);
        m = m.sub(&C::Scalar::ONE);
    }
    for fill in [
        0x01u8, 0x0f, 0x10, 0x1f, 0x20, 0x55, 0x77, 0x7f, 0x80, 0x88, 0xaa, 0xf0, 0xff,
    ] {
        let mut b = C::Scalar::zero_bytes();
        for x in b.as_mut() {
            *x = fill;
        }
        out.push(C::Scalar::from_bytes_reduced(&b));
    }
    let mut two = C::Scalar::ONE;
    for _ in 0..8 * C::SCALAR_BYTES {
        out.push(two);
        two = two.double();
    }
    let mut rng = Rng(seed);
    for _ in 0..random {
        let mut b = C::Scalar::zero_bytes();
        for x in b.as_mut() {
            *x = rng.next() as u8;
        }
        out.push(C::Scalar::from_bytes_reduced(&b));
    }
    out
}

/// The three multiplications against their `Fp` counterparts: `mul_scalar`
/// on the generator, another point and the identity; the comb of a point;
/// the generator table.
fn multiplications<C: TestCurve>(random: usize, seed: u64) -> usize {
    let Some(t) = token() else { return 0 };
    let g = Point::<C>::generator();
    let mut b = C::Scalar::zero_bytes();
    let last = b.as_ref().len() - 1;
    b.as_mut()[last] = 7;
    let p = g.mul_scalar_generic(&C::Scalar::from_bytes_reduced(&b));
    let comb = Comb::new(&p);
    C::prepare_generator_table();
    let mut checked = 0;
    for k in scalars::<C>(random, seed) {
        for base in [g, p, Point::identity()] {
            let want = base.mul_scalar_generic(&k);
            assert!(
                bool::from(mul_scalar(t, &base, &k).ct_eq(&want)),
                "mul_scalar"
            );
        }
        assert!(
            bool::from(comb_mul(t, comb.windows(), &k).ct_eq(&comb.mul_generic(&k))),
            "comb"
        );
        assert!(
            bool::from(Point::<C>::mul_generator(&k).ct_eq(&C::table_mul_generic_for_tests(&k))),
            "table"
        );
        checked += 1;
    }
    checked
}

/// Each multiplication clears the vector registers once, after its last
/// kernel: one `Cleared` dropped per call, whichever of the three. With the
/// guard deleted from one of them, its count is zero and this fails. That
/// the drop's `vzeroall` zeroes every register the kernels name is
/// `scripts/check-ct.py`'s to check, on the compiled probes.
fn clears<C: TestCurve>() {
    let Some(t) = token() else { return };
    let g = Point::<C>::generator();
    let k = C::Scalar::ONE.add(&C::Scalar::ONE).add(&C::Scalar::ONE);
    let comb = Comb::new(&g);
    C::prepare_generator_table();
    cleared_probe::take();
    mul_scalar(t, &g, &k);
    assert_eq!(cleared_probe::take(), 1, "mul_scalar");
    comb_mul(t, comb.windows(), &k);
    assert_eq!(cleared_probe::take(), 1, "comb_mul");
    Point::<C>::mul_generator(&k);
    assert_eq!(cleared_probe::take(), 1, "table_mul");
}

#[test]
fn each_multiplication_clears_the_vector_registers() {
    clears::<P256>();
    clears::<P384>();
}

#[test]
fn p256_multiplications_agree_with_the_fp_form() {
    let n = multiplications::<P256>(count(1_000, 50), 7);
    std::println!("P-256: {n} scalars through every multiplication");
}

#[test]
fn p384_multiplications_agree_with_the_fp_form() {
    let n = multiplications::<P384>(count(400, 20), 8);
    std::println!("P-384: {n} scalars through every multiplication");
}

/// Where the CPU has IFMA, the report says so and the curves' hooks take
/// this path, or every comparison above could be the MULX path against
/// itself; where it does not, neither does.
#[test]
fn the_report_names_the_path_that_runs() {
    use crate::nist::point::Curve;
    let backend = crate::nist_backend();
    std::eprintln!("NIST backend on this CPU: {backend:?}");
    let g = Point::<P256>::generator();
    let k = <P256 as Curve>::Scalar::ONE;
    let fast = <P256 as Curve>::mul_scalar_fast(&g, &k);
    match Ifma::get() {
        Some(_) => {
            assert_eq!(backend, crate::NistBackend::Ifma);
            assert!(fast.is_some_and(|p| bool::from(p.ct_eq(&g))));
            let h = Point::<P384>::generator();
            let fast = <P384 as Curve>::mul_scalar_fast(&h, &<P384 as Curve>::Scalar::ONE);
            assert!(fast.is_some_and(|p| bool::from(p.ct_eq(&h))));
        }
        None => {
            assert_ne!(backend, crate::NistBackend::Ifma);
            // Without IFMA the hook is the MULX/ADX loop where the CPU has
            // BMI2 and ADX (`p256_x86::mul_scalar`), and absent otherwise.
            if backend == crate::NistBackend::MulxAdx {
                assert!(fast.is_some_and(|p| bool::from(p.ct_eq(&g))));
                let h = Point::<P384>::generator();
                let fast = <P384 as Curve>::mul_scalar_fast(&h, &<P384 as Curve>::Scalar::ONE);
                assert!(fast.is_some_and(|p| bool::from(p.ct_eq(&h))));
            } else {
                assert!(fast.is_none());
            }
        }
    }
}

/// Rounds of each pair: `IC_ROUNDS`, or 25.
fn rounds() -> usize {
    std::env::var("IC_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25)
}

/// The two closures alternately, `rounds` times, `iters` calls each time;
/// the least time per call of each, which a loaded machine disturbs least.
fn pair(label: &str, iters: u32, a: &mut dyn FnMut(), b: &mut dyn FnMut()) {
    use std::time::Instant;
    let (mut ta, mut tb) = (f64::INFINITY, f64::INFINITY);
    for _ in 0..rounds() {
        let s = Instant::now();
        for _ in 0..iters {
            a();
        }
        ta = ta.min(s.elapsed().as_secs_f64() * 1e9 / f64::from(iters));
        let s = Instant::now();
        for _ in 0..iters {
            b();
        }
        tb = tb.min(s.elapsed().as_secs_f64() * 1e9 / f64::from(iters));
    }
    std::println!(
        "{label:36} ifma {ta:10.1} ns   fp {tb:10.1} ns   {:.2}x",
        tb / ta
    );
}

fn time<C: TestCurve>(name: &str) {
    use std::hint::black_box;
    let Some(t) = token() else { return };
    let mut b = C::Scalar::zero_bytes();
    for (i, x) in b.as_mut().iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let k = C::Scalar::from_bytes_reduced(&b);
    let p = Point::<C>::generator().double().double();
    let p = p.to_affine().map(|a| Point::from_affine(&a)).unwrap();
    std::println!("{name}");
    pair(
        "mul_scalar",
        10,
        &mut || {
            black_box(mul_scalar(t, black_box(&p), black_box(&k)));
        },
        &mut || {
            black_box(black_box(&p).mul_scalar_generic(black_box(&k)));
        },
    );
    let comb = Comb::new(&p);
    pair(
        "comb",
        20,
        &mut || {
            black_box(comb_mul(t, comb.windows(), black_box(&k)));
        },
        &mut || {
            black_box(comb.mul_generic(black_box(&k)));
        },
    );
    C::prepare_generator_table();
    pair(
        "generator table",
        40,
        &mut || {
            black_box(Point::<C>::mul_generator(black_box(&k)));
        },
        &mut || {
            black_box(C::table_mul_generic_for_tests(black_box(&k)));
        },
    );
    let mut s = C::S::zero();
    {
        // The table multiplication's parts: its scans, and its kernels.
        let digits = [3i8, -7, 1, 0, 15, -16, 9, 2];
        pair(
            "42 table scans / 11 madd4 kernels",
            40,
            &mut || {
                for i in 0..42 {
                    black_box(C::table_select_for_tests(i % 40, digits[i % 8]));
                }
            },
            &mut || {
                let a = [C::V::zero(); 3];
                let q = [C::V::zero(); 2];
                let mut o = [C::V::zero(); 3];
                let masks = [[0u64; 4]; 3];
                for _ in 0..11 {
                    // SAFETY: lane vectors of this curve, twelve mask words.
                    unsafe {
                        run::<C>(
                            t,
                            C::MADD4,
                            black_box(&a).as_ptr().cast(),
                            q.as_ptr().cast(),
                            masks.as_flattened(),
                            o.as_mut_ptr().cast(),
                            &mut s,
                        )
                    };
                }
                black_box(&o);
            },
        );
    }
    let v = load(t, &p, &mut s);
    let mut acc = Pair::<C::V, 1>::new();
    let mut pf = p;
    pair(
        "five doublings, chained",
        400,
        &mut || {
            doublings::<C>(t, &mut acc, &mut s);
        },
        &mut || {
            for _ in 0..WIDTH {
                pf = pf.double();
            }
        },
    );
    black_box((acc.cur(), &pf));
    let mut o = C::V::zero();
    pair(
        "add, independent",
        2_000,
        &mut || {
            // SAFETY: lane vectors of this curve.
            unsafe {
                run::<C>(
                    t,
                    C::ADD,
                    black_box(&v).ptr(),
                    v.ptr(),
                    &NONE,
                    o.mut_ptr(),
                    &mut s,
                )
            };
        },
        &mut || {
            black_box(black_box(&p).add_unequal(&p));
        },
    );
}

#[test]
#[ignore = "timing; run with --release --ignored --nocapture"]
fn where_the_time_goes() {
    let which = std::env::var("IC_CURVE").unwrap_or_default();
    if which != "p384" {
        time::<P256>("P-256");
    }
    if which != "p256" {
        time::<P384>("P-384");
    }
}
