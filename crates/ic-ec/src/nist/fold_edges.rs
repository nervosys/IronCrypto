//! Inputs that take each path through the fused `cm * a - dm * b`
//! operations' fold, for the tests of P-256's and P-384's assembly.
//!
//! The operations compute `V = cm * a + dm * (p - b)` as words `v` and a top
//! word `t`, add `(t + 1)(2^bits - p)` to `v`, and keep the sum where that
//! carries out of the top word or add p back where it does not. The carry
//! needs `v` within `(t + 1)(2^bits - p)` of `2^bits`: about once in 2^27
//! random inputs on P-256 and never in practice on P-384, where
//! `2^384 - p` is 129 bits. So the inputs are built: `V` is chosen as
//! `t * 2^bits + 2^bits - delta` for `delta` on both sides of the bound, `a`
//! near `(V - dm * p / 2) / cm`, moved so that `dm` divides `V - cm * a`, and
//! `b = p - (V - cm * a) / dm`. Integers here are little-endian word vectors.

use std::vec;
use std::vec::Vec;

fn trim(mut x: Vec<u64>) -> Vec<u64> {
    while x.len() > 1 && *x.last().unwrap() == 0 {
        x.pop();
    }
    x
}

fn cmp(a: &[u64], b: &[u64]) -> core::cmp::Ordering {
    let (a, b) = (trim(a.to_vec()), trim(b.to_vec()));
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn add(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len().max(b.len()) + 1;
    let mut out = vec![0u64; n];
    let mut carry = 0u128;
    for (i, o) in out.iter_mut().enumerate() {
        let s = carry + *a.get(i).unwrap_or(&0) as u128 + *b.get(i).unwrap_or(&0) as u128;
        *o = s as u64;
        carry = s >> 64;
    }
    trim(out)
}

/// `a - b`, for `a >= b`.
fn sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert!(cmp(a, b) != core::cmp::Ordering::Less);
    let mut out = a.to_vec();
    let mut borrow = 0i128;
    for (i, o) in out.iter_mut().enumerate() {
        let d = *o as i128 - *b.get(i).unwrap_or(&0) as i128 - borrow;
        *o = d as u64;
        borrow = i128::from(d < 0);
    }
    trim(out)
}

fn mul_small(a: &[u64], k: u64) -> Vec<u64> {
    let mut out = vec![0u64; a.len() + 1];
    let mut carry = 0u128;
    for (i, w) in a.iter().enumerate() {
        let s = *w as u128 * k as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    out[a.len()] = carry as u64;
    trim(out)
}

/// `(a / k, a % k)`.
fn div_small(a: &[u64], k: u64) -> (Vec<u64>, u64) {
    let mut out = vec![0u64; a.len()];
    let mut rem = 0u128;
    for i in (0..a.len()).rev() {
        let cur = (rem << 64) | a[i] as u128;
        out[i] = (cur / k as u128) as u64;
        rem = cur % k as u128;
    }
    (trim(out), rem as u64)
}

fn pow2(bits: usize) -> Vec<u64> {
    let mut out = vec![0u64; bits / 64 + 1];
    out[bits / 64] = 1 << (bits % 64);
    out
}

/// `(a, b)`, each below `p` and as `p.len()` words, for which the fold of
/// `cm * a - dm * b` carries out of the top word, or just fails to, for every
/// top word the construction reaches.
pub(crate) fn cases(p: &[u64], cm: u64, dm: u64) -> Vec<(Vec<u64>, Vec<u64>, bool)> {
    let bits = 64 * p.len();
    let k = sub(&pow2(bits), p);
    let mut out = Vec::new();
    for t in 0..cm + dm {
        let bound = mul_small(&k, t + 1);
        let one = vec![1u64];
        for (delta, carries) in [
            (vec![1u64], true),
            (vec![2u64], true),
            (vec![0x1234_5678_9abc_def1u64], true),
            (sub(&bound, &one), true),
            (bound.clone(), true),
            (add(&bound, &one), false),
            (add(&bound, &[2u64]), false),
        ] {
            // V = t * 2^bits + 2^bits - delta.
            let v = sub(&add(&mul_small(&pow2(bits), t), &pow2(bits)), &delta);
            let half = mul_small(&div_small(p, 2).0, dm);
            if cmp(&v, &half) == core::cmp::Ordering::Less {
                continue;
            }
            let (mut a, _) = div_small(&sub(&v, &half), cm);
            // Move a down until dm divides V - cm * a.
            let mut found = false;
            for _ in 0..dm {
                let ca = mul_small(&a, cm);
                if cmp(&ca, &v) != core::cmp::Ordering::Greater
                    && div_small(&sub(&v, &ca), dm).1 == 0
                {
                    found = true;
                    break;
                }
                if a == [0] {
                    break;
                }
                a = sub(&a, &one);
            }
            if !found || cmp(&a, p) != core::cmp::Ordering::Less {
                continue;
            }
            let (n, _) = div_small(&sub(&v, &mul_small(&a, cm)), dm);
            if n == [0] || cmp(&n, p) == core::cmp::Ordering::Greater {
                continue;
            }
            let b = sub(p, &n);
            let mut aw = a.clone();
            let mut bw = b.clone();
            aw.resize(p.len(), 0);
            bw.resize(p.len(), 0);
            out.push((aw, bw, carries));
        }
    }
    out
}
