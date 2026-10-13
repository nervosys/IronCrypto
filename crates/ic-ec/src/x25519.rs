//! RFC 7748 X25519 key agreement.

use crate::field_ops::Field;
use ic_core::traits::{Algorithm, KeyAgreement, SelfTest};
use ic_core::{ensure, Result};

/// The RFC 7748 base point, `u = 9`.
const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// X25519, the Diffie-Hellman function on Curve25519.
pub struct X25519;

impl Algorithm for X25519 {
    const ID: &'static str = "x25519";
    const NAME: &'static str = "X25519";
}

/// Apply the RFC 7748 clamping to a scalar.
///
/// Clearing the low three bits kills the small-order component; forcing bit 254
/// fixes the ladder length so timing does not reveal the scalar's magnitude.
fn clamp(scalar: &[u8], out: &mut [u8; 32]) {
    out.copy_from_slice(&scalar[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

/// The Montgomery ladder: compute `scalar * u`, on the fastest field this
/// CPU runs. See [`ladder_in`].
fn ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    // On the four-limb field each step is one assembly block, which is what
    // makes that field pay; see `fe64::ladder_step`. It computes what
    // `ladder_in` does, and the tests hold the two to the same answers.
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    {
        // Four lanes at a time on AVX-512 IFMA; see `f51x4`.
        if let Some(t) = crate::f51x4::Ifma::get() {
            return t.x25519_ladder(scalar, u);
        }
        if crate::fe64::available() {
            return crate::fe64::x25519_ladder(scalar, u);
        }
    }
    ladder_in::<crate::field::Fe>(scalar, u)
}

/// The Montgomery ladder over the field `F`.
///
/// RFC 7748's ladder with its conditional swaps taken out of the loop.
///
/// Each RFC step swaps the two points `(x2, z2)` and `(x3, z3)` on the
/// scalar bit, doubles the first and adds the two. The addition is symmetric
/// in its operands -- swapping them negates `DA - CB` and leaves `DA + CB`,
/// and the first is only ever squared -- so it does not need to know which
/// point is which. Only the doubling does. So this keeps the doubled point in
/// one slot (`n`) and the sum in the other (`m`) every step, and chooses the
/// doubling's input with one constant-time selection of its sum and
/// difference: two field-element selections a step where the RFC form makes
/// four swaps, and the addition's multiplications no longer wait for them.
///
/// Slot `n` always holds what the RFC calls `(x2, z2)` before its swap, and
/// `m` holds `(x3, z3)`; the RFC's swap flag says which of the two it then
/// doubles, and that is the selection here. The test
/// `the_ladder_agrees_with_the_rfc_form` compares this against the RFC's own
/// form, which is kept for that purpose.
///
/// The loop is fixed at 255 iterations and selects in constant time, so
/// neither the number of operations nor their operands depend on the scalar.
fn ladder_in<F: Field>(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = F::from_bytes(u);
    // The RFC's initial state: (x2, z2) = (1, 0) in n, (x3, z3) = (u, 1) in m.
    let (mut xn, mut zn) = (F::ONE, F::ZERO);
    let (mut xm, mut zm) = (x1, F::ONE);
    // The secret bits are carried as integers, 0 or 1, and turned into masks
    // only inside the field's `select_bit`, behind its barrier.
    let mut prev = 0u64;

    for pos in (0..255).rev() {
        let bit = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);
        let swap = bit ^ prev;
        prev = bit;

        let sm = xm.add(&zm);
        let dm = xm.sub(&zm);
        let sn = xn.add(&zn);
        let dn = xn.sub(&zn);

        // Addition, symmetric in m and n.
        let dmsn = dm.mul(&sn);
        let dnsm = sm.mul(&dn);

        // Doubling of whichever point the RFC would have swapped into
        // (x2, z2): n, or m when the swap flag is set.
        let s = F::select_bit(&sn, &sm, swap);
        let d = F::select_bit(&dn, &dm, swap);
        let ss = s.square();
        let dd = d.square();
        // E = AA - BB, and RFC 7748's E * (AA + 121665 * E) rewritten as
        // E * (BB + 121666 * E): the same value, since AA = BB + E.
        let e = ss.sub(&dd);
        xn = ss.mul(&dd);
        zn = e.mul(&dd.add(&e.mul121666()));

        xm = dmsn.add(&dnsm).square();
        zm = x1.mul(&dmsn.sub(&dnsm).square());
    }

    // The RFC's last swap: its (x2, z2) is n, or m when the final flag is set.
    let x = F::select_bit(&xn, &xm, prev);
    let z = F::select_bit(&zn, &zm, prev);
    x.mul(&z.invert()).to_bytes()
}

/// The field inversion X25519 ends with, on the field this CPU selects:
/// for `bench/` to separate it from the ladder. Not API.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn invert_for_bench(x: &[u8; 32]) -> [u8; 32] {
    fn inv<F: Field>(x: &[u8; 32]) -> [u8; 32] {
        F::from_bytes(x).invert().to_bytes()
    }
    crate::field_ops::dispatch!(inv(x))
}

/// RFC 7748 section 5's ladder exactly as written, with its swaps: the
/// reference [`ladder_in`] is compared against.
#[cfg(test)]
fn ladder_rfc_in<F: Field>(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = F::from_bytes(u);
    let mut x2 = F::ONE;
    let mut z2 = F::ZERO;
    let mut x3 = x1;
    let mut z3 = F::ONE;
    let mut swap = 0u64;

    for pos in (0..255).rev() {
        let bit = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);
        swap ^= bit;
        (x2, x3) = (F::select_bit(&x2, &x3, swap), F::select_bit(&x3, &x2, swap));
        (z2, z3) = (F::select_bit(&z2, &z3, swap), F::select_bit(&z3, &z2, swap));
        swap = bit;

        let a = x2.add(&z2);
        let b = x2.sub(&z2);
        let aa = a.square();
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&bb.add(&e.mul121666()));
    }

    let x2 = F::select_bit(&x2, &x3, swap);
    let z2 = F::select_bit(&z2, &z3, swap);
    x2.mul(&z2.invert()).to_bytes()
}

impl KeyAgreement for X25519 {
    const PRIVATE_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 32;
    const SHARED_SECRET_LEN: usize = 32;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(private_key.len() == 32, InvalidLength, "x25519 private key");
        ensure!(out.len() == 32, InvalidLength, "x25519 public key buffer");
        let mut k = [0u8; 32];
        clamp(private_key, &mut k);
        out.copy_from_slice(&ladder(&k, &BASEPOINT));
        Ok(())
    }

    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(private_key.len() == 32, InvalidLength, "x25519 private key");
        ensure!(
            peer_public_key.len() == 32,
            InvalidLength,
            "x25519 public key"
        );
        ensure!(
            out.len() == 32,
            InvalidLength,
            "x25519 shared secret buffer"
        );

        let mut k = [0u8; 32];
        clamp(private_key, &mut k);
        let mut u = [0u8; 32];
        u.copy_from_slice(peer_public_key);

        let shared = ladder(&k, &u);

        // RFC 7748 §6.1: an all-zero shared secret means the peer supplied a
        // small-order point. Rejecting it stops a peer from forcing a known
        // secret, which matters for any protocol that does not hash a
        // transcript over the public keys.
        ensure!(
            !bool::from(ic_core::ct::is_zero(&shared)),
            InvalidParameter,
            "x25519 peer public key has small order"
        );
        out.copy_from_slice(&shared);
        Ok(())
    }
}

impl SelfTest for X25519 {
    fn self_test() -> Result<()> {
        // RFC 7748 §6.1: Alice's key pair.
        let mut sk = [0u8; 32];
        ic_core::codec::hex_decode(
            b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            &mut sk,
        )?;
        let mut want = [0u8; 32];
        ic_core::codec::hex_decode(
            b"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            &mut want,
        )?;
        let mut got = [0u8; 32];
        <Self as KeyAgreement>::public_key(&sk, &mut got)?;
        ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, "x25519");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::{hex, unhex};

    /// RFC 7748 §5.2, first scalar-multiplication vector.
    #[test]
    fn rfc7748_scalar_mult_vector_1() {
        let k = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap();
        let u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();
        let mut sk = [0u8; 32];
        clamp(&k, &mut sk);
        let mut up = [0u8; 32];
        up.copy_from_slice(&u);
        assert_eq!(
            hex(&ladder(&sk, &up)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    /// RFC 7748 §5.2, second vector.
    #[test]
    fn rfc7748_scalar_mult_vector_2() {
        let k = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").unwrap();
        let u = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").unwrap();
        let mut sk = [0u8; 32];
        clamp(&k, &mut sk);
        let mut up = [0u8; 32];
        up.copy_from_slice(&u);
        assert_eq!(
            hex(&ladder(&sk, &up)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    /// RFC 7748 §6.1, the full Diffie-Hellman exchange.
    #[test]
    fn rfc7748_diffie_hellman() {
        let a_sk =
            unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let b_sk =
            unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap();

        let mut a_pk = [0u8; 32];
        let mut b_pk = [0u8; 32];
        X25519::public_key(&a_sk, &mut a_pk).unwrap();
        X25519::public_key(&b_sk, &mut b_pk).unwrap();
        assert_eq!(
            hex(&a_pk),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(&b_pk),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );

        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        X25519::agree(&a_sk, &b_pk, &mut s1).unwrap();
        X25519::agree(&b_sk, &a_pk, &mut s2).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(
            hex(&s1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn rejects_small_order_points() {
        let sk = [0x11u8; 32];
        let mut out = [0u8; 32];
        // The identity and the other RFC 7748 small-order points.
        for bad in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let pk = unhex(bad).unwrap();
            assert!(
                X25519::agree(&sk, &pk, &mut out).is_err(),
                "small-order point {bad} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mut out = [0u8; 32];
        assert!(X25519::public_key(&[0u8; 31], &mut out).is_err());
        assert!(X25519::public_key(&[0u8; 32], &mut out[..31]).is_err());
        assert!(X25519::agree(&[1u8; 32], &[0u8; 31], &mut out).is_err());
    }

    /// Clamping must be applied even when the caller passes an unclamped scalar,
    /// so two scalars differing only in the cleared bits agree.
    #[test]
    fn clamping_is_applied_to_caller_scalars() {
        let mut a = [0x42u8; 32];
        let mut b = a;
        a[0] |= 0x07;
        b[0] &= !0x07;
        a[31] |= 0x80;
        b[31] &= 0x7f;

        let mut pa = [0u8; 32];
        let mut pb = [0u8; 32];
        X25519::public_key(&a, &mut pa).unwrap();
        X25519::public_key(&b, &mut pb).unwrap();
        assert_eq!(pa, pb);
    }

    #[test]
    fn self_test_passes() {
        X25519::self_test().unwrap();
    }

    type Ladder = fn(&[u8; 32], &[u8; 32]) -> [u8; 32];

    /// Every ladder this build has: the one `ladder` dispatches to, the
    /// generic one on the portable field, the RFC's own form, and on x86-64
    /// the four-limb field's block ladder and the generic ladder on that field.
    fn ladders() -> std::vec::Vec<(&'static str, Ladder)> {
        let mut v: std::vec::Vec<(&'static str, Ladder)> = std::vec![
            ("dispatched", ladder),
            ("generic, portable field", ladder_in::<crate::field::Fe>),
            (
                "RFC form, portable field",
                ladder_rfc_in::<crate::field::Fe>
            ),
        ];
        #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
        if crate::fe64::available() {
            v.push(("block, four-limb field", crate::fe64::x25519_ladder));
            v.push(("generic, four-limb field", ladder_in::<crate::fe64::Fe64>));
        }
        #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
        if crate::f51x4::Ifma::get().is_some() {
            fn four_lane(s: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
                match crate::f51x4::Ifma::get() {
                    Some(t) => t.x25519_ladder(s, u),
                    None => unreachable!("checked above"),
                }
            }
            v.push(("four lanes, IFMA", four_lane));
        }
        v
    }

    /// RFC 7748 section 5.2's iterated test: `k = u = 9`, then repeatedly
    /// `(k, u) = (X25519(k, u), k)`. Checked after 1 and 1000 iterations,
    /// through every ladder: a thousand chained multiplications, each one's
    /// output the next one's scalar, so a single wrong carry anywhere
    /// diverges.
    #[test]
    fn rfc7748_iterated_vectors_through_every_ladder() {
        for (name, f) in ladders() {
            let mut k = [0u8; 32];
            k[0] = 9;
            let mut u = k;
            for i in 1..=1000 {
                let mut clamped = [0u8; 32];
                clamp(&k, &mut clamped);
                let r = f(&clamped, &u);
                u = k;
                k = r;
                if i == 1 {
                    assert_eq!(
                        hex(&k),
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                        "{name}, 1 iteration"
                    );
                }
            }
            assert_eq!(
                hex(&k),
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                "{name}, 1000 iterations"
            );
        }
    }

    /// All the ladders against each other on scalars and points from a
    /// counter: clamped and unclamped scalars, u with the top bit set (which
    /// is ignored), u at and above p, and the small-order points.
    #[test]
    fn the_ladders_agree() {
        use ic_core::traits::internal::Digest;
        let ladders = ladders();
        let mut special: std::vec::Vec<[u8; 32]> = std::vec![[0u8; 32], [0xffu8; 32]];
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        special.push(p); // p, non-canonical zero
        let mut p1 = p;
        p1[0] = 0xee;
        special.push(p1); // p + 1
        let mut one = [0u8; 32];
        one[0] = 1;
        special.push(one);
        let mut checked = 0;
        for i in 0u32..400 {
            let mut k = ic_hash::Sha256::digest(&i.to_le_bytes());
            if i % 2 == 0 {
                let raw = k;
                clamp(&raw, &mut k);
            }
            let u = if (i as usize) < special.len() {
                special[i as usize]
            } else {
                ic_hash::Sha256::digest(&(i ^ 0x8000_0000).to_le_bytes())
            };
            let want = ladder_rfc_in::<crate::field::Fe>(&k, &u);
            for (name, f) in &ladders {
                assert_eq!(f(&k, &u), want, "{name} differs for k={k:02x?} u={u:02x?}");
                checked += 1;
            }
        }
        assert!(checked >= 1200, "only {checked} comparisons");
    }

    /// On a CPU with BMI2 and ADX the dispatch must pick the four-limb
    /// field, or every vector above would be testing the fallback twice.
    #[test]
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    fn this_cpu_takes_the_fast_path() {
        use crate::Curve25519Backend as B;
        let backend = crate::curve25519_backend();
        if crate::fe64::available() {
            assert!(crate::field_ops::selected().ends_with("Fe64"));
        } else {
            assert!(crate::field_ops::selected().ends_with("field::Fe"));
        }
        let expect = match (crate::f51x4::Ifma::get(), crate::fe64::available()) {
            (Some(_), _) => B::Ifma,
            (None, true) => B::MulxAdx,
            (None, false) => B::Portable,
        };
        assert_eq!(backend, expect);
        // And the dispatched ladder is the one the report names: the same
        // answer as that backend's ladder called directly.
        let k = [0x5au8; 32];
        let u = [9u8; 32];
        let direct = match backend {
            B::Ifma => crate::f51x4::Ifma::get().map(|t| t.x25519_ladder(&k, &u)),
            B::MulxAdx => Some(crate::fe64::x25519_ladder(&k, &u)),
            B::Portable => Some(ladder_in::<crate::field::Fe>(&k, &u)),
        };
        assert_eq!(direct, Some(ladder(&k, &u)));
        std::eprintln!("curve25519 backend on this CPU: {backend:?}");
    }
}
