//! RFC 8032 Ed25519 signatures.
//!
//! Points use extended twisted Edwards coordinates `(X : Y : Z : T)` with
//! `a = -1`. Because `d` is a non-square in GF(2^255-19), the
//! `add-2008-hwcd-3` formula is *complete*: it is correct for every input pair,
//! including doubling and the identity. That is what lets scalar multiplication
//! be a single branch-free loop with no exceptional cases to special-case, and
//! no timing signal from the shape of the scalar.

use crate::field::Fe;
use crate::scalar;
use ic_core::ct::Choice;

// The precomputed basepoint table. See the module for why it is `std` only.
mod basepoint_table;
use ic_core::traits::{Algorithm, Digest, SelfTest, SignatureScheme};
use ic_core::{ensure, Result, Zeroize};
use ic_hash::Sha512;

/// The compressed encoding of the Ed25519 base point.
const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The curve constant `d = -121665/121666`, as 51-bit limbs.
const D: Fe = Fe([
    929_955_233_495_203,
    466_365_720_129_213,
    1_662_059_464_998_953,
    2_033_849_074_728_123,
    1_442_794_654_840_575,
]);

/// `2*d`, used directly by the addition formula.
const D2: Fe = Fe([
    1_859_910_466_990_425,
    932_731_440_258_426,
    1_072_319_116_312_658,
    1_815_898_335_770_999,
    633_789_495_995_903,
]);

/// A square root of -1 in GF(2^255-19), needed for point decompression.
const SQRT_M1: Fe = Fe([
    1_718_705_420_411_056,
    234_908_883_556_509,
    2_233_514_472_574_048,
    2_117_202_627_021_982,
    765_476_049_583_133,
]);

/// A point in extended twisted Edwards coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    /// The neutral element `(0, 1)`.
    pub const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The complete `add-2008-hwcd-3` group law for `a = -1`.
    pub fn add(&self, other: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let d = self.z.mul(&other.z);
        let d = d.add(&d);

        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Point doubling, `dbl-2008-hwcd` for `a = -1`.
    ///
    /// Adding a point to itself works and was what this did, but the general
    /// addition costs nine multiplications and needs both operands' `T`. The
    /// dedicated formula is four multiplications and four squarings, and does
    /// not read `T` at all -- doubling is a function of `X`, `Y` and `Z` alone.
    ///
    /// Worth the separate formula because scalar multiplication is doublings
    /// almost entirely: the non-adjacent form leaves about forty additions
    /// against two hundred and fifty-six doublings.
    pub fn double(&self) -> Point {
        let aa = self.x.square();
        let bb = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        // a = -1, so D = a*A = -A.
        let d = aa.neg();
        // E = (X+Y)^2 - A - B, which is 2*X*Y without a multiplication.
        let xy = self.x.add(&self.y);
        let e = xy.square().sub(&aa).sub(&bb);
        let g = d.add(&bb);
        let f = g.sub(&c);
        let h = d.sub(&bb);

        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Constant-time conditional move.
    /// Negate in place when `choice` is set.
    ///
    /// On a twisted Edwards curve `-(x, y, z, t)` is `(-x, y, z, -t)`, so this
    /// is two field negations and a pair of conditional moves. Used by the
    /// signed-digit basepoint table, which stores only positive multiples.
    fn conditional_negate(&mut self, choice: Choice) {
        let nx = self.x.neg();
        let nt = self.t.neg();
        Fe::cmov(&mut self.x, &nx, choice);
        Fe::cmov(&mut self.t, &nt, choice);
    }

    fn cmov(&mut self, other: &Point, choice: Choice) {
        Fe::cmov(&mut self.x, &other.x, choice);
        Fe::cmov(&mut self.y, &other.y, choice);
        Fe::cmov(&mut self.z, &other.z, choice);
        Fe::cmov(&mut self.t, &other.t, choice);
    }

    /// Scalar multiplication, constant-time in the scalar.
    ///
    /// Every iteration performs a doubling *and* an addition, selecting between
    /// the two results with a conditional move, so the instruction trace is
    /// identical for every scalar.
    pub fn mul_scalar(&self, s: &[u8; 32]) -> Point {
        let mut acc = Point::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            let sum = acc.add(self);
            let bit = Choice::from_u8((s[i / 8] >> (i % 8)) & 1);
            acc.cmov(&sum, bit);
        }
        acc
    }

    /// Negate: `-(x, y, z, t)` is `(-x, y, z, -t)`.
    fn negate(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Scalar multiplication that is **not** constant time.
    ///
    /// # When this is allowed
    ///
    /// Only on values an attacker already has. Verification is the case: the
    /// signature, the public key and the message are all public, so there is no
    /// secret whose timing could leak, and the constant-time ladder buys
    /// nothing there but work. Signing must never call this -- the scalar is
    /// derived from the seed.
    ///
    /// # What it does instead
    ///
    /// A width-5 non-adjacent form. Recoding the scalar into signed odd digits
    /// leaves roughly one position in six non-zero, so the additions drop from
    /// one per bit to about forty in total; the doublings remain, because an
    /// arbitrary point has no precomputed table to take them away. Only odd
    /// multiples are stored, eight of them, since a negative digit negates on
    /// the way out.
    ///
    /// The saving is real but bounded: the doublings dominate and they cannot
    /// be avoided here. The basepoint half of verification is the one that got
    /// a table.
    pub fn mul_scalar_vartime(&self, scalar: &[u8; 32]) -> Point {
        // 1P, 3P, 5P .. 15P.
        let twice = self.double();
        let mut odd = [*self; 8];
        for i in 1..8 {
            odd[i] = odd[i - 1].add(&twice);
        }

        let naf = wnaf5(scalar);
        let mut acc = Point::IDENTITY;
        for digit in naf.iter().rev() {
            acc = acc.double();
            if *digit != 0 {
                // digit is odd and in [-15, 15]; |digit|/2 indexes the table.
                let entry = &odd[(digit.unsigned_abs() as usize) / 2];
                acc = if *digit > 0 {
                    acc.add(entry)
                } else {
                    acc.add(&entry.negate())
                };
            }
        }
        acc
    }

    /// Compress to the 32-byte RFC 8032 encoding.
    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut out = y.to_bytes();
        // The sign of x rides in the top bit.
        out[31] |= x.is_negative().unwrap_u8() << 7;
        out
    }

    /// Decompress a 32-byte encoding, rejecting non-curve points.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let sign = Choice::from_u8(bytes[31] >> 7);
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = Fe::from_bytes(&y_bytes);

        // Solve x^2 = (y^2 - 1) / (d*y^2 + 1).
        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let v = y2.mul(&D).add(&Fe::ONE);

        // x = u*v^3 * (u*v^7)^((p-5)/8)
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow22523());

        let check = v.mul(&x.square());
        let correct = check.ct_eq(&u);
        let flipped = check.ct_eq(&u.neg());
        if !bool::from(correct.or(flipped)) {
            // No square root exists: the encoding is not a curve point.
            return None;
        }
        // When only the flipped case matched, multiply by sqrt(-1).
        let alt = x.mul(&SQRT_M1);
        Fe::cmov(&mut x, &alt, flipped.and(correct.not()));

        // x = 0 with a set sign bit is the one non-canonical encoding.
        if bool::from(x.is_zero()) && bool::from(sign) {
            return None;
        }
        // Match the requested sign.
        let neg = x.neg();
        let wrong_sign = Choice::from_u8(x.is_negative().unwrap_u8() ^ sign.unwrap_u8());
        Fe::cmov(&mut x, &neg, wrong_sign);

        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}

/// The Ed25519 base point.
/// `scalar * B`, through the precomputed table where there is one.
///
/// Every basepoint multiplication in this module goes through here rather than
/// calling `mul_scalar` on the basepoint directly, so the two paths cannot
/// drift apart and a caller cannot accidentally take the slow one.
fn mul_basepoint(scalar: &[u8; 32]) -> Point {
    #[cfg(feature = "std")]
    {
        basepoint_table::table().mul(scalar)
    }
    #[cfg(not(feature = "std"))]
    {
        basepoint().mul_scalar(scalar)
    }
}

fn basepoint() -> Point {
    // The encoding is a compile-time constant and is known to be valid, so the
    // decompression cannot fail.
    Point::decompress(&BASEPOINT_COMPRESSED).unwrap_or(Point::IDENTITY)
}

/// RFC 8032 Ed25519 (PureEdDSA over Curve25519 with SHA-512).
pub struct Ed25519;

impl Algorithm for Ed25519 {
    const ID: &'static str = "ed25519";
    const NAME: &'static str = "Ed25519";
}

/// Expand a 32-byte seed into the clamped scalar and the nonce prefix.
fn expand_seed(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&h.as_ref()[..32]);
    prefix.copy_from_slice(&h.as_ref()[32..]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    (a, prefix)
}

/// Width-5 non-adjacent form of a 256-bit scalar.
///
/// Each non-zero digit is odd and lies in `[-15, 15]`, and no two non-zero
/// digits are adjacent, which is what keeps the density near one in six. The
/// array has room to run past the top of the scalar.
///
/// Variable time by construction: the loop length and the digit pattern depend
/// on the scalar. See [`Point::mul_scalar_vartime`] for when that is allowed.
fn wnaf5(scalar: &[u8; 32]) -> [i8; 258] {
    let mut naf = [0i8; 258];
    // Five limbs for a four-limb scalar. A negative digit adds to `k`, and for
    // a scalar near 2^256 that carries out of the top: on four limbs it wraps
    // to zero, the loop stops early, and the representation is silently short.
    // The scalars that reach this are reduced modulo the group order and could
    // not trigger it -- which is exactly the assumption that was wrong for the
    // NIST recoding, so the room is given rather than argued for.
    let mut k = [0u64; 5];
    for (i, limb) in k.iter_mut().take(4).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&scalar[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(b);
    }

    let mut i = 0;
    while k.iter().any(|&x| x != 0) {
        if k[0] & 1 == 1 {
            let mut d = (k[0] & 0x1f) as i64;
            if d >= 16 {
                d -= 32;
            }
            naf[i] = d as i8;
            if d > 0 {
                sub_u64(&mut k, d as u64);
            } else {
                add_u64(&mut k, d.unsigned_abs());
            }
        }
        shr1(&mut k);
        i += 1;
    }
    naf
}

/// `k -= v`, for `v` small enough not to borrow past the top.
fn sub_u64(k: &mut [u64; 5], v: u64) {
    let (d, mut borrow) = k[0].overflowing_sub(v);
    k[0] = d;
    for limb in k.iter_mut().skip(1) {
        if !borrow {
            break;
        }
        let (d, b) = limb.overflowing_sub(1);
        *limb = d;
        borrow = b;
    }
}

/// `k += v`, for `v` small enough not to carry past the top.
fn add_u64(k: &mut [u64; 5], v: u64) {
    let (d, mut carry) = k[0].overflowing_add(v);
    k[0] = d;
    for limb in k.iter_mut().skip(1) {
        if !carry {
            break;
        }
        let (d, c) = limb.overflowing_add(1);
        *limb = d;
        carry = c;
    }
}

/// `k >>= 1`.
fn shr1(k: &mut [u64; 5]) {
    for i in 0..4 {
        k[i] = (k[i] >> 1) | (k[i + 1] << 63);
    }
    k[4] >>= 1;
}

/// `SHA-512(parts...)` reduced modulo the group order.
fn hash_to_scalar(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(digest.as_ref());
    scalar::reduce_wide(&wide)
}

/// A signing key with its public key already derived.
///
/// # Why this exists
///
/// RFC 8032 signing needs the public key: it goes into the hash that produces
/// `k`. [`Ed25519::sign`] takes only the 32-byte seed, so it has to derive the
/// public key on every call -- a second basepoint multiplication, and with the
/// table in place that is most of what a signature now costs.
///
/// A key that is used more than once should derive it once. That is what a TLS
/// server does with a certificate key, and what dalek's `SigningKey` does,
/// which is why comparing `Ed25519::sign` against it was comparing two
/// different amounts of work.
///
/// The trait method still exists and still takes a seed. This changes nothing
/// for a caller signing once; it halves the cost for a caller signing twice.
pub struct Ed25519Key {
    /// The clamped scalar from the seed's hash.
    scalar: [u8; 32],
    /// The second half of that hash, which seeds the deterministic nonce.
    prefix: [u8; 32],
    /// `scalar * B`, compressed. Derived once, here.
    public: [u8; 32],
}

impl Drop for Ed25519Key {
    fn drop(&mut self) {
        self.scalar.zeroize();
        self.prefix.zeroize();
        // `public` is public, and is left alone.
    }
}

impl Ed25519Key {
    /// Expand a 32-byte seed and derive its public key.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        ensure!(seed.len() == 32, InvalidLength, "ed25519 seed");
        let (scalar, prefix) = expand_seed(seed);
        let public = mul_basepoint(&scalar).compress();
        Ok(Self {
            scalar,
            prefix,
            public,
        })
    }

    /// The public key, already derived.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Sign `message`, performing one basepoint multiplication rather than two.
    pub fn sign(&self, message: &[u8], signature: &mut [u8]) -> Result<()> {
        ensure!(
            signature.len() == 64,
            InvalidLength,
            "ed25519 signature buffer"
        );

        // r = H(prefix || M), deterministic -- Ed25519 needs no RNG at signing
        // time, which removes an entire class of nonce-reuse failures.
        let mut r = hash_to_scalar(&[&self.prefix, message]);
        let big_r = mul_basepoint(&r).compress();

        let k = hash_to_scalar(&[&big_r, &self.public, message]);
        let s = scalar::mul_add(&k, &self.scalar, &r);

        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s);
        r.zeroize();
        Ok(())
    }
}

impl SignatureScheme for Ed25519 {
    const PRIVATE_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(private_key.len() == 32, InvalidLength, "ed25519 seed");
        ensure!(out.len() == 32, InvalidLength, "ed25519 public key buffer");
        let (mut a, mut prefix) = expand_seed(private_key);
        out.copy_from_slice(&mul_basepoint(&a).compress());
        a.zeroize();
        prefix.zeroize();
        Ok(())
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ensure!(private_key.len() == 32, InvalidLength, "ed25519 seed");
        ensure!(
            signature.len() == 64,
            InvalidLength,
            "ed25519 signature buffer"
        );

        // One shot: expand, derive the public key, sign, discard. A caller
        // signing more than once should hold an `Ed25519Key` instead and pay
        // the derivation once.
        Ed25519Key::from_seed(private_key)?.sign(message, signature)
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ensure!(public_key.len() == 32, InvalidLength, "ed25519 public key");
        ensure!(signature.len() == 64, InvalidLength, "ed25519 signature");

        let mut big_r = [0u8; 32];
        big_r.copy_from_slice(&signature[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);

        // RFC 8032 §5.1.7: reject a non-canonical S. Without this check the
        // signature is malleable, and any system that treats a signature as a
        // unique identifier becomes attackable.
        ensure!(
            scalar::is_canonical(&s),
            MalformedEncoding,
            "ed25519 signature S is not reduced"
        );

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);
        let a_point = Point::decompress(&pk_bytes).ok_or(ic_core::err!(
            MalformedEncoding,
            "ed25519 public key is not on the curve"
        ))?;
        let r_point = Point::decompress(&big_r).ok_or(ic_core::err!(
            MalformedEncoding,
            "ed25519 signature R is not on the curve"
        ))?;

        let k = hash_to_scalar(&[&big_r, &pk_bytes, message]);

        // Check [S]B == R + [k]A.
        let lhs = mul_basepoint(&s);
        // Everything here is public -- the signature, the key, the message --
        // so the constant-time ladder protects nothing and costs work.
        let rhs = r_point.add(&a_point.mul_scalar_vartime(&k));

        if ic_core::ct::verify(&lhs.compress(), &rhs.compress()) {
            Ok(())
        } else {
            Err(ic_core::err!(AuthenticationFailed, "ed25519"))
        }
    }
}

impl SelfTest for Ed25519 {
    fn self_test() -> Result<()> {
        // RFC 8032 §7.1 test vector 1: the empty message.
        let mut seed = [0u8; 32];
        ic_core::codec::hex_decode(
            b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            &mut seed,
        )?;
        let mut want_pk = [0u8; 32];
        ic_core::codec::hex_decode(
            b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            &mut want_pk,
        )?;
        let mut want_sig = [0u8; 64];
        ic_core::codec::hex_decode(
            b"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            &mut want_sig,
        )?;

        let mut pk = [0u8; 32];
        <Self as SignatureScheme>::public_key(&seed, &mut pk)?;
        ensure!(
            ic_core::ct::verify(&want_pk, &pk),
            SelfTestFailed,
            "ed25519"
        );

        let mut sig = [0u8; 64];
        <Self as SignatureScheme>::sign(&seed, b"", &mut sig)?;
        ensure!(
            ic_core::ct::verify(&want_sig, &sig),
            SelfTestFailed,
            "ed25519"
        );

        <Self as SignatureScheme>::verify(&pk, b"", &sig)?;

        // A corrupted signature must be rejected.
        sig[0] ^= 1;
        ensure!(
            <Self as SignatureScheme>::verify(&pk, b"", &sig).is_err(),
            SelfTestFailed,
            "ed25519"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::{hex, unhex};

    #[test]
    fn curve_constants_are_correct() {
        // d = -121665 / 121666
        let d = Fe::from_u64(121_665)
            .neg()
            .mul(&Fe::from_u64(121_666).invert());
        assert_eq!(hex(&D.to_bytes()), hex(&d.to_bytes()), "d");
        assert_eq!(hex(&D2.to_bytes()), hex(&d.add(&d).to_bytes()), "2d");
        // sqrt(-1) squares to -1.
        assert_eq!(
            hex(&SQRT_M1.square().to_bytes()),
            hex(&Fe::ONE.neg().to_bytes()),
            "sqrt(-1)"
        );
    }

    #[test]
    fn basepoint_has_the_expected_coordinates() {
        let b = basepoint();
        // y = 4/5
        let expected_y = Fe::from_u64(4).mul(&Fe::from_u64(5).invert());
        let z_inv = b.z.invert();
        assert_eq!(
            hex(&b.y.mul(&z_inv).to_bytes()),
            hex(&expected_y.to_bytes())
        );
        assert_eq!(hex(&b.compress()), hex(&BASEPOINT_COMPRESSED));
    }

    /// The dedicated doubling must agree with adding a point to itself.
    ///
    /// `add` is what RFC 8032's vectors validate, so it is the oracle here.
    /// The two formulas are different enough -- one reads `T`, the other does
    /// not -- that agreeing on the basepoint alone would not be convincing, so
    /// this walks a chain of multiples and doubles each one.
    #[test]
    fn doubling_agrees_with_adding_a_point_to_itself() {
        let mut p = basepoint();
        let mut checked = 0;
        for _ in 0..16 {
            assert_eq!(
                p.double().compress(),
                p.add(&p).compress(),
                "dedicated doubling and self-addition differ"
            );
            p = p.add(&basepoint());
            checked += 1;
        }
        assert_eq!(checked, 16, "the comparison did not run");

        // The identity doubles to itself, which the formula has to get right
        // without a special case.
        assert_eq!(
            Point::IDENTITY.double().compress(),
            Point::IDENTITY.compress()
        );
    }

    #[test]
    fn group_law_is_consistent() {
        let b = basepoint();
        // P + 0 == P
        assert_eq!(hex(&b.add(&Point::IDENTITY).compress()), hex(&b.compress()));
        // 2P via doubling equals 2P via scalar multiplication.
        let mut two = [0u8; 32];
        two[0] = 2;
        assert_eq!(
            hex(&b.double().compress()),
            hex(&b.mul_scalar(&two).compress())
        );
        // (P + P) + P == 3P
        let mut three = [0u8; 32];
        three[0] = 3;
        assert_eq!(
            hex(&b.double().add(&b).compress()),
            hex(&b.mul_scalar(&three).compress())
        );
    }

    #[test]
    fn order_of_the_basepoint_is_l() {
        // [L]B must be the identity.
        assert_eq!(
            hex(&basepoint().mul_scalar(&scalar::L).compress()),
            hex(&Point::IDENTITY.compress())
        );
    }

    #[test]
    fn compression_roundtrips() {
        let b = basepoint();
        for k in [1u8, 2, 3, 47, 200] {
            let mut s = [0u8; 32];
            s[0] = k;
            let p = b.mul_scalar(&s);
            let c = p.compress();
            let d = Point::decompress(&c).expect("valid point");
            assert_eq!(hex(&d.compress()), hex(&c), "k = {k}");
        }
    }

    #[test]
    fn decompression_rejects_non_curve_points() {
        // A y value with no corresponding x.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert!(Point::decompress(&bad).is_none());
    }

    /// RFC 8032 §7.1 test vectors.
    #[test]
    fn rfc8032_vectors() {
        let cases: [(&str, &str, &str, &str); 3] = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];

        for (seed_hex, pk_hex, msg_hex, sig_hex) in cases {
            let seed = unhex(seed_hex).unwrap();
            let msg = unhex(msg_hex).unwrap();

            let mut pk = [0u8; 32];
            Ed25519::public_key(&seed, &mut pk).unwrap();
            assert_eq!(hex(&pk), pk_hex, "public key for {seed_hex}");

            let mut sig = [0u8; 64];
            Ed25519::sign(&seed, &msg, &mut sig).unwrap();
            assert_eq!(hex(&sig), sig_hex, "signature for {seed_hex}");

            Ed25519::verify(&pk, &msg, &sig).unwrap();
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let seed = [0x42u8; 32];
        let mut pk = [0u8; 32];
        Ed25519::public_key(&seed, &mut pk).unwrap();
        let mut sig = [0u8; 64];
        Ed25519::sign(&seed, b"authentic", &mut sig).unwrap();
        Ed25519::verify(&pk, b"authentic", &sig).unwrap();

        // Wrong message.
        assert!(Ed25519::verify(&pk, b"forged", &sig).is_err());
        // Corrupted R.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(Ed25519::verify(&pk, b"authentic", &bad).is_err());
        // Corrupted S.
        let mut bad = sig;
        bad[40] ^= 1;
        assert!(Ed25519::verify(&pk, b"authentic", &bad).is_err());
        // Wrong public key.
        let mut other_pk = [0u8; 32];
        Ed25519::public_key(&[0x43u8; 32], &mut other_pk).unwrap();
        assert!(Ed25519::verify(&other_pk, b"authentic", &sig).is_err());
    }

    /// A signature with `S >= L` must be rejected even though it would
    /// otherwise verify; this is the malleability check.
    #[test]
    fn rejects_non_canonical_s() {
        let seed = [0x42u8; 32];
        let mut pk = [0u8; 32];
        Ed25519::public_key(&seed, &mut pk).unwrap();
        let mut sig = [0u8; 64];
        Ed25519::sign(&seed, b"msg", &mut sig).unwrap();

        // Add L to S. The verification equation still holds mod L, so only the
        // canonicality check can catch it.
        let mut carry = 0u16;
        for i in 0..32 {
            let t = sig[32 + i] as u16 + scalar::L[i] as u16 + carry;
            sig[32 + i] = t as u8;
            carry = t >> 8;
        }
        assert!(Ed25519::verify(&pk, b"msg", &sig).is_err());
    }

    /// The cached key and the seed-only call must produce the same signature.
    ///
    /// They share a code path now, which is the point -- but that is the sort
    /// of thing a later refactor separates again, and the two would then differ
    /// only for callers who use one and verify with the other. RFC 8032's
    /// vectors exercise the trait method alone and would not notice.
    #[test]
    fn the_cached_key_signs_identically_to_the_seed() {
        let mut checked = 0;
        for seed in [[0x11u8; 32], [0x9du8; 32], [0xffu8; 32]] {
            for message in [&b""[..], &b"x"[..], &b"a longer message to sign"[..]] {
                let mut from_seed = [0u8; 64];
                Ed25519::sign(&seed, message, &mut from_seed).unwrap();

                let key = Ed25519Key::from_seed(&seed).unwrap();
                let mut from_key = [0u8; 64];
                key.sign(message, &mut from_key).unwrap();

                assert_eq!(from_seed, from_key, "the two signing paths diverged");

                // And the cached public key is the one the trait derives.
                let mut derived = [0u8; 32];
                Ed25519::public_key(&seed, &mut derived).unwrap();
                assert_eq!(&derived, key.public_key());

                // Both verify, so neither is consistently wrong.
                Ed25519::verify(&derived, message, &from_key).unwrap();
                checked += 1;
            }
        }
        assert_eq!(checked, 9, "the comparison did not run");
    }

    /// The variable-time path must agree with the constant-time one.
    ///
    /// RFC 8032's vectors reach it with a handful of scalars, which says little
    /// about a recoding whose digit pattern is different for every scalar. This
    /// drives both over scalars picked to stress the recoding: zero, one, a
    /// value that carries at every position, alternating bits, and the top of
    /// the range.
    #[test]
    fn the_vartime_multiplication_agrees_with_the_ladder() {
        let p = basepoint();

        let mut one = [0u8; 32];
        one[0] = 1;
        let mut two = [0u8; 32];
        two[0] = 2;
        let mut top = [0xffu8; 32];
        top[31] = 0x7f;

        let mut checked = 0;
        for scalar in [
            [0u8; 32],
            one,
            two,
            [0xffu8; 32],
            [0x55u8; 32],
            [0xaau8; 32],
            top,
            [0x9du8; 32],
        ] {
            let fast = p.mul_scalar_vartime(&scalar);
            let slow = p.mul_scalar(&scalar);
            assert_eq!(
                fast.compress(),
                slow.compress(),
                "vartime and ladder differ for {scalar:02x?}"
            );
            checked += 1;
        }
        assert_eq!(checked, 8, "the comparison did not run");
    }

    /// The recoding must represent the scalar, with the digits it promises.
    #[test]
    fn the_wnaf_digits_are_odd_sparse_and_faithful() {
        for scalar in [[1u8; 32], [0x9du8; 32], [0xffu8; 32], [0x55u8; 32]] {
            let naf = wnaf5(&scalar);

            let mut previous_nonzero: Option<usize> = None;
            for (i, d) in naf.iter().enumerate() {
                if *d == 0 {
                    continue;
                }
                assert!(d % 2 != 0, "digit {d} at {i} is not odd");
                assert!((-15..=15).contains(d), "digit {d} at {i} is out of range");
                if let Some(j) = previous_nonzero {
                    assert!(i - j >= 5, "digits at {j} and {i} are adjacent");
                }
                previous_nonzero = Some(i);
            }

            // And it evaluates back to the scalar, modulo a small prime that
            // has nothing to do with the curve.
            const M: u128 = 1_000_000_007;
            let mut from_digits = 0u128;
            let mut power = 1u128;
            for d in naf {
                let term = ((d as i128).rem_euclid(M as i128)) as u128;
                from_digits = (from_digits + term * power) % M;
                power = power * 2 % M;
            }
            let mut from_bytes = 0u128;
            let mut p = 1u128;
            for byte in scalar {
                from_bytes = (from_bytes + (byte as u128) * p) % M;
                p = p * 256 % M;
            }
            assert_eq!(from_digits, from_bytes, "recoding changed the value");
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let seed = [0x7fu8; 32];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        Ed25519::sign(&seed, b"same input", &mut a).unwrap();
        Ed25519::sign(&seed, b"same input", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mut out = [0u8; 32];
        assert!(Ed25519::public_key(&[0u8; 31], &mut out).is_err());
        assert!(Ed25519::sign(&[0u8; 32], b"", &mut [0u8; 63]).is_err());
        assert!(Ed25519::verify(&[0u8; 32], b"", &[0u8; 63]).is_err());
    }

    #[test]
    fn self_test_passes() {
        Ed25519::self_test().unwrap();
    }
}
