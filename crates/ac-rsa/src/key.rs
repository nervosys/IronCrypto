//! RSA key types, primality testing, and key generation.
//!
//! # What is and is not constant-time
//!
//! The private operation ([`RsaPrivateKey::raw_private`]) is constant-time in
//! the exponent. Key *generation* is not, and deliberately so: the binary GCD
//! and the trial divisions branch on candidate values. That matches every
//! mainstream implementation — generation is a one-time operation, typically
//! offline, and making it constant-time would cost far more than it buys.
//! Generate keys somewhere an attacker is not measuring.
//!
//! # No CRT
//!
//! The private operation is a single exponentiation modulo `n`, not the
//! Chinese-remainder pair modulo `p` and `q`. CRT would be roughly four times
//! faster, and is also where RSA fault attacks land: a single faulted half
//! leaks the factorization. The simpler path is the one implemented; CRT is
//! noted in the ontology as a possible optimization rather than pretended to.

use crate::uint::{Modulus, Uint, MAX_BYTES};
use ac_core::traits::RandomSource;
use ac_core::{ensure, Result, Zeroize};

/// The smallest modulus this accepts, in bits.
///
/// SP 800-131A disallows RSA below 2048 bits for new signatures.
pub const MIN_MODULUS_BITS: usize = 2048;

/// The largest modulus this accepts, in bits.
pub const MAX_MODULUS_BITS: usize = 4096;

/// The only public exponent this generates, and the one essentially everything
/// uses.
///
/// FIPS 186-5 requires an odd public exponent between 2^16 and 2^256. Small
/// exponents like 3 are legal but leave less margin against implementation
/// mistakes, so generation always uses this one.
pub const PUBLIC_EXPONENT: u64 = 65537;

/// An RSA public key.
#[derive(Clone, Copy)]
pub struct RsaPublicKey {
    n: Modulus,
    e: u64,
}

impl RsaPublicKey {
    /// Build from a big-endian modulus and a public exponent.
    pub fn from_components(n: &[u8], e: u64) -> Result<Self> {
        let n_uint =
            Uint::from_be_bytes(n).ok_or(ac_core::err!(InvalidLength, "rsa modulus too large"))?;
        let bits = n_uint.bits();
        ensure!(
            (MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits),
            InvalidParameter,
            "rsa modulus must be 2048..=4096 bits"
        );
        ensure!(
            e >= 3 && e % 2 == 1,
            InvalidParameter,
            "rsa exponent must be odd and >= 3"
        );
        let n = Modulus::new(n_uint)
            .ok_or(ac_core::err!(InvalidParameter, "rsa modulus must be odd"))?;
        Ok(RsaPublicKey { n, e })
    }

    /// The modulus size in bytes, which is also the signature size.
    pub fn size(&self) -> usize {
        self.n.byte_len()
    }

    /// The modulus size in bits.
    pub fn bits(&self) -> usize {
        self.n.value().bits()
    }

    /// The public exponent.
    pub fn exponent(&self) -> u64 {
        self.e
    }

    /// The modulus, big-endian, written into `out` (which must be [`Self::size`]).
    pub fn modulus_bytes(&self, out: &mut [u8]) -> Result<()> {
        ensure!(
            out.len() == self.size(),
            InvalidLength,
            "rsa modulus buffer"
        );
        self.n.value().to_be_bytes(out);
        Ok(())
    }

    /// The raw public operation, `m^e mod n`.
    ///
    /// Both the input and the output are big-endian and exactly [`Self::size`]
    /// bytes. Rejects `m >= n`, which has no valid representative.
    pub fn raw_public(&self, m: &[u8], out: &mut [u8]) -> Result<()> {
        let size = self.size();
        ensure!(
            m.len() == size && out.len() == size,
            InvalidLength,
            "rsa block"
        );
        let value = Uint::from_be_bytes(m)
            .ok_or(ac_core::err!(MalformedEncoding, "rsa block too large"))?;
        ensure!(
            value.cmp_vartime(self.n.value()) == core::cmp::Ordering::Less,
            MalformedEncoding,
            "rsa block is not less than the modulus"
        );
        self.n.pow_public(&value, self.e).to_be_bytes(out);
        Ok(())
    }
}

/// An RSA private key.
pub struct RsaPrivateKey {
    public: RsaPublicKey,
    d: Uint,
    /// Bit length of `d`, which bounds the exponentiation loop. This is a
    /// property of the key rather than of any message, so it is not secret in
    /// the way `d` itself is.
    d_bits: usize,
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl RsaPrivateKey {
    /// Build from a big-endian modulus, public exponent, and private exponent.
    pub fn from_components(n: &[u8], e: u64, d: &[u8]) -> Result<Self> {
        let public = RsaPublicKey::from_components(n, e)?;
        let d_uint =
            Uint::from_be_bytes(d).ok_or(ac_core::err!(InvalidLength, "rsa exponent too large"))?;
        ensure!(
            d_uint.cmp_vartime(public.n.value()) == core::cmp::Ordering::Less,
            InvalidParameter,
            "rsa private exponent must be less than the modulus"
        );
        // The loop runs over the full modulus width rather than d's own bit
        // length, so the timing does not reveal how large d happens to be.
        let d_bits = public.bits();
        Ok(RsaPrivateKey {
            public,
            d: d_uint,
            d_bits,
        })
    }

    /// The matching public key.
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// The modulus size in bytes.
    pub fn size(&self) -> usize {
        self.public.size()
    }

    /// The raw private operation, `c^d mod n`, constant-time in `d`.
    pub fn raw_private(&self, c: &[u8], out: &mut [u8]) -> Result<()> {
        let size = self.size();
        ensure!(
            c.len() == size && out.len() == size,
            InvalidLength,
            "rsa block"
        );
        let value = Uint::from_be_bytes(c)
            .ok_or(ac_core::err!(MalformedEncoding, "rsa block too large"))?;
        ensure!(
            value.cmp_vartime(self.public.n.value()) == core::cmp::Ordering::Less,
            MalformedEncoding,
            "rsa block is not less than the modulus"
        );
        let mut result = self.public.n.pow(&value, &self.d, self.d_bits);
        result.to_be_bytes(out);
        result.zeroize();
        Ok(())
    }

    /// The private exponent, big-endian, written into `out`.
    ///
    /// For serializing a key. The caller is responsible for erasing `out`.
    pub fn exponent_bytes(&self, out: &mut [u8]) -> Result<()> {
        ensure!(
            out.len() == self.size(),
            InvalidLength,
            "rsa exponent buffer"
        );
        self.d.to_be_bytes(out);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Primes below 256, for trial division.
///
/// Rejecting candidates with a small factor before the first Miller-Rabin round
/// removes around 80% of them for a tiny fraction of the cost.
const SMALL_PRIMES: [u64; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// Full-width multiplication, `a * b`, variable time.
///
/// Used only during key generation, on values that are secret but processed
/// once in an offline setting. See the module note on generation timing.
fn mul_vartime(a: &Uint, b: &Uint, a_limbs: usize, b_limbs: usize) -> Uint {
    let mut out = Uint::ZERO;
    for i in 0..a_limbs {
        let mut carry = 0u128;
        for j in 0..b_limbs {
            if i + j >= crate::uint::MAX_LIMBS {
                break;
            }
            let sum = (out.0[i + j] as u128) + (a.0[i] as u128) * (b.0[j] as u128) + carry;
            out.0[i + j] = sum as u64;
            carry = sum >> 64;
        }
        if i + b_limbs < crate::uint::MAX_LIMBS {
            out.0[i + b_limbs] = out.0[i + b_limbs].wrapping_add(carry as u64);
        }
    }
    out
}

/// Miller-Rabin probable-primality test against the first `rounds` prime bases.
///
/// # Why fixed bases rather than random ones
///
/// FIPS 186-5 C.3.1 draws each base at random, which matters when the candidate
/// might have been chosen adversarially to fool a known base set. Here the
/// candidate always comes from this library's own DRBG a few lines earlier, so
/// there is no adversary in a position to choose it, and fixed bases make the
/// test deterministic and therefore testable. A key arriving from outside is
/// never run through this function — [`RsaPublicKey::from_components`] does not
/// attempt to factor what it is given.
///
/// Composites survive a single round with probability at most 1/4, so `rounds`
/// prime bases put the failure probability below 4^-rounds for a random
/// candidate — far below the 2^-100 that FIPS 186-5 Table B.1 asks for by the
/// time `rounds` reaches 8, and in practice much lower still, since no
/// composite is known that fools even the first twelve prime bases.
fn is_probable_prime(candidate: &Uint, limbs: usize, rounds: usize) -> bool {
    if !candidate.is_odd() {
        return false;
    }
    for p in SMALL_PRIMES {
        if candidate.rem_u64(p) == 0 {
            // Divisible: prime only if the candidate *is* that small prime.
            return candidate.cmp_vartime(&Uint::from_u64(p)) == core::cmp::Ordering::Equal;
        }
    }

    let modulus = match Modulus::new(*candidate) {
        Some(m) => m,
        None => return false,
    };
    let one = Uint::one();
    let mut n_minus_1 = *candidate;
    n_minus_1.sub_assign(&one, limbs);

    // n - 1 = 2^s * d with d odd.
    let mut d = n_minus_1;
    let mut s = 0usize;
    while !d.is_odd() {
        d.shr1(limbs);
        s += 1;
    }
    let d_bits = d.bits();

    for &p in SMALL_PRIMES.iter().take(rounds) {
        let base = Uint::from_u64(p);
        // Trial division already established `candidate > p` for every small
        // prime, so the base is in range.
        let mut x = modulus.pow(&base, &d, d_bits);
        if x.cmp_vartime(&one) == core::cmp::Ordering::Equal
            || x.cmp_vartime(&n_minus_1) == core::cmp::Ordering::Equal
        {
            continue;
        }

        let mut witnessed = false;
        for _ in 1..s {
            x = modulus.pow_public(&x, 2);
            if x.cmp_vartime(&n_minus_1) == core::cmp::Ordering::Equal {
                witnessed = true;
                break;
            }
        }
        if !witnessed {
            return false;
        }
    }
    true
}

/// Draw a random odd candidate of exactly `bits` bits.
///
/// The top two bits are set, which is what guarantees that a product of two
/// such primes has exactly `2 * bits` bits — otherwise the modulus could come
/// out a bit short.
fn random_candidate<R: RandomSource + ?Sized>(bits: usize, rng: &mut R) -> Result<Uint> {
    let byte_len = bits / 8;
    let mut buf = [0u8; MAX_BYTES];
    rng.fill(&mut buf[..byte_len])?;
    buf[0] |= 0xC0;
    buf[byte_len - 1] |= 0x01;
    Uint::from_be_bytes(&buf[..byte_len]).ok_or(ac_core::err!(Internal, "candidate did not fit"))
}

/// Generate an RSA key pair of `bits` bits.
///
/// `bits` must be 2048, 3072, or 4096. Expect this to take seconds: the search
/// tries on the order of `ln(2^(bits/2))/2` candidates, most rejected by trial
/// division, and each survivor costs several modular exponentiations.
///
/// The public exponent is always [`PUBLIC_EXPONENT`].
///
/// # Standards note
///
/// The private exponent is derived modulo `phi(n) = (p-1)(q-1)`. FIPS 186-5
/// B.3 specifies `lambda(n) = lcm(p-1, q-1)`, which yields a smaller `d`. Both
/// satisfy `m^(ed) = m mod n`, so signatures and ciphertexts interoperate
/// either way, but a validator would want the `lambda` form.
pub fn generate<R: RandomSource + ?Sized>(bits: usize, rng: &mut R) -> Result<RsaPrivateKey> {
    ensure!(
        matches!(bits, 2048 | 3072 | 4096),
        InvalidParameter,
        "rsa key size must be 2048, 3072, or 4096 bits"
    );

    let half = bits / 2;
    let half_limbs = half / 64;
    let full_limbs = bits / 64;
    let rounds = 8;
    let one = Uint::one();
    let e = Uint::from_u64(PUBLIC_EXPONENT);

    // Bounded so a broken RNG cannot hang the caller.
    for _ in 0..(half * 40) {
        let p = random_candidate(half, rng)?;
        if !is_probable_prime(&p, half_limbs, rounds) {
            continue;
        }

        for _ in 0..(half * 40) {
            let q = random_candidate(half, rng)?;
            if q.cmp_vartime(&p) == core::cmp::Ordering::Equal {
                continue;
            }
            if !is_probable_prime(&q, half_limbs, rounds) {
                continue;
            }

            let n = mul_vartime(&p, &q, half_limbs, half_limbs);
            if n.bits() != bits {
                continue;
            }

            // phi = (p-1)(q-1)
            let mut p1 = p;
            p1.sub_assign(&one, half_limbs);
            let mut q1 = q;
            q1.sub_assign(&one, half_limbs);
            let phi = mul_vartime(&p1, &q1, half_limbs, half_limbs);

            // d = e^-1 mod phi. phi is even, and the binary extended GCD needs
            // an odd modulus, so invert the other way round: solve for d with
            // the roles swapped by inverting phi mod e is not possible here, so
            // fall back to rejecting the rare case where the inverse does not
            // exist (gcd(e, phi) != 1).
            let d = match modinv_even_modulus(&e, &phi, full_limbs) {
                Some(d) => d,
                None => continue,
            };

            let mut n_bytes = [0u8; MAX_BYTES];
            let size = bits / 8;
            n.to_be_bytes(&mut n_bytes[..size]);
            let mut d_bytes = [0u8; MAX_BYTES];
            d.to_be_bytes(&mut d_bytes[..size]);

            let key =
                RsaPrivateKey::from_components(&n_bytes[..size], PUBLIC_EXPONENT, &d_bytes[..size]);
            d_bytes.zeroize();
            return key;
        }
    }

    Err(ac_core::err!(
        Internal,
        "rsa key generation did not converge"
    ))
}

/// Modular inverse of a small odd `a` modulo an even `m`.
///
/// The binary extended GCD needs an odd modulus, which `phi(n)` never is. This
/// solves `a * d = 1 (mod m)` by inverting in the other direction: it finds
/// `t = m^-1 mod a` (a small modulus, since `a` is the public exponent) and
/// then reconstructs `d = (1 + m * (a - t)) / a` exactly.
fn modinv_even_modulus(a: &Uint, m: &Uint, limbs: usize) -> Option<Uint> {
    // `a` is the public exponent and fits in a u64.
    let a_small = a.0[0];
    if a_small == 0 || a.bits() > 64 {
        return None;
    }
    let m_mod_a = m.rem_u64(a_small);
    if m_mod_a == 0 {
        return None; // not coprime
    }
    // t = m^-1 mod a, by extended Euclid on two small integers.
    let t = small_modinv(m_mod_a, a_small)?;
    // k = a - t, so that (1 + m*k) is divisible by a.
    let k = a_small - t;

    // d = (1 + m*k) / a
    let mut product = mul_small(m, k, limbs);
    product.add_assign(&Uint::one(), limbs + 1);
    div_small(&mut product, a_small, limbs + 1)?;
    Some(product)
}

/// Extended Euclid on two `u64`s.
fn small_modinv(a: u64, m: u64) -> Option<u64> {
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (s, old_s - q * s);
    }
    if old_r != 1 {
        return None;
    }
    Some(old_s.rem_euclid(m as i128) as u64)
}

/// `a * b` for a small `b`.
fn mul_small(a: &Uint, b: u64, limbs: usize) -> Uint {
    let mut out = Uint::ZERO;
    let mut carry = 0u128;
    for i in 0..limbs {
        let sum = (a.0[i] as u128) * (b as u128) + carry;
        out.0[i] = sum as u64;
        carry = sum >> 64;
    }
    if limbs < crate::uint::MAX_LIMBS {
        out.0[limbs] = carry as u64;
    }
    out
}

/// Divide in place by a small integer, returning `None` if it does not divide
/// exactly.
fn div_small(a: &mut Uint, b: u64, limbs: usize) -> Option<()> {
    let mut rem = 0u128;
    for i in (0..limbs).rev() {
        let cur = (rem << 64) | (a.0[i] as u128);
        a.0[i] = (cur / b as u128) as u64;
        rem = cur % b as u128;
    }
    if rem != 0 {
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_modular_inverse() {
        assert_eq!(small_modinv(3, 7), Some(5)); // 3*5 = 15 = 1 mod 7
        assert_eq!(
            small_modinv(65537, 11),
            Some(small_modinv(65537 % 11, 11).unwrap())
        );
        assert_eq!(small_modinv(2, 4), None, "not coprime");
    }

    #[test]
    fn small_multiply_and_divide_round_trip() {
        let a = Uint::from_u64(123_456_789);
        let mut p = mul_small(&a, 65537, 4);
        assert_eq!(p.0[0], 123_456_789u64 * 65537);
        div_small(&mut p, 65537, 4).unwrap();
        assert_eq!(p.0[0], 123_456_789);

        let mut q = Uint::from_u64(10);
        assert!(div_small(&mut q, 3, 4).is_none(), "inexact division");
    }

    #[test]
    fn full_multiply_matches_u128() {
        let a = Uint::from_u64(0xffff_ffff_ffff_fffb);
        let b = Uint::from_u64(0xffff_ffff_ffff_fff9);
        let p = mul_vartime(&a, &b, 1, 1);
        let want = (a.0[0] as u128) * (b.0[0] as u128);
        assert_eq!(p.0[0], want as u64);
        assert_eq!(p.0[1], (want >> 64) as u64);
    }

    #[test]
    fn primality_recognizes_known_values() {
        for p in [3u64, 5, 7, 65537, 2_147_483_647, 1_000_000_007] {
            assert!(is_probable_prime(&Uint::from_u64(p), 1, 8), "{p} is prime");
        }
        for c in [9u64, 15, 21, 65535, 2_147_483_645, 1_000_000_009 * 3] {
            assert!(
                !is_probable_prime(&Uint::from_u64(c), 1, 8),
                "{c} is composite"
            );
        }
    }

    /// A Carmichael number passes a naive Fermat test but must fail
    /// Miller-Rabin, which is the whole reason for using the latter.
    #[test]
    fn primality_rejects_carmichael_numbers() {
        for c in [561u64, 1105, 1729, 2465, 6601, 8911, 41041, 62745] {
            assert!(
                !is_probable_prime(&Uint::from_u64(c), 1, 8),
                "{c} is a Carmichael number, not a prime"
            );
        }
    }

    #[test]
    fn generation_rejects_unsupported_sizes() {
        let mut rng = ac_drbg::Rng::from_entropy(&[0x33u8; 32], b"sizes").unwrap();
        for bits in [512usize, 1024, 2047, 2049, 8192] {
            assert!(generate(bits, &mut rng).is_err(), "{bits} bits");
        }
    }

    /// The one property that matters for a generated key: it is a working RSA
    /// key, meaning `(m^e)^d = m (mod n)`. That holds only if `p` and `q` really
    /// are prime and `d` really is the inverse of `e` modulo `phi(n)`, so a
    /// broken primality test or a broken inversion shows up here.
    ///
    /// This generates three 2048-bit keys, which costs a couple of seconds even
    /// in a debug build — worth paying on every run for the only test that
    /// exercises key generation end to end.
    #[test]
    fn generated_keys_satisfy_the_rsa_identity() {
        let mut rng = ac_drbg::Rng::from_entropy(&[0x44u8; 32], b"generate").unwrap();
        let key = generate(2048, &mut rng).unwrap();
        assert_eq!(key.public_key().bits(), 2048);
        assert_eq!(key.size(), 256);

        for seed in [1u8, 0x5a, 0xfe] {
            let mut message = [seed; 256];
            message[0] = 0;
            let mut encrypted = [0u8; 256];
            key.public_key()
                .raw_public(&message, &mut encrypted)
                .unwrap();
            let mut recovered = [0u8; 256];
            key.raw_private(&encrypted, &mut recovered).unwrap();
            assert_eq!(recovered, message, "seed {seed}");
        }

        // Two generations from different seeds must not collide.
        let mut other_rng = ac_drbg::Rng::from_entropy(&[0x55u8; 32], b"generate").unwrap();
        let other = generate(2048, &mut other_rng).unwrap();
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        key.public_key().modulus_bytes(&mut a).unwrap();
        other.public_key().modulus_bytes(&mut b).unwrap();
        assert_ne!(a, b, "distinct seeds give distinct keys");
    }

    #[test]
    fn public_key_validates_its_parameters() {
        let mut n = [0u8; 256];
        n[0] = 0x80;
        n[255] = 1;
        assert!(RsaPublicKey::from_components(&n, 65537).is_ok());
        assert!(
            RsaPublicKey::from_components(&n, 4).is_err(),
            "even exponent"
        );
        assert!(
            RsaPublicKey::from_components(&n, 1).is_err(),
            "exponent too small"
        );

        // Too small a modulus.
        let mut small = [0u8; 128];
        small[0] = 0x80;
        small[127] = 1;
        assert!(RsaPublicKey::from_components(&small, 65537).is_err());

        // Even modulus.
        let mut even = [0u8; 256];
        even[0] = 0x80;
        assert!(RsaPublicKey::from_components(&even, 65537).is_err());
    }
}
