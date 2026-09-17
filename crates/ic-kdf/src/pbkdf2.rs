//! SP 800-132 / RFC 8018 PBKDF2.

use ic_core::traits::Mac;
use ic_core::{ensure, Result, Zeroize};

/// The largest MAC output any supported instantiation produces.
const MAX_TAG_LEN: usize = 64;

/// Advice on an iteration count, for agents choosing parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IterationVerdict {
    /// At or above the modern recommendation.
    Recommended,
    /// Above the SP 800-132 floor but below current practice.
    Weak,
    /// Below the SP 800-132 minimum of 1 000; rejected outright.
    Unacceptable,
}

/// Classify an iteration count without performing any derivation.
///
/// Exposed as an ontology precondition so an agent can validate parameters
/// before spending the work, and so a reviewer can see the threshold the
/// library actually enforces.
pub const fn check_iterations(iterations: u32) -> IterationVerdict {
    if iterations < 1_000 {
        IterationVerdict::Unacceptable
    } else if iterations < crate::PBKDF2_MIN_RECOMMENDED_ITERATIONS {
        IterationVerdict::Weak
    } else {
        IterationVerdict::Recommended
    }
}

/// Derive `out.len()` bytes from `password` and `salt`.
///
/// Rejects iteration counts below the SP 800-132 minimum of 1 000 and salts
/// shorter than the 128-bit minimum, so a misconfigured caller fails loudly
/// rather than producing a weak key.
pub fn pbkdf2<M: Mac>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    ensure!(
        !matches!(check_iterations(iterations), IterationVerdict::Unacceptable),
        InvalidParameter,
        "pbkdf2 iterations below the SP 800-132 minimum of 1000"
    );
    ensure!(
        salt.len() >= 16,
        InvalidParameter,
        "pbkdf2 salt must be >= 128 bits"
    );
    ensure!(!out.is_empty(), InvalidLength, "pbkdf2 output");
    ensure!(
        M::TAG_LEN <= MAX_TAG_LEN,
        InvalidParameter,
        "mac tag too wide"
    );

    let mut u = [0u8; MAX_TAG_LEN];
    let mut acc = [0u8; MAX_TAG_LEN];

    for (block_index, chunk) in out.chunks_mut(M::TAG_LEN).enumerate() {
        let counter = (block_index as u32)
            .checked_add(1)
            .ok_or(ic_core::err!(CounterExhausted, "pbkdf2 block counter"))?;

        // U_1 = PRF(password, salt || INT_BE(i))
        let mut m = M::new(password)?;
        m.update(salt);
        m.update(&counter.to_be_bytes());
        let t = m.finalize();
        u[..M::TAG_LEN].copy_from_slice(t.as_ref());
        acc[..M::TAG_LEN].copy_from_slice(t.as_ref());

        // U_j = PRF(password, U_{j-1}); accumulate the XOR of every U_j.
        for _ in 1..iterations {
            let mut m = M::new(password)?;
            m.update(&u[..M::TAG_LEN]);
            let t = m.finalize();
            u[..M::TAG_LEN].copy_from_slice(t.as_ref());
            for j in 0..M::TAG_LEN {
                acc[j] ^= u[j];
            }
        }
        chunk.copy_from_slice(&acc[..chunk.len()]);
    }

    u.zeroize();
    acc.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::hex;
    use ic_mac::{HmacSha256, HmacSha512};

    /// The defining property of PBKDF2: each output block is the XOR chain of
    /// the PRF iterations. Reconstructing it from HMAC directly checks the
    /// construction rather than pinning an opaque constant.
    ///
    /// RFC 6070's published vectors are HMAC-SHA1 only, which this library
    /// deliberately does not implement.
    #[test]
    fn matches_the_prf_xor_chain() {
        let salt = b"0123456789abcdef";
        let mut out = [0u8; 32];
        pbkdf2::<HmacSha256>(b"pw", salt, 1_000, &mut out).unwrap();

        let mut first = HmacSha256::new(b"pw").unwrap();
        first.update(salt);
        first.update(&1u32.to_be_bytes());
        let mut u = first.finalize();
        let mut acc = u;
        for _ in 1..1_000 {
            u = HmacSha256::mac(b"pw", u.as_ref()).unwrap();
            for j in 0..32 {
                acc[j] ^= u[j];
            }
        }
        assert_eq!(hex(&out), hex(acc.as_ref()));
    }

    #[test]
    fn is_deterministic() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2::<HmacSha256>(b"passwd", b"salt-at-least-16", 1_000, &mut a).unwrap();
        pbkdf2::<HmacSha256>(b"passwd", b"salt-at-least-16", 1_000, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn iteration_count_changes_the_key() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2::<HmacSha256>(b"pw", b"0123456789abcdef", 1_000, &mut a).unwrap();
        pbkdf2::<HmacSha256>(b"pw", b"0123456789abcdef", 2_000, &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn output_longer_than_one_block() {
        let mut out = [0u8; 100];
        pbkdf2::<HmacSha256>(b"pw", b"0123456789abcdef", 1_000, &mut out).unwrap();
        // A repeated 32-byte pattern would mean the block counter never reaches
        // the PRF.
        assert_ne!(&out[..32], &out[32..64]);
    }

    #[test]
    fn sha512_instantiation_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2::<HmacSha256>(b"pw", b"0123456789abcdef", 1_000, &mut a).unwrap();
        pbkdf2::<HmacSha512>(b"pw", b"0123456789abcdef", 1_000, &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_weak_parameters() {
        let mut out = [0u8; 32];
        assert!(pbkdf2::<HmacSha256>(b"pw", b"0123456789abcdef", 999, &mut out).is_err());
        assert!(pbkdf2::<HmacSha256>(b"pw", b"short", 100_000, &mut out).is_err());
        assert!(pbkdf2::<HmacSha256>(b"pw", b"0123456789abcdef", 1_000, &mut []).is_err());
    }

    #[test]
    fn iteration_verdicts() {
        assert_eq!(check_iterations(999), IterationVerdict::Unacceptable);
        assert_eq!(check_iterations(1_000), IterationVerdict::Weak);
        assert_eq!(check_iterations(600_000), IterationVerdict::Recommended);
    }
}
