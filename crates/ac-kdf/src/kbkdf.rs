//! SP 800-108 KDF in counter mode.
//!
//! This expands a key-derivation key into multiple application keys, and is the
//! mechanism behind the key hierarchies in TLS exporters, IKEv2, and most
//! HSM-backed designs.

use ac_core::traits::Mac;
use ac_core::{ensure, Result, Zeroize};

const MAX_TAG_LEN: usize = 64;

/// SP 800-108 counter-mode KDF with a 32-bit big-endian counter.
///
/// Each block is `PRF(key, [i]_32 || label || 0x00 || context || [L]_32)`,
/// where `L` is the total output length in bits. The `0x00` separator makes
/// `label` and `context` unambiguously parseable, which is what stops two
/// different `(label, context)` pairs from deriving the same key.
pub fn kbkdf_counter<M: Mac>(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<()> {
    ensure!(!out.is_empty(), InvalidLength, "kbkdf output");
    ensure!(
        M::TAG_LEN <= MAX_TAG_LEN,
        InvalidParameter,
        "mac tag too wide"
    );
    ensure!(
        !label.contains(&0),
        InvalidParameter,
        "kbkdf label must not contain a zero byte"
    );

    let total_bits = (out.len() as u64)
        .checked_mul(8)
        .and_then(|b| u32::try_from(b).ok())
        .ok_or(ac_core::err!(InvalidLength, "kbkdf output too long"))?;

    let blocks = out.len().div_ceil(M::TAG_LEN);
    ensure!(
        blocks <= u32::MAX as usize,
        CounterExhausted,
        "kbkdf counter"
    );

    let mut scratch = [0u8; MAX_TAG_LEN];
    for (i, chunk) in out.chunks_mut(M::TAG_LEN).enumerate() {
        let counter = (i as u32) + 1;
        let mut m = M::new(key)?;
        m.update(&counter.to_be_bytes());
        m.update(label);
        m.update(&[0u8]);
        m.update(context);
        m.update(&total_bits.to_be_bytes());
        let t = m.finalize();
        scratch[..M::TAG_LEN].copy_from_slice(t.as_ref());
        chunk.copy_from_slice(&scratch[..chunk.len()]);
    }
    scratch.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_mac::HmacSha256;

    #[test]
    fn is_deterministic() {
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        kbkdf_counter::<HmacSha256>(b"kdk", b"label", b"ctx", &mut a).unwrap();
        kbkdf_counter::<HmacSha256>(b"kdk", b"label", b"ctx", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn label_and_context_are_domain_separated() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        kbkdf_counter::<HmacSha256>(b"kdk", b"ab", b"c", &mut a).unwrap();
        kbkdf_counter::<HmacSha256>(b"kdk", b"a", b"bc", &mut b).unwrap();
        kbkdf_counter::<HmacSha256>(b"kdk", b"ab", b"d", &mut c).unwrap();
        // Without the 0x00 separator the first two would collide.
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    /// Output length is bound into every block, so a 32-byte request is not a
    /// prefix of a 64-byte one. That is what blocks a truncation attack.
    #[test]
    fn output_length_is_bound_into_the_derivation() {
        let mut short = [0u8; 32];
        let mut long = [0u8; 64];
        kbkdf_counter::<HmacSha256>(b"kdk", b"l", b"c", &mut short).unwrap();
        kbkdf_counter::<HmacSha256>(b"kdk", b"l", b"c", &mut long).unwrap();
        assert_ne!(&long[..32], &short[..]);
    }

    #[test]
    fn blocks_are_distinct() {
        let mut out = [0u8; 96];
        kbkdf_counter::<HmacSha256>(b"kdk", b"l", b"c", &mut out).unwrap();
        assert_ne!(&out[..32], &out[32..64]);
        assert_ne!(&out[32..64], &out[64..]);
    }

    #[test]
    fn rejects_ambiguous_label() {
        let mut out = [0u8; 32];
        assert!(kbkdf_counter::<HmacSha256>(b"kdk", b"a\0b", b"c", &mut out).is_err());
        assert!(kbkdf_counter::<HmacSha256>(b"kdk", b"l", b"c", &mut []).is_err());
    }
}
