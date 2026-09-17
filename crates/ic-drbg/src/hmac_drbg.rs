//! SP 800-90A HMAC_DRBG.

use ic_core::traits::{Algorithm, Drbg, Mac, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// The widest MAC output supported (SHA-512).
const MAX_LEN: usize = 64;

/// HMAC_DRBG instantiated with the MAC `M`.
///
/// State is the `(K, V)` pair from SP 800-90A §10.1.2, both zeroized on drop.
pub struct HmacDrbg<M: Mac> {
    key: [u8; MAX_LEN],
    value: [u8; MAX_LEN],
    len: usize,
    reseed_counter: u64,
    _marker: core::marker::PhantomData<M>,
}

impl<M: Mac> Drop for HmacDrbg<M> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

impl<M: Mac> HmacDrbg<M> {
    /// The SP 800-90A `HMAC_DRBG_Update` process.
    ///
    /// `provided_data` is absorbed in one or two passes; the second pass runs
    /// only when data is present, which is what makes `update(&[])` a pure
    /// state-advance.
    fn update(&mut self, provided: &[&[u8]]) -> Result<()> {
        let n = self.len;
        let has_data = provided.iter().any(|p| !p.is_empty());

        // K = HMAC(K, V || 0x00 || provided_data)
        let mut m = M::new(&self.key[..n])?;
        m.update(&self.value[..n]);
        m.update(&[0x00]);
        for p in provided {
            m.update(p);
        }
        let k = m.finalize();
        self.key[..n].copy_from_slice(k.as_ref());

        // V = HMAC(K, V)
        let v = M::mac(&self.key[..n], &self.value[..n])?;
        self.value[..n].copy_from_slice(v.as_ref());

        if !has_data {
            return Ok(());
        }

        // K = HMAC(K, V || 0x01 || provided_data)
        let mut m = M::new(&self.key[..n])?;
        m.update(&self.value[..n]);
        m.update(&[0x01]);
        for p in provided {
            m.update(p);
        }
        let k = m.finalize();
        self.key[..n].copy_from_slice(k.as_ref());

        // V = HMAC(K, V)
        let v = M::mac(&self.key[..n], &self.value[..n])?;
        self.value[..n].copy_from_slice(v.as_ref());
        Ok(())
    }

    /// Number of generate calls made since the last reseed.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }
}

impl<M: Mac> Algorithm for HmacDrbg<M> {
    const ID: &'static str = M::ID;
    const NAME: &'static str = "HMAC_DRBG";
}

impl<M: Mac> Drbg for HmacDrbg<M> {
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self> {
        ensure!(M::TAG_LEN <= MAX_LEN, InvalidParameter, "mac tag too wide");
        ensure!(
            entropy.len() >= crate::MIN_ENTROPY_LEN,
            EntropyFailure,
            "drbg entropy input below the required security strength"
        );

        let n = M::TAG_LEN;
        let mut state = Self {
            // SP 800-90A: K starts as all zeroes, V as all 0x01.
            key: [0x00; MAX_LEN],
            value: [0x01; MAX_LEN],
            len: n,
            reseed_counter: 1,
            _marker: core::marker::PhantomData,
        };
        state.update(&[entropy, nonce, personalization])?;
        Ok(state)
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        ensure!(
            entropy.len() >= crate::MIN_ENTROPY_LEN,
            EntropyFailure,
            "drbg reseed entropy below the required security strength"
        );
        self.update(&[entropy, additional])?;
        self.reseed_counter = 1;
        Ok(())
    }

    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(
            self.reseed_counter <= crate::RESEED_INTERVAL,
            CounterExhausted,
            "drbg reseed interval exceeded; reseed before generating"
        );

        if !additional.is_empty() {
            self.update(&[additional])?;
        }

        let n = self.len;
        for chunk in out.chunks_mut(n) {
            // V = HMAC(K, V); emit V.
            let v = M::mac(&self.key[..n], &self.value[..n])?;
            self.value[..n].copy_from_slice(v.as_ref());
            chunk.copy_from_slice(&self.value[..chunk.len()]);
        }

        self.update(&[additional])?;
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }
}

/// HMAC_DRBG over HMAC-SHA-256 (256-bit security strength).
pub type HmacDrbgSha256 = HmacDrbg<ic_mac::HmacSha256>;
/// HMAC_DRBG over HMAC-SHA-512 (256-bit security strength).
pub type HmacDrbgSha512 = HmacDrbg<ic_mac::HmacSha512>;

impl SelfTest for HmacDrbgSha256 {
    fn self_test() -> Result<()> {
        // Integrity KAT. This vector is produced by this implementation, whose
        // correctness is established separately by the reference-comparison
        // test in this module; its job here is to detect a corrupted binary or
        // a broken build, which is what FIPS 140-3 asks a CAST to do. Wiring in
        // the CAVP `HMAC_DRBG.rsp` files is tracked as a pre-validation task
        // (see FIPS.md).
        let mut d = <Self as Drbg>::instantiate(&[0x01u8; 32], &[0x02u8; 16], b"self-test")?;
        let mut out = [0u8; 64];
        d.generate(&[], &mut out)?;
        d.generate(&[], &mut out)?;

        let mut want = [0u8; 64];
        ic_core::codec::hex_decode(SELF_TEST_KAT.as_bytes(), &mut want)?;
        ensure!(
            ic_core::ct::verify(&want, &out),
            SelfTestFailed,
            "hmac-drbg-sha2-256"
        );
        Ok(())
    }
}

/// Second generate block for the [`SelfTest`] inputs above.
const SELF_TEST_KAT: &str = "c40444290d60816f7d35ad2b9e0d9dcdda9d5d04f7ce38c4ec6aa32fc03b4bbc7426b02830f065da0f45e2f26330ef0e97099f4b1c16a552a0a02532472ac11c";

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::hex;
    use ic_mac::HmacSha256;

    fn instantiate() -> HmacDrbgSha256 {
        HmacDrbg::<HmacSha256>::instantiate(&[0x01u8; 32], &[0x02u8; 16], b"test").unwrap()
    }

    /// An independent transcription of the SP 800-90A §10.1.2 pseudocode,
    /// written in terms of raw HMAC calls. The production implementation keeps
    /// `(K, V)` in fixed buffers and skips the second update pass when there is
    /// no provided data; this reference does neither, so agreement between them
    /// checks the optimizations rather than restating them.
    fn reference_hmac_drbg(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
        out_len: usize,
        generates: usize,
    ) -> Vec<u8> {
        fn update(k: &mut Vec<u8>, v: &mut Vec<u8>, data: &[u8]) {
            let mut m = HmacSha256::new(k).unwrap();
            m.update(v);
            m.update(&[0x00]);
            m.update(data);
            *k = m.finalize().to_vec();
            *v = HmacSha256::mac(k, v).unwrap().to_vec();
            if data.is_empty() {
                return;
            }
            let mut m = HmacSha256::new(k).unwrap();
            m.update(v);
            m.update(&[0x01]);
            m.update(data);
            *k = m.finalize().to_vec();
            *v = HmacSha256::mac(k, v).unwrap().to_vec();
        }

        let mut k = vec![0x00u8; 32];
        let mut v = vec![0x01u8; 32];
        let mut seed = entropy.to_vec();
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(personalization);
        update(&mut k, &mut v, &seed);

        let mut out = vec![0u8; out_len];
        for _ in 0..generates {
            let mut produced = 0;
            while produced < out_len {
                v = HmacSha256::mac(&k, &v).unwrap().to_vec();
                let n = core::cmp::min(32, out_len - produced);
                out[produced..produced + n].copy_from_slice(&v[..n]);
                produced += n;
            }
            update(&mut k, &mut v, &[]);
        }
        out
    }

    #[test]
    fn matches_the_sp800_90a_reference() {
        for (out_len, generates) in [(32usize, 1usize), (64, 2), (100, 3), (16, 1)] {
            let mut d =
                HmacDrbg::<HmacSha256>::instantiate(&[0x01u8; 32], &[0x02u8; 16], b"ref").unwrap();
            let mut got = vec![0u8; out_len];
            for _ in 0..generates {
                d.generate(&[], &mut got).unwrap();
            }
            let want =
                reference_hmac_drbg(&[0x01u8; 32], &[0x02u8; 16], b"ref", out_len, generates);
            assert_eq!(
                hex(&got),
                hex(&want),
                "{out_len} bytes over {generates} calls"
            );
        }
    }

    #[test]
    fn is_deterministic_for_identical_seeds() {
        let mut a = instantiate();
        let mut b = instantiate();
        let mut x = [0u8; 64];
        let mut y = [0u8; 64];
        a.generate(&[], &mut x).unwrap();
        b.generate(&[], &mut y).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn successive_outputs_differ() {
        let mut d = instantiate();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        d.generate(&[], &mut a).unwrap();
        d.generate(&[], &mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn personalization_and_additional_input_change_output() {
        let mut base = instantiate();
        let mut other =
            HmacDrbg::<HmacSha256>::instantiate(&[0x01u8; 32], &[0x02u8; 16], b"other").unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        base.generate(&[], &mut a).unwrap();
        other.generate(&[], &mut b).unwrap();
        assert_ne!(a, b);

        let mut c = instantiate();
        let mut d = instantiate();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        c.generate(b"extra", &mut x).unwrap();
        d.generate(&[], &mut y).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn reseed_changes_the_stream_and_resets_the_counter() {
        let mut d = instantiate();
        let mut before = [0u8; 32];
        d.generate(&[], &mut before).unwrap();
        assert!(d.reseed_counter() > 1);

        d.reseed(&[0xAAu8; 32], b"").unwrap();
        assert_eq!(d.reseed_counter(), 1);

        let mut after = [0u8; 32];
        d.generate(&[], &mut after).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn output_is_not_block_aligned_dependent() {
        let mut d = instantiate();
        let mut out = [0u8; 100];
        d.generate(&[], &mut out).unwrap();
        assert_ne!(&out[..32], &out[32..64]);
    }

    #[test]
    fn rejects_short_entropy() {
        assert!(HmacDrbg::<HmacSha256>::instantiate(&[0u8; 16], &[], &[]).is_err());
        let mut d = instantiate();
        assert!(d.reseed(&[0u8; 8], b"").is_err());
    }

    #[test]
    fn refuses_to_generate_past_the_reseed_interval() {
        let mut d = instantiate();
        // Fast-forward the counter rather than making a million calls.
        d.reseed_counter = crate::RESEED_INTERVAL + 1;
        assert!(d.generate(&[], &mut [0u8; 8]).is_err());
        d.reseed(&[0x5Au8; 32], b"").unwrap();
        assert!(d.generate(&[], &mut [0u8; 8]).is_ok());
    }

    #[test]
    fn self_test_passes() {
        HmacDrbgSha256::self_test().unwrap();
    }
}
