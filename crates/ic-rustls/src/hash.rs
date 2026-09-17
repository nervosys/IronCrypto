//! SHA-2 for rustls.
//!
//! TLS 1.3 uses the handshake hash for the transcript, for the key schedule,
//! and for the Finished verification, so this is on the path of every
//! connection rather than off to one side.
//!
//! Only SHA-256 and SHA-384 are here because those are the two the TLS 1.3
//! cipher suites name. `ic-hash` has the rest of the family; nothing in TLS
//! asks for them.

use alloc::boxed::Box;

use ic_core::traits::Digest;
use rustls::crypto::hash::{self, HashAlgorithm};

pub(crate) static SHA256: Hash<ic_hash::Sha256> = Hash::new(HashAlgorithm::SHA256);
pub(crate) static SHA384: Hash<ic_hash::Sha384> = Hash::new(HashAlgorithm::SHA384);

/// One of IronCrypto's digests, presented as a rustls hash.
pub(crate) struct Hash<D: Digest> {
    algorithm: HashAlgorithm,
    // `fn() -> D` rather than `D`: this is Send and Sync for any D, so the
    // provider can be shared between connections without an unsafe impl.
    _digest: core::marker::PhantomData<fn() -> D>,
}

impl<D: Digest> Hash<D> {
    const fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            _digest: core::marker::PhantomData,
        }
    }
}

impl<D: Digest + Send + Sync + 'static> hash::Hash for Hash<D> {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Context(D::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut d = D::new();
        d.update(data);
        hash::Output::new(d.finalize().as_ref())
    }

    fn output_len(&self) -> usize {
        D::OUTPUT_LEN
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Always false.
    ///
    /// rustls asks whether the implementation is FIPS-*validated*, which is a
    /// certificate, not a property of the code. IronCrypto holds none, and
    /// answering anything else here would put a false claim into a TLS stack's
    /// own reporting. See `ic_ontology::runtime::has("fips-validated")`, which
    /// returns false for the same reason.
    fn fips(&self) -> bool {
        false
    }
}

/// An in-progress hash.
///
/// rustls forks the transcript hash rather than finishing it -- the same prefix
/// is used for several different computations during a handshake -- so `D` must
/// be `Clone`, which the `Digest` trait requires.
struct Context<D: Digest>(D);

impl<D: Digest + Send + Sync + 'static> hash::Context for Context<D> {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(self.0.clone().finalize().as_ref())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(self.0.finalize().as_ref())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hash::Hash as _;

    /// The adapter must produce what the algorithm produces.
    ///
    /// Checked against the FIPS 180-4 value for "abc" rather than against
    /// `ic_hash` -- comparing the adapter to the thing it wraps would pass
    /// however wrong both were together.
    #[test]
    fn the_adapter_hashes_what_the_algorithm_hashes() {
        let out = SHA256.hash(b"abc");
        assert_eq!(
            ic_core::codec::hex(out.as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let out = SHA384.hash(b"abc");
        assert_eq!(
            ic_core::codec::hex(out.as_ref()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    /// Forking must produce the same answer as hashing the prefix directly,
    /// because the transcript hash depends on it.
    #[test]
    fn a_forked_context_continues_the_same_computation() {
        let mut ctx = SHA256.start();
        ctx.update(b"abc");

        // The fork and the original must agree at this point,
        let forked = ctx.fork();
        assert_eq!(ctx.fork_finish().as_ref(), forked.fork_finish().as_ref());
        assert_eq!(
            ic_core::codec::hex(ctx.fork_finish().as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // and must then diverge independently, rather than sharing state.
        let mut a = ctx.fork();
        let mut b = ctx.fork();
        a.update(b"d");
        b.update(b"e");
        assert_ne!(a.fork_finish().as_ref(), b.fork_finish().as_ref());

        // The original is unchanged by either.
        assert_eq!(
            ic_core::codec::hex(ctx.fork_finish().as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_declared_lengths_are_right() {
        assert_eq!(SHA256.output_len(), 32);
        assert_eq!(SHA384.output_len(), 48);
        assert_eq!(SHA256.hash(b"").as_ref().len(), 32);
        assert_eq!(SHA384.hash(b"").as_ref().len(), 48);
    }

    /// Nothing here may claim validation.
    #[test]
    fn neither_hash_claims_fips_validation() {
        assert!(!SHA256.fips());
        assert!(!SHA384.fips());
    }
}
