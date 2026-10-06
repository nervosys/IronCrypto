//! An AEAD that chooses its own nonces.
//!
//! Every [`Aead`] takes a nonce from its caller, and under AES-GCM or
//! ChaCha20-Poly1305 a nonce used twice under one key is catastrophic: GCM
//! leaks its authentication subkey, ChaCha20 XORs the two plaintexts. The rule
//! is easy to state and easy to break, because nothing in `seal_detached`'s
//! signature tells you that the bytes you pass it are the dangerous ones.
//!
//! [`Sealer`] takes the nonce out of the caller's hands. It builds each one as
//! SP 800-38D section 8.2.1's deterministic construction does: a 4-byte fixed
//! field naming the sender, then a 64-bit invocation counter, big-endian. It
//! returns the nonce it used, so the receiver can be sent it. It refuses rather
//! than wrap when the counter runs out.
//!
//! [`Opener`] is the receiving side. It accepts only the sender's fixed field
//! and only counters it has not passed, so a replayed or reordered message is
//! refused before the AEAD runs.
//!
//! ```
//! use ic_cipher::{Aes256Gcm, sealer::{Opener, Sealer}};
//!
//! // A key for this session only: from a key exchange and a KDF, not a constant.
//! let key = [0x2a; 32];
//! let mut tx = Sealer::<Aes256Gcm>::new(&key, *b"c->s")?;
//! let mut rx = Opener::<Aes256Gcm>::new(&key, *b"c->s")?;
//!
//! let mut msg = *b"ship it";
//! let mut tag = [0u8; 16];
//! let nonce = tx.seal(b"header", &mut msg, &mut tag)?;
//! rx.open(&nonce, b"header", &mut msg, &tag)?;
//! assert_eq!(&msg, b"ship it");
//!
//! // The same message again is a replay, and is refused.
//! assert!(rx.open(&nonce, b"header", &mut msg, &tag).is_err());
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! ## What the counter cannot know
//!
//! A counter is unique only within the object that holds it. Two `Sealer`s on
//! the same key and fixed field both start at zero and reuse every nonce, and a
//! process that restarts and builds a new one does the same. So:
//!
//! - **Use a key that lives no longer than its `Sealer`**: one derived for the
//!   session, as TLS 1.3 and HPKE do. A long-lived key needs the counter
//!   persisted and restored with [`Sealer::resume`], or a nonce-misuse-resistant
//!   AEAD such as AES-256-GCM-SIV.
//! - **Give every sender under one key its own fixed field**, such as one per
//!   direction. Better still, give each direction its own key.
//!
//! The 12-byte nonce is required: it is the length every AEAD here takes and
//! the one SP 800-38D's construction is defined for.

use core::fmt;
use ic_core::traits::Aead;
use ic_core::{ensure, Result};

/// The nonce length a sealer builds: a 4-byte fixed field and an 8-byte counter.
pub const NONCE_LEN: usize = 12;

/// The fixed field's length.
pub const FIXED_LEN: usize = 4;

/// Assemble `fixed || counter`, refusing the last counter value so that a
/// sealer which has used it cannot wrap.
fn nonce(fixed: &[u8; FIXED_LEN], counter: u64) -> Result<[u8; NONCE_LEN]> {
    ensure!(
        counter != u64::MAX,
        CounterExhausted,
        "sealer counter exhausted; it never reuses a nonce"
    );
    let mut n = [0u8; NONCE_LEN];
    n[..FIXED_LEN].copy_from_slice(fixed);
    n[FIXED_LEN..].copy_from_slice(&counter.to_be_bytes());
    Ok(n)
}

/// Check that `A` takes the 12-byte nonce this construction builds.
fn check_nonce_len<A: Aead>() -> Result<()> {
    ensure!(
        A::NONCE_LEN == NONCE_LEN,
        Unsupported,
        "sealer needs an AEAD with a 12-byte nonce"
    );
    Ok(())
}

/// Seals messages under nonces it builds itself, each used once.
pub struct Sealer<A: Aead> {
    aead: A,
    fixed: [u8; FIXED_LEN],
    counter: u64,
}

impl<A: Aead> Sealer<A> {
    /// A sealer whose first nonce is `fixed || 0`.
    ///
    /// `fixed` names this sender. Any other party sealing under `key` must use
    /// a different one.
    pub fn new(key: &[u8], fixed: [u8; FIXED_LEN]) -> Result<Self> {
        Self::resume(key, fixed, 0)
    }

    /// A sealer that continues from `counter`, the value a previous sealer on
    /// this key and fixed field reported from [`Sealer::counter`] when it was
    /// last used.
    ///
    /// Restoring a counter lower than one already used reuses nonces. Persist
    /// the counter before sending what it sealed, not after.
    pub fn resume(key: &[u8], fixed: [u8; FIXED_LEN], counter: u64) -> Result<Self> {
        check_nonce_len::<A>()?;
        Ok(Self {
            aead: A::new(key)?,
            fixed,
            counter,
        })
    }

    /// The counter the next seal will use.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Encrypt `in_out` in place, write the tag, and return the nonce used.
    ///
    /// The receiver needs the nonce, or the counter, to open the message. On
    /// failure the counter does not advance.
    pub fn seal(
        &mut self,
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<[u8; NONCE_LEN]> {
        let n = nonce(&self.fixed, self.counter)?;
        self.aead.seal_detached(&n, aad, in_out, tag)?;
        self.counter += 1;
        Ok(n)
    }
}

impl<A: Aead> fmt::Debug for Sealer<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("fixed", &self.fixed)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

/// Opens messages from one [`Sealer`], refusing replays and reordering.
pub struct Opener<A: Aead> {
    aead: A,
    fixed: [u8; FIXED_LEN],
    next: u64,
}

impl<A: Aead> Opener<A> {
    /// An opener for the sender whose fixed field is `fixed`.
    pub fn new(key: &[u8], fixed: [u8; FIXED_LEN]) -> Result<Self> {
        check_nonce_len::<A>()?;
        Ok(Self {
            aead: A::new(key)?,
            fixed,
            next: 0,
        })
    }

    /// The lowest counter the next open will accept.
    pub fn next_counter(&self) -> u64 {
        self.next
    }

    /// Verify and decrypt `in_out` in place.
    ///
    /// Refuses a nonce with another sender's fixed field, or a counter lower
    /// than the last one opened plus one, before the AEAD runs. Counters may
    /// skip forward, so a lost message does not stall the stream, but never go
    /// back. On any failure the accepted counter does not advance, and
    /// `in_out` holds no unauthenticated plaintext.
    pub fn open(&mut self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<()> {
        ensure!(
            nonce.len() == NONCE_LEN,
            InvalidLength,
            "sealer nonce must be 12 bytes"
        );
        // Neither the fixed field nor the counter is secret: both travel in
        // the clear beside the ciphertext.
        ensure!(
            nonce[..FIXED_LEN] == self.fixed,
            AuthenticationFailed,
            "sealer nonce is from another sender"
        );
        let mut c = [0u8; 8];
        c.copy_from_slice(&nonce[FIXED_LEN..]);
        let counter = u64::from_be_bytes(c);
        ensure!(
            counter >= self.next && counter != u64::MAX,
            AuthenticationFailed,
            "sealer nonce replayed or out of order"
        );
        self.aead.open_detached(nonce, aad, in_out, tag)?;
        self.next = counter + 1;
        Ok(())
    }
}

impl<A: Aead> fmt::Debug for Opener<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("fixed", &self.fixed)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Aes128Gcm, Aes256Gcm, Aes256GcmSiv, ChaCha20Poly1305};
    use ic_core::ErrorKind;

    const KEY: [u8; 32] = [7; 32];

    fn seal_one<A: Aead>(tx: &mut Sealer<A>, msg: &[u8]) -> ([u8; NONCE_LEN], [u8; 64], [u8; 16]) {
        let mut buf = [0u8; 64];
        buf[..msg.len()].copy_from_slice(msg);
        let mut tag = [0u8; 16];
        let n = tx.seal(b"aad", &mut buf[..msg.len()], &mut tag).unwrap();
        (n, buf, tag)
    }

    /// The nonce is `fixed || counter` big-endian, and the counter advances
    /// by one per seal: SP 800-38D 8.2.1's deterministic construction.
    #[test]
    fn nonces_are_the_fixed_field_then_a_counter() {
        let mut tx = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        for i in 0..3u64 {
            let (n, _, _) = seal_one(&mut tx, b"m");
            assert_eq!(&n[..4], b"abcd");
            assert_eq!(n[4..], i.to_be_bytes());
        }
        assert_eq!(tx.counter(), 3);
    }

    /// What a sealer produces is what the bare AEAD produces under the nonce
    /// it reports, so it adds no format of its own.
    #[test]
    fn a_seal_is_the_bare_aead_under_the_reported_nonce() {
        let mut tx = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        seal_one(&mut tx, b"first");
        let (n, ct, tag) = seal_one(&mut tx, b"second");
        let bare = Aes256Gcm::new(&KEY).unwrap();
        let mut buf = *b"second";
        let mut t = [0u8; 16];
        bare.seal_detached(&n, b"aad", &mut buf, &mut t).unwrap();
        assert_eq!(&ct[..6], &buf);
        assert_eq!(tag, t);
    }

    #[test]
    fn every_twelve_byte_aead_round_trips() {
        fn round<A: Aead>() {
            let key = [9u8; 32];
            let key = &key[..A::KEY_LEN];
            let mut tx = Sealer::<A>::new(key, *b"wxyz").unwrap();
            let mut rx = Opener::<A>::new(key, *b"wxyz").unwrap();
            for _ in 0..3 {
                let (n, mut ct, tag) = seal_one(&mut tx, b"hello");
                rx.open(&n, b"aad", &mut ct[..5], &tag).unwrap();
                assert_eq!(&ct[..5], b"hello");
            }
        }
        round::<Aes128Gcm>();
        round::<Aes256Gcm>();
        round::<ChaCha20Poly1305>();
        round::<Aes256GcmSiv>();
    }

    #[test]
    fn a_replay_or_an_earlier_counter_is_refused() {
        let mut tx = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        let mut rx = Opener::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        let (n0, ct0, t0) = seal_one(&mut tx, b"zero");
        let (n1, ct1, t1) = seal_one(&mut tx, b"one!");
        let mut buf = ct1;
        rx.open(&n1, b"aad", &mut buf[..4], &t1).unwrap();
        assert_eq!(rx.next_counter(), 2);
        // The same message again: a replay.
        let mut buf = ct1;
        let e = rx.open(&n1, b"aad", &mut buf[..4], &t1).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AuthenticationFailed);
        // Counter 0 arriving late: refused, though authentic.
        let mut buf = ct0;
        let e = rx.open(&n0, b"aad", &mut buf[..4], &t0).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AuthenticationFailed);
        assert_eq!(rx.next_counter(), 2, "a refusal does not move the window");
    }

    #[test]
    fn a_skipped_counter_is_accepted_so_a_lost_message_does_not_stall() {
        let mut tx = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        let mut rx = Opener::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        seal_one(&mut tx, b"lost");
        let (n, mut ct, t) = seal_one(&mut tx, b"kept");
        rx.open(&n, b"aad", &mut ct[..4], &t).unwrap();
        assert_eq!(&ct[..4], b"kept");
    }

    #[test]
    fn another_senders_fixed_field_is_refused() {
        let mut tx = Sealer::<Aes256Gcm>::new(&KEY, *b"s->c").unwrap();
        let mut rx = Opener::<Aes256Gcm>::new(&KEY, *b"c->s").unwrap();
        let (n, mut ct, t) = seal_one(&mut tx, b"hi");
        assert!(rx.open(&n, b"aad", &mut ct[..2], &t).is_err());
        assert_eq!(rx.next_counter(), 0);
    }

    #[test]
    fn a_forgery_does_not_advance_the_opener() {
        let mut tx = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        let mut rx = Opener::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        let (n, mut ct, mut t) = seal_one(&mut tx, b"hi");
        t[0] ^= 1;
        assert!(rx.open(&n, b"aad", &mut ct[..2], &t).is_err());
        assert_eq!(rx.next_counter(), 0);
    }

    /// The last counter value is never used, so a sealer cannot wrap to zero.
    #[test]
    fn an_exhausted_sealer_refuses_rather_than_wrapping() {
        let mut tx = Sealer::<Aes256Gcm>::resume(&KEY, *b"abcd", u64::MAX - 1).unwrap();
        seal_one(&mut tx, b"last");
        let mut buf = *b"over";
        let mut tag = [0u8; 16];
        let e = tx.seal(b"", &mut buf, &mut tag).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::CounterExhausted);
        assert_eq!(tx.counter(), u64::MAX);
    }

    #[test]
    fn resume_continues_where_the_last_sealer_stopped() {
        let mut a = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        seal_one(&mut a, b"0");
        seal_one(&mut a, b"1");
        let mut b = Sealer::<Aes256Gcm>::resume(&KEY, *b"abcd", a.counter()).unwrap();
        let (n, _, _) = seal_one(&mut b, b"2");
        assert_eq!(n[4..], 2u64.to_be_bytes());
    }

    #[test]
    fn debug_shows_no_key() {
        let tx = Sealer::<Aes256Gcm>::new(&KEY, *b"abcd").unwrap();
        let s = format!("{tx:?}");
        assert!(s.contains("counter") && !s.contains("aead"), "{s}");
    }
}
