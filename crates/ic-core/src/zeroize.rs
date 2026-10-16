//! Secret erasure.
//!
//! [`Zeroizing`] wipes its contents on drop using volatile writes plus a
//! compiler fence, so the erasure survives optimization. This is the mechanism
//! behind the FIPS 140-3 zeroisation requirement for CSPs held in memory.

use core::mem::MaybeUninit;
use core::sync::atomic::{compiler_fence, Ordering};

/// Types whose in-memory representation can be securely erased.
pub trait Zeroize {
    /// Overwrite `self` with zeroes using non-elidable volatile writes.
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    /// Eight bytes per volatile store, then the tail a byte at a time.
    ///
    /// A volatile store of a `[u8; 8]` is exactly as non-elidable as eight
    /// volatile byte stores, and is one store rather than eight. That matters
    /// because wipes are on hot paths: every SHA-2 state wipes its buffered
    /// block when dropped, and HMAC drops two per tag, so byte-at-a-time
    /// wiping was a measurable share of a short HMAC. `[u8; 8]` has the
    /// alignment of `u8`, so the pointer cast needs nothing a byte slice
    /// does not already guarantee, and no temporary larger than eight bytes
    /// is involved -- which a single store of the whole array would need.
    fn zeroize(&mut self) {
        let mut chunks = self.chunks_exact_mut(8);
        for chunk in &mut chunks {
            // SAFETY: `chunk` is exactly eight valid, uniquely-borrowed bytes,
            // and `[u8; 8]` has alignment 1.
            unsafe { core::ptr::write_volatile(chunk.as_mut_ptr() as *mut [u8; 8], [0u8; 8]) };
        }
        for byte in chunks.into_remainder() {
            // SAFETY: `byte` is a valid, aligned, uniquely-borrowed `u8`.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for [u32] {
    fn zeroize(&mut self) {
        for w in self.iter_mut() {
            // SAFETY: `w` is a valid, aligned, uniquely-borrowed `u32`.
            unsafe { core::ptr::write_volatile(w, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for [u64] {
    fn zeroize(&mut self) {
        for w in self.iter_mut() {
            // SAFETY: `w` is a valid, aligned, uniquely-borrowed `u64`.
            unsafe { core::ptr::write_volatile(w, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "std")]
impl Zeroize for std::vec::Vec<u8> {
    /// The vector's bytes, through the slice wipe. The length and capacity
    /// are left as they are; only the contents are secret.
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<const N: usize> Zeroize for [u32; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<const N: usize> Zeroize for [u64; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

/// Overwrites the `N` bytes of stack directly below the caller's frame, at the
/// point of the call, with zeros. Best effort; defence in depth.
///
/// Call it from a function `C` after a deeper call chain below `C` has
/// returned. Those callees' frames were allocated at the stack pointer `C` had
/// when it made its call, so the dead frames lie where `stack_scrub` now
/// lives: its own local buffer sits in the `N` bytes (plus its return address
/// and any alignment) immediately below `C`'s stack pointer, and the volatile
/// stores zero it. The idea is libsodium's `sodium_stackzero`.
///
/// What it guarantees: the buffer's `N` bytes are written with non-elidable
/// volatile stores and then a compiler fence, so they are zero when the
/// function returns, whatever the optimiser would otherwise do with a buffer
/// that is never read.
///
/// What it does not guarantee:
///
/// - It reaches only the `N` bytes below the caller. A dead frame deeper than
///   `N` keeps its bytes. `N` must cover the deepest path from the caller
///   that could have held the secret, with margin.
/// - It relies on the dead frames having been in that region. A frame placed
///   elsewhere (another caller's stack, a heap copy) is not reached.
/// - It cannot reach registers. A secret left in a vector or general register
///   is untouched.
/// - It is not a proof that no copy exists. Only the stack region the callees
///   used is cleared; a copy the caller made, or one in a spill slot that a
///   later call overwrote with other data, is not something this can see.
///
/// It is a hardening measure against later disclosure of dead stack memory.
/// It is not a constant-time property and does not change any result.
#[inline(never)]
pub fn stack_scrub<const N: usize>() {
    let mut buf = MaybeUninit::<[u8; N]>::uninit();
    // SAFETY: `buf` is `N` bytes of writable storage owned by this frame, and
    // the pointer is valid for `N` bytes for the length of the call.
    unsafe { wipe_raw(buf.as_mut_ptr().cast::<u8>(), N) };
    // The buffer is never read. Its stores are volatile, so they are not
    // removed as dead, and the fence keeps them ordered before the return.
}

/// Writes zeros over `n` bytes at `p`, with volatile stores, then fences.
///
/// # Safety
///
/// `p` must be valid for writes of `n` bytes for the duration of the call.
#[inline(always)]
unsafe fn wipe_raw(p: *mut u8, n: usize) {
    // Sixteen bytes per volatile store, which is one 128-bit store on every
    // target this builds for, so a 32 KiB scrub is 2048 stores, not 4096.
    let mut i = 0;
    while i + 16 <= n {
        // SAFETY: `i + 16 <= n`, so these sixteen bytes lie inside the `n`
        // bytes the caller promised; `[u8; 16]` has alignment 1.
        unsafe { core::ptr::write_volatile(p.add(i).cast::<[u8; 16]>(), [0u8; 16]) };
        i += 16;
    }
    while i + 8 <= n {
        // SAFETY: `i + 8 <= n`, as above.
        unsafe { core::ptr::write_volatile(p.add(i).cast::<[u8; 8]>(), [0u8; 8]) };
        i += 8;
    }
    while i < n {
        // SAFETY: `i < n`, inside the caller's `n` bytes.
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// A wrapper that zeroizes its contents when dropped.
///
/// ```
/// use ic_core::Zeroizing;
/// let mut key = Zeroizing::new([0u8; 32]);
/// key[0] = 0x42;
/// assert_eq!(key[0], 0x42);
/// // `key` is wiped when it leaves scope.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Wrap a value so it is erased on drop.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the protected value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// Mutably borrow the protected value.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_are_wiped() {
        let mut buf = [1u8, 2, 3, 4];
        buf.zeroize();
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn zeroizing_derefs() {
        let mut z = Zeroizing::new([7u8; 8]);
        assert_eq!(z[0], 7);
        z[0] = 9;
        assert_eq!(z.get()[0], 9);
    }

    #[test]
    fn eight_byte_chunks_and_the_tail_are_wiped_and_nothing_else() {
        // Two whole chunks and a three-byte tail, inside a larger array whose
        // bytes either side must survive: a chunked wipe that overran its
        // slice would zero them.
        let mut buf = [0xa5u8; 32];
        buf[5..24].zeroize();
        assert_eq!(&buf[..5], &[0xa5; 5]);
        assert_eq!(&buf[5..24], &[0u8; 19]);
        assert_eq!(&buf[24..], &[0xa5; 8]);
        for len in 0..=17 {
            let mut v = [0xffu8; 17];
            v[..len].zeroize();
            assert!(v[..len].iter().all(|&b| b == 0), "length {len}");
            assert!(v[len..].iter().all(|&b| b == 0xff), "length {len}");
        }
    }

    #[test]
    fn raw_wipe_zeroes_exactly_its_range() {
        // Every length up to two chunks and a tail, inside a buffer whose
        // bytes either side must survive. If the volatile stores were removed
        // the range would keep its pattern and this would fail.
        for n in 0..=19 {
            let mut buf = [0xa5u8; 24];
            // SAFETY: `buf` is 24 valid bytes and `2 + n <= 21`, so the range
            // `2..2 + n` lies inside it.
            unsafe { wipe_raw(buf.as_mut_ptr().add(2), n) };
            assert!(
                buf[..2].iter().all(|&b| b == 0xa5),
                "length {n}: leading guard"
            );
            assert!(
                buf[2..2 + n].iter().all(|&b| b == 0),
                "length {n}: range not zeroed"
            );
            assert!(
                buf[2 + n..].iter().all(|&b| b == 0xa5),
                "length {n}: trailing guard"
            );
        }
    }

    #[test]
    fn stack_scrub_returns_at_several_sizes() {
        // Its effect is on the stack below this frame, which no safe test can
        // read. This checks that each size compiles and returns.
        stack_scrub::<0>();
        stack_scrub::<7>();
        stack_scrub::<4096>();
    }

    #[test]
    fn word_slices_are_wiped() {
        let mut w = [0xDEAD_BEEFu32; 4];
        w.zeroize();
        assert_eq!(w, [0u32; 4]);
        let mut q = [0xDEAD_BEEF_CAFE_F00Du64; 2];
        q.zeroize();
        assert_eq!(q, [0u64; 2]);
    }
}
