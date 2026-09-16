//! Secret erasure.
//!
//! [`Zeroizing`] wipes its contents on drop using volatile writes plus a
//! compiler fence, so the erasure survives optimization. This is the mechanism
//! behind the FIPS 140-3 zeroisation requirement for CSPs held in memory.

use core::sync::atomic::{compiler_fence, Ordering};

/// Types whose in-memory representation can be securely erased.
pub trait Zeroize {
    /// Overwrite `self` with zeroes using non-elidable volatile writes.
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
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

/// A wrapper that zeroizes its contents when dropped.
///
/// ```
/// use ac_core::Zeroizing;
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
    fn word_slices_are_wiped() {
        let mut w = [0xDEAD_BEEFu32; 4];
        w.zeroize();
        assert_eq!(w, [0u32; 4]);
        let mut q = [0xDEAD_BEEF_CAFE_F00Du64; 2];
        q.zeroize();
        assert_eq!(q, [0u64; 2]);
    }
}
