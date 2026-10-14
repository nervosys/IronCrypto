//! Scratch arrays on the SHA-NI short paths, wiped when they leave scope.
//!
//! A padded tail holds the end of the message, and a pad holds the key; both
//! are secret when the input is. Wiping them with a `zeroize` call at the end
//! of a function misses every return that comes before the call, and a
//! mutation that deletes the call passes every test, because no test can read
//! a stack buffer after its frame is gone. [`Scratch`] makes the wipe its
//! `Drop`, so it runs on every way out of the scope that holds it.
//!
//! The test build also records, at each drop, whether the array was clear
//! after the wipe. A `Drop` that does not wipe leaves the padding's `0x80` or
//! the key's pad bytes in place, and the tests in `sha2.rs` fail on that.
//! Nothing here is compiled into a release build except the guard itself.

use core::ops::{Deref, DerefMut};

use ic_core::Zeroize;

/// A value that is wiped when the [`Scratch`] holding it is dropped.
pub(super) struct Scratch<T: Zeroize + Scrub>(T);

impl<T: Zeroize + Scrub> Scratch<T> {
    pub(super) fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Zeroize + Scrub> Deref for Scratch<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize + Scrub> DerefMut for Scratch<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize + Scrub> Drop for Scratch<T> {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        probe::record(self.0.is_clear());
    }
}

/// The arrays a [`Scratch`] can hold. `is_clear` exists only for the probe.
pub(super) trait Scrub {
    #[cfg(test)]
    fn is_clear(&self) -> bool;
}

impl<const N: usize> Scrub for [u8; N] {
    #[cfg(test)]
    fn is_clear(&self) -> bool {
        self.iter().all(|&b| b == 0)
    }
}

impl<const N: usize> Scrub for [u32; N] {
    #[cfg(test)]
    fn is_clear(&self) -> bool {
        self.iter().all(|&w| w == 0)
    }
}

/// Test-only record of every [`Scratch`] drop on this thread.
#[cfg(test)]
pub(super) mod probe {
    use core::cell::Cell;

    thread_local! {
        static DROPS: Cell<usize> = const { Cell::new(0) };
        static DIRTY: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn record(clear: bool) {
        DROPS.with(|c| c.set(c.get() + 1));
        if !clear {
            DIRTY.with(|c| c.set(c.get() + 1));
        }
    }

    /// Clears the record. Call at the start of a test.
    pub(crate) fn reset() {
        DROPS.with(|c| c.set(0));
        DIRTY.with(|c| c.set(0));
    }

    /// `(drops, drops that found their array not clear)` since [`reset`].
    pub(crate) fn snapshot() -> (usize, usize) {
        (DROPS.with(Cell::get), DIRTY.with(Cell::get))
    }
}
