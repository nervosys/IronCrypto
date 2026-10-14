//! `safegcd`'s packed divsteps as x86-64 assembly: the same steps on the
//! same packed words, each decision a conditional move.
//!
//! In Rust each step's decisions are masks, and a mask costs a chain of
//! instructions -- the parity, its negation, an `and` -- between `g` and
//! the sum it selects; measured, a step took about eight cycles, the length
//! of that chain, and so did the packed form, whose words are fewer but
//! whose chain is the same. Here both candidate sums are formed while the
//! decisions are made, and `cmov` picks: `g`'s chain is a sum, two moves
//! and a shift, about four cycles. A `cmov` reads its flags and both
//! operands whatever they hold, so nothing branches and nothing is indexed
//! by data.
//!
//! The step counts are the rounds `safegcd` runs: 19 and 5 of Bernstein and
//! Yang's divsteps, 19 and 2 of the half-delta ones. Its tests hold every
//! batch, through these, to the divsteps step by step.

use core::arch::asm;

/// One of Bernstein and Yang's divsteps on the packed `f` and `g`, `delta`
/// in `d`: where `delta > 0` and `g` is odd, `(1 - delta, g, (g - f) / 2)`;
/// otherwise `(1 + delta, f, (g + (g mod 2) f) / 2)`.
macro_rules! by_step {
    () => {
        concat!(
            // The candidates: g + f, g - f; 1 - delta, 1 + delta.
            "lea {t}, [{g} + {f}]\n",
            "mov {s}, {g}\n",
            "sub {s}, {f}\n",
            "mov {a:e}, 1\n",
            "sub {a}, {d}\n",
            "lea {e}, [{d} + 1]\n",
            "mov {c}, {f}\n",
            "mov {b}, {e}\n",
            // delta > 0: the difference, f becomes g, 1 - delta.
            "test {d}, {d}\n",
            "cmovg {t}, {s}\n",
            "cmovg {c}, {g}\n",
            "cmovg {b}, {a}\n",
            // g even: g alone, f stays, 1 + delta.
            "test {g:e}, 1\n",
            "cmovz {t}, {g}\n",
            "cmovz {c}, {f}\n",
            "cmovz {b}, {e}\n",
            "sar {t}, 1\n",
            "mov {f}, {c}\n",
            "mov {g}, {t}\n",
            "mov {d}, {b}\n",
        )
    };
}

/// One half-delta divstep on the packed `f` and `g`, `zeta` in `d`: where
/// `zeta < 0` and `g` is odd, `(-zeta - 2, g, (g - f) / 2)`; otherwise
/// `(zeta - 1, f, (g + (g mod 2) f) / 2)`.
macro_rules! hd_step {
    () => {
        concat!(
            // The candidates: g + f, g - f; -zeta - 2, zeta - 1.
            "lea {t}, [{g} + {f}]\n",
            "mov {s}, {g}\n",
            "sub {s}, {f}\n",
            "mov {a}, {d}\n",
            "not {a}\n",
            "lea {a}, [{a} - 1]\n",
            "lea {e}, [{d} - 1]\n",
            "mov {c}, {f}\n",
            "mov {b}, {e}\n",
            // zeta < 0: the difference, f becomes g, -zeta - 2.
            "test {d}, {d}\n",
            "cmovs {t}, {s}\n",
            "cmovs {c}, {g}\n",
            "cmovs {b}, {a}\n",
            // g even: g alone, f stays, zeta - 1.
            "test {g:e}, 1\n",
            "cmovz {t}, {g}\n",
            "cmovz {c}, {f}\n",
            "cmovz {b}, {e}\n",
            "sar {t}, 1\n",
            "mov {f}, {c}\n",
            "mov {g}, {t}\n",
            "mov {d}, {b}\n",
        )
    };
}

/// Runs of a step, written out.
macro_rules! x2 {
    ($s:ident) => {
        concat!($s!(), $s!())
    };
}
macro_rules! x4 {
    ($s:ident) => {
        concat!(x2!($s), x2!($s))
    };
}
macro_rules! x16 {
    ($s:ident) => {
        concat!(x4!($s), x4!($s), x4!($s), x4!($s))
    };
}

/// A function running `$steps` of one kind on `(d, f, g)`.
macro_rules! runner {
    ($name:ident, $doc:literal, $($body:tt)*) => {
        #[doc = $doc]
        #[inline(always)]
        pub(super) fn $name(d: &mut i64, f: &mut i64, g: &mut i64) {
            // SAFETY: the block reads and writes only the registers it
            // declares, touches no memory and no stack, and needs nothing
            // beyond the x86-64 baseline (`cmov`).
            unsafe {
                asm!(
                    ".p2align 6",
                    $($body)*,
                    d = inout(reg) *d,
                    f = inout(reg) *f,
                    g = inout(reg) *g,
                    t = out(reg) _,
                    s = out(reg) _,
                    a = out(reg) _,
                    e = out(reg) _,
                    c = out(reg) _,
                    b = out(reg) _,
                    options(pure, nomem, nostack),
                );
            }
        }
    };
}

runner!(
    by_19,
    "Nineteen divsteps.",
    x16!(by_step),
    x2!(by_step),
    by_step!()
);
runner!(by_5, "Five divsteps.", x4!(by_step), by_step!());
runner!(
    hd_19,
    "Nineteen half-delta divsteps.",
    x16!(hd_step),
    x2!(hd_step),
    hd_step!()
);
runner!(hd_2, "Two half-delta divsteps.", x2!(hd_step));
