"""Generate crates/ic-ec/src/nist/p384_x86_point.rs: P-384's field operations
and point formulas as Rust `asm!` blocks over MULX/ADX.

    python scripts/gen_p384_x86_point.py crates/ic-ec/src/nist/p384_x86_point.rs

The counterpart of scripts/gen_p256_x86_point.py for P-384. The field
operations are specialised to the prime p = 2^384 - 2^128 - 2^96 + 2^32 - 1:

- Montgomery reduction, one word at a time. `-p^-1 mod 2^64` is 2^32 + 1, so
  the word's multiplier is `w = t0 + (t0 << 32)`, a shift and an addition.
  Adding `w * p` is adding `w * 2^384` and subtracting `w * (2^384 - p)`, and
  `2^384 - p = 2^128 + 2^96 - 2^32 + 1` is short: two `mulx` by constants
  give its product with `w`, where a generic modulus takes six. That
  product's low word equals `t0`, so the low word cancels exactly and is
  dropped.
- Multiplication: rows of `a * b_i` on two carry chains (`adcx`/`adox`), each
  followed by that reduction of the window's low word. The same function as
  CIOS: the multiplier of each word is the unique one that clears it.
- Squaring: the fifteen cross products once, doubled, plus the six squares:
  21 `mulx` where multiplication takes 36. The high half of the 768-bit
  square waits in the scratch slot while the low half is reduced, and is
  then added back.
- The last correction subtracts p by adding `2^384 - p` and, where that did
  not carry out of the top word, subtracting it again through a mask: no
  branch, no table, no copy through memory.
- Addition corrects the same way; subtraction adds p through a mask made from
  the borrow.

Each formula is a list of those operations on 48-byte slots in one buffer
whose address is in `{s}`; every operation reads its operands before writing
its result. The formulas are those of crates/ic-ec/src/nist/point.rs,
operation for operation, so the results agree bit for bit, which the tests
check. The four field operations are emitted on their own too: `Fp` uses the
multiplication and squaring, and the tests hold each of them to the generic
arithmetic.
"""
import sys

N = 6
SLOT = 8 * N

# The low and high words of 2^96 - 2^32 + 1, which with 2^128 makes
# 2^384 - p.
K_LO = "0xffffffff00000001"
K_HI = "0xffffffff"


def addr(slot, word):
    off = SLOT * slot + 8 * word
    return f"qword ptr [{{s}} + {off}]" if off else "qword ptr [{s}]"


# Ten named registers besides rax and rdx. With the buffer address in an
# eleventh, that is every register the compiler leaves to `asm!`.
R = [f"{{w{i}}}" for i in range(8)] + ["{c}", "{k}"]
W = R[:8]


def e32(reg):
    """The 32-bit name of a named register: `{w0}` -> `{w0:e}`."""
    return reg[:-1] + ":e}"


def reduce_step(d, t, extra=None, k_lo=None, k_hi=None):
    """One word of Montgomery reduction modulo p.

    `d` is six registers [d0..d5], the low words of the value being reduced;
    `t` a free register. Computes `(value + w * p) / 2^64` for
    `w = d0 * (2^32 + 1) mod 2^64`, the multiplier that clears d0, as
    `[d1..d5] - (w * (2^384 - p) >> 64) + w * 2^320`. Without `extra` the
    value is six words and the result is left in [d1, d2, d3, d4, d5, d0]:
    below 2^384, so six words hold it. With `extra = (d6, top)` the value is
    seven words and a top; `w * 2^320` lands on d6, and the result is in
    [d1..d6] and `top`. `k_lo` and `k_hi`, where given, are registers that
    already hold K_LO and K_HI. Uses rax and rdx.
    """
    d0, d1, d2, d3, d4, d5 = d
    out = [
        f"mov rdx, {d0}",
        "shl rdx, 32",
        f"add rdx, {d0}",
    ]
    # q = w * (2^384 - p), four words, of which the lowest is d0 again:
    # w * K_LO into [-, rax], w * K_HI into [t, d0].
    if k_lo is None:
        out += [f"mov rax, {K_LO}", f"mulx rax, {d0}, rax"]
    else:
        out += [f"mulx rax, {d0}, {k_lo}"]
    if k_hi is None:
        out += [f"mov {e32(t)}, {K_HI}", f"mulx {d0}, {t}, {t}"]
    else:
        out += [f"mulx {d0}, {t}, {k_hi}"]
    out += [
        # q1 = rax + t, q2 = d0 + w + carry, q3 = the carry out.
        f"add rax, {t}",
        f"adc {d0}, rdx",
        f"mov {e32(t)}, 0",
        f"adc {t}, 0",
        f"sub {d1}, rax",
        f"sbb {d2}, {d0}",
        f"sbb {d3}, {t}",
        f"sbb {d4}, 0",
        f"sbb {d5}, 0",
    ]
    if extra is None:
        # w less the borrow is the top word: the value is not negative, and
        # w = 0 only where q = 0 and nothing borrows.
        out += [f"mov {d0}, rdx", f"sbb {d0}, 0"]
    else:
        d6, top = extra
        out += ["sbb rdx, 0", f"add {d6}, rdx", f"adc {top}, 0"]
    return out


def finish(dst, v, top):
    """Store `v` (six registers, `top` the word above, the whole below 2p) to
    `dst`, less p if it is at least p. Adds 2^384 - p: a carry out of the top
    word says the value was at least p, and the sum is the answer. If not,
    the same constant, masked, is subtracted back. Uses rax and rdx."""
    return [
        f"mov rax, {K_LO}",
        f"mov edx, {K_HI}",
        f"add {v[0]}, rax",
        f"adc {v[1]}, rdx",
        f"adc {v[2]}, 1",
        f"adc {v[3]}, 0",
        f"adc {v[4]}, 0",
        f"adc {v[5]}, 0",
        f"adc {top}, 0",
        # top is 1 where the subtraction stands and 0 where it must be
        # undone; less one, it is the undoing's mask.
        f"sub {top}, 1",
        f"and rax, {top}",
        f"and rdx, {top}",
        f"and {top}, 1",
        f"sub {v[0]}, rax",
        f"sbb {v[1]}, rdx",
        f"sbb {v[2]}, {top}",
        f"sbb {v[3]}, 0",
        f"sbb {v[4]}, 0",
        f"sbb {v[5]}, 0",
    ] + [f"mov {addr(dst, i)}, {v[i]}" for i in range(N)]


def mul(dst, a, b, scratch):
    out = [f"xor {e32(r)}, {e32(r)}" for r in W[: N + 1]]
    # K_LO stays in {k} for the six reductions.
    out += [f"mov {{k}}, {K_LO}"]
    for i in range(N):
        win = [W[(i + j) % (N + 2)] for j in range(N + 1)]
        top = W[(i + N + 1) % (N + 2)]
        out += [f"mov rdx, {addr(b, i)}", f"xor {e32(top)}, {e32(top)}"]
        for j in range(N):
            out += [f"mulx {{c}}, rax, {addr(a, j)}", f"adcx {win[j]}, rax", f"adox {win[j + 1]}, {{c}}"]
        out += ["mov eax, 0", f"adcx {win[N]}, rax", f"adox {top}, rax", f"adcx {top}, rax"]
        out += reduce_step(win[:N], "{c}", extra=(win[N], top), k_lo="{k}")
    final = [W[(N + j) % (N + 2)] for j in range(N + 1)]
    return out + finish(dst, final[:N], final[N])


def sqr(dst, a, scratch):
    r = R

    def A(j):
        return addr(a, j)

    def H(j):
        return addr(scratch, j)

    # The cross products a_i * a_j, i < j, into S1..S10: r1..r8, r0, r9.
    out = [
        f"mov rdx, {A(0)}",
        f"mulx {r[2]}, {r[1]}, {A(1)}",
        f"mulx {r[3]}, rax, {A(2)}",
        f"add {r[2]}, rax",
        f"mulx {r[4]}, rax, {A(3)}",
        f"adc {r[3]}, rax",
        f"mulx {r[5]}, rax, {A(4)}",
        f"adc {r[4]}, rax",
        f"mulx {r[6]}, rax, {A(5)}",
        f"adc {r[5]}, rax",
        f"adc {r[6]}, 0",
    ]

    def row(i, cols, fresh):
        o = [f"mov rdx, {A(i)}", f"xor {e32(fresh)}, {e32(fresh)}"]
        for j, (lo, hi) in cols:
            o += [f"mulx {r[9]}, rax, {A(j)}", f"adcx {lo}, rax", f"adox {hi}, {r[9]}"]
        return o + ["mov eax, 0", f"adcx {fresh}, rax"]

    out += row(1, [(2, (r[3], r[4])), (3, (r[4], r[5])), (4, (r[5], r[6])), (5, (r[6], r[7]))], r[7])
    out += row(2, [(3, (r[5], r[6])), (4, (r[6], r[7])), (5, (r[7], r[8]))], r[8])
    out += row(3, [(4, (r[7], r[8])), (5, (r[8], r[0]))], r[0])
    out += [f"mov rdx, {A(4)}", f"mulx {r[9]}, rax, {A(5)}", f"add {r[0]}, rax", f"adc {r[9]}, 0"]
    # Doubled, into T1..T11; T10 and T11 go to the scratch slot.
    s_regs = [r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[0], r[9]]
    out += [f"add {s_regs[0]}, {s_regs[0]}"] + [f"adc {x}, {x}" for x in s_regs[1:]]
    out += ["mov eax, 0", "adc eax, 0", f"mov {H(4)}, {r[9]}", f"mov {H(5)}, rax"]
    # Plus the squares a_i^2 at word 2i: z0 into r9, z1..z9 in r1..r8, r0,
    # z10 and z11 in the scratch slot.
    out += [f"mov rdx, {A(0)}", f"mulx rdx, {r[9]}, rdx", f"add {r[1]}, rdx"]
    pairs = [(r[2], r[3]), (r[4], r[5]), (r[6], r[7]), (r[8], r[0]), (H(4), H(5))]
    for i, (lo, hi) in enumerate(pairs, start=1):
        out += [f"mov rdx, {A(i)}", "mulx rdx, rax, rdx", f"adc {lo}, rax", f"adc {hi}, rdx"]
    # z6..z9 join them: the scratch slot holds the high half, z6..z11.
    out += [f"mov {H(0)}, {r[6]}", f"mov {H(1)}, {r[7]}", f"mov {H(2)}, {r[8]}", f"mov {H(3)}, {r[0]}"]
    # Reduce the low half, six words, in place, with the constants in r7, r8.
    out += [f"mov {r[7]}, {K_LO}", f"mov {e32(r[8])}, {K_HI}"]
    d = [r[9], r[1], r[2], r[3], r[4], r[5]]
    for _ in range(N):
        out += reduce_step(d, r[6], k_lo=r[7], k_hi=r[8])
        d = d[1:] + d[:1]
    # Add the high half; the sum is below 2p.
    out += [f"xor {e32(r[7])}, {e32(r[7])}", f"add {d[0]}, {H(0)}"]
    out += [f"adc {d[i]}, {H(i)}" for i in range(1, N)]
    out += [f"adc {r[7]}, 0"]
    return out + finish(dst, d, r[7])


def add(dst, a, b, scratch):
    v = W[:N]
    top = W[N]
    out = [f"xor {e32(top)}, {e32(top)}"]
    out += [f"mov {v[i]}, {addr(a, i)}" for i in range(N)]
    out += [f"add {v[0]}, {addr(b, 0)}"]
    out += [f"adc {v[i]}, {addr(b, i)}" for i in range(1, N)]
    out += [f"adc {top}, 0"]
    return out + finish(dst, v, top)


def sub(dst, a, b, scratch):
    v = W[:N]
    out = [f"mov {v[i]}, {addr(a, i)}" for i in range(N)]
    out += [f"sub {v[0]}, {addr(b, 0)}"]
    out += [f"sbb {v[i]}, {addr(b, i)}" for i in range(1, N)]
    # All ones on a borrow; then p masked by it, word by word: 2^32 - 1,
    # 2^64 - 2^32, 2^64 - 2, and three words of ones.
    out += [
        "sbb {c}, {c}",
        "mov eax, 0xffffffff",
        "and rax, {c}",
        "mov rdx, {c}",
        "shl rdx, 32",
        f"mov {W[6]}, {{c}}",
        f"and {W[6]}, -2",
        f"add {v[0]}, rax",
        f"adc {v[1]}, rdx",
        f"adc {v[2]}, {W[6]}",
        f"adc {v[3]}, {{c}}",
        f"adc {v[4]}, {{c}}",
        f"adc {v[5]}, {{c}}",
    ]
    out += [f"mov {addr(dst, i)}, {v[i]}" for i in range(N)]
    return out


P_WORDS = ["0xffffffff", "0xffffffff00000000", "-2", "-1", "-1", "-1"]


def cms(dst, a, b, cm, dm, scratch):
    """`cm * a - dm * b mod p` for small constants, as one reduction:
    `cm * a + dm * (p - b)`, below `(cm + dm) * p`, so seven words whose top
    is small; `top * 2^384` is `top * (2^384 - p)` modulo p, which brings it
    below 2p for the last correction. `p - b` goes through the scratch slot."""
    acc = W[:7]
    out = []
    for i in range(N):
        imm = P_WORDS[i]
        out += [f"mov eax, {imm}" if imm == "0xffffffff" else f"mov rax, {imm}",
                f"{'sub' if i == 0 else 'sbb'} rax, {addr(b, i)}",
                f"mov {addr(scratch, i)}, rax"]
    assert 2 <= cm <= 16 and 1 <= dm <= 16
    out += [f"mov edx, {cm}", f"mulx {acc[1]}, {acc[0]}, {addr(a, 0)}"]
    for i in range(1, N):
        out += [f"mulx {acc[i + 1]}, rax, {addr(a, i)}",
                f"{'add' if i == 1 else 'adc'} {acc[i]}, rax"]
    out += [f"adc {acc[6]}, 0"]
    if dm == 1:
        out += [f"add {acc[0]}, {addr(scratch, 0)}"]
        out += [f"adc {acc[i]}, {addr(scratch, i)}" for i in range(1, N)]
        out += [f"adc {acc[6]}, 0"]
    else:
        out += [f"mov edx, {dm}", "xor eax, eax"]
        for i in range(N):
            out += [f"mulx {{c}}, rax, {addr(scratch, i)}", f"adcx {acc[i]}, rax",
                    f"adox {acc[i + 1]}, {{c}}"]
        out += ["mov eax, 0", f"adcx {acc[6]}, rax"]
    # top * (2^384 - p), for top below cm + dm <= 32, is three words:
    # top * K_LO into [c, w7]; then top * K_HI = (top << 32) - top, below
    # 2^37, plus c, below 32, is the middle word without a carry; and top.
    out += [
        f"mov rdx, {acc[6]}",
        f"mov rax, {K_LO}",
        f"mulx {{c}}, {W[7]}, rax",
        "mov {k}, rdx",
        "shl {k}, 32",
        "sub {k}, rdx",
        "add {k}, {c}",
        f"add {acc[0]}, {W[7]}",
        f"adc {acc[1]}, {{k}}",
        f"adc {acc[2]}, rdx",
        f"adc {acc[3]}, 0",
        f"adc {acc[4]}, 0",
        f"adc {acc[5]}, 0",
        f"mov {e32(acc[6])}, 0",
        f"adc {acc[6]}, 0",
    ]
    return out + finish(dst, acc[:N], acc[6])


def emit(name, doc, slots, program, attrs=("#[inline(never)]",)):
    slots = slots + ["scratch"]
    idx = {n: i for i, n in enumerate(slots)}
    o = [f"/// {doc}", "///"]
    o.append("/// Slots, 48 bytes each, in order: " + ", ".join(f"`{s}`" for s in slots) + ".")
    o += ["///", "/// # Safety", "///",
          "/// The CPU must support BMI2 and ADX; see `super::p256_x86::has_adx`.",
          "/// Every input slot must hold a value below p."]
    o += list(attrs)
    o += [f"pub unsafe fn {name}(buf: &mut [MaybeUninit<u64>; {N * len(slots)}]) {{",
          "    // SAFETY: the caller guarantees the instructions exist. The block reads",
          "    // and writes only the buffer behind `{s}`, a live, exclusive reference",
          f"    // of {SLOT * len(slots)} bytes, at offsets below that; it writes only the",
          "    // registers it declares, and does not touch the stack. It reads no slot",
          "    // before writing it but the inputs, which the caller has written.",
          "    unsafe {",
          "        asm!("]
    body = []
    for op, *args in program:
        if op == "cms":
            dst, a, b, cm, dm = args
            body.append(f"            // {dst} = {cm} * {a} - {dm} * {b}")
        else:
            body.append(f"            // {args[0]} = {op}({', '.join(args[1:])})")
        operands = [idx[x] if isinstance(x, str) else x for x in args] + [idx["scratch"]]
        for line in {"mul": mul, "sqr": sqr, "add": add, "sub": sub, "cms": cms}[op](*operands):
            body.append(f'            "{line}",')
    o += body
    o.append("            s = in(reg) buf.as_mut_ptr(),")
    # Only the registers the block names: an unused operand is an error.
    text = "\n".join(body)
    for name in [f"w{i}" for i in range(8)] + ["c", "k"]:
        if "{" + name + "}" in text or "{" + name + ":e}" in text:
            o.append(f"            {name} = out(reg) _,")
    o += ['            out("rax") _,', '            out("rdx") _,',
          "            options(nostack),", "        );", "    }", "}"]
    return "\n".join(o)


HEADER = '''//! P-384's field operations and point formulas, each one `asm!` block over
//! `mulx`/`adcx`/`adox`.
//!
//! GENERATED by `scripts/gen_p384_x86_point.py`; edit that, not this.
//!
//! The field operations are specialised to p = 2^384 - 2^128 - 2^96 + 2^32 -
//! 1: Montgomery reduction takes two `mulx` per word, by constants, where a
//! generic modulus takes six; squaring computes each cross product once; and
//! every final correction is a masked addition or subtraction in registers.
//! The point formulas are those of `point.rs` -- doubling, addition and mixed
//! addition -- in the same order of field operations, over a buffer of
//! 48-byte slots. Nothing branches and nothing is indexed by data.

use core::arch::asm;
use core::mem::MaybeUninit;'''

# `Point::double`'s values, with its small multiples folded into three fused
# operations: with `m = X^2 - Z^4`, `alpha = 3m` and `beta = X Y^2`,
#   d  = 12 beta - 9 m^2           (= 4 beta - alpha^2)
#   X3 = 4 beta - d                (= alpha^2 - 8 beta)
#   Y3 = 3 d m - 8 Y^4             (= alpha (4 beta - X3) - 8 gamma^2)
#   Z3 = (Y + Z)^2 - Y^2 - Z^2
# The same field elements, so the same canonical words: eight additive steps
# where the formula as written takes fifteen.
DOUBLE_SLOTS = ["X", "Y", "Z", "X3", "Y3", "Z3", "delta", "gamma", "beta", "m", "u", "m2", "d", "w"]
DOUBLE = [
    ("sqr", "delta", "Z"),
    ("sqr", "gamma", "Y"),
    ("sub", "m", "X", "delta"),
    ("add", "u", "X", "delta"),
    ("mul", "m", "m", "u"),
    ("mul", "beta", "X", "gamma"),
    ("sqr", "m2", "m"),
    ("cms", "d", "beta", "m2", 12, 9),
    ("add", "w", "Y", "Z"),
    ("sqr", "w", "w"),
    ("sub", "w", "w", "gamma"),
    ("sub", "Z3", "w", "delta"),
    ("sqr", "gamma", "gamma"),
    ("cms", "X3", "beta", "d", 4, 1),
    ("mul", "u", "d", "m"),
    ("cms", "Y3", "u", "gamma", 3, 8),
]

# Every (cm, dm) a formula uses; each is emitted alone for the tests.
CMS_USED = sorted({(op[4], op[5]) for op in DOUBLE if op[0] == "cms"})

ADD_SLOTS = ["X1", "Y1", "Z1", "X2", "Y2", "Z2", "X3", "Y3", "Z3", "H", "R",
             "z1z1", "z2z2", "u1", "u2", "s1", "s2", "i", "j", "v", "t"]
ADD = [
    ("sqr", "z1z1", "Z1"),
    ("sqr", "z2z2", "Z2"),
    ("mul", "u1", "X1", "z2z2"),
    ("mul", "u2", "X2", "z1z1"),
    ("mul", "t", "Y1", "Z2"),
    ("mul", "s1", "t", "z2z2"),
    ("mul", "t", "Y2", "Z1"),
    ("mul", "s2", "t", "z1z1"),
    ("sub", "H", "u2", "u1"),
    ("sub", "R", "s2", "s1"),
    ("add", "R", "R", "R"),
    ("add", "i", "H", "H"),
    ("sqr", "i", "i"),
    ("mul", "j", "H", "i"),
    ("mul", "v", "u1", "i"),
    ("sqr", "X3", "R"),
    ("sub", "X3", "X3", "j"),
    ("add", "t", "v", "v"),
    ("sub", "X3", "X3", "t"),
    ("sub", "t", "v", "X3"),
    ("mul", "Y3", "R", "t"),
    ("mul", "t", "s1", "j"),
    ("add", "t", "t", "t"),
    ("sub", "Y3", "Y3", "t"),
    ("add", "Z3", "Z1", "Z2"),
    ("sqr", "Z3", "Z3"),
    ("sub", "Z3", "Z3", "z1z1"),
    ("sub", "Z3", "Z3", "z2z2"),
    ("mul", "Z3", "Z3", "H"),
]

MADD_SLOTS = ["X1", "Y1", "Z1", "x2", "y2", "X3", "Y3", "Z3", "H", "R",
              "z1z1", "u2", "s2", "hh", "i", "j", "v", "t"]
MADD = [
    ("sqr", "z1z1", "Z1"),
    ("mul", "u2", "x2", "z1z1"),
    ("mul", "t", "y2", "Z1"),
    ("mul", "s2", "t", "z1z1"),
    ("sub", "H", "u2", "X1"),
    ("sqr", "hh", "H"),
    ("add", "i", "hh", "hh"),
    ("add", "i", "i", "i"),
    ("mul", "j", "H", "i"),
    ("sub", "R", "s2", "Y1"),
    ("add", "R", "R", "R"),
    ("mul", "v", "X1", "i"),
    ("sqr", "X3", "R"),
    ("sub", "X3", "X3", "j"),
    ("add", "t", "v", "v"),
    ("sub", "X3", "X3", "t"),
    ("sub", "t", "v", "X3"),
    ("mul", "Y3", "R", "t"),
    ("mul", "t", "Y1", "j"),
    ("add", "t", "t", "t"),
    ("sub", "Y3", "Y3", "t"),
    ("add", "Z3", "Z1", "H"),
    ("sqr", "Z3", "Z3"),
    ("sub", "Z3", "Z3", "z1z1"),
    ("sub", "Z3", "Z3", "hh"),
]


def main():
    parts = [HEADER]
    parts.append(emit("fmul_adx", "`a * b * 2^-384 mod p`, canonical.", ["a", "b", "out"],
                      [("mul", "out", "a", "b")], ("#[inline]",)))
    parts.append(emit("fsqr_adx", "`a^2 * 2^-384 mod p`, canonical.", ["a", "out"],
                      [("sqr", "out", "a")], ("#[inline]",)))
    parts.append(emit("fadd_adx", "`a + b mod p`; alone, only for the tests.", ["a", "b", "out"],
                      [("add", "out", "a", "b")], ("#[cfg(test)]", "#[inline(never)]")))
    parts.append(emit("fsub_adx", "`a - b mod p`; alone, only for the tests.", ["a", "b", "out"],
                      [("sub", "out", "a", "b")], ("#[cfg(test)]", "#[inline(never)]")))
    # The fused operations the doubling uses, alone, for the tests.
    for cm, dm in CMS_USED:
        parts.append(emit(f"fcms_{cm}_{dm}_adx", f"`{cm} a - {dm} b mod p`; alone, only for the tests.",
                          ["a", "b", "out"], [("cms", "out", "a", "b", cm, dm)],
                          ("#[cfg(test)]", "#[inline(never)]")))
    parts.append(emit("double_adx", "Point doubling, `dbl-2001-b` for `a = -3`, as `Point::double`.",
                      DOUBLE_SLOTS, DOUBLE))
    parts.append(emit("add_adx",
                      "Jacobian addition, `add-2007-bl`, as `Point::add_formula`; also leaves `H` and `R`.",
                      ADD_SLOTS, ADD))
    parts.append(emit("add_affine_adx",
                      "Mixed addition, `madd-2007-bl`, as `Point::add_affine_formula`; also leaves `H` and `R`.",
                      MADD_SLOTS, MADD))
    text = "\n\n".join(parts) + "\n"
    with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


main()
