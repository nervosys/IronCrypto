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
- The last correction adds `2^384 - p` into copies and takes them with
  `cmovnz` where that carries out of the top word: one carry chain and a
  conditional move per word, where subtracting the constant back through a
  mask took a second chain after the first. No branch, no table.
- Addition corrects the same way; subtraction adds p through a mask made from
  the borrow.
- The doubling's small multiples are three fused operations, `cm * a - dm *
  b`, each one fold of its top word and one correction, in registers.

Each formula is a list of those operations on 48-byte slots in one buffer
whose address is in `{s}`; every operation reads its operands before writing
its result. The formulas compute the values of crates/ic-ec/src/nist/point.rs,
operation for operation, so the results agree bit for bit, which the tests
check; the order of the operations is the generator's, chosen so that the
core can overlap one with the next (measured: the doubling 7 percent faster,
the additions 5 to 7, than in point.rs's order). The doubling is also emitted
in place, its results over its inputs, for the scalar multiplication's loop.
The field operations are emitted on their own too: `Fp` uses the
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


def r32(reg):
    """The 32-bit name of rax, rdx or a named register."""
    return {"rax": "eax", "rdx": "edx"}.get(reg) or e32(reg)


def finish(dst, v, top, free):
    """Store `v` (six registers, `top` the word above, the whole below 2p) to
    `dst`, less p if it is at least p.

    Adds 2^384 - p into copies: a carry out of the top word says the value
    was at least p, and the sum is the answer; `cmovnz` takes it. The
    constant's top three words are zero, so the copies of words 3 and 4
    start as the words themselves; word 5 is added in place and taken back
    from its store with `cmovz` where the sum does not stand. One carry
    chain and one conditional move per word, where subtracting the constant
    back through a mask takes a second chain after the first. `free` is
    three registers the caller no longer needs; uses rax and rdx too."""
    t = ["rax", "rdx"] + list(free[:3])
    assert len(t) == 5
    return [
        f"mov {addr(dst, 5)}, {v[5]}",
        f"mov {t[0]}, {K_LO}",
        f"mov {r32(t[1])}, {K_HI}",
        f"mov {r32(t[2])}, 1",
        f"mov {t[3]}, {v[3]}",
        f"mov {t[4]}, {v[4]}",
        f"add {t[0]}, {v[0]}",
        f"adc {t[1]}, {v[1]}",
        f"adc {t[2]}, {v[2]}",
        f"adc {t[3]}, 0",
        f"adc {t[4]}, 0",
        f"adc {v[5]}, 0",
        f"adc {top}, 0",
    ] + [f"cmovnz {v[i]}, {t[i]}" for i in range(5)] + [
        f"cmovz {v[5]}, {addr(dst, 5)}",
    ] + [f"mov {addr(dst, i)}, {v[i]}" for i in range(N)]


def mul_core(A, B, k_lo):
    """The product rows and their reductions, operands read through `A(j)`
    and `B(i)`; `k_lo` a register holding K_LO, or None to load it per word.
    Returns the instructions, the six result registers and the top word."""
    out = [f"xor {e32(r)}, {e32(r)}" for r in W[: N + 1]]
    if k_lo is not None:
        out += [f"mov {k_lo}, {K_LO}"]
    for i in range(N):
        win = [W[(i + j) % (N + 2)] for j in range(N + 1)]
        top = W[(i + N + 1) % (N + 2)]
        out += [f"mov rdx, {B(i)}", f"xor {e32(top)}, {e32(top)}"]
        for j in range(N):
            out += [f"mulx {{c}}, rax, {A(j)}", f"adcx {win[j]}, rax", f"adox {win[j + 1]}, {{c}}"]
        out += ["mov eax, 0", f"adcx {win[N]}, rax", f"adox {top}, rax", f"adcx {top}, rax"]
        out += reduce_step(win[:N], "{c}", extra=(win[N], top), k_lo=k_lo)
    final = [W[(N + j) % (N + 2)] for j in range(N + 1)]
    return out, final[:N], final[N]


def mul(dst, a, b, scratch):
    out, v, top = mul_core(lambda j: addr(a, j), lambda i: addr(b, i), "{k}")
    return out + finish(dst, v, top, [W[5], "{c}", "{k}"])


def sqr(dst, a, scratch):
    out, d, top = sqr_core(lambda j: addr(a, j), lambda j: addr(scratch, j))
    return out + finish(dst, d, top, [R[0], R[6], R[8]])


def sqr_core(A, H):
    """The square and its reduction, the operand read through `A(j)`, the
    high half kept in the six words `H(j)`. Returns the instructions, the
    six result registers and the top word; r0, r6 and r8 are free after."""
    r = R

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
    return out, d, r[7]


def add(dst, a, b, scratch):
    v = W[:N]
    top = W[N]
    out = [f"xor {e32(top)}, {e32(top)}"]
    out += [f"mov {v[i]}, {addr(a, i)}" for i in range(N)]
    out += [f"add {v[0]}, {addr(b, 0)}"]
    out += [f"adc {v[i]}, {addr(b, i)}" for i in range(1, N)]
    out += [f"adc {top}, 0"]
    return out + finish(dst, v, top, [W[7], "{c}", "{k}"])


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
    """`cm * a - dm * b mod p` for small constants, as one reduction, all in
    registers: `cm * a + dm * (p - b)`, a value V below `(cm + dm) * p`, six
    words `v` and a small top word `t`.

    Then V less `(t + 1) * p`, which is `v - 2^384 + (t + 1)(2^384 - p)`: in
    `[-p, p)`, since `v < 2^384` and `t (2^384 - p) >= 0`. So adding
    `(t + 1)(2^384 - p)`, three words, to `v` either carries out of the top
    word, and the six words are the answer, or does not, and the answer is
    them less `2^384 - p`, subtracted through a mask made from the carry. One
    fold and one correction, where folding `t` and then reducing below p
    takes two corrections."""
    assert 1 <= cm <= 16 and 1 <= dm <= 16 and cm + dm <= 31
    n = W[:N]
    top = W[N]
    hi = W[7]
    out = []
    for i in range(N):
        imm = P_WORDS[i]
        out += [f"mov {e32(n[i])}, {imm}" if imm == "0xffffffff" else f"mov {n[i]}, {imm}",
                f"{'sub' if i == 0 else 'sbb'} {n[i]}, {addr(b, i)}"]
    # n = dm * (p - b), with its top word.
    if dm == 1:
        out += [f"xor {e32(top)}, {e32(top)}"]
    elif dm & (dm - 1) == 0:
        k = dm.bit_length() - 1
        out += [f"mov {top}, {n[5]}", f"shr {top}, {64 - k}"]
        out += [f"shld {n[i]}, {n[i - 1]}, {k}" for i in range(N - 1, 0, -1)]
        out += [f"shl {n[0]}, {k}"]
    else:
        h = [hi, "{c}"]
        out += [f"mov edx, {dm}", f"mulx {h[0]}, {n[0]}, {n[0]}"]
        for i in range(1, N):
            dst_hi = top if i == N - 1 else h[i % 2]
            out += [f"mulx {dst_hi}, {n[i]}, {n[i]}",
                    f"{'add' if i == 1 else 'adc'} {n[i]}, {h[(i - 1) % 2]}"]
        out += [f"adc {top}, 0"]
    # n += cm * a on two carry chains; the top word ends in rdx.
    out += [f"mov edx, {cm}", "xor {c:e}, {c:e}"]
    for i in range(N - 1):
        out += [f"mulx {hi}, rax, {addr(a, i)}", f"adcx {n[i]}, rax", f"adox {n[i + 1]}, {hi}"]
    out += [f"mulx rdx, rax, {addr(a, N - 1)}", f"adcx {n[N - 1]}, rax",
            f"adox rdx, {top}", "adcx rdx, {c}"]
    # q = t + 1; q (2^384 - p) is three words: q * K_LO into [rax, hi]; then
    # q * K_HI = (q << 32) - q, below 2^37, plus hi, below 32, is the middle
    # word without a carry; and q.
    out += [
        "add rdx, 1",
        f"mov rax, {K_LO}",
        f"mulx {hi}, rax, rax",
        "mov {c}, rdx",
        "shl {c}, 32",
        "sub {c}, rdx",
        f"add {{c}}, {hi}",
        f"add {n[0]}, rax",
        f"adc {n[1]}, {{c}}",
        f"adc {n[2]}, rdx",
        f"adc {n[3]}, 0",
        f"adc {n[4]}, 0",
        f"adc {n[5]}, 0",
        # No carry: subtract 2^384 - p. All ones in rax where that is due.
        "cmc",
        "sbb rax, rax",
        f"mov rdx, {K_LO}",
        "and rdx, rax",
        f"mov {{c:e}}, {K_HI}",
        "and {c}, rax",
        "and eax, 1",
        f"sub {n[0]}, rdx",
        f"sbb {n[1]}, {{c}}",
        f"sbb {n[2]}, rax",
        f"sbb {n[3]}, 0",
        f"sbb {n[4]}, 0",
        f"sbb {n[5]}, 0",
    ]
    return out + [f"mov {addr(dst, i)}, {n[i]}" for i in range(N)]


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
//! every final correction is a conditional move or a masked addition, in
//! registers. The point formulas compute the values of `point.rs` --
//! doubling, addition and mixed addition -- over a buffer of 48-byte slots,
//! their operations ordered for the core to overlap them; the doubling also
//! in place, for the scalar multiplication. Nothing branches and nothing is
//! indexed by data.

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
DOUBLE_SLOTS = ["X", "Y", "Z", "X3", "Y3", "Z3", "delta", "gamma", "beta", "m", "u", "m2", "d", "w", "g2"]
DOUBLE = [
    ("sqr", "delta", "Z"),
    ("sqr", "gamma", "Y"),
    ("sub", "m", "X", "delta"),
    ("add", "u", "X", "delta"),
    ("mul", "m", "m", "u"),
    ("mul", "beta", "X", "gamma"),
    ("sqr", "m2", "m"),
    ("add", "w", "Y", "Z"),
    ("sqr", "w", "w"),
    ("cms", "d", "beta", "m2", 12, 9),
    ("sqr", "g2", "gamma"),
    ("mul", "u", "d", "m"),
    ("cms", "X3", "beta", "d", 4, 1),
    ("sub", "w", "w", "gamma"),
    ("sub", "Z3", "w", "delta"),
    ("cms", "Y3", "u", "g2", 3, 8),
]

# The same doubling in place, for the scalar multiplication's loop: X3, Y3
# and Z3 written over X, Y and Z, each after the last operation that reads
# it, which `in_place` checks.
def in_place(program, rename):
    out = []
    written = set()
    for op, dst, *src in program:
        for x in src:
            assert not (isinstance(x, str) and x in written), (op, dst, x)
        dst = rename.get(dst, dst)
        if dst in rename.values():
            written.add(dst)
        out.append((op, dst, *src))
    return out


DOUBLE_IP_RENAME = {"X3": "X", "Y3": "Y", "Z3": "Z"}
DOUBLE_IP_SLOTS = [s for s in DOUBLE_SLOTS if s not in DOUBLE_IP_RENAME]
DOUBLE_IP = in_place(DOUBLE, DOUBLE_IP_RENAME)

# Every (cm, dm) a formula uses; each is emitted alone for the tests.
CMS_USED = sorted({(op[4], op[5]) for op in DOUBLE if op[0] == "cms"})

# The additions' operations in an order for the core to overlap: the
# products that do not wait on others first, each long chain's next step as
# soon as its inputs are there, and independent work -- `Z3`'s chain, `s1 j`
# -- placed between a chain's step and the next, which needs it. The same
# operations as `point.rs`, on the same values, so the same words.
ADD_SLOTS = ["X1", "Y1", "Z1", "X2", "Y2", "Z2", "X3", "Y3", "Z3", "H", "R",
             "z1z1", "z2z2", "u1", "u2", "s1", "s2", "i", "j", "v", "t1", "t2", "t3", "t4"]
ADD = [
    ("sqr", "z1z1", "Z1"),
    ("sqr", "z2z2", "Z2"),
    ("mul", "t1", "Y1", "Z2"),
    ("mul", "u2", "X2", "z1z1"),
    ("mul", "u1", "X1", "z2z2"),
    ("mul", "t2", "Y2", "Z1"),
    ("sub", "H", "u2", "u1"),
    ("add", "i", "H", "H"),
    ("sqr", "i", "i"),
    ("mul", "s1", "t1", "z2z2"),
    ("mul", "v", "u1", "i"),
    ("mul", "s2", "t2", "z1z1"),
    ("mul", "j", "H", "i"),
    ("sub", "R", "s2", "s1"),
    ("add", "R", "R", "R"),
    ("sqr", "X3", "R"),
    ("add", "Z3", "Z1", "Z2"),
    ("sqr", "Z3", "Z3"),
    ("mul", "t3", "s1", "j"),
    ("add", "t1", "v", "v"),
    ("sub", "X3", "X3", "j"),
    ("sub", "X3", "X3", "t1"),
    ("sub", "t4", "v", "X3"),
    ("sub", "Z3", "Z3", "z1z1"),
    ("mul", "Y3", "R", "t4"),
    ("sub", "Z3", "Z3", "z2z2"),
    ("mul", "Z3", "Z3", "H"),
    ("add", "t3", "t3", "t3"),
    ("sub", "Y3", "Y3", "t3"),
]

MADD_SLOTS = ["X1", "Y1", "Z1", "x2", "y2", "X3", "Y3", "Z3", "H", "R",
              "z1z1", "u2", "s2", "hh", "i", "j", "v", "t", "t2", "t3"]
MADD = [
    ("sqr", "z1z1", "Z1"),
    ("mul", "t", "y2", "Z1"),
    ("mul", "u2", "x2", "z1z1"),
    ("mul", "s2", "t", "z1z1"),
    ("sub", "H", "u2", "X1"),
    ("sqr", "hh", "H"),
    ("sub", "R", "s2", "Y1"),
    ("add", "R", "R", "R"),
    ("sqr", "X3", "R"),
    ("add", "i", "hh", "hh"),
    ("add", "i", "i", "i"),
    ("mul", "v", "X1", "i"),
    ("mul", "j", "H", "i"),
    ("add", "Z3", "Z1", "H"),
    ("sqr", "Z3", "Z3"),
    ("mul", "t2", "Y1", "j"),
    ("add", "t", "v", "v"),
    ("sub", "X3", "X3", "j"),
    ("sub", "X3", "X3", "t"),
    ("sub", "t3", "v", "X3"),
    ("sub", "Z3", "Z3", "z1z1"),
    ("mul", "Y3", "R", "t3"),
    ("sub", "Z3", "Z3", "hh"),
    ("add", "t2", "t2", "t2"),
    ("sub", "Y3", "Y3", "t2"),
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
    parts.append(emit("double_in_place_adx",
                      "`double_adx` with X3, Y3 and Z3 written over X, Y and Z: the scalar "
                      "multiplication's doubling, on a buffer whose first slots are its accumulator.",
                      DOUBLE_IP_SLOTS, DOUBLE_IP))
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
