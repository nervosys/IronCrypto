"""Generate crates/ic-ec/src/nist/p256_x86_point.rs: P-256 point formulas as
Rust `asm!` blocks over MULX/ADX.

    python scripts/gen_p256_x86_point.py crates/ic-ec/src/nist/p256_x86_point.rs

Each formula is a list of field operations on 32-byte slots in one buffer
whose address is in `{s}`. Every operation reads its operands from memory and
writes its result to memory after all reads, so a destination may be a source.
The field operations are the instruction sequences of
crates/ic-ec/src/nist/p256_x86.rs (`mul_adx`, `square_adx`, `add`, `sub`),
with memory operands, and the doubling's small multiples are three fused
operations, `cm * a - dm * b`, each one fold and one correction, as P-384's
(scripts/gen_p384_x86_point.py). The formulas compute the values of
crates/ic-ec/src/nist/point.rs, operation for operation, so the results agree
bit for bit, which the tests check; the operations are ordered for the core
to overlap them, and the doubling is also emitted in place, its results over
its inputs, for the scalar multiplication's loop.
"""
import sys

P1 = "0xffffffff"
P3 = "0xffffffff00000001"


def addr(slot, word):
    off = 32 * slot + 8 * word
    return f"qword ptr [{{s}} + {off}]" if off else "qword ptr [{s}]"


def store(dst, regs):
    return [f"mov {addr(dst, i)}, {r}" for i, r in enumerate(regs)]


def step(u, w):
    return [
        f"mov rax, {u}",
        "shl rax, 32",
        f"mov {{c}}, {u}",
        "shr {c}, 32",
        f"mov rdx, {u}",
        "sub rdx, rax",
        f"sbb {u}, {{c}}",
        f"add {w[0]}, rax",
        f"adc {w[1]}, {{c}}",
        f"adc {w[2]}, rdx",
        f"adc {w[3]}, {u}",
        f"adc {w[4]}, 0",
    ]


def mul(dst, a, b):
    T = [f"{{t{i}}}" for i in range(6)]
    out = [
        f"mov rdx, {addr(b, 0)}",
        f"mulx {T[1]}, {T[0]}, {addr(a, 0)}",
        f"mulx {T[2]}, rax, {addr(a, 1)}",
        f"add {T[1]}, rax",
        f"mulx {T[3]}, rax, {addr(a, 2)}",
        f"adc {T[2]}, rax",
        f"mulx {T[4]}, rax, {addr(a, 3)}",
        f"adc {T[3]}, rax",
        f"adc {T[4]}, 0",
        f"xor {T[5][:-1]}:e}}, {T[5][:-1]}:e}}",
    ]
    out += step(T[0], T[1:6])
    t = T[:]
    for i in range(1, 4):
        t = t[1:] + t[:1]
        w, top = t[0:5], t[5]
        out += [
            f"mov rdx, {addr(b, i)}",
            f"xor {top[:-1]}:e}}, {top[:-1]}:e}}",
        ]
        for j in range(4):
            out += [
                f"mulx {{c}}, rax, {addr(a, j)}",
                f"adcx {w[j]}, rax",
                f"adox {w[j + 1]}, {{c}}",
            ]
        out += [
            "mov eax, 0",
            f"adcx {w[4]}, rax",
            f"adox {top}, rax",
            f"adcx {top}, rax",
        ]
        out += step(w[0], w[1:5] + [top])
    # value in t[1..5] = (T3?) -> after 3 rotations t = [t3,t4,t5,t0,t1,t2]
    v = [t[1], t[2], t[3], t[4]]
    top = t[5]
    free = t[0]
    assert free == "{t3}" and v == ["{t4}", "{t5}", "{t0}", "{t1}"] and top == "{t2}"
    out += [
        f"mov rax, {v[0]}",
        f"mov rdx, {v[1]}",
        f"mov {{c}}, {v[2]}",
        f"mov {free}, {v[3]}",
        f"mov {{t6:e}}, {P1}",
        f"mov {{t7}}, {P3}",
        "sub rax, -1",
        "sbb rdx, {t6}",
        "sbb {c}, 0",
        f"sbb {free}, {{t7}}",
        f"sbb {top}, 0",
        f"cmovc rax, {v[0]}",
        f"cmovc rdx, {v[1]}",
        f"cmovc {{c}}, {v[2]}",
        f"cmovc {free}, {v[3]}",
    ]
    out += store(dst, ["rax", "rdx", "{c}", free])
    return out


def sqr(dst, a):
    out = [
        f"mov rdx, {addr(a, 0)}",
        f"mulx {{t2}}, {{t1}}, {addr(a, 1)}",
        f"mulx {{t3}}, rax, {addr(a, 2)}",
        "add {t2}, rax",
        f"mulx {{t4}}, rax, {addr(a, 3)}",
        "adc {t3}, rax",
        "adc {t4}, 0",
        f"mov rdx, {addr(a, 1)}",
        "xor {t5:e}, {t5:e}",
        f"mulx {{c}}, rax, {addr(a, 2)}",
        "adcx {t3}, rax",
        "adox {t4}, {c}",
        f"mulx {{c}}, rax, {addr(a, 3)}",
        "adcx {t4}, rax",
        "adox {t5}, {c}",
        "mov eax, 0",
        "adcx {t5}, rax",
        f"mov rdx, {addr(a, 2)}",
        f"mulx {{t6}}, rax, {addr(a, 3)}",
        "add {t5}, rax",
        "adc {t6}, 0",
        "xor {t7:e}, {t7:e}",
        "add {t1}, {t1}",
        "adc {t2}, {t2}",
        "adc {t3}, {t3}",
        "adc {t4}, {t4}",
        "adc {t5}, {t5}",
        "adc {t6}, {t6}",
        "adc {t7}, 0",
        f"mov rdx, {addr(a, 0)}",
        "mulx {c}, {t0}, rdx",
        "add {t1}, {c}",
        f"mov rdx, {addr(a, 1)}",
        "mulx {c}, rax, rdx",
        "adc {t2}, rax",
        "adc {t3}, {c}",
        f"mov rdx, {addr(a, 2)}",
        "mulx {c}, rax, rdx",
        "adc {t4}, rax",
        "adc {t5}, {c}",
        f"mov rdx, {addr(a, 3)}",
        "mulx {c}, rax, rdx",
        "adc {t6}, rax",
        "adc {t7}, {c}",
    ]
    # Reduce the low window, rotating.
    w = ["{t0}", "{t1}", "{t2}", "{t3}"]
    for _ in range(4):
        u = w[0]
        out += [
            f"mov rax, {u}",
            "shl rax, 32",
            f"mov rdx, {u}",
            "shr rdx, 32",
            f"mov {{c}}, {u}",
            "sub {c}, rax",
            f"sbb {u}, rdx",
            f"add {w[1]}, rax",
            f"adc {w[2]}, rdx",
            f"adc {w[3]}, {{c}}",
            f"adc {u}, 0",
        ]
        w = w[1:] + w[:1]
    out += [
        "xor {c:e}, {c:e}",
        "add {t4}, {t0}",
        "adc {t5}, {t1}",
        "adc {t6}, {t2}",
        "adc {t7}, {t3}",
        "adc {c}, 0",
        "mov rax, {t4}",
        "mov rdx, {t5}",
        "mov {t2}, {t6}",
        "mov {t3}, {t7}",
        f"mov {{t0:e}}, {P1}",
        f"mov {{t1}}, {P3}",
        "sub rax, -1",
        "sbb rdx, {t0}",
        "sbb {t2}, 0",
        "sbb {t3}, {t1}",
        "sbb {c}, 0",
        "cmovc rax, {t4}",
        "cmovc rdx, {t5}",
        "cmovc {t2}, {t6}",
        "cmovc {t3}, {t7}",
    ]
    out += store(dst, ["rax", "rdx", "{t2}", "{t3}"])
    return out


def add(dst, a, b):
    out = [f"mov {{t{i}}}, {addr(a, i)}" for i in range(4)]
    out += ["xor {c:e}, {c:e}", f"add {{t0}}, {addr(b, 0)}"]
    out += [f"adc {{t{i}}}, {addr(b, i)}" for i in range(1, 4)]
    out += ["adc {c}, 0"]
    out += [f"mov {{t{i + 4}}}, {{t{i}}}" for i in range(4)]
    out += [
        f"mov eax, {P1}",
        f"mov rdx, {P3}",
        "sub {t4}, -1",
        "sbb {t5}, rax",
        "sbb {t6}, 0",
        "sbb {t7}, rdx",
        "sbb {c}, 0",
    ]
    out += [f"cmovc {{t{i + 4}}}, {{t{i}}}" for i in range(4)]
    out += store(dst, [f"{{t{i + 4}}}" for i in range(4)])
    return out


def sub(dst, a, b):
    out = [f"mov {{t{i}}}, {addr(a, i)}" for i in range(4)]
    out += [f"sub {{t0}}, {addr(b, 0)}"]
    out += [f"sbb {{t{i}}}, {addr(b, i)}" for i in range(1, 4)]
    out += [
        "sbb {c}, {c}",
        "mov rax, {c}",
        "shr rax, 32",
        f"mov rdx, {P3}",
        "and rdx, {c}",
        "add {t0}, {c}",
        "adc {t1}, rax",
        "adc {t2}, 0",
        "adc {t3}, rdx",
    ]
    out += store(dst, [f"{{t{i}}}" for i in range(4)])
    return out


def mulk(dst, a, k):
    """`k * a mod p` for k in 3, 4, 8: the product in five words, then the
    top word `q` (at most 7) folded back as `q * (2^256 - p)`, which is
    `q*2^224 - q*2^192 - q*2^96 + q`, then one conditional subtraction.

    The fold leaves `t - q*p`, which is non-negative (q <= t / 2^256 < t / p)
    and below 2^256 + 7*2^224 < 2p, so one subtraction makes it canonical.
    """
    k = int(k)
    out = [f"mov {{t{i}}}, {addr(a, i)}" for i in range(4)]
    if k in (4, 8):
        s = {4: 2, 8: 3}[k]
        out += [
            "mov {t4}, {t3}",
            f"shr {{t4}}, {64 - s}",
            f"shld {{t3}}, {{t2}}, {s}",
            f"shld {{t2}}, {{t1}}, {s}",
            f"shld {{t1}}, {{t0}}, {s}",
            f"shl {{t0}}, {s}",
        ]
    elif k == 3:
        out += [
            "mov {t4}, {t3}",
            "shr {t4}, 63",
            "shld {t3}, {t2}, 1",
            "shld {t2}, {t1}, 1",
            "shld {t1}, {t0}, 1",
            "shl {t0}, 1",
            f"add {{t0}}, {addr(a, 0)}",
            f"adc {{t1}}, {addr(a, 1)}",
            f"adc {{t2}}, {addr(a, 2)}",
            f"adc {{t3}}, {addr(a, 3)}",
            "adc {t4}, 0",
        ]
    else:
        raise ValueError(k)
    out += [
        # q*2^32 for the words at 2^96 and 2^224.
        "mov rax, {t4}",
        "shl rax, 32",
        # + q + q*2^224
        "xor {c:e}, {c:e}",
        "add {t0}, {t4}",
        "adc {t1}, 0",
        "adc {t2}, 0",
        "adc {t3}, rax",
        "adc {c}, 0",
        # - q*2^96 - q*2^192
        "sub {t1}, rax",
        "sbb {t2}, 0",
        "sbb {t3}, {t4}",
        "sbb {c}, 0",
    ]
    # One conditional subtraction, as in `add`.
    out += [f"mov {{t{i + 4}}}, {{t{i}}}" for i in range(4)]
    out += [
        f"mov eax, {P1}",
        f"mov rdx, {P3}",
        "sub {t4}, -1",
        "sbb {t5}, rax",
        "sbb {t6}, 0",
        "sbb {t7}, rdx",
        "sbb {c}, 0",
    ]
    out += [f"cmovc {{t{i + 4}}}, {{t{i}}}" for i in range(4)]
    out += store(dst, [f"{{t{i + 4}}}" for i in range(4)])
    return out


def cms(dst, a, b, cm, dm):
    """`cm * a - dm * b mod p` for small constants, as one reduction:
    `cm * a + dm * (p - b)`, a value V below `(cm + dm) * p`, four words `v`
    and a small top word `t`.

    V less `(t + 1) * p` is `v - 2^256 + (t + 1)(2^256 - p)`, in `[-p, p)`:
    `v < 2^256`, and `(t + 1)(2^256 - p) < 32 * 2^224 < p`. So the sum
    `v + (t + 1)(2^256 - p)` either carries out of the top word, and its four
    words are the answer, or does not, and the answer is them plus p, modulo
    2^256, added through a mask made from the carry. One fold and one
    correction. `(t + 1)(2^256 - p)`, with `q = t + 1` and
    `2^256 - p = 2^224 - 2^192 - 2^96 + 1`, is the four words
    `q, -(q << 32), -1, (q << 32) - q - 1`."""
    cm, dm = int(cm), int(dm)
    assert 1 <= cm <= 16 and 1 <= dm <= 16 and cm + dm <= 31
    n = ["{t0}", "{t1}", "{t2}", "{t3}"]
    top = "{t4}"
    out = [f"xor {top[:-1]}:e}}, {top[:-1]}:e}}" if dm == 1 else "",
           "mov {t0}, -1",
           f"sub {{t0}}, {addr(b, 0)}",
           f"mov {{t1:e}}, {P1}",
           f"sbb {{t1}}, {addr(b, 1)}",
           "mov {t2:e}, 0",
           f"sbb {{t2}}, {addr(b, 2)}",
           f"mov {{t3}}, {P3}",
           f"sbb {{t3}}, {addr(b, 3)}"]
    out = [x for x in out if x]
    if dm == 1:
        pass
    elif dm & (dm - 1) == 0:
        k = dm.bit_length() - 1
        out += [f"mov {top}, {{t3}}", f"shr {top}, {64 - k}",
                f"shld {{t3}}, {{t2}}, {k}", f"shld {{t2}}, {{t1}}, {k}",
                f"shld {{t1}}, {{t0}}, {k}", f"shl {{t0}}, {k}"]
    else:
        out += [f"mov edx, {dm}",
                "mulx {c}, {t0}, {t0}",
                "mulx {t5}, {t1}, {t1}",
                "add {t1}, {c}",
                "mulx {c}, {t2}, {t2}",
                "adc {t2}, {t5}",
                f"mulx {top}, {{t3}}, {{t3}}",
                "adc {t3}, {c}",
                f"adc {top}, 0"]
    out += [f"mov edx, {cm}", "xor {t6:e}, {t6:e}"]
    for i in range(3):
        out += [f"mulx {{c}}, rax, {addr(a, i)}", f"adcx {n[i]}, rax", f"adox {n[i + 1]}, {{c}}"]
    out += [f"mulx rdx, rax, {addr(a, 3)}", "adcx {t3}, rax", f"adox rdx, {top}", "adcx rdx, {t6}"]
    # q = t + 1, and q (2^256 - p) as four words.
    out += [
        "add rdx, 1",
        "mov rax, rdx",
        "shl rax, 32",
        "mov {c}, rax",
        "neg rax",
        "sub {c}, rdx",
        "sub {c}, 1",
        "add {t0}, rdx",
        "adc {t1}, rax",
        "adc {t2}, -1",
        "adc {t3}, {c}",
        # No carry: add p. All ones in rax where that is due.
        "cmc",
        "sbb rax, rax",
        "mov rdx, rax",
        "shr rdx, 32",
        f"mov {{c}}, {P3}",
        "and {c}, rax",
        "add {t0}, rax",
        "adc {t1}, rdx",
        "adc {t2}, 0",
        "adc {t3}, {c}",
    ]
    out += store(dst, n)
    return out


OPS = {"mul": mul, "sqr": sqr, "add": add, "sub": sub, "mulk": mulk, "cms": cms}


def emit(name, doc, slots, program, test_only=False):
    """slots: list of slot names in order; program: list of (op, dst, a[, b])."""
    idx = {n: i for i, n in enumerate(slots)}
    out = []
    out.append(f"/// {doc}")
    out.append("///")
    out.append("/// Slots, 32 bytes each, in order: " + ", ".join(f"`{s}`" for s in slots) + ".")
    out.append("///")
    out.append("/// # Safety")
    out.append("///")
    out.append("/// The CPU must support BMI2 and ADX; see `super::p256_x86::has_adx`.")
    if test_only:
        out.append("#[cfg(test)]")
    out.append("#[inline(never)]")
    out.append(f"pub unsafe fn {name}(buf: &mut [MaybeUninit<u64>; {4 * len(slots)}]) {{")
    out.append("    // SAFETY: the caller guarantees the instructions exist. The block reads")
    out.append("    // and writes only the buffer behind `{s}`, a live, exclusive reference")
    out.append(f"    // of {32 * len(slots)} bytes, at offsets below that; it writes only the")
    out.append("    // registers it declares, and does not touch the stack. It reads no slot")
    out.append("    // before writing it but the inputs, which the caller has written.")
    out.append("    unsafe {")
    out.append("        asm!(")
    # Aligned, so the block's speed does not depend on where it lands; see
    # `ic-rsa`'s x86 module. The padding is a few NOPs, run once per call.
    out.append('            ".p2align 6",')
    body = []
    for op, *args in program:
        body.append(f"            // {args[0]} = {op}({', '.join(args[1:])})")
        operands = [idx[x] if x in idx else int(x) for x in args]
        for l in OPS[op](*operands):
            body.append(f'            "{l}",')
    out += body
    out.append("            s = in(reg) buf.as_mut_ptr(),")
    # Only the registers the block names: an unused operand is an error.
    text = "\n".join(body)
    for name in [f"t{i}" for i in range(8)] + ["c"]:
        if "{" + name + "}" in text or "{" + name + ":e}" in text:
            out.append(f"            {name} = out(reg) _,")
    out.append('            out("rax") _,')
    out.append('            out("rdx") _,')
    out.append("            options(nostack),")
    out.append("        );")
    out.append("    }")
    out.append("}")
    return "\n".join(out)


HEADER = '''//! P-256 point formulas, each one `asm!` block over `mulx`/`adcx`/`adox`.
//!
//! GENERATED by `scripts/gen_p256_x86_point.py`; edit that, not this.
//!
//! The field operations are those of [`super::p256_x86`] -- the same
//! multiplication, squaring, addition and subtraction, instruction for
//! instruction -- strung together over a buffer of 32-byte slots instead of
//! called one at a time. What that removes is everything between them: the
//! per-operation feature check, and moving each result out of registers into
//! a Rust value and back into memory for the next. Each formula computes the
//! same field values as its Rust counterpart in `point.rs` -- the doubling's
//! small multiples fused into three operations, the operations in an order
//! the core can overlap -- so the results are equal bit for bit; the tests
//! hold them to that. The doubling is also emitted in place, for the scalar
//! multiplication's loop.
//!
//! Every operation reads its operands before writing its result, so a
//! destination may also be a source. Nothing branches and nothing is indexed
//! by data: the reductions end in `cmovc`, the subtractions in a borrow mask.

use core::arch::asm;
use core::mem::MaybeUninit;
'''


def main():
    parts = [HEADER.rstrip("\n")]
    parts.append(emit(
        "double_adx",
        "Point doubling, `dbl-2001-b` for `a = -3`, as `Point::double`.",
        DOUBLE_SLOTS, DOUBLE))
    parts.append(emit(
        "double_in_place_adx",
        "`double_adx` with X3, Y3 and Z3 written over X, Y and Z: the scalar "
        "multiplication's doubling, on a buffer whose first slots are its accumulator.",
        DOUBLE_IP_SLOTS, DOUBLE_IP))
    parts.append(emit(
        "add_adx",
        "Jacobian addition, `add-2007-bl`, as `Point::add_formula`; also leaves `H` and `R`.",
        ADD_SLOTS, ADD))
    parts.append(emit(
        "add_affine_adx",
        "Mixed addition, `madd-2007-bl`, as `Point::add_affine_formula`; also leaves `H` and `R`.",
        MADD_SLOTS, MADD))
    for cm, dm in CMS_USED:
        parts.append(emit(
            f"cms_{cm}_{dm}_adx",
            f"`{cm} A - {dm} B`, alone, for the tests: a fused operation the doubling uses.",
            ["A", "B", "OUT"], [("cms", "OUT", "A", "B", str(cm), str(dm))], test_only=True))
    for k in (3, 4, 8):
        parts.append(emit(
            f"times{k}_adx",
            f"`{k} * A`, alone, for the tests: the small-multiple operation the formulas use.",
            ["A", "OUT"], [("mulk", "OUT", "A", str(k))], test_only=True))
    text = "\n\n".join(parts) + "\n"
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


# `Point::double`'s values, with its small multiples folded into three fused
# operations, as for P-384: with `m = X^2 - Z^4`, `alpha = 3m` and
# `beta = X Y^2`,
#   d  = 12 beta - 9 m^2           (= 4 beta - alpha^2)
#   X3 = 4 beta - d                (= alpha^2 - 8 beta)
#   Y3 = 3 d m - 8 Y^4             (= alpha (4 beta - X3) - 8 gamma^2)
#   Z3 = (Y + Z)^2 - Y^2 - Z^2
# The same field elements, so the same canonical words; eight additive steps
# where the formula as written takes fifteen. In an order for the core to
# overlap: each chain's next step as soon as its inputs are there, and
# independent work between a step and the next, which needs it.
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
    ("cms", "d", "beta", "m2", "12", "9"),
    ("sqr", "g2", "gamma"),
    ("mul", "u", "d", "m"),
    ("cms", "X3", "beta", "d", "4", "1"),
    ("sub", "w", "w", "gamma"),
    ("sub", "Z3", "w", "delta"),
    ("cms", "Y3", "u", "g2", "3", "8"),
]

# Every (cm, dm) the doubling uses; each is emitted alone for the tests.
CMS_USED = sorted({(int(op[4]), int(op[5])) for op in DOUBLE if op[0] == "cms"})


# The same doubling in place, for the scalar multiplication's loop: X3, Y3
# and Z3 written over X, Y and Z, each after the last operation that reads
# it, which `in_place` checks.
def in_place(program, rename):
    out = []
    written = set()
    for op, dst, *src in program:
        for x in src:
            assert x not in written, (op, dst, x)
        dst = rename.get(dst, dst)
        if dst in rename.values():
            written.add(dst)
        out.append((op, dst, *src))
    return out


DOUBLE_IP_RENAME = {"X3": "X", "Y3": "Y", "Z3": "Z"}
DOUBLE_IP_SLOTS = [x for x in DOUBLE_SLOTS if x not in DOUBLE_IP_RENAME]
DOUBLE_IP = in_place(DOUBLE, DOUBLE_IP_RENAME)

# The additions' operations in an order for the core to overlap, as for
# P-384; the same operations on the same values, so the same words.
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
    ("mulk", "i", "hh", "4"),
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

main()
