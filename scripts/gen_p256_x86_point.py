"""Generate crates/ic-ec/src/nist/p256_x86_point.rs: P-256 point formulas as
Rust `asm!` blocks over MULX/ADX.

    python scripts/gen_p256_x86_point.py crates/ic-ec/src/nist/p256_x86_point.rs

Each formula is a list of field operations on 32-byte slots in one buffer
whose address is in `{s}`. Every operation reads its operands from memory and
writes its result to memory after all reads, so a destination may be a source.
The field operations are the instruction sequences of
crates/ic-ec/src/nist/p256_x86.rs (`mul_adx`, `square_adx`, `add`, `sub`),
with memory operands; the formulas are those of crates/ic-ec/src/nist/point.rs,
operation for operation, so the results agree bit for bit, which the tests
check.
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


OPS = {"mul": mul, "sqr": sqr, "add": add, "sub": sub}


def emit(name, doc, slots, program):
    """slots: list of slot names in order; program: list of (op, dst, a[, b])."""
    idx = {n: i for i, n in enumerate(slots)}
    out = []
    out.append(f"/// {doc}")
    out.append("///")
    out.append("/// Slots, 32 bytes each, in order: " + ", ".join(f"`{s}`" for s in slots) + ".")
    out.append("///")
    out.append("/// # Safety")
    out.append("///")
    out.append("/// The CPU must support BMI2 and ADX; see [`super::p256_x86::has_adx`].")
    out.append("#[inline(never)]")
    out.append(f"pub(crate) unsafe fn {name}(buf: &mut [u64; {4 * len(slots)}]) {{")
    out.append("    // SAFETY: the caller guarantees the instructions exist. The block reads")
    out.append("    // and writes only the buffer behind `{s}`, a live, exclusive reference")
    out.append(f"    // of {32 * len(slots)} bytes, at offsets below that; it writes only the")
    out.append("    // registers it declares, and does not touch the stack.")
    out.append("    unsafe {")
    out.append("        asm!(")
    for op, *args in program:
        out.append(f"            // {args[0]} = {op}({', '.join(args[1:])})")
        for l in OPS[op](*[idx[x] for x in args]):
            out.append(f'            "{l}",')
    out.append("            s = in(reg) buf.as_mut_ptr(),")
    for i in range(8):
        out.append(f"            t{i} = out(reg) _,")
    out.append("            c = out(reg) _,")
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
//! a Rust value and back into memory for the next. Each formula is the same
//! sequence of field operations as its Rust counterpart in `point.rs`, in the
//! same order, so the results are equal bit for bit; the tests hold them to
//! that.
//!
//! Every operation reads its operands before writing its result, so a
//! destination may also be a source. Nothing branches and nothing is indexed
//! by data: the reductions end in `cmovc`, the subtractions in a borrow mask.

use core::arch::asm;
'''


def main():
    parts = [HEADER.rstrip("\n")]
    parts.append(emit(
        "double_adx",
        "Point doubling, `dbl-2001-b` for `a = -3`, as `Point::double`.",
        DOUBLE_SLOTS, DOUBLE))
    parts.append(emit(
        "add_adx",
        "Jacobian addition, `add-2007-bl`, as `Point::add_formula`; also leaves `H` and `R`.",
        ADD_SLOTS, ADD))
    parts.append(emit(
        "add_affine_adx",
        "Mixed addition, `madd-2007-bl`, as `Point::add_affine_formula`; also leaves `H` and `R`.",
        MADD_SLOTS, MADD))
    text = "\n\n".join(parts) + "\n"
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


DOUBLE_SLOTS = ["X", "Y", "Z", "X3", "Y3", "Z3", "delta", "gamma", "beta", "t", "u", "alpha", "beta8", "w"]
DOUBLE = [
    ("sqr", "delta", "Z"),
    ("sqr", "gamma", "Y"),
    ("mul", "beta", "X", "gamma"),
    ("sub", "t", "X", "delta"),
    ("add", "u", "X", "delta"),
    ("mul", "t", "t", "u"),
    ("add", "alpha", "t", "t"),
    ("add", "alpha", "alpha", "t"),
    ("add", "beta", "beta", "beta"),
    ("add", "beta", "beta", "beta"),
    ("add", "beta8", "beta", "beta"),
    ("sqr", "w", "alpha"),
    ("sub", "X3", "w", "beta8"),
    ("add", "w", "Y", "Z"),
    ("sqr", "w", "w"),
    ("sub", "w", "w", "gamma"),
    ("sub", "Z3", "w", "delta"),
    ("sqr", "gamma", "gamma"),
    ("add", "gamma", "gamma", "gamma"),
    ("add", "gamma", "gamma", "gamma"),
    ("add", "gamma", "gamma", "gamma"),
    ("sub", "beta", "beta", "X3"),
    ("mul", "beta", "alpha", "beta"),
    ("sub", "Y3", "beta", "gamma"),
]

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

main()
