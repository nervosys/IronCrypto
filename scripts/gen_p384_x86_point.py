"""Generate crates/ic-ec/src/nist/p384_x86_point.rs: P-384 point formulas as
Rust `asm!` blocks over MULX/ADX.

    python scripts/gen_p384_x86_point.py crates/ic-ec/src/nist/p384_x86_point.rs

The counterpart of scripts/gen_p256_x86_point.py for P-384, whose prime has
no shape the reduction can use as cheaply, so the field operations here are
generic in the modulus: CIOS multiplication with the modulus read through a
RIP-relative address and `-p^-1 mod 2^64` as an immediate, as in
scripts/gen_mont_x86.py, and additions and subtractions that bring the result
back below `p` with one masked correction. Each formula is a list of field
operations on 48-byte slots in one buffer whose address is in `{s}`; every
operation reads its operands before writing its result. The formulas are
those of crates/ic-ec/src/nist/point.rs, operation for operation, so the
results agree bit for bit, which the tests check.
"""
import sys

N = 6
SLOT = 8 * N


def addr(slot, word):
    off = SLOT * slot + 8 * word
    return f"qword ptr [{{s}} + {off}]" if off else "qword ptr [{s}]"


def mod(word):
    return f"qword ptr [rip + {{m}} + {8 * word}]" if word else "qword ptr [rip + {m}]"


W = [f"{{w{i}}}" for i in range(N + 2)]


def finish(dst, value, top):
    """Store `value` (N registers, below 2p, with `top` its carry word) to
    `dst`, less p unless that borrows: the difference goes to memory a word
    at a time through rax, the borrow out decides, and `cmovc` takes the
    register back where it borrowed. `mov` leaves the flags alone."""
    out = []
    for i in range(N):
        op = "sub" if i == 0 else "sbb"
        out += [f"mov rax, {value[i]}", f"{op} rax, {mod(i)}", f"mov {addr(dst, i)}, rax"]
    out.append(f"sbb {top}, 0")
    for i in range(N):
        out += [f"mov rax, {addr(dst, i)}", f"cmovc rax, {value[i]}", f"mov {addr(dst, i)}, rax"]
    return out


def mul(dst, a, b):
    out = [f"xor {r[:-1]}:e}}, {r[:-1]}:e}}" for r in W[: N + 1]]
    for i in range(N):
        win = [W[(i + j) % (N + 2)] for j in range(N + 1)]
        top = W[(i + N + 1) % (N + 2)]
        out += [f"mov rdx, {addr(b, i)}", f"xor {top[:-1]}:e}}, {top[:-1]}:e}}"]
        for j in range(N):
            out += [f"mulx {{c}}, rax, {addr(a, j)}", f"adcx {win[j]}, rax", f"adox {win[j + 1]}, {{c}}"]
        out += ["mov eax, 0", f"adcx {win[N]}, rax", f"adox {top}, rax", f"adcx {top}, rax"]
        out += ["mov rdx, {ninv}", f"imul rdx, {win[0]}", "xor eax, eax"]
        for j in range(N):
            out += [f"mulx {{c}}, rax, {mod(j)}", f"adcx {win[j]}, rax", f"adox {win[j + 1]}, {{c}}"]
        out += ["mov eax, 0", f"adcx {win[N]}, rax", f"adox {top}, rax", f"adcx {top}, rax"]
    final = [W[(N + j) % (N + 2)] for j in range(N + 1)]
    return out + finish(dst, final[:N], final[N])


def sqr(dst, a):
    return mul(dst, a, a)


def add(dst, a, b):
    v = W[:N]
    out = [f"mov {v[i]}, {addr(a, i)}" for i in range(N)]
    out += ["xor {c:e}, {c:e}", f"add {v[0]}, {addr(b, 0)}"]
    out += [f"adc {v[i]}, {addr(b, i)}" for i in range(1, N)]
    out += ["adc {c}, 0"]
    return out + finish(dst, v, "{c}")


def sub(dst, a, b, scratch):
    v = W[:N]
    out = [f"mov {v[i]}, {addr(a, i)}" for i in range(N)]
    out += [f"sub {v[0]}, {addr(b, 0)}"]
    out += [f"sbb {v[i]}, {addr(b, i)}" for i in range(1, N)]
    # All ones on a borrow. Then p masked by it, into the scratch slot, so
    # the addition chain is not broken by the masking's flags.
    out += ["sbb {c}, {c}"]
    for i in range(N):
        out += [f"mov rax, {mod(i)}", "and rax, {c}", f"mov {addr(scratch, i)}, rax"]
    out += [f"add {v[0]}, {addr(scratch, 0)}"]
    out += [f"adc {v[i]}, {addr(scratch, i)}" for i in range(1, N)]
    out += [f"mov {addr(dst, i)}, {v[i]}" for i in range(N)]
    return out


def emit(name, doc, slots, program):
    slots = slots + ["scratch"]
    idx = {n: i for i, n in enumerate(slots)}
    o = [f"/// {doc}", "///"]
    o.append("/// Slots, 48 bytes each, in order: " + ", ".join(f"`{s}`" for s in slots) + ".")
    o += ["///", "/// # Safety", "///",
          "/// The CPU must support BMI2 and ADX; see `super::p256_x86::has_adx`.",
          "#[inline(never)]",
          f"pub unsafe fn {name}(buf: &mut [MaybeUninit<u64>; {N * len(slots)}]) {{",
          "    // SAFETY: the caller guarantees the instructions exist. The block reads",
          "    // and writes only the buffer behind `{s}`, a live, exclusive reference",
          f"    // of {SLOT * len(slots)} bytes, at offsets below that, and reads `P384_P`, a",
          "    // static; it writes only the registers it declares, and does not touch",
          "    // the stack. It reads no slot before writing it but the inputs, which",
          "    // the caller has written.",
          "    unsafe {",
          "        asm!("]
    for op, *args in program:
        o.append(f"            // {args[0]} = {op}({', '.join(args[1:])})")
        operands = [idx[x] for x in args]
        if op == "sub":
            operands.append(idx["scratch"])
        for line in {"mul": mul, "sqr": sqr, "add": add, "sub": sub}[op](*operands):
            o.append(f'            "{line}",')
    o.append("            s = in(reg) buf.as_mut_ptr(),")
    o.append("            m = sym P384_P,")
    o.append("            ninv = const neg_inv(P384_P_WORDS[0]),")
    for i in range(N + 2):
        o.append(f"            w{i} = out(reg) _,")
    o += ["            c = out(reg) _,", '            out("rax") _,', '            out("rdx") _,',
          "            options(nostack),", "        );", "    }", "}"]
    return "\n".join(o)


HEADER = '''//! P-384 point formulas, each one `asm!` block over `mulx`/`adcx`/`adox`.
//!
//! GENERATED by `scripts/gen_p384_x86_point.py`; edit that, not this.
//!
//! The formulas of `point.rs` -- doubling, addition and mixed addition -- in
//! the same order of field operations, over a buffer of 48-byte slots. The
//! field operations are generic in the modulus, which is read from a static
//! through a RIP-relative address: CIOS multiplication on two carry chains,
//! squaring as multiplication, and additions and subtractions corrected by one
//! masked step. Nothing branches and nothing is indexed by data: every final
//! correction is `cmovc` on a borrow or a mask from `sbb`.

use core::arch::asm;
use core::mem::MaybeUninit;

/// `-m^-1 mod 2^64`, by Newton iteration, as `arith::compute_neg_inv`.
const fn neg_inv(m0: u64) -> u64 {
    let mut inv = m0;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// P-384's prime, little-endian.
const P384_P_WORDS: [u64; 6] = [
    0x0000_0000_ffff_ffff,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// The prime, for the RIP-relative reads.
static P384_P: [u64; 6] = P384_P_WORDS;'''

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


def main():
    parts = [HEADER]
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
