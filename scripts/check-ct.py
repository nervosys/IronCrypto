#!/usr/bin/env python3
"""Reject control flow and division in narrowly scoped, fixed-parameter probes.

This is a compiler regression gate, not a proof of constant time. It examines
LTO output from the real library, rejects unresolved calls, and requires every
expected symbol. See docs/CONSTANT_TIME.md for coverage and limitations.
"""

import argparse
import collections
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "thumbv6m-none-eabi",
    "thumbv7em-none-eabihf",
    "riscv32imac-unknown-none-elf",
)
SYMBOLS = (
    "ct_reduce_q", "ct_power2round", "ct_decompose_32", "ct_decompose_88",
    "ct_compress_1", "ct_compress_4", "ct_compress_5", "ct_compress_10",
    "ct_compress_11", "ct_cbd2", "ct_cbd3", "ct_reduce_12", "ct_unpack8_12",
    "ct_pack8_12", "ct_barrett_reduce", "ct_montgomery_reduce", "ct_select_u32", "ct_select_u64", "ct_hex_encode",
    "ct_base64_encode",
    "ct_select_u8", "ct_eq_4", "ct_zero_4", "ct_lt_be_4", "ct_cmov_4", "ct_cswap_4",
)
# P-256 field and scalar operations: what hashing to the curve, the OPRF,
# ECDH and ECDSA are built from.
P256 = tuple(
    f"ct_p256_{field}_{op}"
    for field in ("fp", "fn")
    for op in ("reduce", "add", "sub", "mul", "neg", "cmov", "eq", "is_odd")
)
SYMBOLS += P256
# Ed25519 scalar arithmetic modulo L, on the secret nonce and S.
ED25519 = ("ct_ed25519_reduce_wide", "ct_ed25519_mul_add")
SYMBOLS += ED25519
# The x86-64 Curve25519 backends: the MULX/ADX field, X25519's ladder step and
# signing's group operations on it, and the AVX-512 IFMA four-lane forms.
# They compile for x86-64 only, so they are required there and nowhere else.
X86_ONLY = (
    "ct_fe64_mul", "ct_fe64_square", "ct_fe64_add", "ct_fe64_sub",
    "ct_fe64_mul121666", "ct_fe64_invert", "ct_x25519_fe64_step",
    "ct_ed25519_fe64_madd_ext2", "ct_ed25519_fe64_dbl_nadd",
    "ct_x25519_ifma_step", "ct_ed25519_ifma_select", "ct_ed25519_ifma_add",
    "ct_ed25519_ifma_double",
    # P-256's field multiplication and squaring on MULX/ADCX/ADOX, chosen at
    # run time where the CPU has BMI2 and ADX, and the point formulas that are
    # whole blocks of that assembly; the P-256 probes above, built without
    # `std`, compile to the baseline sequence, so these name the others.
    # P-384's field multiplication and squaring specialised to its prime, its
    # scalar ring's multiplication, its point formulas, and its field
    # inversion by divsteps exist only here. So do the divsteps inversions
    # of P-256's two rings: 64-bit only, and x86-64 is the 64-bit target.
    "ct_p256_fp_mul_adx", "ct_p256_fp_square_adx",
    "ct_p256_point_double_adx", "ct_p256_point_add_adx",
    "ct_p256_point_add_affine_adx", "ct_p256_fp_invert", "ct_p256_fn_invert",
    "ct_p384_fp_mul_adx", "ct_p384_fp_sqr_adx", "ct_p384_fn_mul_adx",
    "ct_p384_point_double_adx", "ct_p384_point_add_adx",
    "ct_p384_point_add_affine_adx", "ct_p384_fp_invert",
    # RSA's windowed-exponentiation table read at 2048 bits. Its masked scan is
    # unrolled on x86-64. On the 32-bit targets and RISC-V LLVM keeps the entry
    # loop rolled, a loop over a public count, so the probe is x86-64 only.
    "ct_rsa_select_2048",
    # ChaCha20's sixteen-block AVX-512 keystream group, and Poly1305's
    # four-lane AVX2 step and final lane folding, under the key's r and s.
    "ct_chacha20_zmm_group", "ct_poly1305_avx2_step", "ct_poly1305_avx2_finish",
    # RSA's Montgomery products at 2048 bits: the MULX/ADCX/ADOX product, the
    # AVX-512 IFMA almost-Montgomery product, and the portable CIOS product.
    # Each loops over the public width, and their loop branches are excused by
    # the x86-64 rules below, up to X86_EXCUSE_CEILINGS. On the 32-bit targets
    # the CIOS product clears its accumulator with a runtime-library call and
    # its loop tests do not fit the 32-bit counter shapes, so it is not
    # required there.
    "ct_rsa_adx_mont_mul_2048", "ct_rsa_ifma_amm_2048", "ct_rsa_cios_2048",
    # RSA's whole exponentiation on AVX-512 IFMA, compiled once per width:
    # at 1024 bits, each of RSA-2048's two CRT exponentiations, and at 2048
    # bits, its modulus. Its loops are excused the same way.
    "ct_rsa_ifma_pow_1024", "ct_rsa_ifma_pow_2048",
)
SYMBOLS += X86_ONLY


def symbols_for(target):
    """The probes `target` must have."""
    if target.startswith("x86_64"):
        return SYMBOLS
    return tuple(s for s in SYMBOLS if s not in X86_ONLY)

# Runtime-library routines a probe may call on a target, because their bodies
# are disassembled from that target's compiler_builtins and held to the same
# rules as the probes. Cortex-M0 has no 32x32->64 multiply, so every wide
# product in the P-256 arithmetic is a call to `__aeabi_lmul`.
VERIFIED_EXTERNAL = {
    "thumbv6m-none-eabi": ("__aeabi_lmul",),
}

# On the 32-bit targets LLVM keeps P-256's Montgomery word loop rolled, and on
# RISC-V zeroes its scratch array with `memset`. Those findings are excused by
# rule, each rule about the instructions around the finding rather than its
# text, and only in the P-256 probes on these targets; everything else still
# fails. Each rule also has a ceiling, the number it excused when the findings
# were last read (docs/CONSTANT_TIME.md): more than that fails too, so a new
# loop or a new call is read before it is accepted, rather than passing because
# it resembles an old one.
# Counted per probe, following calls: one loop in a shared `from_mont` is
# counted once for each probe that reaches it. Read on 2026-10-12, rustc 1.99.0.
EXCUSE_CEILINGS = {
    "thumbv6m-none-eabi": {"counter loop": 32, "unconditional jump": 40,
                           "literal-pool jump": 12},
    "thumbv7em-none-eabihf": {"counter loop": 32},
    "riscv32imac-unknown-none-elf": {"stack-bound loop": 16, "constant memset": 16},
}

# On x86-64 three rules (X86Body, below) excuse loops over a public count, and
# only in the probes named here, each rule up to the number of findings it
# excused when they were read one by one (docs/CONSTANT_TIME.md, "Loops on
# x86-64"). A probe not named excuses nothing; one finding more than its
# ceiling fails. Counted per probe, following calls. Read on 2026-10-13,
# rustc 1.99.0.
X86_EXCUSE_CEILINGS = {
    # The kernel's two inner passes (`jrcxz` on rcx, stepped by `lea 4(rcx)`,
    # each closed by a `jmp`), its row loop (`dec`/`jne` on the row count),
    # the masked subtraction's word loop (`cmp $32`), and the zeroing of the
    # 66-word accumulator on the stack.
    "ct_rsa_adx_mont_mul_2048": {"counter loop": 4, "unconditional jump": 2,
                                 "constant memset": 1},
    # The kernel's row loop: `dec`/`jne` on the 40 rows.
    "ct_rsa_ifma_amm_2048": {"counter loop": 1},
    # The two inner j loops and the outer i loop of CIOS, the masked
    # subtraction's word loop, the jump into the outer loop and the inner
    # loop's back edge, and the zeroing of the 34-word accumulator.
    "ct_rsa_cios_2048": {"counter loop": 4, "unconditional jump": 2,
                         "constant memset": 1},
    # The whole IFMA exponentiation, following its calls. At 1024 bits: the
    # kernel's row loop (`dec`/`jne` on the 20 rows) three times, inlined
    # for the squaring and the multiplication in the window loop and once in
    # the out-of-line product everything else calls; the four squarings; the
    # table read's word loop (20 words); the window loop (`test`/`jne` on a
    # counter from `exp_bits`); the masking of the exponent (64 words, two a
    # time); the conversion out of radix 2^52 (16 words); the wipe of the
    # work area; and the `memset` that zeroes it on the stack.
    "ct_rsa_ifma_pow_1024": {"counter loop": 9, "constant memset": 1},
    # At 2048 bits the same nine (40 rows, 40 words, 32 words), and three that
    # the 1024-bit copy unrolls: the modulus's and the out-of-line conversion
    # into radix 2^52 (39 limbs each), and the masked subtraction at the end
    # (32 words).
    "ct_rsa_ifma_pow_2048": {"counter loop": 12, "constant memset": 1},
}

# Loads and stores, which do not set the flags a conditional branch reads, and
# so may sit between the comparison and the branch.
_MEMORY = re.compile(r"(?:ldr|str|ldm|stm)[a-z]*(?:\.w)?")
_THUMB_COND = re.compile(
    r"b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.w)?")
_LOCAL_LABEL = re.compile(r"\.L[\w.$]+")


def bodies(assembly, required=SYMBOLS):
    """Read ELF function boundaries; missing/aliased bodies fail closed.

    Probes, and every symbol the file declares a function with `.type`, so
    that a call from a probe can be followed into a body in the same file.
    Every symbol in `required` must have a body.
    """
    functions = set(required) | set(re.findall(
        r"^\s*\.type\s+([^\s,]+)\s*,\s*[@%]function", assembly, re.MULTILINE))
    result = {}
    current = None
    for line in assembly.splitlines():
        label = re.fullmatch(r"([^\s:]+):", line.strip())
        if label and label[1] not in functions:
            label = None
        if label:
            name = label[1]
            if name in result:
                raise ValueError(f"duplicate symbol {name}")
            if current:
                raise ValueError(f"unterminated function {current}")
            current = name
            result[current] = []
        elif current:
            if re.match(r"\s*\.size\s+" + re.escape(current) + r"\s*,", line):
                current = None
            else:
                result[current].append(line)
    if current:
        raise ValueError(f"unterminated function {current}")
    missing = set(required) - result.keys()
    if missing:
        raise ValueError("missing probe bodies: " + ", ".join(sorted(missing)))
    return result


def forbidden(line, target):
    # Strip comments without treating ARM immediates (#) as comments.
    line = re.split(r"\s+(?:@|//|# )", line, maxsplit=1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return False
    fields = line.split(None, 1)
    mnemonic = fields[0].lower()
    if target.startswith("riscv32") and mnemonic.startswith("c."):
        mnemonic = mnemonic[2:]
    op = mnemonic.split(".")[0]
    operands = fields[1].strip() if len(fields) == 2 else ""
    if target.startswith("x86_64"):
        return (op.startswith(("j", "loop", "call"))
                or re.fullmatch(r"i?div[bwlq]?", op) is not None)
    if target.startswith("thumb"):
        # bx lr is a return. ARM IT blocks are predication, not branches;
        # this check does not claim to establish instruction-level timing.
        if op == "bx" and operands == "lr":
            return False
        return (op in {"b", "bl", "blx", "bx", "cbz", "cbnz", "tbb", "tbh"}
                or re.fullmatch(r"b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)", op) is not None
                or op in {"sdiv", "udiv"})
    if target.startswith("riscv32"):
        return (op.startswith(("div", "rem"))
                or op in {"call", "tail", "jal", "jalr", "j", "jr"}
                or re.fullmatch(r"b(?:eq|ne|lt|ge|gt|le)(?:u|z)?", op) is not None)
    raise ValueError(f"unsupported target {target}")


def called(line, target, defined):
    """The function a call or tail call names, if its body is in this file.

    A call into a body the checker can read is followed rather than
    rejected, and the callee is held to the same rules. A call to anything
    else -- a runtime-library routine, a register -- stays forbidden: its
    instructions are not here to inspect.
    """
    line = re.split(r"\s+(?:@|//|# )", line, maxsplit=1)[0].strip()
    fields = line.split(None, 1)
    if len(fields) != 2:
        return None
    mnemonic = fields[0].lower()
    if target.startswith("riscv32") and mnemonic.startswith("c."):
        mnemonic = mnemonic[2:]
    op = mnemonic.split(".")[0]
    operand = fields[1].strip().removesuffix("@PLT")
    calls = {
        "x86_64": {"call", "callq", "jmp", "jmpq"},
        "thumb": {"bl", "b"},
        "riscv32": {"call", "tail"},
    }
    family = next(prefix for prefix in calls if target.startswith(prefix))
    if op in calls[family] and operand in defined:
        return operand
    return None


def instructions_of(lines):
    return [line for line in lines if line.strip()
            and not line.strip().startswith((".", "#", "@", "//"))
            and not line.strip().endswith(":")]


def _split(line):
    line = re.split(r"\s+(?:@|//|# )", line, maxsplit=1)[0].strip()
    fields = line.split(None, 1)
    op = fields[0].lower() if fields else ""
    if op.startswith("c."):
        op = op[2:]
    operands = [o.strip() for o in fields[1].split(",")] if len(fields) == 2 else []
    return op, operands


def _previous(ins, i, count, skip=None):
    """Up to `count` instructions before `i`, nearest first, passing over any
    that `skip` matches."""
    found = []
    j = i - 1
    while j >= 0 and len(found) < count:
        op, operands = _split(ins[j])
        if not (skip and skip.fullmatch(op)):
            found.append((op, operands))
        j -= 1
    return found


_POOL_DATA = re.compile(r"\.(?:p2align|align|long|short|byte|word|zero)\b")


def pool_jumps(lines):
    """Indices, into `instructions_of(lines)`, of Thumb unconditional jumps
    over a literal pool: `b L` where everything between it and `L:` is
    constant-pool data -- `.LCPI` labels, alignment and data directives.

    Thumb-1 can only load a 32-bit constant from memory near the code, so
    the compiler parks constants mid-function and jumps over them to the
    very next instruction. Such a jump has one target and no condition, and
    whether it is taken depends on nothing.
    """
    found = set()
    index = -1
    for r, line in enumerate(lines):
        text = line.strip()
        if not text or text.startswith((".", "#", "@", "//")) or text.endswith(":"):
            continue
        index += 1
        op, operands = _split(line)
        if op not in {"b", "b.n"} or len(operands) != 1 or not _LOCAL_LABEL.fullmatch(operands[0]):
            continue
        for following in lines[r + 1:]:
            t = following.strip()
            if t == operands[0] + ":":
                found.add(index)
                break
            if not t or _POOL_DATA.match(t) or re.fullmatch(r"\.LCPI[\w.$]+:", t):
                continue
            break
    return found


def excuse(target, ins, i):
    """The rule that excuses the finding at `ins[i]`, or None.

    Applied only to P-256 probes on 32-bit targets; see EXCUSE_CEILINGS.
    """
    op, operands = _split(ins[i])
    if target.startswith("thumb"):
        if op in {"b", "b.w"} and len(operands) == 1 and _LOCAL_LABEL.fullmatch(operands[0]):
            return "unconditional jump"
        if _THUMB_COND.fullmatch(op) and len(operands) == 1 and _LOCAL_LABEL.fullmatch(operands[0]):
            before = _previous(ins, i, 2, _MEMORY)
            imm = re.compile(r"#\d+")
            # Cortex-M4: a counter decremented by a constant, then tested.
            if (before and before[0][0] == "subs" and len(before[0][1]) == 2
                    and imm.fullmatch(before[0][1][1])):
                return "counter loop"
            # Cortex-M0: a counter stepped by a constant, then compared with
            # a constant.
            if (len(before) == 2 and before[0][0] == "cmp" and before[1][0] == "adds"
                    and len(before[0][1]) == 2 and len(before[1][1]) == 2
                    and before[0][1][0] == before[1][1][0]
                    and imm.fullmatch(before[0][1][1]) and imm.fullmatch(before[1][1][1])):
                return "counter loop"
        return None
    if target.startswith("riscv32"):
        if op == "j" and len(operands) == 1 and _LOCAL_LABEL.fullmatch(operands[0]):
            return "unconditional jump"
        before = _previous(ins, i, 3)
        if (re.fullmatch(r"b(?:eq|ne|lt|ge|ltu|geu)", op) and len(operands) == 3
                and _LOCAL_LABEL.fullmatch(operands[2])):
            # A loop that runs until a pointer reaches the end of a stack
            # array: one operand is that bound, sp plus a constant.
            for prev_op, prev in before:
                if (prev_op == "addi" and len(prev) == 3 and prev[1] == "sp"
                        and prev[0] in operands[:2] and re.fullmatch(r"-?\d+", prev[2])):
                    return "stack-bound loop"
            return None
        if op == "call" and operands == ["memset"]:
            # A constant length, written into the stack.
            length = any(p == "li" and len(a) == 2 and a[0] == "a2"
                         and re.fullmatch(r"\d+", a[1]) for p, a in before)
            dest = any(p == "addi" and len(a) == 3 and a[0] == "a0" and a[1] == "sp"
                       for p, a in before)
            if length and dest:
                return "constant memset"
        return None
    return None


# --- x86-64: loops over a public count -------------------------------------
#
# The rules below excuse three shapes in x86-64 code, and only in the probes
# X86_EXCUSE_CEILINGS names, each up to its own count. They read AT&T syntax,
# which is what rustc emits, inline assembly included; a body that switches to
# Intel syntax gets no excuse at all.
#
# "counter loop": a conditional branch that is a back edge or an exit of a
# natural loop (found from the control-flow graph by dominators, so every
# block on a path between two visits to the loop's header is in it), whose
# condition is a loop counter's: `jrcxz`/`jecxz` on rcx, or a `jcc` whose flags
# come, within its own basic block, from `inc`/`dec`/`add $imm`/`sub $imm` of a
# register, `cmp $imm` or `test` of a register, or `cmp` of two registers. The
# register must be a counter of that loop: every instruction in the loop that
# writes it is `inc`, `dec`, `add $imm`, `sub $imm` or `lea imm(r), r` on it, and
# at least one does. For `cmp` of two registers the other must not be written
# anywhere in the loop. A loop with a call in it excuses nothing.
#
# "unconditional jump": `jmp` to a label in the same function. It has no
# condition; which path reaches it is decided by the branches that are checked.
#
# "constant memset": a call to `memset` whose length was loaded as a constant
# into rdx, value zeroed in rsi, and destination computed as rsp plus a
# constant in rdi, all in the call's own basic block.

_X86_FAMILIES = {}
for _fam, _names in {
    "a": ("rax", "eax", "ax", "al", "ah"), "b": ("rbx", "ebx", "bx", "bl", "bh"),
    "c": ("rcx", "ecx", "cx", "cl", "ch"), "d": ("rdx", "edx", "dx", "dl", "dh"),
    "si": ("rsi", "esi", "si", "sil"), "di": ("rdi", "edi", "di", "dil"),
    "bp": ("rbp", "ebp", "bp", "bpl"), "sp": ("rsp", "esp", "sp", "spl"),
}.items():
    for _n in _names:
        _X86_FAMILIES[_n] = _fam
for _k in range(8, 16):
    for _suffix in ("", "d", "w", "b"):
        _X86_FAMILIES[f"r{_k}{_suffix}"] = f"r{_k}"


def _family(operand):
    """The general-purpose register an operand names, as its 64-bit family, or
    None for anything else: an immediate, memory, a vector register."""
    if not operand.startswith("%"):
        return None
    return _X86_FAMILIES.get(operand[1:].lower())


def _att_operands(text):
    """Operands of an AT&T instruction, split at commas outside parentheses."""
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def _att(line):
    """(mnemonic, operands) of an AT&T line, comments removed."""
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    fields = line.split(None, 1)
    op = fields[0].lower() if fields else ""
    return op, (_att_operands(fields[1]) if len(fields) == 2 else [])


_IMM = re.compile(r"\$-?(?:0x[0-9a-f]+|\d+)")
_JCC = re.compile(r"j(?:n?[abceglopsz]|n?[abgl]e|p[eo])")
# Mnemonics that read every operand and write none.
_READ_ONLY = re.compile(r"(?:cmp|test|bt|u?comis|vu?comis|v?ptest|vtestp|push|prefetch|nop)\w*")
# Instructions that write no flags, which may sit between the instruction that
# sets the flags and the branch that reads them. Anything not listed ends the
# search, and so excuses nothing.
_NO_FLAGS = re.compile(
    r"mov\w*|cmov\w+|lea[wlq]?|mulx[lq]?|(?:shl|shr|sar|ror)x[lq]?|set\w+|nop\w*"
    r"|bswap[lq]?|xchg[bwlq]?|push[wq]?|pop[wq]?|prefetch\w*"
    r"|p(?:and|andn|or|xor|shufd|unpck\w+|add[bwdq]|sub[bwdq]|s[lr]l[wdq]|sra[wd])"
    r"|v(?!u?comis|ptest|testp)\w+")
_IMPLICIT = {
    "cqto": {"d"}, "cqo": {"d"}, "cltd": {"d"}, "cdq": {"d"}, "cwtd": {"d"},
    "cltq": {"a"}, "cdqe": {"a"}, "cwtl": {"a"}, "cbtw": {"a"},
    "cpuid": {"a", "b", "c", "d"}, "rdtsc": {"a", "d"}, "rdtscp": {"a", "c", "d"},
    "xgetbv": {"a", "d"}, "syscall": {"a", "c", "r11"}, "lahf": {"a"}, "xlatb": {"a"},
    "rdmsr": {"a", "d"}, "rdpmc": {"a", "d"}, "rdpkru": {"a", "d"},
    "leave": {"bp"}, "leaveq": {"bp"}, "enter": {"bp"}, "enterq": {"bp"},
}
# Instructions without operands that write no general-purpose register. Any
# other instruction without operands is assumed to write anything.
_NULLARY = {"nop", "ud2", "int3", "hlt", "pause", "lfence", "mfence", "sfence", "clc",
            "stc", "cmc", "cld", "std", "sahf", "vzeroupper", "vzeroall", "endbr64"}


def _writes(op, operands):
    """Register families an AT&T instruction may write; None if it may write
    registers this cannot list (a call, a string instruction, an interrupt)."""
    if (op.startswith(("call", "rep", "int", "loop"))
            or re.fullmatch(r"(?:movs|stos|lods|scas|cmps)[bwlq]?", op) and not operands):
        return None
    if op.startswith(("j", "ret")):
        return set()
    if not operands and op not in _IMPLICIT and op not in _NULLARY:
        return None
    written = set(_IMPLICIT.get(op, ()))
    if op.startswith(("push", "pop", "leave", "enter")):
        written.add("sp")
    if re.fullmatch(r"cmpxchg\w*", op):
        return written | {"a", "d"} | {f for f in map(_family, operands[-1:]) if f}
    if _READ_ONLY.fullmatch(op) and not re.fullmatch(r"bt[src][wlq]?", op):
        return written
    if re.fullmatch(r"i?(?:mul|div)[bwlq]?", op) and len(operands) == 1:
        return written | {"a", "d"}
    targets = operands[-1:]
    if re.fullmatch(r"mulx[lq]?", op):
        targets = operands[-2:]
    elif re.fullmatch(r"(?:xchg|xadd)[bwlq]?", op):
        targets = operands
    return written | {f for f in map(_family, targets) if f}


def _step(op, operands):
    """The family a constant step writes: `inc r`, `dec r`, `add $imm, r`,
    `sub $imm, r`, `lea imm(r), r`. None for anything else."""
    if re.fullmatch(r"(?:inc|dec)[lq]", op) and len(operands) == 1:
        return _family(operands[0])
    if re.fullmatch(r"(?:add|sub)[lq]", op) and len(operands) == 2 and _IMM.fullmatch(operands[0]):
        return _family(operands[1])
    if re.fullmatch(r"lea[lq]", op) and len(operands) == 2:
        m = re.fullmatch(r"-?(?:0x[0-9a-f]+|\d+)\((%\w+)\)", operands[0])
        if m and _family(m[1]) and _family(m[1]) == _family(operands[1]):
            return _family(operands[1])
    return None


class X86Body:
    """One function body's control-flow graph, its natural loops, and the
    findings in it that the x86-64 rules excuse, by index into
    `instructions_of(lines)`."""

    def __init__(self, lines):
        self.rules = {}
        self.ins, labels = [], {}
        for line in lines:
            text = line.strip()
            if text.startswith(".intel_syntax"):
                return
            if text.endswith(":") and not text.startswith(("#", "@", "//")):
                labels[text[:-1]] = len(self.ins)
                continue
            if not text or text.startswith((".", "#", "@", "//")):
                continue
            self.ins.append(_att(line))
        n = len(self.ins)
        self.labels = labels
        if not n:
            return
        # Basic blocks: leaders are the entry, every label, and whatever
        # follows a jump or a return.
        leaders = {0} | {i for i in labels.values() if i < n}
        for i, (op, _) in enumerate(self.ins):
            if (op.startswith("j") or op.startswith("ret") or op == "ud2") and i + 1 < n:
                leaders.add(i + 1)
        starts = sorted(leaders)
        self.block_of = {}
        self.blocks = []
        for b, s in enumerate(starts):
            e = starts[b + 1] if b + 1 < len(starts) else n
            self.blocks.append(range(s, e))
            for i in range(s, e):
                self.block_of[i] = b
        succ = []
        for b, r in enumerate(self.blocks):
            op, operands = self.ins[r[-1]]
            nxt = [self.block_of[r[-1] + 1]] if r[-1] + 1 < n else []
            target = self._target(operands)
            if op in {"jmp", "jmpq"}:
                succ.append([target] if target is not None else [])
            elif _JCC.fullmatch(op) or op in {"jrcxz", "jecxz"}:
                succ.append(([target] if target is not None else []) + nxt)
            elif op.startswith("ret") or op == "ud2":
                succ.append([])
            else:
                succ.append(nxt)
        self.succ = succ
        self.loops = self._natural_loops()
        for i, (op, operands) in enumerate(self.ins):
            rule = self._excuse(i, op, operands)
            if rule:
                self.rules[i] = rule

    def _target(self, operands):
        if len(operands) == 1 and operands[0] in self.labels and self.labels[operands[0]] < len(self.ins):
            return self.block_of[self.labels[operands[0]]]
        return None

    def _natural_loops(self):
        """{header: body}, the union of the natural loops of every back edge
        into that header."""
        reach, stack = {0}, [0]
        while stack:
            for s in self.succ[stack.pop()]:
                if s not in reach:
                    reach.add(s)
                    stack.append(s)
        preds = {b: [p for p in reach if b in self.succ[p]] for b in reach}
        dom = {b: set(reach) for b in reach}
        dom[0] = {0}
        changed = True
        while changed:
            changed = False
            for b in sorted(reach - {0}):
                new = set(reach)
                for p in preds[b]:
                    new &= dom[p]
                new = (new if preds[b] else set()) | {b}
                if new != dom[b]:
                    dom[b], changed = new, True
        loops = {}
        for u in reach:
            for h in self.succ[u]:
                if h in dom[u]:
                    # Everything that reaches u without passing through h.
                    body, stack = {h, u}, ([u] if u != h else [])
                    while stack:
                        for p in preds[stack.pop()]:
                            if p not in body:
                                body.add(p)
                                stack.append(p)
                    loops.setdefault(h, set()).update(body)
        return loops

    def _counter(self, body, family):
        """Whether `family` is a counter of the loop `body`: written there only
        by constant steps, and stepped at least once. None of the loop may be
        a call or otherwise write registers this cannot see."""
        stepped = False
        for b in body:
            for i in self.blocks[b]:
                op, operands = self.ins[i]
                written = _writes(op, operands)
                if written is None:
                    return False
                if family in written:
                    if _step(op, operands) != family:
                        return False
                    stepped = True
        return stepped

    def _invariant(self, body, family):
        for b in body:
            for i in self.blocks[b]:
                written = _writes(*self.ins[i])
                if written is None or family in written:
                    return False
        return True

    def _excuse(self, i, op, operands):
        if op in {"jmp", "jmpq"}:
            return "unconditional jump" if self._target(operands) is not None else None
        if op.startswith("call") and operands and operands[0].lstrip("*").split("@")[0] == "memset":
            return "constant memset" if self._constant_memset(i) else None
        if not (_JCC.fullmatch(op) or op in {"jrcxz", "jecxz"}):
            return None
        b = self.block_of[i]
        target = self._target(operands)
        if target is None or i != self.blocks[b][-1]:
            return None
        # The counters the branch's condition reads, and the registers that
        # must stay fixed in the loop.
        if op in {"jrcxz", "jecxz"}:
            counters, fixed = ["c"], []
        else:
            source = None
            for j in range(i - 1, self.blocks[b][0] - 1, -1):
                prev_op, prev = self.ins[j]
                if not _NO_FLAGS.fullmatch(prev_op):
                    source = (prev_op, prev)
                    break
            if source is None:
                return None
            sop, sargs = source
            regs = [_family(a) for a in sargs]
            if _step(sop, sargs) and not sop.startswith("lea"):
                counters, fixed = [_step(sop, sargs)], []
            elif re.fullmatch(r"(?:cmp|test)[bwlq]", sop) and len(sargs) == 2:
                if _IMM.fullmatch(sargs[0]) and regs[1]:
                    counters, fixed = [regs[1]], []
                elif regs[0] and regs[1] and sop.startswith("test") and regs[0] == regs[1]:
                    counters, fixed = [regs[0]], []
                elif regs[0] and regs[1] and sop.startswith("cmp") and regs[0] != regs[1]:
                    # Either may be the counter; the other must be fixed.
                    counters, fixed = None, regs
                else:
                    return None
            else:
                return None
        for header, body in self.loops.items():
            if b not in body:
                continue
            successors = self.succ[b]
            exits = [s for s in successors if s not in body]
            if not (target == header or exits):
                continue
            if counters is None:
                r1, r2 = fixed
                if ((self._counter(body, r1) and self._invariant(body, r2))
                        or (self._counter(body, r2) and self._invariant(body, r1))):
                    return "counter loop"
            elif all(self._counter(body, c) for c in counters):
                return "counter loop"
        return None

    def _constant_memset(self, i):
        b = self.block_of[i]
        last = {}
        for j in range(self.blocks[b][0], i):
            op, operands = self.ins[j]
            written = _writes(op, operands)
            if written is None:
                return False
            for family in written & {"d", "si", "di"}:
                last[family] = (op, operands)
        length, value, dest = last.get("d"), last.get("si"), last.get("di")
        return bool(
            length and re.fullmatch(r"mov[lq]", length[0]) and _IMM.fullmatch(length[1][0])
            and _family(length[1][1]) == "d"
            and value and re.fullmatch(r"xor[lq]", value[0])
            and _family(value[1][0]) == "si" and _family(value[1][1]) == "si"
            and dest and re.fullmatch(r"leaq", dest[0])
            and re.fullmatch(r"-?\d*\(%rsp\)", dest[1][0]) and _family(dest[1][1]) == "di")


_external_cache = {}


def external_body(target, symbol):
    """The instructions of a runtime-library routine, from the toolchain's
    own compiler_builtins for `target`.

    Fails closed: without llvm-objdump (`rustup component add llvm-tools`) or
    without the symbol, the call is not verified and so is not allowed.
    """
    key = (target, symbol)
    if key in _external_cache:
        return _external_cache[key]
    sysroot = Path(subprocess.run(["rustc", "--print", "sysroot"], check=True,
                                  capture_output=True, text=True).stdout.strip())
    libs = sorted((sysroot / "lib/rustlib" / target / "lib").glob("libcompiler_builtins-*.rlib"))
    tools = sorted((sysroot / "lib/rustlib").glob("*/bin/llvm-objdump*"))
    if not libs or not tools:
        raise ValueError(f"{target}: cannot verify {symbol}: compiler_builtins or llvm-objdump "
                         "not found (rustup component add llvm-tools)")
    out = subprocess.run([str(tools[0]), "-d", "--no-show-raw-insn",
                          f"--disassemble-symbols={symbol}", str(libs[0])],
                         check=True, capture_output=True, text=True).stdout
    body, inside = [], False
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]+ <" + re.escape(symbol) + r">:", line):
            if inside:
                raise ValueError(f"{target}: {symbol} is defined more than once")
            inside = True
            continue
        if inside:
            m = re.match(r"^\s*[0-9a-f]+:\s+(.+)$", line)
            if m:
                body.append("\t" + m[1].strip())
            elif not line.strip():
                inside = False
    if not body:
        raise ValueError(f"{target}: {symbol} not found in {libs[0].name}")
    _external_cache[key] = body
    return body


def inspect(assembly, target, excused=None):
    """Forbidden instructions in the probes, as findings.

    `excused`, a Counter if given, receives a count per rule of the findings
    `excuse` allowed; whether those exceed EXCUSE_CEILINGS is for the caller.
    """
    failures = []
    functions = bodies(assembly, symbols_for(target))
    externals = VERIFIED_EXTERNAL.get(target, ())
    excusable = target in EXCUSE_CEILINGS
    x86 = target.startswith("x86_64")
    if excused is None:
        excused = collections.Counter()

    def walk(probe, name, lines, seen):
        ins = instructions_of(lines)
        pools = pool_jumps(lines) if target.startswith("thumb") else set()
        loops = X86Body(lines).rules if x86 and probe in X86_EXCUSE_CEILINGS else {}
        for i, line in enumerate(ins):
            callee = called(line, target, functions)
            if callee is not None:
                if callee not in seen:
                    seen.add(callee)
                    walk(probe, callee, functions[callee], seen)
                continue
            op, operands = _split(line)
            external = next((s for s in externals if operands == [s]
                             and op in {"bl", "call", "tail"}), None)
            if external is not None:
                if external not in seen:
                    seen.add(external)
                    walk(probe, external, external_body(target, external), seen)
                continue
            if not forbidden(line, target):
                continue
            # x86-64: counted per probe, and only in the probes listed.
            if loops.get(i) in X86_EXCUSE_CEILINGS.get(probe, {}):
                excused[(probe, loops[i])] += 1
                continue
            rule = excuse(target, ins, i) if excusable and probe in P256 else None
            # The Ed25519 scalar probes are straight-line by construction;
            # the one shape excused in them is a jump over a literal pool.
            if probe in ED25519 and i in pools:
                rule = "literal-pool jump"
            # A rule excuses only on a target it was reviewed for.
            if rule is not None and rule in EXCUSE_CEILINGS[target]:
                excused[rule] += 1
                continue
            where = probe if name == probe else f"{probe} -> {name}"
            failures.append(f"{where}: {line.strip()}")

    for name in symbols_for(target):
        if not instructions_of(functions[name]):
            failures.append(f"{name}: empty body")
        walk(name, name, functions[name], {name})
    return failures


def over_ceiling(target, excused):
    """A failure for each rule that excused more than it was reviewed for: per
    rule on the 32-bit targets, per probe and rule on x86-64."""
    if target.startswith("x86_64"):
        failures = []
        for (probe, rule), count in sorted(excused.items()):
            ceiling = X86_EXCUSE_CEILINGS.get(probe, {}).get(rule, 0)
            if count > ceiling:
                failures.append(
                    f"{probe}: {count} findings excused as {rule}, more than the {ceiling} "
                    "reviewed; read them and update X86_EXCUSE_CEILINGS and "
                    "docs/CONSTANT_TIME.md")
        return failures
    ceilings = EXCUSE_CEILINGS.get(target, {})
    return [f"{count} findings excused as {rule}, more than the {ceilings.get(rule, 0)} "
            "reviewed; read them and update EXCUSE_CEILINGS and docs/CONSTANT_TIME.md"
            for rule, count in sorted(excused.items()) if count > ceilings.get(rule, 0)]


def build_probe(target):
    # A fresh explicit output forces Cargo to rebuild the harness and avoids
    # selecting a stale assembly file left by a prior dependency version.
    output_dir = ROOT / "target/ct-audit/probes"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{target}-{uuid.uuid4().hex}.s"
    subprocess.run([
        "cargo", "rustc", "--manifest-path", str(ROOT / "scripts/ct-audit/Cargo.toml"),
        "--release", "--target", target, "--target-dir", str(ROOT / "target/ct-audit"),
        "--", f"--emit=asm={output}",
    ], cwd=ROOT, check=True)
    if not output.is_file():
        raise ValueError(f"{target}: compiler did not produce the requested assembly")
    assembly = output.read_text(encoding="utf-8")
    output.replace(output_dir / f"{target}.s")
    return assembly


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, action="append")
    args = parser.parse_args()
    subprocess.run(["rustc", "--version"], check=True)
    failures = []
    for target in args.target or TARGETS:
        excused = collections.Counter()
        found = inspect(build_probe(target), target, excused) + over_ceiling(target, excused)
        failures.extend(f"{target}: {finding}" for finding in found)
        print(f"{target}: {len(symbols_for(target))} probes, {len(found)} failures"
              + ("; excused by rule: " + ", ".join(
                  f"{' '.join(rule) if isinstance(rule, tuple) else rule} {count}"
                  for rule, count in sorted(excused.items()))
                 if excused else ""), flush=True)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Compiled-code probes passed; this does not cover entire algorithms.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
