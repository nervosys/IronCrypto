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
    "ct_compress_11", "ct_select_u32", "ct_select_u64", "ct_hex_encode",
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

# Probes that exist on one target only. On x86-64, P-256's field multiplication
# and squaring have a second instruction sequence, on MULX/ADCX/ADOX, chosen at
# run time where the CPU has BMI2 and ADX; and the point formulas are whole
# blocks of that assembly. The probes above, built without `std`, compile to
# the baseline sequence, so these name the others directly. P-384's two
# rings' multiplications and point formulas are in the same assembly, and
# exist only in that form.
TARGET_SYMBOLS = {
    "x86_64-unknown-linux-gnu": (
        "ct_p256_fp_mul_adx", "ct_p256_fp_square_adx",
        "ct_p256_point_double_adx", "ct_p256_point_add_adx",
        "ct_p256_point_add_affine_adx",
        "ct_p384_fp_mul_adx", "ct_p384_fn_mul_adx",
        "ct_p384_point_double_adx", "ct_p384_point_add_adx",
        "ct_p384_point_add_affine_adx",
    ),
}


def symbols_for(target):
    """Every probe `target` must have: the common ones and its own."""
    return SYMBOLS + TARGET_SYMBOLS.get(target, ())

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
    "thumbv6m-none-eabi": {"counter loop": 32, "unconditional jump": 40},
    "thumbv7em-none-eabihf": {"counter loop": 32},
    "riscv32imac-unknown-none-elf": {"stack-bound loop": 16, "constant memset": 16},
}

# Loads and stores, which do not set the flags a conditional branch reads, and
# so may sit between the comparison and the branch.
_MEMORY = re.compile(r"(?:ldr|str|ldm|stm)[a-z]*(?:\.w)?")
_THUMB_COND = re.compile(
    r"b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.w)?")
_LOCAL_LABEL = re.compile(r"\.L[\w.$]+")


def bodies(assembly, symbols=SYMBOLS):
    """Read ELF function boundaries; missing/aliased bodies fail closed.

    Probes, and every symbol the file declares a function with `.type`, so
    that a call from a probe can be followed into a body in the same file.
    """
    functions = set(symbols) | set(re.findall(
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
    missing = set(symbols) - result.keys()
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
    if excused is None:
        excused = collections.Counter()

    def walk(probe, name, lines, seen):
        ins = instructions_of(lines)
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
            rule = excuse(target, ins, i) if excusable and probe in P256 else None
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
    """A failure for each rule that excused more than it was reviewed for."""
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
                  f"{rule} {count}" for rule, count in sorted(excused.items()))
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
