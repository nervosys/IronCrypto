#!/usr/bin/env python3
"""Reject control flow and division in narrowly scoped, fixed-parameter probes.

This is a compiler regression gate, not a proof of constant time. It examines
LTO output from the real library, rejects unresolved calls, and requires every
expected symbol. See docs/CONSTANT_TIME.md for coverage and limitations.
"""

import argparse
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
# Probes that gate only on some targets. On the rest they are built and their
# findings printed, not failed: on 32-bit targets P-256's limb loops stay
# rolled, and a text check cannot tell a loop counter from a secret. The
# review that classified those findings is in docs/CONSTANT_TIME.md.
GATED_ONLY_ON = {name: ("x86_64-unknown-linux-gnu",) for name in P256}


def gated(finding, target):
    probe = finding.split(":", 1)[0].split(" -> ", 1)[0]
    return target in GATED_ONLY_ON.get(probe, TARGETS)


def bodies(assembly):
    """Read ELF function boundaries; missing/aliased bodies fail closed.

    Probes, and every symbol the file declares a function with `.type`, so
    that a call from a probe can be followed into a body in the same file.
    """
    functions = set(SYMBOLS) | set(re.findall(
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
    missing = set(SYMBOLS) - result.keys()
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


def inspect(assembly, target):
    failures = []
    functions = bodies(assembly)

    def walk(probe, name, seen):
        for line in instructions_of(functions[name]):
            callee = called(line, target, functions)
            if callee is not None:
                if callee not in seen:
                    seen.add(callee)
                    walk(probe, callee, seen)
            elif forbidden(line, target):
                where = probe if name == probe else f"{probe} -> {name}"
                failures.append(f"{where}: {line.strip()}")

    for name in SYMBOLS:
        if not instructions_of(functions[name]):
            failures.append(f"{name}: empty body")
        walk(name, name, {name})
    return failures


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
        found = inspect(build_probe(target), target)
        gating = [finding for finding in found if gated(finding, target)]
        reported = [finding for finding in found if not gated(finding, target)]
        failures.extend(f"{target}: {finding}" for finding in gating)
        print(f"{target}: {len(SYMBOLS)} probes, {len(gating)} forbidden instructions"
              + (f"; {len(reported)} more in probes not gated on this target"
                 if reported else ""), flush=True)
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
