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


def bodies(assembly):
    """Read ELF function boundaries; missing/aliased bodies fail closed."""
    result = {}
    current = None
    for line in assembly.splitlines():
        label = re.fullmatch(r"(ct_\w+):", line.strip())
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


def inspect(assembly, target):
    failures = []
    for name, lines in bodies(assembly).items():
        if name not in SYMBOLS:
            continue
        instructions = [line for line in lines if line.strip()
                        and not line.strip().startswith((".", "#", "@", "//"))
                        and not line.strip().endswith(":")]
        if not instructions:
            failures.append(f"{name}: empty body")
        for line in instructions:
            if forbidden(line, target):
                failures.append(f"{name}: {line.strip()}")
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
        failures.extend(f"{target}: {finding}" for finding in found)
        print(f"{target}: {len(SYMBOLS)} probes, {len(found)} forbidden instructions", flush=True)
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
