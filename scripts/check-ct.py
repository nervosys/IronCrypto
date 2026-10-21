#!/usr/bin/env python3
"""Reject control flow and division in narrowly scoped, fixed-parameter probes.

This is a compiler regression gate, not a proof of constant time. It examines
LTO output from the real library, rejects unresolved calls, and requires every
expected symbol. See docs/CONSTANT_TIME.md for coverage and limitations.
"""

import argparse
import collections
import os
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
    "aarch64-unknown-linux-gnu",
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
    "ct_x25519_fe64_double", "ct_ed25519_fe64_select",
    "ct_ed25519_fe64_madd_ext2", "ct_ed25519_fe64_dbl_nadd",
    # Signing's radix-32 path on AVX2: the sixteen-entry table read, the step
    # with the next read inside its additions, and the digits themselves.
    "ct_ed25519_fe64_scan", "ct_ed25519_fe64_madd_ext2_scan", "ct_ed25519_digits32",
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
    # The doublings in place that the multiplications without IFMA run five
    # to a digit, and one digit's addition in each: the entry's read, the
    # formula, and the masks that select its identity cases. P-384's reads
    # an affine window, P-256's a Jacobian one; P-256's generator table, as
    # signing reads it, has its own.
    "ct_p256_point_double_in_place_adx", "ct_p384_point_double_in_place_adx",
    "ct_p384_ladder_add", "ct_p256_ladder_add", "ct_p256_table_add",
    # RSA's windowed-exponentiation table read at 2048 bits. Its masked scan is
    # unrolled on x86-64. On the 32-bit targets and RISC-V LLVM keeps the entry
    # loop rolled, a loop over a public count, so the probe is x86-64 only.
    "ct_rsa_select_2048",
    # The same read from the 32 entries of the five-bit window that RSA's
    # primes are exponentiated with: the SSE2 scan, which a build without
    # `std` takes, and the AVX2 read, entry by entry into four, six or eight
    # accumulators, at each prime width (1024, 1536, 2048 bits).
    "ct_rsa_select32_2048", "ct_rsa_select32_avx2_1024", "ct_rsa_select32_avx2_1536",
    "ct_rsa_select32_avx2_2048",
    # ChaCha20's sixteen-block AVX-512 keystream group, and Poly1305's
    # four-lane AVX2 step and final lane folding, under the key's r and s.
    "ct_chacha20_zmm_group", "ct_poly1305_avx2_step", "ct_poly1305_avx2_finish",
    # Keccak-f[1600] over eight states, one block of assembly on thirty-one
    # zmm registers; its loop over the twelve round pairs is a counter loop.
    "ct_keccak_x8_permute",
    # Keccak-f[1600] over four states on AVX2, one state per 64-bit lane: the
    # four-lane permutation ML-KEM's and SHAKE's batched squeezes take where
    # AVX-512 is absent.
    "ct_keccak_x4_permute",
    # Short messages: ChaCha20's two-block AVX2 kernel, two blocks side by
    # side in each register and its rounds written out, once and as two
    # pairs; ChaCha20's eight-block AVX2 kernel over a 512-byte group; the
    # AEAD's tag in radix 2^64 over thirteen bytes of associated data and
    # sixty-four of ciphertext; and HMAC-SHA256's SHA-NI key-pad compressions
    # and its last inner and outer compressions.
    "ct_chacha20_avx2_pair", "ct_chacha20_avx2_two_pairs",
    "ct_chacha20_avx2_eight_blocks", "ct_poly1305_short",
    "ct_hmac_sha256_pads", "ct_hmac_sha256_tail",
    # RSA's Montgomery products at 2048 bits: the MULX/ADCX/ADOX product, the
    # AVX-512 IFMA almost-Montgomery product, and the portable CIOS product.
    # Each loops over the public width, and their loop branches are excused by
    # the x86-64 rules below, up to X86_EXCUSE_CEILINGS. On the 32-bit targets
    # the CIOS product clears its accumulator with a runtime-library call and
    # its loop tests do not fit the 32-bit counter shapes, so it is not
    # required there.
    "ct_rsa_adx_mont_mul_2048", "ct_rsa_ifma_amm_2048", "ct_rsa_cios_2048",
    # The MULX/ADCX/ADOX square at 2048 bits, and the straight-line product
    # and square at 1024 bits that RSA-2048 signing runs on. At 2048 bits,
    # RSA-4096's primes, both are one level of Karatsuba over the 1024-bit
    # kernels; the eight-word blocks they replaced there are read at 1536
    # bits, RSA-3072's primes.
    "ct_rsa_adx_mont_sqr_2048", "ct_rsa_adx_mont_mul_1024", "ct_rsa_adx_mont_sqr_1024",
    "ct_rsa_adx_mont_mul_1536", "ct_rsa_adx_mont_sqr_1536",
    # Four of the 2048-bit pieces on their own, so IronProof can state each on
    # its arguments: the absolute difference, the Karatsuba middle terms, and
    # the final conditional subtraction.
    "ct_rsa_abs_diff_16", "ct_rsa_kara_mid", "ct_rsa_kara_mid_sub", "ct_rsa_finish_2048",
    # The two schoolbook kernels at 16 words, the products that Karatsuba's
    # three sub-products are: straight-line MULX/ADCX/ADOX, with no loop.
    "ct_rsa_mul_16", "ct_rsa_sqr_16",
    # RSA's whole exponentiation on AVX-512 IFMA, compiled once per width:
    # at 1024 bits, each of RSA-2048's two CRT exponentiations, and at 2048
    # bits, its modulus. Its loops are excused the same way.
    "ct_rsa_ifma_pow_1024", "ct_rsa_ifma_pow_2048",
    # The secret digit's read of a prepared P-384 key's window, in ECDH. Its
    # loop over the sixteen entries is excused by the x86-64 rules below, up
    # to X86_EXCUSE_CEILINGS. The additions after it are the point formulas
    # above; the multiplication as a whole is not a probe (CONSTANT_TIME.md).
    "ct_p384_comb_select",
    # AES-GCM's eight-block (AES-NI, PCLMULQDQ), sixteen-block (VAES-256) and
    # 512-bit (AVX-512) loops at AES-256 over a fixed count of groups, sealing
    # and opening, one group alone, and the twist of a power of H. The 512-bit
    # loops are the sixteen-block kernel on zmm registers, and the same over
    # thirty-two blocks. The loops' back edges are excused by the x86-64
    # counter-loop rule below.
    "ct_gcm_clmul8_seal", "ct_gcm_clmul8_open", "ct_gcm_clmul8_group",
    "ct_gcm_vaes256_seal", "ct_gcm_vaes256_open", "ct_gcm_vaes256_group",
    "ct_gcm_vaes512_seal", "ct_gcm_vaes512_open",
    "ct_gcm_vaes512x32_seal", "ct_gcm_vaes512x32_open",
    "ct_gcm_twist",
    # P-256's and P-384's point formulas on AVX-512 IFMA (nist::ifma_kernels,
    # generated), each kernel one block of straight-line assembly; the secret
    # digit's read of a window of lane vectors, every entry under a mask; and
    # the conversion of a secret-derived result back to the Fp form.
    "ct_p256_ifma_double", "ct_p256_ifma_add", "ct_p256_ifma_madd", "ct_p256_ifma_madd4",
    "ct_p256_ifma_from_fp", "ct_p256_ifma_to_fp", "ct_p256_ifma_to_fp4",
    "ct_p256_ifma_select", "ct_p256_ifma_from_limbs",
    "ct_p384_ifma_double", "ct_p384_ifma_add", "ct_p384_ifma_madd", "ct_p384_ifma_madd4",
    "ct_p384_ifma_from_fp", "ct_p384_ifma_to_fp", "ct_p384_ifma_to_fp4",
    "ct_p384_ifma_select", "ct_p384_ifma_from_limbs",
)
SYMBOLS += X86_ONLY
# The ARMv8 backends behind ic-cipher's and ic-hash's `aarch64-crypto`
# feature: AES at AES-256 (each probe loads the key first, so the decryption
# probe reads the AESIMC derivation of the inverse cipher's keys), one block
# each way and a batch of four; the PMULL GHASH multiply and its eight-block
# absorb over three groups; SHA-256 compression over four blocks and SHA-512
# over two. They compile for aarch64 only, so they are required there and
# nowhere else. aarch64 also runs every probe that is not x86-64-only.
AARCH64_ONLY = (
    "ct_aes256_armv8_encrypt", "ct_aes256_armv8_decrypt", "ct_aes256_armv8_encrypt4",
    "ct_ghash_pmull_mul", "ct_ghash_pmull_absorb8",
    "ct_sha256_armv8_compress", "ct_sha512_armv8_compress",
)
SYMBOLS += AARCH64_ONLY


def symbols_for(target):
    """The probes `target` must have."""
    if target.startswith("x86_64"):
        return tuple(s for s in SYMBOLS if s not in AARCH64_ONLY)
    if target.startswith("aarch64"):
        return tuple(s for s in SYMBOLS if s not in X86_ONLY)
    return tuple(s for s in SYMBOLS if s not in X86_ONLY and s not in AARCH64_ONLY)

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
    # MULX/ADX at 2048 bits: the three 1024-bit products or squares of
    # Karatsuba, the absolute differences and the recombination are
    # straight-line; what loops is the reduction, each of its four blocks
    # over its groups of eight steps (`test`/`je` on the group count in rbp,
    # `dec`, a `jmp` back), and the final subtraction's two loops (`jrcxz`
    # on rcx, stepped by `lea`).
    "ct_rsa_adx_mont_mul_2048": {"counter loop": 6, "unconditional jump": 6},
    "ct_rsa_adx_mont_sqr_2048": {"counter loop": 6, "unconditional jump": 6},
    # The final subtraction on its own: the same two loops (`jrcxz` on rcx,
    # stepped by `lea`, and a `jmp` back), counted by the public width.
    "ct_rsa_finish_2048": {"counter loop": 2, "unconditional jump": 2},
    # MULX/ADX at 1536 bits, on the eight-word blocks: three product blocks
    # and three reduction blocks, each looping over its groups as above, and
    # the final subtraction's two loops.
    "ct_rsa_adx_mont_mul_1536": {"counter loop": 8, "unconditional jump": 8},
    # The same for the square: three blocks of cross products, the
    # diagonal's `jrcxz` loop, three reduction blocks, and the final
    # subtraction.
    "ct_rsa_adx_mont_sqr_1536": {"counter loop": 9, "unconditional jump": 9},
    # MULX/ADX at 1024 bits: the kernels are straight-line, and the two loops
    # are the final subtraction's.
    "ct_rsa_adx_mont_mul_1024": {"counter loop": 2, "unconditional jump": 2},
    "ct_rsa_adx_mont_sqr_1024": {"counter loop": 2, "unconditional jump": 2},
    # The table read's SSE2 scan: one `jrcxz` loop over pairs of words, at
    # sixteen entries and at 32.
    "ct_rsa_select_2048": {"counter loop": 1, "unconditional jump": 1},
    "ct_rsa_select32_2048": {"counter loop": 1, "unconditional jump": 1},
    # The AVX2 read: one `jrcxz` loop over the 32 entries, rcx counting up
    # from -32 by `lea`, rdi stepping one entry and rsi one mask.
    "ct_rsa_select32_avx2_1024": {"counter loop": 1, "unconditional jump": 1},
    "ct_rsa_select32_avx2_1536": {"counter loop": 1, "unconditional jump": 1},
    "ct_rsa_select32_avx2_2048": {"counter loop": 1, "unconditional jump": 1},
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
    # The 512-bit AES-GCM loops at AES-256 (round count 14, see the round-count
    # dispatch rule above): each `cmpq $10`/`cmpq $12` dispatch on the round
    # count, and the loop's back edge, the counter loop. Counted from the
    # emitted assembly: the sealing body of zmm32_groups has two sites, each
    # dispatching on 10 and on 12; the other bodies have one site.
    "ct_gcm_vaes512_seal": {"round-count dispatch": 2, "counter loop": 1},
    "ct_gcm_vaes512_open": {"round-count dispatch": 2, "counter loop": 1},
    "ct_gcm_vaes512x32_seal": {"round-count dispatch": 4, "counter loop": 1,
                               "loop-count guard": 1},
    "ct_gcm_vaes512x32_open": {"round-count dispatch": 2, "counter loop": 1},
    # A prepared P-384 key's window read: the loop over its sixteen entries,
    # `incq`/`cmpq $16`/`jne` on the entry counter.
    "ct_p384_comb_select": {"counter loop": 1},
    # One digit's addition in the multiplications on MULX/ADX: each reads
    # its window in one loop, rax counting the entries to a constant and
    # indexing the masks, the entry pointer stepping by a constant -- P-384's
    # affine window (`incq`/`cmpq $16`/`jne`, 96 bytes an entry, in
    # `AffineWindow::select` out of line), P-256's Jacobian one (the same, 96
    # bytes) and the generator table's (`addq $8`/`cmpq $256`/`jne`, 32
    # entries of 64 bytes). The digit decides only the masks. Read on
    # 2026-10-14.
    "ct_p384_ladder_add": {"counter loop": 1},
    "ct_p256_ladder_add": {"counter loop": 1},
    "ct_p256_table_add": {"counter loop": 1},
    # AES-GCM: each loop's `decq; jne` back edge, the counter the fixed group
    # count (2 sealing, the first group being encrypted before the loop; 3
    # opening), written nowhere else in the loop.
    "ct_gcm_clmul8_seal": {"counter loop": 1},
    "ct_gcm_clmul8_open": {"counter loop": 1},
    # Keccak-f[1600] on eight states: the `dec`/`jnz` back edge over the twelve
    # passes of two rounds, the counter written nowhere else in the loop.
    "ct_keccak_x8_permute": {"counter loop": 1},
    # ChaCha20's eight-block AVX2 kernel: the double-round loop, `movl $10,
    # %eax`/`decl %eax`/`jne`, ten double rounds over a fixed count, the
    # counter written nowhere else in the loop.
    "ct_chacha20_avx2_eight_blocks": {"counter loop": 1},
    # Keccak-f[1600] on four states, AVX2: the `addq $16`/`cmpq $192`/`jne`
    # back edge over the twelve passes of two rounds, `%rax` written nowhere
    # else in the loop.
    "ct_keccak_x4_permute": {"counter loop": 1},
    "ct_gcm_vaes256_seal": {"counter loop": 1},
    "ct_gcm_vaes256_open": {"counter loop": 1},
    # The IFMA multiplication's window read (`nist::ifma::scan_avx2`): the
    # loop over the sixteen entries, `incq %rax`/`cmpq $16, %rax`/`jne`, rax
    # indexing the masks and rdi stepping one entry (160 or 256 bytes). The
    # digit decides only the masks.
    "ct_p256_ifma_select": {"counter loop": 1},
    "ct_p384_ifma_select": {"counter loop": 1},
}

# On aarch64 one rule (A64Body, below) excuses loops over a public count, and
# only in the probes named here, each up to the number of findings it excused
# when they were read one by one (docs/CONSTANT_TIME.md, "The ARMv8
# backends"). A probe not named excuses nothing; one finding more than its
# ceiling fails. Counted per probe, following calls.
# Read on 2026-10-14, rustc 1.99.0.
AARCH64_EXCUSE_CEILINGS = {
    # The loop over the three groups of eight blocks: `subs x11, x11, #128;
    # b.ne` on the remaining length, x11 set to 384 before it.
    "ct_ghash_pmull_absorb8": {"counter loop": 1},
    # The loop over the four blocks: `add x8, x8, #64; cmp x8, #256; b.ne`,
    # x8 the block offset from zero; the sixteen round groups are unrolled.
    "ct_sha256_armv8_compress": {"counter loop": 1},
    # The block loop, `subs x8, x8, #128; b.ne` on the remaining length from
    # 256, and inside it the loop over four of the five round groups,
    # `subs x11, x11, #1; b.ne`, x11 set to 4 at the top of each block.
    "ct_sha512_armv8_compress": {"counter loop": 2},
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
    if target.startswith("aarch64"):
        # Everything that transfers control but `ret`: conditional branches
        # (b.<cond>, cbz/cbnz, tbz/tbnz), direct and indirect jumps and calls,
        # and their pointer-authenticated forms. And division.
        if op == "ret" and not operands:
            return False
        return (mnemonic in {"b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz",
                             "sdiv", "udiv", "svc", "hvc", "smc", "eret"}
                or re.fullmatch(r"b\.\w+|bc\.\w+|br\w+|blr\w+|ret\w+", mnemonic) is not None)
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
    op = mnemonic if target.startswith("aarch64") else mnemonic.split(".")[0]
    operand = fields[1].strip().removesuffix("@PLT")
    calls = {
        "x86_64": {"call", "callq", "jmp", "jmpq"},
        "thumb": {"bl", "b"},
        "riscv32": {"call", "tail"},
        "aarch64": {"bl", "b"},
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
# The rules below excuse five shapes in x86-64 code, and only in the probes
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
#
# "round-count dispatch": a `je` or `jne` immediately after `cmp $10, reg` or
# `cmp $12, reg`, in the same basic block. The 512-bit AES-GCM kernels take
# the round count at run time, and test it inside their AES rounds, for AES-192
# (12 rounds) and AES-128 (10). The round count is the key length's, which is
# public, and the four probes that run those kernels fix it at 14 (AES-256), so
# the dispatch never takes the 10- or 12-round branches, and the gate does not
# read those paths. Only the four probes listed under this rule in
# X86_EXCUSE_CEILINGS get it; any other compare-and-branch is not excused.
#
# "loop-count guard": a `je` or `jne` in a block outside a loop, immediately
# after `dec r` or `sub $1, r`, where `r` is a counter of that loop (every write
# in the loop is a constant step, and the back edge's condition is `dec r` or
# `sub $1, r` too), and whose target begins after the back edge, so that a
# count of one (zero after the decrement) skips the loop. The count is the message length's in whole groups,
# which is public. The skip is taken only when the count is one, and the probe
# fixes it at two groups, so the gate never reads that path. Only the probes
# listed under this rule in X86_EXCUSE_CEILINGS get it. It is not taken for a branch into the loop, nor
# for a branch within a loop (its block and target share one), nor for one
# whose register is not the loop's counter.

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
        if op in {"je", "jne"} and self._round_dispatch(i):
            return "round-count dispatch"
        if op in {"je", "jne"} and self._loop_guard(i):
            return "loop-count guard"
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

    def _round_dispatch(self, i):
        """Whether the instruction before `i` is `cmp $10` or `cmp $12` on a
        register, in the same basic block: see the round-count dispatch rule."""
        if i < 1 or self.block_of[i - 1] != self.block_of[i]:
            return False
        op, operands = self.ins[i - 1]
        return bool(re.fullmatch(r"cmp[bwlq]?", op) and len(operands) == 2
                    and operands[0] in {"$10", "$12"} and _family(operands[1]) is not None)

    def _loop_guard(self, i):
        """Whether the `je`/`jne` at `i` is a loop-count guard: see the rule
        of that name."""
        b = self.block_of[i]
        if i < 1 or self.block_of[i - 1] != b or i != self.blocks[b][-1]:
            return False
        op, operands = self.ins[i - 1]
        if re.fullmatch(r"dec[lq]", op) and len(operands) == 1:
            reg = _family(operands[0])
        elif re.fullmatch(r"sub[lq]", op) and len(operands) == 2 and operands[0] == "$1":
            reg = _family(operands[1])
        else:
            return False
        target = self._target(self.ins[i][1])
        if reg is None or target is None:
            return False
        if any(b in body and target in body for body in self.loops.values()):
            return False  # a branch within a loop, which is not a guard
        past = self.blocks[target][0]
        for header, body in self.loops.items():
            if b in body or not self._counter(body, reg):
                continue
            for u in body:
                last = self.blocks[u][-1]
                jop, joperands = self.ins[last]
                if not (_JCC.fullmatch(jop) and self._target(joperands) == header):
                    continue
                if past > last and self._back_edge_counter(u) == reg:
                    return True
        return False

    def _back_edge_counter(self, b):
        """The register that the condition of block `b`'s last branch reads as
        a constant step, from the instruction before it in the same block."""
        last = self.blocks[b][-1]
        for j in range(last - 1, self.blocks[b][0] - 1, -1):
            if not _NO_FLAGS.fullmatch(self.ins[j][0]):
                return _step(*self.ins[j])
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


# --- AArch64: loops over a public count -------------------------------------
#
# One rule, "counter loop", excuses a conditional branch in AArch64 code, and
# only in the probes AARCH64_EXCUSE_CEILINGS names, each up to its own count.
# It reads the GNU syntax rustc emits. It is the x86-64 rule's shape, no wider:
#
# The branch is the last instruction of its basic block, targets a label in
# the same function, and is a back edge or an exit of a natural loop (found
# from the control-flow graph by dominators). Its condition is a counter's:
#
# - `cbz`/`cbnz` on a register, or
# - `b.<cond>` whose flags come, within its own basic block, from
#   `subs`/`adds Xn, Xn, #imm`, `cmp`/`cmn Xn, #imm`, or `cmp Xn, Xm` of two
#   distinct registers. Every instruction between that one and the branch
#   must be one this checker knows does not set the flags.
#
# The register is a counter of that loop: every instruction in the loop that
# writes it is `add`, `sub`, `adds` or `subs` of an immediate to itself, and at
# least one is. For `cmp Xn, Xm` the other register must not be written
# anywhere in the loop. Every instruction in the loop must be one whose
# register writes this checker can list (A64_KNOWN); anything else -- a call,
# an indirect branch, an instruction not in the list -- voids the excuse for
# that loop. `tbz`/`tbnz` (a branch on one bit), `ccmp`/`ccmn` chains, `tst`,
# `ands`, flags from carries (`adcs`, `sbcs`), flags from loads or from data
# arithmetic, and `cmp` against memory are never excused.

# Instructions that set NZCV, and write their first operand (if a general
# register) as well.
_A64_FLAGS_ONLY = {"cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp", "fccmpe"}
_A64_FLAGS_AND_DEST = {"adds", "adcs", "subs", "sbcs", "ands", "bics", "negs", "ngcs"}
# Instructions that set no flags and write at most their first operand. The
# vector ones write no general-purpose register unless that operand is one
# (`fmov x0, d0`, `umov w0, v0.s[1]`).
_A64_DEST = {
    "add", "sub", "adc", "sbc", "and", "orr", "eor", "bic", "orn", "eon", "mov", "movz",
    "movn", "movk", "mvn", "neg", "ngc", "lsl", "lsr", "asr", "ror", "mul", "madd",
    "msub", "mneg", "smull", "umull", "smulh", "umulh", "smaddl", "umaddl", "smsubl",
    "umsubl", "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg",
    "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil", "ubfm", "sbfm", "bfm", "extr",
    "rev", "rev16", "rev32", "rev64", "rbit", "clz", "cls", "sxtb", "sxth", "sxtw",
    "uxtb", "uxth", "adr", "adrp",
    # SIMD and FP.
    "fmov", "umov", "smov", "ins", "dup", "movi", "mvni", "ext", "not", "bsl", "bit",
    "bif", "pmull", "pmull2", "aese", "aesd", "aesmc", "aesimc", "sha256h", "sha256h2",
    "sha256su0", "sha256su1", "sha512h", "sha512h2", "sha512su0", "sha512su1", "eor3",
    "bcax", "rax1", "xar", "zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2", "shl", "ushr",
    "sshr", "ushll", "ushll2", "sshll", "sshll2", "xtn", "xtn2", "addp", "cmeq", "cmhi",
    "cmhs", "cmgt", "cmge", "uaddw", "uaddw2", "umlal", "umlal2", "umull2", "shrn",
    "shrn2", "sli", "sri", "usra", "ssra",
}
_A64_LOADS = {
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh",
    "ldursb", "ldursh", "ldursw", "ldp", "ldpsw", "ldnp", "ld1", "ld2", "ld3", "ld4",
    "ld1r", "ldar", "ldarb", "ldarh",
}
_A64_STORES = {
    "str", "strb", "strh", "stur", "sturb", "sturh", "stp", "stnp", "st1", "st2", "st3",
    "st4", "stlr", "stlrb", "stlrh",
}
_A64_NOTHING = {"nop", "hint", "prfm", "prfum", "ret", "b"}
_A64_CONDITIONAL = re.compile(r"b\.(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|nv)")
A64_KNOWN = (_A64_FLAGS_ONLY | _A64_FLAGS_AND_DEST | _A64_DEST | _A64_LOADS | _A64_STORES
             | _A64_NOTHING | {"cbz", "cbnz", "tbz", "tbnz"})
_A64_IMM = re.compile(r"#-?(?:0x[0-9a-f]+|\d+)")


def _a64_family(operand):
    """The general-purpose register an operand names, as `x0`..`x30` or `sp`,
    or None for anything else: the zero register, an immediate, memory, a
    vector register."""
    o = operand.strip().lower()
    m = re.fullmatch(r"[xw]([0-9]|[12][0-9]|30)", o)
    if m:
        return f"x{m[1]}"
    return {"sp": "sp", "wsp": "sp", "fp": "x29", "lr": "x30"}.get(o)


def _a64_operands(text):
    """Operands of an AArch64 instruction, split at commas outside `[]` and
    `{}`."""
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def _a64(line):
    """(mnemonic, operands) of an AArch64 line, comments removed."""
    line = re.split(r"\s*//", line, maxsplit=1)[0].strip()
    fields = line.split(None, 1)
    op = fields[0].lower() if fields else ""
    return op, (_a64_operands(fields[1]) if len(fields) == 2 else [])


def _a64_writeback(operands):
    """The base register a pre- or post-indexed access writes back, or None."""
    for k, o in enumerate(operands):
        if o.startswith("["):
            base = _a64_family(o[1:].split(",")[0].rstrip("]!"))
            if o.endswith("!") or k + 1 < len(operands):
                return base
            return None
    return None


def _a64_writes(op, operands):
    """General-purpose registers an AArch64 instruction may write, as
    families; None for an instruction not in A64_KNOWN (a call, an indirect
    branch, anything this does not list), which voids any loop it is in."""
    if op in _A64_NOTHING or op in _A64_FLAGS_ONLY or _A64_CONDITIONAL.fullmatch(op) \
            or op in {"cbz", "cbnz", "tbz", "tbnz"}:
        return set()
    if op in _A64_DEST or op in _A64_FLAGS_AND_DEST:
        f = _a64_family(operands[0]) if operands else None
        return {f} if f else set()
    if op in _A64_LOADS or op in _A64_STORES:
        written = set()
        if op in _A64_LOADS and operands and not operands[0].startswith("{"):
            dests = operands[:2] if op in {"ldp", "ldpsw", "ldnp"} else operands[:1]
            written |= {f for f in map(_a64_family, dests) if f}
        base = _a64_writeback(operands)
        if base:
            written.add(base)
        return written
    return None


def _a64_step(op, operands):
    """The family a constant step writes: `add`, `sub`, `adds` or `subs` of an
    immediate to a register, into itself. None for anything else."""
    if (op in {"add", "sub", "adds", "subs"} and len(operands) == 3
            and _A64_IMM.fullmatch(operands[2])):
        f = _a64_family(operands[0])
        if f and f != "sp" and f == _a64_family(operands[1]):
            return f
    return None


class A64Body(X86Body):
    """One AArch64 function body's control-flow graph, its natural loops, and
    the findings in it the AArch64 rule excuses, by index into
    `instructions_of(lines)`."""

    def __init__(self, lines):
        self.rules = {}
        self.ins, labels = [], {}
        for line in lines:
            text = line.strip()
            if text.endswith(":") and not text.startswith(("#", "@", "//")):
                labels[text[:-1]] = len(self.ins)
                continue
            if not text or text.startswith((".", "#", "@", "//")):
                continue
            self.ins.append(_a64(line))
        n = len(self.ins)
        self.labels = labels
        if not n:
            return
        leaders = {0} | {i for i in labels.values() if i < n}
        for i, (op, _) in enumerate(self.ins):
            if self._transfers(op) and i + 1 < n:
                leaders.add(i + 1)
        starts = sorted(leaders)
        self.block_of = {}
        self.blocks = []
        for b, st in enumerate(starts):
            e = starts[b + 1] if b + 1 < len(starts) else n
            self.blocks.append(range(st, e))
            for i in range(st, e):
                self.block_of[i] = b
        succ = []
        for b, r in enumerate(self.blocks):
            op, operands = self.ins[r[-1]]
            nxt = [self.block_of[r[-1] + 1]] if r[-1] + 1 < n else []
            target = self._target(operands[-1:])
            if op == "b":
                succ.append([target] if target is not None else [])
            elif self._conditional(op):
                succ.append(([target] if target is not None else []) + nxt)
            elif self._transfers(op):
                succ.append([])
            else:
                succ.append(nxt)
        self.succ = succ
        self.loops = self._natural_loops()
        for i, (op, operands) in enumerate(self.ins):
            if self._conditional(op) and self._excused(i, op, operands):
                self.rules[i] = "counter loop"

    @staticmethod
    def _conditional(op):
        return bool(_A64_CONDITIONAL.fullmatch(op)) or op in {"cbz", "cbnz", "tbz", "tbnz"}

    def _transfers(self, op):
        return (self._conditional(op) or op in {"b", "br", "ret", "eret"}
                or op.startswith(("br", "ret", "b.")))

    def _counter(self, body, family):
        stepped = False
        for b in body:
            for i in self.blocks[b]:
                op, operands = self.ins[i]
                written = _a64_writes(op, operands)
                if written is None:
                    return False
                if family in written:
                    if _a64_step(op, operands) != family:
                        return False
                    stepped = True
        return stepped

    def _invariant(self, body, family):
        for b in body:
            for i in self.blocks[b]:
                written = _a64_writes(*self.ins[i])
                if written is None or family in written:
                    return False
        return True

    def _excused(self, i, op, operands):
        b = self.block_of[i]
        target = self._target(operands[-1:])
        if target is None or i != self.blocks[b][-1]:
            return False
        if op in {"cbz", "cbnz"}:
            if len(operands) != 2 or not _a64_family(operands[0]):
                return False
            counters, fixed = [_a64_family(operands[0])], None
        elif _A64_CONDITIONAL.fullmatch(op) and len(operands) == 1:
            source = None
            for j in range(i - 1, self.blocks[b][0] - 1, -1):
                prev_op, prev = self.ins[j]
                if prev_op in _A64_FLAGS_ONLY or prev_op in _A64_FLAGS_AND_DEST:
                    source = (prev_op, prev)
                    break
                if _a64_writes(prev_op, prev) is None:
                    return False
            if source is None:
                return False
            sop, sargs = source
            if sop in {"subs", "adds"}:
                step = _a64_step(sop, sargs)
                if not step:
                    return False
                counters, fixed = [step], None
            elif sop in {"cmp", "cmn"} and len(sargs) == 2:
                r0, r1 = _a64_family(sargs[0]), _a64_family(sargs[1])
                if r0 and r0 != "sp" and _A64_IMM.fullmatch(sargs[1]):
                    counters, fixed = [r0], None
                elif sop == "cmp" and r0 and r1 and r0 != r1 and "sp" not in (r0, r1):
                    counters, fixed = None, (r0, r1)
                else:
                    return False
            else:
                return False
        else:
            return False
        for header, body in self.loops.items():
            if b not in body:
                continue
            exits = [s for s in self.succ[b] if s not in body]
            if not (target == header or exits):
                continue
            if counters is None:
                r0, r1 = fixed
                if ((self._counter(body, r0) and self._invariant(body, r1))
                        or (self._counter(body, r1) and self._invariant(body, r0))):
                    return True
            elif all(self._counter(body, c) for c in counters):
                return True
        return False


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
    a64 = target.startswith("aarch64")
    if excused is None:
        excused = collections.Counter()

    def walk(probe, name, lines, seen):
        ins = instructions_of(lines)
        pools = pool_jumps(lines) if target.startswith("thumb") else set()
        loops = (X86Body(lines).rules if x86 and probe in X86_EXCUSE_CEILINGS
                 else A64Body(lines).rules if a64 and probe in AARCH64_EXCUSE_CEILINGS
                 else {})
        ceilings = (X86_EXCUSE_CEILINGS if x86 else AARCH64_EXCUSE_CEILINGS).get(probe, {})
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
            # x86-64 and aarch64: counted per probe, and only in the probes
            # listed.
            if loops.get(i) in ceilings:
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


# Probes whose kernels must leave no working value in a vector register: the
# last inline-assembly block a probe runs that names a vector register (its
# own, or a callee's, followed as `inspect` follows calls) must end by zeroing
# every vector register that any block in the probe names -- `vzeroall` for
# xmm0-15 and their ymm/zmm extensions, or a zeroing idiom (`pxor x, x` and
# its VEX/EVEX forms) per register. Hardening, not constant time: a register
# left holding a round key or a selected entry is not a timing leak. The
# vector registers the compiler's own code writes before that block (building
# a mask, say) count as named, since the block must wipe them too; what it
# does after the block (copying a result out) is outside the check.
# docs/CONSTANT_TIME.md, "Registers and stack after a kernel".
X86_WIPED = (
    "ct_gcm_clmul8_seal", "ct_gcm_clmul8_open", "ct_gcm_clmul8_group",
    "ct_gcm_vaes256_seal", "ct_gcm_vaes256_open", "ct_gcm_vaes256_group",
    "ct_gcm_vaes512_seal", "ct_gcm_vaes512_open",
    "ct_gcm_vaes512x32_seal", "ct_gcm_vaes512x32_open",
    "ct_p256_ifma_double", "ct_p256_ifma_add", "ct_p256_ifma_madd", "ct_p256_ifma_madd4",
    "ct_p256_ifma_from_fp", "ct_p256_ifma_to_fp", "ct_p256_ifma_to_fp4",
    "ct_p384_ifma_double", "ct_p384_ifma_add", "ct_p384_ifma_madd", "ct_p384_ifma_madd4",
    "ct_p384_ifma_from_fp", "ct_p384_ifma_to_fp", "ct_p384_ifma_to_fp4",
    "ct_ed25519_fe64_scan", "ct_ed25519_fe64_madd_ext2_scan",
    "ct_rsa_select_2048", "ct_rsa_select32_2048", "ct_rsa_select32_avx2_1024",
    "ct_rsa_select32_avx2_1536", "ct_rsa_select32_avx2_2048",
    "ct_rsa_ifma_pow_1024", "ct_rsa_ifma_pow_2048",
    "ct_chacha20_zmm_group", "ct_keccak_x8_permute",
)

_VECTOR_REGISTER = re.compile(r"%[xyz]mm(\d+)\b")
_ZEROING = {"pxor", "vpxor", "vpxord", "vpxorq", "xorps", "vxorps", "xorpd", "vxorpd"}


def zeroed_at_end(block):
    """The vector registers known to be zero when a block ends, read forward:
    `vzeroall` zeroes xmm0-15, a zeroing idiom its register, and any other
    instruction whose destination (AT&T: the last operand) is a vector
    register makes that register unknown again. A store of a zeroed register
    (the ChaCha20 kernel wipes its scratch from `zmm0` after `vzeroall`)
    changes nothing."""
    zeroed = set()
    for line in block:
        op, operands = _split(line)
        if op == "vzeroall":
            zeroed |= set(range(16))
            continue
        regs = [_VECTOR_REGISTER.fullmatch(o) for o in operands]
        if op in _ZEROING and operands and all(regs) and len({r[1] for r in regs}) == 1:
            zeroed.add(int(regs[0][1]))
            continue
        if operands and regs[-1]:
            zeroed.discard(int(regs[-1][1]))
    return zeroed


def wipe_failures(assembly, target):
    """A finding for each X86_WIPED probe whose last vector-touching assembly
    block does not end by zeroing every vector register its blocks name."""
    if not target.startswith("x86_64"):
        return []
    functions = bodies(assembly, symbols_for(target))
    failures = []
    for probe in X86_WIPED:
        blocks = []
        # (blocks completed so far, register) for each vector register the
        # compiler's own code, outside any block, writes.
        compiled = []

        def walk(lines, seen):
            # Each block in order, a callee's at its call.
            current = None
            for line in lines:
                text = line.strip()
                callee = None if current is not None else called(line, target, functions)
                if callee is not None:
                    if callee not in seen:
                        seen.add(callee)
                        walk(functions[callee], seen)
                    continue
                if text.startswith("#APP"):
                    current = []
                elif text.startswith("#NO_APP"):
                    if current is not None:
                        block = instructions_of(current)
                        if any(_VECTOR_REGISTER.search(l) for l in block) or any(
                                _split(l)[0] in {"vzeroall", "vzeroupper"} for l in block):
                            blocks.append(block)
                    current = None
                elif current is not None:
                    current.append(line)
                elif text and not text.startswith((".", "#")) and not text.endswith(":"):
                    op, operands = _split(line)
                    last = _VECTOR_REGISTER.fullmatch(operands[-1]) if operands else None
                    if last:
                        compiled.append((len(blocks), int(last[1])))

        walk(functions[probe], {probe})
        if not blocks:
            failures.append(f"{probe}: no assembly block names a vector register")
            continue
        used = {int(n) for block in blocks for l in block for n in _VECTOR_REGISTER.findall(l)}
        # Registers the compiler wrote before the last block are in play too:
        # the block has to wipe what was built in them, not only what it names.
        used |= {n for done, n in compiled if done < len(blocks)}
        missing = used - zeroed_at_end(blocks[-1])
        if missing:
            failures.append(f"{probe}: vector registers not zeroed after its last kernel: "
                            + ", ".join(f"{n}" for n in sorted(missing)))
    return failures


def over_ceiling(target, excused):
    """A failure for each rule that excused more than it was reviewed for: per
    rule on the 32-bit targets, per probe and rule on x86-64 and aarch64."""
    if target.startswith(("x86_64", "aarch64")):
        table, name = ((X86_EXCUSE_CEILINGS, "X86_EXCUSE_CEILINGS") if target.startswith("x86_64")
                       else (AARCH64_EXCUSE_CEILINGS, "AARCH64_EXCUSE_CEILINGS"))
        failures = []
        for (probe, rule), count in sorted(excused.items()):
            ceiling = table.get(probe, {}).get(rule, 0)
            if count > ceiling:
                failures.append(
                    f"{probe}: {count} findings excused as {rule}, more than the {ceiling} "
                    f"reviewed; read them and update {name} and docs/CONSTANT_TIME.md")
        return failures
    ceilings = EXCUSE_CEILINGS.get(target, {})
    return [f"{count} findings excused as {rule}, more than the {ceilings.get(rule, 0)} "
            "reviewed; read them and update EXCUSE_CEILINGS and docs/CONSTANT_TIME.md"
            for rule, count in sorted(excused.items()) if count > ceilings.get(rule, 0)]


def build_root():
    """Where the harness is built: under CARGO_TARGET_DIR, as everything
    scripts/check.sh runs is, or the repository's own target/. Made
    absolute: check.sh sets a relative `target` when none is given, and rustc,
    which cargo starts in another directory, would resolve `--emit` against
    that one instead."""
    return Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target").resolve() / "ct-audit"


def build_probe(target):
    # A fresh explicit output forces Cargo to rebuild the harness and avoids
    # selecting a stale assembly file left by a prior dependency version.
    output_dir = build_root() / "probes"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{target}-{uuid.uuid4().hex}.s"
    subprocess.run([
        "cargo", "rustc", "--manifest-path", str(ROOT / "scripts/ct-audit/Cargo.toml"),
        "--release", "--target", target, "--target-dir", str(build_root()),
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
        assembly = build_probe(target)
        found = (inspect(assembly, target, excused) + over_ceiling(target, excused)
                 + wipe_failures(assembly, target))
        failures.extend(f"{target}: {finding}" for finding in found)
        wiped = (f", {len(X86_WIPED)} checked for cleared vector registers"
                 if target.startswith("x86_64") else "")
        print(f"{target}: {len(symbols_for(target))} probes{wiped}, {len(found)} failures"
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
