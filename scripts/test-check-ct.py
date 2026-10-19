#!/usr/bin/env python3
"""Tests for fail-closed assembly inspection; no Rust builds required."""
import importlib.util
from pathlib import Path
import collections
import unittest
from unittest import mock
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("check_ct", Path(__file__).with_name("check-ct.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def assembly(instruction="ret"):
    return "\n".join(f"{name}:\n\t{instruction}\n\t.size {name}, .-{name}"
                     for name in audit.SYMBOLS)


class InspectionTests(unittest.TestCase):
    def test_all_probes_are_required(self):
        with self.assertRaisesRegex(ValueError, "missing probe"):
            audit.inspect(assembly().replace("ct_reduce_q:", "unrelated:"), audit.TARGETS[0])

    def test_target_probes_are_required_on_their_target_only(self):
        common = "\n".join(f"{name}:\n\tret\n\t.size {name}, .-{name}"
                           for name in audit.symbols_for("thumbv7em-none-eabihf"))
        with self.assertRaisesRegex(ValueError, "missing probe"):
            audit.inspect(common, "x86_64-unknown-linux-gnu")
        self.assertEqual(audit.inspect(common, "thumbv7em-none-eabihf"), [])

    def test_unterminated_and_duplicate_bodies_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unterminated"):
            audit.bodies("ct_reduce_q:\n\tret")
        with self.assertRaisesRegex(ValueError, "unterminated"):
            audit.bodies(assembly().replace("\t.size ct_reduce_q, .-ct_reduce_q", ""))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit.bodies(assembly() + "\nct_reduce_q:")

    def test_empty_bodies_are_rejected(self):
        self.assertTrue(audit.inspect(assembly(""), audit.TARGETS[0]))
        self.assertTrue(audit.inspect(assembly("# no instructions"), audit.TARGETS[0]))

    def test_branches_divisions_and_calls_are_rejected(self):
        cases = {
            "x86_64-unknown-linux-gnu": ("jne .L1", "je .L1", "loop .L1", "idivq %rcx", "divl %ecx", "callq helper", "jmp helper"),
            "thumbv6m-none-eabi": ("bgt .L1", "blo .L1", "beq.w .L1", "cbnz r0, .L1", "bl __aeabi_uidiv", "blx r3", "bx r3", "udiv r0, r1, r2", "tbb [pc, r0]"),
            "riscv32imac-unknown-none-elf": ("bne a0, a1, .L1", "bleu a0, a1, .L1", "beqz a0, .L1", "c.bnez a0, .L1", "c.j .L1", "divu a0, a1, a2", "rem a0, a1, a2", "call __udivsi3", "tail helper", "jalr a0"),
            "aarch64-unknown-linux-gnu": ("b.ne .L1", "b.eq .L1", "b.hs .L1", "cbz x0, .L1", "cbnz w3, .L1", "tbz x0, #3, .L1", "tbnz w1, #0, .L1", "b .L1", "bl memcpy", "blr x8", "br x16", "braaz x1", "retaa", "ret x1", "udiv x0, x1, x2", "sdiv w0, w1, w2"),
        }
        for target, instructions in cases.items():
            for instruction in instructions:
                with self.subTest(target=target, instruction=instruction):
                    self.assertEqual(len(audit.inspect(assembly(instruction), target)),
                                     len(audit.symbols_for(target)))

    def test_returns_directives_and_comments_are_not_branches(self):
        cases = {
            "x86_64-unknown-linux-gnu": ("retq", "cmovneq %rax, %rcx", ".long 40318", "# idivq %rax"),
            "thumbv7em-none-eabihf": ("bx lr", "pop {r7, pc}", "asrs r0, r0, #31", "it ne", "@ bl helper"),
            "riscv32imac-unknown-none-elf": ("ret", "srai a0, a0, 31", "# call helper"),
            "aarch64-unknown-linux-gnu": ("ret", "csel x0, x1, x2, ne", "bic x0, x1, x2", "bfi x0, x1, #3, #4", "aese v0.16b, v1.16b", "// bl helper"),
        }
        for target, instructions in cases.items():
            for instruction in instructions:
                with self.subTest(target=target, instruction=instruction):
                    self.assertFalse(audit.forbidden(instruction, target))


class CallTests(unittest.TestCase):
    """Calls into bodies in the same file are followed, not trusted."""

    X86 = "x86_64-unknown-linux-gnu"

    def with_helper(self, helper_instruction, call="callq\thelper"):
        helper = (f"\t.type helper,@function\nhelper:\n\t{helper_instruction}\n"
                  "\t.size helper, .-helper")
        return assembly(call) + "\n" + helper

    def test_a_clean_helper_passes(self):
        self.assertEqual(audit.inspect(self.with_helper("retq"), self.X86), [])

    def test_a_branch_in_a_helper_is_reported_against_the_probe(self):
        found = audit.inspect(self.with_helper("jne .L1"), self.X86)
        self.assertEqual(len(found), len(audit.symbols_for(self.X86)))
        self.assertTrue(all(" -> helper: jne .L1" in f for f in found), found)

    def test_tail_calls_and_other_targets_are_followed(self):
        self.assertTrue(audit.inspect(self.with_helper("jne .L1", "jmp\thelper"), self.X86))
        a64 = "aarch64-unknown-linux-gnu"
        self.assertTrue(audit.inspect(self.with_helper("b.ne .L1", "b\thelper"), a64))
        self.assertTrue(audit.inspect(self.with_helper("cbz x0, .L1", "bl\thelper"), a64))
        self.assertEqual(audit.inspect(self.with_helper("ret", "b\thelper"), a64), [])
        self.assertTrue(audit.inspect(
            self.with_helper("bne .L1", "bl\thelper"), "thumbv7em-none-eabihf"))
        self.assertTrue(audit.inspect(
            self.with_helper("bnez a0, .L1", "call\thelper"), "riscv32imac-unknown-none-elf"))

    def test_a_helper_that_calls_itself_ends(self):
        asm = self.with_helper("callq\thelper")
        self.assertEqual(audit.inspect(asm, self.X86), [])

    def test_a_call_to_an_undefined_symbol_stays_forbidden(self):
        found = audit.inspect(self.with_helper("callq\t__multi3"), self.X86)
        self.assertEqual(len(found), len(audit.symbols_for(self.X86)))



class TargetSymbolTests(unittest.TestCase):
    """The x86-64-only probes are required there and nowhere else."""

    def test_x86_only_probes_are_required_on_x86(self):
        asm = assembly().replace(f"{audit.X86_ONLY[0]}:", "unrelated:")
        with self.assertRaisesRegex(ValueError, "missing probe"):
            audit.inspect(asm, "x86_64-unknown-linux-gnu")

    def test_and_not_elsewhere(self):
        asm = "\n".join(f"{name}:\n\tbx lr\n\t.size {name}, .-{name}"
                        for name in audit.symbols_for("thumbv7em-none-eabihf"))
        self.assertEqual(audit.inspect(asm, "thumbv7em-none-eabihf"), [])
        self.assertTrue(set(audit.X86_ONLY) <= set(audit.symbols_for("x86_64-unknown-linux-gnu")))
        self.assertFalse(set(audit.X86_ONLY) & set(audit.symbols_for("riscv32imac-unknown-none-elf")))


class Aarch64SymbolTests(unittest.TestCase):
    """The aarch64-only probes are required there and nowhere else, and
    aarch64 runs every probe that is not x86-64-only."""

    def test_required_on_aarch64_only(self):
        a64 = "aarch64-unknown-linux-gnu"
        asm = assembly().replace(f"{audit.AARCH64_ONLY[0]}:", "unrelated:")
        with self.assertRaisesRegex(ValueError, "missing probe"):
            audit.inspect(asm, a64)
        self.assertEqual(audit.inspect(asm, "x86_64-unknown-linux-gnu"), [])
        self.assertEqual(audit.inspect(asm, "riscv32imac-unknown-none-elf"), [])
        common = set(audit.symbols_for("thumbv7em-none-eabihf"))
        self.assertEqual(set(audit.symbols_for(a64)), common | set(audit.AARCH64_ONLY))
        self.assertFalse(set(audit.AARCH64_ONLY) & set(audit.symbols_for("x86_64-unknown-linux-gnu")))
        self.assertIn(a64, audit.TARGETS)


class LiteralPoolTests(unittest.TestCase):
    """A Thumb jump over a constant pool is excused in the Ed25519 probes,
    and nothing that merely resembles one is."""

    M0 = "thumbv6m-none-eabi"

    def ed25519(self, body, probe=None):
        probe = probe or audit.ED25519[0]
        return assembly("bx lr").replace(f"{probe}:\n\tbx lr\n", f"{probe}:\n{body}")

    POOL = ("\tb\t.LBB0_2\n\t.p2align\t2\n.LCPI0_0:\n\t.long\t666643\n"
            ".LBB0_2:\n\tbx lr\n")

    def test_a_jump_over_a_pool_is_excused_and_counted(self):
        excused = collections.Counter()
        self.assertEqual(audit.inspect(self.ed25519(self.POOL), self.M0, excused), [])
        self.assertEqual(excused["literal-pool jump"], 1)

    def test_a_jump_over_code_is_not(self):
        body = self.POOL.replace("\t.long\t666643\n", "\tadds r0, r0, r1\n")
        self.assertTrue(audit.inspect(self.ed25519(body), self.M0))

    def test_a_conditional_jump_over_a_pool_is_not(self):
        body = self.POOL.replace("\tb\t.LBB0_2", "\tbne\t.LBB0_2")
        self.assertTrue(audit.inspect(self.ed25519(body), self.M0))

    def test_a_jump_elsewhere_is_not(self):
        body = self.POOL.replace(".LBB0_2:\n", ".LBB0_3:\n")
        self.assertTrue(audit.inspect(self.ed25519(body), self.M0))

    def test_only_the_ed25519_probes_get_it(self):
        body = self.POOL
        probe = audit.SYMBOLS[0]
        asm = assembly("bx lr").replace(f"{probe}:\n\tbx lr\n", f"{probe}:\n{body}")
        self.assertTrue(audit.inspect(asm, self.M0))

    def test_more_than_the_ceiling_fails(self):
        excused = collections.Counter({"literal-pool jump": 13})
        self.assertTrue(audit.over_ceiling(self.M0, excused))


class ExcuseTests(unittest.TestCase):
    """The 32-bit P-256 findings are excused by rule, and only those."""

    M0, M4, RV = "thumbv6m-none-eabi", "thumbv7em-none-eabihf", "riscv32imac-unknown-none-elf"

    def p256(self, lines, target, probe=None):
        """Every probe a clean body, and one probe, a P-256 one unless named,
        the given instructions."""
        clean = "bx lr" if target.startswith("thumb") else "ret"
        probe = probe or audit.P256[0]
        body = "".join(f"\t{line}\n" for line in lines)
        return assembly(clean).replace(f"{probe}:\n\t{clean}\n", f"{probe}:\n{body}")

    def run_on(self, lines, target, probe=None):
        excused = collections.Counter()
        return audit.inspect(self.p256(lines, target, probe), target, excused), excused

    def test_the_reviewed_loop_shapes_are_excused(self):
        cases = {
            self.M4: ["subs r2, #1", "str r1, [sp, #120]", "bne.w .LBB1_1", "bx lr"],
            self.M0: ["adds r1, #8", "cmp r1, #32", "ldr r2, [sp, #88]", "beq .LBB1_2",
                      "b .LBB1_1", "bx lr"],
            self.RV: ["addi t2, sp, 84", "bne t1, t2, .LBB1_1", "addi a0, sp, 84", "li a2, 40",
                      "li a1, 0", "call memset", "ret"],
        }
        for target, lines in cases.items():
            with self.subTest(target=target):
                failures, excused = self.run_on(lines, target)
                self.assertEqual(failures, [])
                self.assertTrue(excused)

    def test_a_branch_on_a_value_is_not_excused(self):
        cases = {
            self.M4: ["cmp r0, #0", "bne.w .LBB1_1", "bx lr"],
            self.M4 + " ": ["subs r0, r0, r1", "bne.w .LBB1_1", "bx lr"],
            self.M0: ["cmp r0, #32", "beq .LBB1_2", "bx lr"],
            self.RV: ["bne a0, a1, .LBB1_1", "ret"],
        }
        for target, lines in cases.items():
            with self.subTest(target=target):
                failures, _ = self.run_on(lines, target.strip())
                self.assertEqual(len(failures), 1, failures)

    def test_a_memset_of_a_computed_length_is_not_excused(self):
        failures, _ = self.run_on(["addi a0, sp, 84", "mv a2, s1", "call memset", "ret"], self.RV)
        self.assertEqual(len(failures), 1, failures)

    def test_rules_apply_only_to_p256_probes_on_32_bit_targets(self):
        failures, _ = self.run_on(["subs r2, #1", "bne.w .LBB1_1", "bx lr"], self.M4, "ct_reduce_q")
        self.assertEqual(len(failures), 1, failures)
        self.assertNotIn(audit.TARGETS[0], audit.EXCUSE_CEILINGS)

    def test_excusing_more_than_was_reviewed_fails(self):
        ceiling = audit.EXCUSE_CEILINGS[self.M4]["counter loop"]
        over = collections.Counter({"counter loop": ceiling + 1})
        self.assertEqual(len(audit.over_ceiling(self.M4, over)), 1)
        self.assertEqual(audit.over_ceiling(self.M4, collections.Counter({"counter loop": 1})), [])
        self.assertEqual(len(audit.over_ceiling(self.M4, collections.Counter({"new rule": 1}))), 1)

    def test_a_runtime_routine_is_followed_into_its_disassembly(self):
        call = ["bl __aeabi_lmul", "bx lr"]
        clean = ["\tmuls r1, r2, r1", "\tpop {r4, pc}"]
        branchy = ["\tcmp r0, #0", "\tbeq .LBB0_1"]
        with mock.patch.object(audit, "external_body", return_value=clean):
            self.assertEqual(self.run_on(call, self.M0)[0], [])
        with mock.patch.object(audit, "external_body", return_value=branchy):
            failures = self.run_on(call, self.M0)[0]
            self.assertTrue(failures and all("-> __aeabi_lmul" in f for f in failures), failures)
        # Only where it is listed: on Cortex-M4 the same call stays forbidden.
        self.assertEqual(len(self.run_on(call, self.M4)[0]), 1)


class X86LoopTests(unittest.TestCase):
    """On x86-64 a loop over a counter is excused, in the probes listed in
    X86_EXCUSE_CEILINGS and up to their ceilings, and nothing that only looks
    like one is."""

    X86 = "x86_64-unknown-linux-gnu"
    IFMA = "ct_rsa_ifma_amm_2048"   # ceiling: one counter loop, nothing else
    ADX = "ct_rsa_adx_mont_mul_2048"
    CIOS = "ct_rsa_cios_2048"

    def run_on(self, lines, probe=None):
        probe = probe or self.ADX
        body = "".join(line + "\n" if line.endswith(":") else f"\t{line}\n" for line in lines)
        asm = assembly("retq").replace(f"{probe}:\n\tretq\n", f"{probe}:\n{body}")
        self.assertIn(body, asm)
        excused = collections.Counter()
        failures = audit.inspect(asm, self.X86, excused)
        return failures + audit.over_ceiling(self.X86, excused), excused

    DEC = ["movl $32, %r9d", ".LBB0_1:", "movq (%rsi), %rax", "addq %rax, %rdx",
           "leaq 8(%rsi), %rsi", "decq %r9", "jne .LBB0_1", "retq"]
    CMP = ["xorl %ecx, %ecx", ".LBB0_1:", "addq (%rsi,%rcx,8), %rax", "adcq $0, %rdx",
           "addq $2, %rcx", "cmpq $32, %rcx", "jne .LBB0_1", "retq"]
    JRCXZ = ["movq $-32, %rcx", ".Ltmp0:", "mulxq (%rsi,%rcx,8), %rax, %r15",
             "adcxq (%rdi,%rcx,8), %rax", "adoxq %rbp, %rax", "movq %rax, (%rdi,%rcx,8)",
             "leaq 4(%rcx), %rcx", "jrcxz .Ltmp1", "jmp .Ltmp0", ".Ltmp1:", "retq"]

    def test_the_counter_shapes_are_excused(self):
        cases = {
            "dec/jne": (self.DEC, {"counter loop": 1}),
            "cmp counter, imm": (self.CMP, {"counter loop": 1}),
            "jrcxz": (self.JRCXZ, {"counter loop": 1, "unconditional jump": 1}),
            "cmp counter, fixed register": (
                ["movq %rdi, %r8", ".LBB0_1:", "addq (%rsi), %rax", "addq $8, %rsi",
                 "cmpq %rsi, %r8", "jne .LBB0_1", "retq"], {"counter loop": 1}),
            "exit from the middle": (
                ["xorl %ebp, %ebp", "jmp .LBB0_1", ".LBB0_2:", "incq %rbp",
                 "cmpq $32, %rbp", "je .LBB0_3", ".LBB0_1:", "addq (%rsi,%rbp,8), %rax",
                 "jmp .LBB0_2", ".LBB0_3:", "retq"], {"counter loop": 1, "unconditional jump": 2}),
            "constant memset": (
                ["leaq 8(%rsp), %rdi", "movl $528, %edx", "xorl %esi, %esi",
                 "callq *memset@GOTPCREL(%rip)", "retq"], {"constant memset": 1}),
        }
        for name, (lines, rules) in cases.items():
            # The MULX/ADX probe no longer clears a buffer, and has no memset
            # ceiling; CIOS still zeroes its accumulator, and has one.
            probe = self.CIOS if name == "constant memset" else self.ADX
            with self.subTest(name):
                failures, excused = self.run_on(lines, probe)
                self.assertEqual(failures, [])
                self.assertEqual(excused, collections.Counter(
                    {(probe, rule): count for rule, count in rules.items()}))

    def test_a_branch_on_anything_but_a_counter_is_not(self):
        cases = {
            "on a loaded value": [
                ".LBB0_1:", "movq (%rsi,%rcx,8), %rax", "incq %rcx", "testq %rax, %rax",
                "jne .LBB0_1", "retq"],
            "on a carry": [
                "movl $32, %r9d", ".LBB0_1:", "decq %r9", "adcq (%rsi), %rax", "jb .LBB0_1",
                "retq"],
            "on a borrow out of sbb": [
                ".LBB0_1:", "subq $1, %r9", "sbbq %rdx, %rax", "jne .LBB0_1", "retq"],
            "counter also written from data": [
                ".LBB0_1:", "movq (%rsi), %rax", "addq %rax, %r9", "decq %r9", "jne .LBB0_1",
                "retq"],
            "counter moved into from data": [
                ".LBB0_1:", "decq %r9", "cmovneq (%rsi), %r9", "testq %r9, %r9",
                "jne .LBB0_1", "retq"],
            "counter written by mul": [
                ".LBB0_1:", "mulq (%rsi)", "decq %rdx", "jne .LBB0_1", "retq"],
            "cmp against a register written in the loop": [
                ".LBB0_1:", "addq $1, %rcx", "movq (%rsi), %rdx", "cmpq %rdx, %rcx",
                "jne .LBB0_1", "retq"],
            "cmp against memory": [
                ".LBB0_1:", "addq $1, %rcx", "cmpq (%rsi), %rcx", "jne .LBB0_1", "retq"],
            "a never-stepped register": [
                ".LBB0_1:", "addq (%rsi), %rax", "cmpq $0, %r9", "jne .LBB0_1", "retq"],
            "outside any loop": ["decq %r9", "jne .LBB0_1", "addq %rax, %rax", ".LBB0_1:", "retq"],
            "a call in the loop": [
                ".LBB0_1:", "callq helper", "decq %r9", "jne .LBB0_1", "retq"],
            "jrcxz with rcx loaded in the loop": [
                ".Ltmp0:", "movq (%rsi), %rcx", "leaq 4(%rcx), %rcx", "jrcxz .Ltmp1",
                "jmp .Ltmp0", ".Ltmp1:", "retq"],
            "a jump to a register": ["jmpq *%rax", "retq"],
            "memset of a computed length": [
                "leaq 8(%rsp), %rdi", "movq %r8, %rdx", "xorl %esi, %esi",
                "callq *memset@GOTPCREL(%rip)", "retq"],
            "memset of a pointer argument": [
                "movq %r8, %rdi", "movl $528, %edx", "xorl %esi, %esi",
                "callq *memset@GOTPCREL(%rip)", "retq"],
        }
        helper = "\t.type helper,@function\nhelper:\n\tretq\n\t.size helper, .-helper\n"
        for name, lines in cases.items():
            with self.subTest(name):
                probe = self.ADX
                body = "".join(line + "\n" if line.endswith(":") else f"\t{line}\n"
                               for line in lines)
                asm = assembly("retq").replace(f"{probe}:\n\tretq\n", f"{probe}:\n{body}")
                asm += "\n" + helper
                excused = collections.Counter()
                failures = audit.inspect(asm, self.X86, excused)
                failures += audit.over_ceiling(self.X86, excused)
                self.assertTrue(failures, name)
                self.assertFalse(excused.get((probe, "counter loop")), (name, excused))

    def test_intel_syntax_gets_no_excuse(self):
        failures, _ = self.run_on([".intel_syntax noprefix", "mov r9d, 32", ".LBB0_1:",
                                   "dec r9", "jne .LBB0_1", ".att_syntax", "retq"])
        self.assertEqual(len(failures), 1, failures)

    def test_one_more_than_the_ceiling_fails(self):
        # Two counter loops in the IFMA probe, whose ceiling is one.
        two = self.DEC[:-1] + [line.replace("LBB0_1", "LBB0_2") for line in self.DEC]
        failures, excused = self.run_on(two, self.IFMA)
        self.assertEqual(excused[(self.IFMA, "counter loop")], 2)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("more than the 1 reviewed", failures[0])
        self.assertEqual(self.run_on(self.DEC, self.IFMA)[0], [])
        # And a rule the probe was not reviewed for at all.
        failures, _ = self.run_on(self.JRCXZ, self.IFMA)
        self.assertEqual(failures, [f"{self.IFMA}: jmp .Ltmp0"])
        for probe, rules in audit.X86_EXCUSE_CEILINGS.items():
            for rule, ceiling in rules.items():
                with self.subTest(probe=probe, rule=rule):
                    self.assertEqual(audit.over_ceiling(
                        self.X86, collections.Counter({(probe, rule): ceiling})), [])
                    self.assertEqual(len(audit.over_ceiling(
                        self.X86, collections.Counter({(probe, rule): ceiling + 1}))), 1)

    def test_a_probe_not_listed_excuses_nothing(self):
        for lines in (self.DEC, self.CMP, self.JRCXZ):
            with self.subTest(lines[0]):
                failures, excused = self.run_on(lines, "ct_reduce_q")
                self.assertTrue(failures)
                self.assertFalse(excused)
        self.assertNotIn("ct_reduce_q", audit.X86_EXCUSE_CEILINGS)
        self.assertTrue(set(audit.X86_EXCUSE_CEILINGS) <= set(audit.X86_ONLY))
        self.assertEqual(len(audit.over_ceiling(
            self.X86, collections.Counter({("ct_reduce_q", "counter loop"): 1}))), 1)

    def test_a_counter_branch_inside_the_loop_is_not(self):
        # Neither an exit nor the back edge: it picks a path within the
        # iteration. The back edge is excused; this one is not.
        failures, excused = self.run_on([
            ".LBB0_1:", "incq %rcx", "cmpq $7, %rcx", "jne .LBB0_2", "addq (%rsi), %rax",
            ".LBB0_2:", "cmpq $32, %rcx", "jne .LBB0_1", "retq"])
        self.assertEqual(failures, [f"{self.ADX}: jne .LBB0_2"])
        self.assertEqual(excused[(self.ADX, "counter loop")], 1)


class RoundCountDispatchTests(unittest.TestCase):
    """The round-count dispatch rule: a `je` or `jne` straight after
    `cmp $10` or `cmp $12` on a register is excused in the four 512-bit
    AES-GCM probes listed under it, and nowhere else."""

    X86 = "x86_64-unknown-linux-gnu"
    PROBE = "ct_gcm_vaes512_seal"   # ceiling: round-count dispatch 2
    ADX = "ct_rsa_adx_mont_mul_2048"

    def run_on(self, lines, probe):
        return X86LoopTests.run_on(self, lines, probe)

    def test_a_dispatch_on_10_or_12_rounds_is_excused(self):
        for lines in (["cmpq $10, %r11", "je .LBB0_1", ".LBB0_1:", "retq"],
                      ["cmpq $12, %r11", "jne .LBB0_1", ".LBB0_1:", "retq"],
                      ["cmpl $10, %ebx", "je .LBB0_1", ".LBB0_1:", "retq"]):
            with self.subTest(lines[0]):
                failures, excused = self.run_on(lines, self.PROBE)
                self.assertEqual(failures, [])
                self.assertEqual(excused, collections.Counter(
                    {(self.PROBE, "round-count dispatch"): 1}))

    def test_another_count_is_not_excused(self):
        failures, excused = self.run_on(
            ["cmpq $11, %r11", "je .LBB0_1", ".LBB0_1:", "retq"], self.PROBE)
        self.assertEqual(failures, [f"{self.PROBE}: je .LBB0_1"])
        self.assertFalse(excused)

    def test_a_branch_with_no_compare_before_it_is_not(self):
        failures, excused = self.run_on(
            ["xorl %eax, %eax", "je .LBB0_1", ".LBB0_1:", "retq"], self.PROBE)
        self.assertEqual(failures, [f"{self.PROBE}: je .LBB0_1"])
        self.assertFalse(excused)

    def test_only_the_probes_listed_get_it(self):
        failures, excused = self.run_on(
            ["cmpq $10, %r11", "je .LBB0_1", ".LBB0_1:", "retq"], self.ADX)
        self.assertEqual(failures, [f"{self.ADX}: je .LBB0_1"])
        self.assertFalse(excused)
        for probe in ("ct_gcm_vaes512_seal", "ct_gcm_vaes512_open",
                      "ct_gcm_vaes512x32_seal", "ct_gcm_vaes512x32_open"):
            with self.subTest(probe):
                self.assertIn("round-count dispatch", audit.X86_EXCUSE_CEILINGS[probe])


class LoopCountGuardTests(unittest.TestCase):
    """The loop-count guard rule: a `je`/`jne` right after `dec r`, outside a
    loop whose counter is `r`, that jumps past the loop's back edge, is excused
    in the probes listed under it, and nowhere else."""

    X86 = "x86_64-unknown-linux-gnu"
    PROBE = "ct_gcm_vaes512x32_seal"   # ceiling: loop-count guard 1

    def run_on(self, lines, probe):
        return X86LoopTests.run_on(self, lines, probe)

    def loop(self, guard_reg="r10", back_reg="r10"):
        return [f"decq %{guard_reg}", "je .LBB0_2", ".LBB0_1:", "movq (%rsi), %rax",
                "addq %rax, %rdx", f"decq %{back_reg}", "jne .LBB0_1", ".LBB0_2:", "retq"]

    def test_a_back_edge_after_another_loop_is_not_a_guard(self):
        # The second loop's back edge is `dec r10; jne` and lands past the first
        # loop's back edge, the same shape as a guard, but it is within a loop.
        lines = self.loop()[2:7] + [".LBB0_2:", "movq (%rsi), %rax", "decq %r10", "jne .LBB0_2", "retq"]
        failures, excused = self.run_on(["decq %r10"] + lines, self.PROBE)
        self.assertNotIn((self.PROBE, "loop-count guard"), excused)
        self.assertEqual(excused[(self.PROBE, "counter loop")], 2)

    def test_the_real_shape_is_excused(self):
        failures, excused = self.run_on(self.loop(), self.PROBE)
        self.assertEqual(failures, [])
        self.assertEqual(excused, collections.Counter(
            {(self.PROBE, "loop-count guard"): 1, (self.PROBE, "counter loop"): 1}))

    def test_a_guard_on_a_different_register_is_not(self):
        failures, excused = self.run_on(self.loop(guard_reg="r9"), self.PROBE)
        self.assertEqual(failures, [f"{self.PROBE}: je .LBB0_2"])
        self.assertNotIn((self.PROBE, "loop-count guard"), excused)

    def test_a_guard_into_the_loop_is_not(self):
        # Jumping to the loop's header, not past its back edge.
        lines = self.loop()
        lines[1] = "je .LBB0_1"
        failures, excused = self.run_on(lines, self.PROBE)
        self.assertEqual(failures, [f"{self.PROBE}: je .LBB0_1"])
        self.assertNotIn((self.PROBE, "loop-count guard"), excused)

    def test_a_probe_not_listed_excuses_nothing(self):
        failures, excused = self.run_on(self.loop(), "ct_reduce_q")
        self.assertIn("ct_reduce_q: je .LBB0_2", failures)
        self.assertFalse([k for k in excused if k[1] == "loop-count guard"])
        self.assertNotIn("ct_reduce_q", audit.X86_EXCUSE_CEILINGS)

    def test_the_listed_ceiling_is_one(self):
        self.assertEqual(audit.X86_EXCUSE_CEILINGS[self.PROBE]["loop-count guard"], 1)


class Aarch64LoopTests(unittest.TestCase):
    """On aarch64 a loop over a counter is excused, in the probes listed in
    AARCH64_EXCUSE_CEILINGS and up to their ceilings, and nothing that only
    looks like one is."""

    A64 = "aarch64-unknown-linux-gnu"
    ONE = "ct_ghash_pmull_absorb8"    # ceiling: one counter loop
    TWO = "ct_sha512_armv8_compress"  # ceiling: two

    def run_on(self, lines, probe=None, extra=""):
        probe = probe or self.TWO
        body = "".join(line + "\n" if line.endswith(":") else f"\t{line}\n" for line in lines)
        asm = assembly("ret").replace(f"{probe}:\n\tret\n", f"{probe}:\n{body}")
        self.assertIn(body, asm)
        asm += extra
        excused = collections.Counter()
        failures = audit.inspect(asm, self.A64, excused)
        return failures + audit.over_ceiling(self.A64, excused), excused

    # As the compiler emitted them for the probes (docs/CONSTANT_TIME.md).
    SUBS = ["mov w11, #384", ".LBB0_1:", "ldp q8, q11, [x10, #-64]", "subs x11, x11, #128",
            "rbit v15.16b, v8.16b", "ldp q9, q1, [x10], #128", "pmull2 v1.1q, v10.2d, v16.2d",
            "eor v31.16b, v0.16b, v1.16b", "b.ne .LBB0_1", "ret"]
    CMP = ["mov x8, xzr", ".LBB0_1:", "add x9, x1, x8", "ldp q0, q1, [x9]",
           "add x8, x8, #64", "rev32 v0.16b, v0.16b", "cmp x8, #256",
           "sha256h q2, q3, v0.4s", "b.ne .LBB0_1", "ret"]
    CBNZ = ["mov x9, #8", ".LBB0_1:", "ldr q0, [x1], #16", "aese v0.16b, v1.16b",
            "str q0, [x2], #16", "sub x9, x9, #1", "cbnz x9, .LBB0_1", "ret"]

    def test_the_counter_shapes_are_excused(self):
        cases = {
            "subs/b.ne": self.SUBS,
            "cmp counter, imm": self.CMP,
            "cbnz countdown": self.CBNZ,
            "cmp counter, fixed register": [
                "add x12, x1, #256", ".LBB0_1:", "ldr q0, [x1]", "add x1, x1, #16",
                "cmp x1, x12", "b.ne .LBB0_1", "ret"],
            "nested, as SHA-512's": [
                "mov w8, #256", ".LBB0_1:", "mov w11, #4", ".LBB0_2:", "subs x11, x11, #1",
                "sha512h q0, q1, v2.2d", "b.ne .LBB0_2", "subs x8, x8, #128",
                "add x1, x1, #128", "b.ne .LBB0_1", "ret"],
        }
        for name, lines in cases.items():
            with self.subTest(name):
                failures, excused = self.run_on(lines)
                self.assertEqual(failures, [])
                self.assertEqual(sum(excused.values()), 2 if name.startswith("nested") else 1)

    def test_a_branch_on_anything_but_a_counter_is_not(self):
        cases = {
            "b.eq on a loaded value": [
                ".LBB0_1:", "ldr x0, [x1], #8", "subs x9, x9, #1", "cmp x0, #0",
                "b.eq .LBB0_1", "ret"],
            "flags from a load-fed subs": [
                ".LBB0_1:", "ldr x0, [x1]", "subs x0, x0, x2", "b.ne .LBB0_1", "ret"],
            "tbz on a data bit": [
                ".LBB0_1:", "ldr x0, [x1], #8", "sub x9, x9, #1", "tbz x0, #0, .LBB0_1", "ret"],
            "tbnz on the counter": [
                ".LBB0_1:", "sub x9, x9, #1", "tbnz x9, #3, .LBB0_1", "ret"],
            "counter also written from data": [
                ".LBB0_1:", "ldr x0, [x1]", "add x9, x9, x0", "subs x9, x9, #1",
                "b.ne .LBB0_1", "ret"],
            "counter loaded in the loop": [
                ".LBB0_1:", "ldr x9, [x1]", "sub x9, x9, #1", "cbnz x9, .LBB0_1", "ret"],
            "counter as a writeback base": [
                ".LBB0_1:", "ldr q0, [x9], #16", "subs x9, x9, #1", "b.ne .LBB0_1", "ret"],
            "counter selected by csel": [
                ".LBB0_1:", "subs x9, x9, #1", "csel x9, x9, x0, ne", "cmp x9, #0",
                "b.ne .LBB0_1", "ret"],
            "cmp against a register written in the loop": [
                ".LBB0_1:", "add x9, x9, #1", "ldr x12, [x1]", "cmp x9, x12",
                "b.ne .LBB0_1", "ret"],
            "a ccmp chain on data": [
                ".LBB0_1:", "subs x9, x9, #1", "ccmp x0, #0, #4, ne", "b.ne .LBB0_1", "ret"],
            "tst": [".LBB0_1:", "sub x9, x9, #1", "tst x9, #7", "b.ne .LBB0_1", "ret"],
            "flags from a carry": [
                ".LBB0_1:", "sub x9, x9, #1", "adcs x0, x0, x2", "b.ne .LBB0_1", "ret"],
            "a never-stepped register": [
                ".LBB0_1:", "ldr q0, [x1]", "cmp x9, #0", "b.ne .LBB0_1", "ret"],
            "outside any loop": ["subs x9, x9, #1", "b.ne .LBB0_1", "add x0, x0, x0",
                                 ".LBB0_1:", "ret"],
            "a call in the loop": [
                ".LBB0_1:", "bl helper", "subs x9, x9, #1", "b.ne .LBB0_1", "ret"],
            "an unknown instruction in the loop": [
                ".LBB0_1:", "msr nzcv, x0", "subs x9, x9, #1", "b.ne .LBB0_1", "ret"],
            "an unknown instruction between the flags and the branch": [
                ".LBB0_1:", "subs x9, x9, #1", "frobnicate x0", "b.ne .LBB0_1", "ret"],
            "br indirect": ["adr x16, .LBB0_1", "br x16", ".LBB0_1:", "ret"],
            "blr indirect": ["blr x8", "ret"],
        }
        helper = "\t.type helper,@function\nhelper:\n\tret\n\t.size helper, .-helper\n"
        for name, lines in cases.items():
            with self.subTest(name):
                failures, excused = self.run_on(lines, extra="\n" + helper)
                self.assertTrue(failures, name)
                self.assertFalse(excused.get((self.TWO, "counter loop")), (name, excused))

    def test_one_more_than_the_ceiling_fails(self):
        two = self.SUBS[:-1] + [line.replace("LBB0_1", "LBB0_2") for line in self.SUBS]
        failures, excused = self.run_on(two, self.ONE)
        self.assertEqual(excused[(self.ONE, "counter loop")], 2)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("more than the 1 reviewed", failures[0])
        self.assertIn("AARCH64_EXCUSE_CEILINGS", failures[0])
        self.assertEqual(self.run_on(self.SUBS, self.ONE)[0], [])
        for probe, rules in audit.AARCH64_EXCUSE_CEILINGS.items():
            for rule, ceiling in rules.items():
                with self.subTest(probe=probe, rule=rule):
                    self.assertEqual(audit.over_ceiling(
                        self.A64, collections.Counter({(probe, rule): ceiling})), [])
                    self.assertEqual(len(audit.over_ceiling(
                        self.A64, collections.Counter({(probe, rule): ceiling + 1}))), 1)

    def test_a_probe_not_listed_excuses_nothing(self):
        for probe in ("ct_ghash_pmull_mul", "ct_reduce_q", "ct_aes256_armv8_encrypt"):
            for lines in (self.SUBS, self.CMP, self.CBNZ):
                with self.subTest(probe=probe, shape=lines[0]):
                    failures, excused = self.run_on(lines, probe)
                    self.assertTrue(failures)
                    self.assertFalse(excused)
            self.assertNotIn(probe, audit.AARCH64_EXCUSE_CEILINGS)
        self.assertTrue(set(audit.AARCH64_EXCUSE_CEILINGS) <= set(audit.AARCH64_ONLY))

    def test_x86_ceilings_do_not_apply_on_aarch64(self):
        # A probe with an x86-64 ceiling and no aarch64 one excuses nothing
        # here, and the reverse.
        failures, excused = self.run_on(self.SUBS, "ct_reduce_q")
        self.assertTrue(failures)
        self.assertFalse(set(audit.AARCH64_EXCUSE_CEILINGS) & set(audit.X86_EXCUSE_CEILINGS))

    def test_a_counter_branch_inside_the_loop_is_not(self):
        failures, excused = self.run_on([
            ".LBB0_1:", "add x9, x9, #1", "cmp x9, #7", "b.ne .LBB0_2", "ldr q0, [x1]",
            ".LBB0_2:", "cmp x9, #32", "b.ne .LBB0_1", "ret"])
        self.assertEqual(failures, [f"{self.TWO}: b.ne .LBB0_2"])
        self.assertEqual(excused[(self.TWO, "counter loop")], 1)

    def test_an_unconditional_jump_is_not_excused(self):
        failures, _ = self.run_on(["b .LBB0_1", ".LBB0_1:", "ret"])
        self.assertEqual(failures, [f"{self.TWO}: b .LBB0_1"])


class BuildTests(unittest.TestCase):
    def setUp(self):
        # These tests place the build under a temporary ROOT; a
        # CARGO_TARGET_DIR from the caller's environment would move it.
        environment = mock.patch.dict(audit.os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        audit.os.environ.pop("CARGO_TARGET_DIR", None)

    def test_stale_artifacts_cannot_hide_a_current_branch(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(audit, "ROOT", Path(directory)):
            stale_dir = Path(directory) / "target/ct-audit" / audit.TARGETS[0] / "release/deps"
            stale_dir.mkdir(parents=True)
            (stale_dir / "ct_audit-old.s").write_text(assembly(), encoding="utf-8")
            (stale_dir / "ct_audit-older.s").write_text(assembly(), encoding="utf-8")
            outputs = []

            def compiler(command, **kwargs):
                output = Path(command[-1].removeprefix("--emit=asm="))
                outputs.append(output)
                self.assertFalse(output.exists())
                output.write_text(assembly("jne .L1"), encoding="utf-8")

            with mock.patch.object(audit.subprocess, "run", side_effect=compiler):
                for _ in range(2):
                    current = audit.build_probe(audit.TARGETS[0])
                    self.assertEqual(len(audit.inspect(current, audit.TARGETS[0])), len(audit.symbols_for(audit.TARGETS[0])))
            self.assertNotEqual(outputs[0], outputs[1])
            latest = Path(directory) / "target/ct-audit/probes" / f"{audit.TARGETS[0]}.s"
            self.assertEqual(latest.read_text(encoding="utf-8"), assembly("jne .L1"))

    def test_missing_current_output_fails_even_with_a_previous_pass(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(audit, "ROOT", Path(directory)):
            latest = Path(directory) / "target/ct-audit/probes" / f"{audit.TARGETS[0]}.s"
            latest.parent.mkdir(parents=True)
            latest.write_text(assembly(), encoding="utf-8")
            with mock.patch.object(audit.subprocess, "run"):
                with self.assertRaisesRegex(ValueError, "did not produce"):
                    audit.build_probe(audit.TARGETS[0])

    def test_compiler_failure_is_not_replaced_by_cached_output(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(audit, "ROOT", Path(directory)):
            with mock.patch.object(audit.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")):
                with self.assertRaises(subprocess.CalledProcessError):
                    audit.build_probe(audit.TARGETS[0])


if __name__ == "__main__":
    unittest.main()
