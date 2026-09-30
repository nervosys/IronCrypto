#!/usr/bin/env python3
"""Tests for fail-closed assembly inspection; no Rust builds required."""
import importlib.util
from pathlib import Path
import unittest

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
        }
        for target, instructions in cases.items():
            for instruction in instructions:
                with self.subTest(target=target, instruction=instruction):
                    self.assertEqual(len(audit.inspect(assembly(instruction), target)), len(audit.SYMBOLS))

    def test_returns_directives_and_comments_are_not_branches(self):
        cases = {
            "x86_64-unknown-linux-gnu": ("retq", "cmovneq %rax, %rcx", ".long 40318", "# idivq %rax"),
            "thumbv7em-none-eabihf": ("bx lr", "pop {r7, pc}", "asrs r0, r0, #31", "it ne", "@ bl helper"),
            "riscv32imac-unknown-none-elf": ("ret", "srai a0, a0, 31", "# call helper"),
        }
        for target, instructions in cases.items():
            for instruction in instructions:
                with self.subTest(target=target, instruction=instruction):
                    self.assertFalse(audit.forbidden(instruction, target))


if __name__ == "__main__":
    unittest.main()
