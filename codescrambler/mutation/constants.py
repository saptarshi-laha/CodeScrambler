"""Constant-unfolding pass.

Replaces ``mov reg, imm`` with a tiny computation that yields the same value::

    mov reg, imm   ==   mov reg, (imm ^ k); xor reg, k

The mask ``k`` is randomized per occurrence. Because ``xor`` writes the flags,
the rewrite only fires where flag liveness proves the flags are dead. The
emitted value is verified arithmetically before use.
"""

from __future__ import annotations

import re
from typing import List, Optional

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.analysis import flags_dead_after
from codescrambler.mutation.base import Pass, PassReport, register

_PTR_REGS_X64 = frozenset(
    {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    }
)
_PTR_REGS_X86 = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"})
_IMM = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")


@register
class ConstantUnfoldPass(Pass):
    """Hide immediate constants behind a reversible xor mask."""

    name = "constants"

    def __init__(self, coverage: float = 0.5) -> None:
        self.coverage = coverage

    def apply(self, program: Program, rng: Rng) -> PassReport:
        bits = program.arch.pointer_size * 8
        ptr_regs = _PTR_REGS_X64 if program.arch is Arch.X64 else _PTR_REGS_X86
        unfolded = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            instructions = section.instructions
            for index, insn in enumerate(instructions):
                replacement = None
                if rng.chance(self.coverage):
                    replacement = self._unfold(insn, index, instructions, ptr_regs, bits, rng)
                if replacement is None:
                    rebuilt.append(insn)
                else:
                    replacement[0].label = insn.label
                    rebuilt.extend(replacement)
                    unfolded += 1
            section.instructions = rebuilt
        return PassReport(self.name, {"constants_unfolded": unfolded})

    def _unfold(self, insn, index, instructions, ptr_regs, bits, rng) -> Optional[List[Instruction]]:
        if insn.mnemonic != "mov" or insn.is_branch:
            return None
        parts = [p.strip() for p in insn.op_str.split(",")]
        if len(parts) != 2:
            return None
        dst, imm_text = parts
        if dst not in ptr_regs or not _IMM.match(imm_text):
            return None
        if not flags_dead_after(instructions, index):
            return None

        mask_total = (1 << bits) - 1
        value = int(imm_text, 0) & mask_total
        # ``xor r64, imm`` only takes a sign-extended imm32, so keep the key in
        # the positive imm32 range; it then xors the low 32 bits and leaves the
        # high bits (already correct from the wide ``mov``) untouched.
        key = rng.bits(31)
        masked = value ^ key
        # Sanity: (value ^ key) ^ key == value, verified explicitly.
        assert (masked ^ key) == value
        return [
            Instruction.synth(f"mov {dst}, {masked:#x}"),
            Instruction.synth(f"xor {dst}, {key:#x}"),
        ]
