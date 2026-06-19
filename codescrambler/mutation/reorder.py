"""Instruction-reordering pass.

Swaps adjacent instructions when they are provably independent, which perturbs
the instruction schedule without changing behavior. Two instructions may be
swapped only when *all* of the following hold:

* neither participates in control flow (no branch/call/ret, no label), and
* neither writes a register or flag the other reads or writes, and
* neither touches memory (a conservative way to avoid aliasing analysis).

When in doubt the pair is left as-is, so the pass can only ever produce a
different-but-equivalent ordering.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import Pass, PassReport, register

_MEMORY_HINT = "["


@register
class ReorderPass(Pass):
    """Swap independent adjacent instructions."""

    name = "reorder"

    def __init__(self, density: float = 0.3) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        swaps = 0
        for section in program.executable_sections():
            insns = section.instructions
            i = 0
            while i < len(insns) - 1:
                first, second = insns[i], insns[i + 1]
                if rng.chance(self.density) and self._independent(first, second):
                    insns[i], insns[i + 1] = second, first
                    swaps += 1
                    i += 2  # don't immediately re-swap the same pair
                else:
                    i += 1
        return PassReport(self.name, {"pairs_swapped": swaps})

    @staticmethod
    def _independent(a: Instruction, b: Instruction) -> bool:
        for insn in (a, b):
            if insn.is_branch or insn.is_call or insn.is_ret or insn.label:
                return False
            # Synthetic instructions carry no register metadata, so we cannot
            # prove independence; never reorder them.
            if insn.synthetic:
                return False
            if insn.mnemonic == ".byte":
                return False
            if _MEMORY_HINT in insn.op_str:
                return False

        a_writes = set(a.regs_written)
        b_writes = set(b.regs_written)
        a_reads = set(a.regs_read)
        b_reads = set(b.regs_read)

        # No WAW, RAW or WAR hazards in either direction.
        if a_writes & b_writes:
            return False
        if a_writes & b_reads or b_writes & a_reads:
            return False
        return True
