"""Call/jump switching pass.

Rewrites ``call target`` into the equivalent ``push return_address; jmp target``
sequence, which is exactly what a ``call`` does mechanically but hides the call
from tools that key off the opcode.

Correctness note on the pushed return address:

* On **x86** the return address is a 32-bit absolute value, so ``push OFFSET ret``
  encodes directly and the rewrite is exact and flag-neutral.
* On **x64** image bases routinely exceed 32 bits, so the return address cannot
  be pushed as an immediate without clobbering a register (whose liveness we
  cannot always prove at a call site). Rather than risk incorrect code, x64
  calls are left untouched and counted in the report. This is the documented
  extension point for a future, liveness-aware x64 implementation.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import (
    LabelMaker, Pass, PassReport, register, synth_branch, synth_labeled,
)


@register
class CallSwitchPass(Pass):
    """Turn direct calls into ``push ret; jmp target`` (x86 only, for now)."""

    name = "callswitch"

    def __init__(self, density: float = 0.5) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        switched = 0
        skipped = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            for insn in section.instructions:
                if self._eligible(insn, program.arch) and rng.chance(self.density):
                    if program.arch is Arch.X86:
                        rebuilt.extend(self._rewrite_x86(insn))
                        switched += 1
                        continue
                    skipped += 1
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"calls_switched": switched, "calls_skipped": skipped})

    @staticmethod
    def _eligible(insn: Instruction, arch: Arch) -> bool:
        # Only direct calls with a resolvable target (label) or absolute operand.
        return insn.is_call and not insn.is_rip_relative

    def _rewrite_x86(self, insn: Instruction) -> List[Instruction]:
        ret_label = LabelMaker.fresh("ret")
        # push the (absolute, 32-bit) return address; the assembler resolves the
        # label placeholder to its final address.
        push = Instruction.synth_ref(f"push {{{ret_label}}}", (ret_label,))
        if insn.branch_label:
            jmp = synth_branch("jmp", insn.branch_label)
        else:
            jmp = Instruction.synth(f"jmp {insn.op_str}")
        push.label = insn.label
        landing = synth_labeled("nop", ret_label)
        return [push, jmp, landing]
