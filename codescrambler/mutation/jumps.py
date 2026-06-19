"""Jump-obfuscation pass.

Breaks up the linear instruction stream by inserting explicit unconditional
jumps to the immediately following instruction. A ``jmp next`` is flag-neutral
and semantics-preserving, but it defeats naive linear sweep disassembly and
sets up later block reordering. This is the correct, label-based replacement
for the original prototype's hard-coded ``eb00`` marker.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import (
    LabelMaker, Pass, PassReport, register, synth_branch,
)


@register
class JumpPass(Pass):
    """Insert label-targeted ``jmp`` instructions ahead of real instructions."""

    name = "jumps"

    def __init__(self, density: float = 0.2) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        inserted = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            for insn in section.instructions:
                if insn.mnemonic != ".byte" and rng.chance(self.density):
                    target = insn.label or LabelMaker.fresh("jt")
                    insn.label = target
                    rebuilt.append(synth_branch("jmp", target))
                    inserted += 1
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"jumps_inserted": inserted})
