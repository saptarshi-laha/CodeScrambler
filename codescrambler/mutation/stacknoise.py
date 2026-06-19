"""Stack-noise pass.

Inserts net-zero stack-pointer wobble using ``lea``-based adjustments, which -
unlike ``add``/``sub`` - do not touch the flags:

    lea rsp, [rsp - N]
    lea rsp, [rsp + N]

The two adjustments cancel out, leaving the stack pointer and all flags exactly
as they were, while adding noise that complicates stack-frame analysis. ``lea``
on ``rsp`` is encodable on both x86 and x64.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import Pass, PassReport, register
from codescrambler.mutation.catalog import stack_pointer


@register
class StackNoisePass(Pass):
    """Add balanced, flag-neutral stack-pointer adjustments."""

    name = "stacknoise"

    def __init__(self, density: float = 0.1) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        sp = stack_pointer(program.arch)
        inserted = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            for insn in section.instructions:
                if insn.mnemonic != ".byte" and rng.chance(self.density):
                    delta = rng.randint(1, 0x40) * program.arch.pointer_size
                    rebuilt.append(Instruction.synth(f"lea {sp}, [{sp} - {delta}]"))
                    rebuilt.append(Instruction.synth(f"lea {sp}, [{sp} + {delta}]"))
                    inserted += 1
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"adjustments_inserted": inserted})
