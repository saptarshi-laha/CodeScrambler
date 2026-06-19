"""Anti-disassembly pass (defeats linear-sweep disassemblers).

Inserts an unconditional jump over a few *unreachable* "opcode-like" junk bytes:

    jmp over
    .byte 0xE8, ...      ; never executed; desyncs a linear sweep
  over:
    <real instruction>

Execution is unaffected (the jump always skips the junk), but a linear-sweep
disassembler decodes the junk as the start of an instruction and mis-aligns the
following real code. The junk's leading byte is chosen from multi-byte opcode
prefixes (call/jmp/two-byte/REX) to maximize the mis-decode.

This is the correct, label-based realization of the classic "junk byte" trick:
the junk lives strictly between the jump and its target, so it is provably dead.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import (
    LabelMaker, Pass, PassReport, register, synth_branch,
)

# Leading bytes that begin multi-byte instructions, so a linear sweep keeps
# consuming the following (real) bytes and desyncs.
_DECOY_LEADS = (0xE8, 0xE9, 0x0F, 0xFF, 0x48, 0x68)


@register
class AntiDisasmPass(Pass):
    """Insert unreachable junk bytes behind guaranteed jumps."""

    name = "antidisasm"

    def __init__(self, density: float = 0.15, max_junk: int = 4) -> None:
        self.density = density
        self.max_junk = max_junk

    def apply(self, program: Program, rng: Rng) -> PassReport:
        inserted = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            for insn in section.instructions:
                if insn.mnemonic != ".byte" and rng.chance(self.density):
                    over = insn.label or LabelMaker.fresh("ad")
                    insn.label = over
                    rebuilt.append(synth_branch("jmp", over))
                    rebuilt.append(self._junk(rng))
                    inserted += 1
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"decoys_inserted": inserted})

    def _junk(self, rng: Rng) -> Instruction:
        count = rng.randint(1, self.max_junk)
        blob = bytes([rng.choice(_DECOY_LEADS)] + [rng.randint(0, 255) for _ in range(count - 1)])
        # raw, non-synthetic => the assembler emits these bytes verbatim.
        return Instruction(mnemonic=".byte", raw=blob)
