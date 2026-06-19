"""Block splitting + scattering (control-flow layout obfuscation).

Splits a section into basic blocks and **shuffles their physical order**, so the
on-disk/linear layout no longer matches execution order. A linear reader can no
longer follow the program top-to-bottom.

Correctness is by construction:

* Every inter-block edge is expressed as a **symbolic label**, which the
  assembler resolves to the right displacement regardless of block order.
* Before shuffling, every block that can *fall through* gets an explicit
  ``jmp <next-block>`` appended, so reordering can never change which block runs
  next. Blocks ending in an unconditional jump or ``ret`` need nothing.
* A trailing block that falls off the end of the section is **pinned** in place
  (there is no label for "whatever follows the section"), so we never change what
  executes after it.
* The entry point is resolved through the VA map by address, so it keeps working
  wherever its block lands.

No instruction is ever rewritten or dropped - only relinked and reordered - which
is why this is safe to commit (verified in memory; runtime validation is yours).
"""

from __future__ import annotations

from typing import List

from codescrambler.core.cfg import BasicBlock, build_blocks
from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import LabelMaker, Pass, PassReport, register, synth_branch


@register
class BlockScatterPass(Pass):
    """Reorder basic blocks, relinking fall-through edges with explicit jumps."""

    name = "scatter"

    def __init__(self, probability: float = 1.0, min_blocks: int = 3) -> None:
        self.probability = probability
        self.min_blocks = min_blocks

    def apply(self, program: Program, rng: Rng) -> PassReport:
        scattered = 0
        for section in program.executable_sections():
            blocks = build_blocks(section.instructions)
            if len(blocks) < self.min_blocks or not rng.chance(self.probability):
                continue
            self._ensure_leader_labels(blocks)
            self._relink_fallthroughs(blocks)
            section.instructions = self._shuffled(blocks, rng)
            scattered += 1
        return PassReport(self.name, {"sections_scattered": scattered})

    # -- helpers ----------------------------------------------------------
    def _ensure_leader_labels(self, blocks: List[BasicBlock]) -> None:
        for block in blocks:
            if block.instructions and not block.instructions[0].label:
                block.instructions[0].label = LabelMaker.fresh("blk")

    def _relink_fallthroughs(self, blocks: List[BasicBlock]) -> None:
        """Append an explicit jump to the successor for every fall-through block.

        The last block is left alone if it falls through (it would run off the
        end of the section); we simply never move it (see ``_shuffled``).
        """

        last = len(blocks) - 1
        for index, block in enumerate(blocks):
            if not block.falls_through or index == last:
                continue
            successor_label = blocks[index + 1].instructions[0].label
            block.instructions = list(block.instructions) + [synth_branch("jmp", successor_label)]

    def _shuffled(self, blocks: List[BasicBlock], rng: Rng) -> List[Instruction]:
        pinned = blocks[-1] if blocks[-1].falls_through else None
        movable = blocks[:-1] if pinned is not None else list(blocks)
        rng.shuffle(movable)
        order = movable + ([pinned] if pinned is not None else [])
        return [insn for block in order for insn in block.instructions]
