"""A minimal basic-block model over the flat instruction list.

A *basic block* is a straight-line run of instructions with a single entry (its
first instruction, the "leader") and a single exit (its last instruction). This
is the foundation for control-flow transforms (block scattering, and - later -
flattening and branch functions).

We compute leaders conservatively, so the partition is always *safe*:

* the first instruction is a leader;
* the instruction *after* any branch/return is a leader;
* any instruction that carries a label (i.e. is a branch target or a join point)
  is a leader.

Splitting at every labelled instruction means we may produce more (smaller)
blocks than a classic CFG, which is harmless for our purposes and guarantees
that every control-flow edge lands on a block boundary. ``build_blocks`` followed
by ``flatten_blocks`` (without reordering) reproduces the original list exactly -
the property our tests rely on.

This module lives in :mod:`codescrambler.core` so every engine can use it without
depending on another engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from codescrambler.core.ir import Instruction


@dataclass
class BasicBlock:
    """A single-entry, single-exit run of instructions."""

    start: int
    instructions: List[Instruction] = field(default_factory=list)

    @property
    def label(self) -> Optional[str]:
        return self.instructions[0].label if self.instructions else None

    @property
    def terminator(self) -> Optional[Instruction]:
        return self.instructions[-1] if self.instructions else None

    @property
    def falls_through(self) -> bool:
        """True if control can fall off the end into the next block.

        Unconditional jumps and returns do *not* fall through; everything else
        (plain instructions, conditional branches, calls) does.
        """

        last = self.terminator
        if last is None:
            return True
        if last.is_ret:
            return False
        if last.is_branch and not last.is_cond_branch:
            return False  # unconditional jmp
        return True


def _is_hard_terminator(insn: Instruction) -> bool:
    return insn.is_ret or insn.is_branch  # jmp / jcc / ret end a block


def build_blocks(instructions: List[Instruction]) -> List[BasicBlock]:
    """Partition ``instructions`` into basic blocks (safe over-approximation)."""

    n = len(instructions)
    if n == 0:
        return []

    leaders = {0}
    for i, insn in enumerate(instructions):
        if _is_hard_terminator(insn) and i + 1 < n:
            leaders.add(i + 1)
        if insn.label:
            leaders.add(i)

    ordered = sorted(leaders)
    blocks: List[BasicBlock] = []
    for bi, start in enumerate(ordered):
        end = ordered[bi + 1] if bi + 1 < len(ordered) else n
        blocks.append(BasicBlock(start=start, instructions=instructions[start:end]))
    return blocks


def flatten_blocks(blocks: List[BasicBlock]) -> List[Instruction]:
    """Concatenate blocks back into a flat instruction list."""

    out: List[Instruction] = []
    for block in blocks:
        out.extend(block.instructions)
    return out
