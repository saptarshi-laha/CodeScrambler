"""Assembler: turns transformed IR back into machine code.

The single public entry point is :class:`~codescrambler.core.asm.assembler.Assembler`,
which performs iterative two-pass assembly so that branch displacements and
RIP-relative operands are correct even after instructions have been inserted,
removed or reordered.
"""

from codescrambler.core.asm.assembler import AssembledCode, Assembler

__all__ = ["Assembler", "AssembledCode"]
