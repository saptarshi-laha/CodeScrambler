"""Generic helpers for *authoring* passes - shared by every engine.

These live in :mod:`codescrambler.core` (not in any one engine) so that the
mutation, virtualization, hardening and third-party pass authors can all
synthesize control flow without importing one another. Keeping them here is what
lets each engine stay independently importable.

Provided:

* :func:`synth_branch` - a label-targeted synthetic branch the assembler resolves.
* :func:`synth_labeled` - a synthetic instruction that also defines a label.
* :class:`LabelMaker` - process-unique label names.
* :func:`rebuild_section` / :func:`iter_executable` - small section utilities.
"""

from __future__ import annotations

import itertools
from typing import Iterable, List

from codescrambler.core.ir import Instruction, Program, Section


def synth_branch(mnemonic: str, target_label: str) -> Instruction:
    """Create a synthetic branch that the assembler resolves via ``target_label``.

    Synthetic branches must use the label mechanism (not raw text) so the
    two-pass assembler can compute the correct displacement after movement.
    """

    return Instruction(
        mnemonic=mnemonic,
        branch_label=target_label,
        is_branch=True,
        is_cond_branch=mnemonic != "jmp",
        synthetic=True,
    )


def synth_labeled(text: str, label: str) -> Instruction:
    """Create a synthetic instruction that also defines ``label`` at its location."""

    insn = Instruction.synth(text)
    insn.label = label
    return insn


class LabelMaker:
    """Hands out process-unique label names for synthesized control flow."""

    _counter = itertools.count()

    @staticmethod
    def fresh(prefix: str = "cs") -> str:
        return f"{prefix}_{next(LabelMaker._counter):x}"


def rebuild_section(section: Section, instructions: List[Instruction]) -> None:
    """Replace a section's instruction list (kept as a function for clarity)."""

    section.instructions = instructions


def iter_executable(program: Program) -> Iterable[Section]:
    """Yield executable sections; the canonical iteration order for passes."""

    return program.executable_sections()
