"""Disassembler backend interface and registry.

A backend decodes the bytes of a single section into a list of
:class:`~codescrambler.core.ir.Instruction` objects. Branch labelling (turning
absolute targets into symbolic labels) is a cross-section concern and lives in
:func:`label_branches`, so every backend benefits from it equally.
"""

from __future__ import annotations

import abc
from typing import Dict, List

from codescrambler.core.ir import Arch, Instruction, Section


class DisassemblerBackend(abc.ABC):
    """Decodes section bytes into IR instructions for a given architecture."""

    name: str = "abstract"

    @abc.abstractmethod
    def decode(self, data: bytes, base_va: int, arch: Arch) -> List[Instruction]:
        """Decode ``data`` (loaded at ``base_va``) into instructions."""


def get_backend() -> DisassemblerBackend:
    """Return the default disassembler backend (capstone).

    The :class:`DisassemblerBackend` ABC is the extension point for a custom
    decoder; a project that wants one just implements ``decode`` and uses it
    directly (the loader accepts any backend instance).
    """

    from codescrambler.core.disasm.capstone_backend import CapstoneBackend

    return CapstoneBackend()


def label_name(va: int) -> str:
    """Canonical label name for the instruction located at ``va``."""

    return f"loc_{va:08x}"


def label_branches(sections: List[Section], image_base: int) -> None:
    """Attach symbolic labels so intra-program branches survive code movement.

    For every decoded instruction we know its address, so we build a global
    address -> instruction index. Any branch/call whose target lands on a known
    instruction gets:

    * a :attr:`~codescrambler.core.ir.Instruction.label` on the *target* and
    * a matching :attr:`branch_label` on the *source*.

    Targets that do not resolve to decoded code (imports, data, other modules)
    are left numeric; assembling each section at its final VA lets the assembler
    compute the correct relative offset for those.
    """

    index: Dict[int, Instruction] = {}
    for section in sections:
        for insn in section.instructions:
            if insn.address is not None:
                index[insn.address] = insn

    for section in sections:
        for insn in section.instructions:
            target = insn.branch_target
            if target is None:
                continue
            destination = index.get(target)
            if destination is None:
                continue
            if destination.label is None:
                destination.label = label_name(target)
            insn.branch_label = destination.label
