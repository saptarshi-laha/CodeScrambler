"""Parse a PE file into the engine's :class:`~codescrambler.core.ir.Program`.

Sections are classified by their *characteristics*, not their names, so an
executable section called ``.boom`` or several executable sections are all
handled identically. Executable sections are disassembled eagerly; data
sections keep their raw bytes for later (optional) encryption.
"""

from __future__ import annotations

from typing import Optional

import pefile

from codescrambler.core.disasm.base import DisassemblerBackend, get_backend, label_branches
from codescrambler.core.ir import Arch, Program, Section

_PE32 = 0x10B
_PE32_PLUS = 0x20B


class PELoader:
    """Loads a PE from disk and decodes it into the IR.

    Pass a custom :class:`DisassemblerBackend` to use a different decoder;
    by default the capstone backend is used.
    """

    def __init__(self, backend: Optional[DisassemblerBackend] = None) -> None:
        self._backend = backend or get_backend()

    def load(self, path: str) -> Program:
        pe = pefile.PE(path)
        arch = self._detect_arch(pe)
        backend = self._backend

        program = Program(
            arch=arch,
            image_base=pe.OPTIONAL_HEADER.ImageBase,
            entry_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        )

        for raw_section in pe.sections:
            section = self._convert_section(raw_section)
            if section.is_executable:
                base_va = program.image_base + section.rva
                section.instructions = backend.decode(section.raw, base_va, arch)
            program.sections.append(section)

        label_branches(program.sections, program.image_base)
        program.metadata["source_path"] = path
        return program

    @staticmethod
    def _detect_arch(pe: "pefile.PE") -> Arch:
        magic = pe.OPTIONAL_HEADER.Magic
        if magic == _PE32:
            return Arch.X86
        if magic == _PE32_PLUS:
            return Arch.X64
        raise ValueError(f"unsupported PE optional-header magic: {magic:#x}")

    @staticmethod
    def _convert_section(raw_section) -> Section:
        flags = pefile.SECTION_CHARACTERISTICS
        characteristics = raw_section.Characteristics
        is_executable = bool(characteristics & flags["IMAGE_SCN_MEM_EXECUTE"])
        name = raw_section.Name.decode(errors="replace").rstrip("\x00").rstrip()
        return Section(
            name=name,
            rva=raw_section.VirtualAddress,
            virtual_size=raw_section.Misc_VirtualSize,
            raw=raw_section.get_data(),
            characteristics=characteristics,
            is_executable=is_executable,
        )


def load_program(path: str, backend: Optional[DisassemblerBackend] = None) -> Program:
    """Convenience wrapper around :class:`PELoader`."""

    return PELoader(backend).load(path)
