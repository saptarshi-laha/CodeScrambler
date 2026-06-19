"""Rebuild a runnable PE from the transformed IR.

Strategy (the same one packers/protectors use, because it is robust):

* Assemble *every* executable section's instructions into one blob at a fresh
  base VA. Doing it as a single listing lets the assembler resolve branches that
  cross section boundaries, and yields a complete ``old VA -> new VA`` map.
* Append that blob as a new executable section and point the entry point at the
  moved entry instruction. The original sections stay in place (now dead) so any
  absolute reference we did not catch still finds plausible bytes.
* Regenerate the base relocation table so absolute addresses inside the moved
  code remain relocatable, and update the directories that reference code
  (TLS/exports/exceptions/SAFESEH) via :class:`~codescrambler.pe.fidelity.Fidelity`.

The actual byte surgery is done on a copy of the original file bytes using
explicit offsets, which avoids surprises from higher-level serialization.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import pefile

from codescrambler.core.asm import Assembler
from codescrambler.core.ir import Program
from codescrambler.core.rng import Rng
from codescrambler.pe import reloc as reloc_mod
from codescrambler.pe.fidelity import Fidelity

_SECTION_HEADER_SIZE = 0x28
_REL_BASED_HIGHLOW = 3
_REL_BASED_DIR64 = 10

# Section characteristics.
_SCN_CODE = 0x00000020
_SCN_INIT_DATA = 0x00000040
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class _PendingSection:
    name: bytes
    rva: int
    virtual_size: int
    file_offset: int
    raw: bytes
    characteristics: int


# A post-build hook receives the writer and the live pefile object.
PostHook = Callable[["PEWriter", "pefile.PE"], None]


class PEWriter:
    """Builds the output PE for a transformed :class:`Program`."""

    def __init__(self, program: Program, in_path: str, rng: Rng) -> None:
        self.program = program
        self.in_path = in_path
        self.rng = rng
        self.pe = pefile.PE(in_path)
        self._hooks: List[PostHook] = []

        self.section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        self.file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.ptr_size = program.arch.pointer_size

        # Cursors used when appending new sections.
        self._next_rva = self._initial_next_rva()
        self._next_file = _align(len(self.pe.__data__), self.file_alignment)
        self._pending: List[_PendingSection] = []
        self._appended = bytearray()

        # Populated during build for hooks / diagnostics.
        self.address_map: Dict[int, int] = {}
        self.new_entry_rva: int = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # -- public API -------------------------------------------------------
    def add_post_hook(self, hook: PostHook) -> None:
        """Register a callback run just before the file is serialized."""

        self._hooks.append(hook)

    def add_section(self, name: str, raw: bytes, characteristics: int) -> int:
        """Queue a new section; returns its RVA. Data is appended at write()."""

        rva = self._next_rva
        file_offset = self._next_file
        self._pending.append(
            _PendingSection(
                name=name.encode()[:8].ljust(8, b"\x00"),
                rva=rva,
                virtual_size=len(raw),
                file_offset=file_offset,
                raw=raw,
                characteristics=characteristics,
            )
        )
        self._next_rva = _align(rva + len(raw), self.section_alignment)
        self._next_file = _align(file_offset + len(raw), self.file_alignment)
        return rva

    def write(self, out_path: str) -> None:
        code, address_map = self._assemble_code()
        self.address_map = address_map

        rva_map = {old - self.image_base: new - self.image_base for old, new in address_map.items()}
        intervals = self._build_intervals(address_map)

        code_rva = self.add_section(
            self._code_section_name(), code,
            _SCN_CODE | _SCN_MEM_EXECUTE | _SCN_MEM_READ,
        )
        self._code_base_rva = code_rva

        entry_va = self.program.entry_va
        if entry_va in address_map:
            self.new_entry_rva = address_map[entry_va] - self.image_base

        self._rebuild_relocations(intervals)

        # Directory retargeting works on the live pefile (mutates pe.__data__).
        Fidelity(self.pe, lambda r: rva_map.get(r), self.image_base, self.ptr_size).retarget_all()

        for hook in self._hooks:
            hook(self, self.pe)

        self._serialize(out_path)

    # -- assembly ---------------------------------------------------------
    def _assemble_code(self) -> Tuple[bytes, Dict[int, int]]:
        instructions = self.program.all_instructions()
        base_va = self.image_base + self._next_rva
        result = Assembler(self.program.arch).assemble(instructions, base_va)
        return result.data, result.address_map

    def _build_intervals(self, address_map: Dict[int, int]) -> List[Tuple[int, int, int]]:
        """List of ``(old_start_rva, length, new_start_rva)`` for each instruction."""

        intervals: List[Tuple[int, int, int]] = []
        for section in self.program.executable_sections():
            for insn in section.instructions:
                if insn.address is None or insn.address not in address_map:
                    continue
                length = max(len(insn.raw), 1)
                intervals.append(
                    (
                        insn.address - self.image_base,
                        length,
                        address_map[insn.address] - self.image_base,
                    )
                )
        return intervals

    # -- relocations ------------------------------------------------------
    def _rebuild_relocations(self, intervals: List[Tuple[int, int, int]]) -> None:
        existing = reloc_mod.read_relocations(self.pe)
        if not existing:
            return

        def remap(rva: int) -> Optional[int]:
            for old_start, length, new_start in intervals:
                if old_start <= rva < old_start + length:
                    return new_start + (rva - old_start)
            return None

        extra = reloc_mod.map_relocations(existing, remap)
        combined = existing + extra
        blocks = reloc_mod.build_reloc_blocks(combined)
        if not blocks:
            return

        reloc_rva = self.add_section(".csrel", blocks, _SCN_INIT_DATA | _SCN_MEM_READ)
        self._reloc_dir = (reloc_rva, len(blocks))

    # -- serialization ----------------------------------------------------
    def _serialize(self, out_path: str) -> None:
        data = bytearray(self.pe.__data__)

        self._patch_headers(data)
        self._append_sections(data)

        with open(out_path, "wb") as handle:
            handle.write(data)

    def _patch_headers(self, data: bytearray) -> None:
        file_header_off = self.pe.FILE_HEADER.get_file_offset()
        opt_off = self.pe.OPTIONAL_HEADER.get_file_offset()

        old_count = self.pe.FILE_HEADER.NumberOfSections
        new_count = old_count + len(self._pending)
        struct.pack_into("<H", data, file_header_off + 2, new_count)

        # AddressOfEntryPoint (offset 16) and SizeOfImage (offset 56).
        struct.pack_into("<I", data, opt_off + 16, self.new_entry_rva)
        size_of_image = _align(self._next_rva, self.section_alignment)
        struct.pack_into("<I", data, opt_off + 56, size_of_image)

        self._ensure_header_room(old_count, new_count)
        self._write_section_headers(data, old_count)

        if getattr(self, "_reloc_dir", None) is not None:
            self._patch_reloc_directory(data)

    def _ensure_header_room(self, old_count: int, new_count: int) -> None:
        first_section_off = self.pe.sections[0].get_file_offset()
        table_off = first_section_off  # section table starts at first header
        end_of_new_table = table_off + new_count * _SECTION_HEADER_SIZE
        first_raw = min(s.PointerToRawData for s in self.pe.sections if s.SizeOfRawData)
        if end_of_new_table > first_raw:
            raise RuntimeError(
                "not enough header padding to add sections "
                f"(need {end_of_new_table:#x}, raw data starts {first_raw:#x})"
            )

    def _write_section_headers(self, data: bytearray, old_count: int) -> None:
        table_off = self.pe.sections[0].get_file_offset()
        for i, section in enumerate(self._pending):
            entry = table_off + (old_count + i) * _SECTION_HEADER_SIZE
            data[entry:entry + 8] = section.name
            struct.pack_into(
                "<IIII", data, entry + 8,
                section.virtual_size, section.rva,
                _align(len(section.raw), self.file_alignment), section.file_offset,
            )
            struct.pack_into("<IIHHI", data, entry + 24, 0, 0, 0, 0, section.characteristics)

    def _patch_reloc_directory(self, data: bytearray) -> None:
        reloc_rva, reloc_size = self._reloc_dir
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
        ]
        off = directory.get_file_offset()
        struct.pack_into("<II", data, off, reloc_rva, reloc_size)

    def _append_sections(self, data: bytearray) -> None:
        for section in self._pending:
            if len(data) < section.file_offset:
                data.extend(b"\x00" * (section.file_offset - len(data)))
            padded = section.raw + b"\x00" * (
                _align(len(section.raw), self.file_alignment) - len(section.raw)
            )
            data[section.file_offset:section.file_offset + len(padded)] = padded

    # -- misc helpers -----------------------------------------------------
    def _initial_next_rva(self) -> int:
        last = max(
            self.pe.sections,
            key=lambda s: s.VirtualAddress + s.Misc_VirtualSize,
        )
        end = last.VirtualAddress + max(last.Misc_VirtualSize, last.SizeOfRawData)
        return _align(end, self.pe.OPTIONAL_HEADER.SectionAlignment)

    def _code_section_name(self) -> str:
        # A faintly randomized but printable name; never a fixed string.
        suffix = "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(3))
        return f".cs{suffix}"
