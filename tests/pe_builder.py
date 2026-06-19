"""Minimal PE32/PE32+ builder used to create test fixtures.

We cannot rely on real Windows binaries being present on the build host, so the
test-suite synthesizes small but structurally valid PE files here. The builder
deliberately produces *loadable-shaped* images (correct headers, alignment,
section table and data directories) so the loader, writer and fidelity code can
be exercised end to end.

It is intentionally small and readable rather than a general PE assembler.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

import keystone

_FILE_ALIGN = 0x200
_SECT_ALIGN = 0x1000

# Characteristics helpers.
SCN_CODE = 0x00000020
SCN_INIT_DATA = 0x00000040
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

CODE_FLAGS = SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
DATA_FLAGS = SCN_INIT_DATA | SCN_MEM_READ | SCN_MEM_WRITE


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class SectionSpec:
    name: str
    data: bytes
    characteristics: int


@dataclass
class PESpec:
    """Description of a PE to build."""

    arch64: bool = True
    image_base: Optional[int] = None  # defaults to an arch-appropriate base
    entry_asm: str = "xor eax, eax; ret"
    extra_sections: List[SectionSpec] = field(default_factory=list)
    subsystem: int = 3  # console

    def __post_init__(self) -> None:
        if self.image_base is None:
            self.image_base = 0x140000000 if self.arch64 else 0x400000

    def assemble_entry(self) -> bytes:
        mode = keystone.KS_MODE_64 if self.arch64 else keystone.KS_MODE_32
        ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
        encoding, _ = ks.asm(self.entry_asm, self.image_base + _SECT_ALIGN)
        return bytes(encoding)


class _Section:
    def __init__(self, name: str, data: bytes, characteristics: int, rva: int, file_off: int):
        self.name = name
        self.data = data
        self.characteristics = characteristics
        self.rva = rva
        self.file_off = file_off
        self.virtual_size = len(data)
        self.raw_size = _align(len(data), _FILE_ALIGN)


def build_pe(path: str, spec: Optional[PESpec] = None) -> str:
    """Build a PE described by ``spec`` and write it to ``path``."""

    spec = spec or PESpec()
    code = spec.assemble_entry()

    sections_input = [SectionSpec(".text", code, CODE_FLAGS)] + list(spec.extra_sections)

    num_sections = len(sections_input)
    opt_size = 0xF0 if spec.arch64 else 0xE0
    headers_size = _align(0x40 + 0xF8 + opt_size + num_sections * 0x28, _FILE_ALIGN)

    sections: List[_Section] = []
    rva_cursor = _SECT_ALIGN
    file_cursor = headers_size
    for spec_section in sections_input:
        section = _Section(
            spec_section.name, spec_section.data, spec_section.characteristics,
            rva_cursor, file_cursor,
        )
        sections.append(section)
        rva_cursor = _align(rva_cursor + section.virtual_size, _SECT_ALIGN)
        file_cursor += section.raw_size

    size_of_image = rva_cursor
    image = bytearray(_build_headers(spec, sections, headers_size, size_of_image, len(code)))

    for section in sections:
        image[section.file_off:section.file_off + len(section.data)] = section.data

    with open(path, "wb") as handle:
        handle.write(image)
    return path


def _build_optional_header(spec, sections, headers_size, size_of_image, size_of_code) -> bytes:
    """Assemble the optional header by concatenation, then size-check it."""

    entry_rva = sections[0].rva
    base_of_code = sections[0].rva

    if spec.arch64:
        standard = struct.pack(
            "<HBBIIIII", 0x20B, 14, 0, size_of_code, 0, 0, entry_rva, base_of_code
        )
        windows = struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII",
            spec.image_base, _SECT_ALIGN, _FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, headers_size, 0, spec.subsystem, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        opt_size = 0xF0
    else:
        standard = struct.pack(
            "<HBBIIIIIII", 0x10B, 14, 0, size_of_code, 0, 0, entry_rva, base_of_code, 0,
            spec.image_base,
        )
        windows = struct.pack(
            "<IIHHHHHHIIIIHHIIIIII",
            _SECT_ALIGN, _FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, headers_size, 0, spec.subsystem, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        opt_size = 0xE0

    directories = b"\x00" * (16 * 8)  # no data directories in the base image
    optional = standard + windows + directories
    assert len(optional) == opt_size, (len(optional), opt_size)
    return optional


def _build_headers(spec, sections, headers_size, size_of_image, size_of_code) -> bytes:
    pe_off = 0x40
    dos = bytearray(pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)

    machine = 0x8664 if spec.arch64 else 0x14C
    characteristics = 0x0002 | (0x0000 if spec.arch64 else 0x0100)  # EXECUTABLE [+32BIT]
    optional = _build_optional_header(spec, sections, headers_size, size_of_image, size_of_code)

    file_header = b"PE\x00\x00" + struct.pack(
        "<HHIIIHH", machine, len(sections), 0, 0, 0, len(optional), characteristics
    )

    section_table = bytearray()
    for section in sections:
        name = section.name.encode()[:8].ljust(8, b"\x00")
        section_table += name + struct.pack(
            "<IIII", section.virtual_size, section.rva, section.raw_size, section.file_off
        )
        section_table += struct.pack("<IIHHI", 0, 0, 0, 0, section.characteristics)

    buf = bytearray(headers_size)
    blob = bytes(dos) + file_header + optional + bytes(section_table)
    buf[0:len(blob)] = blob
    return bytes(buf)
