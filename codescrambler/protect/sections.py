"""Section selection, at-rest encryption and the writer integration.

``SectionProtector`` registers a post-build hook on the :class:`PEWriter`. At
write time it:

1. picks the non-executable sections that are *safe* to encrypt,
2. encrypts their bytes on disk with a per-section randomized cipher and marks
   them writable so the stub can restore them in place,
3. generates the decryptor stub, appends it as a new code section, and redirects
   the entry point to it (the stub jumps to the real, already-moved OEP).

Safety-first selection (so a protected binary always still runs): a section is
skipped if it overlaps any data directory (imports/IAT/TLS/resources/reloc/
exceptions/etc.) or contains any base-relocation target, because the loader
consumes those bytes before the stub runs. This is conservative by design;
``ARCHITECTURE.md`` describes how to widen coverage with a reloc-aware,
``VirtualProtect``-based stub later.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import pefile

from codescrambler.config import EncryptSections
from codescrambler.core.rng import Rng
from codescrambler.pe import reloc as reloc_mod
from codescrambler.protect.ciphers import build_cipher
from codescrambler.protect.stub import ProtectedSection, StubGenerator

# Section characteristics we set/read.
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000
_SCN_CODE = 0x00000020
_CHARACTERISTICS_OFFSET = 36  # within a 0x28-byte section header

# Section names that are obviously safe "data" for the ``data`` mode.
_DATA_NAMES = {b".data", b".bss", b".xdata\x00\x00"}


class SectionProtector:
    """Encrypts data/other sections and installs a runtime decryptor stub."""

    def __init__(self, mode: EncryptSections, rng: Rng) -> None:
        self.mode = mode
        self.rng = rng
        self.encrypted: List[Tuple[str, int, int, str]] = []  # name, rva, size, cipher

    def attach(self, writer) -> None:
        """Register the protection hook on a :class:`PEWriter`."""

        if self.mode is EncryptSections.NONE:
            return
        writer.add_post_hook(self._hook)

    # -- hook -------------------------------------------------------------
    def _hook(self, writer, pe: "pefile.PE") -> None:
        targets = self._select(pe)
        if not targets:
            return

        protected: List[ProtectedSection] = []
        for section in targets:
            rva = section.VirtualAddress
            size = min(section.Misc_VirtualSize or section.SizeOfRawData, section.SizeOfRawData)
            if size <= 0:
                continue
            cipher = build_cipher(self.rng)
            plain = pe.get_data(rva, size)
            pe.set_bytes_at_rva(rva, cipher.encrypt(plain))
            self._mark_writable(pe, section)
            protected.append(ProtectedSection(rva=rva, size=size, cipher=cipher))
            self.encrypted.append((section.Name.rstrip(b"\x00").decode(errors="replace"),
                                   rva, size, cipher.cipher_id))

        if not protected:
            return

        orig_entry_rva = writer.new_entry_rva
        stub_rva = writer._next_rva  # the RVA add_section will assign next
        stub = StubGenerator().generate(stub_rva, writer.image_base, orig_entry_rva, protected)
        writer.add_section(".csdec", stub.code, _SCN_CODE | _SCN_MEM_EXECUTE | _SCN_MEM_READ)
        writer.new_entry_rva = stub_rva

    # -- selection --------------------------------------------------------
    def _select(self, pe: "pefile.PE") -> List["pefile.SectionStructure"]:
        critical = self._critical_ranges(pe)
        reloc_targets = self._reloc_rvas(pe)

        chosen = []
        for section in pe.sections:
            if section.Characteristics & _SCN_MEM_EXECUTE:
                continue
            if not section.SizeOfRawData:
                continue
            start = section.VirtualAddress
            end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
            if self._overlaps(start, end, critical):
                continue
            if any(start <= rva < end for rva in reloc_targets):
                continue
            if self.mode is EncryptSections.DATA and not self._looks_like_data(section):
                continue
            chosen.append(section)
        return chosen

    @staticmethod
    def _looks_like_data(section) -> bool:
        if section.Name in _DATA_NAMES:
            return True
        return bool(section.Characteristics & _SCN_MEM_WRITE)

    @staticmethod
    def _critical_ranges(pe: "pefile.PE") -> List[Tuple[int, int]]:
        ranges = []
        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if directory.VirtualAddress and directory.Size:
                ranges.append((directory.VirtualAddress, directory.VirtualAddress + directory.Size))
        return ranges

    @staticmethod
    def _reloc_rvas(pe: "pefile.PE") -> set:
        try:
            return {rva for rva, _type in reloc_mod.read_relocations(pe)}
        except Exception:  # pragma: no cover - defensive
            return set()

    @staticmethod
    def _overlaps(start: int, end: int, ranges: List[Tuple[int, int]]) -> bool:
        return any(start < r_end and r_start < end for r_start, r_end in ranges)

    @staticmethod
    def _mark_writable(pe: "pefile.PE", section) -> None:
        section.Characteristics |= _SCN_MEM_WRITE
        offset = section.get_file_offset() + _CHARACTERISTICS_OFFSET
        pe.set_dword_at_offset(offset, section.Characteristics)
