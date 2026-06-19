"""Base relocation handling.

When we move code into a new section, any absolute address embedded in that code
(common on x86, rarer on x64) must also be relocatable, otherwise the binary
breaks under ASLR. We solve this by:

1. reading every existing relocation entry,
2. for each entry whose target lands inside a moved instruction, emitting an
   equivalent entry that points at the *new* location, and
3. regenerating the whole ``.reloc`` table into a fresh section.

The original entries are kept as well; they harmlessly patch the now-dead
original code copy, while the new entries keep the live, moved copy correct.
"""

from __future__ import annotations

import struct
from typing import Callable, List, Optional, Tuple

import pefile

#: A relocation as ``(rva, type)`` where ``type`` is an IMAGE_REL_BASED_* value.
Relocation = Tuple[int, int]


def read_relocations(pe: "pefile.PE") -> List[Relocation]:
    """Return all base relocations as ``(rva, type)`` pairs."""

    out: List[Relocation] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return out
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            # Padding entries use type 0 (ABSOLUTE); skip them.
            if entry.type == 0:
                continue
            out.append((entry.rva, entry.type))
    return out


def map_relocations(
    relocations: List[Relocation],
    remap_rva: Callable[[int], Optional[int]],
) -> List[Relocation]:
    """Produce new relocations for entries whose target moved.

    ``remap_rva`` returns the new RVA for an old RVA, or ``None`` if that RVA was
    not moved (in which case the original entry already covers it).
    """

    extra: List[Relocation] = []
    for rva, rtype in relocations:
        new_rva = remap_rva(rva)
        if new_rva is not None and new_rva != rva:
            extra.append((new_rva, rtype))
    return extra


def build_reloc_blocks(relocations: List[Relocation]) -> bytes:
    """Serialize relocations into the ``.reloc`` block format.

    Entries are grouped per 4 KiB page; each block is
    ``[page_rva(4)][block_size(4)][entry(2) ...]`` where an entry is
    ``(type << 12) | offset_in_page``. Blocks are padded to a 4-byte boundary.
    """

    pages: dict = {}
    for rva, rtype in sorted(set(relocations)):
        page = rva & ~0xFFF
        pages.setdefault(page, []).append((rtype << 12) | (rva & 0xFFF))

    out = bytearray()
    for page in sorted(pages):
        entries = pages[page]
        if len(entries) % 2 == 1:
            entries.append(0)  # pad to keep block size 4-byte aligned
        block_size = 8 + len(entries) * 2
        out += struct.pack("<II", page, block_size)
        for entry in entries:
            out += struct.pack("<H", entry)
    return bytes(out)
