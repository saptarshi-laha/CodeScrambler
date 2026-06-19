"""Runtime decryptor stub generator (x64, position-independent).

The stub becomes the program's entry point. At runtime it:

1. saves the flags and the registers it uses,
2. locates its own address with a ``call/pop`` (so it works under ASLR without
   relocations) and derives a runtime anchor,
3. decrypts each protected section in place using the section's cipher,
4. restores the saved state and jumps to the original entry point.

All addressing is relative to the anchor obtained at runtime, so the stub needs
no relocations of its own. The only assumption is that the original entry does
not rely on a specific initial value of ``rax`` (true for standard CRT entry
points); this is documented in ``ARCHITECTURE.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import keystone

from codescrambler.protect.ciphers import Cipher

# Registers pushed (and restored) by the stub, in push order.
_PROLOGUE = [
    "pushfq",
    "push rax",
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
]
_CALL_SIZE = 5  # e8 + rel32


@dataclass
class ProtectedSection:
    """A section the stub must decrypt at runtime."""

    rva: int
    size: int
    cipher: Cipher


@dataclass
class GeneratedStub:
    code: bytes
    listing: str


class StubGenerator:
    """Builds and assembles the decryptor bootstrap."""

    def __init__(self) -> None:
        self._ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        self._ks.syntax = keystone.KS_OPT_SYNTAX_INTEL

    def generate(self, stub_rva: int, image_base: int, orig_entry_rva: int,
                 sections: List[ProtectedSection]) -> GeneratedStub:
        # Determine the RVA of the ``next:`` anchor (right after the call).
        prologue_bytes, _ = self._ks.asm("\n".join(_PROLOGUE), image_base + stub_rva)
        anchor_rva = stub_rva + len(bytes(prologue_bytes)) + _CALL_SIZE

        listing = self._listing(anchor_rva, orig_entry_rva, sections)
        encoding, _ = self._ks.asm(listing, image_base + stub_rva)
        return GeneratedStub(code=bytes(encoding), listing=listing)

    def _listing(self, anchor_rva: int, orig_entry_rva: int,
                 sections: List[ProtectedSection]) -> str:
        lines: List[str] = list(_PROLOGUE)
        lines += ["    call next", "next:", "    pop rax"]  # rax = runtime &next

        for section in sections:
            delta = section.rva - anchor_rva
            lines.append(f"    lea rsi, [rax {_signed(delta)}]")
            lines.append(f"    mov rbx, {section.size}")
            lines += section.cipher.decrypt_asm("rsi", "rbx", "rcx", "rdx")

        oep_delta = orig_entry_rva - anchor_rva
        lines.append(f"    lea rax, [rax {_signed(oep_delta)}]")  # rax = OEP
        lines += [
            "    pop rsi",
            "    pop rdx",
            "    pop rcx",
            "    pop rbx",
            "    add rsp, 8",   # discard saved rax (keeping OEP in rax)
            "    popfq",
            "    jmp rax",
        ]
        return "\n".join(lines)


def _signed(value: int) -> str:
    return f"+ {value:#x}" if value >= 0 else f"- {abs(value):#x}"
