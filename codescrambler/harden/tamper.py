"""Tamperproofing building blocks: a self-checksum guard.

A guard hashes a range of its own code at runtime and compares the result to a
value computed at build time; if the bytes were patched (a cracker's NOP, an
inline hook), the hash differs and the configured response fires. This is the
checksum-guard family from Collberg & Nagra / Chang-Atallah / Horne et al.

What is implemented and verifiable here:

* :func:`checksum` - the exact 32-bit FNV-1a used at build time, with a self
  test, so the build-time value always matches what the asm computes.
* :class:`GuardGenerator` - emits and assembles a position-independent guard
  (``call/pop`` anchor, hash loop, compare, response).

What is intentionally **gated** (documented, not wired): inserting guards and
patching their expected value at write time. The subtlety is byte-stability -
the checksummed range must exclude the guard's own expected-value immediate, and
ideally guards should overlap/cross-check. The writer-integration contract is in
ARCHITECTURE.md (alongside the VM-commit contract). Until then, treat this as a
correct primitive + code generator you wire on-target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import keystone

from codescrambler.core.ir import Arch

_FNV_OFFSET = 0x811C9DC5
_FNV_PRIME = 0x01000193
_MASK32 = 0xFFFFFFFF


def checksum(data: bytes) -> int:
    """32-bit FNV-1a over ``data`` (matches the generated guard exactly)."""

    h = _FNV_OFFSET
    for byte in data:
        h = ((h ^ byte) * _FNV_PRIME) & _MASK32
    return h


def checksum_self_test() -> bool:
    return checksum(b"") == _FNV_OFFSET and checksum(b"a") == ((_FNV_OFFSET ^ 0x61) * _FNV_PRIME) & _MASK32


@dataclass
class GeneratedGuard:
    code: bytes
    listing: str
    anchor_rva: int


class GuardGenerator:
    """Builds and assembles a self-checksum guard (x64)."""

    _PROLOGUE = ["push rax", "push rcx", "push rdx", "push r8", "pushfq"]
    _CALL_SIZE = 5

    def __init__(self, response: str = "ud2") -> None:
        if response not in ("ud2", "int3", "hlt"):
            raise ValueError("response must be ud2/int3/hlt")
        self.response = response
        self._ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        self._ks.syntax = keystone.KS_OPT_SYNTAX_INTEL

    def generate(self, guard_rva: int, image_base: int, range_rva: int,
                 range_size: int, expected: int) -> GeneratedGuard:
        prologue_bytes, _ = self._ks.asm("\n".join(self._PROLOGUE), image_base + guard_rva)
        anchor_rva = guard_rva + len(bytes(prologue_bytes)) + self._CALL_SIZE
        listing = self._listing(anchor_rva, range_rva, range_size, expected)
        encoding, _ = self._ks.asm(listing, image_base + guard_rva)
        return GeneratedGuard(code=bytes(encoding), listing=listing, anchor_rva=anchor_rva)

    def _listing(self, anchor_rva: int, range_rva: int, range_size: int, expected: int) -> str:
        start_delta = range_rva - anchor_rva
        sign = "+" if start_delta >= 0 else "-"
        lines: List[str] = list(self._PROLOGUE)
        lines += [
            "    call next",
            "next:",
            "    pop rax",                              # rax = runtime &next
            f"    lea rcx, [rax {sign} {abs(start_delta):#x}]",  # rcx = &range
            f"    mov rdx, {range_size}",              # counter
            f"    mov r8d, {_FNV_OFFSET}",             # hash accumulator
            "hashloop:",
            "    movzx eax, byte ptr [rcx]",
            "    xor r8d, eax",
            f"    imul r8d, r8d, {_FNV_PRIME}",
            "    inc rcx",
            "    dec rdx",
            "    jnz hashloop",
            f"    cmp r8d, {expected & _MASK32}",
            "    je guard_ok",
            f"    {self.response}",                     # tamper detected
            "guard_ok:",
            "    popfq",
            "    pop r8",
            "    pop rdx",
            "    pop rcx",
            "    pop rax",
            "    ret",
        ]
        return "\n".join(lines)
