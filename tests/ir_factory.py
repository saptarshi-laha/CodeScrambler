"""Build an in-memory :class:`Program` from assembly text — no PE files.

Used by the test suite to exercise passes/lifters/assembler without ever
touching disk or producing a PE (which keeps AV heuristics out of the picture).
"""

from __future__ import annotations

import keystone

from codescrambler.core.disasm import get_backend
from codescrambler.core.disasm.base import label_branches
from codescrambler.core.ir import Arch, Program, Section

_KS_MODE = {Arch.X86: keystone.KS_MODE_32, Arch.X64: keystone.KS_MODE_64}


def assemble(text: str, arch: Arch = Arch.X64, base: int = 0x1000) -> bytes:
    ks = keystone.Ks(keystone.KS_ARCH_X86, _KS_MODE[arch])
    encoding, _ = ks.asm(text, base)
    return bytes(encoding)


def make_program(text: str, arch: Arch = Arch.X64, base_rva: int = 0x1000) -> Program:
    image_base = 0x140000000 if arch is Arch.X64 else 0x400000
    base_va = image_base + base_rva
    code = assemble(text, arch, base_va)
    insns = get_backend().decode(code, base_va, arch)
    section = Section(".text", base_rva, len(code), code, 0x60000020, True, insns)
    program = Program(arch, image_base, base_rva, [section])
    label_branches(program.sections, image_base)
    return program
