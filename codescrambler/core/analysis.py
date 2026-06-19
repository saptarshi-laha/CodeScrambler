"""Lightweight liveness analysis shared across engines.

No pass ever needs a full dataflow framework; transforms only need two
conservative questions before they clobber something:

* "Are the CPU flags dead here?" - so a pass may emit flag-changing code without
  saving/restoring them.
* "Is this register dead here?" - so a pass may use it as scratch without a
  save/restore.

Both helpers are intentionally *pessimistic*: when in doubt (a label/join point,
a branch, the end of the analyzable window) they report the resource as live.
That can only cause a pass to skip an opportunity, never to emit wrong code.

This lives in :mod:`codescrambler.core` (not in any one engine) so the mutation,
virtualization and hardening engines can all use it without importing one
another.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Arch, Instruction

#: General-purpose registers usable as scratch (the stack pointer is excluded).
_GP_X64 = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_GP_X86 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")

#: Sub-register aliases that mean a GP register is in use (kept small on purpose).
_ALIASES = {
    "rax": {"rax", "eax", "ax", "al", "ah"},
    "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
    "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
    "rdx": {"rdx", "edx", "dx", "dl", "dh"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdi": {"rdi", "edi", "di", "dil"},
    "rbp": {"rbp", "ebp", "bp", "bpl"},
    "eax": {"eax", "ax", "al", "ah"},
    "ebx": {"ebx", "bx", "bl", "bh"},
    "ecx": {"ecx", "cx", "cl", "ch"},
    "edx": {"edx", "dx", "dl", "dh"},
    "esi": {"esi", "si", "sil"},
    "edi": {"edi", "di", "dil"},
    "ebp": {"ebp", "bp", "bpl"},
}


def gp_registers(arch: Arch) -> tuple:
    """Return the scratch-eligible general-purpose registers for ``arch``."""

    return _GP_X64 if arch is Arch.X64 else _GP_X86


def flags_dead_after(instructions: List[Instruction], index: int) -> bool:
    """Conservatively decide whether CPU flags are dead after ``index``."""

    for insn in instructions[index + 1:]:
        if insn.label or insn.is_branch or insn.is_call or insn.is_ret:
            return False  # join/transfer point: assume a consumer may read flags
        if insn.reads_flags:
            return False
        if insn.writes_flags:
            return True  # redefined before any read -> previous flags were dead
    return True  # ran off the end of the block window


def register_dead_after(instructions: List[Instruction], index: int, reg: str) -> bool:
    """Conservatively decide whether ``reg`` is dead after ``index``."""

    names = _ALIASES.get(reg, {reg})
    for insn in instructions[index + 1:]:
        if insn.label or insn.is_branch or insn.is_call or insn.is_ret:
            return False
        if names & set(insn.regs_read):
            return False
        if names & set(insn.regs_written):
            return True
    return False  # unknown at end of window -> assume live to stay safe
