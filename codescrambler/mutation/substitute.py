"""Instruction-substitution pass.

Replaces individual instructions with equivalent sequences chosen at random.
Only *provably* semantics-preserving rewrites are emitted. The headline rewrite
is register-to-register ``mov``:

    mov rA, rB   ->   lea rA, [rB]          (flag-neutral, no stack use)
    mov rA, rB   ->   push rB ; pop rA       (flag-neutral, balanced stack)

Both alternatives leave the flags untouched, so no liveness analysis is needed.
More aggressive arithmetic rewrites live in the MBA pass, which does consult
flag liveness.
"""

from __future__ import annotations

from typing import List, Optional

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import Pass, PassReport, register

# Pointer-width registers, which are the only ones x86/x64 ``push``/``pop`` accept.
_PTR_REGS_X64 = frozenset(
    {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    }
)
_PTR_REGS_X86 = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"})

# Registers we treat as simple, stack-pointer-free GP operands for ``lea``.
_SIMPLE_REGS = _PTR_REGS_X64 | _PTR_REGS_X86 | frozenset(
    {"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}
)


@register
class SubstitutePass(Pass):
    """Swap instructions for equivalent forms where it is provably safe."""

    name = "substitute"

    def __init__(self, density: float = 0.5) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        replaced = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            for insn in section.instructions:
                replacement = None
                if rng.chance(self.density):
                    replacement = self._substitute(insn, rng, program.arch)
                if replacement is None:
                    rebuilt.append(insn)
                else:
                    # Preserve any label/branch metadata on the first emitted insn.
                    replacement[0].label = insn.label
                    rebuilt.extend(replacement)
                    replaced += 1
            section.instructions = rebuilt
        return PassReport(self.name, {"instructions_substituted": replaced})

    def _substitute(self, insn: Instruction, rng: Rng, arch: Arch) -> Optional[List[Instruction]]:
        if insn.mnemonic != "mov" or insn.is_branch:
            return None
        dst, src = self._reg_pair(insn.op_str)
        if dst is None or src is None:
            return None

        ptr_regs = _PTR_REGS_X64 if arch is Arch.X64 else _PTR_REGS_X86
        push_pop_ok = dst in ptr_regs and src in ptr_regs
        if push_pop_ok and rng.chance(0.5):
            return [Instruction.synth(f"push {src}"), Instruction.synth(f"pop {dst}")]
        return [Instruction.synth(f"lea {dst}, [{src}]")]

    @staticmethod
    def _reg_pair(op_str: str):
        parts = [part.strip() for part in op_str.split(",")]
        if len(parts) != 2:
            return None, None
        dst, src = parts
        if dst in _SIMPLE_REGS and src in _SIMPLE_REGS:
            return dst, src
        return None, None
