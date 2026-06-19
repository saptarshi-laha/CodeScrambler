"""Branch functions / indirect dispatch.

Replaces a *direct unconditional* ``jmp target`` with an equivalent sequence that
computes the destination and transfers through the stack, so the explicit
control-flow edge disappears from the disassembly (no ``jmp target`` for a tool
to follow).

* x86: ``push {target}; ret`` - pushes the absolute 32-bit target and returns to
  it. ``push imm`` and ``ret`` touch neither flags nor general registers.
* x64: a 64-bit absolute address does not fit ``push imm32``, so we use a
  register/flag-neutral stack swap::

      push rax                  ; save rax
      mov  rax, {target}        ; movabs absolute target
      xchg rax, [rsp]           ; target -> [rsp], rax restored
      ret                       ; pop target into rip

  ``push``/``mov``/``xchg``/``ret`` do not affect flags, and rax is restored, so
  this is correct regardless of register liveness at the target.

The absolute address of ``target`` is filled in by the assembler via the
``{label}`` reference mechanism, so it is always the final, correct VA. Only
direct unconditional jumps are transformed; conditional branches and calls are
left untouched.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import Pass, PassReport, register


@register
class BranchFunctionPass(Pass):
    """Turn direct unconditional jumps into stack-based indirect transfers."""

    name = "branchfunc"

    def __init__(self, density: float = 0.5) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        rewritten = 0
        for section in program.executable_sections():
            out: List[Instruction] = []
            for insn in section.instructions:
                if self._is_target(insn) and rng.chance(self.density):
                    out.extend(self._rewrite(insn, program.arch))
                    rewritten += 1
                else:
                    out.append(insn)
            section.instructions = out
        return PassReport(self.name, {"branches_rewritten": rewritten})

    def _is_target(self, insn: Instruction) -> bool:
        return (
            insn.is_branch
            and not insn.is_cond_branch
            and not insn.is_call
            and insn.branch_label is not None
        )

    def _rewrite(self, insn: Instruction, arch: Arch) -> List[Instruction]:
        label = insn.branch_label
        if arch is Arch.X86:
            return [
                Instruction.synth_ref(f"push {{{label}}}", (label,), label=insn.label),
                Instruction.synth("ret"),
            ]
        return [
            Instruction.synth("push rax", label=insn.label),
            Instruction.synth_ref(f"mov rax, {{{label}}}", (label,)),
            Instruction.synth("xchg rax, qword ptr [rsp]"),
            Instruction.synth("ret"),
        ]
