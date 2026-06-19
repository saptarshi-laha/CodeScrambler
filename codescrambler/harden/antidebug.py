"""Anti-debugging pass (a preventive transformation).

Inserts one or more import-free debugger checks near the entry point. Each check
reads a field of the Process Environment Block (PEB) directly (x64 via
``gs:[0x60]``, x86 via ``fs:[0x30]``):

* ``being_debugged`` - the ``BeingDebugged`` byte at ``PEB+2`` (set when a
  debugger is attached).
* ``nt_global_flag`` - the ``NtGlobalFlag`` dword (``PEB+0xBC`` on x64,
  ``PEB+0x68`` on x86). A debugger-created process has the heap-debug bits
  ``0x70`` set there even after ``BeingDebugged`` is cleared by anti-anti-debug
  tricks, so it is a useful second signal.

Every check is self-contained and register/flag-neutral for the surrounding code
(it saves and restores the register it uses and the flags). If a debugger is
detected the configured response runs (default ``ud2`` - an illegal instruction
that crashes the process); otherwise control falls through unchanged. Multiple
checks simply concatenate.

Checks are inserted immediately after the entry instruction (so they run at the
very start). For guaranteed-first execution under all entry shapes, use the
documented entry-stub hook approach (see ARCHITECTURE).
"""

from __future__ import annotations

from typing import List, Sequence

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.pass_base import Pass, PassReport, register
from codescrambler.core.rng import Rng
from codescrambler.core.synth import LabelMaker, synth_branch, synth_labeled

_RESPONSES = ("ud2", "int3", "hlt")
_TECHNIQUES = ("being_debugged", "nt_global_flag")


@register
class AntiDebugPass(Pass):
    """Insert PEB-based debugger checks near the entry point."""

    name = "antidebug"

    def __init__(self, response: str = "ud2",
                 techniques: Sequence[str] = ("being_debugged",)) -> None:
        if response not in _RESPONSES:
            raise ValueError(f"response must be one of {_RESPONSES}")
        unknown = [t for t in techniques if t not in _TECHNIQUES]
        if unknown:
            raise ValueError(f"unknown techniques: {unknown}")
        self.response = response
        self.techniques = tuple(techniques)

    def apply(self, program: Program, rng: Rng) -> PassReport:
        entry_va = program.entry_va
        for section in program.executable_sections():
            for index, insn in enumerate(section.instructions):
                if insn.address != entry_va:
                    continue
                if insn.is_terminator:
                    return PassReport(self.name, {"inserted": 0, "reason": "entry_is_terminator"})
                checks: List[Instruction] = []
                for technique in self.techniques:
                    checks.extend(self._build(program.arch, technique))
                section.instructions[index + 1:index + 1] = checks
                return PassReport(self.name, {
                    "inserted": len(self.techniques), "techniques": list(self.techniques),
                })
        return PassReport(self.name, {"inserted": 0, "reason": "entry_not_found"})

    # -- per-technique check builders -------------------------------------
    def _build(self, arch: Arch, technique: str) -> List[Instruction]:
        if technique == "being_debugged":
            return self._being_debugged(arch)
        return self._nt_global_flag(arch)

    def _peb_regs(self, arch: Arch):
        if arch is Arch.X64:
            return "rax", "eax", "gs:[0x60]", "push rax", "pop rax", "pushfq", "popfq"
        return "eax", "eax", "fs:[0x30]", "push eax", "pop eax", "pushfd", "popfd"

    def _being_debugged(self, arch: Arch) -> List[Instruction]:
        reg, wide, seg, push, pop, pushf, popf = self._peb_regs(arch)
        ok = LabelMaker.fresh("nodbg")
        return [
            Instruction.synth(push),
            Instruction.synth(pushf),
            Instruction.synth(f"mov {reg}, {seg}"),
            Instruction.synth(f"movzx {wide}, byte ptr [{reg} + 2]"),
            Instruction.synth("test al, al"),
            synth_branch("jz", ok),
            Instruction.synth(self.response),       # only reached if debugged
            synth_labeled(popf, ok),
            Instruction.synth(pop),
        ]

    def _nt_global_flag(self, arch: Arch) -> List[Instruction]:
        reg, wide, seg, push, pop, pushf, popf = self._peb_regs(arch)
        offset = "0xBC" if arch is Arch.X64 else "0x68"
        ok = LabelMaker.fresh("nodbg")
        return [
            Instruction.synth(push),
            Instruction.synth(pushf),
            Instruction.synth(f"mov {reg}, {seg}"),
            Instruction.synth(f"mov {wide}, dword ptr [{reg} + {offset}]"),
            Instruction.synth("and eax, 0x70"),     # heap-debug bits set under a debugger
            synth_branch("jz", ok),
            Instruction.synth(self.response),       # only reached if debugged
            synth_labeled(popf, ok),
            Instruction.synth(pop),
        ]
