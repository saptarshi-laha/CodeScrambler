"""Anti-VM / anti-emulation pass (a preventive transformation).

Detects execution inside a hypervisor/VM using the architectural "hypervisor
present" signal: ``CPUID`` leaf 1 sets bit 31 of ``ECX`` when a hypervisor is
running underneath. Many automated malware sandboxes and emulator-based analyzers
run guests where this bit is set.

The check is self-contained and register/flag-neutral for the surrounding code
(it saves and restores the four registers ``CPUID`` clobbers, plus the flags). If
a hypervisor is detected the configured response runs (default ``ud2`` - an
illegal instruction that crashes the process); otherwise control falls through
unchanged.

Note: legitimate users sometimes run inside VMs, so this is opt-in by nature and
may cause false positives in virtualized production environments - that trade-off
is the caller's to make. It is spliced in right after the entry instruction (see
the same caveat as ``AntiDebugPass`` about terminator entries).
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.pass_base import Pass, PassReport, register
from codescrambler.core.rng import Rng
from codescrambler.core.synth import LabelMaker, synth_branch, synth_labeled

_RESPONSES = ("ud2", "int3", "hlt")


@register
class AntiVMPass(Pass):
    """Insert a CPUID hypervisor-bit check near the entry point."""

    name = "antivm"

    def __init__(self, response: str = "ud2") -> None:
        if response not in _RESPONSES:
            raise ValueError(f"response must be one of {_RESPONSES}")
        self.response = response

    def apply(self, program: Program, rng: Rng) -> PassReport:
        entry_va = program.entry_va
        for section in program.executable_sections():
            for index, insn in enumerate(section.instructions):
                if insn.address != entry_va:
                    continue
                if insn.is_terminator:
                    return PassReport(self.name, {"inserted": 0, "reason": "entry_is_terminator"})
                section.instructions[index + 1:index + 1] = self._build(program.arch)
                return PassReport(self.name, {"inserted": 1, "response": self.response})
        return PassReport(self.name, {"inserted": 0, "reason": "entry_not_found"})

    def _build(self, arch: Arch) -> List[Instruction]:
        ok = LabelMaker.fresh("novm")
        if arch is Arch.X64:
            saves = ["push rax", "push rbx", "push rcx", "push rdx"]
            restores = ["pop rdx", "pop rcx", "pop rbx", "pop rax"]
            pushf, popf = "pushfq", "popfq"
        else:
            saves = ["push eax", "push ebx", "push ecx", "push edx"]
            restores = ["pop edx", "pop ecx", "pop ebx", "pop eax"]
            pushf, popf = "pushfd", "popfd"

        block: List[Instruction] = [Instruction.synth(text) for text in saves]
        block += [
            Instruction.synth(pushf),
            Instruction.synth("mov eax, 1"),
            Instruction.synth("cpuid"),
            Instruction.synth("bt ecx, 31"),     # hypervisor-present bit -> CF
            synth_branch("jnc", ok),
            Instruction.synth(self.response),     # only reached inside a VM
            synth_labeled(popf, ok),
        ]
        block += [Instruction.synth(text) for text in restores]
        return block
