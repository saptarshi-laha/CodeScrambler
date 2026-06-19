"""Per-build randomization of the VM.

A :class:`VMProfile` captures everything that makes one build's VM different
from another's:

* ``opcode_map`` - a fresh, random byte value for each :class:`~codescrambler.vm.isa.VMOp`.
* ``key`` - the rolling key used to encrypt the bytecode stream.
* ``handler_order`` - the order handlers are laid out in the interpreter.
* ``reg_slots`` - which context slot each native register maps to.

Everything is derived from a single :class:`~codescrambler.core.rng.Rng`, so a
seed reproduces a build exactly while an absent seed yields a different VM each
time. Nothing here is fixed/static across builds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from codescrambler.core.ir import Arch
from codescrambler.core.rng import Rng
from codescrambler.vm.isa import VMOp

_GP_X64 = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_GP_X86 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


@dataclass
class VMProfile:
    """The randomized, per-build description of a VM instance."""

    opcode_map: Dict[VMOp, int]
    key: int
    handler_order: List[VMOp]
    reg_slots: Dict[str, int]
    arch: Arch

    @property
    def inverse_opcodes(self) -> Dict[int, VMOp]:
        return {byte: op for op, byte in self.opcode_map.items()}

    @classmethod
    def generate(cls, rng: Rng, arch: Arch) -> "VMProfile":
        ops = list(VMOp)
        # Unique random opcode byte per operation.
        byte_values = rng.sample(range(1, 256), len(ops))
        opcode_map = {op: byte for op, byte in zip(ops, byte_values)}

        handler_order = rng.shuffled(ops)
        key = rng.bits(8) or 0x5A  # non-zero rolling key seed

        registers = _GP_X64 if arch is Arch.X64 else _GP_X86
        slots = list(range(len(registers)))
        rng.shuffle(slots)
        reg_slots = {reg: slot for reg, slot in zip(registers, slots)}

        return cls(opcode_map, key, handler_order, reg_slots, arch)
