"""The VM instruction set and its reference semantics.

The VM is a simple **register machine** whose virtual registers mirror the
native general-purpose registers: at VM entry the native registers are copied
into a context array, the bytecode operates on that array, and at VM exit the
array is copied back. This mirroring is what makes lifting straightforward -
a native ``add rax, rbx`` becomes a VM ``VADD slot(rax), slot(rbx)``.

Flags are intentionally *not* modeled, so (exactly like the MBA pass) lifting
only happens where flag liveness proves the flags are dead.

The reference semantics in :func:`simulate` are the single source of truth used
to self-check lifted bytecode before it is committed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple


class VMOp(Enum):
    """Logical VM operations (numbered randomly per build, see randomizer)."""

    LDI = "ldi"      # ctx[a] = imm
    MOV = "mov"      # ctx[a] = ctx[b]
    ADD = "add"      # ctx[a] += ctx[b]
    SUB = "sub"      # ctx[a] -= ctx[b]
    XOR = "xor"      # ctx[a] ^= ctx[b]
    AND = "and"      # ctx[a] &= ctx[b]
    OR = "or"        # ctx[a] |= ctx[b]
    ADDI = "addi"    # ctx[a] += imm
    EXIT = "exit"    # leave the VM, resume native execution


#: Number of virtual register slots (mirrors the 16 x64 GP registers).
SLOT_COUNT = 16

#: Operations that carry a 64-bit immediate operand.
IMMEDIATE_OPS = frozenset({VMOp.LDI, VMOp.ADDI})

#: Operations that carry two slot operands.
BINARY_OPS = frozenset({VMOp.MOV, VMOp.ADD, VMOp.SUB, VMOp.XOR, VMOp.AND, VMOp.OR})


@dataclass
class VMInstr:
    """One decoded VM instruction."""

    op: VMOp
    a: int = 0           # destination slot
    b: int = 0           # source slot (binary ops)
    imm: int = 0         # immediate (LDI/ADDI)


@dataclass
class VMProgram:
    """An ordered list of VM instructions."""

    instructions: List[VMInstr] = field(default_factory=list)

    def add(self, op: VMOp, a: int = 0, b: int = 0, imm: int = 0) -> None:
        self.instructions.append(VMInstr(op, a, b, imm))


def simulate(program: VMProgram, context: Dict[int, int], bits: int = 64) -> Dict[int, int]:
    """Execute ``program`` over ``context`` and return the resulting slots.

    This is the authoritative semantics used to validate lifted bytecode.
    """

    mask = (1 << bits) - 1
    ctx = {i: context.get(i, 0) & mask for i in range(SLOT_COUNT)}
    for ins in program.instructions:
        if ins.op is VMOp.EXIT:
            break
        if ins.op is VMOp.LDI:
            ctx[ins.a] = ins.imm & mask
        elif ins.op is VMOp.ADDI:
            ctx[ins.a] = (ctx[ins.a] + ins.imm) & mask
        elif ins.op is VMOp.MOV:
            ctx[ins.a] = ctx[ins.b]
        elif ins.op is VMOp.ADD:
            ctx[ins.a] = (ctx[ins.a] + ctx[ins.b]) & mask
        elif ins.op is VMOp.SUB:
            ctx[ins.a] = (ctx[ins.a] - ctx[ins.b]) & mask
        elif ins.op is VMOp.XOR:
            ctx[ins.a] = ctx[ins.a] ^ ctx[ins.b]
        elif ins.op is VMOp.AND:
            ctx[ins.a] = ctx[ins.a] & ctx[ins.b]
        elif ins.op is VMOp.OR:
            ctx[ins.a] = ctx[ins.a] | ctx[ins.b]
        else:  # pragma: no cover - exhaustive above
            raise ValueError(ins.op)
        ctx[ins.a] &= mask
    return ctx
