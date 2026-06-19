"""Native -> VM translation for the supported instruction subset.

The lifter handles straight-line runs of register arithmetic and constant
loads, which is the subset whose VM semantics we can model exactly:

    mov  dst, src   -> MOV  slot(dst), slot(src)
    mov  dst, imm   -> LDI  slot(dst), imm
    add/sub/xor/and/or dst, src -> ADD/SUB/... slot(dst), slot(src)

Every lifted run is validated by simulating the produced VM program against a
Python reference of the same native run over many random register states (the
build-time equivalence self-check). A run is only virtualized if it passes.

Because flags are not modeled, a run is only liftable when the flags are dead
after its final instruction (checked by the caller).
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

from codescrambler.core.ir import Instruction
from codescrambler.vm.isa import VMOp, VMProgram, simulate
from codescrambler.vm.randomizer import VMProfile

# Native mnemonic -> binary VM op.
_BINARY = {
    "add": VMOp.ADD,
    "sub": VMOp.SUB,
    "xor": VMOp.XOR,
    "and": VMOp.AND,
    "or": VMOp.OR,
    "mov": VMOp.MOV,
}
_IMM_PREFIXES = ("0x", "-0x")

# The stack pointer is never virtualized: the interpreter deliberately does not
# capture or restore it (the live stack must stay intact), so any slot mapped to
# it would hold garbage.
_FORBIDDEN_REGS = frozenset({"rsp", "esp"})


def _operands(insn: Instruction):
    return [part.strip() for part in insn.op_str.split(",")]


def is_liftable(insn: Instruction, reg_slots: Dict[str, int]) -> bool:
    """True if ``insn`` is a register-only op the lifter models exactly."""

    if insn.is_branch or insn.is_call or insn.is_ret or insn.synthetic:
        return False
    if insn.mnemonic not in _BINARY:
        return False
    ops = _operands(insn)
    if len(ops) != 2:
        return False
    dst, src = ops
    if dst not in reg_slots or dst in _FORBIDDEN_REGS:
        return False
    if src in _FORBIDDEN_REGS:
        return False
    if src in reg_slots:
        return True
    # mov dst, imm is allowed; other ops require a register source.
    return insn.mnemonic == "mov" and _is_immediate(src)


def _is_immediate(token: str) -> bool:
    try:
        int(token, 0)
        return True
    except ValueError:
        return False


def lift_run(run: List[Instruction], profile: VMProfile, bits: int = 64) -> Optional[VMProgram]:
    """Lift a run of liftable instructions into a verified VM program."""

    program = VMProgram()
    for insn in run:
        dst, src = _operands(insn)
        op = _BINARY[insn.mnemonic]
        if op is VMOp.MOV and _is_immediate(src):
            program.add(VMOp.LDI, a=profile.reg_slots[dst], imm=int(src, 0))
        elif src in profile.reg_slots:
            program.add(op, a=profile.reg_slots[dst], b=profile.reg_slots[src])
        else:
            return None
    program.add(VMOp.EXIT)

    if not _self_check(run, program, profile, bits):
        return None
    return program


def _reference(run: List[Instruction], regs: Dict[str, int], bits: int) -> Dict[str, int]:
    mask = (1 << bits) - 1
    state = dict(regs)
    for insn in run:
        dst, src = _operands(insn)
        m = insn.mnemonic
        if m == "mov":
            state[dst] = (int(src, 0) & mask) if _is_immediate(src) else state[src]
        elif m == "add":
            state[dst] = (state[dst] + state[src]) & mask
        elif m == "sub":
            state[dst] = (state[dst] - state[src]) & mask
        elif m == "xor":
            state[dst] = state[dst] ^ state[src]
        elif m == "and":
            state[dst] = state[dst] & state[src]
        elif m == "or":
            state[dst] = state[dst] | state[src]
        state[dst] &= mask
    return state


def _self_check(run, program, profile, bits, trials: int = 64) -> bool:
    checker = random.Random(0x5106 ^ bits ^ (profile.key << 3))
    slot_of = profile.reg_slots
    regs = sorted({tok for insn in run for tok in _operands(insn) if tok in slot_of})
    for _ in range(trials):
        values = {reg: checker.getrandbits(bits) for reg in regs}
        expected = _reference(run, values, bits)
        ctx = {slot_of[reg]: values[reg] for reg in regs}
        result = simulate(program, ctx, bits)
        for reg in regs:
            if result[slot_of[reg]] != expected[reg]:
                return False
    return True
