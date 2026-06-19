"""Mixed boolean-arithmetic (MBA) expansion pass.

Rewrites register-to-register arithmetic/bitwise instructions into longer,
equivalent sequences built from MBA identities, for example::

    add dst, src   ==   t = src & dst; dst ^= src; t += t; dst += t
    or  dst, src   ==   (dst ^ src) + (dst & src)
    and dst, src   ==   (dst | src) - (dst ^ src)
    xor dst, src   ==   (dst | src) - (dst & src)
    sub dst, src   ==   dst + (-src)   via the add identity

Two design choices keep this *correct*:

* Every expansion is expressed once as a list of abstract micro-ops. The same
  list is used both to emit assembly and to *simulate* the computation in
  Python, so the emitted code and the checker can never disagree.
* Before an instruction is replaced, the micro-op sequence is verified against
  the original operation over many random inputs (a build-time equivalence
  self-check). If it ever disagrees, the rewrite is abandoned and the original
  instruction is kept.

Because the micro-ops clobber the flags, the pass only fires where flag
liveness analysis proves the flags are dead. Scratch registers are saved and
restored with balanced ``push``/``pop`` pairs, so no register is disturbed.
Deeper recursive nesting is a safe future extension: the self-check would
validate any additional layers automatically.
"""

from __future__ import annotations

import random
from typing import Callable, Dict, List, Optional, Tuple

from codescrambler.core.ir import Arch, Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.analysis import flags_dead_after
from codescrambler.mutation.base import Pass, PassReport, register

MicroOp = Tuple  # ("mov", a, b) | ("add", a, b) | ... | ("neg", a)

# Reference semantics for the instructions we expand: f(dst, src) -> value.
_REFERENCE: Dict[str, Callable[[int, int], int]] = {
    "add": lambda x, y: x + y,
    "sub": lambda x, y: x - y,
    "or": lambda x, y: x | y,
    "and": lambda x, y: x & y,
    "xor": lambda x, y: x ^ y,
}

_PTR_REGS_X64 = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_PTR_REGS_X86 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")


def _expansion(op: str, dst: str, src: str, t: str, u: str) -> List[MicroOp]:
    """Return the micro-op sequence computing ``dst = dst <op> src``."""

    if op == "add":
        return [("mov", t, src), ("and", t, dst), ("xor", dst, src),
                ("add", t, t), ("add", dst, t)]
    if op == "or":
        return [("mov", t, dst), ("xor", t, src), ("mov", u, dst),
                ("and", u, src), ("mov", dst, t), ("add", dst, u)]
    if op == "and":
        return [("mov", t, dst), ("or", t, src), ("mov", u, dst),
                ("xor", u, src), ("mov", dst, t), ("sub", dst, u)]
    if op == "xor":
        return [("mov", t, dst), ("or", t, src), ("mov", u, dst),
                ("and", u, src), ("mov", dst, t), ("sub", dst, u)]
    if op == "sub":
        return [("mov", t, src), ("neg", t), ("mov", u, dst), ("and", u, t),
                ("xor", dst, t), ("add", u, u), ("add", dst, u)]
    raise KeyError(op)


def _simulate(ops: List[MicroOp], regs: Dict[str, int], bits: int) -> None:
    mask = (1 << bits) - 1
    for micro in ops:
        name = micro[0]
        if name == "neg":
            regs[micro[1]] = (-regs[micro[1]]) & mask
            continue
        a, b = micro[1], micro[2]
        if name == "mov":
            regs[a] = regs[b]
        elif name == "add":
            regs[a] = (regs[a] + regs[b]) & mask
        elif name == "sub":
            regs[a] = (regs[a] - regs[b]) & mask
        elif name == "and":
            regs[a] = regs[a] & regs[b]
        elif name == "or":
            regs[a] = regs[a] | regs[b]
        elif name == "xor":
            regs[a] = regs[a] ^ regs[b]
        else:  # pragma: no cover - guarded by construction
            raise ValueError(name)
        regs[a] &= mask


def _emit_asm(micro: MicroOp) -> Instruction:
    if micro[0] == "neg":
        return Instruction.synth(f"neg {micro[1]}")
    return Instruction.synth(f"{micro[0]} {micro[1]}, {micro[2]}")


def _self_check(op: str, ops: List[MicroOp], dst: str, src: str, t: str, u: str,
                bits: int, trials: int = 128) -> bool:
    """Verify the micro-op sequence matches ``op`` over random inputs."""

    mask = (1 << bits) - 1
    reference = _REFERENCE[op]
    checker = random.Random(0xC0DE ^ bits ^ hash((op, dst, src, t, u)) & 0xFFFF)
    names = {dst, src, t, u}
    for _ in range(trials):
        regs = {name: checker.getrandbits(bits) for name in names}
        if src == dst:
            regs[src] = regs[dst]
        expected = reference(regs[dst], regs[src]) & mask
        work = dict(regs)
        _simulate(ops, work, bits)
        if work[dst] != expected:
            return False
    return True


@register
class MBAPass(Pass):
    """Expand reg/reg arithmetic into verified mixed boolean-arithmetic."""

    name = "mba"

    def __init__(self, coverage: float = 0.6) -> None:
        #: Fraction of eligible operations to expand (1.0 == "expand everything").
        self.coverage = coverage

    def apply(self, program: Program, rng: Rng) -> PassReport:
        bits = program.arch.pointer_size * 8
        ptr_regs = _PTR_REGS_X64 if program.arch is Arch.X64 else _PTR_REGS_X86
        expanded = 0
        for section in program.executable_sections():
            rebuilt: List[Instruction] = []
            instructions = section.instructions
            for index, insn in enumerate(instructions):
                replacement = None
                if rng.chance(self.coverage):
                    replacement = self._expand(insn, index, instructions, ptr_regs, bits, rng)
                if replacement is None:
                    rebuilt.append(insn)
                else:
                    replacement[0].label = insn.label
                    rebuilt.extend(replacement)
                    expanded += 1
            section.instructions = rebuilt
        return PassReport(self.name, {"operations_expanded": expanded})

    def _expand(self, insn, index, instructions, ptr_regs, bits, rng) -> Optional[List[Instruction]]:
        if insn.mnemonic not in _REFERENCE or insn.is_branch:
            return None
        dst, src = self._reg_pair(insn.op_str, ptr_regs)
        if dst is None or src is None:
            return None
        if not flags_dead_after(instructions, index):
            return None

        scratch_pool = [r for r in ptr_regs if r not in (dst, src)]
        if len(scratch_pool) < 2:
            return None
        t, u = rng.sample(scratch_pool, 2)

        ops = _expansion(insn.mnemonic, dst, src, t, u)
        if not _self_check(insn.mnemonic, ops, dst, src, t, u, bits):
            return None

        body = [_emit_asm(micro) for micro in ops]
        # Save/restore the scratch registers so nothing leaks out of the block.
        prologue = [Instruction.synth(f"push {t}"), Instruction.synth(f"push {u}")]
        epilogue = [Instruction.synth(f"pop {u}"), Instruction.synth(f"pop {t}")]
        return prologue + body + epilogue

    @staticmethod
    def _reg_pair(op_str: str, ptr_regs) -> Tuple[Optional[str], Optional[str]]:
        parts = [part.strip() for part in op_str.split(",")]
        if len(parts) != 2:
            return None, None
        dst, src = parts
        if dst in ptr_regs and src in ptr_regs:
            return dst, src
        return None, None
