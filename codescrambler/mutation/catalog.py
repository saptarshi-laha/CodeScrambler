"""Generative catalogs of semantics-preserving code.

Everything here produces *fresh* instruction sequences from templates rather
than returning entries from a fixed list, so repeated builds never emit the same
junk twice. Two safety invariants hold for every sequence produced here:

* it preserves all general-purpose registers (any scratch is balanced), and
* it preserves the CPU flags.

That makes the output safe to splice in anywhere, without liveness analysis.
"""

from __future__ import annotations

from typing import List

from codescrambler.core.ir import Arch, Instruction
from codescrambler.core.rng import Rng
from codescrambler.mutation.analysis import gp_registers


def pushf(arch: Arch) -> str:
    return "pushfq" if arch is Arch.X64 else "pushfd"


def popf(arch: Arch) -> str:
    return "popfq" if arch is Arch.X64 else "popfd"


def stack_pointer(arch: Arch) -> str:
    return "rsp" if arch is Arch.X64 else "esp"


class JunkFactory:
    """Builds register- and flag-preserving junk instruction sequences."""

    def __init__(self, arch: Arch) -> None:
        self.arch = arch
        self.registers = gp_registers(arch)

    def sequence(self, rng: Rng, max_len: int = 3) -> List[Instruction]:
        """Return a short, randomized, semantics-preserving junk sequence."""

        count = rng.randint(1, max(1, max_len))
        out: List[Instruction] = []
        for _ in range(count):
            out.extend(self._one(rng))
        return out

    def _one(self, rng: Rng) -> List[Instruction]:
        reg = rng.choice(self.registers)
        kind = rng.choice(
            ("nop", "push_pop", "lea_self", "mov_self", "xchg_self", "lea_pair")
        )
        if kind == "nop":
            return [Instruction.synth("nop")]
        if kind == "push_pop":
            return [Instruction.synth(f"push {reg}"), Instruction.synth(f"pop {reg}")]
        if kind == "lea_self":
            return [Instruction.synth(f"lea {reg}, [{reg}]")]
        if kind == "mov_self":
            return [Instruction.synth(f"mov {reg}, {reg}")]
        if kind == "xchg_self":
            return [Instruction.synth(f"xchg {reg}, {reg}")]
        # lea_pair: nudge a register up then back down by the same constant.
        delta = rng.randint(1, 0x7F)
        return [
            Instruction.synth(f"lea {reg}, [{reg} + {delta}]"),
            Instruction.synth(f"lea {reg}, [{reg} - {delta}]"),
        ]


class PredicateFactory:
    """Builds opaque predicates whose outcome is known at build time.

    The predicates lean on invariants that always hold (e.g. the stack pointer
    is never zero), and are wrapped so they neither clobber a register nor leave
    the flags disturbed for the surrounding code (the caller saves/restores
    flags around the whole construct).
    """

    def __init__(self, arch: Arch) -> None:
        self.arch = arch
        self.sp = stack_pointer(arch)

    def always_taken(self, rng: Rng):
        """Return ``(setup_instructions, jcc_mnemonic)`` that always branches.

        Both templates rely on guaranteed invariants: the stack pointer is never
        zero (``jnz``) and is always equal to itself (``je``).
        """

        choice = rng.choice(("sp_nonzero", "sp_equals_self"))
        if choice == "sp_nonzero":
            return [Instruction.synth(f"test {self.sp}, {self.sp}")], "jnz"
        return [Instruction.synth(f"cmp {self.sp}, {self.sp}")], "je"
