"""Standalone mutation engine.

``Mutator`` lets another project use the mutation passes without touching the
virtualization or protection engines. It owns its own seeded RNG and can either
build a default, intensity-scaled pipeline or accept hand-picked passes.

    from codescrambler.mutation import Mutator
    Mutator(level=0.6).add_default_passes().run("in.exe", "out.exe")
"""

from __future__ import annotations

from typing import List, Optional

from codescrambler.core.ir import Program
from codescrambler.core.pass_base import Pass
from codescrambler.core.rng import Rng
from codescrambler.pe.loader import load_program

from codescrambler.mutation.antidisasm import AntiDisasmPass
from codescrambler.mutation.branchfunc import BranchFunctionPass
from codescrambler.mutation.callswitch import CallSwitchPass
from codescrambler.mutation.constants import ConstantUnfoldPass
from codescrambler.mutation.junk import JunkPass
from codescrambler.mutation.jumps import JumpPass
from codescrambler.mutation.mba import MBAPass
from codescrambler.mutation.opaque import OpaquePass
from codescrambler.mutation.reorder import ReorderPass
from codescrambler.mutation.scatter import BlockScatterPass
from codescrambler.mutation.stacknoise import StackNoisePass
from codescrambler.mutation.substitute import SubstitutePass


def build_passes(level: float) -> List[Pass]:
    """Return the default, intensity-scaled mutation pipeline.

    ``level`` is a 0.0 - 1.0 fraction (the ``--mutation X%`` knob / 100). Passes
    that rewrite real instructions run first (while register metadata is intact),
    followed by passes that splice in synthetic code.
    """

    level = max(0.0, min(1.0, level))
    return [
        MBAPass(coverage=0.9 * level),
        ConstantUnfoldPass(coverage=0.6 * level),
        SubstitutePass(density=0.6 * level),
        ReorderPass(density=0.4 * level),
        CallSwitchPass(density=0.5 * level),
        JumpPass(density=0.3 * level),
        BranchFunctionPass(density=0.4 * level),
        OpaquePass(density=0.25 * level),
        JunkPass(density=0.5 * level, max_run=3),
        AntiDisasmPass(density=0.15 * level),
        BlockScatterPass(probability=min(1.0, 0.8 * level)),
        StackNoisePass(density=0.15 * level),
    ]


class Mutator:
    """A self-contained mutation pipeline over a single PE."""

    def __init__(self, level: float = 0.5, seed: Optional[int] = None) -> None:
        self.level = level
        self.rng = Rng(seed)
        self.seed = self.rng.seed
        self._passes: List[Pass] = []

    def add(self, transform: Pass) -> "Mutator":
        self._passes.append(transform)
        return self

    def add_default_passes(self) -> "Mutator":
        for transform in build_passes(self.level):
            self.add(transform)
        return self

    def apply(self, program: Program) -> Program:
        """Run the pipeline over an already-loaded program (no I/O)."""

        if not self._passes:
            self.add_default_passes()
        for transform in self._passes:
            transform.apply(program, self.rng)
        return program

    def run(self, in_path: str, out_path: str) -> Program:
        """Load, mutate and rebuild a PE end to end."""

        from codescrambler.pe.writer import PEWriter

        program = load_program(in_path)
        self.apply(program)
        PEWriter(program, in_path, self.rng).write(out_path)
        return program
