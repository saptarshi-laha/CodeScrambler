"""Junk-code insertion pass.

Splices semantics-preserving junk (from :class:`~codescrambler.mutation.catalog.JunkFactory`)
between real instructions. Because the junk preserves every register and the
flags, it can be inserted at any point without analysis. Insertion points and
sequence lengths are randomized, so the pass is polymorphic across builds.
"""

from __future__ import annotations

from codescrambler.core.ir import Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import Pass, PassReport, register
from codescrambler.mutation.catalog import JunkFactory


@register
class JunkPass(Pass):
    """Insert flag/register-preserving junk between instructions."""

    name = "junk"

    def __init__(self, density: float = 0.3, max_run: int = 3) -> None:
        #: Probability of inserting junk at any given gap (0.0 - 1.0).
        self.density = density
        self.max_run = max_run

    def apply(self, program: Program, rng: Rng) -> PassReport:
        factory = JunkFactory(program.arch)
        inserted = 0
        for section in program.executable_sections():
            rebuilt = []
            for insn in section.instructions:
                if insn.mnemonic != ".byte" and rng.chance(self.density):
                    junk = factory.sequence(rng, self.max_run)
                    rebuilt.extend(junk)
                    inserted += len(junk)
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"instructions_inserted": inserted})
