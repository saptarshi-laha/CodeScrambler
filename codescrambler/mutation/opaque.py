"""Opaque-predicate insertion pass.

Inserts branches whose outcome is fixed at build time but non-obvious to a
static analyzer, guarding dead junk. The whole construct is flag-neutral and
register-neutral for the surrounding code:

    pushf
    <predicate setup>      ; e.g. test rsp, rsp
    jcc  cont              ; always taken
    <dead junk>            ; never reached
  cont:
    popf

Either control path reaches ``cont`` and restores the flags, and no
general-purpose register is touched, so the predicate is safe to splice between
any two instructions.
"""

from __future__ import annotations

from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation.base import (
    LabelMaker, Pass, PassReport, register, synth_branch, synth_labeled,
)
from codescrambler.mutation.catalog import JunkFactory, PredicateFactory, popf, pushf


@register
class OpaquePass(Pass):
    """Guard dead junk behind always-true opaque predicates."""

    name = "opaque"

    def __init__(self, density: float = 0.15) -> None:
        self.density = density

    def apply(self, program: Program, rng: Rng) -> PassReport:
        predicates = PredicateFactory(program.arch)
        junk = JunkFactory(program.arch)
        inserted = 0
        for section in program.executable_sections():
            rebuilt = []
            for insn in section.instructions:
                if insn.mnemonic != ".byte" and rng.chance(self.density):
                    rebuilt.extend(self._build(program, rng, predicates, junk))
                    inserted += 1
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"predicates_inserted": inserted})

    def _build(self, program, rng, predicates, junk):
        cont = LabelMaker.fresh("opq")
        setup, jcc = predicates.always_taken(rng)
        block = [Instruction.synth(pushf(program.arch))]
        block.extend(setup)
        block.append(synth_branch(jcc, cont))
        block.extend(junk.sequence(rng, max_len=2))  # dead code
        block.append(synth_labeled(popf(program.arch), cont))
        return block
