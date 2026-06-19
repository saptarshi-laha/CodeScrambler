"""Write and register your own pass.

A pass is any class implementing ``apply(program, rng) -> PassReport``. Register
it to expose it by name; or just instantiate and add it to a pipeline directly.
"""

from codescrambler.core.ir import Instruction, Program
from codescrambler.core.rng import Rng
from codescrambler.mutation import Mutator, Pass, PassReport, register


@register
class NopSprinklePass(Pass):
    """Insert a single ``nop`` before every Nth real instruction."""

    name = "nop_sprinkle"

    def __init__(self, every: int = 5) -> None:
        self.every = every

    def apply(self, program: Program, rng: Rng) -> PassReport:
        added = 0
        for section in program.executable_sections():
            rebuilt = []
            for i, insn in enumerate(section.instructions):
                if i % self.every == 0:
                    rebuilt.append(Instruction.synth("nop"))
                    added += 1
                rebuilt.append(insn)
            section.instructions = rebuilt
        return PassReport(self.name, {"nops_added": added})


def build(in_path: str, out_path: str) -> None:
    Mutator(seed=1).add(NopSprinklePass(every=4)).run(in_path, out_path)
