"""Use each engine on its own, and compose your own pass list.

Each engine is independently importable; nothing here pulls in the others
unless you ask for it.
"""

import sys

from codescrambler.core.rng import Rng
from codescrambler.mutation import Mutator, JunkPass, MBAPass, OpaquePass
from codescrambler.pe.loader import load_program
from codescrambler.vm import Virtualizer


def mutation_only(in_path: str, out_path: str) -> None:
    # Convenience: default intensity-scaled pipeline.
    Mutator(level=0.7, seed=1234).add_default_passes().run(in_path, out_path)


def hand_picked_passes(in_path: str, out_path: str) -> None:
    # Build a pipeline by hand from individual passes.
    mutator = Mutator(seed=1234)
    mutator.add(MBAPass(coverage=1.0))
    mutator.add(OpaquePass(density=0.4))
    mutator.add(JunkPass(density=0.6))
    mutator.run(in_path, out_path)


def virtualization_report(in_path: str) -> None:
    # Safe (non-committing) mode: get a lift report without rewriting code.
    program = load_program(in_path)
    report = Virtualizer(coverage=1.0, seed=7).analyze(program)
    print(report.as_dict())


def transform_ir_directly(in_path: str) -> None:
    # Drop down to the IR if you want full control.
    program = load_program(in_path)
    rng = Rng(99)
    JunkPass(density=0.5).apply(program, rng)
    total = sum(len(s.instructions) for s in program.executable_sections())
    print(f"{total} instructions after junk insertion")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        virtualization_report(sys.argv[1])
    else:
        print(__doc__)
