"""The standalone virtualization engine.

Turns runs of native instructions into bytecode for a per-build randomized
register VM, plus a generated interpreter. The pieces:

* :mod:`codescrambler.vm.isa` - the VM instruction set and its reference
  semantics (used for self-checking lifted bytecode).
* :mod:`codescrambler.vm.randomizer` - per-build opcode numbering, handler
  order and bytecode key, so every build yields a structurally different VM.
* :mod:`codescrambler.vm.bytecode` - encode/encrypt/decode/simulate bytecode.
* :mod:`codescrambler.vm.lifter` - native -> VM translation for the supported
  subset, with a build-time equivalence self-check.
* :mod:`codescrambler.vm.interpreter` - generates the dispatcher + handlers as
  machine code for a new section.
* :mod:`codescrambler.vm.virtualizer` - the :class:`VirtualizePass` and the
  standalone :class:`Virtualizer`, plus the lift report.

Maturity: the bytecode system, randomizer and lifter (with simulator
self-check) are verifiable off-target. The generated interpreter is assembled
but its runtime behavior must be validated on a Windows host - see
``ARCHITECTURE.md`` for the exact continuation steps.
"""

from codescrambler.vm.isa import VMOp, VMInstr, VMProgram
from codescrambler.vm.randomizer import VMProfile
from codescrambler.vm.virtualizer import LiftReport, VirtualizePass, Virtualizer

__all__ = [
    "VMOp", "VMInstr", "VMProgram", "VMProfile",
    "VirtualizePass", "Virtualizer", "LiftReport",
]
