"""CodeScrambler: a versatile PE obfuscation toolkit.

The package is split into independently usable building blocks:

- :mod:`codescrambler.core` - shared primitives (seeded RNG, IR, disassembler,
  assembler) that every engine builds on.
- :mod:`codescrambler.pe` - PE loading, rebuilding and structure fidelity.
- :mod:`codescrambler.mutation` - the standalone mutation engine.
- :mod:`codescrambler.vm` - the standalone virtualization engine.
- :mod:`codescrambler.protect` - standalone section/data encryption.
- :mod:`codescrambler.engine` - the orchestrator that composes everything.

Most users only need the high level :class:`~codescrambler.engine.Engine` and
:class:`~codescrambler.config.Config`, but each engine can also be imported and
used on its own in another project.
"""

from codescrambler.config import Config, EmitMode, EncryptSections
from codescrambler.engine import Engine

__all__ = ["Config", "EmitMode", "EncryptSections", "Engine"]

__version__ = "0.1.0"
