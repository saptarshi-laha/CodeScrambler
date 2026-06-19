"""Shared primitives used by every CodeScrambler engine.

Nothing in :mod:`codescrambler.core` knows about a specific obfuscation
technique; it only provides the common substrate: a seeded random source
(:mod:`codescrambler.core.rng`), the intermediate representation
(:mod:`codescrambler.core.ir`), disassembler backends
(:mod:`codescrambler.core.disasm`) and the label-resolving assembler
(:mod:`codescrambler.core.asm`).
"""

from codescrambler.core.rng import Rng

__all__ = ["Rng"]
