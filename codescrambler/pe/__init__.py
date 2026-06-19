"""PE loading, rebuilding and structure fidelity.

* :mod:`codescrambler.pe.loader` parses a PE into the IR :class:`Program`.
* :mod:`codescrambler.pe.writer` rebuilds a runnable PE from transformed code.
* :mod:`codescrambler.pe.reloc` updates the base relocation table.
* :mod:`codescrambler.pe.fidelity` repoints data directories (TLS, exceptions,
  exports, ...) so everything keeps working after code moves.
"""

from codescrambler.pe.loader import PELoader, load_program

__all__ = ["PELoader", "load_program"]
