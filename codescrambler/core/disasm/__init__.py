"""Disassembly: raw section bytes -> IR.

Uses ``capstone``, which exposes the rich per-instruction detail (operands,
register read/write sets, flag access, instruction groups) that the obfuscation
passes and the VM lifter depend on. :class:`DisassemblerBackend` is the ABC to
implement if you want to plug in a different decoder.
"""

from codescrambler.core.disasm.base import DisassemblerBackend, get_backend

__all__ = ["DisassemblerBackend", "get_backend"]
