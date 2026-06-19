"""Liveness analysis for the mutation passes.

The implementation now lives in :mod:`codescrambler.core.analysis` so every
engine can share it without importing the mutation engine. This module re-exports
it for the mutation passes that import from ``codescrambler.mutation.analysis``.
"""

from __future__ import annotations

from codescrambler.core.analysis import (
    flags_dead_after, gp_registers, register_dead_after,
)

__all__ = ["gp_registers", "flags_dead_after", "register_dead_after"]
