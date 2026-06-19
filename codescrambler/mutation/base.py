"""Common helpers shared by the mutation passes.

The pass contract (:class:`Pass`/`PassReport`/`register`) and the generic
synthetic-instruction helpers now live in :mod:`codescrambler.core` so that every
engine can author passes without importing another engine. This module simply
re-exports them, so a mutation-pass author can keep importing everything from
``codescrambler.mutation``.
"""

from __future__ import annotations

from codescrambler.core.pass_base import Pass, PassReport, register
from codescrambler.core.synth import (
    LabelMaker, iter_executable, rebuild_section, synth_branch, synth_labeled,
)

__all__ = [
    "Pass", "PassReport", "register",
    "LabelMaker", "rebuild_section", "iter_executable",
    "synth_branch", "synth_labeled",
]
