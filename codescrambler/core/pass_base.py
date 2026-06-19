"""The transformation-pass contract and a small registry.

Every obfuscation step - whether it lives in the mutation engine, the VM engine
or a third-party plugin - implements :class:`Pass`. Keeping the contract in
:mod:`codescrambler.core` means the orchestrator only depends on ``core`` and
any engine (or external project) can define passes without importing the
others.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Dict, List, Type

from codescrambler.core.ir import Program
from codescrambler.core.rng import Rng


@dataclass
class PassReport:
    """Optional structured feedback a pass can emit for analysis output."""

    name: str
    notes: Dict[str, object] = field(default_factory=dict)


class Pass(abc.ABC):
    """Base class for an IR-to-IR transformation.

    A pass mutates the :class:`Program` in place. All randomness must come from
    the supplied :class:`Rng` so builds stay reproducible and polymorphic.
    """

    #: Stable identifier used by the registry and the CLI.
    name: str = "pass"

    @abc.abstractmethod
    def apply(self, program: Program, rng: Rng) -> PassReport:
        """Transform ``program`` and return a :class:`PassReport`."""


_REGISTRY: Dict[str, Type[Pass]] = {}


def register(cls: Type[Pass]) -> Type[Pass]:
    """Class decorator that records a pass under its :attr:`Pass.name`."""

    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate pass name: {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def get_pass(name: str) -> Type[Pass]:
    """Look up a registered pass class by name."""

    return _REGISTRY[name]


def registered_passes() -> List[str]:
    """Return the names of all registered passes, sorted."""

    return sorted(_REGISTRY)
