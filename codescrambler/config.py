"""Engine configuration.

A single :class:`Config` object captures every knob the CLI exposes. The two
intensity knobs (:attr:`mutation` and :attr:`virtualization`) are percentages so
the surface stays tiny; everything else has a sensible default.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class EmitMode(str, Enum):
    """What the engine produces."""

    BINARY = "binary"  # a rebuilt, runnable PE
    ANALYSIS = "analysis"  # a structured dump of the transformed IR


class EncryptSections(str, Enum):
    """Which non-executable sections to encrypt at rest."""

    NONE = "none"
    DATA = "data"
    ALL = "all"


def _clamp_percent(value: int) -> int:
    return max(0, min(100, int(value)))


@dataclass
class Config:
    """Top-level configuration shared by the CLI and the library API."""

    mutation: int = 0
    virtualization: int = 0
    encrypt_sections: EncryptSections = EncryptSections.NONE
    emit: EmitMode = EmitMode.BINARY
    seed: Optional[int] = None
    #: Insert a runtime debugger check near the entry (preventive transform).
    anti_debug: bool = False
    #: Insert a runtime hypervisor/VM check near the entry (preventive transform).
    anti_vm: bool = False
    #: Optional static watermark string embedded in the output.
    watermark: Optional[str] = None
    #: Embed a notice deterring automated / AI / LLM reverse engineering.
    llm_deterrent: bool = False

    def __post_init__(self) -> None:
        self.mutation = _clamp_percent(self.mutation)
        self.virtualization = _clamp_percent(self.virtualization)
        # Allow plain strings from argparse to flow in unchanged.
        self.encrypt_sections = EncryptSections(self.encrypt_sections)
        self.emit = EmitMode(self.emit)

    @property
    def mutation_level(self) -> float:
        """Mutation intensity as a 0.0 - 1.0 fraction."""

        return self.mutation / 100.0

    @property
    def virtualization_coverage(self) -> float:
        """Virtualization coverage as a 0.0 - 1.0 fraction."""

        return self.virtualization / 100.0
