"""The orchestrator that composes loading, passes and emission.

``Engine`` is the high-level entry point most callers use. It owns the shared
:class:`~codescrambler.core.rng.Rng`, the ordered list of passes, and the logic
for turning a :class:`~codescrambler.config.Config` into a concrete pipeline by
pulling passes from the mutation, virtualization and protection engines.

Each of those engines is imported lazily and only when its knob is non-zero, so
``Engine`` (and a downstream project that only wants one engine) never pays for
the others.
"""

from __future__ import annotations

import json
from typing import List, Optional

from codescrambler.config import Config, EmitMode, EncryptSections
from codescrambler.core.ir import Program
from codescrambler.core.pass_base import Pass, PassReport
from codescrambler.core.rng import Rng
from codescrambler.pe.loader import load_program


class Engine:
    """Composes a pipeline of passes and runs it over a PE."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.rng = Rng(self.config.seed)
        # The resolved seed is recorded so a build can always be reproduced.
        self.config.seed = self.rng.seed
        self._passes: List[Pass] = []
        self._reports: List[PassReport] = []

    # -- pipeline construction -------------------------------------------
    def add(self, transform: Pass) -> "Engine":
        """Append a pass to the pipeline (fluent)."""

        self._passes.append(transform)
        return self

    def build_default_pipeline(self) -> "Engine":
        """Populate the pipeline from :attr:`config`'s intensity knobs."""

        if self.config.mutation > 0:
            from codescrambler.mutation import build_passes

            for transform in build_passes(self.config.mutation_level):
                self.add(transform)

        if self.config.virtualization > 0:
            from codescrambler.vm import VirtualizePass

            self.add(VirtualizePass(coverage=self.config.virtualization_coverage))

        if self.config.anti_debug:
            from codescrambler.harden import AntiDebugPass

            self.add(AntiDebugPass())

        if self.config.anti_vm:
            from codescrambler.harden import AntiVMPass

            self.add(AntiVMPass())

        return self

    # -- execution --------------------------------------------------------
    def run(self, in_path: str, out_path: str) -> Program:
        """Load ``in_path``, apply the pipeline and write ``out_path``."""

        program = load_program(in_path)
        program.metadata["seed"] = self.rng.seed

        if not self._passes and self.config.emit is EmitMode.BINARY:
            self.build_default_pipeline()

        for transform in self._passes:
            report = transform.apply(program, self.rng)
            if report is not None:
                self._reports.append(report)

        if self.config.emit is EmitMode.ANALYSIS:
            self._write_analysis(program, out_path)
        else:
            self._write_binary(program, in_path, out_path)
        return program

    # -- emission ---------------------------------------------------------
    def _write_binary(self, program: Program, in_path: str, out_path: str) -> None:
        from codescrambler.pe.writer import PEWriter

        writer = PEWriter(program, in_path, self.rng)
        if self.config.encrypt_sections is not EncryptSections.NONE:
            from codescrambler.protect import SectionProtector

            SectionProtector(self.config.encrypt_sections, self.rng).attach(writer)
        if self.config.watermark:
            from codescrambler.harden import Watermark

            Watermark(self.config.watermark, self.rng).attach(writer)
        if self.config.llm_deterrent:
            from codescrambler.harden import LlmDeterrent

            LlmDeterrent(self.rng).attach(writer)
        writer.write(out_path)

    def _write_analysis(self, program: Program, out_path: str) -> None:
        payload = {
            "seed": self.rng.seed,
            "arch": program.arch.name,
            "image_base": program.image_base,
            "entry_rva": program.entry_rva,
            "sections": [
                {
                    "name": s.name,
                    "rva": s.rva,
                    "executable": s.is_executable,
                    "instruction_count": len(s.instructions),
                }
                for s in program.sections
            ],
            "reports": [{"name": r.name, **r.notes} for r in self._reports],
        }
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
