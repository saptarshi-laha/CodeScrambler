"""The virtualization pass, lift report and standalone engine.

``VirtualizePass`` walks every executable section, finds maximal runs of
liftable instructions (see :mod:`codescrambler.vm.lifter`), and for a
``coverage``-controlled fraction of them produces verified, encrypted VM
bytecode plus a per-build interpreter. As ``coverage`` approaches 1.0 it lifts
everything the lifter currently supports and records what stayed native (and
why) in a :class:`LiftReport`.

Commit modes
------------
* ``commit=False`` (default): the pass produces all VM artifacts (bytecode,
  interpreter, report) and stores them on ``program.metadata['vm']`` *without*
  rewriting native code, so the rebuilt binary is guaranteed to still run. This
  is the safe mode for off-target development and for inspecting coverage.
* ``commit=True``: additionally rewrite each lifted run into a call-stub into
  the generated interpreter. This path performs real virtualization; because its
  runtime behavior cannot be validated off-target, ``ARCHITECTURE.md`` documents
  the precise writer-integration and on-target validation steps. It is opt-in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from codescrambler.core.ir import Arch, Instruction, Program, Section
from codescrambler.core.pass_base import Pass, PassReport, register
from codescrambler.core.rng import Rng
from codescrambler.core.analysis import flags_dead_after
from codescrambler.vm import bytecode as bc
from codescrambler.vm.interpreter import InterpreterGenerator
from codescrambler.vm.isa import VMProgram
from codescrambler.vm.lifter import is_liftable, lift_run
from codescrambler.vm.randomizer import VMProfile


@dataclass
class LiftReport:
    """Diagnostics describing what was (and was not) virtualized."""

    arch_supported: bool = True
    total_instructions: int = 0
    candidate_runs: int = 0
    lifted_runs: int = 0
    virtualized_instructions: int = 0
    bytecode_bytes: int = 0
    skipped: Dict[str, int] = field(default_factory=dict)

    def note_skip(self, reason: str, count: int = 1) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + count

    def as_dict(self) -> Dict[str, object]:
        return {
            "arch_supported": self.arch_supported,
            "total_instructions": self.total_instructions,
            "candidate_runs": self.candidate_runs,
            "lifted_runs": self.lifted_runs,
            "virtualized_instructions": self.virtualized_instructions,
            "bytecode_bytes": self.bytecode_bytes,
            "skipped": dict(self.skipped),
        }


@dataclass
class _LiftedRun:
    """A virtualized run and its encrypted bytecode (commit-mode payload)."""

    section_index: int
    start: int
    length: int
    bytecode: bytes


@register
class VirtualizePass(Pass):
    """Lift native instruction runs into per-build VM bytecode."""

    name = "virtualize"

    def __init__(self, coverage: float = 0.3, commit: bool = False) -> None:
        self.coverage = max(0.0, min(1.0, coverage))
        self.commit = commit

    def apply(self, program: Program, rng: Rng) -> PassReport:
        report = LiftReport(total_instructions=len(program.all_instructions()))

        if program.arch is not Arch.X64:
            report.arch_supported = False
            report.note_skip("arch_not_supported_x86")
            program.metadata["vm"] = {"report": report.as_dict()}
            return PassReport(self.name, report.as_dict())

        profile = VMProfile.generate(rng, program.arch)
        lifted: List[_LiftedRun] = []

        for section_index, section in enumerate(program.sections):
            if not section.is_executable:
                continue
            self._process_section(section, section_index, profile, rng, report, lifted)

        interpreter = InterpreterGenerator(profile).generate(base_va=0)  # base set at write time
        program.metadata["vm"] = {
            "report": report.as_dict(),
            "profile_seed": rng.seed,
            "interpreter_size": len(interpreter.code),
            "lifted_runs": len(lifted),
        }

        if self.commit and lifted:
            self._commit(program, profile, interpreter, lifted)

        return PassReport(self.name, report.as_dict())

    # -- run discovery ----------------------------------------------------
    def _process_section(self, section, section_index, profile, rng, report, lifted) -> None:
        for start, length in self._find_runs(section.instructions, profile):
            report.candidate_runs += 1
            if not rng.chance(self.coverage):
                report.note_skip("not_selected_by_coverage")
                continue
            run = section.instructions[start:start + length]
            program_bc = lift_run(run, profile)
            if program_bc is None:
                report.note_skip("self_check_failed")
                continue
            if not bc.verify_roundtrip(program_bc, profile):
                report.note_skip("bytecode_roundtrip_failed")
                continue
            blob = bc.assemble_bytecode(program_bc, profile)
            report.lifted_runs += 1
            report.virtualized_instructions += length
            report.bytecode_bytes += len(blob)
            lifted.append(_LiftedRun(section_index, start, length, blob))

    def _find_runs(self, instructions: List[Instruction], profile: VMProfile):
        """Yield ``(start, length)`` for maximal liftable, flag-safe runs."""

        runs = []
        i = 0
        n = len(instructions)
        while i < n:
            if not is_liftable(instructions[i], profile.reg_slots):
                i += 1
                continue
            start = i
            i += 1
            # Extend while liftable and not crossing a branch target (label).
            while i < n and is_liftable(instructions[i], profile.reg_slots) \
                    and instructions[i].label is None:
                i += 1
            # The run is only usable if flags are dead after its last instruction.
            if flags_dead_after(instructions, i - 1):
                runs.append((start, i - start))
        return runs

    # -- commit (opt-in, on-target territory) ----------------------------
    def _commit(self, program, profile, interpreter, lifted) -> None:
        """Record commit-mode artifacts for the writer to consume.

        The actual native-code replacement and section insertion is performed at
        write time, where final section VAs are known. We stash everything the
        writer needs; see ``ARCHITECTURE.md`` for the integration contract.
        """

        program.metadata["vm_commit"] = {
            "interpreter_code": interpreter.code,
            "interpreter_listing": interpreter.listing,
            "runs": [
                {
                    "section_index": run.section_index,
                    "start": run.start,
                    "length": run.length,
                    "bytecode": run.bytecode,
                }
                for run in lifted
            ],
        }


class Virtualizer:
    """Standalone VM engine - usable without the mutation/protection engines."""

    def __init__(self, coverage: float = 0.3, seed: Optional[int] = None,
                 commit: bool = False) -> None:
        self.coverage = coverage
        self.commit = commit
        self.rng = Rng(seed)
        self.seed = self.rng.seed

    def analyze(self, program: Program) -> LiftReport:
        """Run virtualization over a loaded program and return the report."""

        VirtualizePass(self.coverage, self.commit).apply(program, self.rng)
        report = program.metadata.get("vm", {}).get("report", {})
        result = LiftReport()
        for key, value in report.items():
            setattr(result, key, value)
        return result

    def run(self, in_path: str, out_path: str) -> Program:
        from codescrambler.pe.loader import load_program
        from codescrambler.pe.writer import PEWriter

        program = load_program(in_path)
        VirtualizePass(self.coverage, self.commit).apply(program, self.rng)
        PEWriter(program, in_path, self.rng).write(out_path)
        return program
