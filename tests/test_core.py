"""Determinism, registry and standalone-import guarantees (no PE files)."""

from codescrambler.core.asm import Assembler
from codescrambler.core.ir import Arch
from codescrambler.core.pass_base import registered_passes
from codescrambler.core.rng import Rng
from codescrambler import mutation

from ir_factory import make_program


def test_rng_is_reproducible():
    a = [Rng(123).randint(0, 1_000_000) for _ in range(5)]
    b = [Rng(123).randint(0, 1_000_000) for _ in range(5)]
    assert a == b


def test_rng_differs_across_seeds():
    assert Rng(1).bits(64) != Rng(2).bits(64)


def test_mutation_is_deterministic_with_seed():
    # The contract is byte-for-byte reproducibility for a given seed. (Internal
    # synthetic label *names* come from a process-global counter and are never
    # emitted - they resolve to addresses - so they don't affect output bytes.)
    def build():
        program = make_program("mov rax, 0x10; add rax, rbx; xor rcx, rdx; ret")
        base = program.image_base + program.entry_rva
        rng = Rng(999)
        for transform in mutation.build_passes(1.0):
            transform.apply(program, rng)
        return Assembler(Arch.X64).assemble(program.sections[0].instructions, base).data

    assert build() == build()


def test_registry_contains_expected_passes():
    names = set(registered_passes())
    assert {"junk", "opaque", "mba", "substitute", "virtualize"} <= names


def test_engines_import_independently():
    # Importing one engine must not require the others at import time.
    import importlib

    for module in (
        "codescrambler.mutation", "codescrambler.vm",
        "codescrambler.protect", "codescrambler.harden",
    ):
        assert importlib.import_module(module) is not None


def test_engines_do_not_pull_in_each_other():
    """Each engine must be importable in a fresh process without the others."""

    import subprocess
    import sys

    engines = ["mutation", "vm", "protect", "harden"]
    for engine in engines:
        others = [e for e in engines if e != engine]
        code = (
            "import sys, codescrambler.{eng};"
            "pulled=[o for o in {others!r} "
            "if any(k.startswith('codescrambler.'+o) for k in sys.modules)];"
            "assert not pulled, ('{eng} pulled in '+repr(pulled))"
        ).format(eng=engine, others=others)
        subprocess.run([sys.executable, "-c", code], check=True)
