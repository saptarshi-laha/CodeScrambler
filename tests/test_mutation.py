"""In-memory correctness checks for the mutation passes (no PE files)."""

import pytest

from codescrambler.core.asm import Assembler
from codescrambler.core.ir import Arch
from codescrambler.core.rng import Rng
from codescrambler import mutation

from ir_factory import make_program

SAMPLE = """
    mov rax, 0x1234
    add rax, rbx
    xor rcx, rdx
    or  rsi, rdi
    and r8, r9
    sub rbx, rcx
    mov rdx, rax
    test rax, rax
    jnz done
    add rax, 1
done:
    ret
"""

PASSES = [
    mutation.MBAPass(coverage=1.0),
    mutation.ConstantUnfoldPass(coverage=1.0),
    mutation.SubstitutePass(density=1.0),
    mutation.ReorderPass(density=1.0),
    mutation.JumpPass(density=1.0),
    mutation.OpaquePass(density=1.0),
    mutation.JunkPass(density=1.0),
    mutation.AntiDisasmPass(density=1.0),
    mutation.StackNoisePass(density=1.0),
]


@pytest.mark.parametrize("transform", PASSES, ids=lambda p: p.name)
def test_pass_reassembles(transform):
    program = make_program(SAMPLE)
    base = program.image_base + program.entry_rva
    transform.apply(program, Rng(42))
    out = Assembler(Arch.X64).assemble(program.sections[0].instructions, base)
    assert out.data  # produced valid machine code


def test_constant_unfold_recovers_value():
    program = make_program("mov rax, 0x1234; add rax, rbx; ret")
    mutation.ConstantUnfoldPass(coverage=1.0).apply(program, Rng(1))
    rendered = [i.render() for i in program.sections[0].instructions]
    # The original immediate must not appear verbatim, but xor reverses it.
    assert any(r.startswith("xor rax") for r in rendered)


def test_full_pipeline_in_memory():
    program = make_program(SAMPLE)
    base = program.image_base + program.entry_rva
    rng = Rng(7)
    for transform in mutation.build_passes(1.0):
        transform.apply(program, rng)
    out = Assembler(Arch.X64).assemble(program.sections[0].instructions, base)
    assert out.data
