"""Basic-block model + control-flow transforms (no PE files)."""

from codescrambler.core.asm import Assembler
from codescrambler.core.cfg import build_blocks, flatten_blocks
from codescrambler.core.ir import Arch
from codescrambler.core.rng import Rng
from codescrambler.mutation import BlockScatterPass, BranchFunctionPass

from ir_factory import make_program

# A program with several blocks: branches create leaders.
SAMPLE = """
    mov rax, 1
    cmp rax, rbx
    je  l_taken
    add rax, 2
    jmp l_done
l_taken:
    sub rax, 3
l_done:
    xor rcx, rcx
    ret
"""


def test_build_blocks_partition_is_lossless():
    program = make_program(SAMPLE)
    instructions = program.sections[0].instructions
    blocks = build_blocks(instructions)
    assert len(blocks) >= 3
    # Re-concatenating the blocks (no reordering) reproduces the exact list.
    assert flatten_blocks(blocks) == instructions


def test_scatter_preserves_instructions_and_reassembles():
    program = make_program(SAMPLE)
    section = program.sections[0]
    original_real = [i for i in section.instructions if not i.synthetic]
    base = program.image_base + program.entry_rva

    BlockScatterPass(probability=1.0).apply(program, Rng(5))

    after_real = [i for i in section.instructions if not i.synthetic]
    # Every original instruction survives (only added synthetic jmps + reordering).
    assert after_real == original_real or set(map(id, after_real)) == set(map(id, original_real))
    out = Assembler(Arch.X64).assemble(section.instructions, base)
    assert out.data


def test_branchfunc_x64_reassembles():
    program = make_program(SAMPLE)
    section = program.sections[0]
    base = program.image_base + program.entry_rva
    report = BranchFunctionPass(density=1.0).apply(program, Rng(2))
    assert report.notes["branches_rewritten"] >= 1
    out = Assembler(Arch.X64).assemble(section.instructions, base)
    assert out.data


def test_branchfunc_x86_reassembles():
    program = make_program("mov eax, 1\n jmp l_end\n l_end:\n ret", arch=Arch.X86)
    section = program.sections[0]
    base = program.image_base + program.entry_rva
    BranchFunctionPass(density=1.0).apply(program, Rng(2))
    out = Assembler(Arch.X86).assemble(section.instructions, base)
    assert out.data
