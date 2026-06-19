"""VM engine checks: bytecode round-trip, lifter self-check, interpreter asm."""

from codescrambler.core.ir import Arch
from codescrambler.core.rng import Rng
from codescrambler.vm import bytecode as bc
from codescrambler.vm.interpreter import InterpreterGenerator
from codescrambler.vm.lifter import is_liftable, lift_run
from codescrambler.vm.randomizer import VMProfile

from ir_factory import make_program

RUN = "mov rax, 0x10; add rax, rbx; xor rax, rcx; sub rdx, rax; and rsi, rdx; or rdi, rsi"


def _profile(seed=2024):
    return VMProfile.generate(Rng(seed), Arch.X64)


def test_profiles_are_polymorphic():
    a = _profile(1).opcode_map
    b = _profile(2).opcode_map
    assert a != b  # different builds => different opcode numbering


def test_lift_and_roundtrip():
    profile = _profile()
    program = make_program(RUN)
    run = program.sections[0].instructions
    assert all(is_liftable(i, profile.reg_slots) for i in run)

    vprog = lift_run(run, profile)
    assert vprog is not None                  # self-check passed
    assert bc.verify_roundtrip(vprog, profile)

    blob = bc.assemble_bytecode(vprog, profile)
    restored = bc.decode(bc.decrypt(blob, profile.key), profile)
    assert len(restored.instructions) == len(vprog.instructions)


def test_stack_pointer_not_liftable():
    profile = _profile()
    program = make_program("add rsp, rax; ret")
    assert not is_liftable(program.sections[0].instructions[0], profile.reg_slots)


def test_interpreter_assembles():
    gen = InterpreterGenerator(_profile()).generate(base_va=0x180000000)
    assert len(gen.code) > 0
    assert "vm_dispatch" in gen.listing
