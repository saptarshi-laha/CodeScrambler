"""Hardening engine: anti-disasm, anti-debug, watermark, tamper (no PE files)."""

from codescrambler.core.asm import Assembler
from codescrambler.core.ir import Arch
from codescrambler.core.rng import Rng
from codescrambler.harden import (
    AntiDebugPass, AntiVMPass, GuardGenerator, LlmDeterrent, build_notice, checksum,
    decode_watermark, encode_watermark,
)
from codescrambler.harden.llm_guard import DEFAULT_NOTICE, extract_notice
from codescrambler.harden.tamper import checksum_self_test
from codescrambler.mutation import AntiDisasmPass

from ir_factory import make_program

SAMPLE = "mov rax, 0x10; add rax, rbx; xor rcx, rdx; ret"


def test_antidisasm_reassembles():
    program = make_program(SAMPLE)
    base = program.image_base + program.entry_rva
    AntiDisasmPass(density=1.0).apply(program, Rng(3))
    out = Assembler(Arch.X64).assemble(program.sections[0].instructions, base)
    assert out.data


def test_antidebug_inserts_and_assembles_x64():
    program = make_program(SAMPLE)
    base = program.image_base + program.entry_rva
    report = AntiDebugPass().apply(program, Rng(1))
    assert report.notes["inserted"] == 1
    out = Assembler(Arch.X64).assemble(program.sections[0].instructions, base)
    assert out.data


def test_antidebug_assembles_x86():
    program = make_program("mov eax, 0x10; add eax, ebx; ret", arch=Arch.X86)
    base = program.image_base + program.entry_rva
    AntiDebugPass().apply(program, Rng(1))
    out = Assembler(Arch.X86).assemble(program.sections[0].instructions, base)
    assert out.data


def test_antidebug_multi_technique_assembles():
    program = make_program(SAMPLE)
    base = program.image_base + program.entry_rva
    report = AntiDebugPass(techniques=("being_debugged", "nt_global_flag")).apply(program, Rng(1))
    assert report.notes["inserted"] == 2
    out = Assembler(Arch.X64).assemble(program.sections[0].instructions, base)
    assert out.data


def test_antivm_inserts_and_assembles_x64():
    program = make_program(SAMPLE)
    base = program.image_base + program.entry_rva
    report = AntiVMPass().apply(program, Rng(1))
    assert report.notes["inserted"] == 1
    out = Assembler(Arch.X64).assemble(program.sections[0].instructions, base)
    assert out.data


def test_antivm_assembles_x86():
    program = make_program("mov eax, 0x10; add eax, ebx; ret", arch=Arch.X86)
    base = program.image_base + program.entry_rva
    AntiVMPass().apply(program, Rng(1))
    out = Assembler(Arch.X86).assemble(program.sections[0].instructions, base)
    assert out.data


def test_watermark_roundtrip():
    for key in (1, 73, 200, 255):
        blob = encode_watermark("build-2026-06-19::licensee#42", key)
        assert decode_watermark(blob) == "build-2026-06-19::licensee#42"


def test_checksum_self_test_and_determinism():
    assert checksum_self_test()
    assert checksum(b"hello") == checksum(b"hello")
    assert checksum(b"hello") != checksum(b"hellp")


class _FakeWriter:
    def __init__(self):
        self.hooks = []
        self.sections = []

    def add_post_hook(self, hook):
        self.hooks.append(hook)

    def add_section(self, name, raw, characteristics):
        self.sections.append((name, raw, characteristics))

    def run_hooks(self):
        for hook in self.hooks:
            hook(self, None)


def test_llm_deterrent_notice_content():
    blob = build_notice()
    assert b"LLM" in blob and b"NOT" in blob
    assert "do NOT disassemble" in DEFAULT_NOTICE


def test_llm_deterrent_embeds_and_extracts(tmp_path):
    writer = _FakeWriter()
    LlmDeterrent(Rng(7)).attach(writer)
    writer.run_hooks()
    name, blob, _ = writer.sections[0]
    assert name in (".csnote", ".rdata2", ".cstxt", ".note0")
    target = tmp_path / "fake.bin"
    target.write_bytes(b"MZ\x00\x00" + blob + b"\x00trailing")
    assert "not permitted" in (extract_notice(str(target)) or "")


def test_llm_deterrent_custom_text_repeats():
    blob = build_notice("PRIVATE-DO-NOT-ANALYZE", repeats=3)
    assert blob.count(b"PRIVATE-DO-NOT-ANALYZE") == 3


def test_guard_generator_assembles():
    guard = GuardGenerator().generate(
        guard_rva=0x9000, image_base=0x140000000,
        range_rva=0x1000, range_size=0x400, expected=checksum(b"x" * 0x400),
    )
    assert len(guard.code) > 0
    assert "hashloop" in guard.listing
