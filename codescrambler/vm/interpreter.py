"""Generate the VM interpreter as machine code for embedding in a new section.

The interpreter is produced as assembly text (parameterized by the build's
:class:`~codescrambler.vm.randomizer.VMProfile`) and compiled with keystone, so
every build emits a structurally different dispatcher (randomized opcode
comparisons, handler order and bytecode key).

ABI (inline-pointer calling convention - avoids clobbering any register before
the context is captured):

    call vm_dispatch
    .quad <bytecode_va>     ; 8-byte pointer the interpreter consumes
    <native continuation>   ; ret lands here

On entry the interpreter:

1. reserves a context array on the stack and copies every captured GP register
   into its profile-assigned slot (the copies only *read* registers, so all
   originals are preserved);
2. reads the inline bytecode pointer and advances the return address past it;
3. runs a fetch/decrypt/dispatch loop over the bytecode;
4. on ``EXIT`` writes the context slots back to the GP registers and ``ret``s.

MATURITY: this generator emits a complete, self-consistent listing and is
assemble-checked, but its *runtime* behavior must be validated on a Windows
host. ``ARCHITECTURE.md`` documents the exact validation steps and the (small)
surface that needs on-target confirmation. The stack pointer is never captured
or restored, and lifting excludes it, so the live stack is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import keystone

from codescrambler.core.ir import Arch
from codescrambler.vm.isa import SLOT_COUNT, VMOp
from codescrambler.vm.randomizer import VMProfile

_CTX_SIZE = SLOT_COUNT * 8

# Registers captured into / restored from the context (stack pointer excluded).
_CAPTURED_X64 = (
    "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)


@dataclass
class GeneratedInterpreter:
    """The assembled interpreter plus the assembly listing it came from."""

    code: bytes
    listing: str
    entry_label: str = "vm_dispatch"


class InterpreterGenerator:
    """Builds and assembles a per-profile VM interpreter (x64)."""

    def __init__(self, profile: VMProfile) -> None:
        if profile.arch is not Arch.X64:
            raise NotImplementedError("interpreter generation currently targets x64")
        self.profile = profile

    def generate(self, base_va: int) -> GeneratedInterpreter:
        listing = self._listing()
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        ks.syntax = keystone.KS_OPT_SYNTAX_INTEL
        encoding, _ = ks.asm(listing, base_va)
        return GeneratedInterpreter(code=bytes(encoding), listing=listing)

    # -- listing construction --------------------------------------------
    def _listing(self) -> str:
        lines: List[str] = []
        lines += self._prologue()
        lines += self._fetch_and_dispatch()
        lines += self._handlers()
        lines += self._epilogue()
        return "\n".join(lines)

    def _prologue(self) -> List[str]:
        lines = ["vm_dispatch:", f"    sub rsp, {_CTX_SIZE}"]
        # Capture each register into its slot (reads only -> originals preserved).
        for reg in _CAPTURED_X64:
            slot = self.profile.reg_slots[reg]
            lines.append(f"    mov [rsp + {slot * 8}], {reg}")
        # Inline bytecode pointer sits at [rsp + CTX_SIZE] (return address).
        lines += [
            f"    mov r11, [rsp + {_CTX_SIZE}]",   # &inline pointer
            "    mov r10, [r11]",                  # r10 = bytecode ip
            "    add r11, 8",                      # skip the 8-byte pointer
            f"    mov [rsp + {_CTX_SIZE}], r11",   # fix return address
            "    xor r9, r9",                      # r9 = stream position (key roll)
        ]
        return lines

    def _fetch_byte(self, dest: str) -> List[str]:
        """Emit a fetch+decrypt of one bytecode byte into ``dest`` (32-bit)."""

        return [
            f"    movzx {dest}, byte ptr [r10]",
            "    mov ecx, r9d",
            f"    add ecx, {self.profile.key}",
            "    and ecx, 0xff",
            f"    xor {dest}, ecx",
            "    inc r10",
            "    inc r9d",
        ]

    def _fetch_and_dispatch(self) -> List[str]:
        lines = ["vm_loop:"]
        lines += self._fetch_byte("eax")  # eax = opcode
        # Compare against each randomized opcode value and jump to its handler.
        for op in self.profile.handler_order:
            lines.append(f"    cmp eax, {self.profile.opcode_map[op]}")
            lines.append(f"    je vm_h_{op.value}")
        lines.append("    jmp vm_exit")  # unknown opcode -> bail out safely
        return lines

    def _slot_ptr(self, reg_dest: str, byte_reg: str) -> List[str]:
        """Given a slot index in ``byte_reg`` (al/dl), set ``reg_dest`` = &ctx[slot]."""

        return [
            f"    movzx {reg_dest}, {byte_reg}",
            f"    shl {reg_dest}, 3",
            f"    add {reg_dest}, rsp",
        ]

    def _handlers(self) -> List[str]:
        lines: List[str] = []
        for op in self.profile.handler_order:
            lines.append(f"vm_h_{op.value}:")
            lines += self._handler_body(op)
        return lines

    def _handler_body(self, op: VMOp) -> List[str]:
        if op is VMOp.EXIT:
            return ["    jmp vm_exit"]

        if op in (VMOp.LDI, VMOp.ADDI):
            lines = self._fetch_byte("eax")        # eax = slot a
            lines += self._slot_ptr("r8", "al")    # r8 = &ctx[a]
            # Read 8 immediate bytes (little-endian) into rdx.
            lines += ["    xor rdx, rdx"]
            for i in range(8):
                lines += self._fetch_byte("ebx")   # ebx = next imm byte
                lines += [
                    "    movzx rbx, bl",
                    f"    shl rbx, {i * 8}",
                    "    or rdx, rbx",
                ]
            if op is VMOp.LDI:
                lines += ["    mov [r8], rdx"]
            else:  # ADDI
                lines += ["    add [r8], rdx"]
            lines += ["    jmp vm_loop"]
            return lines

        # Binary ops: fetch slot a, slot b, then apply.
        lines = self._fetch_byte("eax")            # eax = slot a
        lines += self._slot_ptr("r8", "al")        # r8 = &ctx[a]
        lines += self._fetch_byte("edx")           # edx = slot b
        lines += self._slot_ptr("r12", "dl")       # r12 = &ctx[b]
        lines += ["    mov rdx, [r12]"]
        mnemonic = {
            VMOp.MOV: "mov", VMOp.ADD: "add", VMOp.SUB: "sub",
            VMOp.XOR: "xor", VMOp.AND: "and", VMOp.OR: "or",
        }[op]
        lines += [f"    {mnemonic} [r8], rdx", "    jmp vm_loop"]
        return lines

    def _epilogue(self) -> List[str]:
        lines = ["vm_exit:"]
        # Restore every captured register from its slot, then return.
        for reg in _CAPTURED_X64:
            slot = self.profile.reg_slots[reg]
            lines.append(f"    mov {reg}, [rsp + {slot * 8}]")
        lines += [f"    add rsp, {_CTX_SIZE}", "    ret"]
        return lines
