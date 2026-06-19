"""Capstone-based disassembler backend (the default).

Capstone is run with ``detail = True`` so we can record register reads/writes,
instruction groups and operand information. That metadata is what makes the
later passes safe: the MBA pass needs to know which registers are free, the
reordering pass needs read/write sets, and the VM lifter needs operand types.
"""

from __future__ import annotations

from typing import List

import capstone

from codescrambler.core.disasm.base import DisassemblerBackend
from codescrambler.core.ir import Arch, Instruction


class CapstoneBackend(DisassemblerBackend):
    """Decode x86/x64 bytes into the IR using capstone."""

    name = "capstone"

    def _make_md(self, arch: Arch) -> "capstone.Cs":
        mode = capstone.CS_MODE_32 if arch is Arch.X86 else capstone.CS_MODE_64
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True
        md.skipdata = True  # never crash on undecodable bytes; emit .byte
        return md

    def decode(self, data: bytes, base_va: int, arch: Arch) -> List[Instruction]:
        md = self._make_md(arch)
        out: List[Instruction] = []
        for insn in md.disasm(data, base_va):
            if insn.id == 0:
                # SKIPDATA produced a raw ".byte" - keep it as opaque data so it
                # round-trips byte-for-byte without going through keystone.
                out.append(self._data_byte(insn))
            else:
                out.append(self._convert(insn, arch))
        return out

    @staticmethod
    def _data_byte(insn) -> Instruction:
        return Instruction(
            mnemonic=".byte",
            op_str=insn.op_str,
            address=insn.address,
            raw=bytes(insn.bytes),
        )

    def _convert(self, insn, arch: Arch) -> Instruction:
        groups = tuple(insn.group_name(g) or str(g) for g in insn.groups)

        is_call = capstone.CS_GRP_CALL in insn.groups
        is_ret = capstone.CS_GRP_RET in insn.groups
        is_jump = capstone.CS_GRP_JUMP in insn.groups
        is_branch = is_call or is_jump
        is_cond = is_jump and insn.mnemonic not in ("jmp",)

        branch_target = self._direct_target(insn)
        rip_relative, rip_target = self._rip_reference(insn, arch)

        try:
            read, written = insn.regs_access()
            regs_read = tuple(insn.reg_name(r) or str(r) for r in read)
            regs_written = tuple(insn.reg_name(r) or str(r) for r in written)
        except capstone.CsError:  # pragma: no cover - rare on skipdata bytes
            regs_read = regs_written = ()

        return Instruction(
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            address=insn.address,
            raw=bytes(insn.bytes),
            is_branch=is_branch,
            is_call=is_call,
            is_ret=is_ret,
            is_cond_branch=is_cond,
            branch_target=branch_target,
            is_rip_relative=rip_relative,
            rip_target=rip_target,
            regs_read=regs_read,
            regs_written=regs_written,
            groups=groups,
        )

    @staticmethod
    def _direct_target(insn) -> "int | None":
        """Return the destination VA of a direct branch/call, if immediate."""

        if capstone.CS_GRP_JUMP not in insn.groups and capstone.CS_GRP_CALL not in insn.groups:
            return None
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                return op.imm
        return None

    @staticmethod
    def _rip_reference(insn, arch: Arch):
        """Return ``(is_rip_relative, absolute_target)`` for x64 RIP operands."""

        if arch is not Arch.X64:
            return False, None
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                return True, target
        return False, None
