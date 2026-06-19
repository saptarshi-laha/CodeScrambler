"""Iterative two-pass assembler built on keystone.

Reassembling a rewritten instruction stream is the hard part of any binary
rewriter: inserting one byte shifts every following address, which changes
branch displacements, which can change instruction sizes, which shifts
addresses again. We solve this with a fixpoint:

1. Estimate every instruction's size.
2. Lay out addresses sequentially from the section's final base VA, recording
   where each label lands.
3. Re-encode size-sensitive instructions (branches, RIP-relative, synthetic)
   against those label addresses.
4. If any size changed, repeat. Sizes only ever shrink, so this converges in a
   couple of iterations.

Crucially, instructions that are *not* branches, RIP-relative or synthetic are
emitted from their original bytes verbatim. That keeps the bulk of the code
byte-identical (perfect round-trip) and limits keystone re-encoding - and the
textual round-trip risk it carries - to the few instructions that actually need
it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

import keystone

from codescrambler.core.ir import Arch, Instruction

_MAX_ITERATIONS = 12
_RIP_OPERAND = re.compile(r"rip\s*([+-])\s*0x[0-9a-fA-F]+")


@dataclass
class AssembledCode:
    """Result of assembling an instruction list."""

    data: bytes
    #: Maps a label name to its final virtual address.
    label_addresses: Dict[str, int] = field(default_factory=dict)
    #: Maps each instruction's original address to its new virtual address.
    address_map: Dict[int, int] = field(default_factory=dict)


class AssemblyError(RuntimeError):
    """Raised when an instruction cannot be encoded."""


class Assembler:
    """Encodes IR instructions into bytes for a given architecture."""

    def __init__(self, arch: Arch) -> None:
        self.arch = arch
        mode = keystone.KS_MODE_32 if arch is Arch.X86 else keystone.KS_MODE_64
        self._ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
        self._ks.syntax = keystone.KS_OPT_SYNTAX_INTEL

    # -- public API -------------------------------------------------------
    def assemble(self, instructions: List[Instruction], base_va: int) -> AssembledCode:
        """Assemble ``instructions`` as if loaded at ``base_va``."""

        sizes = [self._initial_size(insn) for insn in instructions]

        for _ in range(_MAX_ITERATIONS):
            addresses, labels = self._layout(instructions, sizes, base_va)
            encodings, changed = self._encode_all(instructions, addresses, sizes, labels)
            if not changed:
                return self._finalize(instructions, addresses, labels, encodings)

        # One last layout/encode with whatever sizes we converged near.
        addresses, labels = self._layout(instructions, sizes, base_va)
        encodings, _ = self._encode_all(instructions, addresses, sizes, labels)
        return self._finalize(instructions, addresses, labels, encodings)

    # -- internals --------------------------------------------------------
    def _needs_reencode(self, insn: Instruction) -> bool:
        """Only branches, RIP-relative and synthetic instructions re-encode."""

        return insn.is_branch or insn.is_rip_relative or insn.synthetic or not insn.raw

    def _initial_size(self, insn: Instruction) -> int:
        if not self._needs_reencode(insn):
            return len(insn.raw)
        # Assume the longest plausible form initially so layout never overflows;
        # the fixpoint then shrinks branches that fit a short encoding.
        if insn.is_branch:
            return max(len(insn.raw), 6)
        if insn.raw:
            return len(insn.raw)
        return 8

    def _layout(self, instructions, sizes, base_va):
        addresses: List[int] = []
        labels: Dict[str, int] = {}
        cursor = base_va
        for insn, size in zip(instructions, sizes):
            addresses.append(cursor)
            if insn.label:
                labels[insn.label] = cursor
            cursor += size
        return addresses, labels

    def _encode_all(self, instructions, addresses, sizes, labels):
        encodings: List[bytes] = []
        changed = False
        for i, insn in enumerate(instructions):
            if not self._needs_reencode(insn):
                encodings.append(insn.raw)
                continue
            enc = self._encode_one(insn, addresses[i], labels)
            if len(enc) != sizes[i]:
                sizes[i] = len(enc)
                changed = True
            encodings.append(enc)
        return encodings, changed

    def _encode_one(self, insn: Instruction, address: int, labels: Dict[str, int]) -> bytes:
        text = self._render(insn, address, labels)
        try:
            encoding, _ = self._ks.asm(text, address)
        except keystone.KsError as exc:  # pragma: no cover - surfaced to caller
            raise AssemblyError(f"cannot assemble {text!r} @ {address:#x}: {exc}") from exc
        if encoding is None:
            raise AssemblyError(f"keystone produced no output for {text!r}")
        return bytes(encoding)

    def _render(self, insn: Instruction, address: int, labels: Dict[str, int]) -> str:
        """Produce concrete assembly text for re-encoding at ``address``."""

        # Symbolic branch: resolve the label to an absolute target; keystone
        # turns the absolute target into the right relative displacement.
        if insn.branch_label and insn.branch_label in labels:
            return f"{insn.mnemonic} {labels[insn.branch_label]:#x}"

        if insn.text is not None:
            text = insn.text
            for name in insn.label_refs:
                if name in labels:
                    text = text.replace("{" + name + "}", f"{labels[name]:#x}")
            return text

        if insn.is_rip_relative and insn.rip_target is not None:
            return self._rewrite_rip(insn, address)

        if insn.op_str:
            return f"{insn.mnemonic} {insn.op_str}"
        return insn.mnemonic

    def _rewrite_rip(self, insn: Instruction, address: int) -> str:
        """Recompute a ``[rip + disp]`` operand for the instruction's new VA."""

        next_va = address + len(insn.raw)
        disp = insn.rip_target - next_va
        sign = "+" if disp >= 0 else "-"
        replacement = f"rip {sign} {abs(disp):#x}"
        new_op = _RIP_OPERAND.sub(replacement, insn.op_str)
        return f"{insn.mnemonic} {new_op}"

    def _finalize(self, instructions, addresses, labels, encodings) -> AssembledCode:
        address_map: Dict[int, int] = {}
        for insn, new_addr in zip(instructions, addresses):
            if insn.address is not None:
                address_map[insn.address] = new_addr
        return AssembledCode(
            data=b"".join(encodings),
            label_addresses=labels,
            address_map=address_map,
        )
