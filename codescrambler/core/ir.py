"""The intermediate representation (IR) shared by every stage.

The IR is deliberately small and explicit so it is easy to review:

* :class:`Instruction` - one machine instruction (real or synthesized).
* :class:`Section` - one PE section, optionally decoded into instructions.
* :class:`Program` - the whole binary: architecture, image base, entry point
  and the list of sections.

Branch targets are kept *symbolic*. Instead of storing a raw destination
address (which becomes meaningless the moment we move code around), a branch
instruction points at a :class:`Label`. The assembler later turns labels back
into concrete offsets. This is what lets passes freely insert, delete and
reorder instructions without breaking control flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


#: Register names capstone uses for the flags register across widths.
_FLAG_REGS = frozenset({"eflags", "flags", "rflags"})


class Arch(Enum):
    """Target architecture of a program."""

    X86 = 32
    X64 = 64

    @property
    def pointer_size(self) -> int:
        return 4 if self is Arch.X86 else 8


@dataclass
class Instruction:
    """A single instruction in the IR.

    Real instructions (produced by the disassembler) carry their original
    address and raw bytes. Synthetic instructions (produced by passes) leave
    those as ``None`` and are rendered purely from :attr:`text` or from
    ``mnemonic`` + ``op_str``.

    Reassembly always goes through :meth:`render`, which prefers an explicit
    :attr:`text` override, then a symbolic branch label, then the raw operand
    string. The assembler is responsible for fixing RIP-relative operands.
    """

    mnemonic: str = ""
    op_str: str = ""
    address: Optional[int] = None
    raw: bytes = b""

    # Control-flow metadata (populated by the disassembler).
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_cond_branch: bool = False
    branch_target: Optional[int] = None
    branch_label: Optional[str] = None

    # RIP-relative / absolute data references (x64 + relocated x86).
    is_rip_relative: bool = False
    rip_target: Optional[int] = None

    # Register liveness, as reported by capstone (best effort).
    regs_read: Tuple[str, ...] = ()
    regs_written: Tuple[str, ...] = ()
    groups: Tuple[str, ...] = ()

    # A label naming *this* instruction's location, if any.
    label: Optional[str] = None

    # Free-form assembly text that, when set, is emitted verbatim. Passes that
    # synthesize multi-token instructions use this to avoid re-parsing.
    text: Optional[str] = None

    # Names of labels referenced inside :attr:`text` as ``{label}`` placeholders.
    # The assembler substitutes each with the label's resolved absolute address,
    # which lets non-branch instructions (e.g. ``push {ret}``) reference labels.
    label_refs: Tuple[str, ...] = ()

    #: Marks instructions invented by a pass (helps analysis / lift reports).
    synthetic: bool = False

    @property
    def size(self) -> int:
        """Original encoded size in bytes (0 for synthetic instructions)."""

        return len(self.raw)

    @property
    def reads_flags(self) -> bool:
        """True if the instruction reads any CPU flag (per capstone)."""

        return any(name in _FLAG_REGS for name in self.regs_read)

    @property
    def writes_flags(self) -> bool:
        """True if the instruction writes any CPU flag (per capstone)."""

        return any(name in _FLAG_REGS for name in self.regs_written)

    @property
    def is_terminator(self) -> bool:
        """True for unconditional control transfers and returns."""

        return self.is_ret or (self.is_branch and not self.is_cond_branch)

    def render(self) -> str:
        """Return the assembly text used to re-encode this instruction."""

        if self.text is not None:
            return self.text
        if self.branch_label is not None:
            return f"{self.mnemonic} {self.branch_label}".strip()
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}".strip()
        return self.mnemonic

    @classmethod
    def synth(cls, text: str, **kwargs) -> "Instruction":
        """Build a synthetic instruction from raw assembly ``text``."""

        mnemonic = text.split(" ", 1)[0]
        return cls(mnemonic=mnemonic, text=text, synthetic=True, **kwargs)

    @classmethod
    def synth_ref(cls, text: str, label_refs: Tuple[str, ...], **kwargs) -> "Instruction":
        """Synthetic instruction whose ``text`` references labels as ``{name}``."""

        mnemonic = text.split(" ", 1)[0]
        return cls(
            mnemonic=mnemonic, text=text, label_refs=tuple(label_refs),
            synthetic=True, **kwargs,
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        where = f"@{self.address:#x}" if self.address is not None else "@synth"
        return f"<Insn {where} {self.render()!r}>"


@dataclass
class Section:
    """One PE section plus its decoded instructions (if executable)."""

    name: str
    rva: int
    virtual_size: int
    raw: bytes
    characteristics: int
    is_executable: bool
    instructions: List[Instruction] = field(default_factory=list)

    def byte_range(self, image_base: int) -> range:
        """The virtual-address range covered by this section."""

        start = image_base + self.rva
        return range(start, start + max(self.virtual_size, len(self.raw)))


@dataclass
class Program:
    """The decoded binary the pipeline operates on."""

    arch: Arch
    image_base: int
    entry_rva: int
    sections: List[Section] = field(default_factory=list)

    #: Filled in by passes/engines that want to surface diagnostics.
    metadata: Dict[str, object] = field(default_factory=dict)

    @property
    def entry_va(self) -> int:
        return self.image_base + self.entry_rva

    def executable_sections(self) -> List[Section]:
        """All sections flagged executable, regardless of their name."""

        return [s for s in self.sections if s.is_executable]

    def section_at_va(self, va: int) -> Optional[Section]:
        """Return the section containing ``va`` (or ``None``)."""

        for section in self.sections:
            if va in section.byte_range(self.image_base):
                return section
        return None

    def all_instructions(self) -> List[Instruction]:
        """Flat list of every decoded instruction across all sections."""

        out: List[Instruction] = []
        for section in self.executable_sections():
            out.extend(section.instructions)
        return out
