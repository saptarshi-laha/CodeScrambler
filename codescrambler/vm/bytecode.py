"""Encode, encrypt, decode and verify VM bytecode.

Wire format per instruction (before encryption):

* ``[opcode]`` for ``EXIT``
* ``[opcode][a][b]`` for binary ops (two 1-byte slot indices)
* ``[opcode][a][imm:8]`` for immediate ops (1-byte slot + 8-byte little-endian)

The stream is then encrypted with a position-dependent rolling XOR keyed by the
build's :attr:`~codescrambler.vm.randomizer.VMProfile.key`. The interpreter
performs the inverse on fetch. Encoding is the exact inverse of decoding, which
the round-trip helper checks.
"""

from __future__ import annotations

from typing import List

from codescrambler.vm.isa import BINARY_OPS, IMMEDIATE_OPS, VMInstr, VMOp, VMProgram
from codescrambler.vm.randomizer import VMProfile


def encode(program: VMProgram, profile: VMProfile) -> bytes:
    """Serialize ``program`` to plaintext bytecode using the profile's opcodes."""

    out = bytearray()
    for ins in program.instructions:
        out.append(profile.opcode_map[ins.op])
        if ins.op in BINARY_OPS:
            out.append(ins.a & 0xFF)
            out.append(ins.b & 0xFF)
        elif ins.op in IMMEDIATE_OPS:
            out.append(ins.a & 0xFF)
            out += (ins.imm & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        # EXIT has no operands.
    return bytes(out)


def encrypt(data: bytes, key: int) -> bytes:
    """Position-dependent rolling XOR (its own inverse)."""

    return bytes(byte ^ ((key + i) & 0xFF) for i, byte in enumerate(data))


def decrypt(data: bytes, key: int) -> bytes:
    return encrypt(data, key)


def decode(data: bytes, profile: VMProfile) -> VMProgram:
    """Parse plaintext bytecode back into a :class:`VMProgram`."""

    inverse = profile.inverse_opcodes
    program = VMProgram()
    i = 0
    while i < len(data):
        op = inverse[data[i]]
        i += 1
        if op in BINARY_OPS:
            program.add(op, a=data[i], b=data[i + 1])
            i += 2
        elif op in IMMEDIATE_OPS:
            a = data[i]
            imm = int.from_bytes(data[i + 1:i + 9], "little")
            program.add(op, a=a, imm=imm)
            i += 9
        else:  # EXIT
            program.add(op)
    return program


def assemble_bytecode(program: VMProgram, profile: VMProfile) -> bytes:
    """Encode then encrypt - the form embedded in the protected binary."""

    return encrypt(encode(program, profile), profile.key)


def verify_roundtrip(program: VMProgram, profile: VMProfile) -> bool:
    """Check encode -> encrypt -> decrypt -> decode reproduces the program."""

    blob = assemble_bytecode(program, profile)
    restored = decode(decrypt(blob, profile.key), profile)
    original = [(i.op, i.a, i.b, i.imm) for i in program.instructions]
    roundtrip = [(i.op, i.a, i.b, i.imm) for i in restored.instructions]
    return original == roundtrip
