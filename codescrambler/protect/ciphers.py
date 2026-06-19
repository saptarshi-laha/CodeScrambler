"""Per-build randomized cipher catalog.

Each cipher knows how to (a) encrypt bytes in Python at build time and (b) emit
the x64 assembly that performs the *inverse* on a memory range at runtime. The
build-time and runtime halves are kept side by side so they cannot drift, and a
self-test (`python encrypt -> python-modelled decrypt`) guards each cipher.

Two schemes are provided; both take a randomized key (and stride), so no two
builds use the same parameters:

* ``xor_rolling`` - ``b ^= (key + i*stride) & 0xFF``
* ``add_rolling`` - encrypt ``b = (b + key + i*stride)``; decrypt subtracts.

Adding a cipher is just another small class registered in :data:`_CIPHERS`.
"""

from __future__ import annotations

import abc
from typing import List, Type

from codescrambler.core.rng import Rng


class Cipher(abc.ABC):
    """A reversible byte transform with matching build-time and runtime halves."""

    cipher_id: str = "abstract"

    def __init__(self, key: int, stride: int) -> None:
        self.key = key & 0xFF
        self.stride = stride & 0xFF

    @abc.abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt ``data`` at build time."""

    @abc.abstractmethod
    def decrypt_asm(self, ptr_reg: str, len_reg: str, byte_reg: str, idx_reg: str) -> List[str]:
        """Emit x64 asm decrypting ``len_reg`` bytes at ``ptr_reg`` in place.

        Registers are caller-allocated scratch; ``idx_reg`` counts position so
        the rolling key matches the build-time encryption.
        """

    def self_test(self, sample: bytes = b"CodeScrambler\x00\x01\x02\xff") -> bool:
        """Verify the Python model of decrypt inverts encrypt."""

        return self._model_decrypt(self.encrypt(sample)) == sample

    @abc.abstractmethod
    def _model_decrypt(self, data: bytes) -> bytes:
        """Python model of the runtime decryptor (for self-test only)."""


class XorRollingCipher(Cipher):
    cipher_id = "xor_rolling"

    def encrypt(self, data: bytes) -> bytes:
        return bytes((b ^ ((self.key + i * self.stride) & 0xFF)) & 0xFF for i, b in enumerate(data))

    def _model_decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)  # xor is its own inverse

    def decrypt_asm(self, ptr_reg, len_reg, byte_reg, idx_reg) -> List[str]:
        loop = f"cipher_loop_{id(self):x}"
        done = f"cipher_done_{id(self):x}"
        b8 = _low8(byte_reg)
        k8 = _low8(idx_reg)
        return [
            f"    test {len_reg}, {len_reg}",
            f"    jz {done}",
            f"    mov {idx_reg}, {self.key}",   # running key value
            f"{loop}:",
            f"    mov {b8}, [{ptr_reg}]",
            f"    xor {b8}, {k8}",
            f"    mov [{ptr_reg}], {b8}",
            f"    add {k8}, {self.stride}",
            f"    inc {ptr_reg}",
            f"    dec {len_reg}",
            f"    jnz {loop}",
            f"{done}:",
        ]


class AddRollingCipher(Cipher):
    cipher_id = "add_rolling"

    def encrypt(self, data: bytes) -> bytes:
        return bytes(((b + self.key + i * self.stride) & 0xFF) for i, b in enumerate(data))

    def _model_decrypt(self, data: bytes) -> bytes:
        return bytes(((b - self.key - i * self.stride) & 0xFF) for i, b in enumerate(data))

    def decrypt_asm(self, ptr_reg, len_reg, byte_reg, idx_reg) -> List[str]:
        loop = f"cipher_loop_{id(self):x}"
        done = f"cipher_done_{id(self):x}"
        b8 = _low8(byte_reg)
        k8 = _low8(idx_reg)
        return [
            f"    test {len_reg}, {len_reg}",
            f"    jz {done}",
            f"    mov {idx_reg}, {self.key}",
            f"{loop}:",
            f"    mov {b8}, [{ptr_reg}]",
            f"    sub {b8}, {k8}",
            f"    mov [{ptr_reg}], {b8}",
            f"    add {k8}, {self.stride}",
            f"    inc {ptr_reg}",
            f"    dec {len_reg}",
            f"    jnz {loop}",
            f"{done}:",
        ]


_CIPHERS: List[Type[Cipher]] = [XorRollingCipher, AddRollingCipher]

#: Map x64 64-bit register -> its low 8-bit sub-register.
_LOW8 = {
    "rax": "al", "rbx": "bl", "rcx": "cl", "rdx": "dl",
    "rsi": "sil", "rdi": "dil", "r8": "r8b", "r9": "r9b",
    "r10": "r10b", "r11": "r11b", "r12": "r12b", "r13": "r13b",
}


def _low8(reg: str) -> str:
    return _LOW8[reg]


def build_cipher(rng: Rng) -> Cipher:
    """Instantiate a randomly chosen cipher with randomized parameters."""

    cipher_cls = rng.choice(_CIPHERS)
    key = rng.randint(1, 255)
    stride = rng.randint(1, 255)
    cipher = cipher_cls(key, stride)
    if not cipher.self_test():  # pragma: no cover - guards against regressions
        raise RuntimeError(f"cipher {cipher.cipher_id} failed self-test")
    return cipher
