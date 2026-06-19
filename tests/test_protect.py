"""Protection engine checks: cipher round-trips and stub assembly."""

from codescrambler.core.rng import Rng
from codescrambler.protect.ciphers import AddRollingCipher, XorRollingCipher, build_cipher
from codescrambler.protect.stub import ProtectedSection, StubGenerator

FULL_RANGE = bytes(range(256))


def test_xor_cipher_roundtrip():
    c = XorRollingCipher(0x42, 7)
    assert c._model_decrypt(c.encrypt(FULL_RANGE)) == FULL_RANGE


def test_add_cipher_roundtrip():
    c = AddRollingCipher(0x99, 13)
    assert c._model_decrypt(c.encrypt(FULL_RANGE)) == FULL_RANGE


def test_build_cipher_self_tests():
    rng = Rng(7)
    for _ in range(20):
        assert build_cipher(rng).self_test()


def test_stub_assembles_with_multiple_sections():
    sections = [
        ProtectedSection(0x5000, 0x200, XorRollingCipher(0x11, 3)),
        ProtectedSection(0x8000, 0x80, AddRollingCipher(0x22, 5)),
    ]
    stub = StubGenerator().generate(
        stub_rva=0x10000, image_base=0x140000000, orig_entry_rva=0x1000, sections=sections
    )
    assert len(stub.code) > 0
    assert "jmp rax" in stub.listing
