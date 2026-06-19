"""The standalone section/data protection engine.

Encrypts data (and optionally all other non-executable) sections at rest and
prepends a runtime decryptor stub that restores them before the original entry
runs, so the program behaves identically - only the on-disk bytes are scrambled.

* :mod:`codescrambler.protect.ciphers` - per-build randomized cipher catalog.
* :mod:`codescrambler.protect.stub` - position-independent decryptor stub.
* :mod:`codescrambler.protect.sections` - selection, encryption and the writer
  hook that ties it together.
"""

from codescrambler.protect.ciphers import Cipher, build_cipher
from codescrambler.protect.sections import SectionProtector

__all__ = ["Cipher", "build_cipher", "SectionProtector"]
