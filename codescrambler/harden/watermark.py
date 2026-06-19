"""Static software watermarking (embed + extract).

A watermark is a hidden identifier (build id, licensee, campaign tag) embedded in
the binary so a later copy can be attributed. This is a *static* watermark: it is
stored as data in a dedicated section and recovered by reading the file - no
execution required.

Wire format of the embedded blob::

    "CSWM" | key:1 | length:2 (LE) | xor(payload, rolling key)

The light XOR keeps the mark from being a plain grep target; the key travels with
the blob so extraction needs no external secret. (For a tamper-resistant,
collusion-resistant mark you would layer a dynamic/CT-style watermark on top -
see ARCHITECTURE.)
"""

from __future__ import annotations

from typing import Optional

from codescrambler.core.rng import Rng

_MAGIC = b"CSWM"
_SCN_INIT_DATA_READ = 0x40000040


def encode_watermark(text: str, key: int) -> bytes:
    payload = text.encode("utf-8")
    key &= 0xFF
    enc = bytes((b ^ ((key + i) & 0xFF)) & 0xFF for i, b in enumerate(payload))
    return _MAGIC + bytes([key]) + len(enc).to_bytes(2, "little") + enc


def decode_watermark(blob: bytes) -> Optional[str]:
    if len(blob) < 7 or blob[:4] != _MAGIC:
        return None
    key = blob[4]
    length = int.from_bytes(blob[5:7], "little")
    enc = blob[7:7 + length]
    if len(enc) != length:
        return None
    payload = bytes((b ^ ((key + i) & 0xFF)) & 0xFF for i, b in enumerate(enc))
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def extract_watermark(path: str) -> Optional[str]:
    """Recover a watermark from a built file, if present."""

    with open(path, "rb") as handle:
        data = handle.read()
    idx = data.find(_MAGIC)
    if idx < 0:
        return None
    return decode_watermark(data[idx:])


class Watermark:
    """Embeds a static watermark via a :class:`PEWriter` post-hook."""

    def __init__(self, text: str, rng: Rng) -> None:
        self.text = text
        self.rng = rng

    def attach(self, writer) -> None:
        key = self.rng.randint(1, 255)
        blob = encode_watermark(self.text, key)
        writer.add_post_hook(lambda w, _pe: w.add_section(".csmark", blob, _SCN_INIT_DATA_READ))
