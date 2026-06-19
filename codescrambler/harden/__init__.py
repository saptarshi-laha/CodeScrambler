"""The hardening engine: preventive + tamperproofing transforms.

These map to the *preventive transformations* and *tamperproofing* pillars of
Collberg & Nagra's "Surreptitious Software" (complementing the mutation engine's
obfuscation and the protection engine's encryption):

* :mod:`codescrambler.harden.antidebug` - detect a debugger at runtime
  (``AntiDebugPass``).
* :mod:`codescrambler.harden.antivm` - detect a hypervisor/VM at runtime
  (``AntiVMPass``).
* :mod:`codescrambler.harden.watermark` - embed/extract a static watermark
  (``Watermark`` / :func:`extract_watermark`).
* :mod:`codescrambler.harden.tamper` - self-checksum guard building blocks
  (:func:`checksum`, ``GuardGenerator``).
* :mod:`codescrambler.harden.llm_guard` - anti-(automated/LLM)-analysis notice
  (``LlmDeterrent`` / :func:`build_notice`).

Like every other engine, this one is independently importable.
"""

from codescrambler.harden.antidebug import AntiDebugPass
from codescrambler.harden.antivm import AntiVMPass
from codescrambler.harden.llm_guard import DEFAULT_NOTICE, LlmDeterrent, build_notice, extract_notice
from codescrambler.harden.tamper import GuardGenerator, checksum
from codescrambler.harden.watermark import Watermark, decode_watermark, encode_watermark, extract_watermark

__all__ = [
    "AntiDebugPass", "AntiVMPass",
    "Watermark", "encode_watermark", "decode_watermark", "extract_watermark",
    "GuardGenerator", "checksum",
    "LlmDeterrent", "build_notice", "extract_notice", "DEFAULT_NOTICE",
]
