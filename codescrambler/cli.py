"""Command-line interface.

The surface is intentionally tiny - two intensity percentages plus a
section-encryption mode:

    codescrambler in.exe out.exe --mutation 60 --virtualization 30 \
        --encrypt-sections all [--seed N]

Use ``--emit analysis`` to dump the transformed IR as JSON instead of writing a
PE. Per-engine CLIs live at ``python -m codescrambler.mutation`` and
``python -m codescrambler.vm``.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from codescrambler.config import Config, EmitMode, EncryptSections
from codescrambler.engine import Engine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codescrambler",
        description="Polymorphic PE mutation + virtualization + protection engine.",
    )
    parser.add_argument("input", help="path to the input PE file")
    parser.add_argument("output", help="path to write the result to")
    parser.add_argument(
        "--mutation", type=int, default=0, metavar="X",
        help="mutation intensity 0-100 (default: 0)",
    )
    parser.add_argument(
        "--virtualization", type=int, default=0, metavar="X",
        help="fraction of eligible code to virtualize 0-100 (default: 0)",
    )
    parser.add_argument(
        "--encrypt-sections", choices=[m.value for m in EncryptSections],
        default=EncryptSections.NONE.value,
        help="encrypt non-executable sections at rest (default: none)",
    )
    parser.add_argument(
        "--emit", choices=[m.value for m in EmitMode], default=EmitMode.BINARY.value,
        help="produce a rebuilt binary or an analysis dump (default: binary)",
    )
    parser.add_argument("--seed", type=int, default=None, help="seed for reproducible builds")
    parser.add_argument(
        "--anti-debug", action="store_true",
        help="insert a runtime debugger check near the entry point",
    )
    parser.add_argument(
        "--anti-vm", action="store_true",
        help="insert a runtime hypervisor/VM check near the entry point",
    )
    parser.add_argument(
        "--watermark", default=None, metavar="TEXT",
        help="embed a static watermark string in the output",
    )
    parser.add_argument(
        "--llm-deterrent", action="store_true",
        help="embed a notice deterring automated / AI / LLM reverse engineering",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    ns = _build_parser().parse_args(sys.argv[1:] if argv is None else argv)

    config = Config(
        mutation=ns.mutation,
        virtualization=ns.virtualization,
        encrypt_sections=ns.encrypt_sections,
        emit=ns.emit,
        seed=ns.seed,
        anti_debug=ns.anti_debug,
        anti_vm=ns.anti_vm,
        watermark=ns.watermark,
        llm_deterrent=ns.llm_deterrent,
    )

    engine = Engine(config)
    engine.run(ns.input, ns.output)
    print(
        f"[codescrambler] seed={config.seed} mutation={config.mutation}% "
        f"virtualization={config.virtualization}% "
        f"encrypt={config.encrypt_sections.value} -> {ns.output}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
