"""``python -m codescrambler.vm in.exe out.exe [--coverage 0-100] [--seed N]``.

Runs only the virtualization engine. By default it operates in safe
(non-committing) mode and prints the lift report.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from codescrambler.pe.loader import load_program
from codescrambler.vm.virtualizer import Virtualizer


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="codescrambler.vm")
    parser.add_argument("input")
    parser.add_argument("--coverage", type=int, default=30, help="0-100")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--commit", action="store_true", help="rewrite native code (opt-in)")
    ns = parser.parse_args(argv if argv is not None else sys.argv[1:])

    virtualizer = Virtualizer(coverage=ns.coverage / 100.0, seed=ns.seed, commit=ns.commit)
    program = load_program(ns.input)
    report = virtualizer.analyze(program)
    print(f"[vm] seed={virtualizer.seed} coverage={ns.coverage}%")
    print(json.dumps(report.as_dict(), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
