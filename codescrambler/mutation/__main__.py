"""``python -m codescrambler.mutation in.exe out.exe [--level 0-100] [--seed N]``.

A minimal entry point for running *only* the mutation engine.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from codescrambler.mutation.mutator import Mutator


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="codescrambler.mutation")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--level", type=int, default=50, help="intensity 0-100")
    parser.add_argument("--seed", type=int, default=None)
    ns = parser.parse_args(argv if argv is not None else sys.argv[1:])

    mutator = Mutator(level=ns.level / 100.0, seed=ns.seed)
    mutator.add_default_passes().run(ns.input, ns.output)
    print(f"[mutation] seed={mutator.seed} level={ns.level}% -> {ns.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
