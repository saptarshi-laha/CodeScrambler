"""Enable ``python -m codescrambler ...`` to run the CLI."""

from codescrambler.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
