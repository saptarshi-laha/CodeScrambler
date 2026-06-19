"""End-to-end build with the high-level Engine.

Run:  python examples/full_pipeline.py input.exe output.exe

Demonstrates the simplest path: pick intensities, let the Engine compose the
mutation + virtualization + section-encryption pipeline and rebuild the PE.
"""

import sys

from codescrambler import Config, EmitMode, EncryptSections, Engine


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    in_path, out_path = sys.argv[1], sys.argv[2]

    config = Config(
        mutation=60,                 # 0-100, junk/MBA/opaque/etc. intensity
        virtualization=30,           # 0-100, fraction of eligible code to lift
        encrypt_sections=EncryptSections.DATA,
        emit=EmitMode.BINARY,
        seed=None,                   # None -> a different build every run
    )
    engine = Engine(config)
    engine.run(in_path, out_path)
    print(f"built {out_path} (reproduce with seed={config.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
